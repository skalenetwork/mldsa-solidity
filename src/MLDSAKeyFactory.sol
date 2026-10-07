// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ParamSet, ML_DSA_44, ML_DSA_65} from "./IMLDSAVerifier.sol";
import {MLDSA} from "./MLDSA.sol";

/// @title MLDSAKeys — address derivation and loading for `MLDSAKeyFactory` data
/// @notice Per key — identified by (set, pkHash), pkHash = keccak256(pk) — the
///         factory deploys two SSTORE2-style data contracts (runtime = 0x00 ‖ data;
///         the leading STOP makes them uncallable):
///                                          ML-DSA-44        ML-DSA-65
///           A contract:  0x00 ‖ Â          1 + 12,288       1 + 23,040 bytes
///           T contract:  0x00 ‖ tr ‖ t̂     1 + 64 + 3,072   1 + 64 + 4,608 bytes
///         Both addresses are CREATE2(factory, salt, DATA_INITCODE) with a salt
///         that is domain-separated by role (A / T) and by parameter set, and a
///         FIXED init code, so they are a pure function of (factory, set, pkHash):
///         a wallet stores only the set, pkHash and the factory address. The init
///         code carries no data — it fetches its runtime from the factory — so the
///         only way to occupy those addresses is the factory itself, and the factory
///         only ever deploys there what it computed from the key under that set.
library MLDSAKeys {
    /// @dev Init code of every data contract (22 bytes, PUSH0 = Shanghai+):
    ///        STATICCALL(gas, CALLER, 0, 0, 0, 0)   ask the factory for the runtime
    ///        ISZERO, PUSH1 0x12, JUMPI             factory refused → revert
    ///        RETURNDATACOPY(0, 0, RETURNDATASIZE)
    ///        RETURN(0, RETURNDATASIZE)             runtime = whatever it returned
    ///        JUMPDEST, REVERT(0, 0)
    bytes internal constant DATA_INITCODE = hex"5f5f5f5f335afa156012573d5f5f3e3d5ff35b5f5ffd";
    bytes32 internal constant DATA_INITCODE_HASH = keccak256(DATA_INITCODE);

    /// @notice Runtime sizes of the two data contracts of `set` (0, 0 if unknown).
    function codeSizes(ParamSet set) internal pure returns (uint256 aCode, uint256 tCode) {
        if (set == ML_DSA_44) return (12289, 3137); //  1 + 12,288;  1 + 64 + 3,072
        if (set == ML_DSA_65) return (23041, 4673); //  1 + 23,040;  1 + 64 + 4,608
    }

    function saltA(ParamSet set, bytes32 pkHash) internal pure returns (bytes32) {
        return keccak256(abi.encode("MLDSA.A_hat", ParamSet.unwrap(set), pkHash));
    }

    function saltT(ParamSet set, bytes32 pkHash) internal pure returns (bytes32) {
        return keccak256(abi.encode("MLDSA.tr_t_hat", ParamSet.unwrap(set), pkHash));
    }

    /// @notice The two data-contract addresses of a key under `factory`.
    function addressesOf(address factory, ParamSet set, bytes32 pkHash)
        internal
        pure
        returns (address aData, address tData)
    {
        aData = _create2Address(factory, saltA(set, pkHash));
        tData = _create2Address(factory, saltT(set, pkHash));
    }

    /// @notice tr ‖ Â ‖ t̂ (the `MLDSA.precompute` layout of `set`) for a registered
    ///         key; EMPTY if either data contract is not deployed (yet) or the set is
    ///         unknown — verification then returns false.
    function load(address factory, ParamSet set, bytes32 pkHash) internal view returns (bytes memory blob) {
        (uint256 aSize, uint256 tSize) = codeSizes(set);
        if (aSize == 0) return blob;
        (address a, address t) = addressesOf(factory, set, pkHash);
        // Code at these addresses can only be the factory's (see above); the size
        // check just distinguishes "registered" from "not yet".
        if (a.code.length != aSize || t.code.length != tSize) return blob;
        uint256 aHat = aSize - 1;
        uint256 tHat = tSize - 1 - MLDSA.TR_BYTES;
        blob = new bytes(MLDSA.TR_BYTES + aHat + tHat);
        assembly ("memory-safe") {
            let b := add(blob, 0x20)
            extcodecopy(t, b, 1, 64) //                          tr
            extcodecopy(a, add(b, 64), 1, aHat) //                Â
            extcodecopy(t, add(add(b, 64), aHat), 65, tHat) //    t̂
        }
    }

    /// @notice Whether both data contracts of (set, pkHash) are deployed.
    function isRegistered(address factory, ParamSet set, bytes32 pkHash) internal view returns (bool) {
        (uint256 aSize, uint256 tSize) = codeSizes(set);
        if (aSize == 0) return false;
        (address a, address t) = addressesOf(factory, set, pkHash);
        return a.code.length == aSize && t.code.length == tSize;
    }

    /// @notice Makes sure the Â data contract of (set, pkHash) exists, deploying it
    ///         from `aHat` via `factory.storeA` if it does not and `aHat` is
    ///         non-empty. For a wallet's FIRST fast-path verification after a
    ///         commit-only setup (see `MLDSAKeyFactory.commitA`): the signer supplies
    ///         Â (recomputed off-chain from pk) in calldata, this stores it, and the
    ///         verification right after takes the fast path. Reverts (via storeA) iff
    ///         `aHat` is non-empty, not yet stored, and does not match the commitment
    ///         — a wallet that wants "never revert" passes empty bytes when unsure.
    /// @return stored Whether the Â data contract exists afterwards.
    function ensureStored(address factory, ParamSet set, bytes32 pkHash, bytes memory aHat)
        internal
        returns (bool stored)
    {
        (uint256 aSize,) = codeSizes(set);
        if (aSize == 0) return false;
        (address a,) = addressesOf(factory, set, pkHash);
        if (a.code.length == aSize) return true;
        if (aHat.length == 0) return false;
        MLDSAKeyFactory(factory).storeA(set, pkHash, aHat);
        return true;
    }

    /// @notice ML-DSA.Verify (empty context) against a key registered at `factory`
    ///         under `set`. Never reverts; false for a key not registered under
    ///         `set` (including one registered under the other set).
    function verify(address factory, ParamSet set, bytes32 pkHash, bytes memory message, bytes memory signature)
        internal
        view
        returns (bool)
    {
        return MLDSA.verifyPrecomputed(set, load(factory, set, pkHash), message, signature);
    }

    /// @notice ML-DSA.Verify with a context string against a registered key.
    function verifyWithContext(
        address factory,
        ParamSet set,
        bytes32 pkHash,
        bytes memory ctx,
        bytes memory message,
        bytes memory signature
    ) internal view returns (bool) {
        return MLDSA.verifyPrecomputedWithContext(set, load(factory, set, pkHash), ctx, message, signature);
    }

    function _create2Address(address factory, bytes32 salt) private pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), factory, salt, DATA_INITCODE_HASH)))));
    }
}

/// @title MLDSAKeyFactory — permissionless on-chain precomputation of ML-DSA keys
/// @notice `registerA(set, pk)` and `registerT(set, pk)` (anyone may call them, for
///         any key) compute Â respectively tr ‖ NTT(t1·2^d) ON-CHAIN from the
///         public key and deploy the data contracts at the addresses
///         `MLDSAKeys.addressesOf(factory, set, keccak256(pk))`. All entry points
///         are idempotent. `verify(set, pkHash, …)` then needs neither the key nor
///         any trusted input beyond the factory address, the set and pkHash. One
///         factory serves both ML-DSA-44 and ML-DSA-65; the set is part of every
///         salt and commitment key, so a key's data under one set is never found
///         under the other.
///
///         Â in two steps (so a wallet's setup fits one transaction for ML-DSA-65
///         too — the 23 KB code deposit alone is ~4.6M gas):
///           `commitA(set, pk)`  computes Â on-chain from pk, exactly as registerA
///                               does, but only records aHash = keccak256(Â);
///           `storeA(set, pkHash, Â)`  permissionless: deploys the Â data contract
///                               at the SAME address registerA would use, iff
///                               keccak256(Â) equals the commitment. The bytes come
///                               from anyone (the signer recomputes Â off-chain from
///                               pk); the commitment is what makes them trusted.
///         `registerA` = commitA + store in one call. Until Â is stored, the
///         precomputed fast path is simply unavailable (`MLDSAVerifier` falls back
///         to full verification); nothing is ever wrong, only slower.
/// @dev    Data hand-off: the runtime code is staged in transient storage (EIP-1153)
///         and returned by `fallback` to the one contract under construction, whose
///         fixed init code (MLDSAKeys.DATA_INITCODE) STATICCALLs back for it.
contract MLDSAKeyFactory {
    error UnsupportedParamSet();
    error InvalidPublicKey();
    error NotCommitted();
    error CommitmentMismatch();
    error DeployFailed();

    enum AStatus {
        None, //       no commitment, no data contract
        Committed, //  aHash recorded, Â not yet deployed
        Stored //      Â data contract deployed (fast path available once T is too)
    }

    event Registered(ParamSet indexed set, bytes32 indexed pkHash, address indexed data, bool isAHat);
    event CommittedA(ParamSet indexed set, bytes32 indexed pkHash, bytes32 aHash);

    /// @notice keccak256(Â) committed for (set, pkHash), keyed by `_commitKey`; 0 = none.
    mapping(bytes32 => bytes32) public aCommitment;

    // Transient slots: the address allowed to fetch, and the staged code length;
    // code words follow at DATA_SLOT + i.
    uint256 private constant PENDING_SLOT = 0;
    uint256 private constant LEN_SLOT = 1;
    uint256 private constant DATA_SLOT = 2;

    /// @notice Computes Â for `publicKey` under `set` on-chain and records
    ///         keccak256(Â) — no code deploy. Reverts for an unknown set or a key of
    ///         the wrong length for `set` (registration is setup, not verification).
    /// @return aHash The commitment (also when it already existed).
    function commitA(ParamSet set, bytes calldata publicKey) external returns (bytes32 aHash) {
        (aHash,) = _commitA(set, publicKey);
    }

    /// @notice Deploys the Â data contract of (set, pkHash) from `aHat`, which must
    ///         hash to the commitment. Permissionless; idempotent once stored.
    function storeA(ParamSet set, bytes32 pkHash, bytes calldata aHat) external returns (address aData) {
        if (!MLDSA.supported(set)) revert UnsupportedParamSet();
        (aData,) = MLDSAKeys.addressesOf(address(this), set, pkHash);
        if (aData.code.length != 0) return aData;
        bytes32 aHash = aCommitment[_commitKey(set, pkHash)];
        if (aHash == 0) revert NotCommitted();
        if (keccak256(aHat) != aHash) revert CommitmentMismatch();
        _deploy(MLDSAKeys.saltA(set, pkHash), aData, aHat);
        emit Registered(set, pkHash, aData, true);
    }

    /// @notice Commits and deploys the Â data contract for `publicKey` under `set` in
    ///         one call (≈ ExpandA + a 12 KB / 23 KB deposit).
    function registerA(ParamSet set, bytes calldata publicKey) external returns (address aData) {
        (bytes32 aHash, bytes memory data) = _commitA(set, publicKey);
        bytes32 pkHash = keccak256(publicKey);
        (aData,) = MLDSAKeys.addressesOf(address(this), set, pkHash);
        if (aData.code.length != 0) return aData;
        // Freshly computed here unless the commitment predates this call.
        if (data.length == 0) data = MLDSA.precomputeA(set, publicKey);
        assert(keccak256(data) == aHash);
        _deploy(MLDSAKeys.saltA(set, pkHash), aData, data);
        emit Registered(set, pkHash, aData, true);
    }

    /// @notice Where (set, pkHash)'s Â stands: None, Committed or Stored.
    function aStatus(ParamSet set, bytes32 pkHash) external view returns (AStatus) {
        (uint256 aSize,) = MLDSAKeys.codeSizes(set);
        (address a,) = MLDSAKeys.addressesOf(address(this), set, pkHash);
        if (aSize != 0 && a.code.length == aSize) return AStatus.Stored;
        if (aCommitment[_commitKey(set, pkHash)] != 0) return AStatus.Committed;
        return AStatus.None;
    }

    /// @dev Records keccak256(precomputeA(set, pk)) unless already committed (then
    ///      `data` is empty and nothing is recomputed).
    function _commitA(ParamSet set, bytes calldata publicKey) private returns (bytes32 aHash, bytes memory data) {
        if (!MLDSA.supported(set)) revert UnsupportedParamSet();
        bytes32 pkHash = keccak256(publicKey);
        bytes32 key = _commitKey(set, pkHash);
        aHash = aCommitment[key];
        if (aHash != 0) return (aHash, data);
        data = MLDSA.precomputeA(set, publicKey);
        if (data.length == 0) revert InvalidPublicKey();
        aHash = keccak256(data);
        aCommitment[key] = aHash;
        emit CommittedA(set, pkHash, aHash);
    }

    function _commitKey(ParamSet set, bytes32 pkHash) private pure returns (bytes32) {
        return keccak256(abi.encode(ParamSet.unwrap(set), pkHash));
    }

    /// @notice Deploys the tr ‖ t̂ data contract for `publicKey` under `set`.
    function registerT(ParamSet set, bytes calldata publicKey) external returns (address tData) {
        if (!MLDSA.supported(set)) revert UnsupportedParamSet();
        bytes32 pkHash = keccak256(publicKey);
        (, tData) = MLDSAKeys.addressesOf(address(this), set, pkHash);
        if (tData.code.length != 0) return tData;
        bytes memory data = MLDSA.precomputeT(set, publicKey);
        if (data.length == 0) revert InvalidPublicKey();
        _deploy(MLDSAKeys.saltT(set, pkHash), tData, data);
        emit Registered(set, pkHash, tData, false);
    }

    function addressesOf(ParamSet set, bytes32 pkHash) external view returns (address aData, address tData) {
        return MLDSAKeys.addressesOf(address(this), set, pkHash);
    }

    function isRegistered(ParamSet set, bytes32 pkHash) external view returns (bool) {
        return MLDSAKeys.isRegistered(address(this), set, pkHash);
    }

    function load(ParamSet set, bytes32 pkHash) external view returns (bytes memory) {
        return MLDSAKeys.load(address(this), set, pkHash);
    }

    function verify(ParamSet set, bytes32 pkHash, bytes calldata message, bytes calldata signature)
        external
        view
        returns (bool)
    {
        return MLDSAKeys.verify(address(this), set, pkHash, message, signature);
    }

    function verifyWithContext(
        ParamSet set,
        bytes32 pkHash,
        bytes calldata ctx,
        bytes calldata message,
        bytes calldata signature
    ) external view returns (bool) {
        return MLDSAKeys.verifyWithContext(address(this), set, pkHash, ctx, message, signature);
    }

    /// @dev Stages 0x00 ‖ data, CREATE2s the fixed init code, checks the result.
    function _deploy(bytes32 salt, address expected, bytes memory data) private {
        bytes memory code = abi.encodePacked(bytes1(0x00), data);
        bytes memory init = MLDSAKeys.DATA_INITCODE;
        address deployed;
        assembly ("memory-safe") {
            let len := mload(code)
            tstore(PENDING_SLOT, expected)
            tstore(LEN_SLOT, len)
            let src := add(code, 0x20)
            for { let i := 0 } lt(shl(5, i), len) { i := add(i, 1) } {
                tstore(add(DATA_SLOT, i), mload(add(src, shl(5, i))))
            }
            deployed := create2(0, add(init, 0x20), mload(init), salt)
            tstore(PENDING_SLOT, 0)
        }
        if (deployed != expected || deployed.code.length != code.length) revert DeployFailed();
    }

    /// @dev Answers the data contract under construction (and only it) with its
    ///      runtime code; anyone else gets a revert.
    fallback() external {
        // memory-safe: scratch use past the free pointer, then an immediate return
        assembly ("memory-safe") {
            if iszero(eq(caller(), tload(PENDING_SLOT))) { revert(0, 0) }
            let len := tload(LEN_SLOT)
            let p := mload(0x40)
            for { let i := 0 } lt(shl(5, i), len) { i := add(i, 1) } {
                mstore(add(p, shl(5, i)), tload(add(DATA_SLOT, i)))
            }
            return(p, len)
        }
    }
}
