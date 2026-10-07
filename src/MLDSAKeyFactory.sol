// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ParamSet, ML_DSA_44, ML_DSA_65, ML_DSA_87} from "./IMLDSAVerifier.sol";
import {MLDSA} from "./MLDSA.sol";

/// @title MLDSAKeys — address derivation and loading for `MLDSAKeyFactory` data
/// @notice Per key — identified by (set, pkHash), pkHash = keccak256(pk) — the
///         factory deploys SSTORE2-style data contracts (runtime = 0x00 ‖ data;
///         the leading STOP makes them uncallable):
///                                        ML-DSA-44        ML-DSA-65        ML-DSA-87
///           A contract(s): 0x00 ‖ Â      1 + 12,288       1 + 23,040       2 × (1 + 21,504)
///           T contract:    0x00 ‖ tr ‖ t̂ 1 + 64 + 3,072   1 + 64 + 4,608   1 + 64 + 6,144
///         ML-DSA-87's Â (43,008 bytes) is over EIP-170's 24,576, so it is split
///         into two A parts — rows 0..3 and rows 4..7 of Â, 28 polynomials each —
///         in two data contracts; Â is their concatenation.
///         Every address is CREATE2(factory, salt, DATA_INITCODE) with a salt that
///         is domain-separated by role (A / T), by parameter set and — for 87's A
///         parts — by part, and a FIXED init code, so they are a pure function of
///         (factory, set, pkHash[, part]): a wallet stores only the set, pkHash and
///         the factory address. The init code carries no data — it fetches its
///         runtime from the factory — so the only way to occupy those addresses is
///         the factory itself, and the factory only ever deploys there what it
///         computed from the key under that set (or what hashes to its commitment).
library MLDSAKeys {
    /// @dev Init code of every data contract (22 bytes, PUSH0 = Shanghai+):
    ///        STATICCALL(gas, CALLER, 0, 0, 0, 0)   ask the factory for the runtime
    ///        ISZERO, PUSH1 0x12, JUMPI             factory refused → revert
    ///        RETURNDATACOPY(0, 0, RETURNDATASIZE)
    ///        RETURN(0, RETURNDATASIZE)             runtime = whatever it returned
    ///        JUMPDEST, REVERT(0, 0)
    bytes internal constant DATA_INITCODE = hex"5f5f5f5f335afa156012573d5f5f3e3d5ff35b5f5ffd";
    bytes32 internal constant DATA_INITCODE_HASH = keccak256(DATA_INITCODE);

    /// @notice Runtime sizes of the data contracts of `set` (0, 0 if unknown): an
    ///         A contract (each of the `aPartCount` parts) and the T contract.
    function codeSizes(ParamSet set) internal pure returns (uint256 aCode, uint256 tCode) {
        if (set == ML_DSA_44) return (12289, 3137); //  1 + 12,288;  1 + 64 + 3,072
        if (set == ML_DSA_65) return (23041, 4673); //  1 + 23,040;  1 + 64 + 4,608
        if (set == ML_DSA_87) return (21505, 6209); //  1 + 21,504 per part;  1 + 64 + 6,144
    }

    /// @notice How many A data contracts `set` uses: 1 (44, 65), 2 (87), 0 (unknown).
    function aPartCount(ParamSet set) internal pure returns (uint256) {
        if (set == ML_DSA_44 || set == ML_DSA_65) return 1;
        if (set == ML_DSA_87) return 2;
        return 0;
    }

    function saltA(ParamSet set, bytes32 pkHash) internal pure returns (bytes32) {
        return keccak256(abi.encode("MLDSA.A_hat", ParamSet.unwrap(set), pkHash));
    }

    /// @notice Salt of A part `part`. For a single-part set, part 0 IS `saltA` (the
    ///         44 / 65 addresses predate parts and do not move); a multi-part set
    ///         (87) encodes the part in every one of its salts.
    function saltAPart(ParamSet set, bytes32 pkHash, uint256 part) internal pure returns (bytes32) {
        if (aPartCount(set) == 1 && part == 0) return saltA(set, pkHash);
        return keccak256(abi.encode("MLDSA.A_hat", ParamSet.unwrap(set), pkHash, part));
    }

    function saltT(ParamSet set, bytes32 pkHash) internal pure returns (bytes32) {
        return keccak256(abi.encode("MLDSA.tr_t_hat", ParamSet.unwrap(set), pkHash));
    }

    /// @notice The A (part 0) and T data-contract addresses of a key under `factory`.
    function addressesOf(address factory, ParamSet set, bytes32 pkHash)
        internal
        pure
        returns (address aData, address tData)
    {
        aData = aPartAddress(factory, set, pkHash, 0);
        tData = _create2Address(factory, saltT(set, pkHash));
    }

    /// @notice The address of A part `part` of a key under `factory`.
    function aPartAddress(address factory, ParamSet set, bytes32 pkHash, uint256 part) internal pure returns (address) {
        return _create2Address(factory, saltAPart(set, pkHash, part));
    }

    /// @notice tr ‖ Â ‖ t̂ (the `MLDSA.precompute` layout of `set`) for a registered
    ///         key; EMPTY if any of its data contracts is not deployed (yet) or the
    ///         set is unknown — verification then returns false.
    function load(address factory, ParamSet set, bytes32 pkHash) internal view returns (bytes memory blob) {
        if (!isRegistered(factory, set, pkHash)) return blob;
        // Code at these addresses can only be the factory's (see above); the size
        // checks in isRegistered just distinguish "registered" from "not yet".
        (uint256 aSize, uint256 tSize) = codeSizes(set);
        uint256 parts = aPartCount(set);
        uint256 aPart = aSize - 1;
        uint256 tHat = tSize - 1 - MLDSA.TR_BYTES;
        blob = new bytes(MLDSA.TR_BYTES + parts * aPart + tHat);
        address t = _create2Address(factory, saltT(set, pkHash));
        uint256 b;
        assembly ("memory-safe") {
            b := add(blob, 0x20)
            extcodecopy(t, b, 1, 64) //                                  tr
            extcodecopy(t, add(add(b, 64), mul(parts, aPart)), 65, tHat) // t̂
        }
        for (uint256 part; part < parts; ++part) {
            address a = aPartAddress(factory, set, pkHash, part);
            assembly ("memory-safe") {
                extcodecopy(a, add(add(b, 64), mul(part, aPart)), 1, aPart) // Â, rows of this part
            }
        }
    }

    /// @notice Whether every A part of (set, pkHash) is deployed.
    function isAStored(address factory, ParamSet set, bytes32 pkHash) internal view returns (bool) {
        (uint256 aSize,) = codeSizes(set);
        uint256 parts = aPartCount(set);
        if (parts == 0) return false;
        for (uint256 part; part < parts; ++part) {
            if (aPartAddress(factory, set, pkHash, part).code.length != aSize) return false;
        }
        return true;
    }

    /// @notice Whether all data contracts of (set, pkHash) — every A part and T —
    ///         are deployed.
    function isRegistered(address factory, ParamSet set, bytes32 pkHash) internal view returns (bool) {
        (, uint256 tSize) = codeSizes(set);
        if (tSize == 0) return false;
        return _create2Address(factory, saltT(set, pkHash)).code.length == tSize && isAStored(factory, set, pkHash);
    }

    /// @notice Makes sure the Â data contract(s) of (set, pkHash) exist, deploying
    ///         them from `aHat` (ALL of Â, every part concatenated) via
    ///         `factory.storeA` if they do not and `aHat` is non-empty. For a
    ///         wallet's FIRST fast-path verification after a commit-only setup (see
    ///         `MLDSAKeyFactory.commitA`): the signer supplies Â (recomputed
    ///         off-chain from pk) in calldata, this stores it, and the verification
    ///         right after takes the fast path. Reverts (via storeA) iff `aHat` is
    ///         non-empty, not yet (fully) stored, and does not match the commitment
    ///         — a wallet that wants "never revert" passes empty bytes when unsure.
    /// @return stored Whether every Â data contract exists afterwards.
    function ensureStored(address factory, ParamSet set, bytes32 pkHash, bytes memory aHat)
        internal
        returns (bool stored)
    {
        if (aPartCount(set) == 0) return false;
        if (isAStored(factory, set, pkHash)) return true;
        if (aHat.length == 0) return false;
        MLDSAKeyFactory(factory).storeA(set, pkHash, aHat);
        return true;
    }

    /// @notice ML-DSA.Verify (empty context) against a key registered at `factory`
    ///         under `set`. Never reverts; false for a key not registered under
    ///         `set` (including one registered under another set).
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
///         `MLDSAKeys.addressesOf` / `aPartAddress(factory, set, keccak256(pk), …)`.
///         All entry points are idempotent. `verify(set, pkHash, …)` then needs
///         neither the key nor any trusted input beyond the factory address, the
///         set and pkHash. One factory serves every set; the set is part of every
///         salt and commitment key, so a key's data under one set is never found
///         under another.
///
///         Â in two steps (so a wallet's setup fits one transaction for ML-DSA-65
///         and -87 too — the 23 KB code deposit alone is ~4.6M gas):
///           `commitA(set, pk)`  computes Â on-chain from pk, exactly as registerA
///                               does, but only records its hash (per part);
///           `storeA(set, pkHash, Â)`  permissionless: deploys the Â data contract(s)
///                               at the SAME address(es) registerA would use, iff
///                               the bytes hash to the commitment. The bytes come
///                               from anyone (the signer recomputes Â off-chain from
///                               pk); the commitment is what makes them trusted.
///         `registerA` = commitA + store in one call. Until Â is stored, the
///         precomputed fast path is simply unavailable (`MLDSAVerifier` falls back
///         to full verification); nothing is ever wrong, only slower.
///
///         ML-DSA-87 (Â in two parts, see MLDSAKeys): each part has its own
///         commitment, keccak256(part bytes), and its own data contract.
///         `registerAPart(set, pk, part)` / `storeAPart(set, pkHash, part, bytes)`
///         handle one part — `registerA(87, …)` does both in one call, which is
///         over EIP-7825's 2^24 per-transaction gas cap, so on a capped chain use
///         `registerAPart` twice. `commitA(87, pk)` commits both parts in one call
///         (it fits) and `storeA(87, pkHash, Â)` takes all of Â and stores
///         whichever parts are missing. For 44 / 65, part 0 is all of Â and the
///         part functions are the plain ones under another name.
/// @dev    Data hand-off: the runtime code is staged in transient storage (EIP-1153)
///         and returned by `fallback` to the one contract under construction, whose
///         fixed init code (MLDSAKeys.DATA_INITCODE) STATICCALLs back for it.
contract MLDSAKeyFactory {
    error UnsupportedParamSet();
    error InvalidPublicKey();
    error InvalidPart();
    error NotCommitted();
    error CommitmentMismatch();
    error DeployFailed();

    enum AStatus {
        None, //       no commitment, no data contract
        Committed, //  hash recorded, Â not yet deployed
        Stored //      Â data contract deployed (fast path available once T is too)
    }

    event Registered(ParamSet indexed set, bytes32 indexed pkHash, address indexed data, bool isAHat);
    /// @dev Single-part sets (44, 65): aHash = keccak256(Â).
    event CommittedA(ParamSet indexed set, bytes32 indexed pkHash, bytes32 aHash);
    /// @dev Multi-part sets (87): aPartHash = keccak256(Â part `part`).
    event CommittedAPart(ParamSet indexed set, bytes32 indexed pkHash, uint256 part, bytes32 aPartHash);

    /// @notice Committed hash of an Â part, keyed by `_commitKey`; 0 = none. Read it
    ///         through `aPartCommitment`.
    mapping(bytes32 => bytes32) public aCommitment;

    // Transient slots: the address allowed to fetch, and the staged code length;
    // code words follow at DATA_SLOT + i.
    uint256 private constant PENDING_SLOT = 0;
    uint256 private constant LEN_SLOT = 1;
    uint256 private constant DATA_SLOT = 2;

    /// @notice Computes Â for `publicKey` under `set` on-chain and records its
    ///         hash (each part's, for 87) — no code deploy. Reverts for an unknown
    ///         set or a key of the wrong length for `set` (registration is setup,
    ///         not verification).
    /// @return aHash keccak256(Â) for 44 / 65; keccak256(h0 ‖ h1), h_p the part
    ///         hashes, for 87 (also when the commitments already existed).
    function commitA(ParamSet set, bytes calldata publicKey) external returns (bytes32 aHash) {
        uint256 parts = _parts(set);
        bytes32 pkHash = keccak256(publicKey);
        bytes memory hashes = new bytes(32 * parts);
        for (uint256 part; part < parts; ++part) {
            uint256 fmp;
            assembly ("memory-safe") {
                fmp := mload(0x40)
            }
            (bytes32 h,) = _commitPart(set, publicKey, pkHash, part, parts);
            // The part's bytes are dead once hashed: reuse the memory (see
            // MLDSA._writeAHat), so 87's commit peaks at one part's buffers.
            assembly ("memory-safe") {
                mstore(0x40, fmp)
                mstore(add(add(hashes, 0x20), shl(5, part)), h)
            }
        }
        aHash = parts == 1 ? bytes32(hashes) : keccak256(hashes);
    }

    /// @notice Deploys the Â data contract(s) of (set, pkHash) from `aHat` — ALL
    ///         of Â; for 87 both parts concatenated, of which the missing ones are
    ///         stored — each part of which must hash to its commitment.
    ///         Permissionless; idempotent once stored (then `aHat` is ignored).
    /// @return aData The address of part 0 (the only part, for 44 / 65).
    function storeA(ParamSet set, bytes32 pkHash, bytes calldata aHat) external returns (address aData) {
        uint256 parts = _parts(set);
        aData = MLDSAKeys.aPartAddress(address(this), set, pkHash, 0);
        if (parts == 1) {
            _storePart(set, pkHash, 0, aData, aHat);
            return aData;
        }
        (uint256 aSize,) = MLDSAKeys.codeSizes(set);
        uint256 partBytes = aSize - 1;
        bool fits = aHat.length == parts * partBytes;
        for (uint256 part; part < parts; ++part) {
            address a = MLDSAKeys.aPartAddress(address(this), set, pkHash, part);
            if (a.code.length != 0) continue;
            if (aCommitment[_commitKey(set, pkHash, part, parts)] == 0) revert NotCommitted();
            if (!fits) revert CommitmentMismatch();
            _storePart(set, pkHash, part, a, aHat[part * partBytes:(part + 1) * partBytes]);
        }
    }

    /// @notice Deploys A part `part` of (set, pkHash) from `aPart`, which must hash
    ///         to that part's commitment. Permissionless; idempotent once stored.
    function storeAPart(ParamSet set, bytes32 pkHash, uint256 part, bytes calldata aPart)
        external
        returns (address aData)
    {
        if (part >= _parts(set)) revert InvalidPart();
        aData = MLDSAKeys.aPartAddress(address(this), set, pkHash, part);
        _storePart(set, pkHash, part, aData, aPart);
    }

    /// @notice Commits and deploys the Â data contract(s) for `publicKey` under
    ///         `set` in one call (≈ ExpandA + a 12 KB / 23 KB / 2 × 21.5 KB deposit;
    ///         for 87 over EIP-7825's per-transaction cap — see `registerAPart`).
    /// @return aData The address of part 0 (the only part, for 44 / 65).
    function registerA(ParamSet set, bytes calldata publicKey) external returns (address aData) {
        uint256 parts = _parts(set);
        bytes32 pkHash = keccak256(publicKey);
        for (uint256 part; part < parts; ++part) {
            uint256 fmp;
            assembly ("memory-safe") {
                fmp := mload(0x40)
            }
            address a = _registerPart(set, publicKey, pkHash, part, parts);
            if (part == 0) aData = a;
            assembly ("memory-safe") {
                mstore(0x40, fmp)
            }
        }
    }

    /// @notice `registerA` for A part `part` alone (rows [part·k/2, (part+1)·k/2)
    ///         of Â for 87; all of Â, part 0, for 44 / 65): commits that part if it
    ///         is not committed yet and deploys it. Each 87 part fits one
    ///         transaction under EIP-7825.
    function registerAPart(ParamSet set, bytes calldata publicKey, uint256 part) external returns (address aData) {
        uint256 parts = _parts(set);
        if (part >= parts) revert InvalidPart();
        return _registerPart(set, publicKey, keccak256(publicKey), part, parts);
    }

    /// @notice Where (set, pkHash)'s Â stands: None, Committed or Stored. For 87,
    ///         the weaker of its two parts (Stored only once both are; Committed
    ///         once both are at least committed) — see `aPartStatus`.
    function aStatus(ParamSet set, bytes32 pkHash) external view returns (AStatus s) {
        uint256 parts = MLDSAKeys.aPartCount(set);
        if (parts == 0) return AStatus.None;
        s = AStatus.Stored;
        for (uint256 part; part < parts; ++part) {
            AStatus sp = _partStatus(set, pkHash, part, parts);
            if (uint8(sp) < uint8(s)) s = sp;
        }
    }

    /// @notice Where A part `part` of (set, pkHash) stands (None for a part the set
    ///         does not have).
    function aPartStatus(ParamSet set, bytes32 pkHash, uint256 part) external view returns (AStatus) {
        uint256 parts = MLDSAKeys.aPartCount(set);
        if (part >= parts) return AStatus.None;
        return _partStatus(set, pkHash, part, parts);
    }

    /// @notice The committed hash of A part `part` of (set, pkHash); 0 if none (or
    ///         no such part). For 44 / 65, part 0's is keccak256(Â).
    function aPartCommitment(ParamSet set, bytes32 pkHash, uint256 part) external view returns (bytes32) {
        uint256 parts = MLDSAKeys.aPartCount(set);
        if (part >= parts) return 0;
        return aCommitment[_commitKey(set, pkHash, part, parts)];
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

    /// @notice The A (part 0) and T data-contract addresses of (set, pkHash).
    function addressesOf(ParamSet set, bytes32 pkHash) external view returns (address aData, address tData) {
        return MLDSAKeys.addressesOf(address(this), set, pkHash);
    }

    function aPartAddress(ParamSet set, bytes32 pkHash, uint256 part) external view returns (address) {
        return MLDSAKeys.aPartAddress(address(this), set, pkHash, part);
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

    // ── Internals ────────────────────────────────────────────────────────────

    /// @dev aPartCount(set), reverting for an unknown set.
    function _parts(ParamSet set) private pure returns (uint256 parts) {
        parts = MLDSAKeys.aPartCount(set);
        if (parts == 0) revert UnsupportedParamSet();
    }

    /// @dev Records keccak256(precomputeAPart(set, pk, part)) unless already
    ///      committed (then `data` is empty and nothing is recomputed).
    function _commitPart(ParamSet set, bytes calldata publicKey, bytes32 pkHash, uint256 part, uint256 parts)
        private
        returns (bytes32 aHash, bytes memory data)
    {
        bytes32 key = _commitKey(set, pkHash, part, parts);
        aHash = aCommitment[key];
        if (aHash != 0) return (aHash, data);
        data = MLDSA.precomputeAPart(set, publicKey, part);
        if (data.length == 0) revert InvalidPublicKey();
        aHash = keccak256(data);
        aCommitment[key] = aHash;
        if (parts == 1) emit CommittedA(set, pkHash, aHash);
        else emit CommittedAPart(set, pkHash, part, aHash);
    }

    /// @dev Commit (if needed) and deploy A part `part`; a no-op returning the
    ///      address if it is already deployed.
    function _registerPart(ParamSet set, bytes calldata publicKey, bytes32 pkHash, uint256 part, uint256 parts)
        private
        returns (address aData)
    {
        (bytes32 aHash, bytes memory data) = _commitPart(set, publicKey, pkHash, part, parts);
        aData = MLDSAKeys.aPartAddress(address(this), set, pkHash, part);
        if (aData.code.length != 0) return aData;
        // Freshly computed here unless the commitment predates this call.
        if (data.length == 0) data = MLDSA.precomputeAPart(set, publicKey, part);
        assert(keccak256(data) == aHash);
        _deploy(MLDSAKeys.saltAPart(set, pkHash, part), aData, data);
        emit Registered(set, pkHash, aData, true);
    }

    /// @dev Deploys `aPart` as A part `part` at `aData` iff it hashes to the
    ///      commitment; a no-op if something is already deployed there.
    function _storePart(ParamSet set, bytes32 pkHash, uint256 part, address aData, bytes calldata aPart) private {
        if (aData.code.length != 0) return;
        bytes32 aHash = aCommitment[_commitKey(set, pkHash, part, MLDSAKeys.aPartCount(set))];
        if (aHash == 0) revert NotCommitted();
        if (keccak256(aPart) != aHash) revert CommitmentMismatch();
        _deploy(MLDSAKeys.saltAPart(set, pkHash, part), aData, aPart);
        emit Registered(set, pkHash, aData, true);
    }

    function _partStatus(ParamSet set, bytes32 pkHash, uint256 part, uint256 parts) private view returns (AStatus) {
        (uint256 aSize,) = MLDSAKeys.codeSizes(set);
        if (MLDSAKeys.aPartAddress(address(this), set, pkHash, part).code.length == aSize) return AStatus.Stored;
        if (aCommitment[_commitKey(set, pkHash, part, parts)] != 0) return AStatus.Committed;
        return AStatus.None;
    }

    /// @dev Single-part sets: keccak256(abi.encode(set, pkHash)) — unchanged from
    ///      before parts existed. Multi-part sets: keccak256(abi.encode(set,
    ///      pkHash, part)); a 96-byte preimage, so it never equals a 64-byte one.
    function _commitKey(ParamSet set, bytes32 pkHash, uint256 part, uint256 parts) private pure returns (bytes32) {
        if (parts == 1) return keccak256(abi.encode(ParamSet.unwrap(set), pkHash));
        return keccak256(abi.encode(ParamSet.unwrap(set), pkHash, part));
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
