// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

import {MLDSA65} from "./MLDSA65.sol";

/// @title MLDSA65Keys — address derivation and loading for `MLDSA65KeyFactory` data
/// @notice Per key (identified by pkHash = keccak256(pk)) the factory deploys two
///         SSTORE2-style data contracts (runtime = 0x00 ‖ data; the leading STOP
///         makes them uncallable):
///           A contract:  0x00 ‖ Â            (1 + 23,040 bytes)
///           T contract:  0x00 ‖ tr ‖ t̂       (1 + 64 + 4,608 bytes)
///         Both addresses are CREATE2(factory, salt, DATA_INITCODE) with a
///         domain-separated salt of pkHash and a FIXED init code, so they are a pure
///         function of (factory, pkHash): a wallet stores only pkHash and the factory
///         address. The init code carries no data — it fetches its runtime from the
///         factory — so the only way to occupy those addresses is the factory itself,
///         and the factory only ever deploys there what it computed from the key.
library MLDSA65Keys {
    /// @dev Init code of every data contract (22 bytes, PUSH0 = Shanghai+):
    ///        STATICCALL(gas, CALLER, 0, 0, 0, 0)   ask the factory for the runtime
    ///        ISZERO, PUSH1 0x12, JUMPI             factory refused → revert
    ///        RETURNDATACOPY(0, 0, RETURNDATASIZE)
    ///        RETURN(0, RETURNDATASIZE)             runtime = whatever it returned
    ///        JUMPDEST, REVERT(0, 0)
    bytes internal constant DATA_INITCODE = hex"5f5f5f5f335afa156012573d5f5f3e3d5ff35b5f5ffd";
    bytes32 internal constant DATA_INITCODE_HASH = keccak256(DATA_INITCODE);

    uint256 internal constant A_CODE_BYTES = 23041; // 1 + 23,040
    uint256 internal constant T_CODE_BYTES = 4673; //  1 + 64 + 4,608

    function saltA(bytes32 pkHash) internal pure returns (bytes32) {
        return keccak256(abi.encode("MLDSA65.A_hat", pkHash));
    }

    function saltT(bytes32 pkHash) internal pure returns (bytes32) {
        return keccak256(abi.encode("MLDSA65.tr_t_hat", pkHash));
    }

    /// @notice The two data-contract addresses of a key under `factory`.
    function addressesOf(address factory, bytes32 pkHash) internal pure returns (address aData, address tData) {
        aData = _create2Address(factory, saltA(pkHash));
        tData = _create2Address(factory, saltT(pkHash));
    }

    /// @notice tr ‖ Â ‖ t̂ (MLDSA65.BLOB_BYTES) for a registered key; EMPTY if either
    ///         data contract is not deployed (yet) — verification then returns false.
    function load(address factory, bytes32 pkHash) internal view returns (bytes memory blob) {
        (address a, address t) = addressesOf(factory, pkHash);
        // Code at these addresses can only be the factory's (see above); the size
        // check just distinguishes "registered" from "not yet".
        if (a.code.length != A_CODE_BYTES || t.code.length != T_CODE_BYTES) return blob;
        blob = new bytes(MLDSA65.BLOB_BYTES);
        assembly ("memory-safe") {
            let b := add(blob, 0x20)
            extcodecopy(t, b, 1, 64) //                tr
            extcodecopy(a, add(b, 64), 1, 23040) //     Â
            extcodecopy(t, add(b, 23104), 65, 4608) //  t̂
        }
    }

    /// @notice ML-DSA.Verify (empty context) against a key registered at `factory`.
    ///         Never reverts; false for an unregistered key.
    function verify(address factory, bytes32 pkHash, bytes memory message, bytes memory signature)
        internal
        view
        returns (bool)
    {
        return MLDSA65.verifyPrecomputed(load(factory, pkHash), message, signature);
    }

    /// @notice ML-DSA.Verify with a context string against a registered key.
    function verifyWithContext(
        address factory,
        bytes32 pkHash,
        bytes memory ctx,
        bytes memory message,
        bytes memory signature
    ) internal view returns (bool) {
        return MLDSA65.verifyPrecomputedWithContext(load(factory, pkHash), ctx, message, signature);
    }

    function _create2Address(address factory, bytes32 salt) private pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), factory, salt, DATA_INITCODE_HASH)))));
    }
}

/// @title MLDSA65KeyFactory — permissionless on-chain precomputation of ML-DSA-65 keys
/// @notice `registerA(pk)` and `registerT(pk)` (separate transactions, ~equal halves of
///         the work; anyone may call them, for any key) compute Â respectively
///         tr ‖ NTT(t1·2^d) ON-CHAIN from the public key and deploy the data
///         contracts at the addresses `MLDSA65Keys.addressesOf(factory, keccak256(pk))`.
///         Both are idempotent. `verify(pkHash, …)` then needs neither the key nor any
///         trusted input beyond the factory address and pkHash.
/// @dev    Data hand-off: the runtime code is staged in transient storage (EIP-1153)
///         and returned by `fallback` to the one contract under construction, whose
///         fixed init code (MLDSA65Keys.DATA_INITCODE) STATICCALLs back for it.
contract MLDSA65KeyFactory {
    error InvalidPublicKey();
    error DeployFailed();

    event Registered(bytes32 indexed pkHash, address indexed data, bool isAHat);

    // Transient slots: the address allowed to fetch, and the staged code length;
    // code words follow at DATA_SLOT + i.
    uint256 private constant PENDING_SLOT = 0;
    uint256 private constant LEN_SLOT = 1;
    uint256 private constant DATA_SLOT = 2;

    /// @notice Deploys the Â data contract for `publicKey` (≈ ExpandA + 23 KB deposit).
    function registerA(bytes calldata publicKey) external returns (address aData) {
        bytes32 pkHash = keccak256(publicKey);
        (aData,) = MLDSA65Keys.addressesOf(address(this), pkHash);
        if (aData.code.length != 0) return aData;
        bytes memory data = MLDSA65.precomputeA(publicKey);
        if (data.length == 0) revert InvalidPublicKey();
        _deploy(MLDSA65Keys.saltA(pkHash), aData, data);
        emit Registered(pkHash, aData, true);
    }

    /// @notice Deploys the tr ‖ t̂ data contract for `publicKey`.
    function registerT(bytes calldata publicKey) external returns (address tData) {
        bytes32 pkHash = keccak256(publicKey);
        (, tData) = MLDSA65Keys.addressesOf(address(this), pkHash);
        if (tData.code.length != 0) return tData;
        bytes memory data = MLDSA65.precomputeT(publicKey);
        if (data.length == 0) revert InvalidPublicKey();
        _deploy(MLDSA65Keys.saltT(pkHash), tData, data);
        emit Registered(pkHash, tData, false);
    }

    function addressesOf(bytes32 pkHash) external view returns (address aData, address tData) {
        return MLDSA65Keys.addressesOf(address(this), pkHash);
    }

    function isRegistered(bytes32 pkHash) external view returns (bool) {
        return MLDSA65Keys.load(address(this), pkHash).length != 0;
    }

    function load(bytes32 pkHash) external view returns (bytes memory) {
        return MLDSA65Keys.load(address(this), pkHash);
    }

    function verify(bytes32 pkHash, bytes calldata message, bytes calldata signature) external view returns (bool) {
        return MLDSA65Keys.verify(address(this), pkHash, message, signature);
    }

    function verifyWithContext(bytes32 pkHash, bytes calldata ctx, bytes calldata message, bytes calldata signature)
        external
        view
        returns (bool)
    {
        return MLDSA65Keys.verifyWithContext(address(this), pkHash, ctx, message, signature);
    }

    /// @dev Stages 0x00 ‖ data, CREATE2s the fixed init code, checks the result.
    function _deploy(bytes32 salt, address expected, bytes memory data) private {
        bytes memory code = abi.encodePacked(bytes1(0x00), data);
        bytes memory init = MLDSA65Keys.DATA_INITCODE;
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
