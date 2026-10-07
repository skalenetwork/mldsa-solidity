// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MLDSAPublicKeys — keep an ML-DSA public key as contract code
/// @notice A 1,312-byte (ML-DSA-44), 1,952-byte (ML-DSA-65) or 2,592-byte (ML-DSA-87)
///         key is far cheaper to keep as the code of a data contract (written once,
///         ~200 gas/byte, read with EXTCODECOPY at 3 gas/word) than in storage (~20k
///         gas per 32 bytes to write, 2.1k per cold word to read). A wallet stores
///         the returned address (e.g. as an immutable) and hands `load(addr)` to
///         IMLDSAVerifier.verify.
/// @dev    SSTORE2 layout: runtime = 0x00 ‖ pk. The leading STOP makes the data
///         contract uncallable, and it is REQUIRED, not cosmetic: pk starts with
///         the random seed ρ, and EIP-3541 rejects new code whose first byte is
///         0xEF — without the prefix `store` would fail for ~1/256 of keys.
///         TRUST: `load` returns whatever code is at the address. The caller must
///         only ever load from an address it obtained from `store` itself (the data
///         contract is immutable; there is no way to change its code later).
library MLDSAPublicKeys {
    error StoreFailed();

    /// @notice Deploys a data contract holding `publicKey`; returns its address.
    ///         Reverts if the deployment fails (setup, not verification).
    function store(bytes memory publicKey) internal returns (address pointer) {
        uint256 n = publicKey.length + 1; // with the 0x00 prefix
        if (n > 24576) revert StoreFailed(); // EIP-170 (also keeps n in PUSH2 range)
        // Init code: PUSH2 n, DUP1, PUSH1 0x0a, RETURNDATASIZE(0), CODECOPY(0, 10, n),
        //            RETURNDATASIZE(0), RETURN(0, n); then the runtime 0x00 ‖ pk.
        bytes memory init = abi.encodePacked(hex"61", uint16(n), hex"80600a3d393df3", hex"00", publicKey);
        assembly ("memory-safe") {
            pointer := create(0, add(init, 0x20), mload(init))
        }
        if (pointer == address(0) || pointer.code.length != n) revert StoreFailed();
    }

    /// @notice The key stored at `pointer` (code minus the 0x00 prefix); empty if
    ///         there is no code there.
    function load(address pointer) internal view returns (bytes memory publicKey) {
        uint256 size = pointer.code.length;
        if (size == 0) return publicKey;
        publicKey = new bytes(size - 1);
        assembly ("memory-safe") {
            extcodecopy(pointer, add(publicKey, 0x20), 1, sub(size, 1))
        }
    }
}
