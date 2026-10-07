// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IMLDSAVerifier, ParamSet} from "./IMLDSAVerifier.sol";
import {MLDSA} from "./MLDSA.sol";
import {MLDSAKeys} from "./MLDSAKeyFactory.sol";

/// @title MLDSAVerifier — this repository's IMLDSAVerifier, in pure Solidity
/// @notice ML-DSA-44 and ML-DSA-65 (FIPS 204 pure ML-DSA.Verify, empty context).
///         For a key whose per-key data is in the (immutable) `FACTORY` under the
///         given set — both data contracts deployed — it verifies against that
///         precomputation (fast path); for any other key it runs the full
///         verification from the key itself (fallback). Precomputation is purely a
///         gas optimization: both paths compute the same function, so the answer
///         never depends on whether, or by whom, a key was registered.
///
///         Callers take this contract's address at construction and never change
///         it (see IMLDSAVerifier); a different verifier means new callers.
/// @dev    Never reverts on any input (barring out-of-gas): an unsupported set or
///         a wrongly-sized key is `false` before anything else happens. The fast
///         path trusts the factory's data contracts only because they live at
///         CREATE2 addresses that nobody but `FACTORY` can occupy, and `FACTORY`
///         only fills them with what it computed from (or committed to for) the
///         key with this keccak256 under this set (see MLDSAKeyFactory).
contract MLDSAVerifier is IMLDSAVerifier {
    /// @notice The key factory consulted for precomputed data (address(0): none —
    ///         every verification takes the full path).
    address public immutable FACTORY;

    constructor(address factory) {
        FACTORY = factory;
    }

    /// @inheritdoc IMLDSAVerifier
    function verify(ParamSet set, bytes calldata publicKey, bytes calldata message, bytes calldata signature)
        external
        view
        returns (bool)
    {
        if (publicKey.length != MLDSA.publicKeyBytes(set)) return false; // also: unknown set (0)
        if (signature.length != MLDSA.signatureBytes(set)) return false;
        bytes memory blob = MLDSAKeys.load(FACTORY, set, keccak256(publicKey));
        if (blob.length != 0) return MLDSA.verifyPrecomputed(set, blob, message, signature);
        return MLDSA.verify(set, publicKey, message, signature);
    }

    /// @inheritdoc IMLDSAVerifier
    function supportsParamSet(ParamSet set) external pure returns (bool) {
        return MLDSA.supported(set);
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IMLDSAVerifier).interfaceId || interfaceId == type(IERC165).interfaceId;
    }
}
