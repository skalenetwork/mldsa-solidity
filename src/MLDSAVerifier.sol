// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC165 as IPQERC165} from "pq-verifier-interface/IERC165.sol";
import {IPQVerifier} from "pq-verifier-interface/IPQVerifier.sol";
import {PQAlgorithms} from "pq-verifier-interface/PQAlgorithms.sol";

import {IMLDSAVerifier, ParamSet, ML_DSA_44, ML_DSA_65, ML_DSA_87} from "./IMLDSAVerifier.sol";
import {MLDSA} from "./MLDSA.sol";
import {MLDSAKeys} from "./MLDSAKeyFactory.sol";

/// @title MLDSAVerifier — this repository's IMLDSAVerifier and IPQVerifier, in pure Solidity
/// @notice ML-DSA-44, ML-DSA-65 and ML-DSA-87 (FIPS 204 pure ML-DSA.Verify, empty
///         context). For a key whose per-key data is in the (immutable) `FACTORY`
///         under the given set — all its data contracts deployed (T and every A
///         part: one for 44 / 65, two for 87) — it verifies against that
///         precomputation (fast path); for any other key it runs the full
///         verification from the key itself (fallback). Precomputation is purely a
///         gas optimization: both paths compute the same function, so the answer
///         never depends on whether, or by whom, a key was registered.
///
///         Two interfaces, one function behind them: `IMLDSAVerifier` takes a
///         `ParamSet` (0 / 1 / 2), and the scheme-neutral `IPQVerifier` takes a
///         `PQAlgorithms` id (0x0101 / 0x0102 / 0x0103 for ML-DSA-44 / 65 / 87). Both
///         are pure ML-DSA.Verify with the empty context and give the same answer for
///         the same key, message and signature. Every other algorithm id is `false`.
///
///         Callers take this contract's address at construction and never change
///         it (see IMLDSAVerifier); a different verifier means new callers.
/// @dev    Never reverts on any input (barring out-of-gas): an unsupported set or
///         a wrongly-sized key is `false` before anything else happens. The fast
///         path trusts the factory's data contracts only because they live at
///         CREATE2 addresses that nobody but `FACTORY` can occupy, and `FACTORY`
///         only fills them with what it computed from (or committed to for) the
///         key with this keccak256 under this set (see MLDSAKeyFactory).
contract MLDSAVerifier is IMLDSAVerifier, IPQVerifier {
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
        return _verify(set, publicKey, message, signature);
    }

    /// @inheritdoc IPQVerifier
    /// @dev    0x0101 / 0x0102 / 0x0103 are ParamSet 0 / 1 / 2. Note that the ids are not
    ///         ParamSets: `verify(0, …)`, an SLH-DSA or FN-DSA id, or any other value is false.
    function verify(uint256 algorithm, bytes calldata publicKey, bytes calldata message, bytes calldata signature)
        external
        view
        returns (bool)
    {
        (bool known, ParamSet set) = _paramSetOf(algorithm);
        if (!known) return false;
        return _verify(set, publicKey, message, signature);
    }

    /// @inheritdoc IMLDSAVerifier
    function supportsParamSet(ParamSet set) external pure returns (bool) {
        return MLDSA.supported(set);
    }

    /// @inheritdoc IPQVerifier
    function supportsAlgorithm(uint256 algorithm) external pure returns (bool supported) {
        (supported,) = _paramSetOf(algorithm);
    }

    /// @notice True for IMLDSAVerifier, IPQVerifier (0x97b4ac55) and ERC-165 (0x01ffc9a7).
    function supportsInterface(bytes4 interfaceId) external pure override(IERC165, IPQERC165) returns (bool) {
        return interfaceId == type(IMLDSAVerifier).interfaceId || interfaceId == type(IPQVerifier).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    function _verify(ParamSet set, bytes calldata publicKey, bytes calldata message, bytes calldata signature)
        private
        view
        returns (bool)
    {
        if (publicKey.length != MLDSA.publicKeyBytes(set)) return false; // also: unknown set (0)
        if (signature.length != MLDSA.signatureBytes(set)) return false;
        bytes memory blob = MLDSAKeys.load(FACTORY, set, keccak256(publicKey));
        if (blob.length != 0) return MLDSA.verifyPrecomputed(set, blob, message, signature);
        return MLDSA.verify(set, publicKey, message, signature);
    }

    /// The parameter set a PQAlgorithms id names, if it is one of ML-DSA's three.
    function _paramSetOf(uint256 algorithm) private pure returns (bool known, ParamSet set) {
        if (algorithm == PQAlgorithms.ML_DSA_44) return (true, ML_DSA_44);
        if (algorithm == PQAlgorithms.ML_DSA_65) return (true, ML_DSA_65);
        if (algorithm == PQAlgorithms.ML_DSA_87) return (true, ML_DSA_87);
        return (false, ML_DSA_44);
    }
}
