// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @notice An ML-DSA parameter set (FIPS 204, Table 1), as a uint8 id:
///           0  ML-DSA-44  (the default — the zero value)
///           1  ML-DSA-65
///           2  ML-DSA-87  (opt-in: NIST category 5)
///         Any other id is unknown: `supportsParamSet` answers false and `verify` false.
///         A uint8 rather than an enum on purpose: an enum argument outside the
///         declared range makes the ABI decoder REVERT, while an unknown id here is
///         an ordinary "no" — and a later set fits without changing the type or any
///         selector (enums and uint8 encode identically); ML-DSA-87 came in that way.
type ParamSet is uint8;

ParamSet constant ML_DSA_44 = ParamSet.wrap(0);
ParamSet constant ML_DSA_65 = ParamSet.wrap(1);
ParamSet constant ML_DSA_87 = ParamSet.wrap(2);

function _paramSetEq(ParamSet a, ParamSet b) pure returns (bool) {
    return ParamSet.unwrap(a) == ParamSet.unwrap(b);
}

function _paramSetNeq(ParamSet a, ParamSet b) pure returns (bool) {
    return ParamSet.unwrap(a) != ParamSet.unwrap(b);
}

using {_paramSetEq as ==, _paramSetNeq as !=} for ParamSet global;

/// @title IMLDSAVerifier — one swappable ML-DSA signature verifier
/// @notice FIPS 204 ML-DSA.Verify (Algorithm 3), the PURE variant (not HashML-DSA)
///         with the EMPTY context string, for the parameter sets an implementation
///         `supportsParamSet`. The raw public key is an argument on purpose: any verifier
///         — this repository's Solidity `MLDSAVerifier`, or an adapter around a
///         future ML-DSA precompile (EIP-8051 style) — fits this interface unchanged,
///         and how it finds per-key precomputation (if any) is its own business.
///
///         Integration rule: a caller (wallet, guard) takes the verifier address at
///         construction and NEVER changes it. Swapping verifiers means deploying new
///         callers; there is no upgrade or admin path, so no one can point an
///         existing wallet at a verifier that says "yes" to everything.
/// @dev    ERC-165 id: type(IMLDSAVerifier).interfaceId = verify ^ supportsParamSet.
///         (`supports` itself is a reserved word in Solidity.)
interface IMLDSAVerifier is IERC165 {
    /// @notice ML-DSA.Verify(pk, M, σ) with ctx = "" under parameter set `set`.
    ///         Callers should have the device sign a 32-byte digest as M: μ =
    ///         SHAKE256(tr ‖ 0x00 ‖ 0x00 ‖ M) is hashed on-chain, and every further
    ///         136 bytes of M cost one more Keccak-f[1600] (~89k gas in Solidity).
    /// @return True iff σ is a valid signature of `message` under `publicKey`.
    ///         False — never a revert — for an unsupported set, a key or signature
    ///         of the wrong length for `set`, or any malformed or invalid signature.
    function verify(ParamSet set, bytes calldata publicKey, bytes calldata message, bytes calldata signature)
        external
        view
        returns (bool);

    /// @notice Whether `verify` implements parameter set `set`.
    function supportsParamSet(ParamSet set) external view returns (bool);
}
