# Changelog

## v1.0.0 — 2026-10-08

First release.

- **ML-DSA verification** (FIPS 204 ML-DSA.Verify, Algorithm 3, the pure variant with the empty
  context through the interfaces) for **ML-DSA-44**, **ML-DSA-65** and **ML-DSA-87**, in pure
  Solidity with a Yul Keccak-f[1600]. Malformed input of any kind returns `false`, never reverts.
- **`IMLDSAVerifier`**: `verify(ParamSet, publicKey, message, signature)` and
  `supportsParamSet`, with `ParamSet` a `uint8` (0 = ML-DSA-44, 1 = ML-DSA-65, 2 = ML-DSA-87),
  plus ERC-165.
- **`IPQVerifier`** from [pq-verifier-interface](https://github.com/skalenetwork/pq-verifier-interface)
  (a submodule, remapped as `pq-verifier-interface/`): `MLDSAVerifier` also answers
  `verify(algorithm, ...)` for the `PQAlgorithms` ids `0x0101`, `0x0102` and `0x0103`, with the
  same result as `IMLDSAVerifier`; every other id is `false`. ERC-165 id `0x97b4ac55`.
- **`MLDSAKeyFactory`**: permissionless per-key precomputation (`registerA`, `commitA` /
  `storeA`, `registerT`) in data contracts at CREATE2 addresses only the factory can fill, so
  callers trust them by address. ML-DSA-87's `Â` is stored in two parts (`registerAPart`,
  `storeAPart`) to fit the code-size limit and the per-transaction gas cap.
- **`MLDSAVerifier`**: the fast path for precomputed keys (2.69M / 3.68M / 5.39M gas for
  44 / 65 / 87) and a full fallback for any other key (5.76M / 9.15M / 14.09M), with identical
  answers.
- **`MLDSAKeyRegistry`**: stable key ids, `keccak256(registrant, salt)`, for keys of all three
  sets; the current key rotates the id to a new key (of any set) with an EIP-712 signature that
  works once. The most expensive rotation, ML-DSA-87 to ML-DSA-87 without precomputation, is
  15.13M gas as a transaction, under the EIP-7825 cap.
- **`MLDSAPublicKeys`**: a public key kept as contract code.
- **Tests**: NIST ACVP `ML-DSA-sigVer-FIPS204` vectors for all three sets, differential vectors
  from dilithium-py 1.4.0, every vector through both interfaces on both paths, negative,
  cross-set and fuzz tests, and gas against the 2^24 cap.
- **Not audited.** This is new cryptographic code that no third party has reviewed.
