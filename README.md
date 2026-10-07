# mldsa-solidity

FIPS 204 ML-DSA signature verification in Solidity, for **ML-DSA-44** and **ML-DSA-65**.

It implements ML-DSA.Verify (FIPS 204, Algorithm 3), the *pure* variant rather than
HashML-DSA. Messages go through the external interface with a context string (empty by default),
and SHAKE128 and SHAKE256 are built on a Keccak-f[1600] permutation written in Yul. Malformed
input of any kind (wrong lengths, a bad hint encoding, `z` out of range) makes verification
return `false`, never revert.

> **Unaudited.** This is new cryptographic code. It passes the NIST ACVP vectors and agrees with
> an independent implementation (below), but no third party has reviewed it.

## Contracts

| | What it is |
|---|---|
| `IMLDSAVerifier` | The one interface callers depend on: `verify(set, publicKey, message, signature)` and `supportsParamSet(set)`, plus ERC-165. A parameter set is a `uint8` (`0` = ML-DSA-44, `1` = ML-DSA-65). Taking the raw public key keeps a future EIP-8051 precompile adapter a drop-in. |
| `MLDSAVerifier` | The implementation. If the key's precomputed data is registered with the factory, it takes the fast path; otherwise it verifies from scratch. Precomputation is only an optimisation; both paths give identical answers. |
| `MLDSAKeyFactory` / `MLDSAKeys` | Permissionless per-key precomputation. `registerA` computes `Â` from the key, and `registerT` computes `tr` and `NTT(t1·2^d)`. Each lands in a data contract at a CREATE2 address that depends only on the factory, the parameter set and `keccak256(pk)`, and only the factory can fill it. A caller therefore trusts the data by address and stores just the key hash. `commitA` and `storeA` split `registerA` in two (compute and commit a hash, then store on first use), so setting up a key fits easily in one transaction. |
| `MLDSAPublicKeys` | Stores a public key as contract code (written once, read with `EXTCODECOPY`). |
| `MLDSA` | The library underneath: verification, precomputation and the Keccak/SHAKE/NTT primitives. |

Callers should sign a 32-byte digest (an EIP-712 hash, for example). Verification cost grows
with message length, by about 89k gas per extra 136 bytes.

## Gas

Measured with `forge test` at 32-byte messages.

| | ML-DSA-44 | ML-DSA-65 |
|---|---|---|
| Verify, key registered (through `IMLDSAVerifier`) | 2.68M | 3.66M |
| Verify, key not registered (full computation) | 5.75M | 9.13M |
| `registerA` / `registerT` | 5.54M / 2.29M | 10.59M / 3.38M |
| `commitA` / `storeA` | 2.88M / 2.88M | 5.63M / 5.34M |

All of these fit under the EIP-7825 per-transaction cap of 2^24 gas.

## Testing

```
forge test
```

- **NIST ACVP.** The `ML-DSA-sigVer-FIPS204` vectors for both parameter sets, pinned at
  `usnistgov/ACVP-Server@a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324`. Both the external
  (pure) and the internal interface groups are included, with passing and failing cases.
- **Differential.** Vectors from [dilithium-py](https://github.com/GiacomoPope/dilithium-py)
  1.4.0, including contexts, intermediate values and the precomputed data, byte for byte.
  `test/mldsa/gen_vectors.py` regenerates every fixture.
- **One known disagreement with dilithium-py, where FIPS 204 sides with this library.**
  dilithium-py accepts a repeated hint index within a row, which FIPS 204 Algorithm 21 forbids.
  This library rejects it.
- **Negative and cross-set tests.** Bit flips, wrong lengths, every hint-encoding rule, the
  exact `‖z‖∞` boundary, fuzzing, and keys used under the wrong parameter set.

## Origin

Written for [Fermion](https://github.com/skalenetwork/fermionwallet), the hybrid ECDSA + ML-DSA
wallet and Safe guard, and split out so other projects can use it.

## License

MIT, see [LICENSE](LICENSE).
