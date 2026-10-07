# mldsa-solidity

FIPS 204 ML-DSA signature verification in Solidity, for **ML-DSA-44** and **ML-DSA-65**, and
**ML-DSA-87** (NIST category 5) as an opt-in.

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
| `IMLDSAVerifier` | The one interface callers depend on: `verify(set, publicKey, message, signature)` and `supportsParamSet(set)`, plus ERC-165. A parameter set is a `uint8` (`0` = ML-DSA-44, `1` = ML-DSA-65, `2` = ML-DSA-87). Taking the raw public key keeps a future EIP-8051 precompile adapter a drop-in. |
| `MLDSAVerifier` | The implementation. If the key's precomputed data is registered with the factory, it takes the fast path; otherwise it verifies from scratch. Precomputation is only an optimisation; both paths give identical answers. |
| `MLDSAKeyFactory` / `MLDSAKeys` | Permissionless per-key precomputation. `registerA` computes `Â` from the key, and `registerT` computes `tr` and `NTT(t1·2^d)`. Each lands in a data contract at a CREATE2 address that depends only on the factory, the parameter set and `keccak256(pk)`, and only the factory can fill it. A caller therefore trusts the data by address and stores just the key hash. `commitA` and `storeA` split `registerA` in two (compute and commit a hash, then store on first use), so setting up a key fits easily in one transaction. ML-DSA-87's `Â` is over the 24,576-byte code limit, so it is stored in two parts (rows 0–3 and 4–7) with a commitment each: `registerAPart` and `storeAPart` handle one part per transaction, `commitA` commits both, and the fast path needs both. |
| `MLDSAPublicKeys` | Stores a public key as contract code (written once, read with `EXTCODECOPY`). |
| `MLDSA` | The library underneath: verification, precomputation and the Keccak/SHAKE/NTT primitives. |

Callers should sign a 32-byte digest (an EIP-712 hash, for example). Verification cost grows
with message length, by about 89k gas per extra 136 bytes. This matters most for ML-DSA-87:
a 3,000-byte message verified without precomputation costs 16.30M gas as a transaction, within
about 0.5M of the cap.

## Gas

Measured with `forge test` at 32-byte messages. The verify rows are calls through
`IMLDSAVerifier`; the others are factory calls.

| | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| Verify, key registered | 2.69M | 3.68M | 5.39M |
| Verify, key not registered (full computation) | 5.76M | 9.15M | 14.09M |
| `registerA` / `registerT` | 5.54M / 2.29M | 10.59M / 3.38M | 19.09M (9.73M per part as a tx, `registerAPart`) / 4.48M |
| `commitA` / `storeA` | 2.88M / 2.88M | 5.63M / 5.34M | 9.86M / 9.97M (both parts; 5.36M per part as a tx, `storeAPart`) |

Everything here fits under the EIP-7825 per-transaction cap of 2^24 (16.78M) gas. The one
exception is `registerA` for ML-DSA-87 in a single call (19.09M), which is why it has parts. For
ML-DSA-87 as whole transactions (21,000 plus calldata), with headroom under the cap:

| ML-DSA-87 transaction | Gas | Headroom |
|---|---|---|
| Verify, registered, 32 B / 3,000 B message | 5.53M / 7.60M | 11.25M / 9.18M |
| Verify, not registered, 32 B / 3,000 B message | 14.23M / 16.30M | 2.55M / 0.48M |
| Wallet setup: `commitA` + `registerT` + key as code + minimal-proxy wallet | 14.99M | 1.79M |
| First transfer: all of `Â` in calldata, both parts stored, fast verify | 16.30M | 0.48M |
| Later transfer (fast path) | 5.60M | 11.18M |

The first transfer is close to the cap. Either part can instead be stored on its own with
`storeAPart` (5.36M per transaction), permissionlessly and before the first transfer.

## Testing

```
forge test
```

- **NIST ACVP.** The `ML-DSA-sigVer-FIPS204` vectors for all three parameter sets, pinned at
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
- **Two-part storage (ML-DSA-87).** Per-part commitments, wrong or swapped part bytes,
  verification falling back with identical results while only one part is stored, and part
  addresses that only the factory can fill.

## Origin

Written for [Fermion](https://github.com/skalenetwork/fermionwallet), the hybrid ECDSA + ML-DSA
wallet and Safe guard, and split out so other projects can use it.

## License

MIT, see [LICENSE](LICENSE).
