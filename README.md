# mldsa-solidity

FIPS 204 ML-DSA signature verification in Solidity, for **ML-DSA-44** and **ML-DSA-65**, and
**ML-DSA-87** (NIST category 5) as an opt-in.

It implements ML-DSA.Verify (FIPS 204, Algorithm 3), the *pure* variant rather than
HashML-DSA. Messages go through the external interface with a context string (empty by default),
and SHAKE128 and SHAKE256 are built on a Keccak-f[1600] permutation written in Yul. Malformed
input of any kind (wrong lengths, a bad hint encoding, `z` out of range) makes verification
return `false`, never revert.

The verifier answers through two interfaces: its own `IMLDSAVerifier`, and the scheme-neutral
[`IPQVerifier`](https://github.com/skalenetwork/pq-verifier-interface) shared with the SLH-DSA
and FN-DSA verifiers, so a caller can switch scheme without changing code. `MLDSAKeyRegistry`
gives keys stable ids that the key itself can rotate.

> **Unaudited.** This is new cryptographic code. It passes the NIST ACVP vectors and agrees with
> an independent implementation (below), but no third party has reviewed it.

## Contracts

| | What it is |
|---|---|
| `IMLDSAVerifier` | The one interface callers depend on: `verify(set, publicKey, message, signature)` and `supportsParamSet(set)`, plus ERC-165. A parameter set is a `uint8` (`0` = ML-DSA-44, `1` = ML-DSA-65, `2` = ML-DSA-87). Taking the raw public key keeps a future EIP-8051 precompile adapter a drop-in. |
| `IPQVerifier` | The scheme-neutral interface from [pq-verifier-interface](https://github.com/skalenetwork/pq-verifier-interface) (a submodule): `verify(algorithm, publicKey, message, signature)` and `supportsAlgorithm(algorithm)`, ERC-165 id `0x97b4ac55`. Algorithm ids come from its `PQAlgorithms`: `0x0101` ML-DSA-44, `0x0102` ML-DSA-65, `0x0103` ML-DSA-87. |
| `MLDSAVerifier` | The implementation of both interfaces. If the key's precomputed data is registered with the factory, it takes the fast path; otherwise it verifies from scratch. Precomputation is only an optimisation; both paths give identical answers. Through `IPQVerifier` it accepts exactly the three ML-DSA ids, mapped to parameter sets 0, 1 and 2, with the same pure, empty-context verification; any other id (including `0`, `1` and `2`, and every SLH-DSA or FN-DSA id) is `false`. `supportsInterface` is true for `IMLDSAVerifier`, `IPQVerifier` and ERC-165. |
| `MLDSAKeyRegistry` | Stable key ids for ML-DSA keys of all three sets. An id is `keccak256(registrant, salt)`; its registrant chooses the first key and keeps no power over it afterwards. `rotate` replaces the key with a new one (of any set), authorised by an EIP-712 signature from the *current* key over the id, the version being replaced, the new set and the new key's hash, so each rotation signature works once. `verify(keyId, message, signature)` checks against the key currently behind the id. |
| `MLDSAKeyFactory` / `MLDSAKeys` | Permissionless per-key precomputation. `registerA` computes `Â` from the key, and `registerT` computes `tr` and `NTT(t1·2^d)`. Each lands in a data contract at a CREATE2 address that depends only on the factory, the parameter set and `keccak256(pk)`, and only the factory can fill it. A caller therefore trusts the data by address and stores just the key hash. `commitA` and `storeA` split `registerA` in two (compute and commit a hash, then store on first use), so setting up a key fits easily in one transaction. ML-DSA-87's `Â` is over the 24,576-byte code limit, so it is stored in two parts (rows 0–3 and 4–7) with a commitment each: `registerAPart` and `storeAPart` handle one part per transaction, `commitA` commits both, and the fast path needs both. |
| `MLDSAPublicKeys` | Stores a public key as contract code (written once, read with `EXTCODECOPY`). |
| `MLDSA` | The library underneath: verification, precomputation and the Keccak/SHAKE/NTT primitives. |

## Quickstart

```
forge install skalenetwork/mldsa-solidity
```

`remappings.txt` (OpenZeppelin and pq-verifier-interface are this library's own submodules):

```
mldsa-solidity/=lib/mldsa-solidity/src/
pq-verifier-interface/=lib/mldsa-solidity/lib/pq-verifier-interface/src/
@openzeppelin/contracts/=lib/mldsa-solidity/lib/openzeppelin-contracts/contracts/
```

```solidity
import {IMLDSAVerifier, ML_DSA_44} from "mldsa-solidity/IMLDSAVerifier.sol";
import {IPQVerifier} from "pq-verifier-interface/IPQVerifier.sol";
import {PQAlgorithms} from "pq-verifier-interface/PQAlgorithms.sol";

// Either interface, same answer (the verifier address is fixed at construction):
bool ok = IMLDSAVerifier(verifier).verify(ML_DSA_44, publicKey, abi.encodePacked(digest), signature);
bool same = IPQVerifier(verifier).verify(PQAlgorithms.ML_DSA_44, publicKey, abi.encodePacked(digest), signature);
```

Deploy `MLDSAKeyFactory` once and `MLDSAVerifier` with the factory's address; register each key
with the factory for the fast path.

Callers should sign a 32-byte digest (an EIP-712 hash, for example). Verification cost grows
with message length, by about 89k gas per extra 136 bytes. This matters most for ML-DSA-87:
a 3,000-byte message verified without precomputation costs 16.30M gas as a transaction, within
about 0.5M of the cap.

## Gas

Measured with `forge test` at 32-byte messages. The verify rows are calls through
`IMLDSAVerifier`; the others are factory calls. The same verification through `IPQVerifier`
costs 144 to 184 gas more (mapping the algorithm id).

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

`MLDSAKeyRegistry.rotate` verifies one signature by the current key and stores the new key as
code. Its most expensive case, an ML-DSA-87 key rotating to another ML-DSA-87 key, costs
15.13M gas as a transaction when the current key is not precomputed (1.65M under the cap) and
6.42M when it is.

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
- **IPQVerifier.** Every ACVP and differential vector also goes through `IPQVerifier`, on the
  fast path and the fallback, and must give the same result as `IMLDSAVerifier` and the library.
  A valid signature is accepted only under its own algorithm id; unknown ids, other families,
  and fuzzed ids and bytes are `false`, never a revert; ERC-165 ids are checked.
- **Key registry.** Registration, rotation chains across all three sets (44 → 65 → 44,
  44 → 87 → 65, 87 → 87), replayed or misbound rotation signatures, and wrong key lengths, on
  fixtures from dilithium-py (`test/mldsa-key-registry/gen_fixtures.py`).
- **Two-part storage (ML-DSA-87).** Per-part commitments, wrong or swapped part bytes,
  verification falling back with identical results while only one part is stored, and part
  addresses that only the factory can fill.

## Origin

Written for [Fermion](https://github.com/skalenetwork/fermionwallet), the hybrid ECDSA + ML-DSA
wallet and Safe guard, and split out so other projects can use it.

## License

MIT, see [LICENSE](LICENSE).
