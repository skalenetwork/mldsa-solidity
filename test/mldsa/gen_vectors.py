#!/usr/bin/env python3
"""Fixture generator for contracts/test/MLDSA65.t.sol.

Writes three JSON files next to this script:

  differential.json  ML-DSA-65 key/message/context/signature tuples produced by
                     dilithium-py 1.4.0 (the version these fixtures were made with;
                     pip install dilithium-py, MIT, a pure-Python
                     FIPS 204 implementation), plus per-vector intermediates
                     (tr, mu, w1Encode(w1'), A_hat[0][0]) so a failing
                     Solidity run can be pinned to one phase. Also a few
                     hand-built malformed signatures (see `malformed`), and the
                     expected `MLDSA65.precompute` blob of vector 1 (`blob1`:
                     tr || A_hat || NTT(t1*2^d) mod q, 3 bytes/coef big-endian).
  acvp.json          The ML-DSA-65 sigVer cases from NIST's ACVP-Server, trimmed
                     to the groups the library exposes:
                       tgId 3  external interface, pure (no pre-hash)  -> verifyWithContext
                       tgId 10 internal interface, externalMu = false  -> verifyInternal
                     Each case keeps tcId, expected result and NIST's reason text.
  shake.json         SHAKE128 / SHAKE256 outputs from hashlib, for testing the
                     Keccak sponge independently of ML-DSA.

ACVP source (pinned; the three files are fetched at this commit):
  https://github.com/usnistgov/ACVP-Server/tree/a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324/gen-val/json-files/ML-DSA-sigVer-FIPS204
  prompt.json / expectedResults.json / internalProjection.json

Usage:  python3 gen_vectors.py [path/to/internalProjection.json]
With no argument the file is downloaded from the pinned commit. Everything is
deterministic: keys come from fixed seeds and signing uses deterministic=True,
so re-running produces byte-identical fixtures.
"""

import hashlib
import json
import os
import sys
import urllib.request

from dilithium_py.ml_dsa import ML_DSA_65

ACVP_COMMIT = "a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324"
ACVP_URL = (
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/"
    + ACVP_COMMIT
    + "/gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json"
)
HERE = os.path.dirname(os.path.abspath(__file__))

Q = 8380417
K, L, OMEGA = 6, 5, 55


def hx(b: bytes) -> str:
    return "0x" + b.hex()


def m_prime(ctx: bytes, msg: bytes) -> bytes:
    return bytes([0, len(ctx)]) + ctx + msg


def intermediates(pk: bytes, ctx: bytes, msg: bytes, sig: bytes) -> dict:
    """Re-runs Algorithm 8 step by step with dilithium-py's own internals."""
    d = ML_DSA_65
    rho, t1 = d._unpack_pk(pk)
    c_tilde, z, h = d._unpack_sig(sig)
    a_hat = d._expand_matrix_from_seed(rho)
    tr = d._h(pk, 64)
    mu = d._h(tr + m_prime(ctx, msg), 64)
    c = d.R.sample_in_ball(c_tilde, d.tau).to_ntt()
    zh = z.to_ntt()
    t1h = t1.scale(1 << d.d).to_ntt()
    w = ((a_hat @ zh) - t1h.scale(c)).from_ntt()
    w1 = h.use_hint(w, 2 * d.gamma_2)
    w1_bytes = w1.bit_pack_w(d.gamma_2)
    assert d._h(mu + w1_bytes, 48) == c_tilde
    return {
        "tr": hx(tr),
        "mu": hx(mu),
        "w1": hx(w1_bytes),
        # A_hat[0][0], 256 coefficients as 3-byte big-endian words.
        "a00": hx(b"".join(x.to_bytes(3, "big") for x in a_hat[0, 0].coeffs)),
    }


def precompute_blob(pk: bytes) -> bytes:
    """tr || A_hat (30 polys) || NTT(t1 * 2^d) mod q (6 polys); 3-byte BE coefficients."""
    d = ML_DSA_65
    rho, t1 = d._unpack_pk(pk)
    a_hat = d._expand_matrix_from_seed(rho)
    t_hat = t1.scale(1 << d.d).to_ntt()
    pack = lambda poly: b"".join((c % Q).to_bytes(3, "big") for c in poly.coeffs)
    out = d._h(pk, 64)
    out += b"".join(pack(a_hat[i, j]) for i in range(K) for j in range(L))
    out += b"".join(pack(t_hat[i, 0]) for i in range(K))
    assert len(out) == 27712
    return out


def differential() -> dict:
    cases = [
        # (key seed byte, ctx, message)
        (1, b"", b""),
        (1, b"", bytes(range(32))),
        (2, b"", hashlib.sha3_256(b"fermion").digest()),
        (2, b"", bytes((i * 7 + 3) & 0xFF for i in range(3000))),
        (3, b"fermion-wallet", bytes(range(32))),
        (3, bytes(range(255)), b"max-length context"),
        (4, b"\x00", b""),
        (5, b"", b"\xff" * 136),  # exactly one SHAKE256 rate block after tr||M'
    ]
    out = {k: [] for k in ("pk", "ctx", "msg", "sig", "tr", "mu", "w1", "a00")}
    for seed, ctx, msg in cases:
        pk, sk = ML_DSA_65.key_derive(bytes([seed]) * 32)
        sig = ML_DSA_65.sign(sk, msg, ctx=ctx, deterministic=True)
        assert ML_DSA_65.verify(pk, msg, sig, ctx=ctx)
        assert len(pk) == 1952 and len(sig) == 3309
        inter = intermediates(pk, ctx, msg, sig)
        for k, v in (("pk", pk), ("ctx", ctx), ("msg", msg), ("sig", sig)):
            out[k].append(hx(v))
        for k, v in inter.items():
            out[k].append(v)
    return out


def hint_offsets(sig: bytes):
    h = sig[-(OMEGA + K):]
    return list(h[:OMEGA]), list(h[OMEGA:])


def malformed(pk: bytes, msg: bytes, sig: bytes) -> dict:
    """Signatures whose hint encoding FIPS 204 Algorithm 21 rejects.

    `duplicate`: one hint index repeated within a row (all later row offsets
    bumped by one). The decoded hint vector is IDENTICAL to the valid one, so
    the rest of verification would succeed: only the strict "y[Index-1] >=
    y[Index] -> reject" rule catches it. dilithium-py 1.4.0 only rejects strictly
    DECREASING indices and therefore accepts this signature (recorded below as
    `dilithiumPyAccepts`); FIPS 204 requires rejection (strong unforgeability).
    """
    idx, offs = hint_offsets(sig)
    total = offs[-1]
    assert total < OMEGA, "need room for one more hint index"
    # Pick the first non-empty row.
    row = next(i for i in range(K) if offs[i] > (offs[i - 1] if i else 0))
    start = offs[row - 1] if row else 0
    dup_at = start  # duplicate the row's first index
    new_idx = idx[:dup_at + 1] + idx[dup_at:total]
    new_idx += [0] * (OMEGA - len(new_idx))
    new_offs = [o + 1 if i >= row else o for i, o in enumerate(offs)]
    dup = sig[: -(OMEGA + K)] + bytes(new_idx) + bytes(new_offs)
    assert len(dup) == len(sig)
    return {
        "duplicate": hx(dup),
        "dilithiumPyAccepts": bool(ML_DSA_65.verify(pk, msg, dup)),
        "pk": hx(pk),
        "msg": hx(msg),
        "sig": hx(sig),
    }


def acvp(path: str) -> dict:
    src = json.load(open(path))
    groups = {g["tgId"]: g for g in src["testGroups"]}
    out = {}
    for tg, name, iface in ((3, "external", "external"), (10, "internal", "internal")):
        g = groups[tg]
        assert g["parameterSet"] == "ML-DSA-65" and g["signatureInterface"] == iface
        if iface == "external":
            assert g["preHash"] == "pure"
        else:
            assert g["externalMu"] is False
        rows = {k: [] for k in ("tcId", "pk", "msg", "ctx", "sig", "passed", "reason")}
        for t in g["tests"]:
            pk, msg, sig = (bytes.fromhex(t[k]) for k in ("pk", "message", "signature"))
            ctx = bytes.fromhex(t.get("context") or "")
            # Cross-check NIST's expectation against the Python reference.
            if iface == "external":
                got = ML_DSA_65.verify(pk, msg, sig, ctx=ctx)
            else:
                got = ML_DSA_65._verify_internal(pk, msg, sig)
            assert got == t["testPassed"], (tg, t["tcId"])
            rows["tcId"].append(t["tcId"])
            rows["pk"].append(hx(pk))
            rows["msg"].append(hx(msg))
            rows["ctx"].append(hx(ctx))
            rows["sig"].append(hx(sig))
            rows["passed"].append(t["testPassed"])
            rows["reason"].append(t["reason"])
        out[name] = rows
    out["source"] = ACVP_URL
    return out


def shake() -> dict:
    lens = [0, 1, 135, 136, 137, 167, 168, 169, 300, 1952]
    out = {"in": [], "s128": [], "s256": [], "k256": []}
    for n in lens:
        data = bytes((i * 31 + n) & 0xFF for i in range(n))
        out["in"].append(hx(data))
        # Squeeze more than one block for both rates.
        out["s128"].append(hx(hashlib.shake_128(data).digest(400)))
        out["s256"].append(hx(hashlib.shake_256(data).digest(300)))
    return out


def main():
    if len(sys.argv) > 1:
        ip = sys.argv[1]
    else:
        ip = os.path.join(HERE, ".internalProjection.json")
        urllib.request.urlretrieve(ACVP_URL, ip)
    diff = differential()
    pk, msg, sig = (bytes.fromhex(diff[k][1][2:]) for k in ("pk", "msg", "sig"))
    diff["malformed"] = malformed(pk, msg, sig)
    diff["blob1"] = hx(precompute_blob(pk))
    for name, obj in (("differential", diff), ("acvp", acvp(ip)), ("shake", shake())):
        with open(os.path.join(HERE, name + ".json"), "w") as f:
            json.dump(obj, f, indent=1)
            f.write("\n")
    if len(sys.argv) == 1:
        os.remove(ip)
    print("ok; dilithium-py accepts duplicate-index hint:", diff["malformed"]["dilithiumPyAccepts"])


if __name__ == "__main__":
    main()
