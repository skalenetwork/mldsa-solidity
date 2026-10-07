#!/usr/bin/env python3
"""Fixture generator for test/MLDSA.t.sol and MLDSAVerifier.t.sol.

Writes three JSON files next to this script. differential.json and acvp.json
hold one object per parameter set, under the keys "mldsa44" and "mldsa65":

  differential.json  ML-DSA key/message/context/signature tuples produced by
                     dilithium-py 1.4.0 (the version these fixtures were made with;
                     pip install dilithium-py, MIT, a pure-Python
                     FIPS 204 implementation), plus per-vector intermediates
                     (tr, mu, w1Encode(w1'), A_hat[0][0]) so a failing
                     Solidity run can be pinned to one phase. Also a few
                     hand-built malformed signatures (see `malformed`), and the
                     expected `MLDSA.precompute` blob of vector 1 (`blob1`:
                     tr || A_hat || NTT(t1*2^d) mod q, 3 bytes/coef big-endian).
  acvp.json          The sigVer cases from NIST's ACVP-Server, trimmed to the
                     groups the library exposes:
                       external interface, pure (no pre-hash)  -> verifyWithContext
                         ML-DSA-44: tgId 1   ML-DSA-65: tgId 3
                       internal interface, externalMu = false  -> verifyInternal
                         ML-DSA-44: tgId 8   ML-DSA-65: tgId 10
                     Each case keeps tcId, expected result and NIST's reason text.
  shake.json         SHAKE128 / SHAKE256 outputs from hashlib, for testing the
                     Keccak sponge independently of ML-DSA.

The "mldsa65" objects are exactly the contents of the single-set ML-DSA-65
fixtures these files replaced (same seeds, same cases).

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

from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65

ACVP_COMMIT = "a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324"
ACVP_URL = (
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/"
    + ACVP_COMMIT
    + "/gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json"
)
HERE = os.path.dirname(os.path.abspath(__file__))

Q = 8380417

# Per parameter set: the dilithium-py object, FIPS 204 sizes, the precompute
# blob length (64 + k*l*768 + k*768) and the ACVP test groups (external, internal).
SETS = {
    "mldsa44": dict(d=ML_DSA_44, name="ML-DSA-44", pk=1312, sig=2420, blob=15424, tg=(1, 8)),
    "mldsa65": dict(d=ML_DSA_65, name="ML-DSA-65", pk=1952, sig=3309, blob=27712, tg=(3, 10)),
}


def hx(b: bytes) -> str:
    return "0x" + b.hex()


def m_prime(ctx: bytes, msg: bytes) -> bytes:
    return bytes([0, len(ctx)]) + ctx + msg


def intermediates(d, pk: bytes, ctx: bytes, msg: bytes, sig: bytes) -> dict:
    """Re-runs Algorithm 8 step by step with dilithium-py's own internals."""
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
    assert d._h(mu + w1_bytes, d.c_tilde_bytes) == c_tilde
    return {
        "tr": hx(tr),
        "mu": hx(mu),
        "w1": hx(w1_bytes),
        # A_hat[0][0], 256 coefficients as 3-byte big-endian words.
        "a00": hx(b"".join(x.to_bytes(3, "big") for x in a_hat[0, 0].coeffs)),
    }


def precompute_blob(p: dict, pk: bytes) -> bytes:
    """tr || A_hat (k*l polys) || NTT(t1 * 2^d) mod q (k polys); 3-byte BE coefficients."""
    d = p["d"]
    rho, t1 = d._unpack_pk(pk)
    a_hat = d._expand_matrix_from_seed(rho)
    t_hat = t1.scale(1 << d.d).to_ntt()
    pack = lambda poly: b"".join((c % Q).to_bytes(3, "big") for c in poly.coeffs)
    out = d._h(pk, 64)
    out += b"".join(pack(a_hat[i, j]) for i in range(d.k) for j in range(d.l))
    out += b"".join(pack(t_hat[i, 0]) for i in range(d.k))
    assert len(out) == p["blob"]
    return out


def differential(p: dict) -> dict:
    d = p["d"]
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
        pk, sk = d.key_derive(bytes([seed]) * 32)
        sig = d.sign(sk, msg, ctx=ctx, deterministic=True)
        assert d.verify(pk, msg, sig, ctx=ctx)
        assert len(pk) == p["pk"] and len(sig) == p["sig"]
        inter = intermediates(d, pk, ctx, msg, sig)
        for k, v in (("pk", pk), ("ctx", ctx), ("msg", msg), ("sig", sig)):
            out[k].append(hx(v))
        for k, v in inter.items():
            out[k].append(v)
    return out


def hint_offsets(d, sig: bytes):
    h = sig[-(d.omega + d.k):]
    return list(h[:d.omega]), list(h[d.omega:])


def malformed(d, pk: bytes, msg: bytes, sig: bytes) -> dict:
    """Signatures whose hint encoding FIPS 204 Algorithm 21 rejects.

    `duplicate`: one hint index repeated within a row (all later row offsets
    bumped by one). The decoded hint vector is IDENTICAL to the valid one, so
    the rest of verification would succeed: only the strict "y[Index-1] >=
    y[Index] -> reject" rule catches it. dilithium-py 1.4.0 only rejects strictly
    DECREASING indices and therefore accepts this signature (recorded below as
    `dilithiumPyAccepts`); FIPS 204 requires rejection (strong unforgeability).
    """
    idx, offs = hint_offsets(d, sig)
    total = offs[-1]
    assert total < d.omega, "need room for one more hint index"
    # Pick the first non-empty row.
    row = next(i for i in range(d.k) if offs[i] > (offs[i - 1] if i else 0))
    start = offs[row - 1] if row else 0
    dup_at = start  # duplicate the row's first index
    new_idx = idx[:dup_at + 1] + idx[dup_at:total]
    new_idx += [0] * (d.omega - len(new_idx))
    new_offs = [o + 1 if i >= row else o for i, o in enumerate(offs)]
    dup = sig[: -(d.omega + d.k)] + bytes(new_idx) + bytes(new_offs)
    assert len(dup) == len(sig)
    return {
        "duplicate": hx(dup),
        "dilithiumPyAccepts": bool(d.verify(pk, msg, dup)),
        "pk": hx(pk),
        "msg": hx(msg),
        "sig": hx(sig),
    }


def acvp(p: dict, src: dict) -> dict:
    d = p["d"]
    groups = {g["tgId"]: g for g in src["testGroups"]}
    out = {}
    for tg, name, iface in ((p["tg"][0], "external", "external"), (p["tg"][1], "internal", "internal")):
        g = groups[tg]
        assert g["parameterSet"] == p["name"] and g["signatureInterface"] == iface
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
                got = d.verify(pk, msg, sig, ctx=ctx)
            else:
                got = d._verify_internal(pk, msg, sig)
            assert got == t["testPassed"], (tg, t["tcId"])
            rows["tcId"].append(t["tcId"])
            rows["pk"].append(hx(pk))
            rows["msg"].append(hx(msg))
            rows["ctx"].append(hx(ctx))
            rows["sig"].append(hx(sig))
            rows["passed"].append(t["testPassed"])
            rows["reason"].append(t["reason"])
        out[name] = rows
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
    src = json.load(open(ip))
    diffs, acvps = {}, {"source": ACVP_URL}
    for key, p in SETS.items():
        diff = differential(p)
        pk, msg, sig = (bytes.fromhex(diff[k][1][2:]) for k in ("pk", "msg", "sig"))
        diff["malformed"] = malformed(p["d"], pk, msg, sig)
        diff["blob1"] = hx(precompute_blob(p, pk))
        diffs[key] = diff
        acvps[key] = acvp(p, src)
    for name, obj in (("differential", diffs), ("acvp", acvps), ("shake", shake())):
        with open(os.path.join(HERE, name + ".json"), "w") as f:
            json.dump(obj, f, indent=1)
            f.write("\n")
    if len(sys.argv) == 1:
        os.remove(ip)
    for key in SETS:
        print(key, "ok; dilithium-py accepts duplicate-index hint:", diffs[key]["malformed"]["dilithiumPyAccepts"])


if __name__ == "__main__":
    main()
