#!/usr/bin/env python3
"""Fixture generator for test/MLDSAKeyRegistry.t.sol.

Three deterministic ML-DSA keys (ML-DSA-44, ML-DSA-65, ML-DSA-44) and the signatures a
rotation chain needs: key 0 hands the id to key 1, key 1 hands it to key 2. The EIP-712
digests are computed here exactly as `MLDSAKeyRegistry.rotationDigest` computes them, for a
registry deployed at REGISTRY on chain CHAIN_ID; the test deploys it at that address.

Needs dilithium-py 1.4.0 (`pip install dilithium-py==1.4.0`) and Foundry's `cast` (for Keccak
and ABI encoding, so the encoding is the EVM's own).

    python3 test/mldsa-key-registry/gen_fixtures.py
"""
import json
import os
import shutil
import subprocess

from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65

HERE = os.path.dirname(os.path.abspath(__file__))
CAST = shutil.which("cast") or os.path.expanduser("~/.foundry/bin/cast")

CHAIN_ID = 31337
REGISTRY = "0x000000000000000000000000000000000000C0DE"
REGISTRANT = "0x00000000000000000000000000000000000A11CE"
SALT = "0x" + "00" * 31 + "01"
MESSAGE = bytes(range(32))

SETS = {0: ML_DSA_44, 1: ML_DSA_65}


def cast(*args):
    return subprocess.run([CAST, *args], check=True, capture_output=True, text=True).stdout.strip()


def keccak(hexdata):
    return cast("keccak", hexdata)


def keccak_text(text):
    return cast("keccak", text)


def encode(sig, *values):
    return cast("abi-encode", sig, *[str(v) for v in values])


def rotation_digest(key_id, version, new_set, new_pk):
    domain_typehash = keccak_text("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    domain = keccak(
        encode(
            "f(bytes32,bytes32,bytes32,uint256,address)",
            domain_typehash,
            keccak_text("MLDSAKeyRegistry"),
            keccak_text("1"),
            CHAIN_ID,
            REGISTRY,
        )
    )
    typehash = keccak_text("RotateKey(bytes32 keyId,uint64 version,uint8 newParamSet,bytes32 newPublicKeyHash)")
    struct = keccak(
        encode("f(bytes32,bytes32,uint64,uint8,bytes32)", typehash, key_id, version, new_set, keccak("0x" + new_pk.hex()))
    )
    return bytes.fromhex(keccak("0x1901" + domain[2:] + struct[2:])[2:])


def main():
    keys = []
    for i, s in enumerate((0, 1, 0)):
        pk, sk = SETS[s]._keygen_internal(bytes([0xA0 + i]) * 32)
        keys.append((s, pk, sk))

    key_id = keccak(encode("f(address,bytes32)", REGISTRANT, SALT))

    def sign(i, message):
        s, _, sk = keys[i]
        return SETS[s].sign(sk, message, deterministic=True)

    d1 = rotation_digest(key_id, 1, keys[1][0], keys[1][1])
    d2 = rotation_digest(key_id, 2, keys[2][0], keys[2][1])

    out = {
        "chainId": CHAIN_ID,
        "registry": REGISTRY,
        "registrant": REGISTRANT,
        "salt": SALT,
        "keyId": key_id,
        "message": "0x" + MESSAGE.hex(),
        "set0": keys[0][0],
        "set1": keys[1][0],
        "set2": keys[2][0],
        "pk0": "0x" + keys[0][1].hex(),
        "pk1": "0x" + keys[1][1].hex(),
        "pk2": "0x" + keys[2][1].hex(),
        "digestRotate1": "0x" + d1.hex(),
        "digestRotate2": "0x" + d2.hex(),
        "sigRotate1": "0x" + sign(0, d1).hex(),
        "sigRotate2": "0x" + sign(1, d2).hex(),
        "sigMessage0": "0x" + sign(0, MESSAGE).hex(),
        "sigMessage2": "0x" + sign(2, MESSAGE).hex(),
    }
    for name, (i, m) in {"sigRotate1": (0, d1), "sigRotate2": (1, d2), "sigMessage0": (0, MESSAGE),
                         "sigMessage2": (2, MESSAGE)}.items():
        s, pk, _ = keys[i]
        assert SETS[s].verify(pk, m, bytes.fromhex(out[name][2:])), name

    with open(os.path.join(HERE, "fixtures.json"), "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")


if __name__ == "__main__":
    main()
