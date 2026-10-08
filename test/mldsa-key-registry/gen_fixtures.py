#!/usr/bin/env python3
"""Fixture generator for test/MLDSAKeyRegistry.t.sol.

Seven deterministic ML-DSA keys and the signatures three ids need:
  - keyId  (salt 1): key 0 (ML-DSA-44) -> key 1 (ML-DSA-65) -> key 2 (ML-DSA-44);
  - keyId2 (salt 2): key 3 (ML-DSA-44) -> key 4 (ML-DSA-87) -> key 5 (ML-DSA-65),
    a rotation into ML-DSA-87 and one out of it;
  - keyId3 (salt 3): key 4 (ML-DSA-87) registered directly -> key 6 (ML-DSA-87), the most
    expensive rotation there is (an ML-DSA-87 signature checked, an ML-DSA-87 key stored). The EIP-712
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

from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

HERE = os.path.dirname(os.path.abspath(__file__))
CAST = shutil.which("cast") or os.path.expanduser("~/.foundry/bin/cast")

CHAIN_ID = 31337
REGISTRY = "0x000000000000000000000000000000000000C0DE"
REGISTRANT = "0x00000000000000000000000000000000000A11CE"
SALT = "0x" + "00" * 31 + "01"
SALT2 = "0x" + "00" * 31 + "02"
SALT3 = "0x" + "00" * 31 + "03"
MESSAGE = bytes(range(32))

SETS = {0: ML_DSA_44, 1: ML_DSA_65, 2: ML_DSA_87}


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
    for i, s in enumerate((0, 1, 0, 0, 2, 1, 2)):
        pk, sk = SETS[s]._keygen_internal(bytes([0xA0 + i]) * 32)
        keys.append((s, pk, sk))

    key_id = keccak(encode("f(address,bytes32)", REGISTRANT, SALT))
    key_id2 = keccak(encode("f(address,bytes32)", REGISTRANT, SALT2))
    key_id3 = keccak(encode("f(address,bytes32)", REGISTRANT, SALT3))

    def sign(i, message):
        s, _, sk = keys[i]
        return SETS[s].sign(sk, message, deterministic=True)

    d1 = rotation_digest(key_id, 1, keys[1][0], keys[1][1])
    d2 = rotation_digest(key_id, 2, keys[2][0], keys[2][1])
    d21 = rotation_digest(key_id2, 1, keys[4][0], keys[4][1])  # 44 -> 87, signed by key 3
    d22 = rotation_digest(key_id2, 2, keys[5][0], keys[5][1])  # 87 -> 65, signed by key 4
    d31 = rotation_digest(key_id3, 1, keys[6][0], keys[6][1])  # 87 -> 87, signed by key 4

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
        "salt2": SALT2,
        "salt3": SALT3,
        "keyId2": key_id2,
        "keyId3": key_id3,
        "set3": keys[3][0],
        "set4": keys[4][0],
        "set5": keys[5][0],
        "set6": keys[6][0],
        "pk3": "0x" + keys[3][1].hex(),
        "pk4": "0x" + keys[4][1].hex(),
        "pk5": "0x" + keys[5][1].hex(),
        "pk6": "0x" + keys[6][1].hex(),
        "digestRotate21": "0x" + d21.hex(),
        "digestRotate22": "0x" + d22.hex(),
        "digestRotate31": "0x" + d31.hex(),
        "sigRotate21": "0x" + sign(3, d21).hex(),
        "sigRotate22": "0x" + sign(4, d22).hex(),
        "sigRotate31": "0x" + sign(4, d31).hex(),
        "sigMessage4": "0x" + sign(4, MESSAGE).hex(),
        "sigMessage5": "0x" + sign(5, MESSAGE).hex(),
    }
    for name, (i, m) in {"sigRotate1": (0, d1), "sigRotate2": (1, d2), "sigMessage0": (0, MESSAGE),
                         "sigMessage2": (2, MESSAGE), "sigRotate21": (3, d21), "sigRotate22": (4, d22),
                         "sigRotate31": (4, d31), "sigMessage4": (4, MESSAGE),
                         "sigMessage5": (5, MESSAGE)}.items():
        s, pk, _ = keys[i]
        assert SETS[s].verify(pk, m, bytes.fromhex(out[name][2:])), name

    with open(os.path.join(HERE, "fixtures.json"), "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")


if __name__ == "__main__":
    main()
