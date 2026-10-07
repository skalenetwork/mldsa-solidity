// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

import {ParamSet, ML_DSA_44, ML_DSA_65, ML_DSA_87} from "../src/IMLDSAVerifier.sol";
import {MLDSA} from "../src/MLDSA.sol";
import {MLDSAKeyFactory, MLDSAKeys} from "../src/MLDSAKeyFactory.sol";

/// Calls the library from a fresh external frame. Gas figures are taken across this
/// call so the quadratic memory-expansion cost starts from zero, as it would in a
/// real transaction (the test contract itself holds ~1 MB of parsed JSON).
contract MLDSAHarness {
    function verify(ParamSet set, bytes calldata pk, bytes calldata m, bytes calldata sig)
        external
        view
        returns (bool)
    {
        return MLDSA.verify(set, pk, m, sig);
    }

    function verifyWithContext(
        ParamSet set,
        bytes calldata pk,
        bytes calldata ctx,
        bytes calldata m,
        bytes calldata sig
    ) external view returns (bool) {
        return MLDSA.verifyWithContext(set, pk, ctx, m, sig);
    }

    function verifyInternal(ParamSet set, bytes calldata pk, bytes calldata mPrime, bytes calldata sig)
        external
        view
        returns (bool)
    {
        return MLDSA.verifyInternal(set, pk, mPrime, sig);
    }

    function precompute(ParamSet set, bytes calldata pk) external pure returns (bytes memory) {
        return MLDSA.precompute(set, pk);
    }

    function precomputeAPart(ParamSet set, bytes calldata pk, uint256 part) external pure returns (bytes memory) {
        return MLDSA.precomputeAPart(set, pk, part);
    }

    function verifyPrecomputedWithContext(
        ParamSet set,
        bytes calldata blob,
        bytes calldata ctx,
        bytes calldata m,
        bytes calldata sig
    ) external view returns (bool) {
        return MLDSA.verifyPrecomputedWithContext(set, blob, ctx, m, sig);
    }

    function verifyPrecomputed(ParamSet set, bytes calldata blob, bytes calldata m, bytes calldata sig)
        external
        view
        returns (bool)
    {
        return MLDSA.verifyPrecomputed(set, blob, m, sig);
    }

    function verifyPrecomputedInternal(ParamSet set, bytes calldata blob, bytes calldata mPrime, bytes calldata sig)
        external
        view
        returns (bool)
    {
        return MLDSA.verifyPrecomputedInternal(set, blob, mPrime, sig);
    }

    /// The consumer pattern: a wallet holds (factory, set, pkHash) and verifies in
    /// its own context through the library.
    function verifyByHash(address factory, ParamSet set, bytes32 pkHash, bytes calldata m, bytes calldata sig)
        external
        view
        returns (bool)
    {
        return MLDSAKeys.verify(factory, set, pkHash, m, sig);
    }

    /// Gas of the load alone and of the verification after it, in one frame.
    function verifyByHashSplit(address factory, ParamSet set, bytes32 pkHash, bytes calldata m, bytes calldata sig)
        external
        view
        returns (uint256 loadGas, uint256 verifyGas, bool ok)
    {
        uint256 t = gasleft();
        bytes memory blob = MLDSAKeys.load(factory, set, pkHash);
        loadGas = t - gasleft();
        t = gasleft();
        ok = MLDSA.verifyPrecomputed(set, blob, m, sig);
        verifyGas = t - gasleft();
    }

    /// verifyPrecomputed re-run phase by phase (same order as `_verifyCore`'s blob
    /// path): [0] decode h + z, [1] ℓ×NTT(z), [2] μ, [3] SampleInBall + NTT(c),
    /// [4] Â∘ẑ from the blob, [5] k×(−ĉ·t̂ from the blob), [6] k×NTT⁻¹,
    /// [7] UseHint + w1Encode, [8] c̃′, [9] total.
    function phasesPrecomputed(ParamSet set, bytes memory blob, bytes memory mPrime, bytes memory sig)
        external
        view
        returns (uint256[10] memory g, bool ok)
    {
        (, MLDSA.Params memory p) = MLDSA.params(set);
        uint256 t0 = gasleft();
        uint256 t = t0;
        (, uint256[8] memory hints) = MLDSA.hintBitUnpack(p, sig);
        uint256 zHat = MLDSA._allocWords(p.l * 256 + 8);
        MLDSA.decodeZ(p, sig, zHat);
        uint256 zp = MLDSA._ptr(MLDSA._zetas());
        (g[0], t) = (t - gasleft(), gasleft());
        for (uint256 j; j < p.l; ++j) {
            MLDSA.ntt(zHat + j * 0x2000, zp);
        }
        (g[1], t) = (t - gasleft(), gasleft());
        uint256 ks = MLDSA.newKeccakWorkspace();
        uint256 w1Len = 64 + p.k * p.w1PolyBytes;
        bytes memory w1Buf = new bytes(w1Len + 32);
        bytes32 tr0;
        bytes32 tr1;
        assembly ("memory-safe") {
            tr0 := mload(add(blob, 0x20))
            tr1 := mload(add(blob, 0x40))
        }
        bytes memory trM = abi.encodePacked(tr0, tr1, mPrime);
        (bytes32 mu0, bytes32 mu1) =
            MLDSA.shake256MuAndBall(ks, MLDSA._ptr(trM), trM.length, MLDSA._ptr(sig), p.cTildeBytes);
        assembly ("memory-safe") {
            mstore(add(w1Buf, 0x20), mu0)
            mstore(add(w1Buf, 0x40), mu1)
        }
        (g[2], t) = (t - gasleft(), gasleft());
        uint256 cHat = MLDSA._allocWords(256);
        MLDSA.sampleInBall(ks, MLDSA._ptr(sig), p.cTildeBytes, p.tau, cHat, 1);
        MLDSA.ntt(cHat, zp);
        (g[3], t) = (t - gasleft(), gasleft());
        uint256 acc = MLDSA._allocStrided(p.k);
        MLDSA.mulPackedA(MLDSA._ptr(blob) + 64, zHat, acc, p.k, p.l);
        (g[4], t) = (t - gasleft(), gasleft());
        _subPackedRows(p.k, acc, cHat, MLDSA._ptr(blob) + 64 + p.aHatBytes);
        (g[5], t) = (t - gasleft(), gasleft());
        _invNttRows(p.k, acc, zp);
        (g[6], t) = (t - gasleft(), gasleft());
        _useHintRows(p, acc, hints, w1Buf);
        (g[7], t) = (t - gasleft(), gasleft());
        (bytes32 c0,) = MLDSA.shake256To64(ks, MLDSA._ptr(w1Buf), w1Len);
        (g[8], t) = (t - gasleft(), gasleft());
        g[9] = t0 - gasleft();
        bytes32 sig0;
        assembly ("memory-safe") {
            sig0 := mload(add(sig, 0x20))
        }
        ok = c0 == sig0;
    }

    /// Algorithm 8 re-run phase by phase with gasleft() checkpoints (same building
    /// blocks, same order as `verifyInternal`, minus the early-exit checks).
    /// [0] decode h + z, [1] ℓ×NTT(z), [2] tr = H(pk), [3] μ, [4] SampleInBall + NTT(c),
    /// [5] fused ExpandA × ẑ (k·ℓ SHAKE128 streams, 4-way), [6] k×(decode t1 + NTT + ĉ·t̂1),
    /// [7] k×NTT⁻¹, [8] UseHint + w1Encode, [9] c̃′ = H(μ ‖ w1), [10] total.
    /// w1Out = w1Encode(w1′) alone.
    function phases(ParamSet set, bytes memory pk, bytes memory mPrime, bytes memory sig)
        external
        view
        returns (uint256[11] memory g, bool ok, bytes memory w1Out)
    {
        (, MLDSA.Params memory p) = MLDSA.params(set);
        uint256 t0 = gasleft();
        uint256 t = t0;
        (, uint256[8] memory hints) = MLDSA.hintBitUnpack(p, sig);
        uint256 zHat = MLDSA._allocWords(p.l * 256 + 8);
        MLDSA.decodeZ(p, sig, zHat);
        uint256 zp = MLDSA._ptr(MLDSA._zetas());
        (g[0], t) = (t - gasleft(), gasleft());
        for (uint256 j; j < p.l; ++j) {
            MLDSA.ntt(zHat + j * 0x2000, zp);
        }
        (g[1], t) = (t - gasleft(), gasleft());
        uint256 ks = MLDSA.newKeccakWorkspace();
        uint256 w1Len = 64 + p.k * p.w1PolyBytes;
        bytes memory w1Buf = new bytes(w1Len + 32);
        (bytes32 tr0, bytes32 tr1) = MLDSA.shake256To64(ks, MLDSA._ptr(pk), pk.length);
        (g[2], t) = (t - gasleft(), gasleft());
        {
            bytes memory trM = abi.encodePacked(tr0, tr1, mPrime);
            (bytes32 mu0, bytes32 mu1) =
                MLDSA.shake256MuAndBall(ks, MLDSA._ptr(trM), trM.length, MLDSA._ptr(sig), p.cTildeBytes);
            assembly ("memory-safe") {
                mstore(add(w1Buf, 0x20), mu0)
                mstore(add(w1Buf, 0x40), mu1)
            }
        }
        (g[3], t) = (t - gasleft(), gasleft());
        uint256 cHat = MLDSA._allocWords(256);
        MLDSA.sampleInBall(ks, MLDSA._ptr(sig), p.cTildeBytes, p.tau, cHat, 1);
        MLDSA.ntt(cHat, zp);
        MLDSA._scale(cHat, 1 << 13);
        (g[4], t) = (t - gasleft(), gasleft());
        uint256 acc = MLDSA._allocStrided(p.k);
        uint256 t1Hat = MLDSA._allocWords(256);
        bytes32 rho;
        assembly ("memory-safe") {
            rho := mload(add(pk, 0x20))
        }
        MLDSA.sampleMatrix(ks, rho, zHat, 0x2000, acc, true, p.k, p.l);
        (g[5], t) = (t - gasleft(), gasleft());
        _subT1Rows(p.k, pk, acc, cHat, t1Hat, zp);
        (g[6], t) = (t - gasleft(), gasleft());
        _invNttRows(p.k, acc, zp);
        (g[7], t) = (t - gasleft(), gasleft());
        _useHintRows(p, acc, hints, w1Buf);
        (g[8], t) = (t - gasleft(), gasleft());
        (bytes32 c0,) = MLDSA.shake256To64(ks, MLDSA._ptr(w1Buf), w1Len);
        (g[9], t) = (t - gasleft(), gasleft());
        g[10] = t0 - gasleft();
        bytes32 sig0;
        assembly ("memory-safe") {
            sig0 := mload(add(sig, 0x20))
        }
        ok = c0 == sig0;
        w1Out = _w1Part(w1Buf, w1Len);
    }

    function _useHintRows(MLDSA.Params memory p, uint256 acc, uint256[8] memory hints, bytes memory w1Buf)
        private
        pure
    {
        for (uint256 i; i < p.k; ++i) {
            MLDSA.useHintPack(p.w1Nibbles, acc + i * 0x2100, hints[i], MLDSA._ptr(w1Buf) + 64 + i * p.w1PolyBytes);
        }
    }

    function _subPackedRows(uint256 k, uint256 acc, uint256 cHat, uint256 tHat) private pure {
        for (uint256 i; i < k; ++i) {
            MLDSA._subProductPacked(acc + i * 0x2100, cHat, tHat + i * 768);
        }
    }

    function _subT1Rows(uint256 k, bytes memory pk, uint256 acc, uint256 cHat, uint256 t1Hat, uint256 zp) private pure {
        for (uint256 i; i < k; ++i) {
            MLDSA.decodeT1(pk, i, t1Hat);
            MLDSA.ntt(t1Hat, zp);
            MLDSA._subProduct(acc + i * 0x2100, cHat, t1Hat);
        }
    }

    function _invNttRows(uint256 k, uint256 acc, uint256 zp) private pure {
        for (uint256 i; i < k; ++i) {
            MLDSA.invNtt(acc + i * 0x2100, zp);
        }
    }

    function _w1Part(bytes memory w1Buf, uint256 w1Len) private pure returns (bytes memory w1Out) {
        w1Out = new bytes(w1Len - 64);
        for (uint256 i; i < w1Out.length; ++i) {
            w1Out[i] = w1Buf[64 + i];
        }
    }

    /// ExpandA alone: the fused Â∘ẑ form (verification) and the materialising form
    /// (precomputeA, z ≡ 1), on a z of all-ones residues.
    function expandAGas(ParamSet set, bytes memory pk) external view returns (uint256 fused, uint256 plain) {
        (, MLDSA.Params memory p) = MLDSA.params(set);
        bytes32 rho;
        assembly ("memory-safe") {
            rho := mload(add(pk, 0x20))
        }
        uint256 ks = MLDSA.newKeccakWorkspace();
        uint256 z = MLDSA._allocWords(p.l * 256 + 8);
        for (uint256 i; i < p.l * 256; ++i) {
            assembly ("memory-safe") {
                mstore(add(z, shl(5, i)), 1)
            }
        }
        uint256 acc = MLDSA._allocStrided(p.k);
        uint256 polys = MLDSA._allocStrided(p.k * p.l);
        uint256 t = gasleft();
        MLDSA.sampleMatrix(ks, rho, z, 0x2000, acc, true, p.k, p.l);
        fused = t - gasleft();
        t = gasleft();
        MLDSA.sampleMatrix(ks, rho, z, 0, polys, false, p.k, p.l);
        plain = t - gasleft();
    }

    /// One Keccak-f[1600], one NTT, one NTT⁻¹ — the unit costs.
    function unitCosts() external view returns (uint256 perm, uint256 fwd, uint256 inv) {
        uint256 ks = MLDSA.newKeccakWorkspace();
        uint256 p = MLDSA._allocWords(256);
        uint256 zp = MLDSA._ptr(MLDSA._zetas());
        uint256 t = gasleft();
        MLDSA.keccakF(ks);
        perm = t - gasleft();
        t = gasleft();
        MLDSA.ntt(p, zp);
        fwd = t - gasleft();
        t = gasleft();
        MLDSA.invNtt(p, zp);
        inv = t - gasleft();
    }
}

/// Minimal consumer exposing only `verify` (both sets), to size the library's inlined code.
contract MLDSAVerifyOnly {
    function verify(ParamSet set, bytes calldata pk, bytes calldata m, bytes calldata sig)
        external
        view
        returns (bool)
    {
        return MLDSA.verify(set, pk, m, sig);
    }
}

/// Minimal consumer of the registered-key path only, for its inlined code size.
contract MLDSAStoredOnly {
    address internal immutable FACTORY;

    constructor(address factory) {
        FACTORY = factory;
    }

    function verify(ParamSet set, bytes32 pkHash, bytes calldata m, bytes calldata sig) external view returns (bool) {
        return MLDSAKeys.verify(FACTORY, set, pkHash, m, sig);
    }
}

/// Deploys the factory's fixed data init code with the factory's own salts — from a
/// different address, so the CREATE2 address cannot coincide.
contract SquatterCreate2 {
    function squat(bytes32 salt) external returns (address a) {
        bytes memory init = MLDSAKeys.DATA_INITCODE;
        assembly ("memory-safe") {
            a := create2(0, add(init, 0x20), mload(init), salt)
        }
    }
}

/// Every test that concerns the scheme runs for EVERY parameter set (the `_44` /
/// `_65` / `_87` variants share one body); fixtures live under ".mldsa44" /
/// ".mldsa65" / ".mldsa87".
contract MLDSATest is Test {
    MLDSAHarness internal h;
    MLDSAKeyFactory internal factory;
    /// One parameter set's differential vectors and geometry.
    struct Fx {
        ParamSet set;
        string key; //          ".mldsa44" / ".mldsa65" / ".mldsa87"
        MLDSA.Params p;
        uint256 y; //           σ offset of the hint encoding: |c̃| + ℓ·zPolyBytes
        bytes[] pk;
        bytes[] msg;
        bytes[] ctx;
        bytes[] sig;
    }

    function setUp() public {
        h = new MLDSAHarness();
        factory = new MLDSAKeyFactory();
    }

    /// Fixtures are read from disk on use, not kept in storage: with ML-DSA-87 they
    /// are ~1.5 MB, and SSTOREing that in setUp exceeds the per-call gas limit.
    function _diff() internal view returns (string memory) {
        return vm.readFile("test/mldsa/differential.json");
    }

    function _acvp() internal view returns (string memory) {
        return vm.readFile("test/mldsa/acvp.json");
    }

    function _fx(ParamSet set) internal view returns (Fx memory f) {
        f.set = set;
        f.key = _jsonKey(set);
        (, f.p) = MLDSA.params(set);
        f.y = f.p.cTildeBytes + f.p.l * f.p.zPolyBytes;
        string memory js = _diff();
        f.pk = vm.parseJsonBytesArray(js, string.concat(f.key, ".pk"));
        f.msg = vm.parseJsonBytesArray(js, string.concat(f.key, ".msg"));
        f.ctx = vm.parseJsonBytesArray(js, string.concat(f.key, ".ctx"));
        f.sig = vm.parseJsonBytesArray(js, string.concat(f.key, ".sig"));
    }

    function _jsonKey(ParamSet set) internal pure returns (string memory) {
        return set == ML_DSA_44 ? ".mldsa44" : set == ML_DSA_65 ? ".mldsa65" : ".mldsa87";
    }

    function _name(ParamSet set) internal pure returns (string memory) {
        return set == ML_DSA_44 ? "ML-DSA-44" : set == ML_DSA_65 ? "ML-DSA-65" : "ML-DSA-87";
    }

    // ── Parameters ───────────────────────────────────────────────────────────

    /// The geometry the code derives from (k, ℓ, τ, ω, |c̃|, …) against FIPS 204's
    /// sizes: |pk| = 32 + 320k, |σ| = |c̃| + ℓ·zPolyBytes + ω + k.
    function test_params() public pure {
        ParamSet[3] memory sets = [ML_DSA_44, ML_DSA_65, ML_DSA_87];
        uint256[3] memory pkLen = [uint256(1312), 1952, 2592];
        uint256[3] memory sigLen = [uint256(2420), 3309, 4627];
        uint256[3] memory parts = [uint256(1), 1, 2];
        for (uint256 n; n < 3; ++n) {
            (bool ok, MLDSA.Params memory p) = MLDSA.params(sets[n]);
            assertTrue(ok);
            assertEq(p.pkBytes, pkLen[n]);
            assertEq(p.sigBytes, sigLen[n]);
            assertEq(32 + 320 * p.k, p.pkBytes);
            assertEq(p.cTildeBytes + p.l * p.zPolyBytes + p.omega + p.k, p.sigBytes);
            assertEq(p.aHatBytes, p.k * p.l * 768);
            assertEq(p.tHatBytes, p.k * 768);
            assertEq(MLDSA.publicKeyBytes(sets[n]), pkLen[n]);
            assertEq(MLDSA.signatureBytes(sets[n]), sigLen[n]);
            assertTrue(MLDSA.supported(sets[n]));
            assertEq(p.aParts, parts[n]);
            assertEq(MLDSAKeys.aPartCount(sets[n]), parts[n]);
            // Every A part fits EIP-170 as 0x00 ‖ part, and a part is whole 4-way
            // ExpandA batches (precomputeAPart relies on it).
            (uint256 aCode, uint256 tCode) = MLDSAKeys.codeSizes(sets[n]);
            assertEq(aCode, 1 + p.aHatBytes / p.aParts);
            assertEq(tCode, 1 + 64 + p.tHatBytes);
            assertLe(aCode, 24576);
            assertEq(p.k % p.aParts, 0);
            if (p.aParts > 1) assertEq((p.k * p.l / p.aParts) % 4, 0);
        }
        // ML-DSA-87 (FIPS 204 Table 1): (k, ℓ) = (8, 7), τ = 60, ω = 75, λ = 256.
        (, MLDSA.Params memory p87) = MLDSA.params(ML_DSA_87);
        assertEq(p87.k, 8);
        assertEq(p87.l, 7);
        assertEq(p87.tau, 60);
        assertEq(p87.omega, 75);
        assertEq(p87.cTildeBytes, 64);
        assertEq(p87.zPolyBytes, 640); // γ1 = 2^19: 20 bits
        assertEq(p87.w1PolyBytes, 128); // γ2 = (q − 1)/32: 4 bits
        assertTrue(p87.w1Nibbles);
        (bool ok3,) = MLDSA.params(ParamSet.wrap(3));
        assertFalse(ok3, "unknown set");
        assertFalse(MLDSA.supported(ParamSet.wrap(3)));
        assertEq(MLDSA.publicKeyBytes(ParamSet.wrap(255)), 0);
        assertEq(MLDSA.signatureBytes(ParamSet.wrap(3)), 0);
        assertEq(MLDSAKeys.aPartCount(ParamSet.wrap(3)), 0);
    }

    // ── Keccak / SHAKE ───────────────────────────────────────────────────────

    /// Keccak-f[1600] against the keccak256 opcode: same permutation, pad byte 0x01.
    function test_keccakF_matchesKeccak256Opcode() public pure {
        uint256[7] memory lens = [uint256(0), 1, 135, 136, 137, 272, 1952];
        for (uint256 n; n < lens.length; ++n) {
            bytes memory data = new bytes(lens[n]);
            for (uint256 i; i < data.length; ++i) {
                data[i] = bytes1(uint8(i * 13 + n));
            }
            assertEq(_keccakViaLib(data), keccak256(data), "keccak256 mismatch");
        }
    }

    /// SHAKE128 / SHAKE256 against hashlib, including multi-block squeezes.
    function test_shake_matchesHashlib() public view {
        string memory js = vm.readFile("test/mldsa/shake.json");
        bytes[] memory ins = vm.parseJsonBytesArray(js, ".in");
        bytes[] memory s128 = vm.parseJsonBytesArray(js, ".s128");
        bytes[] memory s256 = vm.parseJsonBytesArray(js, ".s256");
        for (uint256 n; n < ins.length; ++n) {
            assertEq(_shake(ins[n], 168, s128[n].length), s128[n], "SHAKE128");
            assertEq(_shake(ins[n], 136, s256[n].length), s256[n], "SHAKE256");
        }
    }

    /// μ and SampleInBall computed in one shared final permutation equal the two
    /// computed separately: μ input lengths around the rate (one, two and many
    /// blocks — slot 1 must be cleared) and both c̃ sizes / τ values.
    function test_muAndBall_matchesSeparate() public pure {
        uint256[7] memory lens = [uint256(0), 1, 98, 135, 136, 300, 3000];
        uint256[3] memory cts = [uint256(32), 48, 64];
        uint256[3] memory taus = [uint256(39), 49, 60];
        for (uint256 n; n < lens.length; ++n) {
            bytes memory data = new bytes(lens[n]);
            for (uint256 i; i < data.length; ++i) {
                data[i] = bytes1(uint8(i * 29 + n));
            }
            for (uint256 s; s < 3; ++s) {
                bytes memory ct = new bytes(cts[s]);
                for (uint256 i; i < ct.length; ++i) {
                    ct[i] = bytes1(uint8(i * 7 + n * 3 + s));
                }
                uint256 ks = MLDSA.newKeccakWorkspace();
                (bytes32 m0, bytes32 m1) = MLDSA.shake256To64(ks, MLDSA._ptr(data), data.length);
                uint256 c1 = MLDSA._allocWords(256);
                MLDSA.sampleInBall(ks, MLDSA._ptr(ct), cts[s], taus[s], c1, 0);
                ks = MLDSA.newKeccakWorkspace();
                (bytes32 p0, bytes32 p1) =
                    MLDSA.shake256MuAndBall(ks, MLDSA._ptr(data), data.length, MLDSA._ptr(ct), cts[s]);
                uint256 c2 = MLDSA._allocWords(256);
                MLDSA.sampleInBall(ks, MLDSA._ptr(ct), cts[s], taus[s], c2, 1);
                assertEq(p0, m0, "mu[0..32)");
                assertEq(p1, m1, "mu[32..64)");
                assertEq(keccak256(_words(c1)), keccak256(_words(c2)), "c");
            }
        }
    }

    function _words(uint256 p) internal pure returns (bytes memory b) {
        b = new bytes(0x2000);
        assembly ("memory-safe") {
            mcopy(add(b, 0x20), p, 0x2000)
        }
    }

    // ── Intermediates against dilithium-py ───────────────────────────────────

    function test_intermediates_44() public view {
        _intermediates(ML_DSA_44);
    }

    function test_intermediates_65() public view {
        _intermediates(ML_DSA_65);
    }

    function test_intermediates_87() public view {
        _intermediates(ML_DSA_87);
    }

    /// tr, μ, Â[0][0] and w1Encode(w1′) of every vector.
    function _intermediates(ParamSet set) internal view {
        Fx memory f = _fx(set);
        bytes[] memory trs = vm.parseJsonBytesArray(_diff(), string.concat(f.key, ".tr"));
        bytes[] memory mus = vm.parseJsonBytesArray(_diff(), string.concat(f.key, ".mu"));
        bytes[] memory a00s = vm.parseJsonBytesArray(_diff(), string.concat(f.key, ".a00"));
        bytes[] memory w1s = vm.parseJsonBytesArray(_diff(), string.concat(f.key, ".w1"));
        for (uint256 v; v < f.pk.length; ++v) {
            uint256 ks = MLDSA.newKeccakWorkspace();
            (bytes32 a, bytes32 b) = MLDSA.shake256To64(ks, MLDSA._ptr(f.pk[v]), f.pk[v].length);
            assertEq(abi.encodePacked(a, b), trs[v], "tr");
            bytes memory mPrime = abi.encodePacked(bytes1(0), uint8(f.ctx[v].length), f.ctx[v], f.msg[v]);
            bytes memory trM = abi.encodePacked(a, b, mPrime);
            (a, b) = MLDSA.shake256To64(ks, MLDSA._ptr(trM), trM.length);
            assertEq(abi.encodePacked(a, b), mus[v], "mu");

            // ExpandA check: Â[0][0] is the first 768 bytes of the packed Â.
            assertEq(_slice(h.precompute(set, f.pk[v]), 64, 768), a00s[v], "A_hat[0][0]");

            // UseHint + w1Encode, and the c̃′ recomputation of the phase harness.
            (, bool ok, bytes memory w1) = h.phases(set, f.pk[v], mPrime, f.sig[v]);
            assertEq(w1, w1s[v], "w1Encode(w1')");
            assertTrue(ok, "phase harness reproduces c~");
        }
    }

    // ── Differential vectors (dilithium-py) ──────────────────────────────────

    function test_differential_44() public view {
        _differential(ML_DSA_44);
    }

    function test_differential_65() public view {
        _differential(ML_DSA_65);
    }

    function test_differential_87() public view {
        _differential(ML_DSA_87);
    }

    function _differential(ParamSet set) internal view {
        Fx memory f = _fx(set);
        for (uint256 v; v < f.pk.length; ++v) {
            bool ok = f.ctx[v].length == 0
                ? h.verify(set, f.pk[v], f.msg[v], f.sig[v])
                : h.verifyWithContext(set, f.pk[v], f.ctx[v], f.msg[v], f.sig[v]);
            assertTrue(ok, string.concat("differential vector ", vm.toString(v)));
            bytes memory blob = h.precompute(set, f.pk[v]);
            assertTrue(
                f.ctx[v].length == 0
                    ? h.verifyPrecomputed(set, blob, f.msg[v], f.sig[v])
                    : h.verifyPrecomputedWithContext(set, blob, f.ctx[v], f.msg[v], f.sig[v]),
                string.concat("precomputed, vector ", vm.toString(v))
            );
            assertFalse(h.verifyPrecomputedWithContext(set, blob, hex"01", f.msg[v], f.sig[v]));
            // The context is bound: the same signature under another context fails.
            assertFalse(h.verifyWithContext(set, f.pk[v], hex"01", f.msg[v], f.sig[v]));
        }
        console.log(_name(set), "differential vectors verified:", f.pk.length);
    }

    // ── NIST ACVP sigVer ─────────────────────────────────────────────────────

    function test_acvp_44_external_pure() public view {
        (uint256 pass, uint256 fail) = _runAcvp(ML_DSA_44, ".mldsa44.external", true);
        console.log("ACVP ML-DSA-44 tgId 1 (external, pure): expected-pass ok", pass);
        console.log("ACVP ML-DSA-44 tgId 1 (external, pure): expected-fail ok", fail);
    }

    function test_acvp_44_internal() public view {
        (uint256 pass, uint256 fail) = _runAcvp(ML_DSA_44, ".mldsa44.internal", false);
        console.log("ACVP ML-DSA-44 tgId 8 (internal): expected-pass ok", pass);
        console.log("ACVP ML-DSA-44 tgId 8 (internal): expected-fail ok", fail);
    }

    function test_acvp_65_external_pure() public view {
        (uint256 pass, uint256 fail) = _runAcvp(ML_DSA_65, ".mldsa65.external", true);
        console.log("ACVP ML-DSA-65 tgId 3 (external, pure): expected-pass ok", pass);
        console.log("ACVP ML-DSA-65 tgId 3 (external, pure): expected-fail ok", fail);
    }

    function test_acvp_65_internal() public view {
        (uint256 pass, uint256 fail) = _runAcvp(ML_DSA_65, ".mldsa65.internal", false);
        console.log("ACVP ML-DSA-65 tgId 10 (internal): expected-pass ok", pass);
        console.log("ACVP ML-DSA-65 tgId 10 (internal): expected-fail ok", fail);
    }

    function test_acvp_87_external_pure() public view {
        (uint256 pass, uint256 fail) = _runAcvp(ML_DSA_87, ".mldsa87.external", true);
        console.log("ACVP ML-DSA-87 tgId 5 (external, pure): expected-pass ok", pass);
        console.log("ACVP ML-DSA-87 tgId 5 (external, pure): expected-fail ok", fail);
        assertEq(pass, 3);
        assertEq(fail, 12);
    }

    function test_acvp_87_internal() public view {
        (uint256 pass, uint256 fail) = _runAcvp(ML_DSA_87, ".mldsa87.internal", false);
        console.log("ACVP ML-DSA-87 tgId 12 (internal): expected-pass ok", pass);
        console.log("ACVP ML-DSA-87 tgId 12 (internal): expected-fail ok", fail);
        assertEq(pass, 3);
        assertEq(fail, 12);
    }

    function _runAcvp(ParamSet set, string memory g, bool external_)
        internal
        view
        returns (uint256 pass, uint256 fail)
    {
        string memory acvp = _acvp();
        uint256[] memory ids = vm.parseJsonUintArray(acvp, string.concat(g, ".tcId"));
        bytes[] memory pk = vm.parseJsonBytesArray(acvp, string.concat(g, ".pk"));
        bytes[] memory m = vm.parseJsonBytesArray(acvp, string.concat(g, ".msg"));
        bytes[] memory ctx = vm.parseJsonBytesArray(acvp, string.concat(g, ".ctx"));
        bytes[] memory sig = vm.parseJsonBytesArray(acvp, string.concat(g, ".sig"));
        bool[] memory expected = vm.parseJsonBoolArray(acvp, string.concat(g, ".passed"));
        string[] memory reason = vm.parseJsonStringArray(acvp, string.concat(g, ".reason"));
        assertGt(ids.length, 0, "no ACVP cases");
        for (uint256 n; n < ids.length; ++n) {
            bytes memory blob = h.precompute(set, pk[n]);
            bool got = external_
                ? h.verifyWithContext(set, pk[n], ctx[n], m[n], sig[n])
                : h.verifyInternal(set, pk[n], m[n], sig[n]);
            bool gotPre = external_
                ? h.verifyPrecomputedWithContext(set, blob, ctx[n], m[n], sig[n])
                : h.verifyPrecomputedInternal(set, blob, m[n], sig[n]);
            string memory what = string.concat("tcId ", vm.toString(ids[n]), ": ", reason[n]);
            assertEq(got, expected[n], what);
            assertEq(gotPre, got, string.concat("precomputed != reference, ", what));
            if (expected[n]) ++pass;
            else ++fail;
        }
    }

    // ── Negative tests: each must return false, never revert ─────────────────

    function test_reject_bitFlips_44() public view {
        _rejectBitFlips(ML_DSA_44);
    }

    function test_reject_bitFlips_65() public view {
        _rejectBitFlips(ML_DSA_65);
    }

    function test_reject_bitFlips_87() public view {
        _rejectBitFlips(ML_DSA_87);
    }

    function _rejectBitFlips(ParamSet set) internal view {
        Fx memory f = _fx(set);
        (bytes memory pk, bytes memory m, bytes memory sig) = (f.pk[1], f.msg[1], f.sig[1]);
        uint256 c = f.p.cTildeBytes;
        assertTrue(h.verify(set, pk, m, sig));
        // c̃ (first and last byte), z (first, middle, last byte), h (first and third byte)
        uint256[7] memory sigBits =
            [uint256(0), (c - 1) * 8 + 7, c * 8, 1000 * 8 + 3, (f.y - 1) * 8 + 7, (f.y + 2) * 8, f.y * 8];
        for (uint256 n; n < sigBits.length; ++n) {
            assertFalse(
                h.verify(set, pk, m, _flip(sig, sigBits[n])), string.concat("sig bit ", vm.toString(sigBits[n]))
            );
        }
        // pk: ρ and t1
        assertFalse(h.verify(set, _flip(pk, 0), m, sig), "pk rho");
        assertFalse(h.verify(set, _flip(pk, 33 * 8), m, sig), "pk t1 first");
        assertFalse(h.verify(set, _flip(pk, (pk.length - 1) * 8 + 7), m, sig), "pk t1 last");
        // message
        assertFalse(h.verify(set, pk, _flip(m, 0), sig), "message");
        assertFalse(h.verify(set, pk, abi.encodePacked(m, bytes1(0)), sig), "message extended");
    }

    function test_reject_wrongLengths_44() public view {
        _rejectWrongLengths(ML_DSA_44);
    }

    function test_reject_wrongLengths_65() public view {
        _rejectWrongLengths(ML_DSA_65);
    }

    function test_reject_wrongLengths_87() public view {
        _rejectWrongLengths(ML_DSA_87);
    }

    function _rejectWrongLengths(ParamSet set) internal view {
        Fx memory f = _fx(set);
        (bytes memory pk, bytes memory m, bytes memory sig) = (f.pk[1], f.msg[1], f.sig[1]);
        assertFalse(h.verify(set, _trim(pk, 1), m, sig), "short pk");
        assertFalse(h.verify(set, abi.encodePacked(pk, bytes1(0)), m, sig), "long pk");
        assertFalse(h.verify(set, pk, m, _trim(sig, 1)), "short sig");
        assertFalse(h.verify(set, pk, m, abi.encodePacked(sig, bytes1(0))), "long sig");
        assertFalse(h.verify(set, "", m, sig), "empty pk");
        assertFalse(h.verify(set, pk, m, ""), "empty sig");
        assertFalse(h.verifyWithContext(set, pk, new bytes(256), m, sig), "ctx > 255");
        // Unknown parameter-set ids: false (and empty precomputation), no revert.
        for (uint256 id = 3; id < 256; id += 51) {
            assertFalse(h.verify(ParamSet.wrap(uint8(id)), pk, m, sig), "unknown set");
            assertEq(h.precompute(ParamSet.wrap(uint8(id)), pk).length, 0, "unknown set precompute");
        }
    }

    function test_reject_malformedHints_44() public view {
        _rejectMalformedHints(ML_DSA_44);
    }

    function test_reject_malformedHints_65() public view {
        _rejectMalformedHints(ML_DSA_65);
    }

    function test_reject_malformedHints_87() public view {
        _rejectMalformedHints(ML_DSA_87);
    }

    function _rejectMalformedHints(ParamSet set) internal view {
        Fx memory f = _fx(set);
        (bytes memory pk, bytes memory m, bytes memory sig) = (f.pk[1], f.msg[1], f.sig[1]);
        uint256 y = f.y; // hint encoding offset in σ
        uint256 omega = f.p.omega;
        uint256 k = f.p.k;
        uint256 total = uint8(sig[y + omega + k - 1]);
        assertLt(total, omega, "fixture needs spare hint slots");

        // Hint count > ω: last row end = ω + 1.
        bytes memory s = _copy(sig);
        s[y + omega + k - 1] = bytes1(uint8(omega + 1));
        assertFalse(h.verify(set, pk, m, s), "count > omega");
        // Row ends decreasing.
        s = _copy(sig);
        s[y + omega + 1] = bytes1(uint8(sig[y + omega]) == 0 ? 0 : uint8(sig[y + omega]) - 1);
        if (uint8(sig[y + omega]) > 0) assertFalse(h.verify(set, pk, m, s), "row ends decreasing");
        // Non-zero byte in the unused tail.
        s = _copy(sig);
        s[y + omega - 1] = bytes1(uint8(1));
        assertFalse(h.verify(set, pk, m, s), "non-zero padding");
        // Non-increasing indices: swap the first two of the first row with ≥ 2 hints.
        s = _copy(sig);
        uint256 start;
        bool swapped;
        for (uint256 i; i < k; ++i) {
            uint256 end = uint8(sig[y + omega + i]);
            if (end >= start + 2) {
                (s[y + start], s[y + start + 1]) = (s[y + start + 1], s[y + start]);
                swapped = true;
                break;
            }
            start = end;
        }
        assertTrue(swapped, "fixture has a row with two hints");
        assertFalse(h.verify(set, pk, m, s), "decreasing indices");

        // Repeated index (decodes to the SAME h as the valid signature): FIPS 204
        // rejects it; dilithium-py accepts it (fixture records that).
        bytes memory dup = vm.parseJsonBytes(_diff(), string.concat(f.key, ".malformed.duplicate"));
        // Informational only (a property of the reference, not of this verifier):
        console.log(
            _name(set),
            "dilithium-py accepts it:",
            vm.parseJsonBool(_diff(), string.concat(f.key, ".malformed.dilithiumPyAccepts"))
        );
        assertFalse(h.verify(set, pk, m, dup), "repeated hint index");
        assertFalse(h.verifyPrecomputed(set, h.precompute(set, pk), m, dup), "repeated hint index, precomputed");
    }

    /// ||z||∞ < γ1 − β is strict: raw field r encodes z = γ1 − r; valid iff β < r < 2γ1 − β.
    /// ML-DSA-44: γ1 = 2^17, β = 78 → 78 < r < 262066 (18-bit fields, four per 9 bytes).
    function test_zNormBoundary_44() public pure {
        (, MLDSA.Params memory p) = MLDSA.params(ML_DSA_44);
        uint256[4] memory raws = [uint256(78), 79, 262065, 262066];
        bool[4] memory want = [false, true, true, false];
        for (uint256 pos; pos < 4; ++pos) {
            // the boundary value in each of the four positions of a 9-byte group
            for (uint256 n; n < 4; ++n) {
                bytes memory sig = new bytes(2420);
                for (uint256 c; c < 1024; c += 4) {
                    _putQuad(sig, 32 + (c / 4) * 9, [uint256(1000), 1000, 1000, 1000]);
                }
                uint256[4] memory q = [uint256(1000), 1000, 1000, 1000];
                q[pos] = raws[n];
                _putQuad(sig, 32 + 9 * 100, q);
                uint256 out = MLDSA._allocWords(4 * 256);
                assertEq(MLDSA.decodeZ(p, sig, out), want[n], vm.toString(raws[n]));
            }
        }
    }

    /// ML-DSA-65: γ1 = 2^19, β = 196 → 196 < r < 1048380 (20-bit fields, two per 5 bytes).
    function test_zNormBoundary_65() public pure {
        (, MLDSA.Params memory p) = MLDSA.params(ML_DSA_65);
        uint256[4] memory raws = [uint256(196), 197, 1048379, 1048380];
        bool[4] memory want = [false, true, true, false];
        for (uint256 n; n < 4; ++n) {
            bytes memory sig = new bytes(3309);
            // fill every z coefficient with r = 1000 (in range), then plant raws[n] at coefficient 0
            for (uint256 c; c < 1280; c += 2) {
                _putPair(sig, 48 + (c / 2) * 5, 1000, 1000);
            }
            _putPair(sig, 48, raws[n], 1000);
            uint256 out = MLDSA._allocWords(5 * 256);
            assertEq(MLDSA.decodeZ(p, sig, out), want[n], vm.toString(raws[n]));
        }
    }

    /// ML-DSA-87: γ1 = 2^19 (as 65) but β = 120 → 120 < r < 1048456; z starts at
    /// σ[64] (|c̃| = 64) and spans ℓ = 7 polynomials. Both positions of a 5-byte
    /// pair, in the first and in the last pair of z.
    function test_zNormBoundary_87() public pure {
        (, MLDSA.Params memory p) = MLDSA.params(ML_DSA_87);
        uint256[6] memory raws = [uint256(120), 121, 1048455, 1048456, 196, 1048380];
        bool[6] memory want = [false, true, true, false, true, true]; // 65's bounds are inside 87's
        uint256[2] memory pairs = [uint256(0), 7 * 128 - 1];
        for (uint256 n; n < raws.length; ++n) {
            for (uint256 at; at < 2; ++at) {
                for (uint256 pos; pos < 2; ++pos) {
                    bytes memory sig = new bytes(4627);
                    for (uint256 c; c < 7 * 256; c += 2) {
                        _putPair(sig, 64 + (c / 2) * 5, 1000, 1000);
                    }
                    if (pos == 0) _putPair(sig, 64 + pairs[at] * 5, raws[n], 1000);
                    else _putPair(sig, 64 + pairs[at] * 5, 1000, raws[n]);
                    uint256 out = MLDSA._allocWords(7 * 256 + 8);
                    assertEq(MLDSA.decodeZ(p, sig, out), want[n], vm.toString(raws[n]));
                }
            }
        }
        // The planted value lands where it should: residue q + γ1 − r.
        bytes memory s2 = new bytes(4627);
        for (uint256 c; c < 7 * 256; c += 2) {
            _putPair(s2, 64 + (c / 2) * 5, 121 + c, 1048455 - c);
        }
        uint256 o2 = MLDSA._allocWords(7 * 256 + 8);
        assertTrue(MLDSA.decodeZ(p, s2, o2));
        for (uint256 c; c < 7 * 256; c += 2) {
            uint256 g0;
            uint256 g1;
            uint256 at0 = o2 + c * 32;
            assembly ("memory-safe") {
                g0 := mload(at0)
                g1 := mload(add(at0, 0x20))
            }
            assertEq(g0, 8904705 - (121 + c));
            assertEq(g1, 8904705 - (1048455 - c));
        }
    }

    /// The 18-bit unpacking itself, against values planted at every position of a
    /// group: the residues come out as q + γ1 − r.
    function test_decodeZ44_values() public pure {
        (, MLDSA.Params memory p) = MLDSA.params(ML_DSA_44);
        bytes memory sig = new bytes(2420);
        for (uint256 g; g < 256; ++g) {
            uint256 b = g * 1000 + 79;
            _putQuad(sig, 32 + g * 9, [b, b + 1, b + 2, (b * 7) % 261900 + 100]);
        }
        uint256 out = MLDSA._allocWords(4 * 256);
        assertTrue(MLDSA.decodeZ(p, sig, out));
        for (uint256 g; g < 256; ++g) {
            uint256 b = g * 1000 + 79;
            uint256[4] memory r = [b, b + 1, b + 2, (b * 7) % 261900 + 100];
            for (uint256 t; t < 4; ++t) {
                uint256 got;
                uint256 at = out + (4 * g + t) * 32;
                assembly ("memory-safe") {
                    got := mload(at)
                }
                assertEq(got, 8380417 + 131072 - r[t]);
            }
        }
    }

    function test_reject_zOutOfRange_44() public view {
        Fx memory f = _fx(ML_DSA_44);
        (bytes memory pk, bytes memory m, bytes memory sig) = (f.pk[1], f.msg[1], f.sig[1]);
        bytes memory s = _copy(sig);
        _putQuad(s, 32, [uint256(78), 1000, 1000, 1000]); // |z_0| = γ1 − β
        assertFalse(h.verify(ML_DSA_44, pk, m, s));
        s = _copy(sig);
        _putQuad(s, 32 + 9 * 200, [uint256(1000), 1000, 1000, 0x3FFFF]); // z = γ1 − (2^18 − 1)
        assertFalse(h.verify(ML_DSA_44, pk, m, s));
    }

    function test_reject_zOutOfRange_65() public view {
        Fx memory f = _fx(ML_DSA_65);
        (bytes memory pk, bytes memory m, bytes memory sig) = (f.pk[1], f.msg[1], f.sig[1]);
        bytes memory s = _copy(sig);
        _putPair(s, 48, 196, 1000); // |z_0| = γ1 − β
        assertFalse(h.verify(ML_DSA_65, pk, m, s));
        s = _copy(sig);
        _putPair(s, 48 + 5 * 300, 1000, 0xFFFFF); // z = γ1 − (2^20 − 1) = −(2^19 − 1)
        assertFalse(h.verify(ML_DSA_65, pk, m, s));
    }

    function test_reject_zOutOfRange_87() public view {
        Fx memory f = _fx(ML_DSA_87);
        (bytes memory pk, bytes memory m, bytes memory sig) = (f.pk[1], f.msg[1], f.sig[1]);
        assertTrue(h.verify(ML_DSA_87, pk, m, sig));
        bytes memory s = _copy(sig);
        _putPair(s, 64, 120, 1000); // |z_0| = γ1 − β exactly
        assertFalse(h.verify(ML_DSA_87, pk, m, s), "|z| = gamma1 - beta");
        s = _copy(sig);
        _putPair(s, 64 + 5 * 895, 1000, 1048456); // last pair, z = −(γ1 − β)
        assertFalse(h.verify(ML_DSA_87, pk, m, s), "z = -(gamma1 - beta), last coefficient");
        s = _copy(sig);
        _putPair(s, 64 + 5 * 300, 1000, 0xFFFFF); // z = γ1 − (2^20 − 1)
        assertFalse(h.verify(ML_DSA_87, pk, m, s));
        assertFalse(h.verifyPrecomputed(ML_DSA_87, h.precompute(ML_DSA_87, pk), m, s), "precomputed");
    }

    /// forge-config: default.fuzz.runs = 48
    function testFuzz_reject_corruptedSignature_44(uint16 pos, uint8 delta) public view {
        _corruptedSignature(ML_DSA_44, pos, delta);
    }

    /// forge-config: default.fuzz.runs = 48
    function testFuzz_reject_corruptedSignature_65(uint16 pos, uint8 delta) public view {
        _corruptedSignature(ML_DSA_65, pos, delta);
    }

    /// forge-config: default.fuzz.runs = 32
    function testFuzz_reject_corruptedSignature_87(uint16 pos, uint8 delta) public view {
        _corruptedSignature(ML_DSA_87, pos, delta);
    }

    function _corruptedSignature(ParamSet set, uint16 pos, uint8 delta) internal view {
        vm.assume(delta != 0);
        Fx memory f = _fx(set);
        bytes memory s = _copy(f.sig[2]);
        uint256 p = uint256(pos) % s.length;
        s[p] = bytes1(uint8(s[p]) ^ delta);
        assertFalse(h.verify(set, f.pk[2], f.msg[2], s));
    }

    /// forge-config: default.fuzz.runs = 48
    function testFuzz_reject_corruptedHints_44(uint8 pos, uint8 value) public view {
        _corruptedHints(ML_DSA_44, pos, value);
    }

    /// forge-config: default.fuzz.runs = 48
    function testFuzz_reject_corruptedHints_65(uint8 pos, uint8 value) public view {
        _corruptedHints(ML_DSA_65, pos, value);
    }

    /// forge-config: default.fuzz.runs = 32
    function testFuzz_reject_corruptedHints_87(uint8 pos, uint8 value) public view {
        _corruptedHints(ML_DSA_87, pos, value);
    }

    function _corruptedHints(ParamSet set, uint8 pos, uint8 value) internal view {
        Fx memory f = _fx(set);
        bytes memory s = _copy(f.sig[3]);
        uint256 p = f.y + (uint256(pos) % (f.p.omega + f.p.k));
        vm.assume(uint8(s[p]) != value);
        s[p] = bytes1(value);
        assertFalse(h.verify(set, f.pk[3], f.msg[3], s));
    }

    // ── Cross-set: a key or signature of one set never verifies under the other ──

    function test_crossSet() public view {
        Fx memory a = _fx(ML_DSA_44);
        Fx memory b = _fx(ML_DSA_65);
        // Sanity: each verifies under its own set.
        assertTrue(h.verify(ML_DSA_44, a.pk[1], a.msg[1], a.sig[1]));
        assertTrue(h.verify(ML_DSA_65, b.pk[1], b.msg[1], b.sig[1]));
        // Right key and signature, wrong set.
        assertFalse(h.verify(ML_DSA_65, a.pk[1], a.msg[1], a.sig[1]), "44 key+sig under 65");
        assertFalse(h.verify(ML_DSA_44, b.pk[1], b.msg[1], b.sig[1]), "65 key+sig under 44");
        // 44 signature against a 65 key and vice versa, under either set.
        assertFalse(h.verify(ML_DSA_65, b.pk[1], a.msg[1], a.sig[1]), "44 sig, 65 key, set 65");
        assertFalse(h.verify(ML_DSA_44, b.pk[1], a.msg[1], a.sig[1]), "44 sig, 65 key, set 44");
        assertFalse(h.verify(ML_DSA_44, a.pk[1], b.msg[1], b.sig[1]), "65 sig, 44 key, set 44");
        assertFalse(h.verify(ML_DSA_65, a.pk[1], b.msg[1], b.sig[1]), "65 sig, 44 key, set 65");
        // A 65 signature cut to 44's length, and a 44 signature padded to 65's.
        assertFalse(h.verify(ML_DSA_44, a.pk[1], b.msg[1], _trim(b.sig[1], 3309 - 2420)), "65 sig trimmed");
        assertFalse(
            h.verify(ML_DSA_65, b.pk[1], a.msg[1], abi.encodePacked(a.sig[1], new bytes(3309 - 2420))), "44 sig padded"
        );
        // Precomputation is per set: none for the other set's key length, and a
        // blob of one set is rejected under the other.
        assertEq(h.precompute(ML_DSA_65, a.pk[1]).length, 0);
        assertEq(h.precompute(ML_DSA_44, b.pk[1]).length, 0);
        bytes memory blobA = h.precompute(ML_DSA_44, a.pk[1]);
        bytes memory blobB = h.precompute(ML_DSA_65, b.pk[1]);
        assertTrue(h.verifyPrecomputed(ML_DSA_44, blobA, a.msg[1], a.sig[1]));
        assertFalse(h.verifyPrecomputed(ML_DSA_65, blobA, a.msg[1], a.sig[1]), "44 blob under 65");
        assertFalse(h.verifyPrecomputed(ML_DSA_44, blobB, b.msg[1], b.sig[1]), "65 blob under 44");
    }

    /// ML-DSA-87 against both other sets: every (key set, signature set, claimed
    /// set) combination but the matching one is false, as are 87 material cut or
    /// padded to another set's length and blobs under the wrong set.
    function test_crossSet_87() public view {
        Fx[3] memory fx = [_fx(ML_DSA_44), _fx(ML_DSA_65), _fx(ML_DSA_87)];
        uint256 checked;
        for (uint256 ks; ks < 3; ++ks) {
            for (uint256 ss; ss < 3; ++ss) {
                for (uint256 cs; cs < 3; ++cs) {
                    if (ks != 2 && ss != 2 && cs != 2) continue; // 44/65-only: test_crossSet
                    bool want = ks == ss && ss == cs;
                    assertEq(
                        h.verify(fx[cs].set, fx[ks].pk[1], fx[ss].msg[1], fx[ss].sig[1]),
                        want,
                        string.concat("key ", vm.toString(ks), " sig ", vm.toString(ss), " set ", vm.toString(cs))
                    );
                    ++checked;
                }
            }
        }
        assertEq(checked, 19);
        Fx memory e = fx[2];
        // An 87 signature cut to 65's / 44's length, and 65 / 44 signatures padded to 87's.
        assertFalse(h.verify(ML_DSA_65, fx[1].pk[1], e.msg[1], _trim(e.sig[1], 4627 - 3309)), "87 sig trimmed to 65");
        assertFalse(h.verify(ML_DSA_44, fx[0].pk[1], e.msg[1], _trim(e.sig[1], 4627 - 2420)), "87 sig trimmed to 44");
        assertFalse(
            h.verify(ML_DSA_87, e.pk[1], fx[1].msg[1], abi.encodePacked(fx[1].sig[1], new bytes(4627 - 3309))),
            "65 sig padded"
        );
        assertFalse(
            h.verify(ML_DSA_87, e.pk[1], fx[0].msg[1], abi.encodePacked(fx[0].sig[1], new bytes(4627 - 2420))),
            "44 sig padded"
        );
        // An 87 key's first 1952 / 1312 bytes (same ρ) under 65 / 44 with 87's signature.
        assertFalse(h.verify(ML_DSA_65, _trim(e.pk[1], 2592 - 1952), e.msg[1], _trim(e.sig[1], 4627 - 3309)));
        assertFalse(h.verify(ML_DSA_44, _trim(e.pk[1], 2592 - 1312), e.msg[1], _trim(e.sig[1], 4627 - 2420)));
        // Precomputation is per set.
        assertEq(h.precompute(ML_DSA_87, fx[1].pk[1]).length, 0);
        assertEq(h.precompute(ML_DSA_65, e.pk[1]).length, 0);
        bytes memory blob87 = h.precompute(ML_DSA_87, e.pk[1]);
        assertTrue(h.verifyPrecomputed(ML_DSA_87, blob87, e.msg[1], e.sig[1]));
        assertFalse(h.verifyPrecomputed(ML_DSA_65, blob87, e.msg[1], e.sig[1]), "87 blob under 65");
        assertFalse(h.verifyPrecomputed(ML_DSA_44, blob87, e.msg[1], e.sig[1]), "87 blob under 44");
        assertFalse(h.verifyPrecomputed(ML_DSA_87, h.precompute(ML_DSA_65, fx[1].pk[1]), e.msg[1], e.sig[1]), "65 blob");
        // Unknown id 3 with valid 87 material.
        assertFalse(h.verify(ParamSet.wrap(3), e.pk[1], e.msg[1], e.sig[1]), "id 3");
    }

    // ── Precomputation (verifyPrecomputed, MLDSAKeyFactory) ──────────────────

    /// precompute(pk) byte-for-byte against dilithium-py's tr, Â and NTT(t1·2^d).
    function test_precompute_matchesReference_44() public view {
        _precomputeMatches(ML_DSA_44, 15424);
    }

    function test_precompute_matchesReference_65() public view {
        _precomputeMatches(ML_DSA_65, 27712);
    }

    function test_precompute_matchesReference_87() public view {
        _precomputeMatches(ML_DSA_87, 49216);
    }

    function _precomputeMatches(ParamSet set, uint256 len) internal view {
        Fx memory f = _fx(set);
        bytes memory blob = h.precompute(set, f.pk[1]);
        assertEq(blob.length, len);
        assertEq(blob, vm.parseJsonBytes(_diff(), string.concat(f.key, ".blob1")));
        assertEq(h.precompute(set, _trim(f.pk[1], 1)).length, 0, "bad pk -> empty");
        // Â part by part is Â cut into aParts equal pieces; no part beyond.
        uint256 partBytes = f.p.aHatBytes / f.p.aParts;
        for (uint256 part; part < f.p.aParts; ++part) {
            assertEq(h.precomputeAPart(set, f.pk[1], part), _slice(blob, 64 + part * partBytes, partBytes), "A part");
        }
        assertEq(h.precomputeAPart(set, f.pk[1], f.p.aParts).length, 0, "no such part");
        assertEq(h.precomputeAPart(set, _trim(f.pk[1], 1), 0).length, 0, "bad pk -> empty part");
    }

    function test_precomputed_rejects_44() public view {
        _precomputedRejects(ML_DSA_44);
    }

    function test_precomputed_rejects_65() public view {
        _precomputedRejects(ML_DSA_65);
    }

    function test_precomputed_rejects_87() public view {
        _precomputedRejects(ML_DSA_87);
    }

    function _precomputedRejects(ParamSet set) internal view {
        Fx memory f = _fx(set);
        (bytes memory pk, bytes memory m, bytes memory sig) = (f.pk[1], f.msg[1], f.sig[1]);
        bytes memory blob = h.precompute(set, pk);
        assertTrue(h.verifyPrecomputed(set, blob, m, sig));
        assertFalse(h.verifyPrecomputed(set, _trim(blob, 1), m, sig), "short blob");
        assertFalse(h.verifyPrecomputed(set, "", m, sig), "empty blob");
        assertFalse(h.verifyPrecomputed(set, _flip(blob, 8 * 3), m, sig), "tampered tr");
        assertFalse(h.verifyPrecomputed(set, _flip(blob, 8 * 1000), m, sig), "tampered A_hat");
        assertFalse(h.verifyPrecomputed(set, _flip(blob, 8 * (64 + f.p.aHatBytes + 1000)), m, sig), "tampered t_hat");
        assertFalse(h.verifyPrecomputed(set, blob, _flip(m, 0), sig), "message");
        assertFalse(h.verifyPrecomputed(set, blob, m, _flip(sig, 0)), "c~");
        assertFalse(h.verifyPrecomputed(set, blob, m, _trim(sig, 1)), "short sig");
        // The precomputation of another key (seed 2; pks[0..1] share seed 1).
        assertFalse(h.verifyPrecomputed(set, h.precompute(set, f.pk[2]), m, sig), "foreign key blob");
    }

    function test_factory_contentsMatchPrecompute_44() public {
        _factoryContents(ML_DSA_44);
    }

    function test_factory_contentsMatchPrecompute_65() public {
        _factoryContents(ML_DSA_65);
    }

    function test_factory_contentsMatchPrecompute_87() public {
        _factoryContents(ML_DSA_87);
    }

    function _factoryContents(ParamSet set) internal {
        Fx memory f = _fx(set);
        bytes32 pkHash = keccak256(f.pk[1]);
        (address a, address t) = factory.addressesOf(set, pkHash);
        assertEq(a, factory.registerA(set, f.pk[1]));
        assertEq(t, factory.registerT(set, f.pk[1]));
        bytes memory blob = h.precompute(set, f.pk[1]);
        uint256 aLen = f.p.aHatBytes;
        // Byte for byte: 0x00 ‖ Â (per part) and 0x00 ‖ tr ‖ t̂.
        uint256 partLen = aLen / f.p.aParts;
        for (uint256 part; part < f.p.aParts; ++part) {
            address ap = factory.aPartAddress(set, pkHash, part);
            assertEq(ap.code, abi.encodePacked(bytes1(0), _slice(blob, 64 + part * partLen, partLen)), "A part code");
            assertLe(ap.code.length, 24576, "EIP-170");
        }
        assertEq(a, factory.aPartAddress(set, pkHash, 0), "addressesOf's A is part 0");
        assertEq(t.code, abi.encodePacked(bytes1(0), _slice(blob, 0, 64), _slice(blob, 64 + aLen, f.p.tHatBytes)));
        assertEq(factory.load(set, pkHash), blob);
        assertEq(factory.load(set, pkHash), vm.parseJsonBytes(_diff(), string.concat(f.key, ".blob1")), "vs dilithium-py");
        assertTrue(factory.isRegistered(set, pkHash));
        assertTrue(factory.verify(set, pkHash, f.msg[1], f.sig[1]));
        assertTrue(h.verifyByHash(address(factory), set, pkHash, f.msg[1], f.sig[1]));
        assertFalse(factory.verify(set, pkHash, _flip(f.msg[1], 0), f.sig[1]));
        // Library-side derivation agrees with the factory's.
        (address a2, address t2) = MLDSAKeys.addressesOf(address(factory), set, pkHash);
        assertEq(a2, a);
        assertEq(t2, t);
    }

    /// Every differential vector through register + verify(set, pkHash), with contexts.
    function test_factory_allVectors_44() public {
        _factoryAllVectors(ML_DSA_44);
    }

    function test_factory_allVectors_65() public {
        _factoryAllVectors(ML_DSA_65);
    }

    function test_factory_allVectors_87() public {
        _factoryAllVectors(ML_DSA_87);
    }

    function _factoryAllVectors(ParamSet set) internal {
        Fx memory f = _fx(set);
        for (uint256 v; v < f.pk.length; ++v) {
            factory.registerA(set, f.pk[v]);
            factory.registerT(set, f.pk[v]);
            bytes32 pkHash = keccak256(f.pk[v]);
            assertTrue(factory.verifyWithContext(set, pkHash, f.ctx[v], f.msg[v], f.sig[v]), vm.toString(v));
            assertFalse(factory.verifyWithContext(set, pkHash, hex"01", f.msg[v], f.sig[v]));
        }
    }

    function test_factory_unregisteredAndForeign_44() public {
        _factoryUnregisteredAndForeign(ML_DSA_44);
    }

    function test_factory_unregisteredAndForeign_65() public {
        _factoryUnregisteredAndForeign(ML_DSA_65);
    }

    function test_factory_unregisteredAndForeign_87() public {
        _factoryUnregisteredAndForeign(ML_DSA_87);
    }

    function _factoryUnregisteredAndForeign(ParamSet set) internal {
        Fx memory f = _fx(set);
        bytes32 h1 = keccak256(f.pk[1]);
        // Nothing registered: false, no revert.
        assertFalse(factory.isRegistered(set, h1));
        assertEq(factory.load(set, h1).length, 0);
        assertFalse(factory.verify(set, h1, f.msg[1], f.sig[1]), "unregistered");
        // Half registered: still false.
        if (f.p.aParts > 1) {
            factory.registerAPart(set, f.pk[1], 1);
            factory.registerT(set, f.pk[1]);
            assertFalse(factory.isRegistered(set, h1));
            assertEq(factory.load(set, h1).length, 0);
            assertFalse(factory.verify(set, h1, f.msg[1], f.sig[1]), "A part 1 + T only");
        }
        factory.registerA(set, f.pk[1]);
        if (f.p.aParts == 1) {
            assertFalse(factory.isRegistered(set, h1));
            assertFalse(factory.verify(set, h1, f.msg[1], f.sig[1]), "only A registered");
        }
        factory.registerT(set, f.pk[1]);
        assertTrue(factory.verify(set, h1, f.msg[1], f.sig[1]));
        // pkHash of key X with key Y's valid signature (seed 2 vs seed 1).
        factory.registerA(set, f.pk[2]);
        factory.registerT(set, f.pk[2]);
        assertTrue(factory.verify(set, keccak256(f.pk[2]), f.msg[2], f.sig[2]));
        assertFalse(factory.verify(set, keccak256(f.pk[2]), f.msg[1], f.sig[1]), "key X hash, key Y signature");
        assertFalse(factory.verify(set, h1, f.msg[2], f.sig[2]), "key Y hash, key X signature");
        // Malformed key: registration reverts (setup call), verification never does.
        vm.expectRevert(MLDSAKeyFactory.InvalidPublicKey.selector);
        factory.registerA(set, _trim(f.pk[1], 1));
        vm.expectRevert(MLDSAKeyFactory.InvalidPublicKey.selector);
        factory.registerT(set, abi.encodePacked(f.pk[1], bytes1(0)));
        vm.expectRevert(MLDSAKeyFactory.InvalidPublicKey.selector);
        factory.registerAPart(set, _trim(f.pk[1], 1), 0);
        vm.expectRevert(MLDSAKeyFactory.InvalidPart.selector);
        factory.registerAPart(set, f.pk[1], f.p.aParts);
        // Unknown set: registration reverts, everything else is a plain "no".
        vm.expectRevert(MLDSAKeyFactory.UnsupportedParamSet.selector);
        factory.registerA(ParamSet.wrap(3), f.pk[1]);
        vm.expectRevert(MLDSAKeyFactory.UnsupportedParamSet.selector);
        factory.registerAPart(ParamSet.wrap(3), f.pk[1], 0);
        vm.expectRevert(MLDSAKeyFactory.UnsupportedParamSet.selector);
        factory.registerT(ParamSet.wrap(3), f.pk[1]);
        assertFalse(factory.isRegistered(ParamSet.wrap(3), h1));
        assertEq(factory.load(ParamSet.wrap(3), h1).length, 0);
        assertFalse(factory.verify(ParamSet.wrap(3), h1, f.msg[1], f.sig[1]));
    }

    /// The set is part of the salt: a key registered under its set is not found
    /// under the other, and the other set cannot register it at all (wrong length).
    function test_factory_crossSet() public {
        Fx memory a = _fx(ML_DSA_44);
        Fx memory b = _fx(ML_DSA_65);
        bytes32 ha = keccak256(a.pk[1]);
        bytes32 hb = keccak256(b.pk[1]);
        // Same pk bytes registered under the wrong set: refused.
        vm.expectRevert(MLDSAKeyFactory.InvalidPublicKey.selector);
        factory.registerA(ML_DSA_65, a.pk[1]);
        vm.expectRevert(MLDSAKeyFactory.InvalidPublicKey.selector);
        factory.registerT(ML_DSA_65, a.pk[1]);
        vm.expectRevert(MLDSAKeyFactory.InvalidPublicKey.selector);
        factory.registerA(ML_DSA_44, b.pk[1]);
        vm.expectRevert(MLDSAKeyFactory.InvalidPublicKey.selector);
        factory.registerT(ML_DSA_44, b.pk[1]);
        factory.registerA(ML_DSA_44, a.pk[1]);
        factory.registerT(ML_DSA_44, a.pk[1]);
        factory.registerA(ML_DSA_65, b.pk[1]);
        factory.registerT(ML_DSA_65, b.pk[1]);
        // Distinct addresses per set for the same pkHash.
        (address a44, address t44) = factory.addressesOf(ML_DSA_44, ha);
        (address a65, address t65) = factory.addressesOf(ML_DSA_65, ha);
        assertTrue(a44 != a65 && t44 != t65 && a44 != t44);
        // Registered under 44 only: under 65 it is not registered, verify is false.
        assertTrue(factory.verify(ML_DSA_44, ha, a.msg[1], a.sig[1]));
        assertFalse(factory.isRegistered(ML_DSA_65, ha));
        assertFalse(factory.verify(ML_DSA_65, ha, a.msg[1], a.sig[1]), "44 key hash under 65");
        assertFalse(factory.isRegistered(ML_DSA_44, hb));
        assertFalse(factory.verify(ML_DSA_44, hb, b.msg[1], b.sig[1]), "65 key hash under 44");
        // Each set's registered key against the other set's signature.
        assertFalse(factory.verify(ML_DSA_44, ha, b.msg[1], b.sig[1]), "65 sig vs registered 44 key");
        assertFalse(factory.verify(ML_DSA_65, hb, a.msg[1], a.sig[1]), "44 sig vs registered 65 key");
    }

    /// The 87 key under 44 / 65 and their keys under 87: registration refused
    /// (wrong length), and a key registered under one set is never found under
    /// another — distinct addresses for every (set, role, part).
    function test_factory_crossSet_87() public {
        Fx memory a = _fx(ML_DSA_44);
        Fx memory b = _fx(ML_DSA_65);
        Fx memory e = _fx(ML_DSA_87);
        bytes32 he = keccak256(e.pk[1]);
        vm.expectRevert(MLDSAKeyFactory.InvalidPublicKey.selector);
        factory.registerAPart(ML_DSA_87, b.pk[1], 0);
        vm.expectRevert(MLDSAKeyFactory.InvalidPublicKey.selector);
        factory.registerT(ML_DSA_87, a.pk[1]);
        vm.expectRevert(MLDSAKeyFactory.InvalidPublicKey.selector);
        factory.registerA(ML_DSA_65, e.pk[1]);
        vm.expectRevert(MLDSAKeyFactory.InvalidPublicKey.selector);
        factory.registerT(ML_DSA_44, e.pk[1]);
        factory.registerA(ML_DSA_87, e.pk[1]);
        factory.registerT(ML_DSA_87, e.pk[1]);
        factory.registerA(ML_DSA_65, b.pk[1]);
        factory.registerT(ML_DSA_65, b.pk[1]);
        assertTrue(factory.verify(ML_DSA_87, he, e.msg[1], e.sig[1]));
        // Seven distinct addresses for one pkHash: A, T under 44 and 65; A0, A1, T under 87.
        address[7] memory xs;
        (xs[0], xs[1]) = factory.addressesOf(ML_DSA_44, he);
        (xs[2], xs[3]) = factory.addressesOf(ML_DSA_65, he);
        (xs[4], xs[6]) = factory.addressesOf(ML_DSA_87, he);
        xs[5] = factory.aPartAddress(ML_DSA_87, he, 1);
        assertEq(xs[4], factory.aPartAddress(ML_DSA_87, he, 0));
        for (uint256 i; i < 7; ++i) {
            for (uint256 j = i + 1; j < 7; ++j) {
                assertTrue(xs[i] != xs[j], "distinct addresses");
            }
        }
        assertFalse(factory.isRegistered(ML_DSA_65, he));
        assertFalse(factory.verify(ML_DSA_65, he, e.msg[1], e.sig[1]), "87 key hash under 65");
        assertFalse(factory.verify(ML_DSA_44, he, e.msg[1], e.sig[1]), "87 key hash under 44");
        assertFalse(factory.isRegistered(ML_DSA_87, keccak256(b.pk[1])));
        assertFalse(factory.verify(ML_DSA_87, keccak256(b.pk[1]), b.msg[1], b.sig[1]), "65 key hash under 87");
        assertFalse(factory.verify(ML_DSA_87, he, b.msg[1], b.sig[1]), "65 sig vs registered 87 key");
        assertFalse(factory.verify(ML_DSA_65, keccak256(b.pk[1]), e.msg[1], e.sig[1]), "87 sig vs registered 65 key");
    }

    /// Backward compatibility: the 44 / 65 data addresses are exactly what they were
    /// before parts existed — CREATE2 with keccak256(abi.encode("MLDSA.A_hat", set,
    /// pkHash)) and the fixed init code — recomputed here by hand.
    function test_factory_addressesUnchanged_44_65() public view {
        bytes32 pkHash = keccak256("any key");
        bytes32 initHash = keccak256(hex"5f5f5f5f335afa156012573d5f5f3e3d5ff35b5f5ffd");
        for (uint8 id; id < 2; ++id) {
            bytes32 sa = keccak256(abi.encode("MLDSA.A_hat", id, pkHash));
            bytes32 st = keccak256(abi.encode("MLDSA.tr_t_hat", id, pkHash));
            address wantA =
                address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(factory), sa, initHash)))));
            address wantT =
                address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(factory), st, initHash)))));
            (address a, address t) = factory.addressesOf(ParamSet.wrap(id), pkHash);
            assertEq(a, wantA);
            assertEq(t, wantT);
            assertEq(factory.aPartAddress(ParamSet.wrap(id), pkHash, 0), wantA);
            assertEq(MLDSAKeys.saltAPart(ParamSet.wrap(id), pkHash, 0), sa);
        }
        // 87: the part is in every A salt (none equals the 44/65-style salt).
        bytes32 s87 = keccak256(abi.encode("MLDSA.A_hat", uint8(2), pkHash));
        assertTrue(MLDSAKeys.saltAPart(ML_DSA_87, pkHash, 0) != s87);
        assertEq(MLDSAKeys.saltAPart(ML_DSA_87, pkHash, 1), keccak256(abi.encode("MLDSA.A_hat", uint8(2), pkHash, 1)));
    }

    function test_factory_idempotent() public {
        Fx memory f = _fx(ML_DSA_65);
        uint256 first = gasleft();
        address a = factory.registerA(ML_DSA_65, f.pk[1]);
        address t = factory.registerT(ML_DSA_65, f.pk[1]);
        first -= gasleft();
        bytes memory before = factory.load(ML_DSA_65, keccak256(f.pk[1]));
        uint256 g = gasleft();
        assertEq(factory.registerA(ML_DSA_65, f.pk[1]), a);
        assertEq(factory.registerT(ML_DSA_65, f.pk[1]), t);
        g -= gasleft();
        // (absolute numbers here include this test contract's large-memory overhead)
        assertLt(g * 20, first, "re-register is a lookup, not a recompute");
        assertEq(factory.load(ML_DSA_65, keccak256(f.pk[1])), before);
    }

    /// Only the factory can occupy the derived addresses: the same init code and
    /// salts from any other deployer land elsewhere, and the factory hands its staged
    /// code to nobody but the contract it is creating.
    function test_factory_addressesOnlyFromFactory() public {
        Fx memory f = _fx(ML_DSA_44);
        bytes32 pkHash = keccak256(f.pk[1]);
        (address a, address t) = factory.addressesOf(ML_DSA_44, pkHash);
        SquatterCreate2 squatter = new SquatterCreate2();
        // The squatter's child asks the squatter (no fallback) for code -> create fails
        // or, at best, lands at the squatter's own CREATE2 address — never at a / t.
        address sa = squatter.squat(MLDSAKeys.saltA(ML_DSA_44, pkHash));
        address st = squatter.squat(MLDSAKeys.saltT(ML_DSA_44, pkHash));
        assertTrue(sa != a && st != t);
        (address oa, address ot) = MLDSAKeys.addressesOf(address(squatter), ML_DSA_44, pkHash);
        assertTrue(oa != a && ot != t);
        // A second factory derives different addresses for the same key.
        MLDSAKeyFactory f2 = new MLDSAKeyFactory();
        (address a2, address t2) = f2.addressesOf(ML_DSA_44, pkHash);
        assertTrue(a2 != a && t2 != t);
        // Nothing is at a / t until this factory registers the key.
        assertEq(a.code.length, 0);
        assertEq(t.code.length, 0);
        // The factory's fallback refuses outside callers (no staged code leaks).
        (bool ok,) = address(factory).call("");
        assertFalse(ok);
        factory.registerA(ML_DSA_44, f.pk[1]);
        (ok,) = address(factory).call("");
        assertFalse(ok, "fallback after registration");

        // ML-DSA-87: both A parts and T, same story.
        Fx memory e = _fx(ML_DSA_87);
        bytes32 he = keccak256(e.pk[1]);
        for (uint256 part; part < 2; ++part) {
            address ap = factory.aPartAddress(ML_DSA_87, he, part);
            assertTrue(squatter.squat(MLDSAKeys.saltAPart(ML_DSA_87, he, part)) != ap);
            assertTrue(f2.aPartAddress(ML_DSA_87, he, part) != ap);
            assertTrue(MLDSAKeys.aPartAddress(address(squatter), ML_DSA_87, he, part) != ap);
            assertEq(ap.code.length, 0);
        }
        factory.registerAPart(ML_DSA_87, e.pk[1], 0);
        assertEq(factory.aPartAddress(ML_DSA_87, he, 0).code.length, 21505);
        assertEq(factory.aPartAddress(ML_DSA_87, he, 1).code.length, 0, "part 1 untouched");
        (ok,) = address(factory).call("");
        assertFalse(ok, "fallback after an 87 part");
    }

    // ── Gas ──────────────────────────────────────────────────────────────────

    function test_gas_verify_44() public view {
        _gasVerify(ML_DSA_44);
    }

    function test_gas_verify_65() public view {
        _gasVerify(ML_DSA_65);
    }

    function test_gas_verify_87() public view {
        _gasVerify(ML_DSA_87);
    }

    function _gasVerify(ParamSet set) internal view {
        Fx memory f = _fx(set);
        uint256 maxGas;
        for (uint256 v; v < f.pk.length; ++v) {
            uint256 g = gasleft();
            bool ok = h.verifyWithContext(set, f.pk[v], f.ctx[v], f.msg[v], f.sig[v]);
            g -= gasleft();
            assertTrue(ok);
            console.log("verify gas (vector, msg bytes, gas):", v, f.msg[v].length, g);
            if (g > maxGas) maxGas = g;
        }
        console.log(_name(set), "max verify gas over differential vectors:", maxGas);
    }

    function test_gas_precomputed_44() public {
        _gasPrecomputed(ML_DSA_44);
    }

    function test_gas_precomputed_65() public {
        _gasPrecomputed(ML_DSA_65);
    }

    function test_gas_precomputed_87() public {
        _gasPrecomputed(ML_DSA_87);
    }

    function _gasPrecomputed(ParamSet set) internal {
        Fx memory f = _fx(set);
        console.log(_name(set));
        uint256 g = gasleft();
        bytes memory blob = h.precompute(set, f.pk[1]);
        console.log("precompute (one-off, in memory) gas:", g - gasleft());
        uint256 maxPre;
        for (uint256 v; v < f.pk.length; ++v) {
            bytes memory b = h.precompute(set, f.pk[v]);
            g = gasleft();
            bool ok = h.verifyPrecomputedWithContext(set, b, f.ctx[v], f.msg[v], f.sig[v]);
            g -= gasleft();
            assertTrue(ok);
            console.log("verifyPrecomputed gas, blob as calldata (vector, msg bytes, gas):", v, f.msg[v].length, g);
            if (g > maxPre) maxPre = g;
        }
        console.log("max verifyPrecomputed gas:", maxPre);

        // Registration: two separate transactions, each its own external call.
        g = gasleft();
        factory.registerA(set, f.pk[1]);
        console.log("registerA gas (ExpandA + A deploy):", g - gasleft());
        g = gasleft();
        factory.registerT(set, f.pk[1]);
        console.log("registerT gas (tr + k NTT + T deploy):", g - gasleft());
        factory.registerA(set, f.pk[3]);
        factory.registerT(set, f.pk[3]);

        // Verification by pkHash, all accounts cold as in a fresh transaction.
        bytes32 h1 = keccak256(f.pk[1]);
        bytes32 h3 = keccak256(f.pk[3]);
        _coolKey(set, h1);
        (uint256 lg, uint256 vg, bool ok1) = h.verifyByHashSplit(address(factory), set, h1, f.msg[1], f.sig[1]);
        assertTrue(ok1);
        console.log("by pkHash, 32-byte msg: load gas (cold)", lg);
        console.log("by pkHash, 32-byte msg: verifyPrecomputed gas after load", vg);
        _coolKey(set, h1);
        g = gasleft();
        assertTrue(h.verifyByHash(address(factory), set, h1, f.msg[1], f.sig[1]));
        console.log("consumer verify(factory, set, pkHash), 32-byte msg, gas:", g - gasleft());
        _coolKey(set, h1);
        g = gasleft();
        assertTrue(factory.verify(set, h1, f.msg[1], f.sig[1]));
        console.log("factory.verify(set, pkHash), 32-byte msg, gas:", g - gasleft());
        _coolKey(set, h3);
        g = gasleft();
        assertTrue(h.verifyByHash(address(factory), set, h3, f.msg[3], f.sig[3]));
        console.log("consumer verify(factory, set, pkHash), 3000-byte msg, gas:", g - gasleft());

        bytes memory mPrime = abi.encodePacked(bytes1(0), bytes1(0), f.msg[1]);
        (uint256[10] memory ph, bool okp) = h.phasesPrecomputed(set, blob, mPrime, f.sig[1]);
        assertTrue(okp);
        string[10] memory names = [
            "pre: decode h + z",
            "pre: l x NTT(z)",
            "pre: mu = H(tr||M',64)",
            "pre: SampleInBall + NTT(c)",
            "pre: A_hat*z from blob",
            "pre: k x c*t_hat from blob",
            "pre: k x inverse NTT",
            "pre: UseHint + w1Encode",
            "pre: c~' = H(mu||w1,lambda/4)",
            "pre: TOTAL (phase harness)"
        ];
        for (uint256 n; n < 10; ++n) {
            console.log(names[n], ph[n]);
        }
    }

    function test_gas_phases_44() public view {
        _gasPhases(ML_DSA_44);
    }

    function test_gas_phases_65() public view {
        _gasPhases(ML_DSA_65);
    }

    function test_gas_phases_87() public view {
        _gasPhases(ML_DSA_87);
    }

    function _gasPhases(ParamSet set) internal view {
        Fx memory f = _fx(set);
        bytes memory mPrime = abi.encodePacked(bytes1(0), bytes1(0), f.msg[1]);
        (uint256[11] memory g, bool ok,) = h.phases(set, f.pk[1], mPrime, f.sig[1]);
        assertTrue(ok, "phase harness reproduces c~");
        console.log(_name(set));
        string[11] memory names = [
            "decode h + z",
            "l x NTT(z)",
            "tr = H(pk,64)",
            "mu = H(tr||M',64)",
            "SampleInBall + NTT(c)",
            "ExpandA fused with A*z (k*l SHAKE128 streams)",
            "k x decode t1 + NTT + c*t1",
            "k x inverse NTT",
            "UseHint + w1Encode",
            "c~' = H(mu||w1,lambda/4)",
            "TOTAL (phase harness)"
        ];
        for (uint256 n; n < 11; ++n) {
            console.log(names[n], g[n]);
        }
        (uint256 perm, uint256 fwd, uint256 inv) = h.unitCosts();
        console.log("unit: Keccak-f[1600]", perm);
        console.log("unit: NTT", fwd);
        console.log("unit: inverse NTT", inv);
    }

    /// ExpandA's rejection sampling per candidate: total minus the 4-way
    /// permutations, over the candidates parsed. For differential key 1 (computed
    /// with hashlib, mirroring the sampler's drain-by-group rule):
    ///   ML-DSA-44: 16 streams, 4,128 candidates parsed, 20 permutations
    ///   ML-DSA-65: 30 streams, 7,736 candidates parsed, 40 permutations
    ///   ML-DSA-87: 56 streams, 14,400 candidates parsed, 70 permutations
    function test_gas_expandA() public view {
        (uint256 perm,,) = h.unitCosts();
        ParamSet[3] memory sets = [ML_DSA_44, ML_DSA_65, ML_DSA_87];
        uint256[3] memory cands = [uint256(4128), 7736, 14400];
        uint256[3] memory perms = [uint256(20), 40, 70];
        for (uint256 n; n < 3; ++n) {
            Fx memory f = _fx(sets[n]);
            (uint256 fused, uint256 plain) = h.expandAGas(sets[n], f.pk[1]);
            console.log(_name(sets[n]));
            console.log("  ExpandA fused with A*z: total", fused);
            console.log("    per candidate excl. permutations", (fused - perms[n] * perm) / cands[n]);
            console.log("  ExpandA materialised (precomputeA): total", plain);
            console.log("    per candidate excl. permutations", (plain - perms[n] * perm) / cands[n]);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    function _coolKey(ParamSet set, bytes32 pkHash) internal {
        (address a, address t) = factory.addressesOf(set, pkHash);
        vm.cool(a);
        vm.cool(t);
        vm.cool(address(factory));
    }

    /// keccak256 built from the library's permutation (rate 136, pad 0x01 … 0x80).
    function _keccakViaLib(bytes memory data) internal pure returns (bytes32 out) {
        uint256 ks = MLDSA.newKeccakWorkspace();
        uint256 rate = 136;
        uint256 blocks = data.length / rate + 1;
        bytes memory padded = new bytes(blocks * rate);
        for (uint256 i; i < data.length; ++i) {
            padded[i] = data[i];
        }
        padded[data.length] = bytes1(uint8(padded[data.length]) ^ 0x01);
        padded[padded.length - 1] = bytes1(uint8(padded[padded.length - 1]) ^ 0x80);
        for (uint256 b; b < blocks; ++b) {
            _xorLanes(ks, padded, b * rate, rate);
            MLDSA.keccakF(ks);
        }
        bytes memory o = _readLanes(ks, 32);
        assembly ("memory-safe") {
            out := mload(add(o, 0x20))
        }
    }

    /// SHAKE via the library's absorb, squeezing `outLen` bytes across blocks.
    function _shake(bytes memory data, uint256 rate, uint256 outLen) internal pure returns (bytes memory out) {
        uint256 ks = MLDSA.newKeccakWorkspace();
        MLDSA.absorb(ks, MLDSA._ptr(data), data.length, rate);
        out = new bytes(0);
        while (out.length < outLen) {
            uint256 take = outLen - out.length < rate ? outLen - out.length : rate;
            out = abi.encodePacked(out, _readLanes(ks, take));
            if (out.length < outLen) MLDSA.keccakF(ks);
        }
    }

    function _xorLanes(uint256 ks, bytes memory buf, uint256 off, uint256 rate) internal pure {
        for (uint256 i; i < rate; ++i) {
            uint256 lane = i / 8;
            uint256 v = uint256(uint8(buf[off + i])) << (8 * (i % 8));
            assembly ("memory-safe") {
                let p := add(ks, shl(5, lane))
                mstore(p, xor(mload(p), v)) // slot 0 of the 4-way state
            }
        }
    }

    function _readLanes(uint256 ks, uint256 n) internal pure returns (bytes memory o) {
        o = new bytes(n);
        for (uint256 i; i < n; ++i) {
            uint256 lane;
            uint256 idx = i / 8;
            assembly ("memory-safe") {
                lane := mload(add(ks, shl(5, idx)))
            }
            o[i] = bytes1(uint8(lane >> (8 * (i % 8))));
        }
    }

    function _slice(bytes memory b, uint256 o, uint256 n) internal pure returns (bytes memory c) {
        c = new bytes(n);
        for (uint256 i; i < n; ++i) {
            c[i] = b[o + i];
        }
    }

    function _flip(bytes memory b, uint256 bit) internal pure returns (bytes memory c) {
        c = _copy(b);
        c[bit / 8] = bytes1(uint8(c[bit / 8]) ^ uint8(1 << (bit % 8)));
    }

    function _copy(bytes memory b) internal pure returns (bytes memory) {
        return abi.encodePacked(b);
    }

    function _trim(bytes memory b, uint256 n) internal pure returns (bytes memory c) {
        c = new bytes(b.length - n);
        for (uint256 i; i < c.length; ++i) {
            c[i] = b[i];
        }
    }

    /// Writes two 20-bit little-endian fields (one ML-DSA-65 / -87 z pair) at byte offset `o`.
    function _putPair(bytes memory s, uint256 o, uint256 r0, uint256 r1) internal pure {
        uint256 v = r0 | (r1 << 20);
        for (uint256 i; i < 5; ++i) {
            s[o + i] = bytes1(uint8(v >> (8 * i)));
        }
    }

    /// Writes four 18-bit little-endian fields (one ML-DSA-44 z group) at byte offset `o`.
    function _putQuad(bytes memory s, uint256 o, uint256[4] memory r) internal pure {
        uint256 v = r[0] | (r[1] << 18) | (r[2] << 36) | (r[3] << 54);
        for (uint256 i; i < 9; ++i) {
            s[o + i] = bytes1(uint8(v >> (8 * i)));
        }
    }
}
