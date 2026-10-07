// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

import {MLDSA65} from "../src/MLDSA65.sol";

/// Calls the library from a fresh external frame. Gas figures are taken across this
/// call so the quadratic memory-expansion cost starts from zero, as it would in a
/// real transaction (the test contract itself holds ~1 MB of parsed JSON).
contract MLDSA65Harness {
    function verify(bytes calldata pk, bytes calldata m, bytes calldata sig) external view returns (bool) {
        return MLDSA65.verify(pk, m, sig);
    }

    function verifyWithContext(bytes calldata pk, bytes calldata ctx, bytes calldata m, bytes calldata sig)
        external
        view
        returns (bool)
    {
        return MLDSA65.verifyWithContext(pk, ctx, m, sig);
    }

    function verifyInternal(bytes calldata pk, bytes calldata mPrime, bytes calldata sig)
        external
        view
        returns (bool)
    {
        return MLDSA65.verifyInternal(pk, mPrime, sig);
    }

    function verifyWithExpandedA(
        bytes calldata pk,
        bytes calldata aHat,
        bytes calldata ctx,
        bytes calldata m,
        bytes calldata sig
    ) external view returns (bool) {
        return MLDSA65.verifyWithExpandedA(pk, aHat, ctx, m, sig);
    }

    function expandA(bytes32 rho) external pure returns (bytes memory) {
        return MLDSA65.expandA(rho);
    }

    /// Algorithm 8 re-run phase by phase with gasleft() checkpoints (same building
    /// blocks, same order as `verifyInternal`, minus the early-exit checks).
    /// [0] decode h + z, [1] 5×NTT(z), [2] tr = H(pk), [3] μ, [4] SampleInBall + NTT(c),
    /// [5] fused ExpandA × ẑ (30 SHAKE128 streams, 4-way), [6] 6×(decode t1 + NTT + ĉ·t̂1),
    /// [7] 6×NTT⁻¹, [8] UseHint + w1Encode, [9] c̃′ = H(μ ‖ w1), [10] total.
    function phases(bytes memory pk, bytes memory mPrime, bytes memory sig)
        external
        view
        returns (uint256[11] memory g, bool ok, bytes memory w1Out)
    {
        uint256 t0 = gasleft();
        uint256 t = t0;
        (, uint256[6] memory hints) = MLDSA65.hintBitUnpack(sig);
        uint256 zHat = MLDSA65._allocWords(5 * 256 + 8);
        MLDSA65.decodeZ(sig, zHat);
        bytes memory zetas = MLDSA65._zetas();
        uint256 zp = MLDSA65._ptr(zetas);
        (g[0], t) = (t - gasleft(), gasleft());
        for (uint256 j; j < 5; ++j) {
            MLDSA65.ntt(zHat + j * 0x2000, zp);
        }
        (g[1], t) = (t - gasleft(), gasleft());
        uint256 ks = MLDSA65.newKeccakWorkspace();
        bytes memory w1Buf = new bytes(64 + 6 * 128);
        (bytes32 tr0, bytes32 tr1) = MLDSA65.shake256To64(ks, MLDSA65._ptr(pk), pk.length);
        (g[2], t) = (t - gasleft(), gasleft());
        bytes memory trM = abi.encodePacked(tr0, tr1, mPrime);
        (bytes32 mu0, bytes32 mu1) = MLDSA65.shake256To64(ks, MLDSA65._ptr(trM), trM.length);
        assembly ("memory-safe") {
            mstore(add(w1Buf, 0x20), mu0)
            mstore(add(w1Buf, 0x40), mu1)
        }
        (g[3], t) = (t - gasleft(), gasleft());
        uint256 cHat = MLDSA65._allocWords(256);
        MLDSA65.sampleInBall(ks, MLDSA65._ptr(sig), cHat);
        MLDSA65.ntt(cHat, zp);
        MLDSA65._scale(cHat, 1 << 13);
        (g[4], t) = (t - gasleft(), gasleft());
        uint256 acc = MLDSA65._allocStrided(6);
        uint256 t1Hat = MLDSA65._allocWords(256);
        bytes32 rho;
        assembly ("memory-safe") {
            rho := mload(add(pk, 0x20))
        }
        MLDSA65.sampleMatrix(ks, rho, zHat, 0x2000, acc, true);
        (g[5], t) = (t - gasleft(), gasleft());
        for (uint256 i; i < 6; ++i) {
            MLDSA65.decodeT1(pk, i, t1Hat);
            MLDSA65.ntt(t1Hat, zp);
            MLDSA65._subProduct(acc + i * 0x2100, cHat, t1Hat);
        }
        (g[6], t) = (t - gasleft(), gasleft());
        for (uint256 i; i < 6; ++i) {
            MLDSA65.invNtt(acc + i * 0x2100, zp);
        }
        (g[7], t) = (t - gasleft(), gasleft());
        for (uint256 i; i < 6; ++i) {
            MLDSA65.useHintPack(acc + i * 0x2100, hints[i], MLDSA65._ptr(w1Buf) + 64 + i * 128);
        }
        (g[8], t) = (t - gasleft(), gasleft());
        (bytes32 c0,) = MLDSA65.shake256To64(ks, MLDSA65._ptr(w1Buf), w1Buf.length);
        (g[9], t) = (t - gasleft(), gasleft());
        g[10] = t0 - gasleft();
        bytes32 sig0;
        assembly ("memory-safe") {
            sig0 := mload(add(sig, 0x20))
        }
        ok = c0 == sig0;
        w1Out = w1Buf;
    }

    /// One Keccak-f[1600], one NTT, one NTT⁻¹ — the unit costs.
    function unitCosts() external view returns (uint256 perm, uint256 fwd, uint256 inv) {
        uint256 ks = MLDSA65.newKeccakWorkspace();
        uint256 p = MLDSA65._allocWords(256);
        uint256 zp = MLDSA65._ptr(MLDSA65._zetas());
        uint256 t = gasleft();
        MLDSA65.keccakF(ks);
        perm = t - gasleft();
        t = gasleft();
        MLDSA65.ntt(p, zp);
        fwd = t - gasleft();
        t = gasleft();
        MLDSA65.invNtt(p, zp);
        inv = t - gasleft();
    }
}

/// Minimal consumer exposing only `verify`, to size the library's inlined code.
contract MLDSA65VerifyOnly {
    function verify(bytes calldata pk, bytes calldata m, bytes calldata sig) external view returns (bool) {
        return MLDSA65.verify(pk, m, sig);
    }
}

contract MLDSA65Test is Test {
    MLDSA65Harness internal h;
    string internal diff;
    string internal acvp;

    // Indices into the differential fixture.
    bytes[] internal pks;
    bytes[] internal msgs;
    bytes[] internal ctxs;
    bytes[] internal sigs;

    function setUp() public {
        h = new MLDSA65Harness();
        diff = vm.readFile("test/mldsa/differential.json");
        acvp = vm.readFile("test/mldsa/acvp.json");
        pks = vm.parseJsonBytesArray(diff, ".pk");
        msgs = vm.parseJsonBytesArray(diff, ".msg");
        ctxs = vm.parseJsonBytesArray(diff, ".ctx");
        sigs = vm.parseJsonBytesArray(diff, ".sig");
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

    // ── Intermediates against dilithium-py ───────────────────────────────────

    function test_intermediates_tr_mu_A00() public view {
        bytes[] memory trs = vm.parseJsonBytesArray(diff, ".tr");
        bytes[] memory mus = vm.parseJsonBytesArray(diff, ".mu");
        bytes[] memory a00s = vm.parseJsonBytesArray(diff, ".a00");
        for (uint256 v; v < pks.length; ++v) {
            uint256 ks = MLDSA65.newKeccakWorkspace();
            (bytes32 a, bytes32 b) = MLDSA65.shake256To64(ks, MLDSA65._ptr(pks[v]), pks[v].length);
            assertEq(abi.encodePacked(a, b), trs[v], "tr");
            bytes memory trM =
                abi.encodePacked(a, b, bytes1(0), uint8(ctxs[v].length), ctxs[v], msgs[v]);
            (a, b) = MLDSA65.shake256To64(ks, MLDSA65._ptr(trM), trM.length);
            assertEq(abi.encodePacked(a, b), mus[v], "mu");

            // ExpandA check: Â[0][0] is the first 768 bytes of the packed Â.
            assertEq(_slice(h.expandA(bytes32(_slice(pks[v], 0, 32))), 0, 768), a00s[v], "A_hat[0][0]");
        }
    }

    // ── Differential vectors (dilithium-py) ──────────────────────────────────

    function test_differential_allVerify() public view {
        for (uint256 v; v < pks.length; ++v) {
            bool ok = ctxs[v].length == 0
                ? h.verify(pks[v], msgs[v], sigs[v])
                : h.verifyWithContext(pks[v], ctxs[v], msgs[v], sigs[v]);
            assertTrue(ok, string.concat("differential vector ", vm.toString(v)));
            // The context is bound: the same signature under another context fails.
            assertFalse(h.verifyWithContext(pks[v], hex"01", msgs[v], sigs[v]));
        }
        console.log("differential vectors verified:", pks.length);
    }

    // ── NIST ACVP sigVer (ML-DSA-65) ─────────────────────────────────────────

    function test_acvp_external_pure() public view {
        (uint256 pass, uint256 fail) = _runAcvp(".external", true);
        console.log("ACVP tgId 3 (external, pure): expected-pass ok", pass);
        console.log("ACVP tgId 3 (external, pure): expected-fail ok", fail);
    }

    function test_acvp_internal() public view {
        (uint256 pass, uint256 fail) = _runAcvp(".internal", false);
        console.log("ACVP tgId 10 (internal): expected-pass ok", pass);
        console.log("ACVP tgId 10 (internal): expected-fail ok", fail);
    }

    function _runAcvp(string memory g, bool external_) internal view returns (uint256 pass, uint256 fail) {
        uint256[] memory ids = vm.parseJsonUintArray(acvp, string.concat(g, ".tcId"));
        bytes[] memory pk = vm.parseJsonBytesArray(acvp, string.concat(g, ".pk"));
        bytes[] memory m = vm.parseJsonBytesArray(acvp, string.concat(g, ".msg"));
        bytes[] memory ctx = vm.parseJsonBytesArray(acvp, string.concat(g, ".ctx"));
        bytes[] memory sig = vm.parseJsonBytesArray(acvp, string.concat(g, ".sig"));
        bool[] memory expected = vm.parseJsonBoolArray(acvp, string.concat(g, ".passed"));
        string[] memory reason = vm.parseJsonStringArray(acvp, string.concat(g, ".reason"));
        for (uint256 n; n < ids.length; ++n) {
            bool got = external_
                ? h.verifyWithContext(pk[n], ctx[n], m[n], sig[n])
                : h.verifyInternal(pk[n], m[n], sig[n]);
            assertEq(got, expected[n], string.concat("tcId ", vm.toString(ids[n]), ": ", reason[n]));
            if (expected[n]) ++pass;
            else ++fail;
        }
    }

    // ── Negative tests: each must return false, never revert ─────────────────

    function test_reject_bitFlips() public view {
        (bytes memory pk, bytes memory m, bytes memory sig) = (pks[1], msgs[1], sigs[1]);
        assertTrue(h.verify(pk, m, sig));
        // c̃ (first and last byte), z (several), h (an index byte)
        uint256[7] memory sigBits = [uint256(0), 47 * 8 + 7, 48 * 8, 1000 * 8 + 3, 3247 * 8 + 7, 3250 * 8, 3248 * 8];
        for (uint256 n; n < sigBits.length; ++n) {
            assertFalse(h.verify(pk, m, _flip(sig, sigBits[n])), string.concat("sig bit ", vm.toString(sigBits[n])));
        }
        // pk: ρ and t1
        assertFalse(h.verify(_flip(pk, 0), m, sig), "pk rho");
        assertFalse(h.verify(_flip(pk, 33 * 8), m, sig), "pk t1 first");
        assertFalse(h.verify(_flip(pk, 1951 * 8 + 7), m, sig), "pk t1 last");
        // message
        assertFalse(h.verify(pk, _flip(m, 0), sig), "message");
        assertFalse(h.verify(pk, abi.encodePacked(m, bytes1(0)), sig), "message extended");
    }

    function test_reject_wrongLengths() public view {
        (bytes memory pk, bytes memory m, bytes memory sig) = (pks[1], msgs[1], sigs[1]);
        assertFalse(h.verify(_trim(pk, 1), m, sig), "short pk");
        assertFalse(h.verify(abi.encodePacked(pk, bytes1(0)), m, sig), "long pk");
        assertFalse(h.verify(pk, m, _trim(sig, 1)), "short sig");
        assertFalse(h.verify(pk, m, abi.encodePacked(sig, bytes1(0))), "long sig");
        assertFalse(h.verify("", m, sig), "empty pk");
        assertFalse(h.verify(pk, m, ""), "empty sig");
        assertFalse(h.verifyWithContext(pk, new bytes(256), m, sig), "ctx > 255");
    }

    function test_reject_malformedHints() public view {
        (bytes memory pk, bytes memory m, bytes memory sig) = (pks[1], msgs[1], sigs[1]);
        uint256 y = 48 + 3200; // hint encoding offset in σ
        uint256 total = uint8(sig[y + 55 + 5]);
        assertLt(total, 55, "fixture needs spare hint slots");

        // Hint count > ω: last row end = 56.
        bytes memory s = _copy(sig);
        s[y + 55 + 5] = bytes1(uint8(56));
        assertFalse(h.verify(pk, m, s), "count > omega");
        // Row ends decreasing.
        s = _copy(sig);
        s[y + 55 + 1] = bytes1(uint8(sig[y + 55 + 0]) == 0 ? 0 : uint8(sig[y + 55 + 0]) - 1);
        if (uint8(sig[y + 55 + 0]) > 0) assertFalse(h.verify(pk, m, s), "row ends decreasing");
        // Non-zero byte in the unused tail.
        s = _copy(sig);
        s[y + 54] = bytes1(uint8(1));
        assertFalse(h.verify(pk, m, s), "non-zero padding");
        // Non-increasing indices: swap the first two of the first row with ≥ 2 hints.
        s = _copy(sig);
        uint256 start;
        bool swapped;
        for (uint256 i; i < 6; ++i) {
            uint256 end = uint8(sig[y + 55 + i]);
            if (end >= start + 2) {
                (s[y + start], s[y + start + 1]) = (s[y + start + 1], s[y + start]);
                swapped = true;
                break;
            }
            start = end;
        }
        assertTrue(swapped, "fixture has a row with two hints");
        assertFalse(h.verify(pk, m, s), "decreasing indices");

        // Repeated index (decodes to the SAME h as the valid signature): FIPS 204
        // rejects it; dilithium-py accepts it (fixture records that).
        bytes memory dup = vm.parseJsonBytes(diff, ".malformed.duplicate");
        // Informational only (a property of the reference, not of this verifier):
        console.log("dilithium-py accepts it:", vm.parseJsonBool(diff, ".malformed.dilithiumPyAccepts"));
        assertFalse(h.verify(pk, m, dup), "repeated hint index");
    }

    /// ||z||∞ < γ1 − β is strict: raw field r encodes z = γ1 − r; valid iff β < r < 2γ1 − β.
    function test_zNormBoundary() public pure {
        uint256[4] memory raws = [uint256(196), 197, 1048379, 1048380];
        bool[4] memory want = [false, true, true, false];
        for (uint256 n; n < 4; ++n) {
            bytes memory sig = new bytes(3309);
            // fill every z coefficient with r = 1000 (in range), then plant raws[n] at coefficient 0
            for (uint256 c; c < 1280; c += 2) {
                _putPair(sig, 48 + (c / 2) * 5, 1000, 1000);
            }
            _putPair(sig, 48, raws[n], 1000);
            uint256 out = MLDSA65._allocWords(5 * 256);
            assertEq(MLDSA65.decodeZ(sig, out), want[n], vm.toString(raws[n]));
        }
    }

    function test_reject_zOutOfRange() public view {
        (bytes memory pk, bytes memory m, bytes memory sig) = (pks[1], msgs[1], sigs[1]);
        bytes memory s = _copy(sig);
        _putPair(s, 48, 196, 1000); // |z_0| = γ1 − β
        assertFalse(h.verify(pk, m, s));
        s = _copy(sig);
        _putPair(s, 48 + 5 * 300, 1000, 0xFFFFF); // z = γ1 − (2^20 − 1) = −(2^19 − 1)
        assertFalse(h.verify(pk, m, s));
    }

    /// forge-config: default.fuzz.runs = 48
    function testFuzz_reject_corruptedSignature(uint16 pos, uint8 delta) public view {
        vm.assume(delta != 0);
        (bytes memory pk, bytes memory m, bytes memory sig) = (pks[2], msgs[2], sigs[2]);
        bytes memory s = _copy(sig);
        uint256 p = uint256(pos) % s.length;
        s[p] = bytes1(uint8(s[p]) ^ delta);
        assertFalse(h.verify(pk, m, s));
    }

    /// forge-config: default.fuzz.runs = 48
    function testFuzz_reject_corruptedHints(uint8 pos, uint8 value) public view {
        (bytes memory pk, bytes memory m, bytes memory sig) = (pks[3], msgs[3], sigs[3]);
        bytes memory s = _copy(sig);
        uint256 p = 3248 + (uint256(pos) % 61);
        vm.assume(uint8(s[p]) != value);
        s[p] = bytes1(value);
        assertFalse(h.verify(pk, m, s));
    }

    // ── Precomputed Â (verifyWithExpandedA) ──────────────────────────────────

    function test_expandedA_allVerify() public view {
        for (uint256 v; v < pks.length; ++v) {
            bytes memory aHat = h.expandA(bytes32(_slice(pks[v], 0, 32)));
            assertEq(aHat.length, MLDSA65.A_HAT_BYTES);
            assertTrue(h.verifyWithExpandedA(pks[v], aHat, ctxs[v], msgs[v], sigs[v]), vm.toString(v));
        }
    }

    function test_expandedA_rejects() public view {
        (bytes memory pk, bytes memory m, bytes memory sig) = (pks[1], msgs[1], sigs[1]);
        bytes memory aHat = h.expandA(bytes32(_slice(pk, 0, 32)));
        assertFalse(h.verifyWithExpandedA(pk, _trim(aHat, 1), "", m, sig), "short aHat");
        assertFalse(h.verifyWithExpandedA(pk, "", "", m, sig), "empty aHat");
        assertFalse(h.verifyWithExpandedA(pk, _flip(aHat, 8 * 1000), "", m, sig), "tampered aHat");
        assertFalse(h.verifyWithExpandedA(pk, aHat, "", _flip(m, 0), sig), "message");
        assertFalse(h.verifyWithExpandedA(pk, aHat, "", m, _flip(sig, 0)), "c~");
        // Â of another key: fails even though it is a well-formed Â.
        bytes memory other = h.expandA(bytes32(_slice(pks[2], 0, 32))); // key seed 2 (pks[0..1] share seed 1)
        assertFalse(h.verifyWithExpandedA(pk, other, "", m, sig), "foreign aHat");
    }

    // ── Gas ──────────────────────────────────────────────────────────────────

    function test_gas_verify() public view {
        uint256 maxGas;
        for (uint256 v; v < pks.length; ++v) {
            uint256 g = gasleft();
            bool ok = h.verifyWithContext(pks[v], ctxs[v], msgs[v], sigs[v]);
            g -= gasleft();
            assertTrue(ok);
            console.log("verify gas (vector, msg bytes, gas):", v, msgs[v].length, g);
            if (g > maxGas) maxGas = g;
        }
        console.log("max verify gas over differential vectors:", maxGas);

        // With a caller-supplied Â (calldata here; from an SSTORE2 blob add
        // EXTCODECOPY of 23040 bytes, ~2.6k cold access + ~2.2k copy + memory).
        uint256 maxPre;
        for (uint256 v; v < pks.length; ++v) {
            bytes memory aHat = h.expandA(bytes32(_slice(pks[v], 0, 32)));
            uint256 g = gasleft();
            bool ok = h.verifyWithExpandedA(pks[v], aHat, ctxs[v], msgs[v], sigs[v]);
            g -= gasleft();
            assertTrue(ok);
            console.log("verifyWithExpandedA gas (vector, msg bytes, gas):", v, msgs[v].length, g);
            if (g > maxPre) maxPre = g;
        }
        console.log("max verifyWithExpandedA gas:", maxPre);
        uint256 ge = gasleft();
        h.expandA(bytes32(_slice(pks[0], 0, 32)));
        console.log("expandA (one-time, per key) gas:", ge - gasleft());
    }

    function test_gas_phases() public view {
        bytes memory mPrime = abi.encodePacked(bytes1(0), bytes1(0), msgs[1]);
        (uint256[11] memory g, bool ok, bytes memory w1) = h.phases(pks[1], mPrime, sigs[1]);
        bytes[] memory w1s = vm.parseJsonBytesArray(diff, ".w1");
        assertEq(_slice(w1, 64, 768), w1s[1], "w1Encode(w1')");
        assertTrue(ok, "phase harness reproduces c~");
        string[11] memory names = [
            "decode h + z",
            "5x NTT(z)",
            "tr = H(pk,64)",
            "mu = H(tr||M',64)",
            "SampleInBall + NTT(c)",
            "ExpandA fused with A*z (30 SHAKE128 streams)",
            "6x decode t1 + NTT + c*t1",
            "6x inverse NTT",
            "UseHint + w1Encode",
            "c~' = H(mu||w1,48)",
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

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// keccak256 built from the library's permutation (rate 136, pad 0x01 … 0x80).
    function _keccakViaLib(bytes memory data) internal pure returns (bytes32 out) {
        uint256 ks = MLDSA65.newKeccakWorkspace();
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
            MLDSA65.keccakF(ks);
        }
        bytes memory o = _readLanes(ks, 32);
        assembly ("memory-safe") {
            out := mload(add(o, 0x20))
        }
    }

    /// SHAKE via the library's absorb, squeezing `outLen` bytes across blocks.
    function _shake(bytes memory data, uint256 rate, uint256 outLen) internal pure returns (bytes memory out) {
        uint256 ks = MLDSA65.newKeccakWorkspace();
        MLDSA65.absorb(ks, MLDSA65._ptr(data), data.length, rate);
        out = new bytes(0);
        while (out.length < outLen) {
            uint256 take = outLen - out.length < rate ? outLen - out.length : rate;
            out = abi.encodePacked(out, _readLanes(ks, take));
            if (out.length < outLen) MLDSA65.keccakF(ks);
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

    /// Writes two 20-bit little-endian fields (one z pair) at byte offset `o`.
    function _putPair(bytes memory s, uint256 o, uint256 r0, uint256 r1) internal pure {
        uint256 v = r0 | (r1 << 20);
        for (uint256 i; i < 5; ++i) {
            s[o + i] = bytes1(uint8(v >> (8 * i)));
        }
    }
}
