// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.24;

/// @title MLDSA65 — FIPS 204 ML-DSA-65 signature verification in pure Solidity
/// @notice `verify` / `verifyWithContext` implement ML-DSA.Verify (FIPS 204
///         Algorithm 3, the "pure" external interface — NOT HashML-DSA) on top of
///         ML-DSA.Verify_internal (Algorithm 8), exposed as `verifyInternal`.
///         Every malformed input — wrong lengths, an over-long context, a hint
///         encoding Algorithm 21 rejects, ||z||∞ ≥ γ1 − β — yields `false`; the
///         library never reverts on attacker-controlled bytes.
///         `precompute` + `verifyPrecomputed` split off the per-key work (tr, Â and
///         NTT(t1·2^d)); `MLDSA65KeyFactory` stores it in data contracts.
/// @dev    Parameter set ML-DSA-65: q = 8380417, d = 13, τ = 49, λ = 192 (c̃ is 48
///         bytes), γ1 = 2^19, γ2 = (q − 1)/32, (k, ℓ) = (6, 5), η = 4, β = τ·η = 196,
///         ω = 55. pk = ρ ‖ t1 (32 + 6·320 = 1952 bytes); σ = c̃ ‖ z ‖ h
///         (48 + 5·640 + 61 = 3309 bytes).
///
///         Verification computes, row by row (i = 0..k−1),
///             w′_i = NTT⁻¹( Σ_j Â[i][j]∘ẑ_j − ĉ∘NTT(t1_i)·2^d )
///         then w1′ = UseHint(h, w′) and checks c̃ = H(μ ‖ w1Encode(w1′), 48) with
///         μ = H(tr ‖ M′, 64), tr = H(pk, 64), H = SHAKE256.
///
///         Hot paths are Yul: the Keccak-f[1600] permutation (SHAKE is NOT the
///         keccak256 opcode — different padding — so the sponge is built here),
///         the NTTs, and ExpandA, which is FUSED with the matrix-vector product:
///         each SHAKE128 coefficient of Â[i][j] is multiplied into the row
///         accumulator the moment it is accepted, so Â is never materialised.
///         The permutation is 4-WAY SIMD: every word holds the same lane of four
///         independent Keccak instances (instance s in bits [64s, 64s + 64)), so the
///         30 SHAKE128 streams of ExpandA run four at a time for little more than
///         the cost of one. Single-stream hashing (SHAKE256) just uses slot 0.
///
///         Memory conventions: every polynomial is 256 consecutive 32-byte words,
///         one coefficient per word, addressed by a raw memory pointer (`uint256`).
///         Coefficients are kept LAZILY reduced (a small multiple of q) inside the
///         NTTs; `mulmod`/`addmod` bring them back into [0, q) where it matters.
///         Keccak state: 25 words, one lane per word, four instances per lane.
library MLDSA65 {
    // ── Parameters (FIPS 204, Table 1, ML-DSA-65) ────────────────────────────

    uint256 internal constant Q = 8380417;
    uint256 internal constant D = 13;
    uint256 internal constant TAU = 49;
    uint256 internal constant GAMMA1 = 1 << 19;
    uint256 internal constant GAMMA2 = (Q - 1) / 32; // 261888
    uint256 internal constant K = 6;
    uint256 internal constant L = 5;
    uint256 internal constant BETA = 196; // τ·η
    uint256 internal constant OMEGA = 55;

    uint256 internal constant C_TILDE_BYTES = 48; //  λ/4
    uint256 internal constant PK_BYTES = 1952; //     32 + k·32·10
    uint256 internal constant Z_POLY_BYTES = 640; //  32·20 (γ1 = 2^19 → 20 bits)
    uint256 internal constant SIG_BYTES = 3309; //    48 + ℓ·640 + ω + k
    uint256 internal constant T1_POLY_BYTES = 320; // 32·10
    uint256 internal constant W1_POLY_BYTES = 128; // 32·4 (w1 ∈ [0, 15])

    /// @dev SHAKE rates in bytes (FIPS 202; the SHAKE domain/pad byte 0x1F is in `absorb`).
    uint256 private constant RATE128 = 168;
    uint256 private constant RATE256 = 136;

    // ── Keccak workspace layout (one allocation, reused by every hash) ───────
    //   [0x000, 0x320)  state A, 25 lanes
    //   [0x320, 0x640)  scratch B (the permutation ping-pongs A → B → A), also
    //                   used to stage the final padded block while absorbing
    //   [0x640, 0x940)  the 24 ι round constants, replicated into all 4 slots
    //   [0x940, 0x9e0)  θ's D[0..4], staged in memory by the permutation
    // Slot s of every word (bits [64s, 64s + 64)) is an independent instance; the
    // single-stream sponge uses slot 0 and ignores whatever slots 1..3 compute.
    uint256 private constant KS_WORDS = 79;

    /// @dev Row accumulators / sampled polynomials are laid out with a stride of
    ///      264 words: 256 coefficients + 8 words of slack, because the sampler
    ///      writes a whole group of 8 candidates before checking for 256.
    uint256 internal constant ACC_STRIDE = 0x2100;

    /// @dev Per-key precomputation (`precompute`), all coefficients 3 bytes big-endian:
    ///        [0, 64)          tr = H(pk, 64)
    ///        [64, 23104)      Â = ExpandA(ρ): k·ℓ = 30 polynomials, order [i][j][n]
    ///        [23104, 27712)   t̂ = NTT(t1·2^d) mod q: k = 6 polynomials, order [i][n]
    ///      27712 bytes exceed EIP-170 (24576), so `MLDSA65KeyFactory` stores Â and tr ‖ t̂
    ///      in two data contracts.
    uint256 internal constant TR_BYTES = 64;
    uint256 internal constant A_HAT_BYTES = 23040; //   30·256·3
    uint256 internal constant T_HAT_BYTES = 4608; //    6·256·3
    uint256 internal constant BLOB_BYTES = 27712; //    64 + 23040 + 4608
    uint256 private constant A_HAT_OFFSET = 64;
    uint256 private constant T_HAT_OFFSET = 23104;

    // ── Public API ───────────────────────────────────────────────────────────

    /// @notice ML-DSA.Verify (Algorithm 3) with the empty context string. The
    ///         reference path: everything is derived from the public key.
    function verify(bytes memory publicKey, bytes memory message, bytes memory signature)
        internal
        view
        returns (bool)
    {
        return verifyWithContext(publicKey, "", message, signature);
    }

    /// @notice ML-DSA.Verify (Algorithm 3): M′ = 0x00 ‖ |ctx| ‖ ctx ‖ M.
    /// @dev    A context longer than 255 bytes is an error in FIPS 204; here it is `false`.
    function verifyWithContext(
        bytes memory publicKey,
        bytes memory ctx,
        bytes memory message,
        bytes memory signature
    ) internal view returns (bool) {
        if (ctx.length > 255) return false;
        return verifyInternal(publicKey, _formatMessage(ctx, message), signature);
    }

    /// @notice ML-DSA.Verify_internal (Algorithm 8) over an already-formatted M′.
    /// @dev    Exposed for the ACVP "internal interface" vectors. Callers that want
    ///         FIPS 204 domain separation must use `verify` / `verifyWithContext`.
    function verifyInternal(bytes memory publicKey, bytes memory mPrime, bytes memory signature)
        internal
        view
        returns (bool)
    {
        if (publicKey.length != PK_BYTES) return false;
        return _verifyCore(publicKey, "", mPrime, signature);
    }

    /// @notice Everything in Algorithm 8 that depends only on the public key, done
    ///         once: tr = H(pk, 64), Â = ExpandA(ρ), t̂ = NTT(t1·2^d). Layout at
    ///         BLOB_BYTES. Returns empty bytes for a wrongly-sized key.
    /// @dev    Deterministic in pk alone, so the blob can be re-derived and compared
    ///         by anyone; `MLDSA65KeyFactory` runs it on-chain from the key itself.
    function precompute(bytes memory publicKey) internal pure returns (bytes memory blob) {
        if (publicKey.length != PK_BYTES) return blob;
        blob = new bytes(BLOB_BYTES);
        uint256 out = _ptr(blob);
        uint256 ks = newKeccakWorkspace();
        _writeTr(ks, publicKey, out);
        _writeAHat(ks, publicKey, out + A_HAT_OFFSET);
        _writeTHat(publicKey, out + T_HAT_OFFSET);
    }

    /// @notice The Â part of `precompute` alone (A_HAT_BYTES; depends on ρ only).
    ///         Empty for a wrongly-sized key.
    function precomputeA(bytes memory publicKey) internal pure returns (bytes memory aHat) {
        if (publicKey.length != PK_BYTES) return aHat;
        aHat = new bytes(A_HAT_BYTES);
        _writeAHat(newKeccakWorkspace(), publicKey, _ptr(aHat));
    }

    /// @notice The tr ‖ t̂ parts of `precompute` (TR_BYTES + T_HAT_BYTES). Empty for
    ///         a wrongly-sized key.
    function precomputeT(bytes memory publicKey) internal pure returns (bytes memory trTHat) {
        if (publicKey.length != PK_BYTES) return trTHat;
        trTHat = new bytes(TR_BYTES + T_HAT_BYTES);
        _writeTr(newKeccakWorkspace(), publicKey, _ptr(trTHat));
        _writeTHat(publicKey, _ptr(trTHat) + TR_BYTES);
    }

    /// @dev tr = H(pk, 64) → 64 bytes at `out`.
    function _writeTr(uint256 ks, bytes memory publicKey, uint256 out) private pure {
        (bytes32 tr0, bytes32 tr1) = shake256To64(ks, _ptr(publicKey), PK_BYTES);
        assembly ("memory-safe") {
            mstore(out, tr0)
            mstore(add(out, 0x20), tr1)
        }
    }

    /// @dev Â = ExpandA(ρ), packed → A_HAT_BYTES at `out`.
    function _writeAHat(uint256 ks, bytes memory publicKey, uint256 out) private pure {
        bytes32 rho;
        assembly ("memory-safe") {
            rho := mload(add(publicKey, 0x20))
        }
        uint256 polys = _allocStrided(K * L);
        uint256 ones = _allocStrided(1); // sample against z ≡ 1: acc = Â[i][j] itself
        assembly ("memory-safe") {
            for { let p := ones } lt(p, add(ones, ACC_STRIDE)) { p := add(p, 0x20) } { mstore(p, 1) }
        }
        sampleMatrix(ks, rho, ones, 0, polys, false);
        for (uint256 m; m < K * L; ++m) {
            _pack3(polys + m * ACC_STRIDE, out + m * 768);
        }
    }

    /// @dev t̂ = NTT(t1·2^d) mod q, packed → T_HAT_BYTES at `out`.
    function _writeTHat(bytes memory publicKey, uint256 out) private pure {
        uint256 zp = _ptr(_zetas());
        uint256 t = _allocWords(256);
        for (uint256 i; i < K; ++i) {
            decodeT1(publicKey, i, t);
            ntt(t, zp);
            _scale(t, 1 << D); // also reduces into [0, q)
            _pack3(t, out + i * 768);
        }
    }

    /// @notice `verify` against a `precompute` blob instead of the public key.
    /// @dev    TRUST: the blob is taken as `precompute(pk)` of the key the caller
    ///         means. Verification checks the signature against tr, Â and t̂ ONLY —
    ///         the key itself is not available here, so nothing ties the blob back to
    ///         it. A blob built from Â/t̂ chosen by an attacker makes forgery easy;
    ///         the blob must come from `precompute` over the registered key (see
    ///         `MLDSA65KeyFactory`, which computes it on-chain from the key and keys
    ///         both data contracts by keccak256(pk)). A blob of another (honest) key simply fails
    ///         to verify. Returns false for a blob that is not BLOB_BYTES long.
    function verifyPrecomputed(bytes memory blob, bytes memory message, bytes memory signature)
        internal
        view
        returns (bool)
    {
        return verifyPrecomputedWithContext(blob, "", message, signature);
    }

    /// @notice `verifyPrecomputed` with a context string (Algorithm 3's M′).
    function verifyPrecomputedWithContext(
        bytes memory blob,
        bytes memory ctx,
        bytes memory message,
        bytes memory signature
    ) internal view returns (bool) {
        if (ctx.length > 255) return false;
        return verifyPrecomputedInternal(blob, _formatMessage(ctx, message), signature);
    }

    /// @notice Algorithm 8 over a formatted M′, against a `precompute` blob.
    function verifyPrecomputedInternal(bytes memory blob, bytes memory mPrime, bytes memory signature)
        internal
        view
        returns (bool)
    {
        if (blob.length != BLOB_BYTES) return false;
        return _verifyCore("", blob, mPrime, signature);
    }

    /// @dev M′ = 0x00 ‖ |ctx| ‖ ctx ‖ M (caller checked |ctx| ≤ 255).
    function _formatMessage(bytes memory ctx, bytes memory message) private pure returns (bytes memory) {
        return abi.encodePacked(bytes1(0x00), uint8(ctx.length), ctx, message);
    }

    /// @dev Algorithm 8. Exactly one of `publicKey` / `blob` is non-empty (length
    ///      already checked): with the key, tr is hashed, Â is streamed from ρ (fused
    ///      with Â∘ẑ) and t̂ is transformed here; with the blob, all three are read.
    function _verifyCore(bytes memory publicKey, bytes memory blob, bytes memory mPrime, bytes memory signature)
        private
        pure
        returns (bool)
    {
        if (signature.length != SIG_BYTES) return false;
        bool pre = blob.length != 0;

        // Algorithm 21 (HintBitUnpack): cheap, and a malformed h is a rejection.
        (bool hintOk, uint256[K] memory hints) = hintBitUnpack(signature);
        if (!hintOk) return false;

        // z ← BitUnpack(...); reject unless ||z||∞ < γ1 − β (step 13 of Algorithm 8,
        // checked early — the result is a conjunction, so order is immaterial).
        // 8 words of slack after the last polynomial: the sampler may read past it.
        uint256 zHat = _allocWords(L * 256 + 8);
        if (!decodeZ(signature, zHat)) return false;

        uint256 zp = _ptr(_zetas());
        for (uint256 j; j < L; ++j) {
            ntt(zHat + j * 0x2000, zp);
        }

        uint256 ks = newKeccakWorkspace();

        // tr ← H(pk, 64) (or from the blob);  μ ← H(BytesToBits(tr) ‖ M′, 64)
        bytes memory w1Buf = new bytes(64 + K * W1_POLY_BYTES); // μ ‖ w1Encode(w1′)
        {
            bytes32 tr0;
            bytes32 tr1;
            if (pre) {
                assembly ("memory-safe") {
                    tr0 := mload(add(blob, 0x20))
                    tr1 := mload(add(blob, 0x40))
                }
            } else {
                (tr0, tr1) = shake256To64(ks, _ptr(publicKey), PK_BYTES);
            }
            bytes memory trM = abi.encodePacked(tr0, tr1, mPrime);
            (bytes32 mu0, bytes32 mu1) = shake256To64(ks, _ptr(trM), trM.length);
            assembly ("memory-safe") {
                mstore(add(w1Buf, 0x20), mu0)
                mstore(add(w1Buf, 0x40), mu1)
            }
        }

        // c ← SampleInBall(c̃);  ĉ = NTT(c). On the key path ĉ′ = ĉ·2^d folds the
        // t1·2^d scaling into ĉ; the blob's t̂ already carries it.
        uint256 cHat = _allocWords(256);
        sampleInBall(ks, _ptr(signature), cHat);
        ntt(cHat, zp);
        if (!pre) _scale(cHat, 1 << D);

        // acc_i = Σ_j Â[i][j]∘ẑ_j for all rows (unreduced, < 5·q·10q < 2^56).
        uint256 accs = _allocStrided(K);
        if (pre) {
            mulPackedA(_ptr(blob) + A_HAT_OFFSET, zHat, accs);
        } else {
            bytes32 rho;
            assembly ("memory-safe") {
                rho := mload(add(publicKey, 0x20))
            }
            sampleMatrix(ks, rho, zHat, 0x2000, accs, true);
        }

        uint256 t1Hat = pre ? 0 : _allocWords(256);
        for (uint256 i; i < K; ++i) {
            uint256 acc = accs + i * ACC_STRIDE;
            // acc = acc − ĉ∘t̂_i, reduced into [0, q); then NTT⁻¹.
            if (pre) {
                _subProductPacked(acc, cHat, _ptr(blob) + T_HAT_OFFSET + i * 768);
            } else {
                decodeT1(publicKey, i, t1Hat);
                ntt(t1Hat, zp);
                _subProduct(acc, cHat, t1Hat);
            }
            invNtt(acc, zp);
            // w1′_i = UseHint(h_i, w′_i), packed straight into the hash input.
            useHintPack(acc, hints[i], _ptr(w1Buf) + 64 + i * W1_POLY_BYTES);
        }

        // c̃′ ← H(μ ‖ w1Encode(w1′), λ/4) and compare with c̃.
        (bytes32 c0, bytes32 c1) = shake256To64(ks, _ptr(w1Buf), w1Buf.length);
        bool same;
        assembly ("memory-safe") {
            let s := add(signature, 0x20)
            let hi := not(sub(shl(128, 1), 1)) // top 16 bytes: c̃ is 48 = 32 + 16 bytes
            same := and(eq(c0, mload(s)), eq(and(c1, hi), and(mload(add(s, 0x20)), hi)))
        }
        return same;
    }

    // ── Decoding (FIPS 204 §7.2 / §7.1) ──────────────────────────────────────

    /// @notice HintBitUnpack (Algorithm 21) of σ's last ω + k bytes, as k bitmaps
    ///         (bit n of hints[i] ⇔ h_i has a 1 at coefficient n).
    /// @return ok false where Algorithm 21 returns ⊥:
    ///         - a row end y[ω+i] below the previous end, or above ω;
    ///         - indices within a row not STRICTLY increasing (a repeated index is
    ///           malformed even though it would decode to the same h — accepting it
    ///           would break strong unforgeability);
    ///         - a non-zero byte in the unused tail y[Index..ω).
    function hintBitUnpack(bytes memory signature) internal pure returns (bool ok, uint256[K] memory hints) {
        assembly ("memory-safe") {
            // y = the 61-byte hint encoding, at σ offset 48 + 3200
            let y := add(signature, add(0x20, 3248))
            ok := 1
            let index := 0
            for { let i := 0 } lt(i, 6) { i := add(i, 1) } {
                let lim := byte(0, mload(add(y, add(55, i))))
                if or(lt(lim, index), gt(lim, 55)) {
                    ok := 0
                    break
                }
                let first := index
                let bits := 0
                for {} lt(index, lim) { index := add(index, 1) } {
                    let cur := byte(0, mload(add(y, index)))
                    if gt(index, first) {
                        if iszero(lt(byte(0, mload(add(y, sub(index, 1)))), cur)) {
                            ok := 0
                            break
                        }
                    }
                    bits := or(bits, shl(cur, 1))
                }
                if iszero(ok) { break }
                mstore(add(hints, shl(5, i)), bits)
            }
            if ok {
                for {} lt(index, 55) { index := add(index, 1) } {
                    if byte(0, mload(add(y, index))) {
                        ok := 0
                        break
                    }
                }
            }
        }
    }

    /// @notice z ← BitUnpack(σ[48 .. 3248], γ1 − 1, γ1) into ℓ polynomials at `out`,
    ///         as residues mod q (lazily: in [0, 2q)).
    /// @return ok ||z||∞ < γ1 − β.
    /// @dev    Each coefficient is z = γ1 − r with r a 20-bit little-endian field
    ///         (two per 5 bytes). |z| < γ1 − β ⇔ β < r < 2γ1 − β; the residue is
    ///         q + γ1 − r ∈ (q − γ1, q + γ1), which the NTT accepts as is.
    function decodeZ(bytes memory signature, uint256 out) internal pure returns (bool ok) {
        assembly ("memory-safe") {
            let src := add(signature, add(0x20, 48))
            let end := add(out, mul(0x2000, 5))
            ok := 1
            for {} lt(out, end) { out := add(out, 0x40) } {
                let w := mload(src)
                let b2 := byte(2, w)
                let r0 := or(or(byte(0, w), shl(8, byte(1, w))), shl(16, and(b2, 0x0f)))
                let r1 := or(or(shr(4, b2), shl(4, byte(3, w))), shl(12, byte(4, w)))
                // β < r < 2γ1 − β  (2γ1 − β = 1048380)
                ok := and(ok, and(and(gt(r0, 196), lt(r0, 1048380)), and(gt(r1, 196), lt(r1, 1048380))))
                mstore(out, sub(8904705, r0)) //          q + γ1 = 8904705
                mstore(add(out, 0x20), sub(8904705, r1))
                src := add(src, 5)
            }
        }
    }

    /// @notice t1_i ← SimpleBitUnpack of row i of pk (10-bit little-endian fields,
    ///         four per 5 bytes) into the polynomial at `out`.
    function decodeT1(bytes memory publicKey, uint256 i, uint256 out) internal pure {
        assembly ("memory-safe") {
            let src := add(add(publicKey, 0x40), mul(i, 320)) // skip length word and ρ
            let end := add(out, 0x2000)
            for {} lt(out, end) { out := add(out, 0x80) } {
                let w := mload(src)
                let b1 := byte(1, w)
                let b2 := byte(2, w)
                let b3 := byte(3, w)
                mstore(out, or(byte(0, w), shl(8, and(b1, 0x03))))
                mstore(add(out, 0x20), or(shr(2, b1), shl(6, and(b2, 0x0f))))
                mstore(add(out, 0x40), or(shr(4, b2), shl(4, and(b3, 0x3f))))
                mstore(add(out, 0x60), or(shr(6, b3), shl(2, byte(4, w))))
                src := add(src, 5)
            }
        }
    }

    // ── Sampling (FIPS 204 §7.3) ─────────────────────────────────────────────

    /// @notice SampleInBall (Algorithm 29): c with τ = 49 coefficients ±1, written
    ///         as residues (1 or q − 1) into the zeroed polynomial at `c`.
    /// @dev    Absorbs ALL 48 bytes of c̃ (final FIPS 204; the draft used 32). The
    ///         first 8 squeezed bytes are the sign bits — exactly Keccak lane 0,
    ///         little-endian — then one byte per draw, rejecting j > i.
    function sampleInBall(uint256 ks, uint256 sigData, uint256 c) internal pure {
        absorb(ks, sigData, C_TILDE_BYTES, RATE256);
        uint256 signs;
        assembly ("memory-safe") {
            signs := and(mload(ks), 0xffffffffffffffff) // lane 0, slot 0
        }
        uint256 pos = 8;
        for (uint256 i = 256 - TAU; i < 256; ++i) {
            uint256 j;
            while (true) {
                if (pos == RATE256) {
                    keccakF(ks);
                    pos = 0;
                }
                assembly ("memory-safe") {
                    j := and(shr(shl(3, and(pos, 7)), mload(add(ks, shl(5, shr(3, pos))))), 0xff)
                }
                ++pos;
                if (j <= i) break;
            }
            assembly ("memory-safe") {
                let pi := add(c, shl(5, i))
                let pj := add(c, shl(5, j))
                mstore(pi, mload(pj))
                // (−1)^{h[i + τ − 256]}: 1, or q − 1
                mstore(pj, add(1, mul(and(signs, 1), 8380415)))
            }
            signs >>= 1;
        }
    }

    /// @notice The 30 RejNTTPoly streams of ExpandA (Algorithms 30 & 32),
    ///         Â[i][j] = RejNTTPoly(ρ ‖ IntegerToBytes(j,1) ‖ IntegerToBytes(i,1)),
    ///         run four at a time on the 4-way permutation. Each accepted
    ///         coefficient a of Â[i][j] at position n does
    ///             acc[n] += a · z_j[n],  z_j = zBase + j·zStride,
    ///         where acc is row i's accumulator (`perRow`) or stream 5i + j's own
    ///         polynomial (`!perRow`, used by `precompute` with z ≡ 1, zStride = 0).
    ///         Accumulators (stride ACC_STRIDE) must start zeroed.
    /// @dev    A SHAKE128 block is 168 bytes = 56 candidates of 3 bytes, and every 3
    ///         lanes (192 bits) hold exactly 8 of them, so a candidate never
    ///         straddles a lane group: CoeffFromThreeBytes is `(X >> 24t) & 0x7FFFFF`
    ///         (the mask is the "b2 mod 128" of Algorithm 14). 256 is checked once
    ///         per group, so up to 7 surplus candidates land in the 8 slack words
    ///         after each accumulator (and read slack after z) — never used.
    function sampleMatrix(uint256 ks, bytes32 rho, uint256 zBase, uint256 zStride, uint256 accBase, bool perRow)
        internal
        pure
    {
        for (uint256 b; b < 8; ++b) {
            // n_s (byte offset of the next coefficient) of the four slots, packed
            // 16 bits each; an unused slot (stream ≥ 30) starts finished.
            uint256 ns;
            for (uint256 s; s < 4; ++s) {
                if (4 * b + s >= K * L) ns |= 0x2000 << (16 * s);
            }
            _initBatch(ks, rho, b);
            while (true) {
                keccakF(ks);
                bool allDone = true;
                for (uint256 s; s < 4; ++s) {
                    uint256 n = (ns >> (16 * s)) & 0xffff;
                    if (n >= 0x2000) continue;
                    uint256 m = 4 * b + s; // stream index 5i + j
                    uint256 acc = accBase + (perRow ? m / L : m) * ACC_STRIDE;
                    n = _drainSlot(ks, s, n, zBase + (m % L) * zStride, acc);
                    ns = (ns & ~(0xffff << (16 * s))) | (n << (16 * s));
                    if (n < 0x2000) allDone = false;
                }
                if (allDone) break;
            }
        }
    }

    /// @dev Absorbs ρ ‖ j ‖ i into the four slots of the state (streams 4b..4b+3).
    ///      The 34-byte input fits one SHAKE128 block, so the padded block is written
    ///      directly: lanes 0..3 = ρ, lane 4 = j | i << 8 | 0x1F << 16 (SHAKE domain
    ///      bits + first pad bit at byte 34), lane 20 = 0x80 << 56 (last pad bit,
    ///      byte 167). The caller then runs the permutation.
    function _initBatch(uint256 ks, bytes32 rho, uint256 b) private pure {
        assembly ("memory-safe") {
            for { let o := 0 } lt(o, 0x320) { o := add(o, 0x20) } { mstore(add(ks, o), 0) }
            let w := _bswap64x4(rho)
            let p := 0x0000000000000001000000000000000100000000000000010000000000000001 // replicate into all 4 slots
            mstore(ks, mul(shr(192, w), p))
            mstore(add(ks, 0x20), mul(and(shr(128, w), 0xffffffffffffffff), p))
            mstore(add(ks, 0x40), mul(and(shr(64, w), 0xffffffffffffffff), p))
            mstore(add(ks, 0x60), mul(and(w, 0xffffffffffffffff), p))
            let l4 := 0
            for { let s := 0 } lt(s, 4) { s := add(s, 1) } {
                let m := add(shl(2, b), s)
                l4 := or(l4, shl(shl(6, s), or(or(mod(m, 5), shl(8, div(m, 5))), 0x1f0000)))
            }
            mstore(add(ks, 0x80), l4)
            mstore(add(ks, 0x280), mul(0x8000000000000000, p))

            function _bswap64x4(x) -> y {
                x := or(
                    and(shr(8, x), 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff),
                    shl(8, and(x, 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff))
                )
                x := or(
                    and(shr(16, x), 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff),
                    shl(16, and(x, 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff))
                )
                y := or(
                    and(shr(32, x), 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff),
                    shl(32, and(x, 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff))
                )
            }
        }
    }

    /// @dev Consumes slot s's current 168-byte block: rejection-samples its 56
    ///      candidates into acc[n..] += v·z[n..]. n is a byte offset; returns it.
    function _drainSlot(uint256 ks, uint256 s, uint256 n, uint256 z, uint256 acc) private pure returns (uint256) {
        assembly ("memory-safe") {
            let sh := shl(6, s)
            let m := 0xffffffffffffffff
            for { let g := ks } lt(g, add(ks, 0x2a0)) { g := add(g, 0x60) } {
                if iszero(lt(n, 0x2000)) { break }
                // lanes g, g+1, g+2 of this slot as one 192-bit little-endian integer
                let x := or(
                    or(and(shr(sh, mload(g)), m), shl(64, and(shr(sh, mload(add(g, 0x20))), m))),
                    shl(128, and(shr(sh, mload(add(g, 0x40))), m))
                )
                let v := and(x, 0x7fffff)
                if lt(v, Q) {
                    let pa := add(acc, n)
                    mstore(pa, add(mload(pa), mul(v, mload(add(z, n)))))
                    n := add(n, 0x20)
                }
                v := and(shr(24, x), 0x7fffff)
                if lt(v, Q) {
                    let pa := add(acc, n)
                    mstore(pa, add(mload(pa), mul(v, mload(add(z, n)))))
                    n := add(n, 0x20)
                }
                v := and(shr(48, x), 0x7fffff)
                if lt(v, Q) {
                    let pa := add(acc, n)
                    mstore(pa, add(mload(pa), mul(v, mload(add(z, n)))))
                    n := add(n, 0x20)
                }
                v := and(shr(72, x), 0x7fffff)
                if lt(v, Q) {
                    let pa := add(acc, n)
                    mstore(pa, add(mload(pa), mul(v, mload(add(z, n)))))
                    n := add(n, 0x20)
                }
                v := and(shr(96, x), 0x7fffff)
                if lt(v, Q) {
                    let pa := add(acc, n)
                    mstore(pa, add(mload(pa), mul(v, mload(add(z, n)))))
                    n := add(n, 0x20)
                }
                v := and(shr(120, x), 0x7fffff)
                if lt(v, Q) {
                    let pa := add(acc, n)
                    mstore(pa, add(mload(pa), mul(v, mload(add(z, n)))))
                    n := add(n, 0x20)
                }
                v := and(shr(144, x), 0x7fffff)
                if lt(v, Q) {
                    let pa := add(acc, n)
                    mstore(pa, add(mload(pa), mul(v, mload(add(z, n)))))
                    n := add(n, 0x20)
                }
                v := and(shr(168, x), 0x7fffff)
                if lt(v, Q) {
                    let pa := add(acc, n)
                    mstore(pa, add(mload(pa), mul(v, mload(add(z, n)))))
                    n := add(n, 0x20)
                }
            }
        }
        return n;
    }

    /// @notice acc_i[n] = Σ_j Â[i][j][n]·ẑ_j[n] from a packed Â at `src` (layout
    ///         as in BLOB_BYTES); accumulators at stride ACC_STRIDE, unreduced like
    ///         the streamed path.
    function mulPackedA(uint256 src, uint256 zHat, uint256 accs) internal pure {
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, 6) { i := add(i, 1) } {
                let acc := add(accs, mul(i, ACC_STRIDE))
                for { let j := 0 } lt(j, 5) { j := add(j, 1) } {
                    let z := add(zHat, shl(13, j))
                    for { let n := 0 } lt(n, 0x2000) { n := add(n, 0x20) } {
                        let pa := add(acc, n)
                        mstore(pa, add(mload(pa), mul(shr(232, mload(src)), mload(add(z, n)))))
                        src := add(src, 3)
                    }
                }
            }
        }
    }

    // ── Polynomial arithmetic ────────────────────────────────────────────────

    /// @notice In-place NTT (Algorithm 41) of the polynomial at `p`.
    /// @dev    Radix-4: the 8 layers are done as 4 merged pairs, so each coefficient
    ///         is loaded and stored 4 times instead of 8. Merging layer len (block b,
    ///         ζ_{2^ℓ+b}) with layer len/2 (its two sub-blocks 2b, 2b+1) is exactly the
    ///         sequence of Algorithm 41 on the 4 points (j, j+len/2, j+len, j+3len/2).
    ///         Lazy: butterflies do (a + t, a + q − t) with t = ζ·b mod q < q, so a
    ///         bound B on the inputs becomes B + 8q after the 8 layers. Outputs are
    ///         congruent mod q, not reduced.
    function ntt(uint256 p, uint256 zp) internal pure {
        assembly ("memory-safe") {
            // Four points j, j+h, j+2h, j+3h (h = len/2 in bytes), for j in [s, e).
            function quad(j, e, h, z1, z2, z3) {
                let h2 := add(h, h)
                for {} lt(j, e) { j := add(j, 0x20) } {
                    let a0 := mload(j)
                    let a1 := mload(add(j, h))
                    let a2 := mload(add(j, h2))
                    let a3 := mload(add(add(j, h2), h))
                    // layer len: (a0, a2), (a1, a3) with ζ1
                    let t := mulmod(z1, a2, Q)
                    a2 := sub(add(a0, Q), t)
                    a0 := add(a0, t)
                    t := mulmod(z1, a3, Q)
                    a3 := sub(add(a1, Q), t)
                    a1 := add(a1, t)
                    // layer len/2: (a0, a1) with ζ2, (a2, a3) with ζ3
                    t := mulmod(z2, a1, Q)
                    mstore(add(j, h), sub(add(a0, Q), t))
                    mstore(j, add(a0, t))
                    t := mulmod(z3, a3, Q)
                    mstore(add(add(j, h2), h), sub(add(a2, Q), t))
                    mstore(add(j, h2), add(a2, t))
                }
            }
            function zeta(zp_, m) -> z {
                z := shr(224, mload(add(zp_, shl(2, m))))
            }
            for { let l := 0 } lt(l, 8) { l := add(l, 2) } {
                let nb := shl(l, 1) //               2^ℓ blocks at the first merged layer
                let h := shl(4, shr(l, 128)) //      len/2 in bytes (len = 128 >> ℓ)
                for { let b := 0 } lt(b, nb) { b := add(b, 1) } {
                    let s := add(p, mul(b, shl(2, h))) // block of 2·len coefficients
                    quad(
                        s,
                        add(s, h),
                        h,
                        zeta(zp, add(nb, b)),
                        zeta(zp, add(shl(1, nb), shl(1, b))),
                        zeta(zp, add(add(shl(1, nb), shl(1, b)), 1))
                    )
                }
            }
        }
    }

    /// @notice In-place inverse NTT (Algorithm 42) of the polynomial at `p`; inputs
    ///         must be < q, outputs are fully reduced into [0, q).
    /// @dev    Radix-4 like `ntt`: layer len (blocks 2b′, 2b′+1, ζ_{2B−1−2b′} and
    ///         ζ_{2B−2−2b′}, B = 128/len) merged with layer 2len (block b′,
    ///         ζ_{B−1−b′}). (t, u) → (t + u, −ζ·(t − u)) is computed as
    ///         ζ·(u + 2^9·q − t) mod q. Sums at most double per layer, so every input
    ///         to a subtraction is < 2^7·q and 2^9·q keeps it positive. The final
    ///         ·256⁻¹ is folded into the last merged pair (ζ_1 premultiplied).
    function invNtt(uint256 p, uint256 zp) internal pure {
        assembly ("memory-safe") {
            // Points j, j+h, j+2h, j+3h (h = len in bytes); f = 1 except for the last
            // pair, where f = 256⁻¹ scales the sums and z3 arrives premultiplied.
            function quad(j, e, h, z1, z2, z3, f) {
                let h2 := add(h, h)
                for {} lt(j, e) { j := add(j, 0x20) } {
                    let a0 := mload(j)
                    let a1 := mload(add(j, h))
                    let a2 := mload(add(j, h2))
                    let a3 := mload(add(add(j, h2), h))
                    // layer len: (a0, a1) with ζ1, (a2, a3) with ζ2
                    let t := add(a0, a1)
                    a1 := mulmod(z1, sub(add(a1, 4290773504), a0), Q) // 2^9·q
                    a0 := t
                    t := add(a2, a3)
                    a3 := mulmod(z2, sub(add(a3, 4290773504), a2), Q)
                    a2 := t
                    // layer 2len: (a0, a2), (a1, a3) with ζ3
                    mstore(add(j, h2), mulmod(z3, sub(add(a2, 4290773504), a0), Q))
                    mstore(j, mulmod(add(a0, a2), f, Q))
                    mstore(add(add(j, h2), h), mulmod(z3, sub(add(a3, 4290773504), a1), Q))
                    mstore(add(j, h), mulmod(add(a1, a3), f, Q))
                }
            }
            let end := add(p, 0x2000)
            for { let l := 0 } lt(l, 8) { l := add(l, 2) } {
                // B = 128/len blocks at the first merged layer; super-block b′ uses
                // ζ_{2B−1−2b′}, ζ_{2B−2−2b′} and ζ_{B−1−b′}, walked down by pointer
                // (zeta table entries are 4 bytes).
                let z12 := add(zp, shl(2, sub(shl(1, shr(l, 128)), 1)))
                let z3 := add(zp, shl(2, sub(shr(l, 128), 1)))
                let h := shl(5, shl(l, 1)) // len in bytes (len = 2^ℓ)
                let f := 1
                if eq(l, 6) { f := 8347681 } // 256⁻¹ mod q
                for { let s := p } lt(s, end) { s := add(s, shl(2, h)) } {
                    quad(
                        s,
                        add(s, h),
                        h,
                        shr(224, mload(z12)),
                        shr(224, mload(sub(z12, 4))),
                        mulmod(shr(224, mload(z3)), f, Q),
                        f
                    )
                    z12 := sub(z12, 8)
                    z3 := sub(z3, 4)
                }
            }
        }
    }

    /// @notice acc[n] ← (acc[n] − c[n]·t[n]) mod q, coefficientwise (NTT domain).
    function _subProduct(uint256 acc, uint256 c, uint256 t) internal pure {
        assembly ("memory-safe") {
            let end := add(acc, 0x2000)
            for {} lt(acc, end) {} {
                mstore(acc, addmod(mload(acc), sub(Q, mulmod(mload(c), mload(t), Q)), Q))
                acc := add(acc, 0x20)
                c := add(c, 0x20)
                t := add(t, 0x20)
            }
        }
    }

    /// @notice acc[n] ← (acc[n] − c[n]·t[n]) mod q with t packed 3 bytes/coefficient at `t`.
    function _subProductPacked(uint256 acc, uint256 c, uint256 t) internal pure {
        assembly ("memory-safe") {
            let end := add(acc, 0x2000)
            for {} lt(acc, end) {} {
                mstore(acc, addmod(mload(acc), sub(Q, mulmod(mload(c), shr(232, mload(t)), Q)), Q))
                acc := add(acc, 0x20)
                c := add(c, 0x20)
                t := add(t, 3)
            }
        }
    }

    /// @notice Packs the 256 coefficients at `p` (each < 2^24) as 3-byte big-endian
    ///         values into the 768 bytes at `out`.
    function _pack3(uint256 p, uint256 out) internal pure {
        assembly ("memory-safe") {
            let end := add(p, 0x2000)
            for {} lt(p, end) { p := add(p, 0x20) } {
                let v := mload(p)
                mstore8(out, shr(16, v))
                mstore8(add(out, 1), shr(8, v))
                mstore8(add(out, 2), v)
                out := add(out, 3)
            }
        }
    }

    /// @notice p[n] ← p[n]·s mod q.
    function _scale(uint256 p, uint256 s) internal pure {
        assembly ("memory-safe") {
            let end := add(p, 0x2000)
            for {} lt(p, end) { p := add(p, 0x20) } {
                mstore(p, mulmod(mload(p), s, Q))
            }
        }
    }

    /// @notice w1′_i = UseHint(h_i, w′_i) (Algorithm 40, via Decompose — Algorithm
    ///         36) for one row, packed with w1Encode/SimpleBitPack (4 bits per
    ///         coefficient, low nibble first) into 128 bytes at `out`.
    /// @dev    For r ∈ [0, q): r0′ = r mod 2γ2, r1 = ⌊r / 2γ2⌋ (+1 if r0′ > γ2, i.e.
    ///         r0 = r0′ − 2γ2 < 0). The corner r − r0 = q − 1 yields r1 = 16, which
    ///         the spec maps to r1 = 0 with r0 − 1 ≤ 0 — the `& 15` and the
    ///         "r0 > 0 ⇔ 1 ≤ r0′ ≤ γ2" test give exactly that. With hint: r1 ± 1 mod 16.
    function useHintPack(uint256 w, uint256 hintBits, uint256 out) internal pure {
        assembly ("memory-safe") {
            for { let n := 0 } lt(n, 256) {} {
                let word := 0
                for { let e := add(n, 64) } lt(n, e) { n := add(n, 1) } {
                    let r := mload(add(w, shl(5, n)))
                    let r0 := mod(r, 523776) // 2γ2
                    let r1 := add(div(r, 523776), gt(r0, 261888))
                    if and(shr(n, hintBits), 1) {
                        // r0 > 0 → r1 + 1, else r1 − 1 (mod 16)
                        switch and(iszero(iszero(r0)), iszero(gt(r0, 261888)))
                        case 0 { r1 := add(r1, 15) }
                        default { r1 := add(r1, 1) }
                    }
                    // byte (n mod 64)/2 of this 32-byte word, low nibble for even n
                    let sh := add(shl(3, sub(31, shr(1, and(n, 63)))), shl(2, and(n, 1)))
                    word := or(word, shl(sh, and(r1, 15)))
                }
                mstore(out, word)
                out := add(out, 0x20)
            }
        }
    }

    // ── Keccak / SHAKE (FIPS 202) ────────────────────────────────────────────

    /// @notice Allocates and initialises the Keccak workspace (state + scratch +
    ///         round constants); returns its memory address.
    function newKeccakWorkspace() internal pure returns (uint256 ks) {
        uint256[] memory buf = new uint256[](KS_WORDS);
        assembly ("memory-safe") {
            ks := add(buf, 0x20)
            let rc := add(ks, 0x640)
            mstore(rc, 0x0000000000000001000000000000000100000000000000010000000000000001)
            mstore(add(rc, 0x020), 0x0000000000008082000000000000808200000000000080820000000000008082)
            mstore(add(rc, 0x040), 0x800000000000808a800000000000808a800000000000808a800000000000808a)
            mstore(add(rc, 0x060), 0x8000000080008000800000008000800080000000800080008000000080008000)
            mstore(add(rc, 0x080), 0x000000000000808b000000000000808b000000000000808b000000000000808b)
            mstore(add(rc, 0x0a0), 0x0000000080000001000000008000000100000000800000010000000080000001)
            mstore(add(rc, 0x0c0), 0x8000000080008081800000008000808180000000800080818000000080008081)
            mstore(add(rc, 0x0e0), 0x8000000000008009800000000000800980000000000080098000000000008009)
            mstore(add(rc, 0x100), 0x000000000000008a000000000000008a000000000000008a000000000000008a)
            mstore(add(rc, 0x120), 0x0000000000000088000000000000008800000000000000880000000000000088)
            mstore(add(rc, 0x140), 0x0000000080008009000000008000800900000000800080090000000080008009)
            mstore(add(rc, 0x160), 0x000000008000000a000000008000000a000000008000000a000000008000000a)
            mstore(add(rc, 0x180), 0x000000008000808b000000008000808b000000008000808b000000008000808b)
            mstore(add(rc, 0x1a0), 0x800000000000008b800000000000008b800000000000008b800000000000008b)
            mstore(add(rc, 0x1c0), 0x8000000000008089800000000000808980000000000080898000000000008089)
            mstore(add(rc, 0x1e0), 0x8000000000008003800000000000800380000000000080038000000000008003)
            mstore(add(rc, 0x200), 0x8000000000008002800000000000800280000000000080028000000000008002)
            mstore(add(rc, 0x220), 0x8000000000000080800000000000008080000000000000808000000000000080)
            mstore(add(rc, 0x240), 0x000000000000800a000000000000800a000000000000800a000000000000800a)
            mstore(add(rc, 0x260), 0x800000008000000a800000008000000a800000008000000a800000008000000a)
            mstore(add(rc, 0x280), 0x8000000080008081800000008000808180000000800080818000000080008081)
            mstore(add(rc, 0x2a0), 0x8000000000008080800000000000808080000000000080808000000000008080)
            mstore(add(rc, 0x2c0), 0x0000000080000001000000008000000100000000800000010000000080000001)
            mstore(add(rc, 0x2e0), 0x8000000080008008800000008000800880000000800080088000000080008008)
        }
    }

    /// @notice Keccak-f[1600] on the 25 lanes at `ks`, four instances at once (one
    ///         per 64-bit slot; 24 rounds, scratch at ks + 0x320, D at ks + 0x940).
    /// @dev    Lane (x, y) lives at word x + 5y. ⊕, ∧, ¬ act slot-wise for free; a
    ///         rotation by r is (v << r & HI_r) | (v >> (64 − r) & LO_r), the masks
    ///         keeping bits from crossing into the neighbouring slot. Each round is θ, then ρ+π+χ fused
    ///         one output plane at a time (π sends A[x][y] to B[y][2x + 3y]), then ι.
    ///         Rounds alternate A → B and B → A, so 24 rounds end back in A.
    function keccakF(uint256 ks) internal pure {
        assembly ("memory-safe") {
            function round(a, o, dp) {
                // θ: column parities C[x]; D[x] = C[x−1] ⊕ rot(C[x+1], 1), staged in memory
                let c0 := xor(xor(xor(xor(mload(a), mload(add(a, 0xa0))), mload(add(a, 0x140))), mload(add(a, 0x1e0))), mload(add(a, 0x280)))
                let c1 := xor(xor(xor(xor(mload(add(a, 0x20)), mload(add(a, 0xc0))), mload(add(a, 0x160))), mload(add(a, 0x200))), mload(add(a, 0x2a0)))
                let c2 := xor(xor(xor(xor(mload(add(a, 0x40)), mload(add(a, 0xe0))), mload(add(a, 0x180))), mload(add(a, 0x220))), mload(add(a, 0x2c0)))
                let c3 := xor(xor(xor(xor(mload(add(a, 0x60)), mload(add(a, 0x100))), mload(add(a, 0x1a0))), mload(add(a, 0x240))), mload(add(a, 0x2e0)))
                let c4 := xor(xor(xor(xor(mload(add(a, 0x80)), mload(add(a, 0x120))), mload(add(a, 0x1c0))), mload(add(a, 0x260))), mload(add(a, 0x300)))
                mstore(dp, xor(c4, or(and(shl(1, c1), 0xfffffffffffffffefffffffffffffffefffffffffffffffefffffffffffffffe), and(shr(63, c1), 0x0000000000000001000000000000000100000000000000010000000000000001))))
                mstore(add(dp, 0x20), xor(c0, or(and(shl(1, c2), 0xfffffffffffffffefffffffffffffffefffffffffffffffefffffffffffffffe), and(shr(63, c2), 0x0000000000000001000000000000000100000000000000010000000000000001))))
                mstore(add(dp, 0x40), xor(c1, or(and(shl(1, c3), 0xfffffffffffffffefffffffffffffffefffffffffffffffefffffffffffffffe), and(shr(63, c3), 0x0000000000000001000000000000000100000000000000010000000000000001))))
                mstore(add(dp, 0x60), xor(c2, or(and(shl(1, c4), 0xfffffffffffffffefffffffffffffffefffffffffffffffefffffffffffffffe), and(shr(63, c4), 0x0000000000000001000000000000000100000000000000010000000000000001))))
                mstore(add(dp, 0x80), xor(c3, or(and(shl(1, c0), 0xfffffffffffffffefffffffffffffffefffffffffffffffefffffffffffffffe), and(shr(63, c0), 0x0000000000000001000000000000000100000000000000010000000000000001))))
                // ρ + π + χ, one output plane at a time: B[y][2x+3y] = rot(A[x][y] ⊕ D[x], r[x][y])
                let b0 := xor(mload(a), mload(dp))
                let b1 := xor(mload(add(a, 0xc0)), mload(add(dp, 0x20)))
                b1 := or(and(shl(44, b1), 0xfffff00000000000fffff00000000000fffff00000000000fffff00000000000), and(shr(20, b1), 0x00000fffffffffff00000fffffffffff00000fffffffffff00000fffffffffff))
                let b2 := xor(mload(add(a, 0x180)), mload(add(dp, 0x40)))
                b2 := or(and(shl(43, b2), 0xfffff80000000000fffff80000000000fffff80000000000fffff80000000000), and(shr(21, b2), 0x000007ffffffffff000007ffffffffff000007ffffffffff000007ffffffffff))
                let b3 := xor(mload(add(a, 0x240)), mload(add(dp, 0x60)))
                b3 := or(and(shl(21, b3), 0xffffffffffe00000ffffffffffe00000ffffffffffe00000ffffffffffe00000), and(shr(43, b3), 0x00000000001fffff00000000001fffff00000000001fffff00000000001fffff))
                let b4 := xor(mload(add(a, 0x300)), mload(add(dp, 0x80)))
                b4 := or(and(shl(14, b4), 0xffffffffffffc000ffffffffffffc000ffffffffffffc000ffffffffffffc000), and(shr(50, b4), 0x0000000000003fff0000000000003fff0000000000003fff0000000000003fff))
                mstore(o, xor(b0, and(not(b1), b2)))
                mstore(add(o, 0x20), xor(b1, and(not(b2), b3)))
                mstore(add(o, 0x40), xor(b2, and(not(b3), b4)))
                mstore(add(o, 0x60), xor(b3, and(not(b4), b0)))
                mstore(add(o, 0x80), xor(b4, and(not(b0), b1)))
                b0 := xor(mload(add(a, 0x60)), mload(add(dp, 0x60)))
                b0 := or(and(shl(28, b0), 0xfffffffff0000000fffffffff0000000fffffffff0000000fffffffff0000000), and(shr(36, b0), 0x000000000fffffff000000000fffffff000000000fffffff000000000fffffff))
                b1 := xor(mload(add(a, 0x120)), mload(add(dp, 0x80)))
                b1 := or(and(shl(20, b1), 0xfffffffffff00000fffffffffff00000fffffffffff00000fffffffffff00000), and(shr(44, b1), 0x00000000000fffff00000000000fffff00000000000fffff00000000000fffff))
                b2 := xor(mload(add(a, 0x140)), mload(dp))
                b2 := or(and(shl(3, b2), 0xfffffffffffffff8fffffffffffffff8fffffffffffffff8fffffffffffffff8), and(shr(61, b2), 0x0000000000000007000000000000000700000000000000070000000000000007))
                b3 := xor(mload(add(a, 0x200)), mload(add(dp, 0x20)))
                b3 := or(and(shl(45, b3), 0xffffe00000000000ffffe00000000000ffffe00000000000ffffe00000000000), and(shr(19, b3), 0x00001fffffffffff00001fffffffffff00001fffffffffff00001fffffffffff))
                b4 := xor(mload(add(a, 0x2c0)), mload(add(dp, 0x40)))
                b4 := or(and(shl(61, b4), 0xe000000000000000e000000000000000e000000000000000e000000000000000), and(shr(3, b4), 0x1fffffffffffffff1fffffffffffffff1fffffffffffffff1fffffffffffffff))
                mstore(add(o, 0xa0), xor(b0, and(not(b1), b2)))
                mstore(add(o, 0xc0), xor(b1, and(not(b2), b3)))
                mstore(add(o, 0xe0), xor(b2, and(not(b3), b4)))
                mstore(add(o, 0x100), xor(b3, and(not(b4), b0)))
                mstore(add(o, 0x120), xor(b4, and(not(b0), b1)))
                b0 := xor(mload(add(a, 0x20)), mload(add(dp, 0x20)))
                b0 := or(and(shl(1, b0), 0xfffffffffffffffefffffffffffffffefffffffffffffffefffffffffffffffe), and(shr(63, b0), 0x0000000000000001000000000000000100000000000000010000000000000001))
                b1 := xor(mload(add(a, 0xe0)), mload(add(dp, 0x40)))
                b1 := or(and(shl(6, b1), 0xffffffffffffffc0ffffffffffffffc0ffffffffffffffc0ffffffffffffffc0), and(shr(58, b1), 0x000000000000003f000000000000003f000000000000003f000000000000003f))
                b2 := xor(mload(add(a, 0x1a0)), mload(add(dp, 0x60)))
                b2 := or(and(shl(25, b2), 0xfffffffffe000000fffffffffe000000fffffffffe000000fffffffffe000000), and(shr(39, b2), 0x0000000001ffffff0000000001ffffff0000000001ffffff0000000001ffffff))
                b3 := xor(mload(add(a, 0x260)), mload(add(dp, 0x80)))
                b3 := or(and(shl(8, b3), 0xffffffffffffff00ffffffffffffff00ffffffffffffff00ffffffffffffff00), and(shr(56, b3), 0x00000000000000ff00000000000000ff00000000000000ff00000000000000ff))
                b4 := xor(mload(add(a, 0x280)), mload(dp))
                b4 := or(and(shl(18, b4), 0xfffffffffffc0000fffffffffffc0000fffffffffffc0000fffffffffffc0000), and(shr(46, b4), 0x000000000003ffff000000000003ffff000000000003ffff000000000003ffff))
                mstore(add(o, 0x140), xor(b0, and(not(b1), b2)))
                mstore(add(o, 0x160), xor(b1, and(not(b2), b3)))
                mstore(add(o, 0x180), xor(b2, and(not(b3), b4)))
                mstore(add(o, 0x1a0), xor(b3, and(not(b4), b0)))
                mstore(add(o, 0x1c0), xor(b4, and(not(b0), b1)))
                b0 := xor(mload(add(a, 0x80)), mload(add(dp, 0x80)))
                b0 := or(and(shl(27, b0), 0xfffffffff8000000fffffffff8000000fffffffff8000000fffffffff8000000), and(shr(37, b0), 0x0000000007ffffff0000000007ffffff0000000007ffffff0000000007ffffff))
                b1 := xor(mload(add(a, 0xa0)), mload(dp))
                b1 := or(and(shl(36, b1), 0xfffffff000000000fffffff000000000fffffff000000000fffffff000000000), and(shr(28, b1), 0x0000000fffffffff0000000fffffffff0000000fffffffff0000000fffffffff))
                b2 := xor(mload(add(a, 0x160)), mload(add(dp, 0x20)))
                b2 := or(and(shl(10, b2), 0xfffffffffffffc00fffffffffffffc00fffffffffffffc00fffffffffffffc00), and(shr(54, b2), 0x00000000000003ff00000000000003ff00000000000003ff00000000000003ff))
                b3 := xor(mload(add(a, 0x220)), mload(add(dp, 0x40)))
                b3 := or(and(shl(15, b3), 0xffffffffffff8000ffffffffffff8000ffffffffffff8000ffffffffffff8000), and(shr(49, b3), 0x0000000000007fff0000000000007fff0000000000007fff0000000000007fff))
                b4 := xor(mload(add(a, 0x2e0)), mload(add(dp, 0x60)))
                b4 := or(and(shl(56, b4), 0xff00000000000000ff00000000000000ff00000000000000ff00000000000000), and(shr(8, b4), 0x00ffffffffffffff00ffffffffffffff00ffffffffffffff00ffffffffffffff))
                mstore(add(o, 0x1e0), xor(b0, and(not(b1), b2)))
                mstore(add(o, 0x200), xor(b1, and(not(b2), b3)))
                mstore(add(o, 0x220), xor(b2, and(not(b3), b4)))
                mstore(add(o, 0x240), xor(b3, and(not(b4), b0)))
                mstore(add(o, 0x260), xor(b4, and(not(b0), b1)))
                b0 := xor(mload(add(a, 0x40)), mload(add(dp, 0x40)))
                b0 := or(and(shl(62, b0), 0xc000000000000000c000000000000000c000000000000000c000000000000000), and(shr(2, b0), 0x3fffffffffffffff3fffffffffffffff3fffffffffffffff3fffffffffffffff))
                b1 := xor(mload(add(a, 0x100)), mload(add(dp, 0x60)))
                b1 := or(and(shl(55, b1), 0xff80000000000000ff80000000000000ff80000000000000ff80000000000000), and(shr(9, b1), 0x007fffffffffffff007fffffffffffff007fffffffffffff007fffffffffffff))
                b2 := xor(mload(add(a, 0x1c0)), mload(add(dp, 0x80)))
                b2 := or(and(shl(39, b2), 0xffffff8000000000ffffff8000000000ffffff8000000000ffffff8000000000), and(shr(25, b2), 0x0000007fffffffff0000007fffffffff0000007fffffffff0000007fffffffff))
                b3 := xor(mload(add(a, 0x1e0)), mload(dp))
                b3 := or(and(shl(41, b3), 0xfffffe0000000000fffffe0000000000fffffe0000000000fffffe0000000000), and(shr(23, b3), 0x000001ffffffffff000001ffffffffff000001ffffffffff000001ffffffffff))
                b4 := xor(mload(add(a, 0x2a0)), mload(add(dp, 0x20)))
                b4 := or(and(shl(2, b4), 0xfffffffffffffffcfffffffffffffffcfffffffffffffffcfffffffffffffffc), and(shr(62, b4), 0x0000000000000003000000000000000300000000000000030000000000000003))
                mstore(add(o, 0x280), xor(b0, and(not(b1), b2)))
                mstore(add(o, 0x2a0), xor(b1, and(not(b2), b3)))
                mstore(add(o, 0x2c0), xor(b2, and(not(b3), b4)))
                mstore(add(o, 0x2e0), xor(b3, and(not(b4), b0)))
                mstore(add(o, 0x300), xor(b4, and(not(b0), b1)))
            }
            let b := add(ks, 0x320)
            let rcp := add(ks, 0x640)
            let dp := add(ks, 0x940)
            for { let r := 0 } lt(r, 0x300) { r := add(r, 0x40) } {
                round(ks, b, dp)
                mstore(b, xor(mload(b), mload(add(rcp, r)))) // ι
                round(b, ks, dp)
                mstore(ks, xor(mload(ks), mload(add(rcp, add(r, 0x20)))))
            }
        }
    }

    /// @notice Resets the sponge and absorbs `len` bytes at `src` with SHAKE padding
    ///         (domain bits 1111, then pad10*1) at rate `rate`, finishing with the
    ///         permutation: lanes 0.. now hold the first squeezed block.
    function absorb(uint256 ks, uint256 src, uint256 len, uint256 rate) internal pure {
        assembly ("memory-safe") {
            for { let o := 0 } lt(o, 0x320) { o := add(o, 0x20) } { mstore(add(ks, o), 0) }
        }
        while (len >= rate) {
            _xorBlock(ks, src, rate);
            keccakF(ks);
            src += rate;
            len -= rate;
        }
        uint256 last;
        assembly ("memory-safe") {
            last := add(ks, 0x320)
            for { let o := 0 } lt(o, 0xc0) { o := add(o, 0x20) } { mstore(add(last, o), 0) }
            mcopy(last, src, len)
            mstore8(add(last, len), 0x1f) // SHAKE domain separation + first pad bit
            let fin := add(last, sub(rate, 1))
            mstore8(fin, or(byte(0, mload(fin)), 0x80)) // last pad bit (may share the byte)
        }
        _xorBlock(ks, last, rate);
        keccakF(ks);
    }

    /// @notice XORs one `rate`-byte block at `src` into slot 0 of the state. Lanes are
    ///         little-endian: each 32-byte load is byte-reversed within its four
    ///         64-bit groups, giving four lane values at once.
    function _xorBlock(uint256 ks, uint256 src, uint256 rate) private pure {
        assembly ("memory-safe") {
            let lanes := shr(3, rate)
            for { let k := 0 } lt(k, lanes) { k := add(k, 4) } {
                let w := _bswap64x4(mload(add(src, shl(3, k))))
                let p := add(ks, shl(5, k))
                mstore(p, xor(mload(p), shr(192, w)))
                if lt(add(k, 1), lanes) {
                    mstore(add(p, 0x20), xor(mload(add(p, 0x20)), and(shr(128, w), 0xffffffffffffffff)))
                    mstore(add(p, 0x40), xor(mload(add(p, 0x40)), and(shr(64, w), 0xffffffffffffffff)))
                    mstore(add(p, 0x60), xor(mload(add(p, 0x60)), and(w, 0xffffffffffffffff)))
                }
            }

            // Reverses the bytes inside each 64-bit group of a word.
            function _bswap64x4(x) -> y {
                x := or(
                    and(shr(8, x), 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff),
                    shl(8, and(x, 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff))
                )
                x := or(
                    and(shr(16, x), 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff),
                    shl(16, and(x, 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff))
                )
                y := or(
                    and(shr(32, x), 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff),
                    shl(32, and(x, 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff))
                )
            }
        }
    }

    /// @notice SHAKE256(src[0..len)) truncated to 64 bytes, as two words.
    function shake256To64(uint256 ks, uint256 src, uint256 len) internal pure returns (bytes32 o0, bytes32 o1) {
        absorb(ks, src, len, RATE256);
        return squeezeWords(ks);
    }

    /// @notice The first 64 bytes of the current output block (lanes 0..7) as two
    ///         big-endian words — the byte order of the SHAKE output stream.
    function squeezeWords(uint256 ks) internal pure returns (bytes32 o0, bytes32 o1) {
        assembly ("memory-safe") {
            function bswap(x) -> y {
                x := or(
                    and(shr(8, x), 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff),
                    shl(8, and(x, 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff))
                )
                x := or(
                    and(shr(16, x), 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff),
                    shl(16, and(x, 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff))
                )
                y := or(
                    and(shr(32, x), 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff),
                    shl(32, and(x, 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff))
                )
            }
            function pack(p) -> w {
                let m := 0xffffffffffffffff
                w := or(
                    or(shl(192, mload(p)), shl(128, and(mload(add(p, 0x20)), m))),
                    or(shl(64, and(mload(add(p, 0x40)), m)), and(mload(add(p, 0x60)), m))
                )
            }
            o0 := bswap(pack(ks))
            o1 := bswap(pack(add(ks, 0x80)))
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// @dev `words` zeroed words; returns the address of the first.
    function _allocWords(uint256 words) internal pure returns (uint256 p) {
        uint256[] memory buf = new uint256[](words);
        assembly ("memory-safe") {
            p := add(buf, 0x20)
        }
    }

    /// @dev `count` zeroed polynomials at stride ACC_STRIDE (256 + 8 slack words).
    function _allocStrided(uint256 count) internal pure returns (uint256 p) {
        return _allocWords(count * (ACC_STRIDE / 32));
    }

    /// @dev Address of a bytes array's first data byte.
    function _ptr(bytes memory b) internal pure returns (uint256 p) {
        assembly ("memory-safe") {
            p := add(b, 0x20)
        }
    }

    /// @dev zetas[m] = ζ^{BitRev8(m)} mod q, ζ = 1753 (FIPS 204 Appendix B), as
    ///      256 big-endian uint32. Entry 0 (= 1) is never read by the transforms.
    function _zetas() internal pure returns (bytes memory) {
        return
            hex"0000000100495e020039756700396569004f062b0053df73004fe033004f066b"
            hex"0076b1ae00360dd50028edb000207fe4003972830070894a00088192006d3dc8"
            hex"004c72940041e0b40028a3d20066528a004a18a700794034000a52ee006b7d81"
            hex"004e9f1d001a2877002571df001649ee007611bd00492bb7002af6970022d8d5"
            hex"0036f72a0030911e0029d13f004926730050685f002010a2003887f70011b2c3"
            hex"000603a4000e2bed0010b72c004a5f35001f9d1500428cd4003177f40020e612"
            hex"00341c1d001ad873007366810049553f003952f60062564a0065ad0500439a1c"
            hex"0053aa5f0030b62200087f38003b0e6d002c83da001c496e00330e2b001c5b70"
            hex"002ee3f100137eb90057a930003ac6ef003fd54c004eb2ea00503ee1007bb175"
            hex"002648b4001ef256001d90a20045a6d4002ae59b0052589c006ef1f5003f7288"
            hex"0017510200075d59001187ba0052aca900773e9e000296d8002592ec004cff12"
            hex"00404ce8004aa582001e54e6004f16c1001a7e790003978f004e48170031b859"
            hex"005884cc001b4827005b63d0005d787a0035225e00400c7e006c09d1005bd532"
            hex"006bc4d300258ecb002e534c00097a6c003b8820006d285c002ca4f800337caa"
            hex"0014b2a0005585360028f1860055795d004af67000234a860075e8260078de66"
            hex"0005528c007adf59000f6e17005bf3da00459b7e00628b34005dbecb001a9e7b"
            hex"000006d9006257c500574b3c0069a8ef002898380064b5fe007ef8f5002a4e78"
            hex"00120a23000154a80009b7ff00435e8700437ff8005cd5b4004dc04e004728af"
            hex"007f735d000c8d0d000f66d5005a6d800061ab9800185d9600437f3100468298"
            hex"00662960004bd5790028de0600465d8d0049b0e30009b434007c0db3005a68b0"
            hex"00409ba90064d3d50021762a0065859100246e390048c39b007bc759004f5859"
            hex"00392db2002309230012eb6700454df20030c31c002854240013232e007faf80"
            hex"002dbfcb00022a0b007e832c0026587a006b337500095b76006be1cc005e061e"
            hex"0078e00d00628c37003da604004ae53c001f1d68006330bb007361b8005ea06c"
            hex"00671ac700201fc6005ba4ff0060d7720008f201006de02400080e6d0056038e"
            hex"00695688001e6d3e002603bd006a9dfa0007c017006dbfd40074d0bd0063e1e3"
            hex"00519573007ab60d002867ba002decd40058018c003f4cf5000b700900427e23"
            hex"003cbd370027333300673957001a4b5d00196926001ef2060011c14e004c76c8"
            hex"003cf42f007fb19a006af66c002e1669003352d6000347600008526000741e78"
            hex"002f6316006f0a110007c0f100776d0b000d1ff000345824000223d40068c559"
            hex"005e8885002faa320023fc65005e69420051e0ed0065adb3002ca5e60079e1fe"
            hex"007b40640035e1dd00433aac00464ade001cfe140073f1ce0010170e0074b6d7";
    }
}
