// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IPQVerifier} from "pq-verifier-interface/IPQVerifier.sol";
import {PQAlgorithms} from "pq-verifier-interface/PQAlgorithms.sol";

import {IMLDSAVerifier, ParamSet, ML_DSA_44, ML_DSA_65, ML_DSA_87} from "../src/IMLDSAVerifier.sol";
import {MLDSA} from "../src/MLDSA.sol";
import {MLDSAKeyFactory, MLDSAKeys} from "../src/MLDSAKeyFactory.sol";
import {MLDSAPublicKeys} from "../src/MLDSAPublicKeys.sol";
import {MLDSAVerifier} from "../src/MLDSAVerifier.sol";
import {MLDSAHarness} from "./MLDSA.t.sol";

/// A different IMLDSAVerifier: stands in for an adapter around a future ML-DSA
/// precompile that only offers ML-DSA-44 (the "precompile" here is the library's
/// full verification). Callers must not be able to tell it from MLDSAVerifier.
contract MockPrecompileAdapter is IMLDSAVerifier {
    function verify(ParamSet set, bytes calldata publicKey, bytes calldata message, bytes calldata signature)
        external
        view
        returns (bool)
    {
        if (!(set == ML_DSA_44)) return false;
        return MLDSA.verify(set, publicKey, message, signature);
    }

    function supportsParamSet(ParamSet set) external pure returns (bool) {
        return set == ML_DSA_44;
    }

    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == type(IMLDSAVerifier).interfaceId || id == type(IERC165).interfaceId;
    }
}

/// A minimal wallet stand-in, written against IMLDSAVerifier only: the verifier is
/// fixed at construction (immutable — swapping verifiers means a new deployment),
/// the key is kept as contract code (MLDSAPublicKeys), the set is chosen once.
/// Deployed as an EIP-1167 clone per user; the implementation holds the immutables.
contract WalletStandIn {
    IMLDSAVerifier public immutable VERIFIER;
    address public immutable FACTORY; // for the optional Â store on first use

    ParamSet public set;
    address public pkPointer;
    bytes32 public pkHash;
    uint256 public nonce;

    error AlreadyInitialized();
    error UnsupportedSet();
    error BadSignature();

    constructor(IMLDSAVerifier verifier, address factory) {
        VERIFIER = verifier;
        FACTORY = factory;
    }

    function initialize(ParamSet set_, address pkPointer_, bytes32 pkHash_) external {
        if (pkPointer != address(0)) revert AlreadyInitialized();
        if (!VERIFIER.supportsParamSet(set_)) revert UnsupportedSet();
        (set, pkPointer, pkHash) = (set_, pkPointer_, pkHash_);
    }

    /// Authorises one action over a 32-byte digest. `aHat` (optional, any caller can
    /// supply it: it is checked against the factory's commitment) stores Â first so
    /// that this very verification takes the fast path.
    function transfer(bytes32 digest, bytes calldata signature, bytes calldata aHat) external {
        if (aHat.length != 0 && FACTORY != address(0)) MLDSAKeys.ensureStored(FACTORY, set, pkHash, aHat);
        if (!VERIFIER.verify(set, MLDSAPublicKeys.load(pkPointer), abi.encodePacked(digest), signature)) {
            revert BadSignature();
        }
        ++nonce;
    }
}

/// One-transaction wallet setup: commit Â, register tr ‖ t̂, keep pk as code, clone
/// and initialise the wallet.
contract SetupBundler {
    MLDSAKeyFactory public immutable FACTORY;
    address public immutable WALLET_IMPL;

    constructor(MLDSAKeyFactory factory, address walletImpl) {
        FACTORY = factory;
        WALLET_IMPL = walletImpl;
    }

    function setup(ParamSet set, bytes calldata pk) external returns (address wallet) {
        FACTORY.commitA(set, pk);
        FACTORY.registerT(set, pk);
        address pointer = MLDSAPublicKeys.store(pk);
        wallet = Clones.clone(WALLET_IMPL);
        WalletStandIn(wallet).initialize(set, pointer, keccak256(pk));
    }
}

/// Keeps a key as code and measures loading it back.
contract PkStoreHarness {
    function store(bytes calldata pk) external returns (address) {
        return MLDSAPublicKeys.store(pk);
    }

    function load(address p) external view returns (bytes memory) {
        return MLDSAPublicKeys.load(p);
    }

    function loadGas(address p) external view returns (uint256 g, uint256 len) {
        g = gasleft();
        bytes memory pk = MLDSAPublicKeys.load(p);
        g -= gasleft();
        len = pk.length;
    }
}

/// Measures from a small-memory caller, as a wallet would: (a) the external
/// IMLDSAVerifier call carrying the raw key, (b) the same verification through the
/// library in the caller's own frame (MLDSAKeys.verify by pkHash), (c) (b) plus
/// hashing the key, i.e. what the interface path must do beyond (b).
contract GasProbe {
    function viaInterface(IMLDSAVerifier v, ParamSet set, bytes calldata pk, bytes calldata m, bytes calldata sig)
        external
        view
        returns (uint256 g, bool ok)
    {
        g = gasleft();
        ok = v.verify(set, pk, m, sig);
        g -= gasleft();
    }

    function viaPQ(IPQVerifier v, uint256 alg, bytes calldata pk, bytes calldata m, bytes calldata sig)
        external
        view
        returns (uint256 g, bool ok)
    {
        g = gasleft();
        ok = v.verify(alg, pk, m, sig);
        g -= gasleft();
    }

    function viaLibrary(address factory, ParamSet set, bytes32 pkHash, bytes calldata m, bytes calldata sig)
        external
        view
        returns (uint256 g, bool ok)
    {
        g = gasleft();
        ok = MLDSAKeys.verify(factory, set, pkHash, m, sig);
        g -= gasleft();
    }

    function viaLibraryHashingPk(address factory, ParamSet set, bytes calldata pk, bytes calldata m, bytes calldata sig)
        external
        view
        returns (uint256 g, bool ok)
    {
        g = gasleft();
        ok = MLDSAKeys.verify(factory, set, keccak256(pk), m, sig);
        g -= gasleft();
    }
}

contract MLDSAVerifierTest is Test {
    MLDSAHarness internal h;
    MLDSAKeyFactory internal factory; //   keys get registered here
    MLDSAVerifier internal fast; //        reads `factory`
    MLDSAVerifier internal slow; //        reads an empty factory: always the fallback

    function setUp() public {
        h = new MLDSAHarness();
        factory = new MLDSAKeyFactory();
        fast = new MLDSAVerifier(address(factory));
        slow = new MLDSAVerifier(address(new MLDSAKeyFactory()));
    }

    /// Fixtures are read from disk on use, not kept in storage: with ML-DSA-87 they
    /// are ~1.5 MB, and SSTOREing that in setUp exceeds the per-call gas limit.
    function _diff() internal view returns (string memory) {
        return vm.readFile("test/mldsa/differential.json");
    }

    function _acvp() internal view returns (string memory) {
        return vm.readFile("test/mldsa/acvp.json");
    }

    function _key(ParamSet set) internal pure returns (string memory) {
        return set == ML_DSA_44 ? ".mldsa44" : set == ML_DSA_65 ? ".mldsa65" : ".mldsa87";
    }

    function _vec(ParamSet set, string memory field) internal view returns (bytes[] memory) {
        return vm.parseJsonBytesArray(_diff(), string.concat(_key(set), ".", field));
    }

    function _register(ParamSet set, bytes memory pk) internal {
        factory.registerA(set, pk);
        factory.registerT(set, pk);
        assertTrue(factory.isRegistered(set, keccak256(pk)));
    }

    // ── Interface basics ─────────────────────────────────────────────────────

    function test_interface_supportsAndErc165() public {
        assertTrue(fast.supportsParamSet(ML_DSA_44));
        assertTrue(fast.supportsParamSet(ML_DSA_65));
        assertTrue(fast.supportsParamSet(ML_DSA_87));
        assertTrue(fast.supportsParamSet(ParamSet.wrap(2)));
        assertFalse(fast.supportsParamSet(ParamSet.wrap(3)));
        assertFalse(fast.supportsParamSet(ParamSet.wrap(255)));
        assertTrue(fast.supportsInterface(type(IMLDSAVerifier).interfaceId));
        assertTrue(fast.supportsInterface(type(IERC165).interfaceId));
        assertFalse(fast.supportsInterface(0xffffffff));
        assertEq(
            type(IMLDSAVerifier).interfaceId, IMLDSAVerifier.verify.selector ^ IMLDSAVerifier.supportsParamSet.selector
        );
        // verify(uint8,bytes,bytes,bytes): the selector an enum-typed interface would have too.
        assertEq(IMLDSAVerifier.verify.selector, bytes4(keccak256("verify(uint8,bytes,bytes,bytes)")));
        assertEq(fast.FACTORY(), address(factory));
        // An unknown id, raw in calldata, is a plain false — not an ABI-decoding revert.
        bytes[] memory pk = _vec(ML_DSA_44, "pk");
        bytes[] memory m = _vec(ML_DSA_44, "msg");
        bytes[] memory s = _vec(ML_DSA_44, "sig");
        (bool ok, bytes memory ret) =
            address(fast).call(abi.encodeWithSelector(IMLDSAVerifier.verify.selector, uint8(7), pk[1], m[1], s[1]));
        assertTrue(ok, "no revert");
        assertFalse(abi.decode(ret, (bool)));
    }

    // ── Every vector through the interface: fast path, fallback, library ─────

    // (In halves: with IPQVerifier on both paths as well, all eight vectors of a set
    // in one test pass the per-test gas limit for ML-DSA-87.)

    function test_interface_differential_44_a() public {
        _differential(ML_DSA_44, 0, 4);
    }

    function test_interface_differential_44_b() public {
        _differential(ML_DSA_44, 4, 99);
    }

    function test_interface_differential_65_a() public {
        _differential(ML_DSA_65, 0, 4);
    }

    function test_interface_differential_65_b() public {
        _differential(ML_DSA_65, 4, 99);
    }

    function test_interface_differential_87_a() public {
        _differential(ML_DSA_87, 0, 4);
    }

    function test_interface_differential_87_b() public {
        _differential(ML_DSA_87, 4, 99);
    }

    /// Empty-context vectors must verify; contexted ones (the interface is pure
    /// ML-DSA with ctx = "") must not; and all three paths agree on every input,
    /// including corruptions.
    function _differential(ParamSet set, uint256 from, uint256 to) internal {
        bytes[] memory pk = _vec(set, "pk");
        bytes[] memory m = _vec(set, "msg");
        bytes[] memory ctx = _vec(set, "ctx");
        bytes[] memory sig = _vec(set, "sig");
        uint256 passed;
        if (to > pk.length) to = pk.length;
        for (uint256 v = from; v < to; ++v) {
            _register(set, pk[v]);
            bool want = ctx[v].length == 0;
            _agree(set, pk[v], m[v], sig[v], want);
            if (want) ++passed;
            bytes memory bad = abi.encodePacked(sig[v]);
            bad[100] = bytes1(uint8(bad[100]) ^ 1);
            _agree(set, pk[v], m[v], bad, false);
            _agree(set, pk[v], abi.encodePacked(m[v], bytes1(0)), sig[v], false);
        }
        bytes memory dup = vm.parseJsonBytes(_diff(), string.concat(_key(set), ".malformed.duplicate"));
        if (from <= 1 && 1 < to) _agree(set, pk[1], m[1], dup, false); // repeated hint index: FIPS 204 rejects
        console.log("interface: differential vectors verified on both paths:", passed);
    }

    // (Each group in two halves: registering and verifying 15 keys three ways in
    // one test comes close to the per-test gas cap for ML-DSA-65.)

    function test_interface_acvp_44_external_a() public {
        _acvp(ML_DSA_44, ".mldsa44.external", true, 0, 8);
    }

    function test_interface_acvp_44_external_b() public {
        _acvp(ML_DSA_44, ".mldsa44.external", true, 8, 99);
    }

    function test_interface_acvp_44_internal_a() public {
        _acvp(ML_DSA_44, ".mldsa44.internal", false, 0, 8);
    }

    function test_interface_acvp_44_internal_b() public {
        _acvp(ML_DSA_44, ".mldsa44.internal", false, 8, 99);
    }

    function test_interface_acvp_65_external_a() public {
        _acvp(ML_DSA_65, ".mldsa65.external", true, 0, 8);
    }

    function test_interface_acvp_65_external_b() public {
        _acvp(ML_DSA_65, ".mldsa65.external", true, 8, 99);
    }

    function test_interface_acvp_65_internal_a() public {
        _acvp(ML_DSA_65, ".mldsa65.internal", false, 0, 8);
    }

    function test_interface_acvp_65_internal_b() public {
        _acvp(ML_DSA_65, ".mldsa65.internal", false, 8, 99);
    }

    // ML-DSA-87 per key is ~2× 65 (two A parts, a bigger T): quarters.

    function test_interface_acvp_87_external_a() public {
        _acvp(ML_DSA_87, ".mldsa87.external", true, 0, 4);
    }

    function test_interface_acvp_87_external_b() public {
        _acvp(ML_DSA_87, ".mldsa87.external", true, 4, 8);
    }

    function test_interface_acvp_87_external_c() public {
        _acvp(ML_DSA_87, ".mldsa87.external", true, 8, 12);
    }

    function test_interface_acvp_87_external_d() public {
        _acvp(ML_DSA_87, ".mldsa87.external", true, 12, 99);
    }

    function test_interface_acvp_87_internal_a() public {
        _acvp(ML_DSA_87, ".mldsa87.internal", false, 0, 4);
    }

    function test_interface_acvp_87_internal_b() public {
        _acvp(ML_DSA_87, ".mldsa87.internal", false, 4, 8);
    }

    function test_interface_acvp_87_internal_c() public {
        _acvp(ML_DSA_87, ".mldsa87.internal", false, 8, 12);
    }

    function test_interface_acvp_87_internal_d() public {
        _acvp(ML_DSA_87, ".mldsa87.internal", false, 12, 99);
    }

    /// The interface is ML-DSA.Verify with ctx = "": NIST's external vectors carry
    /// contexts (and the internal ones a raw M′), so through the interface each
    /// vector is run as (pk, msg, sig) and the fast path, the fallback and the
    /// library's verify(set, pk, msg, sig) must agree; where NIST's context is
    /// empty, the result must also be NIST's.
    function _acvp(ParamSet set, string memory g, bool external_, uint256 from, uint256 to) internal {
        string memory acvp = _acvp();
        uint256[] memory ids = vm.parseJsonUintArray(acvp, string.concat(g, ".tcId"));
        bytes[] memory pk = vm.parseJsonBytesArray(acvp, string.concat(g, ".pk"));
        bytes[] memory m = vm.parseJsonBytesArray(acvp, string.concat(g, ".msg"));
        bytes[] memory ctx = vm.parseJsonBytesArray(acvp, string.concat(g, ".ctx"));
        bytes[] memory sig = vm.parseJsonBytesArray(acvp, string.concat(g, ".sig"));
        bool[] memory expected = vm.parseJsonBoolArray(acvp, string.concat(g, ".passed"));
        uint256 nistChecked;
        if (to > ids.length) to = ids.length;
        for (uint256 n = from; n < to; ++n) {
            _register(set, pk[n]);
            bool lib = h.verify(set, pk[n], m[n], sig[n]);
            _agree(set, pk[n], m[n], sig[n], lib);
            if (external_ && ctx[n].length == 0) {
                assertEq(lib, expected[n], string.concat("tcId ", vm.toString(ids[n])));
                ++nistChecked;
            }
            // And the vector's own (ctx, M′) through the library, against NIST, so
            // every case still meets its expected result on this code.
            bool own = external_
                ? h.verifyWithContext(set, pk[n], ctx[n], m[n], sig[n])
                : h.verifyInternal(set, pk[n], m[n], sig[n]);
            assertEq(own, expected[n], string.concat("own ctx, tcId ", vm.toString(ids[n])));
        }
        console.log("interface: ACVP cases run on both paths:", to - from);
        console.log("interface: of which with empty ctx, checked against NIST:", nistChecked);
    }

    /// fast (registered), slow (fallback) and the library all return `want`, and so do
    /// fast and slow through IPQVerifier under the set's PQAlgorithms id.
    function _agree(ParamSet set, bytes memory pk, bytes memory m, bytes memory sig, bool want) internal view {
        assertTrue(factory.isRegistered(set, keccak256(pk)), "fast path available");
        assertEq(fast.verify(set, pk, m, sig), want, "fast path");
        assertEq(slow.verify(set, pk, m, sig), want, "fallback");
        assertEq(h.verify(set, pk, m, sig), want, "library");
        assertEq(IPQVerifier(fast).verify(_alg(set), pk, m, sig), want, "IPQVerifier, fast path");
        assertEq(IPQVerifier(slow).verify(_alg(set), pk, m, sig), want, "IPQVerifier, fallback");
    }

    function _alg(ParamSet set) internal pure returns (uint256) {
        return
            set == ML_DSA_44
                ? PQAlgorithms.ML_DSA_44
                : set == ML_DSA_65 ? PQAlgorithms.ML_DSA_65 : PQAlgorithms.ML_DSA_87;
    }

    // ── IPQVerifier ──────────────────────────────────────────────────────────

    function test_pq_supportsAndErc165() public view {
        assertEq(type(IPQVerifier).interfaceId, bytes4(0x97b4ac55));
        assertEq(
            type(IPQVerifier).interfaceId,
            bytes4(keccak256("verify(uint256,bytes,bytes,bytes)")) ^ bytes4(keccak256("supportsAlgorithm(uint256)"))
        );
        assertTrue(type(IPQVerifier).interfaceId != type(IMLDSAVerifier).interfaceId);
        MLDSAVerifier[2] memory vs = [fast, slow];
        for (uint256 i; i < 2; ++i) {
            IPQVerifier v = IPQVerifier(vs[i]);
            assertTrue(v.supportsInterface(0x97b4ac55), "IPQVerifier");
            assertTrue(v.supportsInterface(type(IMLDSAVerifier).interfaceId), "IMLDSAVerifier");
            assertTrue(v.supportsInterface(0x01ffc9a7), "ERC-165");
            assertFalse(v.supportsInterface(0xffffffff));
            assertFalse(v.supportsInterface(0x00000000));
            assertTrue(v.supportsAlgorithm(0x0101));
            assertTrue(v.supportsAlgorithm(0x0102));
            assertTrue(v.supportsAlgorithm(0x0103));
            uint256[14] memory no = _unsupportedAlgorithms();
            for (uint256 k; k < no.length; ++k) {
                assertFalse(v.supportsAlgorithm(no[k]), vm.toString(no[k]));
            }
        }
    }

    /// Ids that are not ML-DSA-44/65/87: zero, the ParamSet values themselves, ML-DSA's
    /// neighbours, the other families, and ids that agree with an ML-DSA id in the low bits.
    function _unsupportedAlgorithms() internal pure returns (uint256[14] memory) {
        return [
            uint256(0),
            1,
            2,
            3,
            0x0100,
            0x0104,
            0x01ff,
            PQAlgorithms.SLH_DSA_SHA2_128S,
            PQAlgorithms.SLH_DSA_SHAKE_256F,
            PQAlgorithms.FN_DSA_512,
            PQAlgorithms.FN_DSA_1024,
            0x010101,
            (uint256(1) << 255) | 0x0101,
            type(uint256).max
        ];
    }

    /// A valid signature of each set is false under every id but its own, through both
    /// paths, and true under its own. The ParamSet value as an algorithm id is not enough.
    function test_pq_onlyItsOwnIdAccepts() public {
        ParamSet[3] memory sets = [ML_DSA_44, ML_DSA_65, ML_DSA_87];
        uint256[14] memory no = _unsupportedAlgorithms();
        for (uint256 i; i < 3; ++i) {
            bytes memory pk = _vec(sets[i], "pk")[1];
            bytes memory m = _vec(sets[i], "msg")[1];
            bytes memory sg = _vec(sets[i], "sig")[1];
            _register(sets[i], pk);
            MLDSAVerifier[2] memory vs = [fast, slow];
            for (uint256 x; x < 2; ++x) {
                IPQVerifier v = IPQVerifier(vs[x]);
                for (uint256 a = 0x0101; a <= 0x0103; ++a) {
                    assertEq(v.verify(a, pk, m, sg), a == _alg(sets[i]));
                }
                for (uint256 k; k < no.length; ++k) {
                    assertFalse(v.verify(no[k], pk, m, sg), vm.toString(no[k]));
                }
            }
        }
    }

    /// Never a revert: any id and any bytes, raw in calldata, come back as a decodable bool,
    /// and an id outside the three is false.
    function testFuzz_pq_neverReverts(uint256 alg, bytes calldata pk, bytes calldata m, bytes calldata sg) public view {
        MLDSAVerifier[2] memory vs = [fast, slow];
        for (uint256 x; x < 2; ++x) {
            (bool ok, bytes memory ret) =
                address(vs[x]).staticcall(abi.encodeCall(IPQVerifier.verify, (alg, pk, m, sg)));
            assertTrue(ok, "no revert");
            assertEq(ret.length, 32);
            bool got = abi.decode(ret, (bool));
            if (alg < 0x0101 || alg > 0x0103) assertFalse(got);
            assertEq(IPQVerifier(vs[x]).supportsAlgorithm(alg), alg >= 0x0101 && alg <= 0x0103);
        }
    }

    /// Valid-length but random key and signature under each ML-DSA id: false, not a revert.
    function testFuzz_pq_garbageOfTheRightLength(uint8 which, bytes32 seed) public view {
        ParamSet set = ParamSet.wrap(which % 3);
        bytes memory pk = _fill(MLDSA.publicKeyBytes(set), seed);
        bytes memory sg = _fill(MLDSA.signatureBytes(set), keccak256(abi.encode(seed)));
        (bool ok, bytes memory ret) =
            address(slow).staticcall(abi.encodeCall(IPQVerifier.verify, (_alg(set), pk, abi.encode(seed), sg)));
        assertTrue(ok, "no revert");
        assertFalse(abi.decode(ret, (bool)));
    }

    function _fill(uint256 n, bytes32 seed) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < n; i += 32) {
            seed = keccak256(abi.encode(seed));
            for (uint256 j; j < 32 && i + j < n; ++j) {
                b[i + j] = seed[j];
            }
        }
    }

    // ── Wrong set, wrong lengths, fallback states ────────────────────────────

    function test_interface_wrongSetAndLengths() public {
        bytes[] memory pk4 = _vec(ML_DSA_44, "pk");
        bytes[] memory m4 = _vec(ML_DSA_44, "msg");
        bytes[] memory s4 = _vec(ML_DSA_44, "sig");
        bytes[] memory pk6 = _vec(ML_DSA_65, "pk");
        bytes[] memory m6 = _vec(ML_DSA_65, "msg");
        bytes[] memory s6 = _vec(ML_DSA_65, "sig");
        _register(ML_DSA_44, pk4[1]);
        _register(ML_DSA_65, pk6[1]);
        IMLDSAVerifier[2] memory vs = [IMLDSAVerifier(fast), IMLDSAVerifier(slow)];
        for (uint256 i; i < 2; ++i) {
            IMLDSAVerifier v = vs[i];
            assertTrue(v.verify(ML_DSA_44, pk4[1], m4[1], s4[1]));
            assertTrue(v.verify(ML_DSA_65, pk6[1], m6[1], s6[1]));
            assertFalse(v.verify(ML_DSA_65, pk4[1], m4[1], s4[1]), "44 under 65");
            assertFalse(v.verify(ML_DSA_44, pk6[1], m6[1], s6[1]), "65 under 44");
            assertFalse(v.verify(ML_DSA_44, pk4[1], m6[1], s6[1]), "65 sig, 44 key");
            assertFalse(v.verify(ML_DSA_65, pk6[1], m4[1], s4[1]), "44 sig, 65 key");
            assertFalse(v.verify(ParamSet.wrap(3), pk4[1], m4[1], s4[1]), "unknown set");
            assertFalse(v.verify(ML_DSA_44, "", m4[1], s4[1]), "empty pk");
            assertFalse(v.verify(ML_DSA_44, pk4[1], m4[1], ""), "empty sig");
            assertFalse(v.verify(ML_DSA_44, abi.encodePacked(pk4[1], bytes1(0)), m4[1], s4[1]), "long pk");
            assertFalse(v.verify(ML_DSA_44, pk4[1], m4[1], abi.encodePacked(s4[1], bytes1(0))), "long sig");
        }
        // Half-registered (T only / A only committed): fallback, still correct.
        bytes memory pk = pk4[2];
        bytes[] memory s = s4;
        factory.registerT(ML_DSA_44, pk);
        assertTrue(fast.verify(ML_DSA_44, pk, m4[2], s[2]), "T only");
        factory.commitA(ML_DSA_44, pk);
        assertTrue(fast.verify(ML_DSA_44, pk, m4[2], s[2]), "A committed, not stored");
        assertFalse(fast.verify(ML_DSA_44, pk, m4[1], s[1]), "A committed, foreign sig");
    }

    /// ML-DSA-87 through the interface, against 44 and 65, on both paths.
    function test_interface_wrongSetAndLengths_87() public {
        ParamSet[3] memory sets = [ML_DSA_44, ML_DSA_65, ML_DSA_87];
        bytes[3] memory pk;
        bytes[3] memory m;
        bytes[3] memory sg;
        for (uint256 i; i < 3; ++i) {
            pk[i] = _vec(sets[i], "pk")[1];
            m[i] = _vec(sets[i], "msg")[1];
            sg[i] = _vec(sets[i], "sig")[1];
            _register(sets[i], pk[i]);
        }
        IMLDSAVerifier[2] memory vs = [IMLDSAVerifier(fast), IMLDSAVerifier(slow)];
        for (uint256 x; x < 2; ++x) {
            for (uint256 ks; ks < 3; ++ks) {
                for (uint256 ss; ss < 3; ++ss) {
                    for (uint256 cs; cs < 3; ++cs) {
                        if (ks != 2 && ss != 2 && cs != 2) continue;
                        assertEq(vs[x].verify(sets[cs], pk[ks], m[ss], sg[ss]), ks == ss && ss == cs);
                    }
                }
            }
            assertFalse(vs[x].verify(ParamSet.wrap(3), pk[2], m[2], sg[2]), "unknown set");
            assertFalse(vs[x].verify(ML_DSA_87, _slice(pk[2], 0, 2591), m[2], sg[2]), "short pk");
            assertFalse(vs[x].verify(ML_DSA_87, abi.encodePacked(pk[2], bytes1(0)), m[2], sg[2]), "long pk");
            assertFalse(vs[x].verify(ML_DSA_87, pk[2], m[2], _slice(sg[2], 0, 4626)), "short sig");
            assertFalse(vs[x].verify(ML_DSA_87, pk[2], m[2], abi.encodePacked(sg[2], bytes1(0))), "long sig");
            assertFalse(vs[x].verify(ML_DSA_87, "", m[2], sg[2]), "empty pk");
            assertFalse(vs[x].verify(ML_DSA_87, pk[2], m[2], ""), "empty sig");
        }
    }

    // ── Callers are implementation-agnostic ──────────────────────────────────

    /// The same wallet code runs on MLDSAVerifier and on a mock "precompile
    /// adapter"; only what the verifier supports differs.
    function test_interface_walletWithEitherVerifier() public {
        MockPrecompileAdapter mock = new MockPrecompileAdapter();
        assertTrue(mock.supportsInterface(type(IMLDSAVerifier).interfaceId));
        bytes[] memory pk = _vec(ML_DSA_44, "pk");
        bytes[] memory m = _vec(ML_DSA_44, "msg");
        bytes[] memory sig = _vec(ML_DSA_44, "sig");
        IMLDSAVerifier[2] memory vs = [IMLDSAVerifier(fast), IMLDSAVerifier(mock)];
        for (uint256 i; i < 2; ++i) {
            WalletStandIn w = new WalletStandIn(vs[i], address(0));
            address pointer = MLDSAPublicKeys.store(pk[1]);
            w.initialize(ML_DSA_44, pointer, keccak256(pk[1]));
            w.transfer(bytes32(m[1]), sig[1], "");
            assertEq(w.nonce(), 1);
            vm.expectRevert(WalletStandIn.BadSignature.selector);
            w.transfer(bytes32(m[2]), sig[1], "");
            // Same verdicts from both implementations on a corrupted signature.
            bytes memory bad = abi.encodePacked(sig[1]);
            bad[5] = bytes1(uint8(bad[5]) ^ 0x80);
            assertFalse(vs[i].verify(ML_DSA_44, pk[1], m[1], bad));
        }
        // A 44-only implementation refuses a 65 wallet at setup.
        WalletStandIn w65 = new WalletStandIn(mock, address(0));
        vm.expectRevert(WalletStandIn.UnsupportedSet.selector);
        w65.initialize(ML_DSA_65, address(1), bytes32(0));
    }

    // ── Public keys as code ──────────────────────────────────────────────────

    function test_publicKeys_storeLoad() public {
        PkStoreHarness ps = new PkStoreHarness();
        ParamSet[3] memory sets = [ML_DSA_44, ML_DSA_65, ML_DSA_87];
        for (uint256 i; i < 3; ++i) {
            bytes[] memory pk = _vec(sets[i], "pk");
            for (uint256 v; v < pk.length; ++v) {
                address p = ps.store(pk[v]);
                assertEq(p.code, abi.encodePacked(bytes1(0), pk[v]));
                assertEq(ps.load(p), pk[v]);
            }
            // A key whose first byte is 0xEF stores fine (the 0x00 prefix; EIP-3541).
            bytes memory ef = abi.encodePacked(pk[0]);
            ef[0] = 0xEF;
            assertEq(ps.load(ps.store(ef)), ef);
        }
        assertEq(ps.load(address(0xdead)).length, 0, "no code -> empty");
        vm.expectRevert(MLDSAPublicKeys.StoreFailed.selector);
        ps.store(new bytes(24576));
    }

    // ── Commit-then-store Â, one-transaction setup, first and later transfer ─

    function test_gas_walletLifecycle_44() public {
        _lifecycle(ML_DSA_44);
    }

    function test_gas_walletLifecycle_65() public {
        _lifecycle(ML_DSA_65);
    }

    function test_gas_walletLifecycle_87() public {
        _lifecycle(ML_DSA_87);
    }

    function _lifecycle(ParamSet set) internal {
        string memory name = _name(set);
        bytes[] memory pks = _vec(set, "pk");
        bytes[] memory m = _vec(set, "msg");
        bytes[] memory sig = _vec(set, "sig");
        bytes memory pk = pks[1];
        bytes32 pkHash = keccak256(pk);
        if (set == ML_DSA_87) _lifecycleParts87(pk, pkHash);
        bytes memory aHat = h.precompute(set, pk); // tr ‖ Â ‖ t̂; Â is the middle
        {
            (, MLDSA.Params memory p) = MLDSA.params(set);
            aHat = _slice(aHat, 64, p.aHatBytes);
        }

        // Separate steps, each in a fresh factory so nothing is warm or pre-done.
        MLDSAKeyFactory f1 = new MLDSAKeyFactory();
        uint256 g = gasleft();
        f1.commitA(set, pk);
        uint256 gCommit = g - gasleft();
        vm.cool(address(f1));
        g = gasleft();
        f1.storeA(set, pkHash, aHat);
        uint256 gStore = g - gasleft();
        g = gasleft();
        f1.registerT(set, pk);
        uint256 gT = g - gasleft();

        // One-transaction setup: commitA + registerT + pk as code + clone + init.
        MLDSAKeyFactory f = new MLDSAKeyFactory();
        MLDSAVerifier verifier = new MLDSAVerifier(address(f));
        WalletStandIn impl = new WalletStandIn(verifier, address(f));
        SetupBundler bundler = new SetupBundler(f, address(impl));
        bytes memory setupData = abi.encodeCall(SetupBundler.setup, (set, pk));
        vm.cool(address(f));
        vm.cool(address(bundler));
        vm.cool(address(impl));
        g = gasleft();
        WalletStandIn wallet = WalletStandIn(bundler.setup(set, pk));
        uint256 gSetup = g - gasleft() + 21000 + _calldataGas(setupData);
        assertLt(gSetup, CAP, "setup fits one transaction (EIP-7825 cap)");
        assertEq(uint8(f.aStatus(set, pkHash)), uint8(MLDSAKeyFactory.AStatus.Committed));

        // First transfer: Â in calldata, stored, then the fast path.
        bytes memory firstData = abi.encodeCall(WalletStandIn.transfer, (bytes32(m[1]), sig[1], aHat));
        _coolAll(f, set, pkHash, address(wallet), address(verifier), address(impl));
        g = gasleft();
        wallet.transfer(bytes32(m[1]), sig[1], aHat);
        uint256 gFirst = g - gasleft() + 21000 + _calldataGas(firstData);
        assertLt(gFirst, CAP, "first transfer fits one transaction");
        assertEq(uint8(f.aStatus(set, pkHash)), uint8(MLDSAKeyFactory.AStatus.Stored));
        assertTrue(f.isRegistered(set, pkHash), "fast path now available");

        // Later transfer: fast path only (same signature; the stand-in has no replay
        // protection — it only counts).
        bytes memory laterData = abi.encodeCall(WalletStandIn.transfer, (bytes32(m[1]), sig[1], bytes("")));
        _coolAll(f, set, pkHash, address(wallet), address(verifier), address(impl));
        g = gasleft();
        wallet.transfer(bytes32(m[1]), sig[1], "");
        uint256 gLater = g - gasleft() + 21000 + _calldataGas(laterData);
        assertLt(gLater, CAP);
        assertEq(wallet.nonce(), 2);

        // For comparison: a transfer on a wallet whose Â was never stored (fallback).
        WalletStandIn w2 = WalletStandIn(bundler.setup(set, pks[2]));
        bytes memory fbData = abi.encodeCall(WalletStandIn.transfer, (bytes32(m[2]), sig[2], bytes("")));
        _coolAll(f, set, keccak256(pks[2]), address(w2), address(verifier), address(impl));
        g = gasleft();
        w2.transfer(bytes32(m[2]), sig[2], "");
        uint256 gFallback = g - gasleft() + 21000 + _calldataGas(fbData);
        assertLt(gFallback, CAP);

        console.log(name, "wallet lifecycle (tx totals incl. 21000 + calldata at 16/4 per byte where noted):");
        console.log("  commitA (call only)", gCommit);
        console.log("  storeA (call only)", gStore);
        console.log("  registerT (call only)", gT);
        console.log("  ONE-tx setup: commitA + registerT + pk code + clone + init (tx)", gSetup);
        console.log("  FIRST transfer: A_hat calldata + storeA + fast verify (tx)", gFirst);
        console.log("  LATER transfer: fast verify (tx)", gLater);
        console.log("  transfer before A_hat is stored: fallback verify (tx)", gFallback);
        console.log("  calldata gas of A_hat alone", _calldataGas(aHat));
        console.log("  headroom under the 2^24 cap: setup / first / later / fallback");
        console.log("   ", CAP - gSetup, CAP - gFirst, CAP - gLater);
        console.log("   ", CAP - gFallback);
    }

    /// ML-DSA-87 only: the per-part API, each step in its own fresh factory and
    /// measured as a transaction (21000 + calldata), all against the cap. (Â as a
    /// whole — registerA — is over the cap; that is what the parts are for.)
    function _lifecycleParts87(bytes memory pk, bytes32 pkHash) internal {
        bytes memory blob = h.precompute(ML_DSA_87, pk);
        bytes[2] memory part = [_slice(blob, 64, 21504), _slice(blob, 64 + 21504, 21504)];
        console.log("ML-DSA-87 per-part steps (tx totals):");
        MLDSAKeyFactory f1 = new MLDSAKeyFactory();
        for (uint256 i; i < 2; ++i) {
            vm.cool(address(f1));
            bytes memory data = abi.encodeCall(MLDSAKeyFactory.registerAPart, (ML_DSA_87, pk, i));
            uint256 g = gasleft();
            f1.registerAPart(ML_DSA_87, pk, i);
            g = g - gasleft() + 21000 + _calldataGas(data);
            assertLt(g, CAP, "registerAPart fits");
            console.log("  registerAPart (tx), part", i, g);
        }
        MLDSAKeyFactory f2 = new MLDSAKeyFactory();
        {
            bytes memory data = abi.encodeCall(MLDSAKeyFactory.commitA, (ML_DSA_87, pk));
            uint256 g = gasleft();
            f2.commitA(ML_DSA_87, pk);
            g = g - gasleft() + 21000 + _calldataGas(data);
            assertLt(g, CAP, "commitA fits");
            console.log("  commitA, both parts (tx)", g);
        }
        for (uint256 i; i < 2; ++i) {
            vm.cool(address(f2));
            bytes memory data = abi.encodeCall(MLDSAKeyFactory.storeAPart, (ML_DSA_87, pkHash, i, part[i]));
            uint256 g = gasleft();
            f2.storeAPart(ML_DSA_87, pkHash, i, part[i]);
            g = g - gasleft() + 21000 + _calldataGas(data);
            assertLt(g, CAP, "storeAPart fits");
            console.log("  storeAPart (tx), part", i, g);
        }
        {
            vm.cool(address(f2));
            bytes memory data = abi.encodeCall(MLDSAKeyFactory.registerT, (ML_DSA_87, pk));
            uint256 g = gasleft();
            f2.registerT(ML_DSA_87, pk);
            g = g - gasleft() + 21000 + _calldataGas(data);
            assertLt(g, CAP, "registerT fits");
            console.log("  registerT (tx)", g);
        }
        // Both ways end in the same bytes at the same kind of address.
        assertEq(f1.aPartAddress(ML_DSA_87, pkHash, 1).code, f2.aPartAddress(ML_DSA_87, pkHash, 1).code);
        assertTrue(f2.isRegistered(ML_DSA_87, pkHash));
    }

    uint256 internal constant CAP = 16_777_216; // EIP-7825: 2^24 gas per transaction

    function _name(ParamSet set) internal pure returns (string memory) {
        return set == ML_DSA_44 ? "ML-DSA-44" : set == ML_DSA_65 ? "ML-DSA-65" : "ML-DSA-87";
    }

    function _coolAll(MLDSAKeyFactory f, ParamSet set, bytes32 pkHash, address w, address v, address impl) internal {
        (address a, address t) = f.addressesOf(set, pkHash);
        if (set == ML_DSA_87) vm.cool(f.aPartAddress(set, pkHash, 1));
        vm.cool(a);
        vm.cool(t);
        vm.cool(address(f));
        vm.cool(w);
        vm.cool(v);
        vm.cool(impl);
        vm.cool(WalletStandIn(w).pkPointer());
    }

    /// Intrinsic calldata gas: 16 per non-zero byte, 4 per zero byte.
    function _calldataGas(bytes memory data) internal pure returns (uint256 g) {
        for (uint256 i; i < data.length; ++i) {
            g += data[i] == 0 ? 4 : 16;
        }
    }

    // ── commitA / storeA invariants ──────────────────────────────────────────

    function test_commitStore_44() public {
        _commitStore(ML_DSA_44);
    }

    function test_commitStore_65() public {
        _commitStore(ML_DSA_65);
    }

    function test_commitStore_87() public {
        _commitStore(ML_DSA_87);
    }

    function _commitStore(ParamSet set) internal {
        bytes[] memory pks = _vec(set, "pk");
        bytes[] memory m = _vec(set, "msg");
        bytes[] memory sig = _vec(set, "sig");
        bytes memory pk = pks[1];
        bytes32 pkHash = keccak256(pk);
        (, MLDSA.Params memory p) = MLDSA.params(set);
        bytes memory aHat = _slice(h.precompute(set, pk), 64, p.aHatBytes);
        (address a, address t) = factory.addressesOf(set, pkHash);

        // registerA's result, then rewind and do it in two steps.
        uint256 snap = vm.snapshotState();
        factory.registerA(set, pk);
        bytes memory viaRegister = a.code;
        assertEq(uint8(factory.aStatus(set, pkHash)), uint8(MLDSAKeyFactory.AStatus.Stored));
        vm.revertToState(snap);
        assertEq(a.code.length, 0);

        assertEq(uint8(factory.aStatus(set, pkHash)), uint8(MLDSAKeyFactory.AStatus.None));
        vm.expectRevert(MLDSAKeyFactory.NotCommitted.selector);
        factory.storeA(set, pkHash, aHat);
        bytes32 aHash = factory.commitA(set, pk);
        if (p.aParts == 1) {
            assertEq(aHash, keccak256(aHat), "commitment = keccak256(precomputeA(pk))");
        } else {
            // 87: one commitment per part; commitA returns keccak256(h0 ‖ h1).
            uint256 half = p.aHatBytes / 2;
            bytes32 h0 = keccak256(_slice(aHat, 0, half));
            bytes32 h1 = keccak256(_slice(aHat, half, half));
            assertEq(aHash, keccak256(abi.encodePacked(h0, h1)), "commitment covers both parts");
        }
        assertEq(factory.commitA(set, pk), aHash, "idempotent");
        assertEq(uint8(factory.aStatus(set, pkHash)), uint8(MLDSAKeyFactory.AStatus.Committed));
        assertFalse(factory.isRegistered(set, pkHash));

        // Anything that does not hash to the commitment: revert, nothing deployed.
        bytes memory wrong = abi.encodePacked(aHat);
        wrong[1000] = bytes1(uint8(wrong[1000]) ^ 1);
        vm.expectRevert(MLDSAKeyFactory.CommitmentMismatch.selector);
        factory.storeA(set, pkHash, wrong);
        vm.expectRevert(MLDSAKeyFactory.CommitmentMismatch.selector);
        factory.storeA(set, pkHash, _slice(aHat, 0, aHat.length - 1));
        vm.expectRevert(MLDSAKeyFactory.CommitmentMismatch.selector);
        factory.storeA(set, pkHash, "");
        // Â of another key, honestly computed: still not this key's commitment.
        bytes memory foreign = _slice(h.precompute(set, pks[2]), 64, p.aHatBytes);
        vm.expectRevert(MLDSAKeyFactory.CommitmentMismatch.selector);
        factory.storeA(set, pkHash, foreign);
        // Committed under another set: nothing to store against.
        ParamSet other = set == ML_DSA_44 ? ML_DSA_65 : ML_DSA_44;
        vm.expectRevert(MLDSAKeyFactory.NotCommitted.selector);
        factory.storeA(other, pkHash, aHat);
        if (!(set == ML_DSA_87)) {
            vm.expectRevert(MLDSAKeyFactory.NotCommitted.selector);
            factory.storeA(ML_DSA_87, pkHash, aHat);
        }
        vm.expectRevert(MLDSAKeyFactory.UnsupportedParamSet.selector);
        factory.storeA(ParamSet.wrap(9), pkHash, aHat);
        assertEq(a.code.length, 0, "nothing at the address");

        // The right bytes, from anyone: deployed where registerA would have, same code.
        vm.prank(address(0xBEEF));
        assertEq(factory.storeA(set, pkHash, aHat), a);
        assertEq(a.code, viaRegister, "byte-identical to registerA");
        // 0x00 ‖ precomputeA(pk) — for 87, part 0's half of it (part 1 alongside).
        uint256 pb = p.aHatBytes / p.aParts;
        for (uint256 part; part < p.aParts; ++part) {
            assertEq(
                factory.aPartAddress(set, pkHash, part).code,
                abi.encodePacked(bytes1(0), _slice(aHat, part * pb, pb)),
                "0x00 || precomputeA(pk) part"
            );
        }
        assertEq(uint8(factory.aStatus(set, pkHash)), uint8(MLDSAKeyFactory.AStatus.Stored));
        assertEq(factory.storeA(set, pkHash, wrong), a, "idempotent once stored");
        assertEq(a.code, viaRegister);
        factory.registerA(set, pk); // no-op now
        assertEq(a.code, viaRegister);
        // The part functions are the plain ones for a single-part set: same code,
        // same address, in a fresh factory.
        if (p.aParts == 1) {
            MLDSAKeyFactory g = new MLDSAKeyFactory();
            address ga = g.registerAPart(set, pk, 0);
            assertEq(ga.code, viaRegister, "registerAPart(set, pk, 0) = registerA");
            MLDSAKeyFactory g2 = new MLDSAKeyFactory();
            g2.commitA(set, pk);
            assertEq(g2.aPartCommitment(set, pkHash, 0), keccak256(aHat));
            address ga2 = g2.storeAPart(set, pkHash, 0, aHat);
            assertEq(ga2, g2.aPartAddress(set, pkHash, 0));
            assertEq(ga2.code, viaRegister, "storeAPart(set, pkHash, 0, A) = storeA");
        }

        // With T: fast path; identical verdicts to the fallback.
        factory.registerT(set, pk);
        assertTrue(factory.isRegistered(set, pkHash));
        assertTrue(t.code.length != 0);
        assertTrue(factory.verify(set, pkHash, m[1], sig[1]));
        assertEq(fast.verify(set, pk, m[1], sig[1]), slow.verify(set, pk, m[1], sig[1]));
    }

    // ── ML-DSA-87: Â in two parts ────────────────────────────────────────────

    /// Per-part commitments and stores: wrong bytes for a part (including the
    /// OTHER part's bytes, and a different key's part) revert and deploy nothing;
    /// one part stored leaves the fast path off and every path still agrees; the
    /// second part switches it on; storeA with all of Â fills in what is missing.
    function test_twoPart_storage_87() public {
        bytes[] memory pks = _vec(ML_DSA_87, "pk");
        bytes[] memory m = _vec(ML_DSA_87, "msg");
        bytes[] memory sig = _vec(ML_DSA_87, "sig");
        bytes memory pk = pks[1];
        bytes32 pkHash = keccak256(pk);
        bytes memory blob = h.precompute(ML_DSA_87, pk);
        bytes memory aHat = _slice(blob, 64, 43008);
        bytes[2] memory part = [_slice(aHat, 0, 21504), _slice(aHat, 21504, 21504)];
        bytes memory foreign1 = _slice(h.precompute(ML_DSA_87, pks[2]), 64 + 21504, 21504);
        address[2] memory addr =
            [factory.aPartAddress(ML_DSA_87, pkHash, 0), factory.aPartAddress(ML_DSA_87, pkHash, 1)];

        vm.expectRevert(MLDSAKeyFactory.NotCommitted.selector);
        factory.storeAPart(ML_DSA_87, pkHash, 0, part[0]);
        vm.expectRevert(MLDSAKeyFactory.InvalidPart.selector);
        factory.storeAPart(ML_DSA_87, pkHash, 2, part[0]);
        vm.expectRevert(MLDSAKeyFactory.InvalidPart.selector);
        factory.storeAPart(ML_DSA_65, pkHash, 1, part[0]);

        bytes32 aHash = factory.commitA(ML_DSA_87, pk);
        assertEq(factory.aPartCommitment(ML_DSA_87, pkHash, 0), keccak256(part[0]));
        assertEq(factory.aPartCommitment(ML_DSA_87, pkHash, 1), keccak256(part[1]));
        assertEq(aHash, keccak256(abi.encodePacked(keccak256(part[0]), keccak256(part[1]))), "commitment covers both");
        assertEq(factory.aPartCommitment(ML_DSA_87, pkHash, 2), bytes32(0));
        assertEq(uint8(factory.aStatus(ML_DSA_87, pkHash)), uint8(MLDSAKeyFactory.AStatus.Committed));

        // Wrong bytes per part: revert, nothing deployed.
        vm.expectRevert(MLDSAKeyFactory.CommitmentMismatch.selector);
        factory.storeAPart(ML_DSA_87, pkHash, 1, part[0]); //   part 0's bytes as part 1
        vm.expectRevert(MLDSAKeyFactory.CommitmentMismatch.selector);
        factory.storeAPart(ML_DSA_87, pkHash, 0, part[1]); //   and vice versa
        vm.expectRevert(MLDSAKeyFactory.CommitmentMismatch.selector);
        factory.storeAPart(ML_DSA_87, pkHash, 1, foreign1); //  another key's part 1
        vm.expectRevert(MLDSAKeyFactory.CommitmentMismatch.selector);
        factory.storeAPart(ML_DSA_87, pkHash, 0, aHat); //      all of Â as one part
        bytes memory flipped = abi.encodePacked(part[1]);
        flipped[21503] = bytes1(uint8(flipped[21503]) ^ 1);
        vm.expectRevert(MLDSAKeyFactory.CommitmentMismatch.selector);
        factory.storeAPart(ML_DSA_87, pkHash, 1, flipped);
        // storeA (all of Â): parts swapped, truncated, or one part only.
        vm.expectRevert(MLDSAKeyFactory.CommitmentMismatch.selector);
        factory.storeA(ML_DSA_87, pkHash, abi.encodePacked(part[1], part[0]));
        vm.expectRevert(MLDSAKeyFactory.CommitmentMismatch.selector);
        factory.storeA(ML_DSA_87, pkHash, part[0]);
        vm.expectRevert(MLDSAKeyFactory.CommitmentMismatch.selector);
        factory.storeA(ML_DSA_87, pkHash, _slice(aHat, 0, 43007));
        assertEq(addr[0].code.length + addr[1].code.length, 0, "nothing deployed");

        // T plus part 1 only: no fast path; fast == slow == library on good and bad input.
        factory.registerT(ML_DSA_87, pk);
        vm.prank(address(0xBEEF));
        assertEq(factory.storeAPart(ML_DSA_87, pkHash, 1, part[1]), addr[1]);
        assertEq(addr[1].code, abi.encodePacked(bytes1(0), part[1]));
        assertEq(uint8(factory.aPartStatus(ML_DSA_87, pkHash, 0)), uint8(MLDSAKeyFactory.AStatus.Committed));
        assertEq(uint8(factory.aPartStatus(ML_DSA_87, pkHash, 1)), uint8(MLDSAKeyFactory.AStatus.Stored));
        assertEq(uint8(factory.aStatus(ML_DSA_87, pkHash)), uint8(MLDSAKeyFactory.AStatus.Committed), "weakest part");
        assertFalse(factory.isRegistered(ML_DSA_87, pkHash));
        assertEq(factory.load(ML_DSA_87, pkHash).length, 0);
        assertFalse(factory.verify(ML_DSA_87, pkHash, m[1], sig[1]), "factory path needs both parts");
        _agreePartial(pk, m[1], sig[1], true);
        _agreePartial(pk, m[2], sig[1], false);
        _agreePartial(pk, m[1], sig[2], false);
        // Idempotent once stored: wrong bytes for a stored part are ignored.
        assertEq(factory.storeAPart(ML_DSA_87, pkHash, 1, part[0]), addr[1]);
        assertEq(addr[1].code, abi.encodePacked(bytes1(0), part[1]));

        // storeA with all of Â stores just the missing part 0; now the fast path.
        assertEq(factory.storeA(ML_DSA_87, pkHash, aHat), addr[0]);
        assertEq(addr[0].code, abi.encodePacked(bytes1(0), part[0]));
        assertTrue(factory.isRegistered(ML_DSA_87, pkHash));
        assertEq(uint8(factory.aStatus(ML_DSA_87, pkHash)), uint8(MLDSAKeyFactory.AStatus.Stored));
        assertEq(factory.load(ML_DSA_87, pkHash), blob, "load = precompute");
        assertEq(factory.load(ML_DSA_87, pkHash), vm.parseJsonBytes(_diff(), ".mldsa87.blob1"), "vs dilithium-py");
        _agree(ML_DSA_87, pk, m[1], sig[1], true);
        _agree(ML_DSA_87, pk, m[2], sig[1], false);
        // Byte-identical to registerA / registerAPart in another factory.
        MLDSAKeyFactory g = new MLDSAKeyFactory();
        g.registerAPart(ML_DSA_87, pk, 1);
        g.registerAPart(ML_DSA_87, pk, 0);
        assertEq(g.aPartAddress(ML_DSA_87, pkHash, 0).code, addr[0].code);
        assertEq(g.aPartAddress(ML_DSA_87, pkHash, 1).code, addr[1].code);
        assertEq(g.aPartCommitment(ML_DSA_87, pkHash, 0), keccak256(part[0]));
        assertEq(g.commitA(ML_DSA_87, pk), aHash, "registerAPart recorded the same commitments");
    }

    /// Part-wise registration first, then commitA: commitA only fills the missing
    /// part's commitment and the result is the same as committing from scratch.
    function test_twoPart_registerPartThenCommit_87() public {
        bytes memory pk = _vec(ML_DSA_87, "pk")[2];
        bytes32 pkHash = keccak256(pk);
        factory.registerAPart(ML_DSA_87, pk, 0);
        assertEq(uint8(factory.aStatus(ML_DSA_87, pkHash)), uint8(MLDSAKeyFactory.AStatus.None), "part 1 untouched");
        assertEq(factory.aPartCommitment(ML_DSA_87, pkHash, 1), bytes32(0));
        bytes32 aHash = factory.commitA(ML_DSA_87, pk);
        MLDSAKeyFactory g = new MLDSAKeyFactory();
        assertEq(g.commitA(ML_DSA_87, pk), aHash);
        assertEq(uint8(factory.aStatus(ML_DSA_87, pkHash)), uint8(MLDSAKeyFactory.AStatus.Committed));
        assertEq(uint8(factory.aPartStatus(ML_DSA_87, pkHash, 0)), uint8(MLDSAKeyFactory.AStatus.Stored));
        // registerA finishes it (part 0 is a no-op, part 1 is computed and stored).
        assertEq(factory.registerA(ML_DSA_87, pk), factory.aPartAddress(ML_DSA_87, pkHash, 0));
        assertEq(uint8(factory.aStatus(ML_DSA_87, pkHash)), uint8(MLDSAKeyFactory.AStatus.Stored));
    }

    /// The fast verifier on a partially stored key: takes the fallback and agrees
    /// with the empty-factory verifier and the library.
    function _agreePartial(bytes memory pk, bytes memory m, bytes memory sig, bool want) internal view {
        assertFalse(factory.isRegistered(ML_DSA_87, keccak256(pk)), "partial: no fast path");
        assertEq(fast.verify(ML_DSA_87, pk, m, sig), want, "fast (falls back)");
        assertEq(slow.verify(ML_DSA_87, pk, m, sig), want, "fallback");
        assertEq(h.verify(ML_DSA_87, pk, m, sig), want, "library");
    }

    function test_ensureStored() public {
        bytes[] memory pks = _vec(ML_DSA_44, "pk");
        bytes32 pkHash = keccak256(pks[1]);
        (, MLDSA.Params memory p) = MLDSA.params(ML_DSA_44);
        bytes memory aHat = _slice(h.precompute(ML_DSA_44, pks[1]), 64, p.aHatBytes);
        assertFalse(this.ensureStoredExt(ML_DSA_44, pkHash, ""), "empty: no-op");
        vm.expectRevert(MLDSAKeyFactory.NotCommitted.selector);
        this.ensureStoredExt(ML_DSA_44, pkHash, aHat);
        factory.commitA(ML_DSA_44, pks[1]);
        assertTrue(this.ensureStoredExt(ML_DSA_44, pkHash, aHat));
        assertTrue(this.ensureStoredExt(ML_DSA_44, pkHash, ""), "already stored");
        assertTrue(this.ensureStoredExt(ML_DSA_44, pkHash, hex"00"), "already stored: bytes ignored");
        assertFalse(this.ensureStoredExt(ParamSet.wrap(3), pkHash, aHat), "unknown set");

        // ML-DSA-87: all of Â (both parts) in one go; or part 0 already stored.
        bytes[] memory p87 = _vec(ML_DSA_87, "pk");
        bytes32 h87 = keccak256(p87[1]);
        bytes memory a87 = _slice(h.precompute(ML_DSA_87, p87[1]), 64, 43008);
        assertFalse(this.ensureStoredExt(ML_DSA_87, h87, ""), "87 empty: no-op");
        vm.expectRevert(MLDSAKeyFactory.NotCommitted.selector);
        this.ensureStoredExt(ML_DSA_87, h87, a87);
        factory.registerAPart(ML_DSA_87, p87[1], 0); // commits and stores part 0 only
        vm.expectRevert(MLDSAKeyFactory.NotCommitted.selector);
        this.ensureStoredExt(ML_DSA_87, h87, a87); //    part 1 not committed yet
        factory.commitA(ML_DSA_87, p87[1]);
        assertFalse(this.ensureStoredExt(ML_DSA_87, h87, ""), "half stored is not stored");
        assertTrue(this.ensureStoredExt(ML_DSA_87, h87, a87));
        assertEq(factory.aPartAddress(ML_DSA_87, h87, 1).code.length, 21505);
        assertTrue(this.ensureStoredExt(ML_DSA_87, h87, ""), "87 stored");
    }

    function ensureStoredExt(ParamSet set, bytes32 pkHash, bytes calldata aHat) external returns (bool) {
        return MLDSAKeys.ensureStored(address(factory), set, pkHash, aHat);
    }

    // ── Gas through the interface ────────────────────────────────────────────

    function test_gas_interface_44() public {
        _gasInterface(ML_DSA_44);
    }

    function test_gas_interface_65() public {
        _gasInterface(ML_DSA_65);
    }

    function test_gas_interface_87() public {
        _gasInterface(ML_DSA_87);
    }

    function _gasInterface(ParamSet set) internal {
        string memory name = _name(set);
        bytes[] memory pk = _vec(set, "pk");
        bytes[] memory m = _vec(set, "msg");
        bytes[] memory sig = _vec(set, "sig");
        _register(set, pk[1]);
        _register(set, pk[3]);
        console.log(name, "gas, measured inside a small caller contract, all accounts cold:");
        GasProbe probe = new GasProbe();
        uint256[2] memory vs = [uint256(1), 3];
        for (uint256 i; i < 2; ++i) {
            uint256 v = vs[i];
            bytes32 pkHash = keccak256(pk[v]);
            bool ok;
            _cool(set, pkHash);
            (uint256 gFast, bool ok1) = probe.viaInterface(fast, set, pk[v], m[v], sig[v]);
            _cool(set, pkHash);
            (uint256 gSlow, bool ok2) = probe.viaInterface(slow, set, pk[v], m[v], sig[v]);
            _cool(set, pkHash);
            (uint256 gLib, bool ok3) = probe.viaLibrary(address(factory), set, pkHash, m[v], sig[v]);
            _cool(set, pkHash);
            (uint256 gLibH, bool ok4) = probe.viaLibraryHashingPk(address(factory), set, pk[v], m[v], sig[v]);
            ok = ok1 && ok2 && ok3 && ok4;
            assertTrue(ok);
            console.log("  msg bytes", m[v].length);
            console.log("    IMLDSAVerifier fast path (registered)", gFast);
            console.log("    IMLDSAVerifier fallback (unregistered)", gSlow);
            console.log("    library MLDSAKeys.verify by pkHash, in-frame (reference)", gLib);
            console.log("    library, in-frame, hashing the pk first", gLibH);
            console.log("    interface overhead over the in-frame library path", gFast - gLib);
            _cool(set, pkHash);
            (uint256 gPqFast, bool ok5) = probe.viaPQ(fast, _alg(set), pk[v], m[v], sig[v]);
            _cool(set, pkHash);
            (uint256 gPqSlow, bool ok6) = probe.viaPQ(slow, _alg(set), pk[v], m[v], sig[v]);
            assertTrue(ok5 && ok6);
            console.log("    IPQVerifier fast path (registered)", gPqFast);
            console.log("    IPQVerifier fallback (unregistered)", gPqSlow);
            // As transactions (21000 + calldata of verify(set, pk, m, sig)) under the cap.
            uint256 cd = 21000 + _calldataGas(abi.encodeCall(IMLDSAVerifier.verify, (set, pk[v], m[v], sig[v])));
            console.log("    as a tx: fast / fallback", gFast + cd, gSlow + cd);
            assertLt(gFast + cd, CAP, "fast path fits a transaction");
            assertLt(gSlow + cd, CAP, "fallback fits a transaction");
        }
        PkStoreHarness ps = new PkStoreHarness();
        address p = ps.store(pk[1]);
        vm.cool(p);
        (uint256 lg, uint256 len) = ps.loadGas(p);
        console.log("  MLDSAPublicKeys.load (cold), bytes", len);
        console.log("    gas", lg);
    }

    function _cool(ParamSet set, bytes32 pkHash) internal {
        (address a, address t) = factory.addressesOf(set, pkHash);
        if (set == ML_DSA_87) vm.cool(factory.aPartAddress(set, pkHash, 1));
        vm.cool(a);
        vm.cool(t);
        vm.cool(address(factory));
        vm.cool(address(fast));
        vm.cool(address(slow));
        vm.cool(address(h));
    }

    function _slice(bytes memory b, uint256 o, uint256 n) internal pure returns (bytes memory c) {
        c = new bytes(n);
        for (uint256 i; i < n; ++i) {
            c[i] = b[o + i];
        }
    }
}
