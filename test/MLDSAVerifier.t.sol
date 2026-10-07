// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {IMLDSAVerifier, ParamSet, ML_DSA_44, ML_DSA_65} from "../src/IMLDSAVerifier.sol";
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
    string internal diff;
    string internal acvp;

    function setUp() public {
        h = new MLDSAHarness();
        factory = new MLDSAKeyFactory();
        fast = new MLDSAVerifier(address(factory));
        slow = new MLDSAVerifier(address(new MLDSAKeyFactory()));
        diff = vm.readFile("test/mldsa/differential.json");
        acvp = vm.readFile("test/mldsa/acvp.json");
    }

    function _key(ParamSet set) internal pure returns (string memory) {
        return set == ML_DSA_44 ? ".mldsa44" : ".mldsa65";
    }

    function _vec(ParamSet set, string memory field) internal view returns (bytes[] memory) {
        return vm.parseJsonBytesArray(diff, string.concat(_key(set), ".", field));
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
        assertTrue(fast.supportsParamSet(ParamSet.wrap(2))); // ML-DSA-87
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

    function test_interface_differential_44() public {
        _differential(ML_DSA_44);
    }

    function test_interface_differential_65() public {
        _differential(ML_DSA_65);
    }

    /// Empty-context vectors must verify; contexted ones (the interface is pure
    /// ML-DSA with ctx = "") must not; and all three paths agree on every input,
    /// including corruptions.
    function _differential(ParamSet set) internal {
        bytes[] memory pk = _vec(set, "pk");
        bytes[] memory m = _vec(set, "msg");
        bytes[] memory ctx = _vec(set, "ctx");
        bytes[] memory sig = _vec(set, "sig");
        uint256 passed;
        for (uint256 v; v < pk.length; ++v) {
            _register(set, pk[v]);
            bool want = ctx[v].length == 0;
            _agree(set, pk[v], m[v], sig[v], want);
            if (want) ++passed;
            bytes memory bad = abi.encodePacked(sig[v]);
            bad[100] = bytes1(uint8(bad[100]) ^ 1);
            _agree(set, pk[v], m[v], bad, false);
            _agree(set, pk[v], abi.encodePacked(m[v], bytes1(0)), sig[v], false);
        }
        bytes memory dup = vm.parseJsonBytes(diff, string.concat(_key(set), ".malformed.duplicate"));
        _agree(set, pk[1], m[1], dup, false); // repeated hint index: FIPS 204 rejects
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

    /// The interface is ML-DSA.Verify with ctx = "": NIST's external vectors carry
    /// contexts (and the internal ones a raw M′), so through the interface each
    /// vector is run as (pk, msg, sig) and the fast path, the fallback and the
    /// library's verify(set, pk, msg, sig) must agree; where NIST's context is
    /// empty, the result must also be NIST's.
    function _acvp(ParamSet set, string memory g, bool external_, uint256 from, uint256 to) internal {
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

    /// fast (registered), slow (fallback) and the library all return `want`.
    function _agree(ParamSet set, bytes memory pk, bytes memory m, bytes memory sig, bool want) internal view {
        assertTrue(factory.isRegistered(set, keccak256(pk)), "fast path available");
        assertEq(fast.verify(set, pk, m, sig), want, "fast path");
        assertEq(slow.verify(set, pk, m, sig), want, "fallback");
        assertEq(h.verify(set, pk, m, sig), want, "library");
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
        ParamSet[2] memory sets = [ML_DSA_44, ML_DSA_65];
        for (uint256 i; i < 2; ++i) {
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

    function _lifecycle(ParamSet set) internal {
        string memory name = set == ML_DSA_44 ? "ML-DSA-44" : "ML-DSA-65";
        bytes[] memory pks = _vec(set, "pk");
        bytes[] memory m = _vec(set, "msg");
        bytes[] memory sig = _vec(set, "sig");
        bytes memory pk = pks[1];
        bytes32 pkHash = keccak256(pk);
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
        assertLt(gSetup, 16_777_216, "setup fits one transaction (EIP-7825 cap)");
        assertEq(uint8(f.aStatus(set, pkHash)), uint8(MLDSAKeyFactory.AStatus.Committed));

        // First transfer: Â in calldata, stored, then the fast path.
        bytes memory firstData = abi.encodeCall(WalletStandIn.transfer, (bytes32(m[1]), sig[1], aHat));
        _coolAll(f, set, pkHash, address(wallet), address(verifier), address(impl));
        g = gasleft();
        wallet.transfer(bytes32(m[1]), sig[1], aHat);
        uint256 gFirst = g - gasleft() + 21000 + _calldataGas(firstData);
        assertEq(uint8(f.aStatus(set, pkHash)), uint8(MLDSAKeyFactory.AStatus.Stored));
        assertTrue(f.isRegistered(set, pkHash), "fast path now available");

        // Later transfer: fast path only (same signature; the stand-in has no replay
        // protection — it only counts).
        bytes memory laterData = abi.encodeCall(WalletStandIn.transfer, (bytes32(m[1]), sig[1], bytes("")));
        _coolAll(f, set, pkHash, address(wallet), address(verifier), address(impl));
        g = gasleft();
        wallet.transfer(bytes32(m[1]), sig[1], "");
        uint256 gLater = g - gasleft() + 21000 + _calldataGas(laterData);
        assertEq(wallet.nonce(), 2);

        // For comparison: a transfer on a wallet whose Â was never stored (fallback).
        WalletStandIn w2 = WalletStandIn(bundler.setup(set, pks[2]));
        bytes memory fbData = abi.encodeCall(WalletStandIn.transfer, (bytes32(m[2]), sig[2], bytes("")));
        _coolAll(f, set, keccak256(pks[2]), address(w2), address(verifier), address(impl));
        g = gasleft();
        w2.transfer(bytes32(m[2]), sig[2], "");
        uint256 gFallback = g - gasleft() + 21000 + _calldataGas(fbData);

        console.log(name, "wallet lifecycle (tx totals incl. 21000 + calldata at 16/4 per byte where noted):");
        console.log("  commitA (call only)", gCommit);
        console.log("  storeA (call only)", gStore);
        console.log("  registerT (call only)", gT);
        console.log("  ONE-tx setup: commitA + registerT + pk code + clone + init (tx)", gSetup);
        console.log("  FIRST transfer: A_hat calldata + storeA + fast verify (tx)", gFirst);
        console.log("  LATER transfer: fast verify (tx)", gLater);
        console.log("  transfer before A_hat is stored: fallback verify (tx)", gFallback);
        console.log("  calldata gas of A_hat alone", _calldataGas(aHat));
    }

    function _coolAll(MLDSAKeyFactory f, ParamSet set, bytes32 pkHash, address w, address v, address impl) internal {
        (address a, address t) = f.addressesOf(set, pkHash);
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
        assertEq(aHash, keccak256(aHat), "commitment = keccak256(precomputeA(pk))");
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
        // Committed under the other set: nothing to store against.
        ParamSet other = set == ML_DSA_44 ? ML_DSA_65 : ML_DSA_44;
        vm.expectRevert(MLDSAKeyFactory.NotCommitted.selector);
        factory.storeA(other, pkHash, aHat);
        vm.expectRevert(MLDSAKeyFactory.UnsupportedParamSet.selector);
        factory.storeA(ParamSet.wrap(9), pkHash, aHat);
        assertEq(a.code.length, 0, "nothing at the address");

        // The right bytes, from anyone: deployed where registerA would have, same code.
        vm.prank(address(0xBEEF));
        assertEq(factory.storeA(set, pkHash, aHat), a);
        assertEq(a.code, viaRegister, "byte-identical to registerA");
        assertEq(a.code, abi.encodePacked(bytes1(0), aHat), "0x00 || precomputeA(pk)");
        assertEq(uint8(factory.aStatus(set, pkHash)), uint8(MLDSAKeyFactory.AStatus.Stored));
        assertEq(factory.storeA(set, pkHash, wrong), a, "idempotent once stored");
        assertEq(a.code, viaRegister);
        factory.registerA(set, pk); // no-op now
        assertEq(a.code, viaRegister);

        // With T: fast path; identical verdicts to the fallback.
        factory.registerT(set, pk);
        assertTrue(factory.isRegistered(set, pkHash));
        assertTrue(t.code.length != 0);
        assertTrue(factory.verify(set, pkHash, m[1], sig[1]));
        assertEq(fast.verify(set, pk, m[1], sig[1]), slow.verify(set, pk, m[1], sig[1]));
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

    function _gasInterface(ParamSet set) internal {
        string memory name = set == ML_DSA_44 ? "ML-DSA-44" : "ML-DSA-65";
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
