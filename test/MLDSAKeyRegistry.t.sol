// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

import {IMLDSAVerifier, ParamSet, ML_DSA_44, ML_DSA_65, ML_DSA_87} from "../src/IMLDSAVerifier.sol";
import {MLDSAKeyFactory} from "../src/MLDSAKeyFactory.sol";
import {MLDSAVerifier} from "../src/MLDSAVerifier.sol";

import {MLDSAKeyRegistry} from "../src/MLDSAKeyRegistry.sol";

/// Fixtures: test/mldsa-key-registry/gen_fixtures.py (dilithium-py 1.4.0). Key 0 is
/// ML-DSA-44, key 1 ML-DSA-65, key 2 ML-DSA-44; `keyId` passes 0 → 1 → 2. Key 3 is ML-DSA-44,
/// key 4 ML-DSA-87, key 5 ML-DSA-65, key 6 ML-DSA-87; `keyId2` passes 3 → 4 → 5 (into ML-DSA-87
/// and out of it) and `keyId3` starts at key 4 and passes to key 6 (87 → 87). The registry is
/// deployed at the address the fixtures' EIP-712 digests were computed for.
contract MLDSAKeyRegistryTest is Test {
    string internal constant FIXTURES = "test/mldsa-key-registry/fixtures.json";

    /// EIP-7825: the most gas one transaction may use.
    uint256 internal constant CAP = 1 << 24;

    MLDSAKeyRegistry internal registry;
    MLDSAKeyFactory internal factory;
    IMLDSAVerifier internal verifier;
    string internal json;

    address internal registrant;
    bytes32 internal salt;
    bytes32 internal keyId;
    bytes internal message;
    ParamSet[7] internal sets;
    bytes[7] internal pks;
    bytes32 internal keyId2;
    bytes32 internal keyId3;

    function setUp() public {
        json = vm.readFile(FIXTURES);
        vm.chainId(vm.parseJsonUint(json, ".chainId"));

        factory = new MLDSAKeyFactory();
        verifier = new MLDSAVerifier(address(factory));
        address at = vm.parseJsonAddress(json, ".registry");
        deployCodeTo("MLDSAKeyRegistry.sol:MLDSAKeyRegistry", abi.encode(verifier), at);
        registry = MLDSAKeyRegistry(at);

        registrant = vm.parseJsonAddress(json, ".registrant");
        salt = vm.parseJsonBytes32(json, ".salt");
        keyId = vm.parseJsonBytes32(json, ".keyId");
        message = vm.parseJsonBytes(json, ".message");
        keyId2 = vm.parseJsonBytes32(json, ".keyId2");
        keyId3 = vm.parseJsonBytes32(json, ".keyId3");
        for (uint256 i; i < 7; ++i) {
            sets[i] = ParamSet.wrap(uint8(vm.parseJsonUint(json, string.concat(".set", vm.toString(i)))));
            pks[i] = vm.parseJsonBytes(json, string.concat(".pk", vm.toString(i)));
        }
    }

    function _sig(string memory name) internal view returns (bytes memory) {
        return vm.parseJsonBytes(json, string.concat(".", name));
    }

    function _register() internal {
        vm.prank(registrant);
        assertEq(registry.register(salt, sets[0], pks[0]), keyId);
    }

    function test_theDigestsTheFixturesSignedAreTheRegistrysOwn() public view {
        assertEq(
            registry.rotationDigest(keyId, 1, sets[1], keccak256(pks[1])), vm.parseJsonBytes32(json, ".digestRotate1")
        );
        assertEq(
            registry.rotationDigest(keyId, 2, sets[2], keccak256(pks[2])), vm.parseJsonBytes32(json, ".digestRotate2")
        );
        assertEq(registry.keyIdOf(registrant, salt), keyId);
    }

    function test_registerThenVerify() public {
        _register();
        (ParamSet set, bytes memory pk, uint64 version) = registry.getKey(keyId);
        assertEq(ParamSet.unwrap(set), ParamSet.unwrap(sets[0]));
        assertEq(pk, pks[0]);
        assertEq(version, 1);
        assertTrue(registry.verify(keyId, message, _sig("sigMessage0")));
        assertFalse(registry.verify(keyId, message, _sig("sigMessage2")), "another key's signature");
    }

    /// The id keeps its name while the key behind it changes twice, across parameter sets;
    /// each rotation is authorized by the key it replaces, and a replaced key's signatures
    /// stop counting the moment it is replaced.
    function test_rotationChainAcrossParameterSets() public {
        _register();

        vm.expectEmit(address(registry));
        emit MLDSAKeyRegistry.KeyRotated(keyId, 2, sets[1], keccak256(pks[1]));
        registry.rotate(keyId, sets[1], pks[1], _sig("sigRotate1"));
        (ParamSet set, bytes memory pk, uint64 version) = registry.getKey(keyId);
        assertEq(ParamSet.unwrap(set), ParamSet.unwrap(sets[1]));
        assertEq(pk, pks[1]);
        assertEq(version, 2);
        assertFalse(registry.verify(keyId, message, _sig("sigMessage0")), "the replaced key no longer speaks");

        registry.rotate(keyId, sets[2], pks[2], _sig("sigRotate2"));
        (, pk, version) = registry.getKey(keyId);
        assertEq(pk, pks[2]);
        assertEq(version, 3);
        assertTrue(registry.verify(keyId, message, _sig("sigMessage2")));
    }

    /// The signed version makes every rotation signature single-use.
    function test_aRotationSignatureCannotBeReplayed() public {
        _register();
        registry.rotate(keyId, sets[1], pks[1], _sig("sigRotate1"));
        vm.expectRevert(abi.encodeWithSelector(MLDSAKeyRegistry.InvalidRotationSignature.selector, keyId));
        registry.rotate(keyId, sets[1], pks[1], _sig("sigRotate1"));
    }

    /// Only the current key can rotate: key 1's signature means nothing while key 0 holds the id.
    function test_onlyTheCurrentKeyCanRotate() public {
        _register();
        vm.expectRevert(abi.encodeWithSelector(MLDSAKeyRegistry.InvalidRotationSignature.selector, keyId));
        registry.rotate(keyId, sets[2], pks[2], _sig("sigRotate2"));
    }

    /// The signature binds the new key: the same authorization cannot install a different key
    /// or the same key under a different parameter set.
    function test_theSignatureBindsTheNewKey() public {
        _register();
        vm.expectRevert(abi.encodeWithSelector(MLDSAKeyRegistry.InvalidRotationSignature.selector, keyId));
        registry.rotate(keyId, sets[2], pks[2], _sig("sigRotate1"));
        bytes memory tampered = pks[1];
        tampered[100] ^= 0x01;
        vm.expectRevert(abi.encodeWithSelector(MLDSAKeyRegistry.InvalidRotationSignature.selector, keyId));
        registry.rotate(keyId, sets[1], tampered, _sig("sigRotate1"));
    }

    /// The id is bound to its registrant, so nobody can squat an id someone is about to take,
    /// and the registrant holds no power over the id afterwards — only the key does.
    function test_idsBelongToTheirRegistrant() public {
        address other = makeAddr("other");
        vm.prank(other);
        bytes32 otherId = registry.register(salt, sets[0], pks[0]);
        assertTrue(otherId != keyId);
        _register();
        vm.prank(registrant);
        vm.expectRevert(abi.encodeWithSelector(MLDSAKeyRegistry.KeyIdTaken.selector, keyId));
        registry.register(salt, sets[1], pks[1]);
    }

    function test_unknownIds() public {
        assertFalse(registry.verify(keyId, message, _sig("sigMessage0")));
        vm.expectRevert(abi.encodeWithSelector(MLDSAKeyRegistry.UnknownKeyId.selector, keyId));
        registry.getKey(keyId);
        vm.expectRevert(abi.encodeWithSelector(MLDSAKeyRegistry.UnknownKeyId.selector, keyId));
        registry.rotate(keyId, sets[1], pks[1], _sig("sigRotate1"));
    }

    function test_keysMustMatchTheirParameterSet() public {
        vm.startPrank(registrant);
        vm.expectRevert(abi.encodeWithSelector(MLDSAKeyRegistry.WrongPublicKeyLength.selector, sets[1], pks[0].length));
        registry.register(salt, sets[1], pks[0]);
        ParamSet unknown = ParamSet.wrap(7);
        vm.expectRevert(abi.encodeWithSelector(MLDSAKeyRegistry.UnsupportedParamSet.selector, unknown));
        registry.register(salt, unknown, pks[0]);
        vm.stopPrank();
    }

    // ── ML-DSA-87 ────────────────────────────────────────────────────────────

    function _salt(uint256 n) internal pure returns (bytes32) {
        return bytes32(n);
    }

    function test_fixtures87_areTheRegistrysOwn() public view {
        assertEq(ParamSet.unwrap(sets[3]), ParamSet.unwrap(ML_DSA_44));
        assertEq(ParamSet.unwrap(sets[4]), ParamSet.unwrap(ML_DSA_87));
        assertEq(ParamSet.unwrap(sets[5]), ParamSet.unwrap(ML_DSA_65));
        assertEq(ParamSet.unwrap(sets[6]), ParamSet.unwrap(ML_DSA_87));
        assertEq(pks[4].length, 2592);
        assertEq(pks[6].length, 2592);
        assertEq(registry.keyIdOf(registrant, _salt(2)), keyId2);
        assertEq(registry.keyIdOf(registrant, _salt(3)), keyId3);
        assertEq(
            registry.rotationDigest(keyId2, 1, sets[4], keccak256(pks[4])), vm.parseJsonBytes32(json, ".digestRotate21")
        );
        assertEq(
            registry.rotationDigest(keyId2, 2, sets[5], keccak256(pks[5])), vm.parseJsonBytes32(json, ".digestRotate22")
        );
        assertEq(
            registry.rotationDigest(keyId3, 1, sets[6], keccak256(pks[6])), vm.parseJsonBytes32(json, ".digestRotate31")
        );
    }

    /// An ML-DSA-87 key registers directly and speaks for its id.
    function test_register87ThenVerify() public {
        vm.prank(registrant);
        assertEq(registry.register(_salt(3), ML_DSA_87, pks[4]), keyId3);
        (ParamSet set, bytes memory pk, uint64 version) = registry.getKey(keyId3);
        assertEq(ParamSet.unwrap(set), ParamSet.unwrap(ML_DSA_87));
        assertEq(pk, pks[4]);
        assertEq(version, 1);
        assertTrue(registry.verify(keyId3, message, _sig("sigMessage4")));
        assertFalse(registry.verify(keyId3, message, _sig("sigMessage5")), "another key's signature");
        assertFalse(registry.verify(keyId3, abi.encodePacked(message, bytes1(0)), _sig("sigMessage4")));
    }

    /// 44 → 87 → 65: a rotation into ML-DSA-87, authorized by the 44 key, and one out of it,
    /// authorized by the 87 key. Each replaced key stops counting at once.
    function test_rotationChainThrough87() public {
        vm.prank(registrant);
        assertEq(registry.register(_salt(2), sets[3], pks[3]), keyId2);

        vm.expectEmit(address(registry));
        emit MLDSAKeyRegistry.KeyRotated(keyId2, 2, ML_DSA_87, keccak256(pks[4]));
        registry.rotate(keyId2, ML_DSA_87, pks[4], _sig("sigRotate21"));
        (ParamSet set, bytes memory pk, uint64 version) = registry.getKey(keyId2);
        assertEq(ParamSet.unwrap(set), ParamSet.unwrap(ML_DSA_87));
        assertEq(pk, pks[4]);
        assertEq(version, 2);
        assertTrue(registry.verify(keyId2, message, _sig("sigMessage4")));

        // The 87 → 65 authorization cannot install another key under another set.
        vm.expectRevert(abi.encodeWithSelector(MLDSAKeyRegistry.InvalidRotationSignature.selector, keyId2));
        registry.rotate(keyId2, ML_DSA_87, pks[6], _sig("sigRotate22"));

        registry.rotate(keyId2, ML_DSA_65, pks[5], _sig("sigRotate22"));
        (set, pk, version) = registry.getKey(keyId2);
        assertEq(ParamSet.unwrap(set), ParamSet.unwrap(ML_DSA_65));
        assertEq(pk, pks[5]);
        assertEq(version, 3);
        assertFalse(registry.verify(keyId2, message, _sig("sigMessage4")), "the replaced 87 key no longer speaks");
        assertTrue(registry.verify(keyId2, message, _sig("sigMessage5")));

        vm.expectRevert(abi.encodeWithSelector(MLDSAKeyRegistry.InvalidRotationSignature.selector, keyId2));
        registry.rotate(keyId2, ML_DSA_65, pks[5], _sig("sigRotate22"));
    }

    /// An ML-DSA-87 key must be 2,592 bytes; a 44 or 65 key is refused under set 87 and vice versa.
    function test_keysMustMatchTheirParameterSet_87() public {
        vm.startPrank(registrant);
        vm.expectRevert(abi.encodeWithSelector(MLDSAKeyRegistry.WrongPublicKeyLength.selector, ML_DSA_87, 1952));
        registry.register(_salt(3), ML_DSA_87, pks[5]);
        vm.expectRevert(abi.encodeWithSelector(MLDSAKeyRegistry.WrongPublicKeyLength.selector, ML_DSA_65, 2592));
        registry.register(_salt(3), ML_DSA_65, pks[4]);
        vm.expectRevert(abi.encodeWithSelector(MLDSAKeyRegistry.WrongPublicKeyLength.selector, ML_DSA_44, 2592));
        registry.register(_salt(3), ML_DSA_44, pks[4]);
        vm.stopPrank();
        _register();
        vm.expectRevert(abi.encodeWithSelector(MLDSAKeyRegistry.WrongPublicKeyLength.selector, ML_DSA_87, 1952));
        registry.rotate(keyId, ML_DSA_87, pks[5], _sig("sigRotate1"));
    }

    /// The most expensive rotation: an ML-DSA-87 signature checked and an ML-DSA-87 key stored.
    /// Measured as a whole transaction (21,000 + calldata + execution, every account cold), with
    /// the current key not precomputed (full verification) and precomputed (fast path). Both
    /// must fit under the EIP-7825 per-transaction cap.
    function test_gas_rotation87() public {
        uint256 nonce = vm.getNonce(address(registry));
        vm.prank(registrant);
        registry.register(_salt(3), ML_DSA_87, pks[4]);
        address pointer = vm.computeCreateAddress(address(registry), nonce);
        assertEq(pointer.code.length, 2593, "the key's data contract");

        bytes memory sig = _sig("sigRotate31");
        uint256 cd = 21000 + _calldataGas(abi.encodeCall(MLDSAKeyRegistry.rotate, (keyId3, ML_DSA_87, pks[6], sig)));

        uint256 snap = vm.snapshotState();
        uint256 gSlow = _rotateGas(pointer, sig) + cd;
        vm.revertToState(snap);

        factory.registerA(ML_DSA_87, pks[4]);
        factory.registerT(ML_DSA_87, pks[4]);
        assertTrue(factory.isRegistered(ML_DSA_87, keccak256(pks[4])));
        uint256 gFast = _rotateGas(pointer, sig) + cd;

        console.log("ML-DSA-87 -> ML-DSA-87 rotation as a transaction, current key not precomputed:", gSlow);
        console.log("ML-DSA-87 -> ML-DSA-87 rotation as a transaction, current key precomputed:", gFast);
        console.log("headroom under the 2^24 cap (not precomputed):", CAP - gSlow);
        assertLt(gSlow, CAP, "fits one transaction without precomputation");
        assertLt(gFast, gSlow);
    }

    function _rotateGas(address pointer, bytes memory sig) internal returns (uint256 g) {
        bytes32 pkHash = keccak256(pks[4]);
        (address a, address t) = factory.addressesOf(ML_DSA_87, pkHash);
        vm.cool(address(registry));
        vm.cool(address(verifier));
        vm.cool(address(factory));
        vm.cool(pointer);
        vm.cool(a);
        vm.cool(t);
        vm.cool(factory.aPartAddress(ML_DSA_87, pkHash, 1));
        g = gasleft();
        registry.rotate(keyId3, ML_DSA_87, pks[6], sig);
        g -= gasleft();
        (ParamSet set, bytes memory pk, uint64 version) = registry.getKey(keyId3);
        assertEq(ParamSet.unwrap(set), ParamSet.unwrap(ML_DSA_87));
        assertEq(pk, pks[6]);
        assertEq(version, 2);
    }

    function _calldataGas(bytes memory data) internal pure returns (uint256 g) {
        for (uint256 i; i < data.length; ++i) {
            g += data[i] == 0 ? 4 : 16;
        }
    }
}
