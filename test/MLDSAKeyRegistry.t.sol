// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {IMLDSAVerifier, ParamSet} from "../src/IMLDSAVerifier.sol";
import {MLDSAKeyFactory} from "../src/MLDSAKeyFactory.sol";
import {MLDSAVerifier} from "../src/MLDSAVerifier.sol";

import {MLDSAKeyRegistry} from "../src/MLDSAKeyRegistry.sol";

/// Fixtures: test/mldsa-key-registry/gen_fixtures.py (dilithium-py 1.4.0). Key 0 is
/// ML-DSA-44, key 1 ML-DSA-65, key 2 ML-DSA-44; the id passes 0 → 1 → 2. The registry is
/// deployed at the address the fixtures' EIP-712 digests were computed for.
contract MLDSAKeyRegistryTest is Test {
    string internal constant FIXTURES = "test/mldsa-key-registry/fixtures.json";

    MLDSAKeyRegistry internal registry;
    string internal json;

    address internal registrant;
    bytes32 internal salt;
    bytes32 internal keyId;
    bytes internal message;
    ParamSet[3] internal sets;
    bytes[3] internal pks;

    function setUp() public {
        json = vm.readFile(FIXTURES);
        vm.chainId(vm.parseJsonUint(json, ".chainId"));

        IMLDSAVerifier verifier = new MLDSAVerifier(address(new MLDSAKeyFactory()));
        address at = vm.parseJsonAddress(json, ".registry");
        deployCodeTo("MLDSAKeyRegistry.sol:MLDSAKeyRegistry", abi.encode(verifier), at);
        registry = MLDSAKeyRegistry(at);

        registrant = vm.parseJsonAddress(json, ".registrant");
        salt = vm.parseJsonBytes32(json, ".salt");
        keyId = vm.parseJsonBytes32(json, ".keyId");
        message = vm.parseJsonBytes(json, ".message");
        for (uint256 i; i < 3; ++i) {
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
            registry.rotationDigest(keyId, 1, sets[1], keccak256(pks[1])),
            vm.parseJsonBytes32(json, ".digestRotate1")
        );
        assertEq(
            registry.rotationDigest(keyId, 2, sets[2], keccak256(pks[2])),
            vm.parseJsonBytes32(json, ".digestRotate2")
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
}
