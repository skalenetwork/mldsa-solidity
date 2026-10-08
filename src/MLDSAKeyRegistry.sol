// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {IMLDSAVerifier, ParamSet, ML_DSA_44, ML_DSA_65, ML_DSA_87} from "./IMLDSAVerifier.sol";
import {MLDSAPublicKeys} from "./MLDSAPublicKeys.sol";

/// @title MLDSAKeyRegistry — stable key ids for ML-DSA keys, rotated by the key itself
/// @notice A key id names an identity, not a key: it stays the same while the ML-DSA public
///         key behind it is replaced. Whoever registers an id chooses its first key; from then
///         on only the current key can replace itself, by signing a `RotateKey` message. The
///         registrant keeps no power over the id after registration.
///
///         ML-DSA keeps no per-signature state, so unlike a stateful hash-based key there is
///         no leaf to spend and no exhaustion to plan around: a key signs as often as it
///         needs to, and rotation is a security decision (suspected compromise, routine
///         renewal, moving to a stronger parameter set), never a forced one.
/// @dev    Verification goes through one `IMLDSAVerifier`, fixed at construction and never
///         changed (see that interface's integration rule). Public keys are kept as contract
///         code via `MLDSAPublicKeys`; the registry stores only the pointer.
contract MLDSAKeyRegistry is EIP712 {
    /// @notice The key currently behind an id. `version` counts registrations and rotations:
    ///         1 after `register`, +1 per `rotate`; 0 means the id was never registered.
    struct Key {
        ParamSet paramSet;
        address publicKey;
        uint64 version;
    }

    /// @notice What the current key signs to hand the id to a new key. `version` is the
    ///         version being replaced, so a rotation signature is valid exactly once.
    bytes32 public constant ROTATE_KEY_TYPEHASH =
        keccak256("RotateKey(bytes32 keyId,uint64 version,uint8 newParamSet,bytes32 newPublicKeyHash)");

    /// @notice The verifier every signature in this registry is checked by. Immutable.
    IMLDSAVerifier public immutable VERIFIER;

    mapping(bytes32 keyId => Key) private _keys;

    event KeyRegistered(bytes32 indexed keyId, address indexed registrant, ParamSet paramSet, bytes32 publicKeyHash);
    event KeyRotated(bytes32 indexed keyId, uint64 version, ParamSet paramSet, bytes32 publicKeyHash);

    error KeyIdTaken(bytes32 keyId);
    error UnknownKeyId(bytes32 keyId);
    error UnsupportedParamSet(ParamSet paramSet);
    error WrongPublicKeyLength(ParamSet paramSet, uint256 length);
    error InvalidRotationSignature(bytes32 keyId);

    constructor(IMLDSAVerifier verifier) EIP712("MLDSAKeyRegistry", "1") {
        VERIFIER = verifier;
    }

    /// @notice The id `registrant` gets for `salt`. Binding the id to the caller means nobody
    ///         can take an id someone else is about to register.
    function keyIdOf(address registrant, bytes32 salt) public pure returns (bytes32) {
        return keccak256(abi.encode(registrant, salt));
    }

    /// @notice Create the id `keyIdOf(msg.sender, salt)` with `publicKey` as its first key.
    /// @dev    No proof of possession is asked for: the id is the registrant's own, and a key
    ///         they cannot sign with only means they cannot rotate it.
    function register(bytes32 salt, ParamSet paramSet, bytes calldata publicKey) external returns (bytes32 keyId) {
        keyId = keyIdOf(msg.sender, salt);
        if (_keys[keyId].version != 0) revert KeyIdTaken(keyId);
        _checkKey(paramSet, publicKey);
        _keys[keyId] = Key({paramSet: paramSet, publicKey: MLDSAPublicKeys.store(publicKey), version: 1});
        emit KeyRegistered(keyId, msg.sender, paramSet, keccak256(publicKey));
    }

    /// @notice Replace the key behind `keyId` with `newPublicKey`, authorized by `signature`
    ///         from the CURRENT key over `rotationDigest(keyId, version, newParamSet,
    ///         keccak256(newPublicKey))`. Anyone may submit it; the signature is the authority.
    /// @dev    Only the current key signs. Asking the new key for a proof of possession as well
    ///         would cost a second ML-DSA verification (up to ~9M gas for an unregistered
    ///         ML-DSA-65 key, ~14M for ML-DSA-87), pushing a rotation past the EIP-7825
    ///         per-transaction cap, and it protects nobody but the rotator, who chose the new
    ///         key. The worst case that remains, an unregistered ML-DSA-87 key rotating to
    ///         another ML-DSA-87 key, stays under the cap (see the tests for the figure).
    function rotate(bytes32 keyId, ParamSet newParamSet, bytes calldata newPublicKey, bytes calldata signature)
        external
    {
        Key memory current = _keys[keyId];
        if (current.version == 0) revert UnknownKeyId(keyId);
        _checkKey(newParamSet, newPublicKey);

        bytes32 digest = rotationDigest(keyId, current.version, newParamSet, keccak256(newPublicKey));
        if (!VERIFIER.verify(current.paramSet, MLDSAPublicKeys.load(current.publicKey), abi.encode(digest), signature))
        {
            revert InvalidRotationSignature(keyId);
        }

        uint64 version = current.version + 1;
        _keys[keyId] = Key({paramSet: newParamSet, publicKey: MLDSAPublicKeys.store(newPublicKey), version: version});
        emit KeyRotated(keyId, version, newParamSet, keccak256(newPublicKey));
    }

    /// @notice Whether `signature` is a valid signature of `message` by the key CURRENTLY behind
    ///         `keyId`. False, never a revert, for an unknown id or any invalid signature. A
    ///         signature by a key that has since been rotated away is no longer accepted.
    function verify(bytes32 keyId, bytes calldata message, bytes calldata signature) external view returns (bool) {
        Key memory current = _keys[keyId];
        if (current.version == 0) return false;
        return VERIFIER.verify(current.paramSet, MLDSAPublicKeys.load(current.publicKey), message, signature);
    }

    /// @notice The key behind `keyId`. Reverts for an id that was never registered.
    function getKey(bytes32 keyId) external view returns (ParamSet paramSet, bytes memory publicKey, uint64 version) {
        Key memory current = _keys[keyId];
        if (current.version == 0) revert UnknownKeyId(keyId);
        return (current.paramSet, MLDSAPublicKeys.load(current.publicKey), current.version);
    }

    /// @notice The EIP-712 digest the current key signs to rotate `keyId` away from `version`.
    function rotationDigest(bytes32 keyId, uint64 version, ParamSet newParamSet, bytes32 newPublicKeyHash)
        public
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(ROTATE_KEY_TYPEHASH, keyId, version, ParamSet.unwrap(newParamSet), newPublicKeyHash))
        );
    }

    function _checkKey(ParamSet paramSet, bytes calldata publicKey) private view {
        if (!VERIFIER.supportsParamSet(paramSet)) revert UnsupportedParamSet(paramSet);
        uint256 expected =
            paramSet == ML_DSA_44 ? 1312 : paramSet == ML_DSA_65 ? 1952 : paramSet == ML_DSA_87 ? 2592 : 0;
        if (publicKey.length != expected) revert WrongPublicKeyLength(paramSet, publicKey.length);
    }
}
