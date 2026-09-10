// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Ed25519} from "./Ed25519.sol";

import {Governed} from "./Governed.sol";

/// Maps MobileCoin block-signing keys to validator ENTITIES, scoped to the
/// block heights each key was valid for, and decides what counts as a quorum.
///
/// WHY THIS IS NOT A FLAT KEY LIST, WHICH IS WHAT IT LOOKED LIKE IT SHOULD BE.
///
/// There are two kinds of key involved and conflating them is a quorum
/// forgery. `BlockMetadata` is signed with the node's configured SCP message
/// key, which is what defines its `NodeID`. `BlockSignature` -- the cheap
/// route, where every validator signs one identical block digest -- is signed
/// with a *separate per-enclave identity key*, created randomly by default and
/// restored from sealing when available. `BlockSignature`'s own verifier
/// trusts the signer embedded in the object.
///
/// So N block signatures are NOT N validators. Without an authenticated
/// mapping from enclave key to entity, one operator running several enclaves
/// -- or one enclave that rotated its key -- satisfies any threshold by
/// itself. That is why quorum here is counted over ENTITIES, why each key
/// carries a validity height range, and why the same entity appearing twice is
/// rejected rather than counted twice.
///
/// WHAT THIS CONTRACT CANNOT DO. It cannot verify attestation. Binding an
/// enclave key to a real attested validator requires DCAP certificate-chain
/// verification, far outside any gas budget. That authentication happens
/// off-chain at enrollment, and this registry records its result. Whoever
/// controls this registry can therefore forge returns and drain the escrow,
/// which is why changes are timelocked and why this is a named component
/// rather than a mapping hidden inside the verifier.
contract ValidatorRegistry is Governed {
    struct KeyRecord {
        /// The validator entity this signing key belongs to. Quorum is counted
        /// over these, never over keys.
        bytes32 entity;
        /// Inclusive first block height this key may sign for.
        uint64 fromHeight;
        /// Exclusive last block height. 0 means open-ended.
        uint64 toHeight;
        bool present;
        bool revoked;
    }

    /// Distinct entities required for a quorum.
    uint8 public threshold;

    /// Timelock on registry changes.
    uint64 public immutable delay;

    mapping(bytes32 => KeyRecord) public keys;      // signing key -> record
    mapping(bytes32 => bool) public isEntity;       // known validator entities
    bytes32[] private _entities;

    /// Proposal presence is an explicit flag rather than a nonzero timestamp.
    /// Using 0 as both "never proposed" and a legitimate `executableAt` makes
    /// enrollment impossible whenever `block.timestamp + delay` is 0, and is
    /// ambiguous even when it is not.
    struct Proposal {
        bool exists;
        uint64 executableAt;
    }

    mapping(bytes32 => Proposal) public proposals;

    /// The height range is in the event because it is part of what the timelock
    /// commits to: a watcher that only saw key and entity could not tell that a
    /// proposal grants signing authority over past blocks.
    event KeyProposed(
        bytes32 indexed key,
        bytes32 indexed entity,
        uint64 fromHeight,
        uint64 toHeight,
        uint64 executableAt
    );
    event KeyEnrolled(bytes32 indexed key, bytes32 indexed entity, uint64 fromHeight, uint64 toHeight);
    event KeyRevoked(bytes32 indexed key, bytes32 indexed entity);
    event ThresholdChanged(uint8 from, uint8 to);
    event ThresholdProposed(uint8 to, uint64 executableAt);

    error KeyAlreadyEnrolled(bytes32 key);
    error KeyNotEnrolled(bytes32 key);
    /// Carries the proposal id, since the id commits to the height range too:
    /// enrolling a proposed key with different heights lands here.
    error NotProposed(bytes32 key, bytes32 proposalId);
    error TooEarly(uint64 nowTs, uint64 executableAt);
    error BadThreshold(uint8 threshold, uint256 entityCount);
    error BadHeightRange(uint64 fromHeight, uint64 toHeight);
    error ZeroEntity();
    error InadmissibleKey(bytes32 key);
    error ThresholdNotProposed(uint8 threshold);

    constructor(address _governance, uint8 _threshold, uint64 _delay)
        Governed(_governance)
    {
        delay = _delay;
        // Threshold is checked against the entity count on every change; at
        // construction the roster is empty, so only zero is rejected here.
        if (_threshold == 0) revert BadThreshold(_threshold, 0);
        threshold = _threshold;
    }

    // ------------------------------------------------------------------ views

    function entityCount() external view returns (uint256) {
        return _entities.length;
    }

    function entityAt(uint256 i) external view returns (bytes32) {
        return _entities[i];
    }

    /// True iff `key` may sign for a block at `height`.
    function keyValidAt(bytes32 key, uint64 height) public view returns (bool) {
        KeyRecord storage r = keys[key];
        if (!r.present || r.revoked) return false;
        if (height < r.fromHeight) return false;
        if (r.toHeight != 0 && height >= r.toHeight) return false;
        return true;
    }

    function entityOf(bytes32 key) external view returns (bytes32) {
        return keys[key].entity;
    }

    // -------------------------------------------------------------- mutation

    /// A proposal is identified by everything it grants, not by the key. So
    /// enrolling a proposed key over a different height range is a different,
    /// unproposed grant, and has to wait out its own delay.
    function _proposalId(
        bytes32 key,
        bytes32 entity,
        uint64 fromHeight,
        uint64 toHeight
    ) private pure returns (bytes32) {
        return keccak256(abi.encode(key, entity, fromHeight, toHeight));
    }

    /// Enrollment is two-step and timelocked. `entity` is the off-chain
    /// attestation result: that this enclave key belongs to that validator.
    function proposeKey(
        bytes32 key,
        bytes32 entity,
        uint64 fromHeight,
        uint64 toHeight
    ) external onlyGovernance {
        if (entity == bytes32(0)) revert ZeroEntity();
        // A small-order key admits universal forgery: with A neutral, [h]A is
        // neutral for every h, so (R = [r]B, s = r) verifies against ANY
        // message. Ed25519.verify reproduces that on purpose, to agree with
        // libsodium and dalek, which makes refusing such keys this contract's
        // job. Checked at proposal AND at enrollment so a key cannot be
        // proposed while admissible and enrolled after a library change.
        if (!Ed25519.isAdmissiblePublicKey(key)) revert InadmissibleKey(key);
        if (keys[key].present) revert KeyAlreadyEnrolled(key);
        if (toHeight != 0 && toHeight <= fromHeight) {
            revert BadHeightRange(fromHeight, toHeight);
        }
        uint64 at = uint64(block.timestamp) + delay;
        proposals[_proposalId(key, entity, fromHeight, toHeight)] =
            Proposal({exists: true, executableAt: at});
        emit KeyProposed(key, entity, fromHeight, toHeight, at);
    }

    function enrollKey(
        bytes32 key,
        bytes32 entity,
        uint64 fromHeight,
        uint64 toHeight
    ) external onlyGovernance {
        bytes32 id = _proposalId(key, entity, fromHeight, toHeight);
        Proposal memory p = proposals[id];
        if (!p.exists) revert NotProposed(key, id);
        if (uint64(block.timestamp) < p.executableAt) {
            revert TooEarly(uint64(block.timestamp), p.executableAt);
        }
        delete proposals[id];
        if (keys[key].present) revert KeyAlreadyEnrolled(key);
        if (!Ed25519.isAdmissiblePublicKey(key)) revert InadmissibleKey(key);

        keys[key] = KeyRecord({
            entity: entity,
            fromHeight: fromHeight,
            toHeight: toHeight,
            present: true,
            revoked: false
        });
        if (!isEntity[entity]) {
            isEntity[entity] = true;
            _entities.push(entity);
        }
        emit KeyEnrolled(key, entity, fromHeight, toHeight);
    }

    /// Revocation is immediate and NOT timelocked: a key believed compromised
    /// must be removable faster than an attacker can use it. The asymmetry is
    /// deliberate -- adding authority is slow, removing it is fast.
    ///
    /// The entity is intentionally left in `_entities`. It is a denominator for
    /// the threshold check, not a claim that the entity currently has a usable
    /// key, and removing it would silently lower the bar for everyone else.
    function revokeKey(bytes32 key) external onlyGovernance {
        KeyRecord storage r = keys[key];
        if (!r.present) revert KeyNotEnrolled(key);
        r.revoked = true;
        emit KeyRevoked(key, r.entity);
    }

    /// Raising the threshold only tightens the quorum, so it takes effect at
    /// once. LOWERING it weakens the quorum exactly as enrolling a key does,
    /// and an immediate decrease would let governance step around the
    /// enrollment timelock entirely: drop the threshold to 1, sign with one
    /// key, restore it. So a decrease is proposed and executed like a key.
    function setThreshold(uint8 t) external onlyGovernance {
        if (t == 0 || t > _entities.length) {
            revert BadThreshold(t, _entities.length);
        }
        if (t < threshold) {
            bytes32 id = keccak256(abi.encode("threshold", t));
            Proposal memory p = proposals[id];
            if (!p.exists) revert ThresholdNotProposed(t);
            if (uint64(block.timestamp) < p.executableAt) {
                revert TooEarly(uint64(block.timestamp), p.executableAt);
            }
            delete proposals[id];
        }
        emit ThresholdChanged(threshold, t);
        threshold = t;
    }

    function proposeThreshold(uint8 t) external onlyGovernance {
        if (t == 0 || t > _entities.length) {
            revert BadThreshold(t, _entities.length);
        }
        bytes32 id = keccak256(abi.encode("threshold", t));
        uint64 at = uint64(block.timestamp) + delay;
        proposals[id] = Proposal({exists: true, executableAt: at});
        emit ThresholdProposed(t, at);
    }

    // ---------------------------------------------------------------- quorum

    /// True iff `signingKeys` are all valid at `height` and belong to at least
    /// `threshold` DISTINCT entities.
    ///
    /// The caller must pass keys ordered by strictly ascending ENTITY. That
    /// single check gives entity-distinctness in one pass: sorting by key
    /// would not, because two different keys can map to the same entity, which
    /// is exactly the case this contract exists to reject.
    function isQuorum(bytes32[] calldata signingKeys, uint64 height)
        external
        view
        returns (bool)
    {
        if (signingKeys.length < threshold) return false;
        bytes32 prevEntity = bytes32(0);
        for (uint256 i = 0; i < signingKeys.length; i++) {
            if (!keyValidAt(signingKeys[i], height)) return false;
            bytes32 e = keys[signingKeys[i]].entity;
            // Strictly ascending: rejects both an unsorted list and any repeat
            // of an entity, however many distinct keys it presents.
            if (e <= prevEntity) return false;
            prevEntity = e;
        }
        return true;
    }
}
