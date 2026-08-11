// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// The set of MobileCoin consensus validator signing keys this bridge will
/// accept, and the quorum rule over them.
///
/// WHY THIS IS GOVERNANCE-MANAGED, STATED PLAINLY.
///
/// MobileCoin binds a validator's signing key to an attested enclave through
/// `BlockMetadataContents.attestation_evidence`. An Ethereum contract cannot
/// check that evidence: doing so means verifying an IAS/DCAP certificate
/// chain, which is far outside any plausible gas budget. It could only *hash*
/// bytes it has no way to interpret.
///
/// So the trust in "these keys are real attested validators" rests here, on
/// governance, in BOTH available proof routes. That is a real limitation and
/// it is the reason this contract exists as a named, auditable component
/// rather than a mapping tucked inside the verifier: whoever controls this
/// registry can mint arbitrary MobileCoin "returns" and drain the escrow.
///
/// Because the trust is identical either way, the cheaper route is preferred
/// -- see `MobileCoinVerifier` -- since paying ~25x more gas to hash evidence
/// nobody can validate buys nothing.
contract ValidatorRegistry {
    /// A key set version. Rotation bumps this.
    ///
    /// NOTE: the escrow's replay set is deliberately NOT keyed on this. A
    /// nullifier scoped to a rotatable value is re-usable by rotating it.
    uint64 public epoch;

    address public governance;

    /// Ed25519 public keys, in compressed 32-byte form.
    mapping(bytes32 => bool) public isValidator;
    bytes32[] private _validators;

    /// Signatures required for a quorum.
    uint8 public threshold;

    /// Timelock on registry changes. Rotating the validator set is equivalent
    /// to being able to forge returns, so it should never be instantaneous.
    uint64 public immutable delay;
    mapping(bytes32 => uint64) public pendingSince;

    event ValidatorProposed(bytes32 indexed key, bool add, uint64 executableAt);
    event ValidatorChanged(bytes32 indexed key, bool added, uint64 epoch);
    event ThresholdChanged(uint8 from, uint8 to);
    event GovernanceTransferred(address indexed from, address indexed to);

    error NotGovernance();
    error AlreadyPresent(bytes32 key);
    error NotPresent(bytes32 key);
    error NotProposed(bytes32 key);
    error TooEarly(uint64 nowTs, uint64 executableAt);
    error BadThreshold(uint8 threshold, uint256 validatorCount);
    error ZeroAddress();

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    constructor(
        address _governance,
        bytes32[] memory initial,
        uint8 _threshold,
        uint64 _delay
    ) {
        if (_governance == address(0)) revert ZeroAddress();
        governance = _governance;
        delay = _delay;
        for (uint256 i = 0; i < initial.length; i++) {
            if (isValidator[initial[i]]) revert AlreadyPresent(initial[i]);
            isValidator[initial[i]] = true;
            _validators.push(initial[i]);
        }
        if (_threshold == 0 || _threshold > initial.length) {
            revert BadThreshold(_threshold, initial.length);
        }
        threshold = _threshold;
    }

    // ------------------------------------------------------------------ views

    function validatorCount() external view returns (uint256) {
        return _validators.length;
    }

    function validatorAt(uint256 i) external view returns (bytes32) {
        return _validators[i];
    }

    function validators() external view returns (bytes32[] memory) {
        return _validators;
    }

    // ------------------------------------------------------------- mutation

    function propose(bytes32 key, bool add) external onlyGovernance {
        if (add && isValidator[key]) revert AlreadyPresent(key);
        if (!add && !isValidator[key]) revert NotPresent(key);
        bytes32 id = keccak256(abi.encode(key, add));
        uint64 at = uint64(block.timestamp) + delay;
        pendingSince[id] = at;
        emit ValidatorProposed(key, add, at);
    }

    function execute(bytes32 key, bool add) external onlyGovernance {
        bytes32 id = keccak256(abi.encode(key, add));
        uint64 at = pendingSince[id];
        if (at == 0) revert NotProposed(key);
        if (uint64(block.timestamp) < at) {
            revert TooEarly(uint64(block.timestamp), at);
        }
        delete pendingSince[id];

        if (add) {
            if (isValidator[key]) revert AlreadyPresent(key);
            isValidator[key] = true;
            _validators.push(key);
        } else {
            if (!isValidator[key]) revert NotPresent(key);
            isValidator[key] = false;
            uint256 n = _validators.length;
            for (uint256 i = 0; i < n; i++) {
                if (_validators[i] == key) {
                    _validators[i] = _validators[n - 1];
                    _validators.pop();
                    break;
                }
            }
            // Removing a validator can strand the threshold above the roster.
            // Clamp rather than revert: leaving the registry unusable is worse
            // than lowering the bar, and governance can raise it again.
            if (threshold > _validators.length) {
                emit ThresholdChanged(threshold, uint8(_validators.length));
                threshold = uint8(_validators.length);
            }
        }
        epoch += 1;
        emit ValidatorChanged(key, add, epoch);
    }

    function setThreshold(uint8 t) external onlyGovernance {
        if (t == 0 || t > _validators.length) {
            revert BadThreshold(t, _validators.length);
        }
        emit ThresholdChanged(threshold, t);
        threshold = t;
    }

    function transferGovernance(address to) external onlyGovernance {
        if (to == address(0)) revert ZeroAddress();
        emit GovernanceTransferred(governance, to);
        governance = to;
    }

    // -------------------------------------------------------------- quorum

    /// True iff `keys` are all registered validators, all distinct, and number
    /// at least `threshold`.
    ///
    /// Distinctness is the whole point: without it one validator's signature
    /// repeated `threshold` times is a "quorum". The caller sorts, and this
    /// checks strict ascending order, which gives distinctness in one pass
    /// without quadratic comparison or scratch storage.
    function isQuorum(bytes32[] calldata keys) external view returns (bool) {
        if (keys.length < threshold) return false;
        bytes32 prev = bytes32(0);
        for (uint256 i = 0; i < keys.length; i++) {
            if (keys[i] <= prev) return false;    // unsorted or duplicate
            if (!isValidator[keys[i]]) return false;
            prev = keys[i];
        }
        return true;
    }
}
