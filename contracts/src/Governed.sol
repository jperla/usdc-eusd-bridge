// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// A single governance address, transferred in two steps.
///
/// TWO STEPS BECAUSE THE ONE-STEP MISTAKE IS UNRECOVERABLE AND TOTAL. Escrow
/// governance chooses the verifier; ValidatorRegistry governance enrolls the
/// signing keys a return proof is checked against, so it can forge returns and
/// drain the escrow. Handing either to an address nobody controls -- a typo, a
/// contract that cannot call, the wrong chain's multisig -- cannot be undone.
/// The nominee must prove it can transact before it gets anything.
///
/// A nomination confers NO authority. Until `acceptGovernance` lands, the
/// incumbent still holds every power, and re-nominating replaces the pending
/// nominee (nominating the incumbent cancels an outstanding one).
abstract contract Governed {
    address public governance;

    /// Nominee, not a second governor. Powerless until it accepts.
    address public pendingGovernance;

    event GovernanceNominated(address indexed from, address indexed to);
    event GovernanceTransferred(address indexed from, address indexed to);

    error NotGovernance(address caller, address governance);
    error NotPendingGovernance(address caller, address pendingGovernance);
    error ZeroGovernance();

    modifier onlyGovernance() {
        if (msg.sender != governance) {
            revert NotGovernance(msg.sender, governance);
        }
        _;
    }

    constructor(address initialGovernance) {
        if (initialGovernance == address(0)) revert ZeroGovernance();
        governance = initialGovernance;
        // Emitted so the holder of these powers is traceable from deployment by
        // the same log a monitor already watches for handovers.
        emit GovernanceTransferred(address(0), initialGovernance);
    }

    function transferGovernance(address to) external onlyGovernance {
        if (to == address(0)) revert ZeroGovernance();
        pendingGovernance = to;
        emit GovernanceNominated(msg.sender, to);
    }

    function acceptGovernance() external {
        if (msg.sender != pendingGovernance) {
            revert NotPendingGovernance(msg.sender, pendingGovernance);
        }
        emit GovernanceTransferred(governance, msg.sender);
        governance = msg.sender;
        delete pendingGovernance;
    }
}
