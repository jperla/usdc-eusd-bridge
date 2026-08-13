// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IMobileCoinVerifier, VerifiedReturn} from "./IMobileCoinVerifier.sol";
import {Governed} from "./Governed.sol";

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount)
        external
        returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// USDC custody for the USDC <-> eUSD bridge.
///
/// Two legs, and they are NOT symmetric:
///
///   Deposit leg  -- a user deposits USDC here. Operators watch this contract,
///                   each through its own Ethereum node, and release eUSD on
///                   MobileCoin. Ethereum cannot compel that release and this
///                   contract does not pretend to: the deposit leg is
///                   ATTESTED, capped and audited, not trustless.
///
///   Return leg   -- a user sends eUSD back to the bridge's MobileCoin return
///                   address `R`. Anyone may relay the proof. This contract
///                   verifies it cryptographically and pays USDC out.
///
/// The asymmetry is structural: Ethereum can verify MobileCoin, MobileCoin
/// cannot verify Ethereum.
contract Escrow is Governed {
    // ------------------------------------------------------------------ types

    struct Deposit {
        address depositor;
        uint256 amount;
        bytes32 mobDestination;
        uint64 timestamp;
    }

    // ------------------------------------------------------------- immutables

    IERC20 public immutable usdc;

    /// MobileCoin token id this bridge accepts on the return leg.
    uint64 public immutable eusdTokenId;

    /// USDC has 6 decimals and eUSD amounts are u64 base units. If the two
    /// ever differ this is the single place the conversion lives.
    uint256 public immutable conversionNumerator;
    uint256 public immutable conversionDenominator;

    // --------------------------------------------------------------- storage

    IMobileCoinVerifier public verifier;

    address public auditor;

    /// Releases are blocked while frozen. Deposits are NOT: freezing the
    /// deposit path would strand users mid-flow without reducing exposure,
    /// because exposure is created by RELEASES, not deposits.
    bool public frozen;

    /// Ceiling on USDC held. Caps the theft surface at the float, which is the
    /// quantity the whole risk model is denominated in.
    uint256 public depositCap;

    uint256 public nextDepositId;
    mapping(uint256 => Deposit) public deposits;

    /// The replay set, keyed on the MobileCoin OUTPUT PUBLIC KEY.
    ///
    /// Keyed on the output rather than on a claim id, an epoch, or a key-set
    /// version, so that rotating any of those cannot re-open a spent claim.
    /// `ClaimAcceptance.tla` model-checks exactly this: a nullifier scoped to
    /// an epoch is re-usable across epochs.
    mapping(bytes32 => bool) public redeemed;

    uint256 public totalDeposited;
    uint256 public totalReleased;

    /// Reentrancy guard. USDC is a well-behaved token today, but the release
    /// path pays an address derived from attacker-influenced memo bytes, so
    /// the contract must not depend on the callee's behaviour.
    uint256 private _entered;

    // ---------------------------------------------------------------- events

    event Deposited(
        uint256 indexed depositId,
        address indexed depositor,
        uint256 amount,
        bytes32 indexed mobDestination
    );
    event Released(
        bytes32 indexed outputPublicKey,
        address indexed beneficiary,
        uint256 usdcAmount,
        uint64 mobBlockIndex
    );
    event Frozen(address indexed by, string reason);
    event Unfrozen(address indexed by);
    event VerifierChanged(address indexed from, address indexed to);
    event DepositCapChanged(uint256 from, uint256 to);
    event AuditorChanged(address indexed from, address indexed to);

    // ---------------------------------------------------------------- errors
    //
    // One selector per failure SITE, not per failure shape: the first thing an
    // auditor has from a reverted trace is four bytes, and a shared
    // `ZeroAddress()` across config, deposit and payout would make those four
    // bytes say nothing about which of them happened.

    error NotAuditorOrGovernance(address caller, address auditor, address governance);
    error IsFrozen();
    error ZeroAmount();
    error ZeroPayout(uint64 mobAmount);
    error ZeroUsdc();
    error ZeroVerifier();
    error ZeroDestination();
    error ZeroBeneficiary();
    error CapExceeded(uint256 attempted, uint256 cap);
    error AlreadyRedeemed(bytes32 outputPublicKey);
    error WrongToken(uint64 got, uint64 want);
    error TransferFailed(bytes reason);
    error Reentrancy();
    error InsufficientEscrow(uint256 need, uint256 have);

    // ------------------------------------------------------------- modifiers

    modifier nonReentrant() {
        if (_entered == 1) revert Reentrancy();
        _entered = 1;
        _;
        _entered = 0;
    }

    // ----------------------------------------------------------- constructor

    constructor(
        IERC20 _usdc,
        IMobileCoinVerifier _verifier,
        uint64 _eusdTokenId,
        uint256 _depositCap,
        address _governance,
        address _auditor
    ) Governed(_governance) {
        if (address(_usdc) == address(0)) revert ZeroUsdc();
        if (address(_verifier) == address(0)) revert ZeroVerifier();
        usdc = _usdc;
        verifier = _verifier;
        eusdTokenId = _eusdTokenId;
        depositCap = _depositCap;
        auditor = _auditor;
        // 1:1 today. Present as state so a future re-denomination is a
        // deployment parameter and not a code change under time pressure.
        conversionNumerator = 1;
        conversionDenominator = 1;
    }

    // ------------------------------------------------------------ deposit leg

    /// Deposit USDC and name a MobileCoin destination.
    ///
    /// `mobDestination` is opaque to this contract -- it is carried in the
    /// event for the operators, who are the ones that can act on it. Emitting
    /// it rather than storing intent on-chain keeps the contract from implying
    /// a guarantee it cannot enforce.
    function deposit(uint256 amount, bytes32 mobDestination)
        external
        nonReentrant
        returns (uint256 depositId)
    {
        if (amount == 0) revert ZeroAmount();
        if (mobDestination == bytes32(0)) revert ZeroDestination();

        uint256 attempted = outstanding() + amount;
        if (attempted > depositCap) revert CapExceeded(attempted, depositCap);

        depositId = nextDepositId++;
        deposits[depositId] = Deposit({
            depositor: msg.sender,
            amount: amount,
            mobDestination: mobDestination,
            timestamp: uint64(block.timestamp)
        });
        totalDeposited += amount;

        // Interaction last.
        _move(
            abi.encodeCall(
                IERC20.transferFrom, (msg.sender, address(this), amount)
            )
        );

        emit Deposited(depositId, msg.sender, amount, mobDestination);
    }

    // ------------------------------------------------------------- return leg

    /// Redeem a MobileCoin return for USDC. Permissionless.
    ///
    /// Permissionless is safe *because* the beneficiary comes from the proof.
    /// A relayer only carries bytes; it cannot redirect the payment. Paying
    /// `msg.sender` here would let any watcher of the mempool take someone
    /// else's redemption, which is the defect `ClaimAcceptance.tla` exists to
    /// rule out.
    function release(bytes calldata proof)
        external
        nonReentrant
        returns (address beneficiary, uint256 usdcAmount)
    {
        if (frozen) revert IsFrozen();

        // --- checks ---
        VerifiedReturn memory r = verifier.verifyReturn(proof);

        if (r.tokenId != eusdTokenId) {
            revert WrongToken(r.tokenId, eusdTokenId);
        }
        if (redeemed[r.outputPublicKey]) {
            revert AlreadyRedeemed(r.outputPublicKey);
        }
        if (r.beneficiary == address(0)) revert ZeroBeneficiary();

        usdcAmount =
            (uint256(r.amount) * conversionNumerator) / conversionDenominator;
        // Also the r.amount == 0 case; the error carries the pre-conversion
        // amount so a dust return is distinguishable from an empty one.
        if (usdcAmount == 0) revert ZeroPayout(r.amount);

        uint256 have = usdc.balanceOf(address(this));
        if (usdcAmount > have) revert InsufficientEscrow(usdcAmount, have);

        // --- effects, BEFORE the transfer ---
        redeemed[r.outputPublicKey] = true;
        totalReleased += usdcAmount;
        beneficiary = r.beneficiary;

        // --- interaction ---
        _move(abi.encodeCall(IERC20.transfer, (beneficiary, usdcAmount)));

        emit Released(r.outputPublicKey, beneficiary, usdcAmount, r.blockIndex);
    }

    // ------------------------------------------------------------ freeze path

    /// The auditor's response, not a dashboard warning.
    ///
    /// A pause here bounds only USDC leaving THIS contract. It cannot stop a
    /// compromised operator quorum from spending eUSD on MobileCoin -- that
    /// requires the composite spend key's gate cohort, which lives on the
    /// MobileCoin side. Stated here so the limit is visible at the point
    /// someone would otherwise assume otherwise.
    function freeze(string calldata reason) external {
        if (msg.sender != auditor && msg.sender != governance) {
            revert NotAuditorOrGovernance(msg.sender, auditor, governance);
        }
        frozen = true;
        emit Frozen(msg.sender, reason);
    }

    /// Deliberately governance-only: whoever can unfreeze can undo the
    /// auditor, so it must be the slower, more distributed key.
    function unfreeze() external onlyGovernance {
        frozen = false;
        emit Unfrozen(msg.sender);
    }

    // ------------------------------------------------------------- governance

    function setVerifier(IMobileCoinVerifier v) external onlyGovernance {
        if (address(v) == address(0)) revert ZeroVerifier();
        emit VerifierChanged(address(verifier), address(v));
        verifier = v;
    }

    function setDepositCap(uint256 cap) external onlyGovernance {
        emit DepositCapChanged(depositCap, cap);
        depositCap = cap;
    }

    function setAuditor(address a) external onlyGovernance {
        emit AuditorChanged(auditor, a);
        auditor = a;
    }

    // ----------------------------------------------------------------- views

    /// USDC currently backing outstanding eUSD, by this contract's accounting.
    ///
    /// Saturates at zero rather than subtracting. Releases are NOT bounded by
    /// deposits: the float can be seeded directly, and eUSD issued against an
    /// earlier escrow can be returned here. A plain subtraction underflows the
    /// moment cumulative releases pass cumulative deposits, which panics this
    /// view AND the cap check in `deposit`, bricking the deposit leg until
    /// deposits catch up.
    function outstanding() public view returns (uint256) {
        return totalDeposited > totalReleased
            ? totalDeposited - totalReleased
            : 0;
    }

    // --------------------------------------------------------------- internal

    /// Move USDC, treating a `false` return as a failure.
    ///
    /// USDC returns a bool; some tokens return nothing. Accept both, reject an
    /// explicit false. Whatever the token said -- its revert reason, or the
    /// `false` -- is carried into `TransferFailed`: without it, "allowance too
    /// low" and "recipient blacklisted" are the same four bytes to whoever is
    /// on call at the time.
    function _move(bytes memory call) private {
        (bool ok, bytes memory data) = address(usdc).call(call);
        if (!ok || (data.length > 0 && !abi.decode(data, (bool)))) {
            revert TransferFailed(data);
        }
    }
}
