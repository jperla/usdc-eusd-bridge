//! The decision: a value the caller acts on, not a message the caller reads.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::amount::{Amount, Bytes32};
use crate::bound::{exposure_bound, irrevocable_value, ReleaseRate};
use crate::ledger::Ledger;
use crate::matcher::{Discrepancy, MatchPolicy, MatchReport, Severity};

/// The four inputs to the bound, plus the horizon used to derive `P`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundParams {
    /// `B` -- USDC currently held by the escrow.
    pub remaining_balance: Amount,
    /// `rho` -- the configured release rate ceiling.
    pub rho: ReleaseRate,
    /// `delta_eff` -- detection to freeze-in-force.
    pub delta_eff: Duration,
    /// How long value must be out before it counts toward `P`.
    pub recall_horizon: Duration,
}

/// Everything the auditor was configured with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPolicy {
    /// Matching tolerances.
    pub matching: MatchPolicy,
    /// Bound inputs.
    pub bound: BoundParams,
    /// Whether an [`Severity::Anomaly`]-only finding freezes.
    ///
    /// Defaults to `true`. The alternative is a state in which the auditor has
    /// concluded that releases are being authorised by something other than
    /// the deposit log, and responds by writing it down.
    pub freeze_on_anomaly: bool,
}

/// Why the escrow is being frozen.
///
/// Ordered by how much it should alarm the reader; [`FreezeReason::worst_of`]
/// relies on the declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FreezeReason {
    /// Realised loss already exceeds what the bound said was reachable, so at
    /// least one of `rho`, `delta_eff` or `P` is not describing reality. Ranked
    /// above the individual findings: a wrong model is worse news than a known
    /// hole, because it means the size of the hole is also unknown.
    ExposureBoundViolated,
    /// eUSD exists that no deposit backs.
    UnbackedRelease,
    /// One deposit was released against twice.
    DoubleRelease,
    /// A release exceeded its deposit.
    OverRelease,
    /// A release went to the wrong destination.
    DestinationMismatch,
    /// A release predates the deposit it claims.
    ReleasePrecedesDeposit,
}

impl FreezeReason {
    fn of(d: &Discrepancy) -> FreezeReason {
        match d {
            Discrepancy::UnbackedRelease { .. } => FreezeReason::UnbackedRelease,
            Discrepancy::DoubleRelease { .. } => FreezeReason::DoubleRelease,
            Discrepancy::OverRelease { .. } => FreezeReason::OverRelease,
            Discrepancy::DestinationMismatch { .. } => FreezeReason::DestinationMismatch,
            Discrepancy::ReleasePrecedesDeposit { .. } => {
                FreezeReason::ReleasePrecedesDeposit
            }
        }
    }

    /// The most alarming reason among some findings.
    pub fn worst_of(ds: &[Discrepancy]) -> Option<FreezeReason> {
        ds.iter().map(FreezeReason::of).min()
    }

    /// Stable slug, safe to put in on-chain calldata.
    pub fn slug(self) -> &'static str {
        match self {
            FreezeReason::ExposureBoundViolated => "exposure-bound-violated",
            FreezeReason::UnbackedRelease => "unbacked-release",
            FreezeReason::DoubleRelease => "double-release",
            FreezeReason::OverRelease => "over-release",
            FreezeReason::DestinationMismatch => "destination-mismatch",
            FreezeReason::ReleasePrecedesDeposit => "release-precedes-deposit",
        }
    }
}

impl fmt::Display for FreezeReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// What the decision was made on. Carried by value so the caller holds the
/// case, not a pointer into state that keeps moving.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Every finding.
    pub report: MatchReport,
    /// Unbacked value the findings account for.
    pub observed_exposure: Amount,
    /// `P` at `observed_at`.
    pub p_irrevocable: Amount,
    /// `min(B, P + rho * delta_eff)`.
    pub bound: Amount,
    /// The bound's inputs, recorded so the number can be recomputed later
    /// without trusting this run.
    pub params: BoundParams,
    /// Unix seconds the audit ran at.
    pub observed_at: u64,
}

/// Counts from a clean run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditStats {
    /// Releases matched one-to-one.
    pub matched: usize,
    /// Releases examined.
    pub releases_examined: usize,
    /// Deposits examined.
    pub deposits_examined: usize,
    /// Deposits waiting past the policy's patience. A liveness problem, not a
    /// solvency one -- see [`crate::StaleDeposit`].
    pub stale_deposits: usize,
    /// The bound as it stands with no findings. Reported on the clean path
    /// too, because the number worth watching is the one *before* something
    /// goes wrong.
    pub bound: Amount,
}

/// The auditor's output.
///
/// `#[must_use]` on the type, not just on [`audit`]: the failure this crate
/// exists to prevent is a mismatch that gets noticed and not acted on, and a
/// value that is awkward to discard is a materially better defence against
/// that than a log line nobody reads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[must_use]
pub enum FreezeDecision {
    /// Nothing found. Keep going.
    Continue {
        /// What was checked.
        stats: AuditStats,
    },
    /// Freeze the escrow.
    Freeze {
        /// The most alarming reason found.
        reason: FreezeReason,
        /// The full case.
        evidence: Box<Evidence>,
    },
}

impl FreezeDecision {
    /// `true` if this decision demands a freeze.
    pub fn is_freeze(&self) -> bool {
        matches!(self, FreezeDecision::Freeze { .. })
    }

    /// The reason, if frozen.
    pub fn reason(&self) -> Option<FreezeReason> {
        match self {
            FreezeDecision::Freeze { reason, .. } => Some(*reason),
            FreezeDecision::Continue { .. } => None,
        }
    }

    /// The string to pass to `Escrow.freeze(string)`.
    ///
    /// Deterministic and length-bounded. It goes on-chain as calldata, so it
    /// names the finding and points at the first offending release rather than
    /// trying to carry the case; the case is [`Evidence`], which is far too
    /// large to pay gas for and does not need to be on-chain to be
    /// authoritative.
    pub fn escrow_reason(&self) -> Option<String> {
        let FreezeDecision::Freeze { reason, evidence } = self else {
            return None;
        };
        let first = evidence
            .report
            .discrepancies
            .first()
            .map(|d| d.release_id())
            .unwrap_or(Bytes32([0u8; 32]));
        // First 8 bytes of the output public key: enough to locate the release
        // in the MobileCoin ledger, short enough to keep this well under the
        // 200-byte cap asserted in the tests.
        let s = format!(
            "auditor/{} n={} rel=0x{} exp={} bound={}",
            reason.slug(),
            evidence.report.discrepancies.len(),
            hex::encode(&first.0[..8]),
            evidence.observed_exposure,
            evidence.bound,
        );
        Some(s)
    }
}

/// Reconcile, bound the exposure, and decide.
#[must_use]
pub fn audit(ledger: &Ledger, policy: &AuditPolicy, now: u64) -> FreezeDecision {
    let report = ledger.reconcile(&policy.matching, now);

    // `P` is derived from the findings, not from the ledger at large: it is the
    // unbacked value that is already gone. Each finding is dated by the
    // MobileCoin block its release landed in, which is the moment the value
    // started being spendable by whoever received it.
    let by_id: std::collections::BTreeMap<Bytes32, u64> = ledger
        .releases_in_order()
        .into_iter()
        .map(|r| (r.release_id, r.timestamp))
        .collect();
    let dated: Vec<(Amount, u64)> = report
        .discrepancies
        .iter()
        .filter(|d| !d.exposure().is_zero())
        .map(|d| {
            let ts = by_id.get(&d.release_id()).copied().unwrap_or(now);
            (d.exposure(), ts)
        })
        .collect();

    let p_irrevocable = irrevocable_value(dated, now, policy.bound.recall_horizon);
    let bound = exposure_bound(
        policy.bound.remaining_balance,
        p_irrevocable,
        policy.bound.rho,
        policy.bound.delta_eff,
    );

    let observed_exposure = report.exposure();

    let must_freeze = match report.worst_severity() {
        None => false,
        Some(Severity::Loss) => true,
        Some(Severity::Anomaly) => policy.freeze_on_anomaly,
    };

    if !must_freeze {
        return FreezeDecision::Continue {
            stats: AuditStats {
                matched: report.matched,
                releases_examined: report.releases_examined,
                deposits_examined: report.deposits_examined,
                stale_deposits: report.stale_deposits.len(),
                bound,
            },
        };
    }

    // The observed loss is measured from two chains' records; the bound is
    // computed from declared policy parameters. They share no inputs, so the
    // comparison is a real test of the parameters rather than of this
    // function's own arithmetic. Loss beyond the bound means the rate limit or
    // the delay estimate is wrong, and that outranks the individual finding.
    let reason = if observed_exposure > bound {
        FreezeReason::ExposureBoundViolated
    } else {
        FreezeReason::worst_of(&report.discrepancies)
            .expect("must_freeze implies at least one discrepancy")
    };

    FreezeDecision::Freeze {
        reason,
        evidence: Box::new(Evidence {
            report,
            observed_exposure,
            p_irrevocable,
            bound,
            params: policy.bound,
            observed_at: now,
        }),
    }
}
