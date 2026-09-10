//! One-to-one matching of releases against deposits.
//!
//! Matching is on the *claimed deposit id*, not on a heuristic pairing of
//! `(destination, amount)`. Heuristic pairing is ambiguous the moment two
//! identical deposits exist, and ambiguity is precisely where a thief hides:
//! given two 50k deposits to the same destination and three 50k releases, a
//! greedy matcher can be steered into reporting one anomaly instead of one
//! theft. Requiring the operators to name the deposit makes the pairing their
//! assertion, and an assertion can be contradicted by evidence.
//!
//! The rule is strict one-to-one -- one release discharges one deposit,
//! entirely. Partial and split releases are not permitted, not because they
//! are hard to account for but because permitting them turns "two releases
//! against one deposit" from a bright line into a running-sum question, and a
//! running sum has no moment at which it is definitely wrong.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::amount::{Amount, Bytes32};
use crate::ledger::{DepositId, Ledger};

/// How bad a finding is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// Value is or may be gone. Always freezes.
    Loss,
    /// The invariant held on value but the process did not. Freezes under the
    /// default policy: a release that could not have been justified when it
    /// was made is a control failure, and control failures precede losses.
    Anomaly,
}

/// A way the release stream fails to correspond to the deposit stream.
///
/// Each variant carries the identifiers needed to reproduce the finding from
/// the two chains independently -- the evidence has to survive being handed to
/// someone who does not trust this program.
///
/// The serialised tag matches [`Discrepancy::kind`], so the JSON an operator
/// reads and the slug that goes on-chain in the freeze reason are the same
/// word.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Discrepancy {
    /// eUSD was released against a deposit that does not exist, or against no
    /// deposit at all. The whole amount is unbacked.
    UnbackedRelease {
        /// The offending release.
        release: Bytes32,
        /// The deposit id it named, if it named one.
        claimed: Option<DepositId>,
        /// Value released with nothing behind it.
        amount: Amount,
    },

    /// Two releases discharge one deposit. The first is backed; the second is
    /// not, so the second's full amount is the exposure.
    DoubleRelease {
        /// The deposit claimed twice.
        deposit: DepositId,
        /// The release that claimed it first, in `(block_index, release_id)`
        /// order.
        first: Bytes32,
        /// The release that claimed it again.
        second: Bytes32,
        /// The second release's amount.
        amount: Amount,
    },

    /// A release exceeds the deposit it claims. Only the excess is unbacked.
    OverRelease {
        /// The deposit claimed.
        deposit: DepositId,
        /// The offending release.
        release: Bytes32,
        /// What the deposit was worth.
        deposited: Amount,
        /// What was released against it.
        released: Amount,
        /// `released - deposited`.
        excess: Amount,
    },

    /// A release went somewhere other than the destination the depositor
    /// named. The depositor did not get their eUSD, so from the bridge's
    /// balance sheet the entire amount is a loss: it must still pay the
    /// depositor, and it cannot recover what it sent.
    DestinationMismatch {
        /// The deposit claimed.
        deposit: DepositId,
        /// The offending release.
        release: Bytes32,
        /// Where the depositor asked for it.
        expected: Bytes32,
        /// Where it actually went.
        actual: Bytes32,
        /// Value sent to the wrong destination.
        amount: Amount,
    },

    /// A release is timestamped before the deposit it claims to discharge.
    ///
    /// Zero exposure on its own -- the deposit did arrive and the amounts do
    /// match -- but the operators cannot have been acting on the deposit when
    /// they released, which means the release was authorised by something
    /// other than the rule. That is a compromised or bypassed attestation
    /// path, and the next one may not be so lucky as to be backed.
    ReleasePrecedesDeposit {
        /// The deposit claimed.
        deposit: DepositId,
        /// The offending release.
        release: Bytes32,
        /// Ethereum block timestamp of the deposit.
        deposit_ts: u64,
        /// MobileCoin block timestamp of the release.
        release_ts: u64,
    },
}

impl Discrepancy {
    /// The release this finding is about. Every finding is about exactly one.
    pub fn release_id(&self) -> Bytes32 {
        match *self {
            Discrepancy::UnbackedRelease { release, .. } => release,
            Discrepancy::DoubleRelease { second, .. } => second,
            Discrepancy::OverRelease { release, .. } => release,
            Discrepancy::DestinationMismatch { release, .. } => release,
            Discrepancy::ReleasePrecedesDeposit { release, .. } => release,
        }
    }

    /// Value this finding puts at risk.
    pub fn exposure(&self) -> Amount {
        match *self {
            Discrepancy::UnbackedRelease { amount, .. } => amount,
            Discrepancy::DoubleRelease { amount, .. } => amount,
            Discrepancy::OverRelease { excess, .. } => excess,
            Discrepancy::DestinationMismatch { amount, .. } => amount,
            Discrepancy::ReleasePrecedesDeposit { .. } => Amount::ZERO,
        }
    }

    /// How bad it is.
    pub fn severity(&self) -> Severity {
        match *self {
            Discrepancy::ReleasePrecedesDeposit { .. } => Severity::Anomaly,
            _ => Severity::Loss,
        }
    }

    /// Stable short name, used in the freeze reason string that goes on-chain.
    pub fn kind(&self) -> &'static str {
        match *self {
            Discrepancy::UnbackedRelease { .. } => "unbacked-release",
            Discrepancy::DoubleRelease { .. } => "double-release",
            Discrepancy::OverRelease { .. } => "over-release",
            Discrepancy::DestinationMismatch { .. } => "destination-mismatch",
            Discrepancy::ReleasePrecedesDeposit { .. } => "release-precedes-deposit",
        }
    }
}

/// A deposit that has waited too long for its release.
///
/// Not a [`Discrepancy`]: nobody has lost money, a user is stuck. Reported
/// separately so that a liveness failure cannot be quietly counted as a
/// solvency failure or vice versa -- they have opposite remedies, and freezing
/// on this one would strand every other user to no benefit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaleDeposit {
    /// The waiting deposit.
    pub deposit_id: DepositId,
    /// Its value.
    pub amount: Amount,
    /// Seconds since the deposit's Ethereum block.
    pub age_secs: u64,
}

/// Tolerances for matching.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchPolicy {
    /// Allowance for Ethereum and MobileCoin block clocks disagreeing.
    ///
    /// Both are consensus timestamps, not observations of a shared clock, and
    /// neither chain has any reason to agree with the other. Ten minutes is
    /// far wider than either chain's own drift tolerance; the ordering check
    /// exists to catch a release issued *hours* before its deposit, which is
    /// what a bypassed attestation path looks like, not to catch skew.
    pub clock_skew_tolerance: Duration,

    /// How long a deposit may go unreleased before it is reported stale.
    pub stale_deposit_after: Duration,
}

impl Default for MatchPolicy {
    fn default() -> Self {
        MatchPolicy {
            clock_skew_tolerance: Duration::from_secs(600),
            stale_deposit_after: Duration::from_secs(3600),
        }
    }
}

/// The outcome of matching.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchReport {
    /// Every finding, in release order.
    pub discrepancies: Vec<Discrepancy>,
    /// Deposits still waiting on a release past the policy's patience.
    pub stale_deposits: Vec<StaleDeposit>,
    /// Releases that matched a deposit cleanly.
    pub matched: usize,
    /// Releases examined.
    pub releases_examined: usize,
    /// Deposits examined.
    pub deposits_examined: usize,
}

impl MatchReport {
    /// `true` if nothing at all was found.
    pub fn is_clean(&self) -> bool {
        self.discrepancies.is_empty()
    }

    /// Total value the findings put at risk.
    ///
    /// Per release, the *maximum* over that release's findings, not the sum.
    /// One release can trip several checks at once -- a release that is both
    /// sent to the wrong destination and larger than its deposit produces two
    /// findings -- and adding them would report more value at risk than the
    /// release moved. An exposure figure that can exceed the money involved is
    /// not usable as an input to a bound.
    pub fn exposure(&self) -> Amount {
        let mut worst: BTreeMap<Bytes32, Amount> = BTreeMap::new();
        for d in &self.discrepancies {
            let slot = worst.entry(d.release_id()).or_insert(Amount::ZERO);
            if d.exposure() > *slot {
                *slot = d.exposure();
            }
        }
        worst.values().fold(Amount::ZERO, |a, v| a.saturating_add(*v))
    }

    /// The worst severity present, if any.
    ///
    /// `min`, not `max`: [`Severity`] declares `Loss` before `Anomaly`, so the
    /// derived ordering puts the worse outcome first and the smallest value is
    /// the one to act on.
    pub fn worst_severity(&self) -> Option<Severity> {
        self.discrepancies.iter().map(|d| d.severity()).min()
    }
}

pub(crate) fn reconcile(ledger: &Ledger, policy: &MatchPolicy, now: u64) -> MatchReport {
    let mut report = MatchReport {
        deposits_examined: ledger.deposits().count(),
        ..Default::default()
    };

    let skew = policy.clock_skew_tolerance.as_secs();

    // First claimant per deposit id. A deposit is discharged exactly once; the
    // claimant is recorded so the second claimant's evidence can name it.
    let mut claimed_by: BTreeMap<DepositId, Bytes32> = BTreeMap::new();
    let mut discharged: BTreeSet<DepositId> = BTreeSet::new();

    for r in ledger.releases_in_order() {
        report.releases_examined += 1;

        let Some(claimed) = r.claimed_deposit_id else {
            report.discrepancies.push(Discrepancy::UnbackedRelease {
                release: r.release_id,
                claimed: None,
                amount: r.amount,
            });
            continue;
        };

        let Some(dep) = ledger.deposit(claimed) else {
            report.discrepancies.push(Discrepancy::UnbackedRelease {
                release: r.release_id,
                claimed: Some(claimed),
                amount: r.amount,
            });
            continue;
        };

        let before = report.discrepancies.len();

        match claimed_by.get(&claimed) {
            Some(first) => report.discrepancies.push(Discrepancy::DoubleRelease {
                deposit: claimed,
                first: *first,
                second: r.release_id,
                amount: r.amount,
            }),
            None => {
                claimed_by.insert(claimed, r.release_id);
            }
        }

        // The remaining checks run even for a double release. A double release
        // already freezes, but the evidence handed to whoever unwinds this has
        // to describe what actually happened, not stop at the first thing that
        // was wrong.
        if r.amount > dep.amount {
            report.discrepancies.push(Discrepancy::OverRelease {
                deposit: claimed,
                release: r.release_id,
                deposited: dep.amount,
                released: r.amount,
                excess: r.amount.saturating_sub(dep.amount),
            });
        }

        if r.mob_destination != dep.mob_destination {
            report.discrepancies.push(Discrepancy::DestinationMismatch {
                deposit: claimed,
                release: r.release_id,
                expected: dep.mob_destination,
                actual: r.mob_destination,
                amount: r.amount,
            });
        }

        if dep.timestamp > r.timestamp.saturating_add(skew) {
            report.discrepancies.push(Discrepancy::ReleasePrecedesDeposit {
                deposit: claimed,
                release: r.release_id,
                deposit_ts: dep.timestamp,
                release_ts: r.timestamp,
            });
        }

        if report.discrepancies.len() == before {
            report.matched += 1;
            discharged.insert(claimed);
        }
    }

    let stale_after = policy.stale_deposit_after.as_secs();
    for d in ledger.deposits() {
        if discharged.contains(&d.deposit_id) || claimed_by.contains_key(&d.deposit_id) {
            continue;
        }
        let age = now.saturating_sub(d.timestamp);
        if age >= stale_after {
            report.stale_deposits.push(StaleDeposit {
                deposit_id: d.deposit_id,
                amount: d.amount,
                age_secs: age,
            });
        }
    }

    report
}
