//! The freeze bound.
//!
//! ```text
//!     E  =  min( B , P + rho * delta_eff )
//! ```
//!
//! * `B`          -- remaining escrow balance. Nothing can be lost that is not
//!                   there to lose; the freeze cannot claw back what already
//!                   left, and the attacker cannot take what was never
//!                   deposited.
//! * `P`          -- value already past the point of recall at the moment of
//!                   detection. Freezing does not undo it.
//! * `rho`        -- the maximum rate at which value can keep leaving. This is
//!                   a *policy* number (the release rate limit), not a measured
//!                   one; the audit cross-checks observed loss against it and
//!                   treats a violation as its own finding, because a rate
//!                   above `rho` means the control that was supposed to make
//!                   this bound true is not working.
//! * `delta_eff`  -- detection-to-freeze delay, *effective*: not just how long
//!                   the auditor takes to notice, but the whole path to the
//!                   freeze being in force on Ethereum. See
//!                   [`ReleaseRate::max_released_within`] and the components
//!                   listed on [`effective_delay`].
//!
//! Both terms are needed. `B` alone ignores that the escrow is drained
//! gradually and would over-state exposure for a large float. `P + rho*delta`
//! alone would exceed the money that exists.
//!
//! Everything here rounds and saturates *upward*. A bound that is too large
//! costs a conservative parameter choice; a bound that is too small is a
//! silent under-estimate of how much can be stolen.

use core::time::Duration;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::amount::Amount;

/// Rejected release-rate parameters.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RateError {
    /// A zero window makes the rate infinite; an infinite rate would make the
    /// bound trivially `B` and hide a misconfiguration behind a plausible
    /// number.
    #[error("release rate window must be non-zero")]
    ZeroWindow,
}

/// `rho`: a ceiling on how much value can leave per unit time.
///
/// Expressed as amount-per-window rather than amount-per-second because that
/// is how a rate limit is actually configured ("at most 250k USDC per hour"),
/// and because per-second would force a lossy division at construction time --
/// exactly where a rounding error becomes a permanently under-stated bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRate {
    max_amount: Amount,
    window: Duration,
}

impl ReleaseRate {
    /// At most `max_amount` per `window`.
    pub fn new(max_amount: Amount, window: Duration) -> Result<Self, RateError> {
        if window.is_zero() {
            return Err(RateError::ZeroWindow);
        }
        Ok(ReleaseRate { max_amount, window })
    }

    /// At most `max_amount` per second.
    pub fn per_second(max_amount: Amount) -> Self {
        ReleaseRate { max_amount, window: Duration::from_secs(1) }
    }

    /// A rate of zero: releases are already halted.
    pub fn halted() -> Self {
        ReleaseRate { max_amount: Amount::ZERO, window: Duration::from_secs(1) }
    }

    /// The configured ceiling per window.
    pub fn max_amount(self) -> Amount {
        self.max_amount
    }

    /// The window the ceiling applies over.
    pub fn window(self) -> Duration {
        self.window
    }

    /// `rho * d`, rounded up.
    ///
    /// Rounded up rather than to nearest: a partial window is a window the
    /// attacker gets to use. Computed in nanoseconds so that a sub-second
    /// `delta_eff` -- which is not realistic today but is what you would want
    /// after any latency work -- does not truncate to zero.
    pub fn max_released_within(self, d: Duration) -> Amount {
        let per_window = self.max_amount.base_units();
        match per_window.checked_mul(d.as_nanos()) {
            // Saturating here is the conservative direction: an overflowing
            // product means "more than can exist", and the `min` with the
            // balance is what turns that back into a finite answer.
            None => Amount::MAX,
            // `window` is non-zero by construction, so this cannot divide by
            // zero -- see `ReleaseRate::new`.
            Some(n) => Amount::from_base_units(n.div_ceil(self.window.as_nanos())),
        }
    }
}

/// The bound. `min(B, P + rho * delta_eff)`.
///
/// Deliberately a free function of exactly its four inputs, with no clock, no
/// ledger and no configuration reached through a global: it is the one number
/// the whole freeze policy rests on, and it should be possible to reproduce it
/// by hand from four values written on paper.
#[must_use]
pub fn exposure_bound(
    remaining_balance: Amount,
    p_irrevocable: Amount,
    rho: ReleaseRate,
    delta_eff: Duration,
) -> Amount {
    let reachable = p_irrevocable.saturating_add(rho.max_released_within(delta_eff));
    remaining_balance.min(reachable)
}

/// The `P` term: of the value already identified as unbacked, how much has
/// been out long enough that no response can recover it.
///
/// `items` are `(value_at_risk, settled_at_unix_secs)` pairs -- in practice the
/// exposure of each discrepancy paired with its release's block timestamp.
/// Note what is *not* summed here: legitimately backed releases. `P` is a term
/// in a bound on loss, so it counts only value that is both unbacked and
/// unrecoverable. Summing all released value instead would make `P` roughly the
/// float and the bound would degenerate to the balance, which is true but
/// useless.
///
/// "Past the point of recall" is a property of the recipient's opportunity to
/// move funds on, not of MobileCoin finality, so `recall_horizon` is a policy
/// input. Zero -- nothing is ever recoverable -- is the conservative setting
/// and the one to prefer absent a specific reason to believe otherwise.
#[must_use]
pub fn irrevocable_value<I>(items: I, now: u64, recall_horizon: Duration) -> Amount
where
    I: IntoIterator<Item = (Amount, u64)>,
{
    let horizon = recall_horizon.as_secs();
    items
        .into_iter()
        .filter(|(_, settled_at)| now.saturating_sub(*settled_at) >= horizon)
        .fold(Amount::ZERO, |acc, (v, _)| acc.saturating_add(v))
}

/// Compose `delta_eff` from the segments that actually make it up.
///
/// Stated as a sum of named parts because the number is otherwise guessed. The
/// path from a bad release existing to USDC stopping is: the MobileCoin block
/// becoming visible to the auditor's feed, the auditor's polling interval, the
/// reconciliation and decision, the freeze transaction reaching inclusion, and
/// -- the part most often forgotten -- the fact that a freeze only takes effect
/// at the *end* of the block it lands in.
#[must_use]
pub fn effective_delay(
    feed_lag: Duration,
    poll_interval: Duration,
    decision: Duration,
    tx_inclusion: Duration,
) -> Duration {
    feed_lag
        .saturating_add(poll_interval)
        .saturating_add(decision)
        .saturating_add(tx_inclusion)
}
