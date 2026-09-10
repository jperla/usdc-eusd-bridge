//! Deposit auditor for the USDC <-> eUSD bridge.
//!
//! # What this component is for
//!
//! Every eUSD release on MobileCoin must correspond to exactly one USDC
//! deposit into [`Escrow`]. The deposit leg is *attested*, not proved:
//! Ethereum cannot compel the release and MobileCoin cannot check that the
//! deposit happened. Operators assert the correspondence. This crate is the
//! thing that checks the assertion after the fact and turns a failed check
//! into an action.
//!
//! # The structural limit -- read this before assuming a later check saves you
//!
//! **An unbacked release cannot be caught downstream.** Once operators mint
//! eUSD that no deposit backs, that eUSD is indistinguishable from every other
//! eUSD. An ordinary MobileCoin spend erases provenance: outputs are one-time
//! addresses, amounts are hidden in Pedersen commitments, and the ring
//! signature deliberately makes the true input unidentifiable among its
//! decoys. There is no field to inspect and no history to walk.
//!
//! The consequence is specific and it is the reason this crate exists:
//!
//! * The return leg's cryptographic verifier ([`IMobileCoinVerifier`]) proves
//!   that *some* eUSD arrived at the bridge's return address. It cannot prove
//!   that eUSD was legitimately issued. A verified return of stolen eUSD
//!   verifies exactly as well as a verified return of honest eUSD.
//! * Therefore no validation performed on a later return detects an earlier
//!   bad release. There is no downstream backstop. Reconciliation against the
//!   Ethereum deposit log is the only detector, and it is this component.
//! * Detection alone is not a control. By the time an unbacked release is
//!   visible, the attacker is already converting it. The response has to be
//!   enforceable -- [`Escrow.freeze`] blocks USDC from leaving -- and it has to
//!   be fast, because the loss grows at the release rate until it lands. That
//!   growth is what [`exposure_bound`] quantifies.
//!
//! What a freeze *cannot* do is equally structural and is stated in
//! `Escrow.sol`: pausing Ethereum does not stop a compromised operator quorum
//! from spending eUSD on MobileCoin. It stops that eUSD from becoming USDC.
//! The bound below is a bound on *realised loss*, not on misbehaviour.
//!
//! # Shape of the API
//!
//! * [`Ledger`] ingests [`DepositEvent`]s (Ethereum `Deposited` logs) and
//!   [`ReleaseRecord`]s (MobileCoin-side release attestations).
//! * [`Ledger::reconcile`] matches them one-to-one and returns every
//!   [`Discrepancy`] with the value each puts at risk.
//! * [`exposure_bound`] bounds the loss reachable from now.
//! * [`audit`] combines the two into a [`FreezeDecision`] -- an enum carrying
//!   the reason and the evidence. It is `#[must_use]`, so a caller cannot
//!   obtain one and drop it on the floor the way it can ignore a log line.
//!
//! # What this crate does not establish
//!
//! Stated here rather than left to be discovered, because each of these is a
//! place where someone could reasonably assume more coverage than exists.
//!
//! * **No external known-answer vectors.** There is no RFC, FIPS document or
//!   upstream implementation of a bridge deposit auditor to test against, so
//!   nothing here is validated by a third party. What stands in for it: the
//!   bound's arithmetic is pinned to hand-computed vectors written out in
//!   `tests/bound.rs`; `rho * delta_eff` is additionally checked against the
//!   *defining property* of ceiling division using multiplication only, so the
//!   oracle does not restate the implementation; and the matcher is checked by
//!   a randomised study in `tests/property.rs` that mutates records and
//!   compares against what the generator knows it changed. That is weaker than
//!   a published vector and should not be described as equivalent.
//!
//! * **Both feeds are trusted.** This crate cannot distinguish "operators
//!   released against no deposit" from "the Ethereum feed failed to show a
//!   deposit that exists". Both freeze, which is the safe direction, but the
//!   evidence attributes a discrepancy to the release stream when the fault may
//!   be in the observer. Corroborating the feeds against independent nodes is
//!   out of scope here and has to happen upstream.
//!
//! * **`rho` and `delta_eff` are declared, not measured.** The audit contradicts
//!   them when realised loss exceeds the bound
//!   ([`FreezeReason::ExposureBoundViolated`]), which catches a rate limit that
//!   is not being enforced, but it cannot confirm them. A `delta_eff` that is
//!   optimistic produces a bound that is too small and no test here can tell.
//!
//! * **Enforcement ends at the crate boundary.** [`FreezeDecision`] is a value
//!   the caller must act on; whether the freeze transaction is submitted,
//!   included, or front-run is not observable from here. "Enforceable" means
//!   the decision is a value with the reason and evidence attached rather than
//!   a log line -- not that this crate can compel the chain.
//!
//! * **`#[must_use]` is a compile-time property.** No runtime test asserts that
//!   a dropped [`FreezeDecision`] warns; that would need a compile-fail
//!   harness this crate does not pull in.
//!
//! * **The clock-ordering check is deliberately loose.** Ethereum and
//!   MobileCoin block timestamps are independent consensus values. The
//!   tolerance is wide enough that a release issued a few minutes before its
//!   deposit will not be caught.
//!
//! * **Strict one-to-one matching is assumed, not verified.** If the deployed
//!   protocol ever permits a deposit to be discharged by several partial
//!   releases, every one of them is reported here as a double release. That is
//!   a deliberate trade -- see `matcher.rs` -- but it is a coupling to a
//!   protocol rule that lives elsewhere.
//!
//! * **Release records are not cryptographically checked.** That a
//!   [`ReleaseRecord`] describes a real MobileCoin transaction is the feed's
//!   responsibility. This crate checks correspondence, not existence.
//!
//! [`Escrow`]: https://
//! [`IMobileCoinVerifier`]: https://
//! [`Escrow.freeze`]: https://

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod amount;
mod bound;
mod decision;
mod ledger;
mod matcher;

pub use amount::{Amount, Bytes32, EthAddress};
pub use bound::{effective_delay, exposure_bound, irrevocable_value, RateError, ReleaseRate};
pub use decision::{audit, AuditPolicy, AuditStats, BoundParams, Evidence, FreezeDecision,
                   FreezeReason};
pub use ledger::{DepositEvent, DepositId, IngestError, Ledger, ReleaseRecord};
pub use matcher::{Discrepancy, MatchPolicy, MatchReport, Severity, StaleDeposit};
