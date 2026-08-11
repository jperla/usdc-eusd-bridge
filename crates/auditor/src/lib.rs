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
