//! The abstract authorisation backend.
//!
//! The machine never sees a key, a nonce or a scalar. It sees opaque byte
//! payloads, a slot id naming a one-time value it must not let be reused, and
//! four questions it can ask the backend. Everything the machine enforces is
//! therefore enforced against a real signer and a test double alike -- which is
//! the reason the trait exists, since a real signer here is an HSM plus a
//! quorum of humans.
//!
//! `crate::frost` is the reference implementation used by the tests. It is a
//! genuine threshold Schnorr signer, not a stub: its shares really do fail to
//! aggregate below threshold, and its nonces really do leak the long-term share
//! when reused.

use crate::context::{Commitment, ParticipantId, Share, SigningContext, SlotId};
use crate::store::Receipt;

/// An attributable defect in one participant's own signed contribution.
///
/// "Attributable" is a strong claim and the type exists to stop it being made
/// casually: the only thing that may be reported as a fault is a check that
/// failed on bytes the accused participant signed. Everything else -- a
/// verification share missing from our table, a roster or epoch we disagree
/// about, a backend that did not answer -- is an `Error`, because a proceeding
/// cannot tell those apart from misconduct and will remove whoever is named.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Fault(String);

impl Fault {
    pub fn new(detail: impl Into<String>) -> Self {
        Fault(detail.into())
    }
}

/// Why a check on one participant's contribution did not pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejection<E> {
    /// The participant's own signed bytes fail the check. Only this may become
    /// abort evidence.
    Fault(Fault),
    /// Not attributable to any participant: configuration, epoch, roster,
    /// transport, or a backend that is simply not there.
    Error(E),
}

impl<E: std::fmt::Display> std::fmt::Display for Rejection<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rejection::Fault(fault) => write!(f, "{fault}"),
            Rejection::Error(e) => write!(f, "{e}"),
        }
    }
}

pub trait Authorizer {
    /// The aggregated signature this backend produces.
    type Signature;
    type Error: std::fmt::Display;

    /// Allocate a one-time value and return its slot and public commitment.
    ///
    /// The backend is trusted to make each call a fresh value; the machine does
    /// not trust it, which is why the slot is durably reserved before the
    /// commitment is published and durably bound before any share is produced.
    /// A backend restored from a snapshot will happily hand out a slot it has
    /// already used -- that is the case the store exists to catch.
    fn round_one(&mut self) -> Result<(SlotId, Commitment), Self::Error>;

    /// Produce this participant's share for `context` using the one-time value
    /// in `slot`.
    ///
    /// The `Receipt` argument is not decoration: it is mintable only by a
    /// store's own write path, so there is no way to spell "produce a share"
    /// that does not have a durable write in front of it. Implementations must
    /// check the arguments against `Receipt::record()` -- what the store read
    /// back -- and not against the receipt's agreement with the caller, which
    /// is two copies of the same claim.
    fn round_two(
        &mut self,
        slot: SlotId,
        context: &SigningContext,
        receipt: &Receipt,
    ) -> Result<Share, Self::Error>;

    /// Check one peer's share on its own. This is what makes an abort
    /// identifiable rather than merely detectable -- an aggregate that fails to
    /// verify tells you nothing about who caused it.
    ///
    /// Report `Rejection::Fault` only when the share itself fails the
    /// verification equation, or is malformed, under key material the backend
    /// is confident is the right material. Anything the backend could not
    /// establish -- a missing verification share, a roster it does not
    /// recognise, an unreachable HSM -- is `Rejection::Error`, and the machine
    /// will produce no evidence for it.
    fn verify_share(
        &self,
        context: &SigningContext,
        participant: ParticipantId,
        share: &Share,
    ) -> Result<(), Rejection<Self::Error>>;

    fn aggregate(
        &self,
        context: &SigningContext,
        shares: &[(ParticipantId, Share)],
    ) -> Result<Self::Signature, Self::Error>;

    fn verify_signature(
        &self,
        context: &SigningContext,
        signature: &Self::Signature,
    ) -> Result<(), Self::Error>;
}
