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
    /// The `Receipt` argument is not decoration: it is only mintable by a
    /// `BindingStore`, so there is no way to spell "produce a share" that does
    /// not have a durable write in front of it.
    fn round_two(
        &mut self,
        slot: SlotId,
        context: &SigningContext,
        receipt: &Receipt,
    ) -> Result<Share, Self::Error>;

    /// Check one peer's share on its own. This is what makes an abort
    /// identifiable rather than merely detectable -- an aggregate that fails to
    /// verify tells you nothing about who caused it.
    fn verify_share(
        &self,
        context: &SigningContext,
        participant: ParticipantId,
        share: &Share,
    ) -> Result<(), Self::Error>;

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
