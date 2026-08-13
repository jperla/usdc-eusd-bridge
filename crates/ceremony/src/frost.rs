//! Reference authorisation backend: threshold Schnorr over Ristretto, in the
//! shape of FROST (RFC 9591) -- two-nonce commitments, a per-participant
//! binding factor, Lagrange-weighted responses.
//!
//! It exists so the state machine's guarantees are tested against something
//! that can actually fail. A stub backend would make every guard in
//! `machine.rs` vacuous: the sub-threshold test would pass because the stub
//! returns `Ok`, not because a sub-threshold quorum cannot sign. Here, a
//! sub-threshold aggregate really does fail to verify, an altered share really
//! is caught by `verify_share`, and a one-time value used three times really
//! does give up the long-term share to linear algebra -- all of which the tests
//! exercise directly.
//!
//! LIMITATION. This is deliberately NOT RFC 9591's ciphersuite: the hash is
//! Blake2b (the hash this workspace already vendors) rather than SHA-512, and
//! the transcript encoding is this crate's own. There is therefore no known-
//! answer vector for it and none is claimed. What is claimed and tested is the
//! algebra -- verification equations, threshold behaviour, nonce-reuse
//! consequences. The production backend is an HSM-resident MobileCoin signer
//! and is out of this crate's scope; the `Authorizer` trait is the seam.

use std::collections::BTreeMap;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use mc_crypto_hashes::{Blake2b512, Digest};
use rand_core::{CryptoRng, RngCore};
use two_cohort::{lagrange_at_zero, Cohort};

use crate::authorizer::Authorizer;
use crate::context::{Commitment, ContextId, ParticipantId, Share, SigningContext, SlotId, Subset};
use crate::store::Receipt;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrostError {
    #[error("slot {0:?} holds no one-time value (already consumed, or never issued)")]
    UnknownSlot(SlotId),
    #[error("receipt does not match the slot and context being signed")]
    ReceiptMismatch,
    #[error("commitment for {0:?} is missing or malformed")]
    BadCommitment(ParticipantId),
    #[error("no verification share on file for {0:?}")]
    UnknownParticipant(ParticipantId),
    #[error("share for {0:?} is not a canonical scalar")]
    BadShare(ParticipantId),
    #[error("share for {0:?} does not satisfy the verification equation")]
    ShareInvalid(ParticipantId),
    #[error("signature does not verify")]
    SignatureInvalid,
    #[error("participant {0:?} appears twice")]
    Duplicate(ParticipantId),
    /// A roster or subset the Shamir layer refused: threshold zero, threshold
    /// above the roster, a repeated id, or id 0 -- which is the interpolation
    /// point, so a participant issued it would hold the group secret outright.
    #[error(transparent)]
    Sharing(#[from] two_cohort::Error),
}

/// Public key material: the group key and each participant's verification share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupKey {
    pub threshold: u16,
    pub group_public: RistrettoPoint,
    pub verification_shares: BTreeMap<ParticipantId, RistrettoPoint>,
}

/// Trusted-dealer Shamir sharing of a fresh secret.
///
/// A trusted dealer, not a DKG: this crate is about ceremony sequencing, and
/// key generation is a separate ceremony with a separate threat model. The
/// sharing itself is `two_cohort::Cohort`, which is where the roster rules and
/// the Lagrange arithmetic live for the whole workspace -- a second copy here
/// would be a second chance to get the interpolation wrong, and only one of the
/// two would be pinned by that crate's hand-computed weight vectors.
///
/// Returned as a `Result` rather than asserted: a threshold copied from the
/// wrong cohort or an operator id left at its default is config a human types,
/// and a signing service that aborts on bad config can be taken down by bad
/// config.
pub fn deal<R: RngCore + CryptoRng>(
    threshold: u16,
    ids: &[ParticipantId],
    rng: &mut R,
) -> Result<(GroupKey, BTreeMap<ParticipantId, Scalar>), FrostError> {
    let roster: Vec<u64> = ids.iter().map(|id| id.0 as u64).collect();
    let secret = Scalar::random(rng);
    let cohort = Cohort::deal("ceremony", &secret, threshold as usize, &roster, rng)?;

    let mut shares = BTreeMap::new();
    for id in ids {
        shares.insert(*id, *cohort.share(id.0 as u64)?);
    }
    let verification_shares = shares
        .iter()
        .map(|(id, s)| (*id, RISTRETTO_BASEPOINT_POINT * *s))
        .collect();

    Ok((
        GroupKey {
            threshold,
            group_public: RISTRETTO_BASEPOINT_POINT * secret,
            verification_shares,
        },
        shares,
    ))
}

/// One participant's signer.
///
/// `Clone` is how the tests model a signer restored from a VM snapshot: the
/// clone has its RNG and its unconsumed one-time values back. Nothing else in
/// the crate clones it.
#[derive(Clone)]
pub struct FrostSigner<R: RngCore + CryptoRng + Clone> {
    me: ParticipantId,
    share: Scalar,
    group: GroupKey,
    nonces: BTreeMap<SlotId, (Scalar, Scalar)>,
    next_slot: u64,
    rng: R,
}

impl<R: RngCore + CryptoRng + Clone> FrostSigner<R> {
    pub fn new(me: ParticipantId, share: Scalar, group: GroupKey, rng: R) -> Self {
        FrostSigner {
            me,
            share,
            group,
            nonces: BTreeMap::new(),
            next_slot: 0,
            rng,
        }
    }

    pub fn group(&self) -> &GroupKey {
        &self.group
    }

    /// Reference backend only. A real backend has no such accessor; the tests
    /// need the true value to assert that a nonce-reuse attack recovers exactly
    /// it.
    pub fn secret_share(&self) -> Scalar {
        self.share
    }
}

impl<R: RngCore + CryptoRng + Clone> Authorizer for FrostSigner<R> {
    type Signature = FrostSignature;
    type Error = FrostError;

    fn round_one(&mut self) -> Result<(SlotId, Commitment), FrostError> {
        let slot = SlotId(self.next_slot);
        self.next_slot += 1;
        let d = Scalar::random(&mut self.rng);
        let e = Scalar::random(&mut self.rng);
        let big_d = RISTRETTO_BASEPOINT_POINT * d;
        let big_e = RISTRETTO_BASEPOINT_POINT * e;
        self.nonces.insert(slot, (d, e));

        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(big_d.compress().as_bytes());
        bytes.extend_from_slice(big_e.compress().as_bytes());
        Ok((slot, Commitment(bytes)))
    }

    fn round_two(
        &mut self,
        slot: SlotId,
        context: &SigningContext,
        receipt: &Receipt,
    ) -> Result<Share, FrostError> {
        if receipt.slot() != slot || receipt.context() != Some(context.id()) {
            return Err(FrostError::ReceiptMismatch);
        }
        // Consumed, not merely marked. A correct signer never answers twice for
        // one one-time value; the store exists because "correct signer" is an
        // assumption that a restore from backup silently removes.
        let (d, e) = self.nonces.remove(&slot).ok_or(FrostError::UnknownSlot(slot))?;

        let ctx_id = context.id();
        let rho = binding_factor(ctx_id, self.me);
        let r = group_commitment(context)?;
        let c = challenge(&r, &self.group.group_public, ctx_id);
        let lambda = lagrange(context.subset(), self.me)?;

        let z = d + e * rho + lambda * c * self.share;
        Ok(Share(z.to_bytes().to_vec()))
    }

    fn verify_share(
        &self,
        context: &SigningContext,
        participant: ParticipantId,
        share: &Share,
    ) -> Result<(), FrostError> {
        let z = scalar_from(&share.0).ok_or(FrostError::BadShare(participant))?;
        let (big_d, big_e) = commitment_of(context, participant)?;
        let ctx_id = context.id();
        let rho = binding_factor(ctx_id, participant);
        let r = group_commitment(context)?;
        let c = challenge(&r, &self.group.group_public, ctx_id);
        let lambda = lagrange(context.subset(), participant)?;
        let y = self
            .group
            .verification_shares
            .get(&participant)
            .ok_or(FrostError::UnknownParticipant(participant))?;

        if RISTRETTO_BASEPOINT_POINT * z == big_d + big_e * rho + y * (lambda * c) {
            Ok(())
        } else {
            Err(FrostError::ShareInvalid(participant))
        }
    }

    fn aggregate(
        &self,
        context: &SigningContext,
        shares: &[(ParticipantId, Share)],
    ) -> Result<FrostSignature, FrostError> {
        let mut seen = BTreeMap::new();
        let mut z = Scalar::ZERO;
        for (id, s) in shares {
            if seen.insert(*id, ()).is_some() {
                return Err(FrostError::Duplicate(*id));
            }
            z += scalar_from(&s.0).ok_or(FrostError::BadShare(*id))?;
        }
        Ok(FrostSignature {
            r: group_commitment(context)?,
            z,
        })
    }

    fn verify_signature(
        &self,
        context: &SigningContext,
        signature: &FrostSignature,
    ) -> Result<(), FrostError> {
        let c = challenge(&signature.r, &self.group.group_public, context.id());
        if RISTRETTO_BASEPOINT_POINT * signature.z
            == signature.r + self.group.group_public * c
        {
            Ok(())
        } else {
            Err(FrostError::SignatureInvalid)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrostSignature {
    pub r: RistrettoPoint,
    pub z: Scalar,
}

// ------------------------------------------------------------- primitives
//
// Public because the attack-witness tests do algebra with them. Everything here
// is derived from public data.

/// rho_i = H(ctx_id, i). Derived from the context id, which is exactly the
/// point: the context id already covers the complete round-one package, so any
/// change to any participant's commitment moves every binding factor.
pub fn binding_factor(context: ContextId, participant: ParticipantId) -> Scalar {
    let mut h = Blake2b512::new();
    h.update(b"bridge/ceremony/frost/rho/v1");
    h.update(context.0);
    h.update(participant.0.to_le_bytes());
    wide_scalar(h)
}

pub fn challenge(r: &RistrettoPoint, group_public: &RistrettoPoint, context: ContextId) -> Scalar {
    let mut h = Blake2b512::new();
    h.update(b"bridge/ceremony/frost/challenge/v1");
    h.update(r.compress().as_bytes());
    h.update(group_public.compress().as_bytes());
    h.update(context.0);
    wide_scalar(h)
}

/// R = sum_j (D_j + rho_j E_j) over the whole package.
pub fn group_commitment(context: &SigningContext) -> Result<RistrettoPoint, FrostError> {
    let ctx_id = context.id();
    let mut acc = RistrettoPoint::default();
    for id in context.subset().iter() {
        let (d, e) = commitment_of(context, id)?;
        acc += d + e * binding_factor(ctx_id, id);
    }
    Ok(acc)
}

/// Lagrange coefficient at zero for `participant` over `subset`.
///
/// Fallible because the weight is only meaningful for a participant that is in
/// the subset: computed for one that is not, the formula still returns a
/// perfectly well-formed scalar, and a share built on it would be wrong in a
/// way nothing downstream can attribute.
pub fn lagrange(subset: &Subset, participant: ParticipantId) -> Result<Scalar, FrostError> {
    let ids: Vec<u64> = subset.iter().map(|id| id.0 as u64).collect();
    Ok(lagrange_at_zero(participant.0 as u64, &ids)?)
}

pub fn commitment_of(
    context: &SigningContext,
    participant: ParticipantId,
) -> Result<(RistrettoPoint, RistrettoPoint), FrostError> {
    let c = context
        .package()
        .get(participant)
        .ok_or(FrostError::BadCommitment(participant))?;
    if c.0.len() != 64 {
        return Err(FrostError::BadCommitment(participant));
    }
    let d = point_from(&c.0[..32]).ok_or(FrostError::BadCommitment(participant))?;
    let e = point_from(&c.0[32..]).ok_or(FrostError::BadCommitment(participant))?;
    Ok((d, e))
}

fn wide_scalar(h: Blake2b512) -> Scalar {
    let out = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&out);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn point_from(bytes: &[u8]) -> Option<RistrettoPoint> {
    let mut b = [0u8; 32];
    b.copy_from_slice(bytes);
    CompressedRistretto(b).decompress()
}

/// Canonical scalars only: a non-canonical encoding would let one share be
/// presented two ways, and the identity signature is over the bytes.
pub fn scalar_from(bytes: &[u8]) -> Option<Scalar> {
    if bytes.len() != 32 {
        return None;
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(bytes);
    Option::from(Scalar::from_canonical_bytes(b))
}
