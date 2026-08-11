//! Per-participant IDENTITY keys, and the round messages signed under them.
//!
//! Identity keys are NOT the threshold shares, and the separation is the whole
//! point. A threshold signing transcript is forgeable by the quorum it would
//! incriminate: any set of participants holding enough shares can compute the
//! exact bytes an honest peer would have sent -- correct ones or wrong ones --
//! so "participant 3's share was invalid" is not a claim the transcript can
//! support. `tests/identifiable_abort.rs` carries that out: an adversary holding
//! every share reproduces an honest peer's round-two bytes exactly, and the only
//! thing it cannot reproduce is the Ed25519 signature over them.
//!
//! Consequently every round message is signed under a key that lives outside the
//! sharing, and abort evidence is the signature, never the transcript.

use mc_crypto_keys::{Ed25519Pair, Ed25519Public, Ed25519Signature, Signer, Verifier};

use crate::context::{Commitment, ContextId, ParticipantId, Share, Statement, Subset};

/// A participant's identity public key. Newtype because the upstream key type
/// carries neither `Debug` nor `PartialEq`, and a roster wants both.
#[derive(Clone, Copy)]
pub struct IdentityPublic(Ed25519Public);

impl IdentityPublic {
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_ref()
    }
    pub fn inner(&self) -> &Ed25519Public {
        &self.0
    }
}

impl From<Ed25519Public> for IdentityPublic {
    fn from(k: Ed25519Public) -> Self {
        IdentityPublic(k)
    }
}

impl PartialEq for IdentityPublic {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}
impl Eq for IdentityPublic {}

impl std::fmt::Debug for IdentityPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdentityPublic(")?;
        for b in &self.as_bytes()[..6] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "..)")
    }
}

/// Detached Ed25519 signature, kept as bytes so the message types stay plain
/// data that can be compared, hashed and logged.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IdentitySignature(pub [u8; 64]);

impl std::fmt::Debug for IdentitySignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdentitySignature(")?;
        for b in &self.0[..6] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "..)")
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("identity signature does not verify for participant {0:?}")]
    BadSignature(ParticipantId),
}

/// Signing side of an identity key.
pub struct IdentityKey {
    pair: Ed25519Pair,
}

impl IdentityKey {
    /// `seed` is the 32-byte Ed25519 private key (RFC 8032 secret key).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let pair = Ed25519Pair::try_from(&seed[..]).expect("32 bytes is a valid Ed25519 seed");
        IdentityKey { pair }
    }
    pub fn public(&self) -> IdentityPublic {
        IdentityPublic(self.pair.public_key())
    }
    fn sign(&self, msg: &[u8]) -> IdentitySignature {
        IdentitySignature(self.pair.sign(msg).to_bytes())
    }
}

fn verify(
    key: &IdentityPublic,
    msg: &[u8],
    sig: &IdentitySignature,
    who: ParticipantId,
) -> Result<(), IdentityError> {
    key.0
        .verify(msg, &Ed25519Signature::new(sig.0))
        .map_err(|_| IdentityError::BadSignature(who))
}

// Distinct domain tags so a round-one signature can never be replayed as a
// round-two signature or vice versa.
const R1_DOMAIN: &[u8] = b"bridge/ceremony/round1/v1";
const R2_DOMAIN: &[u8] = b"bridge/ceremony/round2/v1";

/// Round-one message: this participant's commitment, bound to the statement and
/// the subset it believes it is signing under.
///
/// It cannot be bound to the context id -- the context does not exist until
/// every round-one message is in -- so the statement and subset are named
/// explicitly. A peer that signs round one for statement A and round two for
/// statement B is detectable because both are signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRoundOne {
    pub participant: ParticipantId,
    pub statement: Statement,
    pub subset: Subset,
    pub commitment: Commitment,
    pub signature: IdentitySignature,
}

impl SignedRoundOne {
    pub fn create(
        key: &IdentityKey,
        participant: ParticipantId,
        statement: Statement,
        subset: Subset,
        commitment: Commitment,
    ) -> Self {
        let payload = Self::payload(participant, &statement, &subset, &commitment);
        let signature = key.sign(&payload);
        SignedRoundOne {
            participant,
            statement,
            subset,
            commitment,
            signature,
        }
    }

    pub fn verify(&self, key: &IdentityPublic) -> Result<(), IdentityError> {
        let payload = Self::payload(
            self.participant,
            &self.statement,
            &self.subset,
            &self.commitment,
        );
        verify(key, &payload, &self.signature, self.participant)
    }

    fn payload(
        participant: ParticipantId,
        statement: &Statement,
        subset: &Subset,
        commitment: &Commitment,
    ) -> Vec<u8> {
        let mut out = Vec::from(R1_DOMAIN);
        out.extend_from_slice(&participant.0.to_le_bytes());
        out.extend_from_slice(&(statement.0.len() as u64).to_le_bytes());
        out.extend_from_slice(&statement.0);
        out.extend_from_slice(&(subset.len() as u64).to_le_bytes());
        for id in subset.iter() {
            out.extend_from_slice(&id.0.to_le_bytes());
        }
        out.extend_from_slice(&(commitment.0.len() as u64).to_le_bytes());
        out.extend_from_slice(&commitment.0);
        out
    }
}

/// Round-two message: this participant's share, bound to the FULL context id.
///
/// Because the context id covers the complete round-one package, a signed share
/// names exactly one binding factor and one challenge. That is what makes the
/// signature usable as evidence: there is no second context in which these
/// bytes would have been the honest answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRoundTwo {
    pub participant: ParticipantId,
    pub context: ContextId,
    pub share: Share,
    pub signature: IdentitySignature,
}

impl SignedRoundTwo {
    pub fn create(
        key: &IdentityKey,
        participant: ParticipantId,
        context: ContextId,
        share: Share,
    ) -> Self {
        let payload = Self::payload(participant, context, &share);
        let signature = key.sign(&payload);
        SignedRoundTwo {
            participant,
            context,
            share,
            signature,
        }
    }

    pub fn verify(&self, key: &IdentityPublic) -> Result<(), IdentityError> {
        let payload = Self::payload(self.participant, self.context, &self.share);
        verify(key, &payload, &self.signature, self.participant)
    }

    fn payload(participant: ParticipantId, context: ContextId, share: &Share) -> Vec<u8> {
        let mut out = Vec::from(R2_DOMAIN);
        out.extend_from_slice(&participant.0.to_le_bytes());
        out.extend_from_slice(&context.0);
        out.extend_from_slice(&(share.0.len() as u64).to_le_bytes());
        out.extend_from_slice(&share.0);
        out
    }
}
