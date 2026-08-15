//! Ed25519 ORGANISATION identity keys: who produced a piece of the protocol.
//!
//! Nothing here is threshold material, and the separation is the whole point.
//! A threshold transcript is reproducible by anyone holding enough shares, so
//! it can say what a cohort's key IS and never who published it. An identity
//! signature is the other half: it says a named holder of a long-term key
//! endorsed these exact bytes, and it is not reproducible by the quorum it
//! would incriminate.
//!
//! # Why this lives in `two-cohort` and not in `crates/ceremony`
//!
//! It was written in `crates/ceremony/src/identity.rs` for identifiable abort,
//! where a signature over a round message is the only evidence a threshold
//! transcript cannot forge. [`ceremony`](crate::ceremony) now needs the same
//! notion for a different question -- which organisation sealed a component --
//! and `crates/ceremony` already depends on this crate, so importing upward
//! would be a cycle. The primitive therefore moved DOWN to the crate both can
//! reach, and `crates/ceremony`'s `identity` module re-exports these three
//! types rather than declaring a second identity notion beside them. One key
//! type, two uses: an organisation whose key signs a ceremony round message is
//! the same organisation whose key signs a commitment.
//!
//! # What a signature here does and does not say
//!
//! It says: the holder of this private key signed these bytes. It does NOT say
//! when, and it does not say the signer is a different organisation from the
//! other signer -- two "different" parties are two different keys, and whether
//! two keys are held by two organisations is a fact about the world. A funder
//! that checks a commitment against a key it obtained from the artifact rather
//! than from the organisation has checked nothing at all.

use mc_crypto_keys::{Ed25519Pair, Ed25519Public, Ed25519Signature, Signer, Verifier};

/// An organisation's (or participant's) identity public key.
///
/// Newtype because the upstream key type carries neither `Debug` nor
/// `PartialEq`, and a roster -- and an audit error naming who signed -- wants
/// both.
#[derive(Clone, Copy)]
pub struct IdentityPublic(Ed25519Public);

impl IdentityPublic {
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_ref()
    }

    /// `sig` is a signature by this key over `msg`.
    ///
    /// Returns a plain `bool` rather than a typed error because the two callers
    /// report the failure in their own vocabularies -- a participant id in
    /// `crates/ceremony`'s abort evidence, a cohort name in
    /// [`ceremony`](crate::ceremony)'s audit -- and a shared error type here
    /// would force one of them to translate.
    ///
    /// **Domain separation is the caller's.** This verifies over whatever bytes
    /// it is handed; every caller prefixes a tag naming the message type, so a
    /// signature over one kind of message cannot be replayed as another.
    pub fn verify(&self, msg: &[u8], sig: &IdentitySignature) -> bool {
        self.0.verify(msg, &Ed25519Signature::new(sig.0)).is_ok()
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

/// Full hex, because an audit rejection that names two keys is read by a human
/// deciding which organisation to go and talk to, and six bytes of prefix is
/// not enough to look a key up with.
impl std::fmt::Display for IdentityPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
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

    /// A freshly drawn identity key.
    ///
    /// Every 32-byte string is a valid RFC 8032 secret key, so this is a draw
    /// and not a rejection loop.
    pub fn draw<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        IdentityKey::from_seed(&seed)
    }

    pub fn public(&self) -> IdentityPublic {
        IdentityPublic(self.pair.public_key())
    }

    /// Sign `msg`.
    ///
    /// **Domain separation is the caller's**, and it is not optional: this signs
    /// whatever bytes it is handed, so two message types that do not carry
    /// distinct tags are one message type as far as a verifier is concerned.
    /// The tags in use are `bridge/ceremony/round{1,2}/v1` in `crates/ceremony`
    /// and `two-cohort/composition/commit-signature/v1` in
    /// [`ceremony`](crate::ceremony), and each of those payload builders puts
    /// its tag first.
    pub fn sign(&self, msg: &[u8]) -> IdentitySignature {
        IdentitySignature(self.pair.sign(msg).to_bytes())
    }
}
