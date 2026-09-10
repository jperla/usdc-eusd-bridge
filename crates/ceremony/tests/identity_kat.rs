//! Known-answer tests for the identity-key primitive.
//!
//! Vectors are RFC 8032 section 7.1 ("Test Vectors for Ed25519"), TEST 1 and
//! TEST 2, verbatim. They pin two things: that `IdentityKey` is Ed25519 as
//! specified rather than something merely Ed25519-shaped, and that the seed ->
//! public-key derivation this crate's roster depends on is the standard one, so
//! a roster built here matches a roster built by any other Ed25519 tool.
//!
//! LIMITATION. There is no comparable vector for the FROST reference backend in
//! `frost.rs`: it is not RFC 9591's ciphersuite (Blake2b, Ristretto, this
//! crate's own transcript encoding), so nothing published covers it and this
//! file does not pretend otherwise.

mod common;

use mc_crypto_keys::{Ed25519Pair, Signer, Verifier};

use ceremony::{IdentityKey, ParticipantId, SignedRoundOne, Statement, Subset};
use ceremony::{Commitment, IdentityPublic, IdentitySignature};
use common::identity;

// RFC 8032 7.1, TEST 1 (empty message).
const T1_SECRET: [u8; 32] =
    hex_literal("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
const T1_PUBLIC: [u8; 32] =
    hex_literal("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
const T1_MESSAGE: &[u8] = b"";
const T1_SIGNATURE: [u8; 64] = hex_literal_64(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
);

// RFC 8032 7.1, TEST 2 (one-byte message 0x72).
const T2_SECRET: [u8; 32] =
    hex_literal("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
const T2_PUBLIC: [u8; 32] =
    hex_literal("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
const T2_MESSAGE: &[u8] = &[0x72];
const T2_SIGNATURE: [u8; 64] = hex_literal_64(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
);

#[test]
fn identity_keys_reproduce_the_rfc8032_vectors() {
    for (secret, public, message, signature) in [
        (T1_SECRET, T1_PUBLIC, T1_MESSAGE, T1_SIGNATURE),
        (T2_SECRET, T2_PUBLIC, T2_MESSAGE, T2_SIGNATURE),
    ] {
        // The derivation the roster uses.
        assert_eq!(
            IdentityKey::from_seed(&secret).public().as_bytes(),
            &public,
            "seed -> public key must be RFC 8032's derivation"
        );

        let pair = Ed25519Pair::try_from(&secret[..]).expect("seed");
        assert_eq!(
            pair.sign(message).to_bytes(),
            signature,
            "signature must match the RFC 8032 vector"
        );
        pair.verify(message, &pair.sign(message)).expect("verifies");
    }
}

/// A verifier that accepted everything would pass the test above.
#[test]
fn a_tampered_message_does_not_verify() {
    let pair = Ed25519Pair::try_from(&T2_SECRET[..]).expect("seed");
    let sig = pair.sign(T2_MESSAGE);
    assert!(pair.verify(&[0x73], &sig).is_err());
}

/// The same key material, used the way the ceremony uses it: a round-one
/// message verifies, and one flipped bit of the payload does not.
#[test]
fn round_message_verification_rides_on_the_same_primitive() {
    let key = IdentityKey::from_seed(&T1_SECRET);
    let me = ParticipantId(1);
    let subset = Subset::new([me, ParticipantId(2)]);
    let msg = SignedRoundOne::create(
        &key,
        me,
        Statement(b"release 250000 eUSD to R".to_vec()),
        subset,
        Commitment(vec![0xAA; 64]),
    );
    msg.verify(&key.public()).expect("honest message verifies");

    let mut tampered = msg.clone();
    tampered.commitment.0[0] ^= 1;
    assert!(tampered.verify(&key.public()).is_err());

    // Another participant's key does not verify it either.
    assert!(msg.verify(&identity(ParticipantId(2)).public()).is_err());

    // A signature that is simply wrong bytes is rejected rather than skipped.
    let mut zeroed = msg;
    zeroed.signature = IdentitySignature([0u8; 64]);
    assert!(zeroed.verify(&key.public()).is_err());
}

/// **This crate's identity key IS `two_cohort`'s, not a second copy of the same
/// idea.**
///
/// `two-cohort`'s composition ceremony endorses each cohort's sealed commitment
/// under an identity key, and it must be the same notion of identity a round
/// message is signed under -- an organisation has one long-term key, not one per
/// module. The primitive therefore lives in `two_cohort::identity` (the crate
/// both can reach; this one depends on it, so the reverse would be a cycle) and
/// this crate re-exports it.
///
/// Checked by the compiler rather than asserted: the assignments below are
/// type-level identity, so a second declaration anywhere would stop this
/// compiling rather than quietly diverge. The RFC 8032 vector is carried through
/// as well, so the shared type is still the specified Ed25519 and not merely
/// shared.
#[test]
fn the_identity_primitive_is_two_cohorts_own() {
    let mine: IdentityKey = two_cohort::identity::IdentityKey::from_seed(&T1_SECRET);
    let theirs: two_cohort::identity::IdentityPublic = mine.public();
    let back: IdentityPublic = theirs;
    assert_eq!(back.as_bytes(), &T1_PUBLIC);

    // And the signature type crosses too, so a signature produced by one crate's
    // API is verifiable by the other's without conversion.
    let sig: two_cohort::identity::IdentitySignature = mine.sign(T1_MESSAGE);
    let sig: IdentitySignature = sig;
    assert_eq!(sig.0, T1_SIGNATURE);
    assert!(back.verify(T1_MESSAGE, &sig));
}

// -------------------------------------------------------------- hex helpers
//
// const fns rather than a hex crate call so the vectors sit in the source in
// exactly the form the RFC prints them.

const fn hex_literal(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(b.len() == 64);
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(b[2 * i]) * 16 + nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn hex_literal_64(hi: &str, lo: &str) -> [u8; 64] {
    let a = hex_literal(hi);
    let b = hex_literal(lo);
    let mut out = [0u8; 64];
    let mut i = 0;
    while i < 32 {
        out[i] = a[i];
        out[i + 32] = b[i];
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("test vectors are lowercase hex"),
    }
}
