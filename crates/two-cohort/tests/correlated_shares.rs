//! An artifact proves algebra and possession, not independent randomness.
//!
//! This is a passing attack witness, not an expected rejection: the public
//! audit cannot establish threshold secrecy for adversarially correlated
//! polynomial coefficients. Honest authenticated DKG execution remains a trust
//! condition. Every required organisation and seat really endorses this claim;
//! this does not bypass a holder checking its own honestly generated DKG key.

mod common;

use std::collections::BTreeMap;

use common::{
    own_share_scalar, parties, seal_and_sign, seat_endorsements, seat_keys_over, CohortSide,
    SUBADDRESS,
};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, scalar::Scalar};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_crypto_ring_signature::{Commitment, CompressedCommitment};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use two_cohort::{
    audit_address,
    ceremony::SealedComposition,
    derive::subaddress_offset,
    fixture::make_ring_from_seed,
    mlsag::{sign, MaskSigner, MemoryNonceGuard, SessionParams, SpendSigner},
    production::{self, authorize_release, deposit_spend_key},
    CeremonyId, ComponentClaim, ComponentReveal, CompositeSpend, ControlDomain, Gates, Owners, Pop,
};

#[test]
fn correlated_coefficients_pass_the_audit_but_one_owner_recovers_the_component() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xC077E1A7E);
    let ceremony = CeremonyId::draw("coefficient independence is not proved", &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &production::gates(), &mut rng);
    let owner_spec = production::owners();
    let roster = owner_spec.ids();
    let b = Scalar::random(&mut rng);

    // Exact degree one, but its two coefficients are the SAME secret:
    // p(x) = b + b*x. Every pair reconstructs b under standard interpolation;
    // no singleton equals b, yet every singleton recovers b by known scaling.
    let secrets: Vec<_> = (1..=roster.len() as u64)
        .map(|x| b * Scalar::from(x + 1))
        .collect();
    for (i, share) in secrets.iter().enumerate() {
        assert_ne!(
            *share, b,
            "the existing singleton check has nothing to reject"
        );
        assert_eq!(*share * Scalar::from(i as u64 + 2).invert(), b);
    }
    let claim = ComponentClaim::from_parts(
        Owners::NAME,
        production::OWNER_THRESHOLD,
        roster.to_vec(),
        b * G,
        secrets.iter().map(|share| share * G).collect(),
        seat_keys_over::<Owners>(roster),
    );
    let salt = [0xC0; 32];
    let sealed = SealedComposition::new(
        ceremony,
        seal_and_sign::<Owners>(&ceremony, &claim, &salt),
        gates.commitment,
    )
    .unwrap();
    let pops: BTreeMap<_, _> = roster
        .iter()
        .zip(&secrets)
        .map(|(&id, secret)| {
            (
                id,
                Pop::prove_unchecked(&sealed, &claim, id, secret).unwrap(),
            )
        })
        .collect();
    let endorsements = seat_endorsements::<Owners>(&ceremony, &claim, &secrets);
    let owner_reveal = ComponentReveal::assemble(&sealed, claim, pops, endorsements, salt).unwrap();
    let artifact = sealed
        .open(owner_reveal, gates.reveal(&sealed), &parties())
        .expect("all algebra, identity and possession checks really pass");

    let view = RistrettoPrivate::from(Scalar::random(&mut rng));
    let tx_public = RistrettoPublic::from(&RistrettoPrivate::from(Scalar::random(&mut rng)));
    let deposit = RistrettoPublic::from(
        artifact.declared_root() + subaddress_offset(view.as_ref(), SUBADDRESS) * G,
    );
    let audited = audit_address(&artifact, &parties(), &view, SUBADDRESS, &deposit).unwrap();
    let spend = CompositeSpend::from_ceremony(&audited, &view, &tx_public).unwrap();
    let auth = authorize_release(&spend, &parties())
        .expect("the funding gate checks provenance, attribution and declared shape");
    assert_eq!(deposit_spend_key(&auth), deposit);
    assert_eq!(audited.root().owner_structure().threshold(), 2);

    // Only owner seat 1's share is read here. Add the genuine one-seat gate
    // and the view service's public-policy term: two seats suffice despite the
    // advertised 2-owner + 1-gate shape. Confirm through the stock verifier.
    let owner_component = secrets[0] * Scalar::from(2u64).invert();
    let gate_component = own_share_scalar(&gates, Gates::nth(0));
    let x = owner_component + gate_component + spend.common();
    assert_eq!(x * G, *spend.target().as_ref());
    let (blinding, output_blinding) = (Scalar::from(9u64), Scalar::from(4u64));
    let (ring, gens) = make_ring_from_seed(&spend, 11, 5, 5_000, &blinding, 0xC077);
    let output = CompressedCommitment::from(&Commitment::new(5_000, output_blinding, &gens));
    let message = b"correlated dealing: one owner and the gate release";
    let session_id = [0x71; 32];
    let signature = sign(
        SessionParams {
            session_id: &session_id,
            message,
            ring: &ring,
            real_index: 5,
            output_commitment: &output,
        },
        vec![SpendSigner::view(&x)],
        MaskSigner::owner_held(&output_blinding, &blinding),
        &mut MemoryNonceGuard::new(),
        &mut rng,
    )
    .unwrap();
    signature.verify(message, &ring, &output).unwrap();
}
