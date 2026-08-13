//! The composite-root algebra, and the one property the scheme rests on:
//! the key image does not depend on which quorums signed.
//!
//! Every test here was carried over from the `m2d-two-cohort` spike; the
//! asymmetric-cohort, unweighted-sum and per-participant-term tests are new.
//!
//! None of these can establish that the two cohorts are held by different
//! entities -- the algebra is identical either way. That claim lives in
//! `tests/control_domain.rs`, and these tests only hold their meaning because
//! it does.

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_crypto_ring_signature::{
    onetime_keys::recover_onetime_private_key, Commitment, CompressedCommitment, KeyImage,
    RingMLSAG,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use two_cohort::{
    derive::subaddress_offset, fixture::make_ring_from_seed, lagrange_at_zero, subsets_of,
    CohortSpec, CompositeSpend, ControlDomain, Error, Gates, Owners,
};

fn spend(seed: u64, k: usize, n: usize, g: usize, m: usize, index: u64) -> CompositeSpend {
    CompositeSpend::simulate_from_seed(
        seed,
        &CohortSpec::<Owners>::sequential(k, n),
        &CohortSpec::<Gates>::sequential(g, m),
        index,
    )
    .expect("well-formed cohort specs")
}

/// Owner ids by 1-based roster position. Owner and gate ids are drawn from
/// disjoint bands, so a test that wrote bare integers would be asserting
/// against the band layout rather than against the scheme.
fn owner_ids(positions: &[usize]) -> Vec<u64> {
    positions
        .iter()
        .map(|&p| Owners::nth(p as u64 - 1))
        .collect()
}

/// Gate ids by 1-based roster position.
fn gate_ids(positions: &[usize]) -> Vec<u64> {
    positions
        .iter()
        .map(|&p| Gates::nth(p as u64 - 1))
        .collect()
}

#[test]
fn cohorts_carry_independent_rosters_and_thresholds() {
    // 2-of-3 owners AND 1-of-1 gate: different sizes, different thresholds.
    // A design with one roster and one t/n shared between roles cannot
    // represent this at all.
    let s = spend(1, 2, 3, 1, 1, 0);
    assert_eq!(s.owners().threshold(), 2);
    assert_eq!(s.owners().n(), 3);
    assert_eq!(s.gates().threshold(), 1);
    assert_eq!(s.gates().n(), 1);
    assert_ne!(s.owners().n(), s.gates().n());

    // ...and each cohort's threshold binds only its own roster.
    assert!(
        s.owners().public(&owner_ids(&[1])).is_err(),
        "1 of 3 owners is below 2"
    );
    assert!(
        s.gates().public(&gate_ids(&[1])).is_ok(),
        "1 of 1 gate is a quorum"
    );
}

#[test]
fn composite_root_is_the_sum_of_the_two_cohort_publics() {
    let s = spend(2, 2, 3, 2, 3, 0);
    let root = s
        .composite_root(&owner_ids(&[1, 2]), &gate_ids(&[1, 2]))
        .unwrap();
    let offset = subaddress_offset(s.view_private().as_ref(), s.subaddress_index());
    // D_i = (B_owner + B_gate) + Hs(a || i) * G
    assert_eq!(
        s.spend_public().as_ref(),
        &(root + offset * RISTRETTO_BASEPOINT_POINT)
    );

    // Neither half alone is the root.
    assert_ne!(s.owners().public(&owner_ids(&[1, 2])).unwrap(), root);
    assert_ne!(s.gates().public(&gate_ids(&[1, 2])).unwrap(), root);
}

/// THE property. A key image that varied with the signing subset would give
/// one output several images, and MobileCoin deduplicates spends on the image.
#[test]
fn key_image_is_invariant_across_every_owner_gate_subset_pair() {
    let s = spend(3, 2, 3, 2, 3, 7);
    let reference = s
        .key_image_from_shares(&owner_ids(&[1, 2]), &gate_ids(&[1, 2]))
        .unwrap();

    let mut pairs = 0;
    for osub in subsets_of(s.owners().roster(), 2) {
        for gsub in subsets_of(s.gates().roster(), 2) {
            let assembled = s.key_image_from_shares(&osub, &gsub).unwrap();
            assert_eq!(
                assembled, reference,
                "key image varied at owners {osub:?} gates {gsub:?} -- \
                 a subset-dependent image permits a double spend"
            );

            // Differential: upstream's own KeyImage derivation, which uses
            // MobileCoin's private hash_to_point and takes the image as
            // x * Hp(x*G). Agreement pins both this crate's hash_to_point and
            // its claim that the assembled point is the image of a key whose
            // public form really is the output's target key.
            let x = RistrettoPrivate::from(*s.onetime(&osub, &gsub).unwrap());
            assert_eq!(KeyImage::from(&x).point, assembled.compress());
            pairs += 1;
        }
    }
    assert_eq!(pairs, 9, "every 2-of-3 x 2-of-3 pair");
}

/// The same claim where the two cohorts share neither size nor threshold, over
/// the full 10 x 6 product. Equal-shaped cohorts could hide an accidental
/// dependence on cohort geometry; these cannot.
#[test]
fn key_image_is_invariant_across_asymmetric_cohorts() {
    let s = spend(31, 3, 5, 2, 4, 11);
    let reference = s
        .key_image_from_shares(&owner_ids(&[1, 2, 3]), &gate_ids(&[1, 2]))
        .unwrap();

    let osubs = subsets_of(s.owners().roster(), 3);
    let gsubs = subsets_of(s.gates().roster(), 2);
    assert_eq!((osubs.len(), gsubs.len()), (10, 6));

    let mut pairs = 0;
    for osub in &osubs {
        for gsub in &gsubs {
            assert_eq!(
                s.key_image_from_shares(osub, gsub).unwrap(),
                reference,
                "key image varied at owners {osub:?} gates {gsub:?}"
            );
            pairs += 1;
        }
    }
    assert_eq!(pairs, 60);
}

#[test]
fn one_time_key_is_invariant_and_matches_upstream() {
    let s = spend(4, 2, 3, 2, 3, 1);
    let x = s.onetime(&owner_ids(&[1, 2]), &gate_ids(&[2, 3])).unwrap();
    for osub in subsets_of(s.owners().roster(), 2) {
        for gsub in subsets_of(s.gates().roster(), 2) {
            assert_eq!(*s.onetime(&osub, &gsub).unwrap(), *x);
        }
    }

    // The one-time key really is the private key for the output's target key.
    assert_eq!(
        RistrettoPublic::from(&RistrettoPrivate::from(*x)),
        *s.target()
    );

    // Differential against upstream recovery. This pins this crate's
    // hash_to_scalar, not its subaddress_offset -- the offset is supplied to
    // both sides here, and is pinned separately in tests/vectors.rs against
    // MobileCoin's published account-key vectors.
    let offset = subaddress_offset(s.view_private().as_ref(), s.subaddress_index());
    let b_owner = s.owners().reconstruct(&owner_ids(&[1, 2])).unwrap();
    let b_gate = s.gates().reconstruct(&gate_ids(&[1, 2])).unwrap();
    let d = RistrettoPrivate::from(offset + *b_owner + *b_gate);
    let upstream = recover_onetime_private_key(s.tx_public(), s.view_private(), &d);
    let upstream_scalar: &Scalar = upstream.as_ref();
    assert_eq!(*upstream_scalar, *x);
}

#[test]
fn an_owner_quorum_without_gates_reaches_a_different_key_image() {
    let s = spend(5, 2, 3, 2, 3, 0);
    let full = s
        .key_image_from_shares(&owner_ids(&[1, 2]), &gate_ids(&[1, 2]))
        .unwrap();
    let no_gate = s.key_image_without_gates(&owner_ids(&[1, 2])).unwrap();
    assert_ne!(full, no_gate);

    // And the difference is exactly the gate cohort's contribution -- checked
    // additively, so this is not merely "two points happened to differ".
    let terms = s
        .key_image_terms(&owner_ids(&[1, 2]), &gate_ids(&[1, 2]))
        .unwrap();
    let gate_term: curve25519_dalek::ristretto::RistrettoPoint =
        terms.gate_terms.iter().map(|(_, p)| p).sum();
    assert_eq!(full, no_gate + gate_term);

    // No gate subset is optional: dropping the gates is not a weaker
    // signature, it is a different image, which belongs to no ring member.
    for gsub in subsets_of(s.gates().roster(), 2) {
        assert_ne!(
            s.key_image_from_shares(&owner_ids(&[1, 2]), &gsub).unwrap(),
            no_gate
        );
    }
}

#[test]
fn stock_verifier_accepts_a_two_cohort_signature() {
    let s = spend(6, 2, 3, 2, 3, 0);
    let (value, blinding, out_blinding) = (5_000u64, Scalar::from(9u64), Scalar::from(4u64));
    let (ring, gens) = make_ring_from_seed(&s, 11, 5, value, &blinding, 0xD2D);

    let x = RistrettoPrivate::from(*s.onetime(&owner_ids(&[1, 3]), &gate_ids(&[2, 3])).unwrap());
    let mut rng = ChaCha20Rng::seed_from_u64(77);
    let sig = RingMLSAG::sign(
        b"two-cohort",
        &ring,
        5,
        &x,
        value,
        &blinding,
        &out_blinding,
        &gens,
        &mut rng,
    )
    .expect("sign");

    let out = CompressedCommitment::from(&Commitment::new(value, out_blinding, &gens));
    sig.verify(b"two-cohort", &ring, &out)
        .expect("unmodified RingMLSAG::verify must accept a two-cohort composite signature");
    assert_eq!(sig.key_image, KeyImage::from(&x));

    // The image the verifier accepted is the one assembled from shares.
    assert_eq!(
        sig.key_image.point,
        s.key_image_from_shares(&owner_ids(&[1, 3]), &gate_ids(&[2, 3]))
            .unwrap()
            .compress()
    );
}

#[test]
fn stock_verifier_accepts_every_subset_pair_and_all_agree_on_the_key_image() {
    let s = spend(7, 2, 3, 2, 3, 3);
    let (value, blinding, out_blinding) = (1_500u64, Scalar::from(2u64), Scalar::from(6u64));
    let (ring, gens) = make_ring_from_seed(&s, 11, 0, value, &blinding, 0xD2E);
    let out = CompressedCommitment::from(&Commitment::new(value, out_blinding, &gens));

    let mut seen: Option<KeyImage> = None;
    let mut count = 0u64;
    for osub in subsets_of(s.owners().roster(), 2) {
        for gsub in subsets_of(s.gates().roster(), 2) {
            let x = RistrettoPrivate::from(*s.onetime(&osub, &gsub).unwrap());
            // Fresh nonces per signature; only the key image is supposed to
            // repeat across sessions.
            let mut rng = ChaCha20Rng::seed_from_u64(1000 + count);
            let sig = RingMLSAG::sign(
                b"two-cohort",
                &ring,
                0,
                &x,
                value,
                &blinding,
                &out_blinding,
                &gens,
                &mut rng,
            )
            .expect("sign");
            sig.verify(b"two-cohort", &ring, &out)
                .expect("stock verify");

            match &seen {
                None => seen = Some(sig.key_image),
                Some(first) => assert_eq!(
                    *first, sig.key_image,
                    "different subsets produced different key images at \
                     owners {osub:?} gates {gsub:?}"
                ),
            }
            count += 1;
        }
    }
    assert_eq!(count, 9);
}

#[test]
fn below_threshold_subsets_are_rejected() {
    let s = spend(8, 2, 3, 2, 3, 0);
    for err in [
        s.owners().weighted(&owner_ids(&[1])).unwrap_err(),
        s.gates().weighted(&gate_ids(&[2])).unwrap_err(),
        s.onetime(&owner_ids(&[1]), &gate_ids(&[1, 2])).unwrap_err(),
        s.key_image_from_shares(&owner_ids(&[1, 2]), &gate_ids(&[3]))
            .unwrap_err(),
    ] {
        assert!(
            matches!(
                err.kind(),
                Error::BelowThreshold {
                    have: 1,
                    threshold: 2
                }
            ),
            "expected a threshold rejection, got {err}"
        );
    }
}

/// Known-answer test. The Lagrange basis polynomials at 0 over small integer
/// point sets are hand-computable from
/// `lambda_i = prod_{j != i} x_j / (x_j - x_i)`:
///
/// ```text
///     {1,2}      ->   2, -1
///     {2,3}      ->   3, -2
///     {1,2,3}    ->   3, -3,  1
///     {1,2,3,4}  ->   4, -6,  4, -1
/// ```
///
/// These are the values a correct implementation must produce; an
/// implementation that returned, say, 1 for every weight would pass a
/// round-trip test built out of itself but fails here.
#[test]
fn lagrange_weights_match_hand_computed_values() {
    fn s(i: i64) -> Scalar {
        if i >= 0 {
            Scalar::from(i as u64)
        } else {
            -Scalar::from((-i) as u64)
        }
    }

    let cases: &[(&[u64], &[i64])] = &[
        (&[1, 2], &[2, -1]),
        (&[2, 3], &[3, -2]),
        (&[1, 2, 3], &[3, -3, 1]),
        (&[1, 2, 3, 4], &[4, -6, 4, -1]),
    ];

    for (subset, expected) in cases {
        let mut total = Scalar::ZERO;
        for (&id, &want) in subset.iter().zip(expected.iter()) {
            let got = lagrange_at_zero(id, subset).unwrap();
            assert_eq!(got, s(want), "lambda_{id} over {subset:?}");
            total += got;
        }
        // Interpolating the constant polynomial 1 at 0 gives 1, so the weights
        // of any subset sum to 1. Independent of the values above.
        assert_eq!(total, Scalar::ONE, "weights over {subset:?} must sum to 1");
    }
}

/// Establishes that the invariance claim is not vacuous: the naive
/// combination -- adding raw shares -- IS subset-dependent. The Lagrange
/// weighting is what removes the dependence, so an implementation that got the
/// weights wrong would show up as a varying key image, which is exactly what
/// the invariance tests look for.
#[test]
fn unweighted_share_sums_are_subset_dependent_and_weighted_sums_are_not() {
    let s = spend(9, 2, 3, 2, 3, 0);

    let raw = |ids: &[u64]| -> Scalar {
        ids.iter()
            .map(|&id| *s.owners().share(id).unwrap())
            .sum::<Scalar>()
    };
    assert_ne!(
        raw(&owner_ids(&[1, 2])),
        raw(&owner_ids(&[1, 3])),
        "raw share sums are supposed to differ; if they did not, the \
         weighted-sum invariance below would be establishing nothing"
    );
    assert_ne!(raw(&owner_ids(&[1, 2])), raw(&owner_ids(&[2, 3])));

    let weighted = |ids: &[u64]| *s.owners().reconstruct(ids).unwrap();
    assert_eq!(weighted(&owner_ids(&[1, 2])), weighted(&owner_ids(&[1, 3])));
    assert_eq!(weighted(&owner_ids(&[1, 2])), weighted(&owner_ids(&[2, 3])));

    // And a raw sum is not the secret: it does not reproduce the public key.
    assert_ne!(
        raw(&owner_ids(&[1, 2])) * RISTRETTO_BASEPOINT_POINT,
        s.owners().public(&owner_ids(&[1, 2])).unwrap()
    );
}

/// The exposed per-participant terms are the ones a group-combining signer
/// would use, so they have to add up to the image the verifier accepts.
#[test]
fn per_participant_terms_sum_to_the_accepted_key_image() {
    let s = spend(10, 3, 5, 2, 4, 2);
    let (osub, gsub) = (owner_ids(&[2, 4, 5]), gate_ids(&[1, 3]));

    let terms = s.key_image_terms(&osub, &gsub).unwrap();
    assert_eq!(terms.owner_terms.len(), 3);
    assert_eq!(terms.gate_terms.len(), 2);
    assert_eq!(
        terms
            .owner_terms
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>(),
        osub
    );

    let x = RistrettoPrivate::from(*s.onetime(&osub, &gsub).unwrap());
    assert_eq!(terms.key_image(), KeyImage::from(&x));

    // Every term is load-bearing: drop any one and the sum moves.
    let full = terms.sum();
    for (id, point) in terms.owner_terms.iter().chain(terms.gate_terms.iter()) {
        assert_ne!(full - point, full, "term for participant {id} was zero");
    }
    assert_ne!(full - terms.view_term, full);
}
