//! Degenerate configurations, and the reason each one is refused.
//!
//! These are rejections rather than panics because every one of them is
//! reachable from a roster a human types.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
    traits::Identity,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use two_cohort::{lagrange_at_zero, CohortSpec, Cohort, CompositeSpend, Error};
use zeroize::Zeroize;

fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

fn secret() -> Scalar {
    Scalar::from(0x5EC2E7u64)
}

fn deal(threshold: usize, ids: &[u64]) -> Result<Cohort, Error> {
    Cohort::deal("owners", &secret(), threshold, ids, &mut rng(1))
}

#[test]
fn threshold_zero_is_rejected() {
    // A 0-of-n cohort authorises everybody: the empty subset qualifies.
    let err = deal(0, &[1, 2, 3]).unwrap_err();
    assert!(matches!(err.kind(), Error::ThresholdZero), "{err}");
}

#[test]
fn threshold_above_the_roster_is_rejected() {
    // Unmeetable thresholds do not protect funds, they strand them.
    let err = deal(4, &[1, 2, 3]).unwrap_err();
    assert!(
        matches!(
            err.kind(),
            Error::ThresholdExceedsRoster {
                threshold: 4,
                roster: 3
            }
        ),
        "{err}"
    );
    // The boundary is inclusive: n-of-n is a legitimate cohort.
    assert!(deal(3, &[1, 2, 3]).is_ok());
}

#[test]
fn an_empty_roster_is_rejected() {
    let err = deal(1, &[]).unwrap_err();
    assert!(matches!(err.kind(), Error::EmptyRoster), "{err}");
}

#[test]
fn duplicate_participant_ids_are_rejected_at_dealing() {
    let err = deal(2, &[1, 2, 2]).unwrap_err();
    assert!(matches!(err.kind(), Error::DuplicateParticipant(2)), "{err}");
}

/// Participant id 0 is refused because 0 is the interpolation point: the
/// Shamir polynomial's value there IS the secret. The first half of this test
/// demonstrates that directly rather than asserting it in a comment.
#[test]
fn participant_id_zero_is_rejected_because_it_would_hold_the_secret() {
    // A 2-of-n polynomial, built here so the demonstration owes nothing to the
    // code under test: p(x) = secret + c1 * x.
    let c1 = Scalar::from(1234567u64);
    let p = |x: Scalar| secret() + c1 * x;
    assert_eq!(p(Scalar::ZERO), secret(), "p(0) is the secret by construction");
    assert_ne!(p(Scalar::ONE), secret(), "p(1) is a share, not the secret");

    // So a participant issued id 0 would be handed the secret outright,
    // whatever the threshold says.
    let err = deal(2, &[0, 1, 2]).unwrap_err();
    assert!(matches!(err.kind(), Error::ReservedParticipantId), "{err}");

    // Also refused when 0 is the only id, and when it appears late.
    assert!(matches!(
        deal(1, &[0]).unwrap_err().kind(),
        Error::ReservedParticipantId
    ));
    assert!(matches!(
        deal(2, &[1, 2, 0]).unwrap_err().kind(),
        Error::ReservedParticipantId
    ));
}

/// A repeated id inside a signing subset is not a harmless duplicate: the
/// Lagrange weight for an id is computed over the OTHER points, so a
/// duplicate-tolerant implementation would count one share twice at a weight
/// derived from a subset that no longer matches.
#[test]
fn duplicate_ids_within_a_signing_subset_are_rejected() {
    let cohort = deal(2, &[1, 2, 3]).unwrap();
    let (s1, s2) = (
        *cohort.share(1).unwrap(),
        *cohort.share(2).unwrap(),
    );
    let l1 = lagrange_at_zero(1, &[1, 2]).unwrap();
    let l2 = lagrange_at_zero(2, &[1, 2]).unwrap();

    let honest = l1 * s1 + l2 * s2;
    assert_eq!(honest, secret(), "2-of-3 reconstruction over {{1,2}}");

    // What counting id 1 twice would produce.
    let doubled = l1 * s1 + l1 * s1 + l2 * s2;
    assert_ne!(doubled, secret());

    let err = cohort.weighted(&[1, 1, 2]).unwrap_err();
    assert!(matches!(err.kind(), Error::DuplicateParticipant(1)), "{err}");

    // A duplicate must not be able to fake a quorum either: {1,1} is one
    // participant, not two.
    let err = cohort.weighted(&[1, 1]).unwrap_err();
    assert!(matches!(err.kind(), Error::DuplicateParticipant(1)), "{err}");
}

#[test]
fn ids_outside_the_roster_are_rejected() {
    let cohort = deal(2, &[1, 2, 3]).unwrap();
    let err = cohort.weighted(&[1, 9]).unwrap_err();
    assert!(matches!(err.kind(), Error::UnknownParticipant(9)), "{err}");
    assert!(matches!(
        cohort.share(9).unwrap_err().kind(),
        Error::UnknownParticipant(9)
    ));

    // Non-sequential rosters are legitimate; 9 is only unknown here because
    // this roster is 1..=3.
    let sparse = Cohort::deal("owners", &secret(), 2, &[9, 40, 41], &mut rng(2)).unwrap();
    assert!(sparse.weighted(&[9, 41]).is_ok());
    assert_eq!(
        *sparse.reconstruct(&[9, 41]).unwrap(),
        secret(),
        "interpolation must not assume ids are 1..=n"
    );
}

#[test]
fn lagrange_at_zero_validates_its_own_arguments() {
    assert!(matches!(
        lagrange_at_zero(1, &[]).unwrap_err(),
        Error::EmptyRoster
    ));
    assert!(matches!(
        lagrange_at_zero(0, &[0, 1]).unwrap_err(),
        Error::ReservedParticipantId
    ));
    assert!(matches!(
        lagrange_at_zero(1, &[1, 1, 2]).unwrap_err(),
        Error::DuplicateParticipant(1)
    ));
    assert!(matches!(
        lagrange_at_zero(5, &[1, 2]).unwrap_err(),
        Error::UnknownParticipant(5)
    ));
}

#[test]
fn errors_name_the_cohort_that_rejected_the_input() {
    // The two cohorts have different rosters and thresholds, so an operator
    // reading the failure needs to know which one it got wrong.
    let owners = CohortSpec::sequential("owners", 2, 3);
    let gates = CohortSpec::sequential("gates", 2, 3);
    let s = CompositeSpend::simulate_from_seed(20, &owners, &gates, 0).unwrap();

    let owner_err = s.onetime(&[1], &[1, 2]).unwrap_err().to_string();
    assert!(owner_err.contains("owners"), "{owner_err}");
    assert!(!owner_err.contains("gates"), "{owner_err}");

    let gate_err = s.onetime(&[1, 2], &[1]).unwrap_err().to_string();
    assert!(gate_err.contains("gates"), "{gate_err}");
}

#[test]
fn a_cohort_spec_with_a_bad_roster_fails_the_whole_setup() {
    let owners = CohortSpec::sequential("owners", 2, 3);
    let bad_gates = CohortSpec::with_ids("gates", 1, &[0]);
    let err = CompositeSpend::simulate_from_seed(21, &owners, &bad_gates, 0).unwrap_err();
    assert!(matches!(err.kind(), Error::ReservedParticipantId), "{err}");
    assert!(err.to_string().contains("gates"), "{err}");
}

/// Debug output is the easiest way for a secret to end up in a log file, so
/// the secret-bearing types redact themselves.
#[test]
fn debug_formatting_does_not_leak_shares() {
    let cohort = deal(2, &[1, 2, 3]).unwrap();
    let rendered = format!("{cohort:?}");
    for id in cohort.roster() {
        let share = hex::encode(cohort.share(*id).unwrap().as_bytes());
        assert!(
            !rendered.contains(&share),
            "share for participant {id} appeared in Debug output"
        );
    }
    assert!(rendered.contains("owners") && rendered.contains("redacted"));

    let term = &cohort.weighted(&[1, 2]).unwrap()[0];
    let rendered = format!("{term:?}");
    assert!(!rendered.contains(&hex::encode(term.weight().as_bytes())));

    let owners = CohortSpec::sequential("owners", 2, 3);
    let gates = CohortSpec::sequential("gates", 2, 3);
    let s = CompositeSpend::simulate_from_seed(22, &owners, &gates, 0).unwrap();
    let rendered = format!("{s:?}");
    assert!(!rendered.contains(&hex::encode(s.common().as_bytes())));
    let view: &Scalar = s.view_private().as_ref();
    assert!(!rendered.contains(&hex::encode(view.as_bytes())));
}

/// Establishes that the zeroize wiring is real -- the derive is present and
/// clears the secret field. It does NOT establish that dropped memory is
/// scrubbed: `Scalar` is `Copy`, so copies the compiler makes in registers or
/// on the stack are outside this crate's reach. See the crate-level docs.
#[test]
fn participant_terms_zeroize_their_weight() {
    let cohort = deal(2, &[1, 2, 3]).unwrap();
    let mut terms = cohort.weighted(&[1, 2]).unwrap();
    assert_ne!(*terms[0].weight(), Scalar::ZERO);

    terms[0].zeroize();
    assert_eq!(*terms[0].weight(), Scalar::ZERO);
    // A zeroized term contributes nothing, which is the point: it is no longer
    // usable as the participant's contribution.
    assert_eq!(
        terms[0].in_group(&RISTRETTO_BASEPOINT_POINT),
        RistrettoPoint::identity()
    );
}
