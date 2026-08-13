//! PROPERTY 4 -- a sub-threshold subset cannot complete a ceremony.
//!
//! The guard is one comparison, so the test that matters is the one showing it
//! guards something: below threshold the backend's shares still verify
//! individually and the aggregate still does not verify. The machine's refusal
//! is an early, attributable version of a failure that is real either way.
//!
//! The second half of the file is about the thresholds themselves: a roster or
//! a dealing that is degenerate on its face must be refused, and refused as a
//! value rather than a process abort.

mod common;

use ceremony::frost::{deal, lagrange, FrostError};
use ceremony::machine::{Ceremony, Roster};
use ceremony::{
    Authorizer, BindingStore, Error, MemoryAnchor, MemoryStore, ParticipantId, RoundOnePackage,
    SigningContext, Subset,
};
use common::*;

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::cell::RefCell;
use std::rc::Rc;

const P1: ParticipantId = ParticipantId(1);
const P2: ParticipantId = ParticipantId(2);
const P3: ParticipantId = ParticipantId(3);
const P4: ParticipantId = ParticipantId(4);

/// THE GUARD. Delete the `subset.len() < threshold` check in `Ceremony::begin`
/// and this fails.
#[test]
fn a_sub_threshold_subset_is_refused_before_any_one_time_value_exists() {
    let fx = fixture(3, 4);
    let mut node = fx.node(P1);
    let err = node
        .machine
        .begin(statement(b"m"), Subset::new([P1, P2]))
        .unwrap_err();
    assert_eq!(err, Error::SubThreshold { have: 2, need: 3 });

    // Refused early enough that no one-time value was created and nothing was
    // written: an abandoned partial run is material an adversary can combine
    // with a later one.
    assert_eq!(node.store.borrow().sequence(), 0);
}

/// What the guard is guarding: two of a three-threshold sharing, driving the
/// backend directly. Each share passes its own verification equation -- the
/// failure is not local to any participant -- and the aggregate does not verify.
#[test]
fn a_sub_threshold_quorum_bypassing_the_machine_produces_an_invalid_signature() {
    let fx = fixture(3, 4);
    let subset = Subset::new([P1, P2]);
    let stmt = statement(b"release 250000 eUSD to R, block 12345");

    let mut signers = vec![(P1, fx.signer(P1)), (P2, fx.signer(P2))];
    let mut package = RoundOnePackage::new();
    let mut slots = Vec::new();
    for (id, s) in signers.iter_mut() {
        let (slot, c) = s.round_one().unwrap();
        package.insert(*id, c);
        slots.push((*id, slot));
    }
    let ctx = SigningContext::new(stmt, subset, package);

    let mut shares = Vec::new();
    for ((id, s), (_, slot)) in signers.iter_mut().zip(slots.iter()) {
        // Bypassing the machine, not the store: each signer still binds its own
        // one-time value, since without that it has no receipt and no share.
        let mut store = MemoryStore::new();
        store.reserve(*slot).unwrap();
        let receipt = store.bind(*slot, ctx.id()).unwrap();
        let share = s.round_two(*slot, &ctx, &receipt).unwrap();
        fx.public_verifier()
            .verify_share(&ctx, *id, &share)
            .expect("each share is individually well formed");
        shares.push((*id, share));
    }

    let sig = fx.public_verifier().aggregate(&ctx, &shares).unwrap();
    assert!(
        fx.public_verifier().verify_signature(&ctx, &sig).is_err(),
        "two of a three-threshold sharing must not produce a valid signature"
    );
}

/// Positive control: exactly-threshold completes and verifies, so the guard is
/// not simply rejecting everything.
#[test]
fn an_exactly_threshold_subset_completes() {
    let fx = fixture(3, 4);
    let subset = Subset::new([P2, P3, P4]);
    let stmt = statement(b"release 250000 eUSD to R, block 12345");
    let mut nodes = vec![fx.node(P2), fx.node(P3), fx.node(P4)];

    let sigs = run(&mut nodes, &stmt, &subset).expect("threshold quorum completes");
    assert_eq!(sigs[0], sigs[1]);
    assert_eq!(sigs[1], sigs[2]);
    fx.public_verifier()
        .verify_signature(nodes[0].machine.context().unwrap(), &sigs[0])
        .expect("aggregate verifies");
}

/// A quorum that starts at threshold and then loses a member cannot finish with
/// what it has: `finish` needs a share from every member of the subset it
/// committed to in round one. Threshold is a floor on who must answer, not a
/// count that can be met by whoever is left.
#[test]
fn a_quorum_that_drops_a_member_mid_ceremony_cannot_finish() {
    let fx = fixture(3, 4);
    let subset = Subset::new([P1, P2, P3]);
    let stmt = statement(b"release 250000 eUSD to R, block 12345");

    let store = Rc::new(RefCell::new(MemoryStore::new()));
    let anchor = Rc::new(RefCell::new(MemoryAnchor::new()));
    let mut machine = Ceremony::new(
        fx.roster.clone(),
        P1,
        identity(P1),
        store,
        anchor,
        fx.signer(P1),
    );
    machine.begin(stmt.clone(), subset.clone()).expect("begin");
    for id in [P2, P3] {
        let mut s = fx.signer(id);
        machine
            .receive_round_one(ceremony::SignedRoundOne::create(
                &identity(id),
                id,
                stmt.clone(),
                subset.clone(),
                s.round_one().unwrap().1,
            ))
            .expect("peer round one");
    }
    machine.round_two().expect("we sign");

    // Both peers go quiet after round one.
    assert_eq!(
        machine.finish().unwrap_err(),
        Error::IncompleteRoundTwo { have: 1, need: 3 }
    );
}

// ------------------------------------------------- degenerate configurations

/// The underlying roster complaint, with the cohort-name wrapper stripped.
fn refusal(err: &FrostError) -> &two_cohort::Error {
    match err {
        FrostError::Sharing(e) => e.kind(),
        other => panic!("expected a sharing refusal, got {other}"),
    }
}

fn dealt(threshold: u16, ids: &[ParticipantId]) -> Result<(), FrostError> {
    deal(threshold, ids, &mut ChaCha20Rng::seed_from_u64(4)).map(|_| ())
}

/// Every one of these is reachable from a config file a human types, so each
/// has to come back as a value the caller can act on. A signing service that
/// aborts the process on bad config can be taken down by bad config.
///
/// Participant id 0 is the sharpest of them: 0 is the interpolation point, so
/// the polynomial's value there IS the group secret and a participant issued
/// that id holds the whole signing key alone, whatever the threshold says.
/// `two-cohort`'s `participant_id_zero_is_rejected_because_it_would_hold_the_secret`
/// demonstrates that from the polynomial; what this asserts is that the
/// ceremony's dealer inherits the refusal instead of issuing the key.
#[test]
fn degenerate_dealings_are_refused_rather_than_aborting() {
    let ids = [P1, P2, P3];
    assert!(dealt(3, &ids).is_ok(), "n-of-n is a legitimate dealing");

    let empty: [ParticipantId; 0] = [];
    let cases: [(&[ParticipantId], u16, two_cohort::Error); 4] = [
        (&ids, 0, two_cohort::Error::ThresholdZero),
        (
            &ids,
            4,
            two_cohort::Error::ThresholdExceedsRoster {
                threshold: 4,
                roster: 3,
            },
        ),
        (&empty, 1, two_cohort::Error::EmptyRoster),
        (
            &[ParticipantId(0), P1, P2],
            2,
            two_cohort::Error::ReservedParticipantId,
        ),
    ];

    for (roster, threshold, want) in cases {
        let err = dealt(threshold, roster).unwrap_err();
        assert_eq!(refusal(&err), &want, "dealing {threshold} over {roster:?}");
    }
}

/// A weight is only meaningful for a participant that is in the subset. The
/// formula happily returns a well-formed scalar for one that is not, and a
/// share built on it would be silently wrong -- not invalid, wrong.
#[test]
fn a_lagrange_weight_outside_the_subset_is_an_error_not_a_number() {
    let subset = Subset::new([P1, P2]);
    assert!(lagrange(&subset, P1).is_ok());
    let err = lagrange(&subset, P4).unwrap_err();
    assert_eq!(
        refusal(&err),
        &two_cohort::Error::UnknownParticipant(P4.0 as u64)
    );
}

/// Zero authorises every subset; a threshold above the roster authorises none
/// and strands the funds. Neither is a state the machine should be able to
/// start in.
#[test]
fn a_degenerate_roster_threshold_is_refused() {
    let fx = fixture(2, 3);
    let members: Vec<_> = fx
        .ids
        .iter()
        .map(|id| (*id, identity(*id).public()))
        .collect();

    assert_eq!(
        Roster::new(members.clone(), 0).unwrap_err(),
        Error::ThresholdZero
    );
    assert_eq!(
        Roster::new(members.clone(), 4).unwrap_err(),
        Error::ThresholdExceedsRoster {
            threshold: 4,
            roster: 3
        }
    );
    assert!(Roster::new(members, 3).is_ok(), "n-of-n is legitimate");
}

/// Participant id 0 must never be dealt a share.
///
/// Shamir evaluates the sharing polynomial at each participant's numeric id,
/// and `p(0)` is the secret itself -- so a participant numbered 0 does not hold
/// a share of the key, it holds the key. `ParticipantId` is a public tuple over
/// `u16`, so nothing in the type stops a caller writing `ParticipantId(0)`; an
/// operator id left at its default is exactly the config a human types.
///
/// Rejection comes from `two-cohort`'s roster validation, one crate away, which
/// is precisely why it is worth a test here: a refactor there would silently
/// unguard this one.
#[test]
fn participant_id_zero_is_never_dealt_a_share() {
    let ids = [ParticipantId(0), ParticipantId(1), ParticipantId(2)];
    let err = deal(2, &ids, &mut ChaCha20Rng::from_seed([9u8; 32])).expect_err(
        "dealing to participant 0 must be refused: p(0) is the secret, not a share",
    );
    // A value, not a panic -- a signing service that aborts on bad config can
    // be taken down with bad config.
    assert!(
        matches!(err, FrostError::Sharing(_)),
        "expected a typed rejection, got {err:?}"
    );

    // The same roster without the zero is fine, so this is not just refusing
    // every roster.
    deal(2, &[ParticipantId(1), ParticipantId(2)], &mut ChaCha20Rng::from_seed([9u8; 32]))
        .expect("a roster with no zero id must deal");
}
