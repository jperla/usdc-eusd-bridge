//! PROPERTY 4 -- a sub-threshold subset cannot complete a ceremony.
//!
//! The guard is one comparison, so the test that matters is the one showing it
//! guards something: below threshold the backend's shares still verify
//! individually and the aggregate still does not verify. The machine's refusal
//! is an early, attributable version of a failure that is real either way.

mod common;

use ceremony::machine::Ceremony;
use ceremony::store::Receipt;
use ceremony::{
    Authorizer, BindingStore, Error, MemoryAnchor, MemoryStore, ParticipantId, RoundOnePackage,
    SigningContext, Subset,
};
use common::*;

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
        let receipt = Receipt::issue(*slot, Some(ctx.id()), 1);
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
