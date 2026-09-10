//! The honest run, plus the transitions that must NOT be reachable.
//!
//! A positive control matters here: every other test file asserts that
//! something is refused, and a machine that refused everything would pass all
//! of them.

mod common;

use ceremony::machine::State;
use ceremony::{Authorizer, BindingStore, Error, ParticipantId, Subset};
use common::*;

#[test]
fn a_threshold_quorum_produces_a_signature_every_participant_verifies() {
    let fx = fixture(2, 3);
    let subset = Subset::new([ParticipantId(1), ParticipantId(2)]);
    let mut nodes = vec![fx.node(ParticipantId(1)), fx.node(ParticipantId(2))];
    let stmt = statement(b"release 250000 eUSD to R, block 12345");

    let sigs = run(&mut nodes, &stmt, &subset).expect("honest run completes");

    // Every node aggregated independently and got the same signature.
    assert_eq!(sigs[0], sigs[1]);
    for n in &nodes {
        assert_eq!(n.machine.state(), &State::Complete);
    }

    // And it verifies under the group key alone, which is what a MobileCoin
    // consensus node would be doing.
    let ctx = nodes[0].machine.context().unwrap();
    fx.public_verifier()
        .verify_signature(ctx, &sigs[0])
        .expect("aggregate verifies under the group public key");
}

#[test]
fn a_different_subset_of_the_same_roster_also_completes() {
    // 2-of-3 with {1,3} rather than {1,2}: the Lagrange weights differ, so this
    // is not the previous test with renamed participants.
    let fx = fixture(2, 3);
    let subset = Subset::new([ParticipantId(1), ParticipantId(3)]);
    let mut nodes = vec![fx.node(ParticipantId(1)), fx.node(ParticipantId(3))];
    let stmt = statement(b"release 250000 eUSD to R, block 12345");
    let sigs = run(&mut nodes, &stmt, &subset).expect("honest run completes");
    assert_eq!(sigs[0], sigs[1]);
}

#[test]
fn round_two_before_round_one_is_complete_is_refused() {
    let fx = fixture(2, 3);
    let subset = Subset::new([ParticipantId(1), ParticipantId(2)]);
    let mut node = fx.node(ParticipantId(1));
    node.machine
        .begin(statement(b"m"), subset.clone())
        .expect("begin");

    assert_eq!(
        node.machine.round_two().unwrap_err(),
        Error::IncompleteRoundOne { have: 1, need: 2 }
    );
    // Refused, not poisoned: the peer may still be about to send.
    assert_eq!(node.machine.state(), &State::CollectingRoundOne);
}

#[test]
fn calls_out_of_order_are_typed_errors_not_partial_work() {
    let fx = fixture(2, 3);
    let subset = Subset::new([ParticipantId(1), ParticipantId(2)]);
    let mut node = fx.node(ParticipantId(1));

    assert!(matches!(
        node.machine.round_two().unwrap_err(),
        Error::WrongState { .. }
    ));
    assert!(matches!(
        node.machine.finish().unwrap_err(),
        Error::WrongState { .. }
    ));
    // Nothing above touched the store, so no one-time value was consumed by a
    // mis-ordered call.
    assert_eq!(node.store.borrow().sequence(), 0);

    node.machine
        .begin(statement(b"m"), subset.clone())
        .expect("begin");
    assert!(matches!(
        node.machine.begin(statement(b"m"), subset).unwrap_err(),
        Error::WrongState { .. }
    ));
}

#[test]
fn a_participant_outside_the_subset_is_refused() {
    let fx = fixture(2, 3);
    let subset = Subset::new([ParticipantId(1), ParticipantId(2)]);
    let mut outsider = fx.node(ParticipantId(3));
    assert_eq!(
        outsider
            .machine
            .begin(statement(b"m"), subset)
            .unwrap_err(),
        Error::SelfNotInSubset(ParticipantId(3))
    );
}

#[test]
fn a_participant_not_on_the_roster_cannot_be_named_in_a_subset() {
    let fx = fixture(2, 3);
    let subset = Subset::new([ParticipantId(1), ParticipantId(9)]);
    let mut node = fx.node(ParticipantId(1));
    assert_eq!(
        node.machine.begin(statement(b"m"), subset).unwrap_err(),
        Error::UnknownParticipant(ParticipantId(9))
    );
}
