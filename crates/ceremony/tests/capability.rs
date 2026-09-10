//! The durable-write capability.
//!
//! A `Receipt` is the machine's evidence that a durable write happened before a
//! share was produced. It is only worth that if the store that performed the
//! write is the only thing that can mint one, and if what it says is what the
//! store read back rather than what the caller asked for.
//!
//! The guard against a forged receipt is the type system, checked by the
//! `compile_fail` doctests on `store::Receipt`: there is no constructor to call
//! and no field to set. What is checked here is the other half -- that a
//! receipt which really was minted says what the store read back, so a backend
//! comparing its arguments against it is comparing them against storage.

mod common;

use ceremony::store::{BindingStore, MemoryStore, SlotRecord};
use ceremony::{Authorizer, Commitment, ParticipantId, RoundOnePackage, SigningContext, Subset};
use common::*;

const P1: ParticipantId = ParticipantId(1);
const P2: ParticipantId = ParticipantId(2);

fn a_context(mine: Commitment, peer: Commitment) -> SigningContext {
    let mut package = RoundOnePackage::new();
    package.insert(P1, mine);
    package.insert(P2, peer);
    SigningContext::new(
        statement(b"release 250000 eUSD to R, block 12345"),
        Subset::new([P1, P2]),
        package,
    )
}

/// A receipt for a slot that was only RESERVED is not a binding, and the
/// backend must not treat it as one.
#[test]
fn a_reservation_receipt_does_not_authorise_a_share() {
    let fx = fixture(2, 3);
    let mut victim = fx.signer(P1);
    let (slot, mine) = victim.round_one().unwrap();
    let mut peer = fx.signer(P2);
    let ctx = a_context(mine, peer.round_one().unwrap().1);

    let mut store = MemoryStore::new();
    let receipt = store.reserve(slot).expect("reserve");
    assert_eq!(receipt.record(), SlotRecord::Reserved);

    assert!(
        victim.round_two(slot, &ctx, &receipt).is_err(),
        "a reservation is not a binding"
    );
}

/// A receipt for a different context does not authorise this one.
#[test]
fn a_receipt_for_another_context_does_not_authorise_a_share() {
    let fx = fixture(2, 3);
    let mut victim = fx.signer(P1);
    let (slot, mine) = victim.round_one().unwrap();
    let mut peer = fx.signer(P2);
    let ctx_a = a_context(mine.clone(), peer.round_one().unwrap().1);
    let ctx_b = a_context(mine, peer.round_one().unwrap().1);
    assert_ne!(ctx_a.id(), ctx_b.id());

    let mut store = MemoryStore::new();
    store.reserve(slot).expect("reserve");
    let receipt = store.bind(slot, ctx_a.id()).expect("bind");

    assert!(
        victim.round_two(slot, &ctx_b, &receipt).is_err(),
        "the durable record binds this one-time value to another context"
    );
}

/// Positive control: a receipt from a store that really did bind the slot works.
#[test]
fn a_real_binding_authorises_exactly_one_share() {
    let fx = fixture(2, 3);
    let mut victim = fx.signer(P1);
    let (slot, mine) = victim.round_one().unwrap();
    let mut peer = fx.signer(P2);
    let ctx = a_context(mine, peer.round_one().unwrap().1);

    let mut store = MemoryStore::new();
    store.reserve(slot).expect("reserve");
    let receipt = store.bind(slot, ctx.id()).expect("bind");

    victim
        .round_two(slot, &ctx, &receipt)
        .expect("a durably bound one-time value produces a share");
    assert!(
        victim.round_two(slot, &ctx, &receipt).is_err(),
        "and only one: the one-time value is consumed"
    );
}
