//! PROPERTY 2 -- the one-time value is durably committed before anything
//! observable happens, and a store restored from an earlier snapshot cannot
//! re-bind a slot.
//!
//! Two separate claims, tested separately: ORDER (durable write precedes the
//! observable step) and ROLLBACK (the machine fails closed when the store is
//! rewound underneath it).

mod common;

use std::cell::RefCell;
use std::rc::Rc;

use ceremony::authorizer::Authorizer;
use ceremony::context::{Commitment, ContextId, Share, SigningContext, SlotId};
use ceremony::machine::{Ceremony, State};
use ceremony::store::{Anchor, AnchorError, BindingStore, Receipt, SlotRecord, StoreError};
use ceremony::{Error, MemoryAnchor, MemoryStore, ParticipantId, SignedRoundOne, Subset};
use common::*;

const P1: ParticipantId = ParticipantId(1);
const P2: ParticipantId = ParticipantId(2);

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    OneTimeValueCreated(SlotId),
    Reserved(SlotId),
    CommitmentPublished(SlotId),
    Bound(SlotId, ContextId),
    ShareProduced(SlotId),
}

type Log = Rc<RefCell<Vec<Event>>>;

/// Store wrapper that records when a write became durable.
struct LoggingStore {
    inner: Rc<RefCell<MemoryStore>>,
    log: Log,
}

impl BindingStore for LoggingStore {
    fn sequence(&self) -> u64 {
        self.inner.borrow().sequence()
    }
    fn reserve(&mut self, slot: SlotId) -> Result<Receipt, StoreError> {
        let r = self.inner.borrow_mut().reserve(slot)?;
        self.log.borrow_mut().push(Event::Reserved(slot));
        Ok(r)
    }
    fn bind(&mut self, slot: SlotId, context: ContextId) -> Result<Receipt, StoreError> {
        let r = self.inner.borrow_mut().bind(slot, context)?;
        self.log.borrow_mut().push(Event::Bound(slot, context));
        Ok(r)
    }
    fn lookup(&self, slot: SlotId) -> Option<SlotRecord> {
        self.inner.borrow().lookup(slot)
    }
}

/// Backend wrapper that records when a one-time value came into existence and
/// when a response -- the irreversible, externally observable act -- was made.
struct LoggingSigner {
    inner: Signer,
    log: Log,
}

impl Authorizer for LoggingSigner {
    type Signature = <Signer as Authorizer>::Signature;
    type Error = <Signer as Authorizer>::Error;

    fn round_one(&mut self) -> Result<(SlotId, Commitment), Self::Error> {
        let (slot, c) = self.inner.round_one()?;
        self.log.borrow_mut().push(Event::OneTimeValueCreated(slot));
        Ok((slot, c))
    }
    fn round_two(
        &mut self,
        slot: SlotId,
        context: &SigningContext,
        receipt: &Receipt,
    ) -> Result<Share, Self::Error> {
        let s = self.inner.round_two(slot, context, receipt)?;
        self.log.borrow_mut().push(Event::ShareProduced(slot));
        Ok(s)
    }
    fn verify_share(
        &self,
        context: &SigningContext,
        participant: ParticipantId,
        share: &Share,
    ) -> Result<(), Self::Error> {
        self.inner.verify_share(context, participant, share)
    }
    fn aggregate(
        &self,
        context: &SigningContext,
        shares: &[(ParticipantId, Share)],
    ) -> Result<Self::Signature, Self::Error> {
        self.inner.aggregate(context, shares)
    }
    fn verify_signature(
        &self,
        context: &SigningContext,
        signature: &Self::Signature,
    ) -> Result<(), Self::Error> {
        self.inner.verify_signature(context, signature)
    }
}

/// Swap the two blocks in `Ceremony::round_two` -- ask the backend first, write
/// to the store second -- and this test fails.
#[test]
fn every_durable_write_precedes_the_observable_step_it_protects() {
    let fx = fixture(2, 3);
    let subset = Subset::new([P1, P2]);
    let stmt = statement(b"release 250000 eUSD to R, block 12345");
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let backing = Rc::new(RefCell::new(MemoryStore::new()));

    let mut machine = Ceremony::new(
        fx.roster.clone(),
        P1,
        identity(P1),
        LoggingStore {
            inner: backing.clone(),
            log: log.clone(),
        },
        Rc::new(RefCell::new(MemoryAnchor::new())),
        LoggingSigner {
            inner: fx.signer(P1),
            log: log.clone(),
        },
    );

    let mine = machine.begin(stmt.clone(), subset.clone()).expect("begin");
    // begin() returning is the moment the commitment leaves this process.
    log.borrow_mut()
        .push(Event::CommitmentPublished(SlotId(0)));

    let mut peer = fx.signer(P2);
    machine
        .receive_round_one(SignedRoundOne::create(
            &identity(P2),
            P2,
            stmt.clone(),
            subset.clone(),
            peer.round_one().unwrap().1,
        ))
        .expect("peer round one");
    machine.round_two().expect("round two");

    let events = log.borrow().clone();
    let position = |want: &Event| events.iter().position(|e| e == want).expect("event missing");

    let created = position(&Event::OneTimeValueCreated(SlotId(0)));
    let reserved = position(&Event::Reserved(SlotId(0)));
    let published = position(&Event::CommitmentPublished(SlotId(0)));
    let bound = events
        .iter()
        .position(|e| matches!(e, Event::Bound(SlotId(0), _)))
        .expect("bind happened");
    let produced = position(&Event::ShareProduced(SlotId(0)));

    assert!(created < reserved && reserved < published,
        "a one-time value must be durable before its commitment is published: {events:?}");
    assert!(
        bound < produced,
        "the binding must be durable before the share exists: {events:?}"
    );
    assert!(mine.commitment.0.len() == 64);
}

/// THE GUARD. The store is rolled back to a snapshot taken before the first
/// ceremony; the anchor did not roll back with it, and the machine refuses.
///
/// Remove the `observe` calls from `Ceremony::round_two`/`begin`, or the
/// `sequence < high_water` arm of `MemoryAnchor::observe`, and this test fails
/// -- the second ceremony signs, over a one-time value already used, which is
/// the key-recovery case in `one_time_values.rs`.
#[test]
fn a_rolled_back_store_makes_the_signer_fail_closed() {
    let fx = fixture(2, 3);
    let subset = Subset::new([P1, P2]);
    let stmt = statement(b"release 250000 eUSD to R, block 12345");

    let store = Rc::new(RefCell::new(MemoryStore::new()));
    let anchor = Rc::new(RefCell::new(MemoryAnchor::new()));
    let pristine = fx.signer(P1);
    let mut peer = fx.signer(P2);

    let before = store.borrow().snapshot();

    let mut first = Ceremony::new(
        fx.roster.clone(),
        P1,
        identity(P1),
        store.clone(),
        anchor.clone(),
        pristine.clone(),
    );
    first.begin(stmt.clone(), subset.clone()).expect("begin");
    first
        .receive_round_one(SignedRoundOne::create(
            &identity(P2),
            P2,
            stmt.clone(),
            subset.clone(),
            peer.round_one().unwrap().1,
        ))
        .expect("peer round one");
    first.round_two().expect("first ceremony signs");
    let reached = store.borrow().sequence();
    assert!(reached >= 2);

    // The restore: disk image from before the ceremony, signer from before the
    // ceremony. Nothing in either of them remembers the signature that exists.
    store.borrow_mut().restore(&before);
    assert_eq!(store.borrow().sequence(), 0);
    assert_eq!(store.borrow().lookup(SlotId(0)), None);

    let mut second = Ceremony::new(
        fx.roster.clone(),
        P1,
        identity(P1),
        store.clone(),
        anchor.clone(),
        pristine.clone(),
    );
    let err = second
        .begin(stmt.clone(), subset.clone())
        .expect_err("rollback must be refused");
    assert_eq!(
        err,
        Error::Rollback(AnchorError::Rewound {
            observed: 0,
            high_water: reached
        })
    );
    assert_eq!(second.state(), &State::Failed);
    assert!(anchor.borrow().is_poisoned());

    // Fails closed, and stays closed: a fresh machine on a *fresh* store is
    // still refused, because the anchor is what remembers.
    let mut third = Ceremony::new(
        fx.roster.clone(),
        P1,
        identity(P1),
        Rc::new(RefCell::new(MemoryStore::new())),
        anchor.clone(),
        pristine,
    );
    assert_eq!(
        third.begin(stmt, subset).unwrap_err(),
        Error::Terminated,
        "a signer that has seen a rollback does not sign again"
    );
}

/// The negative control for the test above: the store on its own is blind to
/// its own rollback. This is why the anchor is a separate trait rather than a
/// field the store maintains.
#[test]
fn a_store_cannot_detect_its_own_rollback() {
    let mut store = MemoryStore::new();
    let slot = SlotId(0);
    let ctx_a = ContextId([1u8; 32]);
    let ctx_b = ContextId([2u8; 32]);

    let before = store.snapshot();
    store.reserve(slot).unwrap();
    store.bind(slot, ctx_a).unwrap();
    assert_eq!(store.bind(slot, ctx_b).is_err(), true);

    store.restore(&before);
    store.reserve(slot).unwrap();
    store
        .bind(slot, ctx_b)
        .expect("after a rollback the store has no objection at all");
}

#[test]
fn the_anchor_accepts_forward_progress() {
    // A guard that rejected everything would pass the rollback test above.
    let mut anchor = MemoryAnchor::new();
    anchor.observe(0).unwrap();
    anchor.observe(1).unwrap();
    anchor.observe(1).expect("equal is not a rewind");
    anchor.observe(9).unwrap();
    assert_eq!(anchor.high_water(), 9);
    assert!(!anchor.is_poisoned());
    assert_eq!(
        anchor.observe(8).unwrap_err(),
        AnchorError::Rewound {
            observed: 8,
            high_water: 9
        }
    );
    assert!(anchor.is_poisoned());
    assert_eq!(anchor.observe(100).unwrap_err(), AnchorError::Poisoned);
}
