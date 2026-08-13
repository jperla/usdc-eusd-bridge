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

use ceremony::authorizer::{Authorizer, Rejection};
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
    ) -> Result<(), Rejection<Self::Error>> {
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

/// A rollback the counter has already caught up with.
///
/// A sequence number says how many writes happened, never which. A signer that
/// serves many slots pushes the counter back past the high-water mark within a
/// few writes of a restore, and from that moment the restore is invisible to
/// anything that only compares numbers -- the store is forked, at the same
/// sequence, and says so to nobody.
///
/// Here the store is rewound to just before a binding, two unrelated
/// reservations bring the counter back level, and the same one-time value is
/// then offered to a second statement. What that buys the adversary is the
/// first test in `one_time_values.rs`: one nonce answering two challenges.
#[test]
fn a_rollback_the_counter_has_caught_up_with_is_still_refused() {
    let fx = fixture(2, 3);
    let subset = Subset::new([P1, P2]);
    let store = Rc::new(RefCell::new(MemoryStore::new()));
    let anchor = Rc::new(RefCell::new(MemoryAnchor::new()));
    let pristine = fx.signer(P1);
    let mut peer = fx.signer(P2);

    let stmt_a = statement(b"release 250000 eUSD to R, block 12345");
    let mut first = Ceremony::new(
        fx.roster.clone(),
        P1,
        identity(P1),
        store.clone(),
        anchor.clone(),
        pristine.clone(),
    );
    first.begin(stmt_a.clone(), subset.clone()).expect("begin");
    // The disk image an operator restores: the reservation is on it, the
    // binding that follows is not.
    let fork_point = store.borrow().snapshot();
    first
        .receive_round_one(SignedRoundOne::create(
            &identity(P2),
            P2,
            stmt_a.clone(),
            subset.clone(),
            peer.round_one().unwrap().1,
        ))
        .expect("peer round one");
    first.round_two().expect("first ceremony signs");

    store.borrow_mut().restore(&fork_point);
    // Unrelated traffic on other slots, which is all it takes for the counter
    // to stop being behind.
    store.borrow_mut().reserve(SlotId(7)).unwrap();
    store.borrow_mut().reserve(SlotId(8)).unwrap();
    assert!(
        store.borrow().sequence() >= anchor.borrow().high_water(),
        "the counter has caught up, so a bare counter has nothing left to see"
    );
    assert_ne!(
        store.borrow().head(),
        anchor.borrow().head(),
        "what remains different is the history, not the count"
    );

    // Same signer state, same one-time value, a different statement.
    let stmt_b = statement(b"release 250000 eUSD to Q, block 12345");
    let mut second = Ceremony::new(
        fx.roster.clone(),
        P1,
        identity(P1),
        store.clone(),
        anchor.clone(),
        pristine,
    );
    let outcome = second
        .begin(stmt_b.clone(), subset.clone())
        .and_then(|_| {
            second.receive_round_one(SignedRoundOne::create(
                &identity(P2),
                P2,
                stmt_b,
                subset,
                peer.round_one().unwrap().1,
            ))
        })
        .and_then(|()| second.round_two());

    assert!(
        matches!(outcome, Err(Error::Rollback(AnchorError::Forked { .. }))),
        "a store on a forked history must be refused as such, counter or no \
         counter, got: {outcome:?}"
    );
    assert_eq!(second.state(), &State::Failed);
    assert!(anchor.borrow().is_poisoned());
}

/// The mechanism the test above rests on, on its own: two divergent records
/// written at the same sequence, of which the anchor accepts exactly one.
///
/// Delete the `prev_head` comparison in `MemoryAnchor::commit` and this passes
/// both writes, because there is nothing left to tell them apart -- they carry
/// the same sequence number and differ only in what they say.
#[test]
fn a_divergent_record_at_the_same_sequence_is_refused() {
    let mut store = MemoryStore::new();
    let mut anchor = MemoryAnchor::new();
    let slot = SlotId(0);
    let ctx_a = ContextId([1u8; 32]);
    let ctx_b = ContextId([2u8; 32]);

    let reserved = store.reserve(slot).unwrap();
    anchor.commit(&reserved).expect("first write anchors");
    let fork_point = store.snapshot();

    let a = store.bind(slot, ctx_a).unwrap();
    anchor.commit(&a).expect("the binding anchors");

    store.restore(&fork_point);
    let b = store.bind(slot, ctx_b).expect("the rewound store has no objection");

    assert_eq!(
        a.sequence(),
        b.sequence(),
        "the two records really are at the same sequence"
    );
    assert_ne!(a.head(), b.head(), "and they really do differ");
    assert_eq!(anchor.head(), Some(a.head()), "the anchor holds the first record");
    assert_eq!(
        anchor.commit(&b).unwrap_err(),
        AnchorError::Forked {
            presented: b.prev_head(),
            anchored: Some(a.head()),
        }
    );
    assert!(anchor.is_poisoned());

    // Not a blanket refusal: re-presenting the record the anchor already holds
    // is a crash between the store's commit and the anchor's, and must resume.
    let mut fresh = MemoryAnchor::new();
    fresh.commit(&reserved).unwrap();
    fresh.commit(&a).unwrap();
    fresh.commit(&a).expect("re-presenting the anchored record is a replay");
}

/// A torn record: the log says the slot was bound, storage says it is only
/// reserved. That is the shape a half-applied write leaves behind, and it is
/// the one a counter cannot see -- the generation is current, the phase bytes
/// are stale.
///
/// Binding it again would be a second context on a one-time value that already
/// answered one, so the store must refuse to act on a record it cannot trust.
#[test]
fn a_torn_record_is_refused_rather_than_rebound() {
    let mut store = MemoryStore::new();
    let slot = SlotId(0);
    let ctx_a = ContextId([1u8; 32]);
    let ctx_b = ContextId([2u8; 32]);

    store.reserve(slot).unwrap();
    store.bind(slot, ctx_a).unwrap();

    // The write that lost half of itself.
    store.tear_record(slot, SlotRecord::Reserved);

    assert_eq!(
        store.bind(slot, ctx_b).unwrap_err(),
        StoreError::TornRecord {
            slot,
            logged: SlotRecord::Bound(ctx_a),
            found: Some(SlotRecord::Reserved),
        },
        "a record that disagrees with the log must not be bound over"
    );
    // Nor may it be quietly re-reserved back into a bindable state.
    assert!(matches!(
        store.reserve(slot),
        Err(StoreError::TornRecord { .. })
    ));

    // And the other way round: storage claiming a binding the log never
    // recorded. Reported as what it is rather than as reuse, because the two
    // ask different things of an operator -- one is a signer to retire, the
    // other is a disk to distrust.
    let mut ahead = MemoryStore::new();
    ahead.reserve(slot).unwrap();
    ahead.tear_record(slot, SlotRecord::Bound(ctx_a));
    assert_eq!(
        ahead.bind(slot, ctx_b).unwrap_err(),
        StoreError::TornRecord {
            slot,
            logged: SlotRecord::Reserved,
            found: Some(SlotRecord::Bound(ctx_a)),
        }
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
