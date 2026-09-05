//! Configuration must preserve the per-seat identity the evidence checker uses.

mod common;

use ceremony::{
    context::{Commitment, SlotId},
    frost::{FrostError, FrostSignature},
    machine::{Ceremony, Roster, State},
    store::Receipt,
    Authorizer, BindingStore, Error, MemoryAnchor, MemoryStore, ParticipantId, Rejection, Share,
    SigningContext, Subset,
};
use common::{fixture, identity, statement};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

const P1: ParticipantId = ParticipantId(1);
const P2: ParticipantId = ParticipantId(2);
const P3: ParticipantId = ParticipantId(3);

struct CountingSigner {
    signer: common::Signer,
    round_one_calls: Rc<Cell<usize>>,
}

impl Authorizer for CountingSigner {
    type Signature = FrostSignature;
    type Error = FrostError;

    fn round_one(&mut self) -> Result<(SlotId, Commitment), Self::Error> {
        self.round_one_calls.set(self.round_one_calls.get() + 1);
        self.signer.round_one()
    }

    fn round_two(
        &mut self,
        slot: SlotId,
        context: &SigningContext,
        receipt: &Receipt,
    ) -> Result<Share, Self::Error> {
        self.signer.round_two(slot, context, receipt)
    }

    fn verify_share(
        &self,
        context: &SigningContext,
        participant: ParticipantId,
        share: &Share,
    ) -> Result<(), Rejection<Self::Error>> {
        self.signer.verify_share(context, participant, share)
    }

    fn aggregate(
        &self,
        context: &SigningContext,
        shares: &[(ParticipantId, Share)],
    ) -> Result<Self::Signature, Self::Error> {
        self.signer.aggregate(context, shares)
    }

    fn verify_signature(
        &self,
        context: &SigningContext,
        signature: &Self::Signature,
    ) -> Result<(), Self::Error> {
        self.signer.verify_signature(context, signature)
    }
}

#[test]
fn duplicate_roster_ids_are_rejected_instead_of_replacing_the_named_key() {
    let original = identity(P1).public();
    let replacement = identity(P3).public();
    assert_ne!(original, replacement);
    assert_eq!(
        Roster::new(
            [
                (P1, original),
                (P2, identity(P2).public()),
                (P1, replacement)
            ],
            2
        )
        .unwrap_err(),
        Error::Duplicate(P1),
    );
    let roster = Roster::new([(P1, original), (P2, identity(P2).public())], 2).unwrap();
    assert_eq!(roster.identity(P1), Some(&original));
}

#[test]
fn one_identity_key_cannot_be_configured_as_two_distinct_seats() {
    let key = identity(P1).public();
    assert_eq!(
        Roster::new([(P1, key), (P2, key)], 2).unwrap_err(),
        Error::DuplicateIdentity {
            first: P1,
            second: P2
        },
    );
    assert!(Roster::new([(P1, key), (P2, identity(P2).public())], 2).is_ok());
}

#[test]
fn zero_id_is_refused_by_the_ceremony_roster_as_well_as_by_the_dealer() {
    assert_eq!(
        Roster::new([(ParticipantId(0), identity(P1).public())], 1).unwrap_err(),
        Error::ReservedParticipantId,
    );
    assert!(Roster::new([(P1, identity(P1).public())], 1).is_ok());
}

#[test]
fn local_identity_mismatch_is_refused_before_a_nonce_or_durable_record_exists() {
    let fx = fixture(1, 1);
    let store = Rc::new(RefCell::new(MemoryStore::new()));
    let round_one_calls = Rc::new(Cell::new(0));
    let mut machine = Ceremony::new(
        fx.roster.clone(),
        P1,
        identity(P2),
        store.clone(),
        MemoryAnchor::new(),
        CountingSigner {
            signer: fx.signer(P1),
            round_one_calls: round_one_calls.clone(),
        },
    );
    assert_eq!(
        machine
            .begin(statement(b"release"), Subset::new([P1]))
            .unwrap_err(),
        Error::IdentityKeyMismatch(P1),
    );
    assert_eq!(round_one_calls.get(), 0, "the backend allocated no nonce");
    assert_eq!(store.borrow().sequence(), 0);
    assert_eq!(machine.state(), &State::Fresh);

    let mut control = Ceremony::new(
        fx.roster.clone(),
        P1,
        identity(P1),
        MemoryStore::new(),
        MemoryAnchor::new(),
        CountingSigner {
            signer: fx.signer(P1),
            round_one_calls: round_one_calls.clone(),
        },
    );
    let message = control
        .begin(statement(b"release"), Subset::new([P1]))
        .unwrap();
    assert_eq!(
        round_one_calls.get(),
        1,
        "the control exercises the counter"
    );
    message.verify(fx.roster.identity(P1).unwrap()).unwrap();
    control.round_two().unwrap();
    control.finish().unwrap();
}
