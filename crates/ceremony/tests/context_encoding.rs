//! The context id is the store key, so its encoding has to be injective. These
//! tests are about the encoding itself rather than about any protocol step.

mod common;

use ceremony::{Commitment, ParticipantId, RoundOnePackage, SigningContext, Statement, Subset};

const P1: ParticipantId = ParticipantId(1);
const P2: ParticipantId = ParticipantId(2);
const P3: ParticipantId = ParticipantId(3);

fn ctx(statement: &[u8], subset: &[ParticipantId], entries: &[(ParticipantId, &[u8])]) -> SigningContext {
    let mut package = RoundOnePackage::new();
    for (id, bytes) in entries {
        package.insert(*id, Commitment(bytes.to_vec()));
    }
    SigningContext::new(
        Statement(statement.to_vec()),
        Subset::new(subset.iter().copied()),
        package,
    )
}

/// Two contexts that concatenate to the same bytes if the statement's length
/// prefix is dropped: the statement's trailing bytes are exactly the encoding
/// of the participant the other context lists in its subset.
///
/// Remove the length prefix from `SigningContext::encode`'s `field` and this
/// fails -- and with it, the store would treat two different signing contexts
/// as one key, which is the collision `one_time_values.rs` turns into a key
/// recovery.
#[test]
fn the_statement_subset_boundary_cannot_be_shifted() {
    let a = ctx(b"A\x01\x00", &[], &[(P1, b"C")]);
    let b = ctx(b"A", &[P1], &[(P1, b"C")]);
    assert_ne!(a.encode(), b.encode());
    assert_ne!(a.id(), b.id());
}

/// The same shift one field along: between two participants' commitments.
#[test]
fn commitment_boundaries_cannot_be_shifted() {
    let a = ctx(b"m", &[P1, P2], &[(P1, b"AB"), (P2, b"C")]);
    let b = ctx(b"m", &[P1, P2], &[(P1, b"A"), (P2, b"BC")]);
    assert_ne!(a.encode(), b.encode());
    assert_ne!(a.id(), b.id());
}

#[test]
fn the_id_covers_the_statement_the_subset_and_every_commitment() {
    let base = ctx(b"m", &[P1, P2], &[(P1, b"c1"), (P2, b"c2")]);

    let other_statement = ctx(b"m!", &[P1, P2], &[(P1, b"c1"), (P2, b"c2")]);
    let other_subset = ctx(b"m", &[P1, P2, P3], &[(P1, b"c1"), (P2, b"c2")]);
    // Only the PEER's commitment differs: this is the case a (statement,
    // subset) key cannot see.
    let other_peer = ctx(b"m", &[P1, P2], &[(P1, b"c1"), (P2, b"c2'")]);
    let other_mine = ctx(b"m", &[P1, P2], &[(P1, b"c1'"), (P2, b"c2")]);

    for other in [other_statement, other_subset, other_peer, other_mine] {
        assert_ne!(base.id(), other.id());
    }
}

#[test]
fn the_id_is_deterministic_and_independent_of_insertion_order() {
    let a = ctx(b"m", &[P1, P2], &[(P1, b"c1"), (P2, b"c2")]);
    let b = ctx(b"m", &[P2, P1], &[(P2, b"c2"), (P1, b"c1")]);
    assert_eq!(a.id(), b.id());
    assert_eq!(a.id(), a.id());
}
