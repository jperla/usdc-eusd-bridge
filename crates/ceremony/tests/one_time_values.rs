//! PROPERTY 1 -- one-time values are never reused, and the store key is the
//! FULL signing context.
//!
//! The file is arranged as: what goes wrong (an attack carried out to the end),
//! why the obvious narrower key does not prevent it, and then the guard that
//! does.

mod common;

use std::cell::RefCell;
use std::rc::Rc;

use curve25519_dalek::scalar::Scalar;
use mc_crypto_hashes::{Blake2b256, Digest};

use ceremony::frost::{binding_factor, challenge, group_commitment, lagrange, scalar_from};
use ceremony::machine::{Ceremony, State};
use ceremony::{
    Authorizer, BindingStore, Commitment, Error, MemoryAnchor, MemoryStore, ParticipantId, Receipt,
    RoundOnePackage, SignedRoundOne, SigningContext, SlotId, Statement, StoreError, Subset,
};
use common::*;

const P1: ParticipantId = ParticipantId(1);
const P2: ParticipantId = ParticipantId(2);

/// Contexts that agree on statement and subset and differ only in the peer's
/// round-one commitment -- i.e. exactly what a coordinator can produce at will
/// by re-running round one with a different peer contribution.
fn context_with(
    stmt: &Statement,
    subset: &Subset,
    mine: &Commitment,
    peer: &Commitment,
) -> SigningContext {
    let mut package = RoundOnePackage::new();
    package.insert(P1, mine.clone());
    package.insert(P2, peer.clone());
    SigningContext::new(stmt.clone(), subset.clone(), package)
}

/// The key this crate deliberately does NOT use: statement and subset only.
/// Computed from a full context, so the two keyings can be compared on the same
/// inputs.
fn narrow_key(ctx: &SigningContext) -> [u8; 32] {
    let mut h = Blake2b256::new();
    h.update(&ctx.statement().0);
    for id in ctx.subset().iter() {
        h.update(id.0.to_le_bytes());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn det3(m: [[Scalar; 3]; 3]) -> Scalar {
    m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1])
        - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
        + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0])
}

/// THE ATTACK, carried out. Three responses under one one-time value are three
/// linear equations in (d, e, s); the long-term share falls out by Cramer's
/// rule. Nothing here is simulated -- the responses come from the backend's own
/// `round_two`, and the recovered scalar is compared against the dealer's share.
///
/// This is what every guard in this file is standing in front of, and it is why
/// the machine fails closed rather than retrying.
#[test]
fn three_responses_under_one_one_time_value_recover_the_long_term_share() {
    let fx = fixture(2, 3);
    let subset = Subset::new([P1, P2]);
    let stmt = statement(b"release 250000 eUSD to R, block 12345");

    let mut victim = fx.signer(P1);
    let (slot, mine) = victim.round_one().expect("round one");

    // Three different peer contributions under the same statement and subset.
    let mut peer = fx.signer(P2);
    let peers: Vec<Commitment> = (0..3).map(|_| peer.round_one().unwrap().1).collect();

    let lambda = lagrange(&subset, P1).unwrap();
    let mut rows = [[Scalar::ZERO; 3]; 3];
    let mut rhs = [Scalar::ZERO; 3];

    for (k, peer_commitment) in peers.iter().enumerate() {
        let ctx = context_with(&stmt, &subset, &mine, peer_commitment);
        let receipt = Receipt::issue(slot, Some(ctx.id()), 1);

        // A signer restored from a snapshot: same slot, same one-time value.
        let mut restored = victim.clone();
        let share = restored
            .round_two(slot, &ctx, &receipt)
            .expect("backend answers");

        let rho = binding_factor(ctx.id(), P1);
        let c = challenge(
            &group_commitment(&ctx).unwrap(),
            &fx.group.group_public,
            ctx.id(),
        );
        rows[k] = [Scalar::ONE, rho, lambda * c];
        rhs[k] = scalar_from(&share.0).unwrap();
    }

    // Solve for the third unknown, s.
    let det = det3(rows);
    assert_ne!(det, Scalar::ZERO, "the three contexts must be independent");
    let mut m_s = rows;
    for k in 0..3 {
        m_s[k][2] = rhs[k];
    }
    let recovered = det3(m_s) * det.invert();

    assert_eq!(
        recovered,
        fx.shares[&P1],
        "three replays under one one-time value recover the long-term share"
    );
}

/// The narrow key cannot see the attack: all three contexts above share it.
#[test]
fn statement_and_subset_alone_do_not_identify_the_signing_context() {
    let fx = fixture(2, 3);
    let subset = Subset::new([P1, P2]);
    let stmt = statement(b"release 250000 eUSD to R, block 12345");

    let mut victim = fx.signer(P1);
    let mine = victim.round_one().unwrap().1;
    let mut peer = fx.signer(P2);
    let a = context_with(&stmt, &subset, &mine, &peer.round_one().unwrap().1);
    let b = context_with(&stmt, &subset, &mine, &peer.round_one().unwrap().1);

    // Same two contexts, two keyings, opposite verdicts. Under the narrow key a
    // store would call the second run a replay of the first and let it through;
    // the responses are not replays, as the previous test shows.
    assert_eq!(
        narrow_key(&a),
        narrow_key(&b),
        "the narrow key merges two distinct signing contexts"
    );
    assert_ne!(
        a.id(),
        b.id(),
        "the full context distinguishes what the narrow key merges"
    );
}

/// Why re-binding an identical context is safe and re-binding a narrow-key
/// match is not: the response is a function of the full context, and of nothing
/// less.
#[test]
fn replaying_the_identical_context_is_byte_identical_and_a_narrow_match_is_not() {
    let fx = fixture(2, 3);
    let subset = Subset::new([P1, P2]);
    let stmt = statement(b"release 250000 eUSD to R, block 12345");

    let mut victim = fx.signer(P1);
    let (slot, mine) = victim.round_one().unwrap();
    let mut peer = fx.signer(P2);
    let ctx_a = context_with(&stmt, &subset, &mine, &peer.round_one().unwrap().1);
    let ctx_b = context_with(&stmt, &subset, &mine, &peer.round_one().unwrap().1);

    let ra = Receipt::issue(slot, Some(ctx_a.id()), 1);
    let rb = Receipt::issue(slot, Some(ctx_b.id()), 1);

    let first = victim.clone().round_two(slot, &ctx_a, &ra).unwrap();
    let again = victim.clone().round_two(slot, &ctx_a, &ra).unwrap();
    let other = victim.clone().round_two(slot, &ctx_b, &rb).unwrap();

    assert_eq!(first, again, "identical context, identical bytes: no leak");
    assert_ne!(
        first, other,
        "same narrow key, different response: the leak the narrow key hides"
    );
}

/// THE GUARD. A signer whose own state was restored re-offers the one-time value
/// it already used; the store refuses to bind it a second time and the machine
/// fails closed.
///
/// Delete the `AlreadyBound` arm of `MemoryStore::bind` and this test fails --
/// and the run it would have permitted is the first test in this file.
#[test]
fn the_machine_refuses_to_bind_one_one_time_value_to_two_contexts() {
    let fx = fixture(2, 3);
    let subset = Subset::new([P1, P2]);
    let stmt = statement(b"release 250000 eUSD to R, block 12345");

    let store = Rc::new(RefCell::new(MemoryStore::new()));
    let anchor = Rc::new(RefCell::new(MemoryAnchor::new()));
    let pristine = fx.signer(P1);
    let mut peer = fx.signer(P2);
    let peer_id_key = identity(P2);

    let mut first = Ceremony::new(
        fx.roster.clone(),
        P1,
        identity(P1),
        store.clone(),
        anchor.clone(),
        pristine.clone(),
    );
    let mine_first = first.begin(stmt.clone(), subset.clone()).expect("begin");
    first
        .receive_round_one(SignedRoundOne::create(
            &peer_id_key,
            P2,
            stmt.clone(),
            subset.clone(),
            peer.round_one().unwrap().1,
        ))
        .expect("peer round one");
    first.round_two().expect("first ceremony signs");

    // Same signer state as before the first ceremony -- a restore from backup.
    let mut second = Ceremony::new(
        fx.roster.clone(),
        P1,
        identity(P1),
        store.clone(),
        anchor.clone(),
        pristine,
    );
    let mine_again = second.begin(stmt.clone(), subset.clone()).expect("begin");
    assert_eq!(
        mine_first.commitment, mine_again.commitment,
        "precondition: the restored signer really did re-offer the same one-time value"
    );
    second
        .receive_round_one(SignedRoundOne::create(
            &peer_id_key,
            P2,
            stmt.clone(),
            subset.clone(),
            peer.round_one().unwrap().1,
        ))
        .expect("peer round one");

    let err = second.round_two().unwrap_err();
    assert!(
        matches!(err, Error::OneTimeValueReuse(StoreError::AlreadyBound { .. })),
        "expected a reuse refusal, got {err:?}"
    );
    assert_eq!(second.state(), &State::Failed);
    assert!(matches!(
        second.round_two().unwrap_err(),
        Error::Terminated
    ));
}

#[test]
fn store_binds_a_slot_once_and_only_once() {
    let mut store = MemoryStore::new();
    let slot = SlotId(7);
    let a = context_with(
        &statement(b"a"),
        &Subset::new([P1, P2]),
        &Commitment(vec![1; 64]),
        &Commitment(vec![2; 64]),
    )
    .id();
    let b = context_with(
        &statement(b"b"),
        &Subset::new([P1, P2]),
        &Commitment(vec![1; 64]),
        &Commitment(vec![2; 64]),
    )
    .id();

    assert_eq!(store.bind(slot, a).unwrap_err(), StoreError::NotReserved(slot));
    store.reserve(slot).unwrap();
    store.bind(slot, a).expect("first bind");
    store.bind(slot, a).expect("identical context is idempotent");
    assert_eq!(
        store.bind(slot, b).unwrap_err(),
        StoreError::AlreadyBound {
            slot,
            existing: a,
            attempted: b
        }
    );
}
