//! PROPERTY 3 -- identifiable abort rests on per-participant IDENTITY keys, not
//! on the signing transcript.
//!
//! The order of the tests is the argument: first that a transcript proves
//! nothing (a quorum can manufacture one, and anyone can manufacture an
//! accusation), then that identity signatures do prove something, then that the
//! evidence checker is not a rubber stamp.

mod common;

use std::cell::{Cell, RefCell};
use std::fmt;
use std::rc::Rc;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use ceremony::context::{Commitment, SlotId};
use ceremony::frost::{challenge, lagrange, scalar_from, FrostSignature, FrostSigner};
use ceremony::machine::{AbortEvidence, Ceremony, EvidenceError, State};
use ceremony::store::Receipt;
use ceremony::{
    Authorizer, ContextId, Error, IdentityError, MemoryAnchor, MemoryStore, ParticipantId,
    Rejection, RoundOnePackage, Share, SignedRoundOne, SignedRoundTwo, SigningContext, Subset,
};
use common::*;

const P1: ParticipantId = ParticipantId(1);
const P2: ParticipantId = ParticipantId(2);
const P3: ParticipantId = ParticipantId(3);

/// A signing transcript is forgeable by the quorum it would incriminate.
///
/// Concretely: any two of these three can reconstruct the group secret from
/// their shares and emit a signature that verifies under the group key, with no
/// ceremony, no round one, and no contribution from the third. Anything derived
/// from such a transcript -- including "who signed" -- is therefore unfounded,
/// which is why attribution here lives in `identity.rs` instead.
#[test]
fn a_quorum_can_forge_a_valid_signature_with_no_ceremony_at_all() {
    let fx = fixture(2, 3);
    let quorum = Subset::new([P1, P3]);

    // Lagrange interpolation at zero over the quorum's own shares.
    let secret: Scalar = quorum
        .iter()
        .map(|id| lagrange(&quorum, id).unwrap() * fx.shares[&id])
        .sum();
    assert_eq!(
        RISTRETTO_BASEPOINT_POINT * secret,
        fx.group.group_public,
        "the quorum really does hold the group secret"
    );

    // A plain Schnorr signature over an arbitrary context, made up wholesale.
    let ctx = SigningContext::new(
        statement(b"a statement no ceremony ever authorised"),
        Subset::new([P1, P2, P3]),
        RoundOnePackage::new(),
    );
    let mut rng = ChaCha20Rng::seed_from_u64(99);
    let k = Scalar::random(&mut rng);
    let r = RISTRETTO_BASEPOINT_POINT * k;
    let c = challenge(&r, &fx.group.group_public, ctx.id());
    let forged = FrostSignature {
        r,
        z: k + c * secret,
    };

    fx.public_verifier()
        .verify_signature(&ctx, &forged)
        .expect("a forged signature is indistinguishable from a ceremony's output");
}

/// And an accusation is even cheaper: a transcript naming a participant and a
/// share that fails the verification equation can be written by anybody. Passed
/// to the evidence checker it is rejected -- for want of a signature, which is
/// the only part that cannot be manufactured.
#[test]
fn a_fabricated_transcript_convicts_no_one() {
    let fx = fixture(2, 3);
    let subset = Subset::new([P1, P2]);
    let stmt = statement(b"release 250000 eUSD to R, block 12345");

    // The forger picks the "victim's" commitment itself -- it is only a pair of
    // group elements, and nothing in the transcript ties it to P2.
    let mut forger = fx.signer(P3);
    let victim_commitment = forger.round_one().unwrap().1;
    let mine = fx.signer(P1).round_one().unwrap().1;

    let mut package = RoundOnePackage::new();
    package.insert(P1, mine.clone());
    package.insert(P2, victim_commitment.clone());
    let ctx = SigningContext::new(stmt.clone(), subset.clone(), package);

    let bogus = Share(vec![7u8; 32]);
    // Transcript-level "proof of misbehaviour": the share does not verify.
    assert!(fx
        .public_verifier()
        .verify_share(&ctx, P2, &bogus)
        .is_err());

    // The same accusation as evidence. The forger cannot sign as P2, so it
    // signs as itself and attributes the message to P2.
    let evidence = AbortEvidence {
        round_one: vec![
            SignedRoundOne::create(&identity(P1), P1, stmt.clone(), subset.clone(), mine),
            // Signed by P3's identity key, claiming to be P2.
            SignedRoundOne {
                participant: P2,
                ..SignedRoundOne::create(
                    &identity(P3),
                    P3,
                    stmt.clone(),
                    subset.clone(),
                    victim_commitment,
                )
            },
        ],
        accused: SignedRoundTwo {
            participant: P2,
            ..SignedRoundTwo::create(&identity(P3), P3, ctx.id(), bogus)
        },
    };

    assert_eq!(
        evidence
            .verify(&fx.roster, &fx.public_verifier())
            .unwrap_err(),
        EvidenceError::Identity(IdentityError::BadSignature(P2))
    );
}

/// THE GUARD. An invalid share arriving under a valid identity signature is
/// attributed to its sender, and the evidence stands up to an independent
/// check.
///
/// Remove the `verify_share` call in `Ceremony::receive_round_two` and the abort
/// stops being identifiable: the ceremony proceeds to `finish`, which is where
/// the failure would surface without a culprit.
#[test]
fn an_invalid_share_is_attributed_to_its_sender() {
    let fx = fixture(2, 3);
    let subset = Subset::new([P1, P2]);
    let stmt = statement(b"release 250000 eUSD to R, block 12345");

    let mut nodes = vec![fx.node(P1), fx.node(P2)];
    round_one(&mut nodes, &stmt, &subset).expect("round one");
    let honest_p2 = nodes[1].machine.round_two().expect("p2 signs");
    nodes[0].machine.round_two().expect("p1 signs");

    // P2 nudges its response by one and re-signs it under its own identity key,
    // which is what a faulty or hostile signer actually looks like.
    let z = scalar_from(&honest_p2.share.0).unwrap();
    let tampered = SignedRoundTwo::create(
        &identity(P2),
        P2,
        honest_p2.context,
        Share((z + Scalar::ONE).to_bytes().to_vec()),
    );

    let err = nodes[0]
        .machine
        .receive_round_two(tampered.clone())
        .unwrap_err();
    assert_eq!(err, Error::IdentifiableAbort { culprit: P2 });
    assert_eq!(nodes[0].machine.state(), &State::Aborted(P2));

    let evidence = nodes[0].machine.evidence().expect("evidence retained");
    assert_eq!(
        evidence
            .verify(&fx.roster, &fx.public_verifier())
            .expect("evidence stands up"),
        P2
    );

    // The evidence is checkable by someone holding only public material: the
    // roster's identity keys and the group's verification shares.
    assert_eq!(evidence.accused, tampered);
}

/// The evidence checker is not a rubber stamp: an accusation carrying a share
/// that actually verifies is rejected, and that rejection is a finding about the
/// accuser.
#[test]
fn evidence_carrying_a_valid_share_is_rejected() {
    let fx = fixture(2, 3);
    let subset = Subset::new([P1, P2]);
    let stmt = statement(b"release 250000 eUSD to R, block 12345");

    let mut nodes = vec![fx.node(P1), fx.node(P2)];
    let r1 = round_one(&mut nodes, &stmt, &subset).expect("round one");
    let honest_p2 = nodes[1].machine.round_two().expect("p2 signs");

    let evidence = AbortEvidence {
        round_one: r1,
        accused: honest_p2,
    };
    assert_eq!(
        evidence
            .verify(&fx.roster, &fx.public_verifier())
            .unwrap_err(),
        EvidenceError::ShareIsValid
    );
}

#[test]
fn a_round_message_signed_by_the_wrong_identity_key_is_refused() {
    let fx = fixture(2, 3);
    let subset = Subset::new([P1, P2]);
    let stmt = statement(b"release 250000 eUSD to R, block 12345");

    let mut node = fx.node(P1);
    node.machine
        .begin(stmt.clone(), subset.clone())
        .expect("begin");

    // P3 impersonating P2 in round one.
    let mut peer = fx.signer(P2);
    let impersonated = SignedRoundOne {
        participant: P2,
        ..SignedRoundOne::create(
            &identity(P3),
            P3,
            stmt.clone(),
            subset.clone(),
            peer.round_one().unwrap().1,
        )
    };
    assert_eq!(
        node.machine.receive_round_one(impersonated).unwrap_err(),
        Error::Identity(IdentityError::BadSignature(P2))
    );
    assert_eq!(node.machine.state(), &State::CollectingRoundOne);
}

/// A share is signed under the context id, so it is valid in exactly one
/// context. Neither replaying it into another ceremony nor relabelling it works.
#[test]
fn a_signed_share_cannot_be_moved_to_another_context() {
    let fx = fixture(2, 3);
    let subset = Subset::new([P1, P2]);
    let stmt = statement(b"release 250000 eUSD to R, block 12345");

    // Ceremony A, from which P2's share is taken.
    let mut a = vec![fx.node(P1), fx.node(P2)];
    round_one(&mut a, &stmt, &subset).expect("round one");
    a[0].machine.round_two().expect("p1 signs");
    let p2_share = a[1].machine.round_two().expect("p2 signs");

    // Ceremony B: same statement, same subset, fresh one-time values and
    // therefore a different round-one package.
    let mut b = vec![fx.node_seeded(P1, 77), fx.node_seeded(P2, 78)];
    round_one(&mut b, &stmt, &subset).expect("round one");
    b[0].machine.round_two().expect("p1 signs");
    let ctx_b = b[0].machine.context().unwrap().id();
    assert_ne!(p2_share.context, ctx_b);

    assert_eq!(
        b[0].machine
            .receive_round_two(p2_share.clone())
            .unwrap_err(),
        Error::WrongContext(P2)
    );

    // Relabelling it to context B breaks the signature, which covers the id.
    let relabelled = SignedRoundTwo {
        context: ctx_b,
        ..p2_share
    };
    assert_eq!(
        b[0].machine.receive_round_two(relabelled).unwrap_err(),
        Error::Identity(IdentityError::BadSignature(P2))
    );
}

/// Evidence must be authenticated end to end, not just at the accused message.
///
/// The context id already ties the accused's signature to one exact round-one
/// package, so an accuser cannot swap a commitment without invalidating the
/// accused's own signature. What it cannot do by itself is establish that the
/// *rest* of the transcript was really sent by the participants it names -- and
/// a proceeding that convicts on a transcript nobody else is bound to is one
/// the accuser can walk away from. Here the accused message is genuine and only
/// P1's round-one message is re-signed by P3; verification must still refuse.
#[test]
fn evidence_with_an_unauthenticated_round_one_message_is_rejected() {
    let fx = fixture(2, 3);
    let subset = Subset::new([P1, P2]);
    let stmt = statement(b"release 250000 eUSD to R, block 12345");

    let mut nodes = vec![fx.node(P1), fx.node(P2)];
    let r1 = round_one(&mut nodes, &stmt, &subset).expect("round one");
    let honest_p2 = nodes[1].machine.round_two().expect("p2 signs");
    let z = scalar_from(&honest_p2.share.0).unwrap();
    let bad_p2 = SignedRoundTwo::create(
        &identity(P2),
        P2,
        honest_p2.context,
        Share((z + Scalar::ONE).to_bytes().to_vec()),
    );

    // Same commitment, so the context id -- and P2's signature over it -- still
    // match. Only the authorship of P1's message has been forged.
    let forged_p1 = SignedRoundOne {
        participant: P1,
        ..SignedRoundOne::create(
            &identity(P3),
            P3,
            stmt.clone(),
            subset.clone(),
            r1[0].commitment.clone(),
        )
    };
    let evidence = AbortEvidence {
        round_one: vec![forged_p1, r1[1].clone()],
        accused: bad_p2,
    };

    assert_eq!(
        evidence
            .verify(&fx.roster, &fx.public_verifier())
            .unwrap_err(),
        EvidenceError::Identity(IdentityError::BadSignature(P1))
    );
}

#[test]
fn evidence_naming_a_context_the_round_one_messages_do_not_produce_is_rejected() {
    let fx = fixture(2, 3);
    let subset = Subset::new([P1, P2]);
    let stmt = statement(b"release 250000 eUSD to R, block 12345");

    let mut nodes = vec![fx.node(P1), fx.node(P2)];
    let r1 = round_one(&mut nodes, &stmt, &subset).expect("round one");
    nodes[1].machine.round_two().expect("p2 signs");

    let evidence = AbortEvidence {
        round_one: r1,
        accused: SignedRoundTwo::create(
            &identity(P2),
            P2,
            ContextId([0xab; 32]),
            Share(vec![7u8; 32]),
        ),
    };
    assert_eq!(
        evidence
            .verify(&fx.roster, &fx.public_verifier())
            .unwrap_err(),
        EvidenceError::WrongContext
    );
}

// -------------------------------------------------- fault versus error
//
// Identifiable abort is only worth having if the identification is sound. An
// accusation that an honest operator cannot distinguish from a config typo or a
// dropped HSM session is worse than no accusation at all: it is a mechanism for
// removing whoever happened to be on the roster when the network blipped.

/// The backend could not answer. Not a finding about anybody.
#[derive(Debug, PartialEq, Eq)]
struct Outage;

impl fmt::Display for Outage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signer backend unavailable")
    }
}

/// A signer whose verification path can be taken away underneath it -- an HSM
/// that lost its session, a key service that timed out.
struct Unavailable {
    inner: Signer,
    down: Rc<Cell<bool>>,
}

impl Authorizer for Unavailable {
    type Signature = FrostSignature;
    type Error = Outage;

    fn round_one(&mut self) -> Result<(SlotId, Commitment), Outage> {
        self.inner.round_one().map_err(|_| Outage)
    }
    fn round_two(
        &mut self,
        slot: SlotId,
        context: &SigningContext,
        receipt: &Receipt,
    ) -> Result<Share, Outage> {
        self.inner
            .round_two(slot, context, receipt)
            .map_err(|_| Outage)
    }
    fn verify_share(
        &self,
        context: &SigningContext,
        participant: ParticipantId,
        share: &Share,
    ) -> Result<(), Rejection<Outage>> {
        if self.down.get() {
            return Err(Rejection::Error(Outage));
        }
        // A fault stays a fault; only the backend's own failures become Outage.
        self.inner
            .verify_share(context, participant, share)
            .map_err(|r| match r {
                Rejection::Fault(f) => Rejection::Fault(f),
                Rejection::Error(_) => Rejection::Error(Outage),
            })
    }
    fn aggregate(
        &self,
        context: &SigningContext,
        shares: &[(ParticipantId, Share)],
    ) -> Result<FrostSignature, Outage> {
        self.inner.aggregate(context, shares).map_err(|_| Outage)
    }
    fn verify_signature(
        &self,
        context: &SigningContext,
        signature: &FrostSignature,
    ) -> Result<(), Outage> {
        // A backend that is down cannot verify a signature either. Without
        // this the outage is only half-modelled: aggregation succeeds, the
        // signature verifies, and finish() never reaches the branch that goes
        // looking for a culprit -- which is the branch under test.
        if self.down.get() {
            return Err(Outage);
        }
        self.inner
            .verify_signature(context, signature)
            .map_err(|_| Outage)
    }
}

/// THE GUARD. A backend that cannot check a share must produce no evidence at
/// all -- and in particular no evidence naming the participant whose share it
/// happened to be holding when the backend went away.
#[test]
fn a_backend_outage_accuses_no_one() {
    let fx = fixture(2, 3);
    let subset = Subset::new([P1, P2]);
    let stmt = statement(b"release 250000 eUSD to R, block 12345");

    let down = Rc::new(Cell::new(false));
    let mut p1 = Ceremony::new(
        fx.roster.clone(),
        P1,
        identity(P1),
        Rc::new(RefCell::new(MemoryStore::new())),
        Rc::new(RefCell::new(MemoryAnchor::new())),
        Unavailable {
            inner: fx.signer(P1),
            down: down.clone(),
        },
    );
    let mut p2 = fx.node(P2);

    let m1 = p1.begin(stmt.clone(), subset.clone()).expect("p1 begins");
    let m2 = p2
        .machine
        .begin(stmt.clone(), subset.clone())
        .expect("p2 begins");
    p1.receive_round_one(m2).expect("p1 takes p2's round one");
    p2.machine
        .receive_round_one(m1)
        .expect("p2 takes p1's round one");
    p1.round_two().expect("p1 signs");
    let honest = p2.machine.round_two().expect("p2 signs");

    // The session drops between p2 sending and p1 checking.
    down.set(true);
    let err = p1
        .receive_round_two(honest.clone())
        .expect_err("an unchecked share cannot be accepted either");

    assert!(
        !matches!(err, Error::IdentifiableAbort { .. }),
        "a backend outage is not an accusation, got: {err}"
    );
    assert!(
        p1.evidence().is_none(),
        "no evidence may name a participant on the strength of a backend error"
    );
    assert!(
        !matches!(p1.state(), State::Aborted(_)),
        "the ceremony must not be aborted against a participant, got: {:?}",
        p1.state()
    );

    // And the share really was fine: when the backend comes back it is taken.
    down.set(false);
    p1.receive_round_two(honest)
        .expect("the share was valid all along");
}

/// The same rule at the LAST place it can be broken.
///
/// `finish` re-checks every share when the aggregate signature fails to
/// verify, which is the one moment the machine is actively looking for someone
/// to blame. A backend that cannot answer there must still produce no
/// accusation -- and this is where getting it wrong is most tempting, because
/// something has demonstrably gone wrong and a culprit would be convenient.
///
/// Pinned separately from the round-two case because the two paths have
/// separate `match` arms: mutating only `finish`'s arm to convict on any
/// rejection left the round-two tests green.
#[test]
fn a_backend_that_fails_during_finish_still_accuses_no_one() {
    let fx = fixture(2, 3);
    let subset = Subset::new([P1, P2]);
    let stmt = statement(b"release 250000 eUSD to R, block 12345");

    let down = Rc::new(Cell::new(false));
    let mut p1 = Ceremony::new(
        fx.roster.clone(),
        P1,
        identity(P1),
        Rc::new(RefCell::new(MemoryStore::new())),
        Rc::new(RefCell::new(MemoryAnchor::new())),
        Unavailable {
            inner: fx.signer(P1),
            down: down.clone(),
        },
    );
    let mut p2 = fx.node(P2);

    let m1 = p1.begin(stmt.clone(), subset.clone()).expect("p1 begins");
    let m2 = p2
        .machine
        .begin(stmt.clone(), subset.clone())
        .expect("p2 begins");
    p1.receive_round_one(m2).expect("p1 takes p2's round one");
    p2.machine
        .receive_round_one(m1)
        .expect("p2 takes p1's round one");
    p1.round_two().expect("p1 signs");
    let honest = p2.machine.round_two().expect("p2 signs");

    // Both shares arrive and are checked while the backend is up, so nothing
    // is known to be wrong when finish() is entered.
    p1.receive_round_two(honest).expect("p1 takes p2's share");

    // The backend drops before aggregation. finish() will fail to verify the
    // aggregate and go looking for a culprit with a checker that cannot check.
    down.set(true);
    let err = p1.finish().expect_err("finish cannot succeed with the backend down");

    assert!(
        !matches!(err, Error::IdentifiableAbort { .. }),
        "finish must not accuse anyone on a backend error, got: {err}"
    );
    assert!(
        p1.evidence().is_none(),
        "no evidence may be emitted from an uncheckable share in finish"
    );
    assert!(
        !matches!(p1.state(), State::Aborted(_)),
        "the ceremony must not be aborted against a participant, got: {:?}",
        p1.state()
    );
}

/// The same distinction on the other side of the fence: a third party checking
/// evidence with key material that cannot check it must not convict. Here the
/// accused's share genuinely is bad and every signature genuinely is valid --
/// only the checker's verification-share table is missing an entry, which is
/// what a roster or epoch mismatch looks like from inside.
#[test]
fn a_checker_that_cannot_check_does_not_convict() {
    let fx = fixture(2, 3);
    let subset = Subset::new([P1, P2]);
    let stmt = statement(b"release 250000 eUSD to R, block 12345");

    let mut nodes = vec![fx.node(P1), fx.node(P2)];
    let r1 = round_one(&mut nodes, &stmt, &subset).expect("round one");
    let honest_p2 = nodes[1].machine.round_two().expect("p2 signs");
    let z = scalar_from(&honest_p2.share.0).unwrap();
    let evidence = AbortEvidence {
        round_one: r1,
        accused: SignedRoundTwo::create(
            &identity(P2),
            P2,
            honest_p2.context,
            Share((z + Scalar::ONE).to_bytes().to_vec()),
        ),
    };

    // A checker one key short of being able to answer the question.
    let mut group = fx.group.clone();
    group.verification_shares.remove(&P2);
    let stale = FrostSigner::new(
        ParticipantId(0),
        Scalar::ZERO,
        group,
        ChaCha20Rng::seed_from_u64(0),
    );

    assert!(
        evidence.verify(&fx.roster, &stale).is_err(),
        "a checker that cannot check a share must not convict on it"
    );
    // The properly configured checker still convicts, so this is not a blanket
    // refusal.
    assert_eq!(
        evidence
            .verify(&fx.roster, &fx.public_verifier())
            .expect("evidence stands up to a checker that can check"),
        P2
    );
}
