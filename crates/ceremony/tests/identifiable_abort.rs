//! PROPERTY 3 -- identifiable abort rests on per-participant IDENTITY keys, not
//! on the signing transcript.
//!
//! The order of the tests is the argument: first that a transcript proves
//! nothing (a quorum can manufacture one, and anyone can manufacture an
//! accusation), then that identity signatures do prove something, then that the
//! evidence checker is not a rubber stamp.

mod common;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use ceremony::frost::{challenge, lagrange, scalar_from, FrostSignature};
use ceremony::machine::{AbortEvidence, EvidenceError, State};
use ceremony::{
    Authorizer, ContextId, Error, IdentityError, ParticipantId, RoundOnePackage, Share,
    SignedRoundOne, SignedRoundTwo, SigningContext, Subset,
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
        .map(|id| lagrange(&quorum, id) * fx.shares[&id])
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

    // Ceremony B: same statement, same subset, fresh nodes and therefore a
    // different round-one package.
    let mut b = vec![fx.node(P1), fx.node(P2)];
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
