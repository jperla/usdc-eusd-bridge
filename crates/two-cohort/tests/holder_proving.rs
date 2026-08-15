//! The holder's proving entry point.
//!
//! `ceremony.rs` has three provers, and they are not interchangeable:
//!
//! ```text
//!   Pop::prove_unchecked(sealed, claim, participant, secret)  signs what it is handed
//!   Pop::prove_for(sealed, share, claim, salt)                checks the claim and salt
//!   prove_possession(sealed, share)                           derives the claim itself
//! ```
//!
//! These tests are about the one a holder reaches first. `CohortShare::prove`
//! is a method on the type the holder actually has, and it forwards to the
//! CHECKED prover -- so the default path carries the claim check, the salt
//! check and the one-composition rule.
//!
//! **What "goes out of its way" means, exactly.** The raw prover is
//! `pub(crate)`; `Pop::prove_unchecked` exposes it behind the
//! `unchecked-proving` feature, off by default. These tests can call it because
//! this crate dev-depends on itself with that feature on. A deployment reaches
//! it only by writing the feature name in its own manifest -- and cargo unifies
//! features within one build, so a workspace where any crate turns it on turns
//! it on for all of them. Verified, not assumed: a probe calling
//! `Pop::prove_unchecked` from `crates/ceremony`'s tests fails to compile under
//! `cargo test -p ceremony` and compiles under a whole-workspace `cargo test`.
//!
//! What this file does NOT claim: that a holder CANNOT prove without the
//! checks. Two ways past it, both open and neither closed by anything here:
//! `composition.rs::a_holder_can_recover_its_own_share_through_public_api`
//! recovers `s_i` from public material, after which any Schnorr proof can be
//! written by hand; and `forgery.rs` reaches an auditing artifact through
//! `Cohort::deal_in` while answering the CHECKED prover honestly. The claim is
//! about which path is the default and what it costs to leave it, which is
//! smaller than a boundary and is what is actually true.
//!
//! Every rejection here is paired with a control on the same share, the same
//! composition and the same run, so a refusal is attributable to the one thing
//! that was changed.

mod common;

use std::collections::BTreeMap;

use common::{parties_over, seal_and_sign, seat_endorsements, CohortSide};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, scalar::Scalar};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use two_cohort::{
    audit,
    ceremony::{ComponentClaim, ComponentReveal, Pop, SealedComposition},
    lagrange_at_zero, CeremonyError, CeremonyId, CohortSpec, ControlDomain, Gates, Owners,
};

fn owners_spec() -> CohortSpec<Owners> {
    CohortSpec::<Owners>::sequential(2, 3)
}

fn gates_spec() -> CohortSpec<Gates> {
    CohortSpec::<Gates>::sequential(2, 3)
}

/// Everyone a funder of an artifact at this file's shape holds a key for.
fn parties() -> two_cohort::Parties {
    parties_over(owners_spec().ids(), gates_spec().ids())
}

/// A fresh composition, with both cohorts' DKGs behind it.
///
/// Each test builds its own, because a share answers ONE sealed composition and
/// these tests are precisely about that rule firing.
fn setup(
    seed: u64,
) -> (
    CohortSide<Owners>,
    CohortSide<Gates>,
    SealedComposition,
    CeremonyId,
) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let ceremony = CeremonyId::draw("holder proving", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);
    let sealed = SealedComposition::new(ceremony, owners.commitment, gates.commitment)
        .expect("commitments are of the right cohorts");
    (owners, gates, sealed, ceremony)
}

/// One cohort's reveal, with every proof produced by the DEFAULT holder entry
/// point.
///
/// `CohortSide::reveal` uses `prove_possession`; this is the same sequence with
/// `share.prove` in its place, which is what makes the audit below evidence
/// about the default path rather than about the harness.
fn reveal_via_default<C: ControlDomain>(
    side: &CohortSide<C>,
    sealed: &SealedComposition,
) -> ComponentReveal {
    let pops: BTreeMap<u64, Pop> = side
        .shares
        .iter()
        .map(|s| {
            (
                s.id(),
                s.prove(sealed, &side.claim, &side.salt)
                    .expect("its own claim, its own salt, its first composition"),
            )
        })
        .collect();
    ComponentReveal::assemble(
        sealed,
        side.claim.clone(),
        pops,
        side.endorsements.clone(),
        side.salt,
    )
    .expect("an honest cohort's own proofs verify")
}

/// The default entry point forwards to `Pop::prove_for` and to nothing else:
/// it produces exactly what `prove_for` produces, and a whole ceremony proved
/// through it audits.
///
/// The two calls are on the SAME share under the SAME composition, which the
/// one-composition rule permits -- a holder asked twice because a message was
/// lost is not the thing being refused -- so this compares the two provers
/// rather than two runs.
///
/// **This test alone does not establish that the default prover CHECKS
/// anything**, and it is named for what it does rather than for what the file
/// is about. Under a valid claim and salt the checked and unchecked provers
/// return the identical `Pop` -- the checks only ever refuse -- so
/// `assert_eq!(default, spelled_out)` cannot separate them, and mutating
/// `CohortShare::prove` to forward to the raw prover leaves this passing. The
/// discriminating power is in the three refusal tests below and in
/// `the_raw_prover_signs_what_the_default_entry_point_refuses`, which is the
/// one that pins the difference directly.
#[test]
fn the_default_entry_point_produces_the_same_proof_as_prove_for() {
    let (owners, gates, sealed, _) = setup(0x11E1);
    let share = &gates.shares[0];

    let default = share
        .prove(&sealed, &gates.claim, &gates.salt)
        .expect("this share's own claim, sealed under its own salt");
    let spelled_out = Pop::prove_for(&sealed, share, &gates.claim, &gates.salt)
        .expect("the same thing, written out");
    assert_eq!(default, spelled_out);

    // And the proofs are real, not merely equal: an artifact whose every seat
    // proved through this entry point audits.
    let artifact = sealed
        .open(
            reveal_via_default(&owners, &sealed),
            reveal_via_default(&gates, &sealed),
            &parties(),
        )
        .expect("a composition proved entirely through `share.prove`");
    audit(&artifact, &parties()).expect("and it audits standing alone");
}

/// A holder's own share scalar, recovered from public material.
///
/// `CohortShare::secret` is `pub(crate)`, so this is how a holder outside the
/// crate reaches its own secret -- and it is not a trick: the roster is public,
/// the evaluation points are `1..=n` by position as `dkg` documents, and
/// `lagrange_at_zero` is a public function of those.
/// `composition.rs::a_holder_can_recover_its_own_share_through_public_api` is
/// the test that owns this property; here it is only the means of driving the
/// raw prover as a holder actually would.
fn own_share_scalar<C: ControlDomain>(side: &CohortSide<C>, id: u64) -> Scalar {
    let share = side.share_of(id);
    let roster = share.key().roster().to_vec();
    // A quorum containing this holder. Which other seats are in it does not
    // matter: `term` weights the share for exactly this quorum and the Lagrange
    // weight below is computed over the same one, so they cancel.
    let mut quorum: Vec<u64> = vec![id];
    for &r in &roster {
        if quorum.len() == side.claim.threshold() {
            break;
        }
        if r != id {
            quorum.push(r);
        }
    }
    quorum.sort_unstable();

    let points: Vec<u64> = quorum
        .iter()
        .map(|q| roster.iter().position(|r| r == q).unwrap() as u64 + 1)
        .collect();
    let mine = roster.iter().position(|r| *r == id).unwrap() as u64 + 1;
    let lambda = lagrange_at_zero(mine, &points).expect("public arithmetic");

    let recovered = *share
        .term(&quorum)
        .expect("a quorum member's own term")
        .weight()
        * lambda.invert();
    assert_eq!(
        recovered * G,
        side.claim
            .verification_share(id)
            .expect("on the roster"),
        "the recovered scalar opens this seat's published verification share",
    );
    recovered
}

/// **The two provers separated, on one share, one composition, one claim.**
///
/// The same inflated claim that the default entry point refuses is SIGNED by the
/// raw prover -- and the resulting proof is not junk: it verifies, so a
/// coordinator holding it can assemble a reveal that claims a threshold this
/// cohort never ran. That is the whole content of "the default path is the
/// checked one", and it is the assertion
/// `the_default_entry_point_produces_the_same_proof_as_prove_for` cannot make.
///
/// The claim is inflated in the threshold only. Everything else -- roster,
/// component, verification shares -- is the cohort's own, so what the default
/// prover objects to is the one changed field.
#[test]
fn the_raw_prover_signs_what_the_default_entry_point_refuses() {
    let (owners, gates, sealed, _) = setup(0x55E1);
    let share = &gates.shares[0];

    let inflated = ComponentClaim::from_parts(
        gates.claim.cohort(),
        gates.claim.threshold() + 1,
        gates.claim.roster().to_vec(),
        gates.claim.component(),
        gates.claim.verification_shares().to_vec(),
        gates.claim.seat_keys().to_vec(),
    );

    // The default entry point looks and refuses.
    assert_eq!(
        share.prove(&sealed, &inflated, &gates.salt).unwrap_err(),
        CeremonyError::ClaimNotOwn {
            cohort: Gates::NAME,
            participant: share.id(),
        },
    );

    // The raw prover signs it. Same share, same secret, same composition.
    let forged = Pop::prove_unchecked(
        &sealed,
        &inflated,
        share.id(),
        &own_share_scalar(&gates, share.id()),
    )
    .expect("the raw prover checks only that the secret opens the published share");

    // And it is a real proof, not a rejected one: an auditor checking this
    // cohort against the inflated claim accepts every seat's proof. The audit
    // refuses the artifact elsewhere -- `check_consistency`'s lower bound is
    // what catches an overstated threshold -- but not here, which is the point:
    // the raw prover puts the holder's signature on a coordinator's numbers and
    // leaves the objection to somebody else.
    let mut pops = BTreeMap::new();
    pops.insert(share.id(), forged);
    for s in gates.shares.iter().skip(1) {
        pops.insert(
            s.id(),
            Pop::prove_unchecked(&sealed, &inflated, s.id(), &own_share_scalar(&gates, s.id()))
                .expect("opens its own"),
        );
    }
    // `assemble` VERIFIES every proof it is given, and it accepts these: the
    // holders' signatures are on the coordinator's threshold. Nothing in the
    // proving path objected.
    let endorsements = seat_endorsements::<Gates>(sealed.ceremony(), &inflated);
    let inflated_reveal =
        ComponentReveal::assemble(&sealed, inflated, pops, endorsements, gates.salt)
            .expect("every forged proof verifies against the claim it was taken over");
    assert_eq!(inflated_reveal.threshold(), gates.claim.threshold() + 1);

    // The objection, when it finally arrives, comes from a different check
    // entirely -- the commitment this cohort actually published sealed the
    // honest claim. Had the coordinator sealed the inflated claim too, the
    // objection would be `ThresholdOverstated` from `check_consistency`'s lower
    // bound, which `composition.rs` owns. Either way it is somebody else's
    // check: the prover that signed this raised none of its own.
    let artifact = sealed
        .open(reveal_via_default(&owners, &sealed), inflated_reveal, &parties())
        .expect_err("the audit refuses it, but not for anything the prover did");
    assert_eq!(
        artifact,
        CeremonyError::CommitmentMismatch {
            cohort: Gates::NAME
        },
    );

    // Control: the honest claim through the same raw prover is accepted by both.
    let (_, gates2, sealed2, _) = setup(0x56E1);
    let s2 = &gates2.shares[0];
    assert_eq!(
        Pop::prove_unchecked(
            &sealed2,
            &gates2.claim,
            s2.id(),
            &own_share_scalar(&gates2, s2.id())
        )
        .expect("honest"),
        s2.prove(&sealed2, &gates2.claim, &gates2.salt)
            .expect("honest"),
    );
}

/// A coordinator's inflated claim is refused by the default entry point,
/// because the default entry point is the one that looks.
#[test]
fn the_default_holder_entry_point_refuses_a_claim_that_is_not_its_own() {
    let (_, gates, sealed, _) = setup(0x22E1);
    let share = &gates.shares[0];

    let inflated = ComponentClaim::from_parts(
        gates.claim.cohort(),
        gates.claim.threshold() + 1,
        gates.claim.roster().to_vec(),
        gates.claim.component(),
        gates.claim.verification_shares().to_vec(),
        gates.claim.seat_keys().to_vec(),
    );
    assert_eq!(
        share.prove(&sealed, &inflated, &gates.salt).unwrap_err(),
        CeremonyError::ClaimNotOwn {
            cohort: Gates::NAME,
            participant: share.id(),
        },
    );
    assert_eq!(
        share.proved_under(),
        None,
        "a refused claim does not spend the share's one proof"
    );

    // Control: the same call, same share, same composition, real claim.
    share
        .prove(&sealed, &gates.claim, &gates.salt)
        .expect("the real claim is accepted");
}

/// A salt that does not open this cohort's commitment is refused BEFORE the one
/// proof is spent.
///
/// The ordering is the value of the check, not a detail of it: a coordinator
/// that could burn a holder's one shot on a composition the holder's own reveal
/// can never open would force a restart at will.
#[test]
fn the_default_holder_entry_point_refuses_a_salt_before_spending_the_one_proof() {
    let (_, gates, sealed, _) = setup(0x33E1);
    let share = &gates.shares[0];

    assert_eq!(
        share.prove(&sealed, &gates.claim, &[0x5A; 32]).unwrap_err(),
        CeremonyError::CommitmentMismatch {
            cohort: Gates::NAME
        },
    );
    assert_eq!(
        share.proved_under(),
        None,
        "the shot is intact, which is why the salt is checked first"
    );

    // Control: the salt this cohort actually sealed under.
    share
        .prove(&sealed, &gates.claim, &gates.salt)
        .expect("the real salt is accepted");
    assert_eq!(share.proved_under(), Some(sealed));
}

/// The one-composition rule is carried by the default entry point too, so a
/// holder that never calls `prove_possession` still observes it.
#[test]
fn the_default_holder_entry_point_answers_one_sealed_composition() {
    let (owners, gates, sealed, ceremony) = setup(0x44E1);
    let share = &gates.shares[0];

    share
        .prove(&sealed, &gates.claim, &gates.salt)
        .expect("first proof");

    // A second composition: same ceremony, same claim, a DIFFERENT salt, so the
    // gate commitment inside it differs and this is a genuinely different
    // sealed composition rather than the same one re-asked.
    let other_salt = [0xEE; 32];
    let elsewhere = SealedComposition::new(
        ceremony,
        owners.commitment,
        seal_and_sign::<Gates>(&ceremony, &gates.claim, &other_salt),
    )
    .expect("well-formed");
    assert_ne!(elsewhere, sealed);

    assert_eq!(
        share
            .prove(&elsewhere, &gates.claim, &other_salt)
            .unwrap_err(),
        CeremonyError::ProofAlreadyIssued {
            cohort: Gates::NAME,
            participant: share.id(),
        },
    );

    // Control: the first composition is still answerable, idempotently.
    share
        .prove(&sealed, &gates.claim, &gates.salt)
        .expect("asking again for the same proof is not the thing being refused");
}
