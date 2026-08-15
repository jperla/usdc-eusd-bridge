//! Adversarial pass over per-seat attribution: forge an artifact that passes
//! with fewer real principals than `COMPROMISE_THRESHOLD`.
//!
//! `tests/seat_identity.rs` is the file that BUILT the seat rosters and states
//! their residual. This one attacks that statement. Everything here was written
//! against the crate's public API only, from the position of a party that holds
//! what the attack says it holds and nothing else.
//!
//! Two of the three tests are refusals with a named error and a control. The
//! first PASSES, deliberately: it is a forgery that reaches a published deposit
//! address, and it is here so the residual is a value this suite produces rather
//! than a paragraph in a doc comment.

mod common;

use std::collections::BTreeMap;

use common::{
    identity_of, parties_over, seat_key_of, seat_keys_over, seal_and_sign, CohortSide, Honest,
    SUBADDRESS,
};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, scalar::Scalar};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use two_cohort::{
    audit, audit_address,
    ceremony::{
        draw_salt, endorse_seat, seat_endorsement_message, ComponentClaim, ComponentReveal,
        SealedComposition, SeatRoster,
    },
    derive::subaddress_offset,
    dkg::run_dkg,
    identity::IdentitySignature,
    production::{
        authorize_release, check_decided_structure, deposit_spend_key, ReleaseRefused,
        COMPROMISE_THRESHOLD, OWNER_THRESHOLD,
    },
    CeremonyError, CeremonyId, Cohort, CohortSpec, CompositeSpend, CompositionArtifact,
    ControlDomain, Gates, Owners, Parties, Pop,
};

fn owners_spec() -> CohortSpec<Owners> {
    CohortSpec::<Owners>::sequential(2, 3)
}

fn gates_spec() -> CohortSpec<Gates> {
    CohortSpec::<Gates>::sequential(1, 1)
}

/// The keys a funder went and collected from the two organisations and the four
/// seat-holders, at the decided shape.
fn parties() -> Parties {
    parties_over(owners_spec().ids(), gates_spec().ids())
}

/// The view-side values a deployment supplies for one deposit.
struct Deposit {
    view: RistrettoPrivate,
    spend_public: RistrettoPublic,
    tx_public: RistrettoPublic,
}

impl Deposit {
    fn to(root: curve25519_dalek::ristretto::RistrettoPoint, rng: &mut ChaCha20Rng) -> Deposit {
        let view = RistrettoPrivate::from(Scalar::random(rng));
        let spend_public =
            RistrettoPublic::from(root + subaddress_offset(view.as_ref(), SUBADDRESS) * G);
        let tx_private = Scalar::random(rng);
        Deposit {
            view,
            tx_public: RistrettoPublic::from(tx_private * spend_public.as_ref()),
            spend_public,
        }
    }
}

/// The deployment path `production`'s module docs prescribe, end to end.
///
/// Copied in shape from `tests/forgery.rs::deployment_publishes` on purpose: an
/// attack that reaches a published address has to walk the SAME sequence a
/// deployment walks, and a path rewritten per test is a path that can be quietly
/// weakened per test.
fn deployment_publishes(
    artifact: &CompositionArtifact,
    parties: &Parties,
    deposit: &Deposit,
) -> Result<(CompositeSpend, RistrettoPublic), Box<dyn std::error::Error>> {
    let address = audit_address(
        artifact,
        parties,
        &deposit.view,
        SUBADDRESS,
        &deposit.spend_public,
    )?;
    check_decided_structure(address.root())?;
    let spend = CompositeSpend::from_ceremony(&address, &deposit.view, &deposit.tx_public)?;
    let published = {
        let auth = authorize_release(&spend, parties)?;
        deposit_spend_key(&auth)
    };
    Ok((spend, published))
}

// ---------------------------------------------------------------------------
// 1. The forgery that passes.
// ---------------------------------------------------------------------------

/// **A forgery at TWO principals against a decided threshold of three, in which
/// the three operator seats are three real parties that ran a real DKG and hold
/// real shares.**
///
/// `seat_identity.rs::a_dealer_that_keeps_the_shares_and_collects_signatures_still_passes`
/// performs the residual with seat-holders that hold nothing but an identity
/// key. The obvious reading of that test is that the named parties simply had
/// no key material to check the claim against, and that a deployment where the
/// DKG really ran is not exposed. This test removes that reading.
///
/// The sequence, and who holds what:
///
///   1. the owner cohort's DKG runs for real. `P1`, `P2`, `P3` each finish with
///      a `CohortShare` and each holds its own long-term seat key. The gate runs
///      its own cohort honestly;
///   2. the attacker is the operator ORGANISATION -- it holds the owners'
///      organisation identity key and NOT ONE SHARE and NOT ONE SEAT KEY. It
///      deals a secret `b'` of its own to itself over the same three ids, and
///      writes the three real seat-holders' public keys into the claim, which
///      are public values it is free to copy;
///   3. it asks each of `P1`, `P2`, `P3` to endorse its own seat. This is the
///      step the design intends to be the barrier, and it is crossed: the crate
///      exposes two entry points for it and only one of them looks at the
///      holder's own key material.
///
/// Both halves of step 3 are asserted below rather than described, because the
/// finding is exactly the gap between them:
///
///   * [`two_cohort::dkg::CohortShare::endorse`] REFUSES with
///     [`CeremonyError::ClaimNotOwn`] -- it compares the claim, field for field,
///     against the one this share's own key generation produced;
///   * [`endorse_seat`], a public free function taking only the claim and an
///     identity key, SIGNS. It checks that the claim attributes this seat to
///     this key, and nothing about the verification share it is signing over.
///
/// A seat-holder whose identity key lives where its share does not -- an HSM,
/// another process, the offline laptop the long-term key is on, which is the
/// ordinary arrangement for a long-term key -- has only the second entry point
/// available. The artifact records which one was used nowhere, so no funder can
/// tell the two apart.
///
/// The result: the attacker knows the discrete log of the whole owner component.
/// With the gate it opens the address; that is two principals against
/// [`COMPROMISE_THRESHOLD`] of three, and it reaches [`deposit_spend_key`].
///
/// **Said exactly, because "holds no share" is true of one dealing and false of
/// the other.** The attacker holds no share of the REAL DKG the three parties
/// ran -- that is what makes the three endorsements worth collecting. It
/// necessarily holds every share behind the dealing it SUBSTITUTED, because it
/// dealt that one to itself; that is what makes the published component
/// spendable by it alone. The published artifact is over the substituted
/// dealing. The real DKG's output appears nowhere in it and its shares are
/// worthless to their holders.
///
/// # If this test fails, it has been FIXED, not broken
///
/// This asserts that a forgery SUCCEEDS -- the only honest way to keep a
/// residual measurable, and the reason to state the consequence here rather
/// than leave it for whoever meets the red output. The day something binds an
/// endorser to a share-holder (endorse over a value derived from `s_i`, or make
/// [`endorse_seat`] non-public and record which entry point signed), the
/// `expect` calls in the audit half of this test will fail. That is the gap
/// closing. Replace the test with its inverse -- the refusal, asserted by exact
/// error, as `forgery.rs::a_dealt_owner_cohort_is_refused_at_the_seat_attribution`
/// does for the case that IS refused -- and update
/// `proofs/tla/AttributionCoverage.tla`'s `EndorserHoldsShare` row, which cites
/// this test by name as the reason that switch is FALSE. Do not "repair" it by
/// weakening an assertion.
#[test]
fn a_seat_holder_with_a_real_share_endorses_a_substituted_dealing_and_it_audits() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x50B);
    let ceremony = CeremonyId::draw("two-cohort eUSD release address", &mut rng);
    let ids = owners_spec().ids().to_vec();

    // ---- 1. the real cohort. Three parties, three real shares. ----
    let real_seats = SeatRoster::<Owners>::new(
        ids.iter().map(|&id| (id, seat_key_of::<Owners>(id).public())),
    )
    .expect("the decided owner seats");
    let real_shares = run_dkg::<Owners, _>(&ceremony, &owners_spec(), &real_seats, &mut rng)
        .expect("an honest owner DKG");
    let real_claim = ComponentClaim::of(real_shares[0].key());

    // ---- 2. the operator organisation's substituted dealing ----
    let b_forged = Scalar::random(&mut rng);
    let dealt = Cohort::deal_in::<Owners, _>(&b_forged, OWNER_THRESHOLD, &ids, &mut rng)
        .expect("a real 2-of-3 dealing of a secret the attacker chose");
    let forged_claim = ComponentClaim::from_parts(
        Owners::NAME,
        OWNER_THRESHOLD,
        ids.clone(),
        b_forged * G,
        ids.iter()
            .map(|&id| dealt.verification_share(id).expect("on the roster"))
            .collect(),
        // The real seat-holders' PUBLIC keys, copied.
        seat_keys_over::<Owners>(&ids),
    );
    assert_ne!(
        forged_claim.component(),
        real_claim.component(),
        "the attacker's dealing is a different cohort key from the one the DKG produced",
    );

    // ---- 3. the endorsements, through both entry points ----
    for share in &real_shares {
        // The checked one sees the substitution.
        assert_eq!(
            share
                .endorse(&ceremony, &forged_claim, &seat_key_of::<Owners>(share.id()))
                .expect_err("a real holder's own key material contradicts this claim"),
            CeremonyError::ClaimNotOwn {
                cohort: Owners::NAME,
                participant: share.id(),
            },
        );
    }
    // The unchecked one does not, and it is public, and it needs no share.
    let endorsements: BTreeMap<u64, IdentitySignature> = ids
        .iter()
        .map(|&id| {
            (
                id,
                endorse_seat(&ceremony, &forged_claim, id, &seat_key_of::<Owners>(id))
                    .expect("THE FINDING: this signs a claim the signer's own share contradicts"),
            )
        })
        .collect();

    // ---- assemble, with an honest gate ----
    let salt = draw_salt(&mut rng);
    let signed = seal_and_sign::<Owners>(&ceremony, &forged_claim, &salt);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);
    let sealed = SealedComposition::new(ceremony, signed, gates.commitment).expect("well-formed");
    let pops: BTreeMap<u64, Pop> = ids
        .iter()
        .map(|&id| {
            (
                id,
                // The attacker dealt, so the attacker knows every share.
                Pop::prove_unchecked(&sealed, &forged_claim, id, &dealt.share(id).expect("dealt"))
                    .expect("the dealer holds it"),
            )
        })
        .collect();
    let artifact = CompositionArtifact::from_parts(
        sealed,
        ComponentReveal::from_parts(forged_claim, pops, endorsements, salt),
        gates.reveal(&sealed),
    );

    // ---- the funder's own check, under the keys it collected from the six ----
    let audited = audit(&artifact, &parties()).expect("THE FORGERY AUDITS");
    let (owners_found, _) = audited.structure();
    assert_eq!(
        owners_found.seats(),
        ids.iter()
            .map(|&id| (id, seat_key_of::<Owners>(id).public()))
            .collect::<Vec<_>>(),
        "the funder is told the three real parties hold the three operator seats",
    );

    // ---- and it reaches a published deposit address ----
    let deposit = Deposit::to(artifact.declared_root(), &mut rng);
    let (spend, published) = deployment_publishes(&artifact, &parties(), &deposit)
        .expect("the forgery reaches the funding path, not only the audit");
    assert_eq!(published, deposit.spend_public);

    // ---- and TWO principals open the output paid to it ----
    //
    // The attacker contributes `b_forged` -- the whole owner component, which it
    // chose -- and the gate contributes its one share through the ordinary
    // holder API. Nothing here needs any of the three operator seats, and none
    // of them could have supplied anything if it wanted to: their shares are of
    // a component that is not in this address.
    let gq = gates.quorum(1);
    let b_gate: Scalar = gq
        .iter()
        .map(|&id| *gates.share_of(id).term(&gq).expect("quorum member").weight())
        .sum();
    assert_eq!(
        (*spend.common() + b_forged + b_gate) * G,
        *spend.target().as_ref(),
        "two principals -- the operator organisation and the gate -- open an output \
         against a decided COMPROMISE_THRESHOLD of {COMPROMISE_THRESHOLD}",
    );

    // ---- THE HARM, stated as arithmetic ----
    //
    // The attacker holds `b_forged`, the discrete log of the entire owner
    // component. No member of the honest 2-of-3 that actually ran holds that,
    // and the three parties whose keys are in the audited structure hold shares
    // of a DIFFERENT component that appears nowhere in the artifact.
    assert_eq!(owners_found.component(), b_forged * G);
    for share in &real_shares {
        assert_ne!(
            owners_found.component(),
            real_claim
                .verification_share(share.id())
                .expect("on the roster"),
        );
    }
    assert_ne!(
        owners_found.component(),
        real_claim.component(),
        "the component a funder audited is not the one the real DKG produced",
    );
    // Two principals -- the operator organisation and the gate -- against three.
    assert_eq!(COMPROMISE_THRESHOLD, 3);

    // ---- and the count the docs give for this bar is wrong ----
    //
    // `production.rs` and `lib.rs` both say per-seat keys moved "the number of
    // distinct SIGNATURES a forgery must collect, from one to five". The
    // signatures THIS forgery had to collect are the owner organisation's
    // commitment endorsement (its own) and one endorsement from each of the
    // three operator seats: four. The gate's organisation signature and the gate
    // seat's endorsement are made by the honest gate for its own honest cohort
    // and are not collected by the forger at all. Counted the other way -- every
    // identity signature the artifact carries -- it is two organisations plus
    // four seats, which is six. Five is neither.
    let collected_by_the_forger = 1 + ids.len();
    assert_eq!(collected_by_the_forger, 4);
    let carried_by_the_artifact = 2 + ids.len() + gates_spec().ids().len();
    assert_eq!(carried_by_the_artifact, 6);
}

// ---------------------------------------------------------------------------
// 2. Transposition, at the audit.
// ---------------------------------------------------------------------------

/// **Attack.** Present the funder's own four keys, at each other's seats.
///
/// The multiset of keys in the claim is exactly the multiset the funder
/// collected, so nothing is added, forged or removed -- only WHICH seat each key
/// is attributed to. Every endorsement verifies against the claim's own keys, so
/// the endorsement check is not what fires and cannot be what fires: the seat
/// signing at position `k` really does hold the key the claim names there.
///
/// This is the shape a set comparison admits and a positional one refuses, and
/// it is worth its own test because the audit's seat check is the only thing
/// standing between "the funder's four keys appear" and "the funder's four keys
/// hold the seats the funder thinks". Refused at
/// [`CeremonyError::SeatUnexpected`].
///
/// The control is the same construction with the permutation removed -- one
/// input, applied to both the attribution and the signer that follows it -- and
/// it audits.
#[test]
fn transposing_two_seat_keys_is_refused_though_the_key_multiset_is_unchanged() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x7A5);
    let ceremony = CeremonyId::draw("transposed seats", &mut rng);
    let ids = owners_spec().ids().to_vec();
    let b_owner = Scalar::random(&mut rng);
    let dealt = Cohort::deal_in::<Owners, _>(&b_owner, OWNER_THRESHOLD, &ids, &mut rng)
        .expect("dealt");
    let verification: Vec<_> = ids
        .iter()
        .map(|&id| dealt.verification_share(id).expect("on the roster"))
        .collect();

    // `assign[k]` is the id whose SEAT KEY is written at roster position `k`.
    let mount = |assign: &[u64], rng: &mut ChaCha20Rng| {
        let claim = ComponentClaim::from_parts(
            Owners::NAME,
            OWNER_THRESHOLD,
            ids.clone(),
            b_owner * G,
            verification.clone(),
            assign
                .iter()
                .map(|&id| seat_key_of::<Owners>(id).public())
                .collect(),
        );
        let salt = draw_salt(rng);
        let signed = seal_and_sign::<Owners>(&ceremony, &claim, &salt);
        let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), rng);
        let sealed =
            SealedComposition::new(ceremony, signed, gates.commitment).expect("well-formed");
        let pops: BTreeMap<u64, Pop> = ids
            .iter()
            .map(|&id| {
                (
                    id,
                    Pop::prove_unchecked(&sealed, &claim, id, &dealt.share(id).expect("dealt"))
                        .expect("holds it"),
                )
            })
            .collect();
        // Signed by whoever the claim names at that position, so every
        // endorsement VERIFIES and the refusal below cannot be the signature
        // check standing in for the attribution check.
        let endorsements: BTreeMap<u64, IdentitySignature> = ids
            .iter()
            .zip(assign)
            .map(|(&id, &signer)| {
                let msg = seat_endorsement_message(&ceremony, &claim, id).expect("on the roster");
                (id, seat_key_of::<Owners>(signer).sign(&msg))
            })
            .collect();
        CompositionArtifact::from_parts(
            sealed,
            ComponentReveal::from_parts(claim, pops, endorsements, salt),
            gates.reveal(&sealed),
        )
    };

    let swapped = [ids[1], ids[0], ids[2]];
    let attack = mount(&swapped, &mut rng);
    assert_eq!(
        audit(&attack, &parties()).expect_err("the funder's keys are at the wrong seats"),
        CeremonyError::SeatUnexpected {
            cohort: Owners::NAME,
            participant: ids[0],
            expected: seat_key_of::<Owners>(ids[0]).public(),
            found: seat_key_of::<Owners>(ids[1]).public(),
        },
    );

    // CONTROL: the permutation removed and nothing else changed.
    let control = mount(&ids, &mut rng);
    audit(&control, &parties()).expect("the identity permutation audits");
}

// ---------------------------------------------------------------------------
// 3. Transposition, at the release gate.
// ---------------------------------------------------------------------------

/// **Attack.** The audit ran under the true seat roster; the DEPLOYMENT is
/// holding the same four keys against the wrong four seats.
///
/// The gate's own seat arm is the twin of the audit's, and it needs its own
/// transposition test for the same reason: `production::check_seats` compares
/// the id SETS first and then walks them, and a version that compared key sets
/// instead would admit this. The key multiset is identical on both sides.
///
/// Refused at [`ReleaseRefused::Seat`]. The control is the same spend passed the
/// untransposed roster.
#[test]
fn a_deployment_holding_the_seat_keys_transposed_is_refused_at_the_gate() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x7A6);
    let h = Honest::run(0x7A7, &owners_spec(), &gates_spec());
    let ids = owners_spec().ids().to_vec();
    let deposit = Deposit::to(h.artifact.declared_root(), &mut rng);

    let address = audit_address(
        &h.artifact,
        &parties(),
        &deposit.view,
        SUBADDRESS,
        &deposit.spend_public,
    )
    .expect("an honest ceremony audits");
    let spend = CompositeSpend::from_ceremony(&address, &deposit.view, &deposit.tx_public)
        .expect("audited address");

    let transposed = Parties::new(
        identity_of::<Owners>().public(),
        SeatRoster::<Owners>::new([
            (ids[0], seat_key_of::<Owners>(ids[1]).public()),
            (ids[1], seat_key_of::<Owners>(ids[0]).public()),
            (ids[2], seat_key_of::<Owners>(ids[2]).public()),
        ])
        .expect("three distinct owner ids"),
        identity_of::<Gates>().public(),
        SeatRoster::<Gates>::new([(
            gates_spec().ids()[0],
            seat_key_of::<Gates>(gates_spec().ids()[0]).public(),
        )])
        .expect("one gate id"),
    );
    assert_eq!(
        authorize_release(&spend, &transposed)
            .map(|_| ())
            .expect_err("the deployment names the wrong party for two of its seats"),
        ReleaseRefused::Seat {
            cohort: Owners::NAME,
            participant: ids[0],
            expected: seat_key_of::<Owners>(ids[1]).public(),
            found: seat_key_of::<Owners>(ids[0]).public(),
        },
    );

    // CONTROL: the same spend, the same gate, the transposition removed.
    authorize_release(&spend, &parties()).expect("the untransposed roster authorises");
}
