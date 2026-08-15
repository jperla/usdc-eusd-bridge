//! The release gate: what a deployment must pass before a key is used, and
//! what a funder must be able to answer about the key it is asked to pay.
//!
//! The order of this file is the order the work was done in. The GAP is
//! performed first -- a simulated root reaching the funding path a deployment
//! writes today, and then being spent by the single process that made it -- so
//! that every refusal below is a refusal of something exhibited rather than of
//! something imagined.
//!
//! The honest ceremony is driven by `common::Honest`, which is the same harness
//! `composition.rs` uses; the shape it runs at is the argument, so the tests
//! that need a WRONG shape get one by running a real ceremony at that shape
//! rather than by editing an audited value.

mod common;

use common::{identity_of, parties, CohortSide, Honest, SUBADDRESS};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, scalar::Scalar};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use two_cohort::{
    audit, audit_address,
    ceremony::{Parties, SealedComposition, SignedCommitment},
    identity::IdentityKey,
    production::{
        self, authorize_release, check_decided_structure, deposit_spend_key, ReleaseRefused,
        GATE_THRESHOLD, OWNER_THRESHOLD,
    },
    CohortSpec, CompositeSpend, ControlDomain, Error, Gates, Owners, Provenance,
};

/// The decided owner cohort: 2 of 3.
fn decided_owners() -> CohortSpec<Owners> {
    production::owners()
}

/// The decided gate cohort: the single gate must sign.
fn decided_gates() -> CohortSpec<Gates> {
    production::gates()
}

/// An honest ceremony at the decided shape.
fn decided_ceremony(seed: u64) -> Honest {
    Honest::run(seed, &decided_owners(), &decided_gates())
}

// ---------------------------------------------------------------------------
// THE GAP.
// ---------------------------------------------------------------------------

/// **The gap, performed: a simulated root reaches a funding path today, and the
/// one process that made it can spend the address it published.**
///
/// `Provenance` has been on `CompositeSpend` since `CompositeSpend` existed and
/// nothing outside a test read it. `todays_funding_path` below is what a
/// deployment writes when the type offers nothing to consult -- it takes the
/// spend, and there is no argument it could take instead that would be any
/// safer, because until `authorize_release` there was no such argument.
///
/// The harm is not that the two values look alike. It is the last block: the
/// address this test just published is spendable by this test, alone, with no
/// cohort convened. That is what `Provenance::Simulated` means and what a
/// deployment had no way to notice.
#[test]
fn a_simulated_root_reaches_the_funding_path_today() {
    // The funding path as it can be written today: it has a `CompositeSpend`
    // and publishes the address depositors pay.
    fn todays_funding_path(spend: &CompositeSpend) -> mc_crypto_keys::RistrettoPublic {
        *spend.spend_public()
    }

    // Right shape, right subaddress, wrong -- and undetectable -- origin.
    let simulated =
        CompositeSpend::simulate_from_seed(0xDEA1E7, &decided_owners(), &decided_gates(), SUBADDRESS)
            .expect("a dealer will deal any shape asked of it");
    assert_eq!(simulated.provenance(), Provenance::Simulated);
    assert_eq!(simulated.owners().roster(), decided_owners().ids());
    assert_eq!(simulated.owners().threshold(), OWNER_THRESHOLD);
    assert_eq!(simulated.gates().roster(), decided_gates().ids());
    assert_eq!(simulated.gates().threshold(), GATE_THRESHOLD);

    // It is published. Nothing refused it.
    let published = todays_funding_path(&simulated);
    assert_eq!(published, *simulated.spend_public());

    // And this process -- one process, holding no ceremony, convening nobody --
    // opens the output paid to it.
    let o = vec![Owners::nth(0), Owners::nth(1)];
    let g = vec![Gates::nth(0)];
    let x = simulated
        .onetime(&o, &g)
        .expect("a dealt cohort hands over its shares");
    assert_eq!(
        *x * G,
        *simulated.target().as_ref(),
        "the single process that generated this address holds the one-time key \
         for an output paid to it"
    );
}

/// The same call, refused. `authorize_release` is the arm that reads the field
/// nothing read before.
#[test]
fn the_gate_refuses_the_simulated_root_the_funding_path_accepted() {
    let simulated =
        CompositeSpend::simulate_from_seed(0xDEA1E7, &decided_owners(), &decided_gates(), SUBADDRESS)
            .expect("dealt");
    assert_eq!(
        authorize_release(&simulated, &parties()).unwrap_err(),
        ReleaseRefused::NotFromCeremony,
    );
}

// ---------------------------------------------------------------------------
// The control: the decided shape, out of a real ceremony, passes.
// ---------------------------------------------------------------------------

/// A production key at the decided shape passes the gate, reaches the funding
/// path, and CANNOT be spent by the process holding it.
///
/// The last assertion is the one that makes the first test's harm attributable
/// to provenance rather than to some other difference: same shape, same
/// subaddress, same funding call -- and here `onetime` refuses, because the
/// shares are with the participants that generated them.
#[test]
fn the_gate_admits_a_ceremony_key_at_the_decided_shape() {
    let h = decided_ceremony(0x9A1E);
    let d = h.spend_public();
    let address = audit_address(&h.artifact, &parties(), &h.view, SUBADDRESS, &d)
        .expect("an honest ceremony audits");
    let spend = CompositeSpend::from_ceremony(&address, &h.view, &h.tx_public()).expect("production");

    let auth = authorize_release(&spend, &parties()).expect("the decided shape, out of a ceremony");
    assert_eq!(auth.ceremony(), h.ceremony);
    assert!(
        std::ptr::eq(auth.spend(), &spend),
        "the authorisation is bound to the value it was issued against, not to a \
         copy of its fields"
    );
    assert_eq!(deposit_spend_key(&auth), d);

    // The harm exhibited in `a_simulated_root_reaches_the_funding_path_today` is
    // absent here, and absent for a structural reason rather than by omission.
    let o = vec![Owners::nth(0), Owners::nth(1)];
    let g = vec![Gates::nth(0)];
    assert_eq!(
        spend.onetime(&o, &g).unwrap_err().kind(),
        &Error::SharesNotHeld,
    );
}

// ---------------------------------------------------------------------------
// The shape arms. Each one is a real ceremony run at a shape nobody decided.
// ---------------------------------------------------------------------------

/// A 2-of-3 gate cohort is refused, even though it is HARDER to compromise than
/// the decided 1-of-1.
///
/// The gate pins the decided structure in both directions on purpose. The
/// decided structure is the one that was reviewed and the one
/// `COMPROMISE_THRESHOLD` is computed over; a key that differs from it in a
/// direction nobody asked for is still a key nobody signed off, and for the gate
/// cohort specifically it is a key with a different -- unwritten -- recovery
/// story.
#[test]
fn the_gate_refuses_a_ceremony_at_an_undecided_gate_threshold() {
    let h = Honest::run(0x6A7E, &decided_owners(), &CohortSpec::<Gates>::sequential(2, 3));
    let d = h.spend_public();
    let address =
        audit_address(&h.artifact, &parties(), &h.view, SUBADDRESS, &d).expect("it audits fine");
    let spend = CompositeSpend::from_ceremony(&address, &h.view, &h.tx_public()).expect("built");

    // The roster arm fires first: 3 gate seats is already not the decided one.
    assert_eq!(
        authorize_release(&spend, &parties()).unwrap_err(),
        ReleaseRefused::Roster {
            cohort: "gates",
            expected: decided_gates().ids().to_vec(),
            found: vec![Gates::nth(0), Gates::nth(1), Gates::nth(2)],
        },
    );
}

/// The threshold arm, isolated: the decided ROSTERS, one of them at a threshold
/// nobody decided.
///
/// 3-of-3 owners over the decided three seats. The roster arm cannot fire, so
/// the refusal is attributable to the threshold alone.
#[test]
fn the_gate_refuses_a_ceremony_at_an_undecided_owner_threshold() {
    let h = Honest::run(
        0x3073,
        &CohortSpec::<Owners>::sequential(3, 3),
        &decided_gates(),
    );
    let d = h.spend_public();
    let address =
        audit_address(&h.artifact, &parties(), &h.view, SUBADDRESS, &d).expect("it audits fine");
    let spend = CompositeSpend::from_ceremony(&address, &h.view, &h.tx_public()).expect("built");

    assert_eq!(
        spend.owners().roster(),
        decided_owners().ids(),
        "control: the roster is the decided one, so only the threshold differs"
    );
    assert_eq!(
        authorize_release(&spend, &parties()).unwrap_err(),
        ReleaseRefused::Threshold {
            cohort: "owners",
            expected: OWNER_THRESHOLD,
            found: 3,
        },
    );
}

/// The roster arm, isolated: the decided COUNT and the decided threshold, over
/// seats that are not the decided ones.
///
/// Two owner organisations and a third that was never on the list is a 2-of-3
/// by every count the audit reports. Only the identity of the seats differs.
#[test]
fn the_gate_refuses_a_ceremony_over_an_undecided_owner_roster() {
    let substituted = CohortSpec::<Owners>::with_ids(
        OWNER_THRESHOLD,
        &[Owners::nth(0), Owners::nth(1), Owners::nth(9)],
    );
    let h = Honest::run(0x5EA7, &substituted, &decided_gates());
    let d = h.spend_public();
    let address =
        audit_address(&h.artifact, &parties(), &h.view, SUBADDRESS, &d).expect("it audits fine");
    let spend = CompositeSpend::from_ceremony(&address, &h.view, &h.tx_public()).expect("built");

    assert_eq!(
        spend.owners().threshold(),
        OWNER_THRESHOLD,
        "control: the threshold is the decided one, so only the roster differs"
    );
    assert_eq!(
        authorize_release(&spend, &parties()).unwrap_err(),
        ReleaseRefused::Roster {
            cohort: "owners",
            expected: decided_owners().ids().to_vec(),
            found: vec![Owners::nth(0), Owners::nth(1), Owners::nth(9)],
        },
    );
}

// ---------------------------------------------------------------------------
// The organisations behind the ceremony.
// ---------------------------------------------------------------------------

/// **A ceremony run by an entirely different pair of organisations produces a
/// key that passes every OTHER arm of this gate, and is refused because the
/// audited identity keys travel with the spend.**
///
/// This is not a forged artifact. Two impostor organisations run two real DKGs,
/// endorse their own commitments with their own long-term keys, and hand over a
/// composition that `audit` accepts -- under THEIR keys, which is the only thing
/// `audit` can do, since the keys are its caller's input. Shape, rosters,
/// thresholds, subaddress and `Provenance::Ceremony` are all identical to the
/// real thing. The single difference is who endorsed it.
///
/// The control is the same spend authorised against the impostors' own keys: it
/// passes. So the refusal below is attributable to the identity comparison and
/// to nothing else about the ceremony.
#[test]
fn the_gate_refuses_a_key_audited_under_organisations_this_deployment_does_not_name() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x1D0175);
    let ceremony = two_cohort::CeremonyId::draw("impostor composition", &mut rng);

    // Two real DKGs at the decided shape...
    let owners = CohortSide::<Owners>::generate(&ceremony, &decided_owners(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &decided_gates(), &mut rng);

    // ...endorsed by organisations that are not the ones this deployment names.
    let impostor_owner_org = IdentityKey::from_seed(&[0xA1; 32]);
    let impostor_gate_org = IdentityKey::from_seed(&[0xA2; 32]);
    let impostors = Parties::new(impostor_owner_org.public(), impostor_gate_org.public());
    assert_ne!(
        impostors,
        parties(),
        "control: these really are different organisations"
    );

    let sealed = SealedComposition::new(
        ceremony,
        SignedCommitment::create(
            &ceremony,
            owners.commitment.commitment(),
            &impostor_owner_org,
        ),
        SignedCommitment::create(&ceremony, gates.commitment.commitment(), &impostor_gate_org),
    )
    .expect("well-formed");
    let artifact = sealed
        .open(owners.reveal(&sealed), gates.reveal(&sealed), &impostors)
        .expect("a real ceremony, run by the wrong people");

    // It audits -- under the impostors' keys, which is what a deployment that
    // took the keys from the artifact instead of from the organisations would
    // be doing.
    let view = mc_crypto_keys::RistrettoPrivate::from(Scalar::random(&mut rng));
    let d = mc_crypto_keys::RistrettoPublic::from(
        artifact.declared_root()
            + two_cohort::derive::subaddress_offset(view.as_ref(), SUBADDRESS) * G,
    );
    let r = mc_crypto_keys::RistrettoPublic::from(Scalar::random(&mut rng) * d.as_ref());
    let address = audit_address(&artifact, &impostors, &view, SUBADDRESS, &d).expect("audits");
    let spend = CompositeSpend::from_ceremony(&address, &view, &r).expect("built");

    // Every other arm is satisfied.
    assert!(matches!(spend.provenance(), Provenance::Ceremony(_)));
    assert_eq!(spend.owners().roster(), decided_owners().ids());
    assert_eq!(spend.owners().threshold(), OWNER_THRESHOLD);
    assert_eq!(spend.gates().roster(), decided_gates().ids());
    assert_eq!(spend.gates().threshold(), GATE_THRESHOLD);
    check_decided_structure(address.root()).expect("the decided shape, exactly");

    assert_eq!(
        authorize_release(&spend, &parties()).unwrap_err(),
        ReleaseRefused::Endorser {
            cohort: "owners",
            expected: identity_of::<Owners>().public(),
            found: impostor_owner_org.public(),
        },
    );

    // Control: the same spend, authorised against the keys it was actually
    // audited under, passes. Only the named organisations differed.
    authorize_release(&spend, &impostors)
        .expect("the gate has no objection to this ceremony except who ran it");
}

/// The gate side is checked as well as the owner side, so one honest half does
/// not satisfy a single check.
#[test]
fn the_endorser_arm_is_per_cohort() {
    let h = decided_ceremony(0x2222);
    let d = h.spend_public();
    let address = audit_address(&h.artifact, &parties(), &h.view, SUBADDRESS, &d).expect("audits");
    let spend = CompositeSpend::from_ceremony(&address, &h.view, &h.tx_public()).expect("built");

    let stranger = IdentityKey::from_seed(&[0xB9; 32]);
    assert_eq!(
        authorize_release(
            &spend,
            &Parties::new(identity_of::<Owners>().public(), stranger.public()),
        )
        .unwrap_err(),
        ReleaseRefused::Endorser {
            cohort: "gates",
            expected: stranger.public(),
            found: identity_of::<Gates>().public(),
        },
        "the real gate organisation is not the one this deployment named"
    );

    // Control: both named correctly.
    authorize_release(&spend, &parties()).expect("both organisations named correctly");
}

// ---------------------------------------------------------------------------
// The funder's half.
// ---------------------------------------------------------------------------

/// **The funder's question, answered from the artifact.**
///
/// Stated as narrowly as the body supports, which is narrower than the name it
/// used to carry. It is NOT "is this subaddress spend key jointly controlled by
/// exactly these two rosters at exactly these thresholds?" -- review pointed out
/// that no assertion over the present artifact can establish that, and
/// `forgery.rs` returns YES to this very sequence for a root one operator entity
/// controls outright. What the two calls answer is:
///
/// > Does `D_i` equal `B_owner + B_gate + Hs(a||i)*G`, where each component
/// > opens a commitment endorsed under the identity key supplied for its cohort,
/// > every published verification share carries a bound proof of possession, and
/// > the audited rosters and exact degrees are the DECIDED ones?
///
/// YES for the decided ceremony, NO for a ceremony that audits perfectly at a
/// shape nobody decided. The NO is the point: `audit` alone answers "these
/// rosters at these degrees", and it is `check_decided_structure` that knows
/// which ones were agreed. See `production`'s module docs for the trust
/// conditions that ride along, including the view key this test hands in.
#[test]
fn the_funder_question_is_answerable_from_the_artifact() {
    let h = decided_ceremony(0xF00D);
    let d = h.spend_public();

    // The funder holds the artifact, the two organisations' identity public
    // keys, the view key and the address it is about to pay.
    let address =
        audit_address(&h.artifact, &parties(), &h.view, SUBADDRESS, &d).expect("YES: it audits");
    check_decided_structure(address.root()).expect("YES: and at the decided shape");
    assert_eq!(address.spend_public(), &d);

    // A ceremony at an undecided shape audits and is still refused.
    let wrong = Honest::run(0xBADD, &decided_owners(), &CohortSpec::<Gates>::sequential(2, 3));
    let wd = wrong.spend_public();
    let wrong_address = audit_address(&wrong.artifact, &parties(), &wrong.view, SUBADDRESS, &wd)
        .expect("it audits: `audit` does not know what was decided");
    assert_eq!(
        check_decided_structure(wrong_address.root()).unwrap_err(),
        ReleaseRefused::Roster {
            cohort: "gates",
            expected: decided_gates().ids().to_vec(),
            found: vec![Gates::nth(0), Gates::nth(1), Gates::nth(2)],
        },
        "NO",
    );
}

/// The two entry points cannot drift on SHAPE: the same ceremony gets the same
/// verdict from the artifact side and from the constructed-spend side.
///
/// They share `check_decided_shape`, and this is the assertion that the sharing
/// is real rather than two copies that happen to agree today. It is scoped to
/// shape on purpose -- `authorize_release` has strictly more arms than
/// `check_decided_structure` (provenance, and the endorsing organisations), and
/// the runs below are all honest ceremonies under the named parties so those
/// arms pass and the shape verdict is what is left to compare.
#[test]
fn the_artifact_side_and_the_spend_side_agree() {
    for (label, owners, gates) in [
        ("decided", decided_owners(), decided_gates()),
        (
            "undecided owner threshold",
            CohortSpec::<Owners>::sequential(3, 3),
            decided_gates(),
        ),
        (
            "undecided gate roster",
            decided_owners(),
            CohortSpec::<Gates>::sequential(2, 3),
        ),
    ] {
        let h = Honest::run(0xA9A9, &owners, &gates);
        let d = h.spend_public();
        let address =
            audit_address(&h.artifact, &parties(), &h.view, SUBADDRESS, &d).expect("audits");
        let spend =
            CompositeSpend::from_ceremony(&address, &h.view, &h.tx_public()).expect("built");

        let from_artifact = check_decided_structure(address.root());
        let from_spend = authorize_release(&spend, &parties()).map(|_| ());
        assert_eq!(from_artifact, from_spend, "{label}");
    }
}

/// `audit` on its own does not answer the funder's question, and this is the
/// evidence that the second half is load-bearing rather than ceremonial.
#[test]
fn audit_alone_accepts_a_shape_nobody_decided() {
    let wrong = Honest::run(0xBADD, &decided_owners(), &CohortSpec::<Gates>::sequential(2, 3));
    let audited = audit(&wrong.artifact, &parties()).expect("a perfectly honest ceremony");
    let (_, gates_found) = audited.structure();
    assert_eq!(gates_found.threshold(), 2);
    assert_eq!(gates_found.roster().len(), 3);

    // The exact refusal, not `is_err()`. A test that accepts any error accepts
    // one raised for a reason it was not written about -- this file's own
    // history includes a negative test that took an error from the wrong layer.
    assert_eq!(
        check_decided_structure(&audited).unwrap_err(),
        ReleaseRefused::Roster {
            cohort: Gates::NAME,
            expected: decided_gates().ids().to_vec(),
            found: gates_found.roster().to_vec(),
        },
    );
}

// ---------------------------------------------------------------------------
// The one-time key is still the one upstream derives, at the decided shape.
// ---------------------------------------------------------------------------

/// A 1-of-1 gate cohort is a real cohort, not a degenerate case the algebra
/// quietly drops.
///
/// The decided structure has exactly one gate seat, so every property this crate
/// rests on has to hold at `g = m = 1` -- and a Lagrange weight over a
/// single-point subset is exactly where a "1" could be produced by accident
/// rather than by interpolation. Checked here against the composite target key,
/// which is derived from the audited root and not from anything this test
/// assembles.
#[test]
fn the_decided_shape_reconstructs_the_one_time_key_over_every_quorum() {
    let h = decided_ceremony(0x1111);
    let d = h.spend_public();
    let address = audit_address(&h.artifact, &parties(), &h.view, SUBADDRESS, &d).expect("audits");
    let spend = CompositeSpend::from_ceremony(&address, &h.view, &h.tx_public()).expect("built");
    let auth = authorize_release(&spend, &parties()).expect("decided");

    let g = vec![Gates::nth(0)];
    let gate_term: Scalar = *h.gates.share_of(Gates::nth(0)).term(&g).unwrap().weight();

    let mut seen = 0;
    for o in two_cohort::subsets_of(decided_owners().ids(), OWNER_THRESHOLD) {
        let owner_term: Scalar = o
            .iter()
            .map(|&id| *h.owners.share_of(id).term(&o).unwrap().weight())
            .sum();
        let x = auth.spend().common() + owner_term + gate_term;
        assert_eq!(
            x * G,
            *auth.spend().target().as_ref(),
            "owner quorum {o:?} with the single gate does not open the output"
        );
        seen += 1;
    }
    assert_eq!(seen, 3, "all three owner quorums of the decided structure");
}
