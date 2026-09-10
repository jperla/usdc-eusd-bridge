//! The composition ceremony, and the artifact a funder checks.
//!
//! One honest ceremony is driven in `common::Honest` and reused where it can
//! be; a tampering test that starts from it changes exactly ONE thing, so the
//! rejection is attributable to that change against the same run.
//!
//! Not every test can do that, and the ones that cannot say so at the point
//! where it matters. `prove_possession` lets each share answer exactly one
//! sealed composition, and a tampered gate claim is a different composition --
//! so a control and its defect need separate owner cohorts. Where that is the
//! case the two runs differ only in freshly drawn honest material on the side
//! the assertion is not about, and the comment on the helper says which.
//!
//! Acceptance is decided by [`two_cohort::audit`] for the artifact and by the
//! unmodified, vendored `RingMLSAG::verify` for the signature. The one place a
//! value is checked against something this file computed --
//! [`the_production_key_image_agrees_with_upstreams_own_derivation`] -- is
//! checked against MobileCoin's own `KeyImage` derivation, not against a
//! constant chosen here.

mod common;

use std::collections::BTreeMap;

use common::{parties_over, seal_and_sign, seat_endorsements, seat_keys_over, CohortSide, Honest, SUBADDRESS};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G, ristretto::RistrettoPoint, scalar::Scalar,
    traits::Identity,
};
use mc_crypto_keys::RistrettoPrivate;
use mc_crypto_ring_signature::{Commitment, CompressedCommitment, KeyImage};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use two_cohort::{
    audit, audit_address,
    ceremony::{prove_possession, SealedComposition},
    fixture::make_ring_from_seed,
    mlsag::{
        quorum_signers, sign, MaskSigner, MemoryNonceGuard, SessionParams, SigningError,
        SpendSigner,
    },
    lagrange_at_zero, subsets_of, CeremonyError, CeremonyId, CohortSpec, CompositeSpend, CompositionArtifact, ComponentClaim,
    ComponentReveal, ControlDomain, Error, Gates, Owners, Pop, Provenance,
};

const MESSAGE: &[u8] = b"composition: release eUSD from the composite root";
const RING_SIZE: usize = 11;
const REAL_INDEX: usize = 5;
const VALUE: u64 = 5_000;

fn owners_spec() -> CohortSpec<Owners> {
    CohortSpec::<Owners>::sequential(2, 3)
}

fn gates_spec() -> CohortSpec<Gates> {
    CohortSpec::<Gates>::sequential(2, 3)
}

fn honest() -> Honest {
    Honest::run(0xC0FFEE, &owners_spec(), &gates_spec())
}

/// Everyone a funder of an artifact at THIS file's shape holds a key for.
///
/// Local rather than `common::parties`, because a `Parties` now names SEATS and
/// this file's gate cohort is 2-of-3 rather than the decided 1-of-1. A test that
/// builds a cohort at some other shape must use [`parties_over`] -- reusing this
/// one would be audited as the wrong seats, which is now a refusal rather than
/// something that silently passes.
fn parties() -> two_cohort::Parties {
    parties_over(owners_spec().ids(), gates_spec().ids())
}

// ---------------------------------------------------------------------------
// The honest ceremony.
// ---------------------------------------------------------------------------

/// The artifact audits, and what it says is what the two cohorts actually did.
#[test]
fn an_honest_ceremony_produces_an_artifact_that_audits() {
    let h = honest();
    let audited = audit(&h.artifact, &parties()).expect("an honest composition audits");

    // The root is the sum of exactly the two components, each of which is the
    // key its own cohort's DKG produced -- values this test never assembles.
    assert_eq!(
        audited.root(),
        h.owners.shares[0].key().component() + h.gates.shares[0].key().component()
    );
    assert_eq!(audited.ceremony(), &h.ceremony);

    // "exactly these two rosters at exactly these thresholds", and -- since the
    // audit was given the two organisations' keys -- by exactly these two
    // parties. `tests/attribution.rs` is where that last clause is earned.
    let (o, g) = audited.structure();
    let (orost, grost) = (o.roster(), g.roster());
    assert_eq!((o.threshold(), orost), (2, owners_spec().ids()));
    assert_eq!((g.threshold(), grost), (2, gates_spec().ids()));

    // The two rosters are disjoint, which is what makes an owner quorum not a
    // gate quorum. Checked on the audited value, not on the specs.
    assert!(orost.iter().all(|id| !grost.contains(id)));
    assert!(orost.iter().all(|&id| Owners::owns(id)));
    assert!(grost.iter().all(|&id| Gates::owns(id)));
}

/// The audit is a function of the artifact and the two identity keys, and of
/// nothing else: an artifact rebuilt from its own published parts audits
/// identically. It does NOT depend on having been present, on a shared session,
/// or on anything either cohort still holds.
#[test]
fn the_audit_needs_nothing_but_the_artifact() {
    let h = honest();
    let rebuilt =
        CompositionArtifact::from_parts(h.sealed, h.owner_reveal.clone(), h.gate_reveal.clone());
    assert_eq!(
        audit(&rebuilt, &parties()).expect("audits"),
        audit(&h.artifact, &parties()).expect("audits"),
    );
}

/// A funder that watched the commit broadcast can match what it saw against
/// what was revealed. That comparison is the only way the ORDERING half of the
/// defence is checkable from outside, and the artifact supports it.
#[test]
fn a_funder_can_match_the_reveals_against_the_commitments_it_saw() {
    let h = honest();
    let (owner_commitment, gate_commitment) = h.artifact.commitments();
    assert_eq!(
        h.owner_reveal.commitment(&h.ceremony),
        owner_commitment.commitment(),
        "the owner reveal opens the commitment the artifact carries"
    );
    assert_eq!(
        h.gate_reveal.commitment(&h.ceremony),
        gate_commitment.commitment()
    );
    // ...and those are the values the cohorts published at seal time.
    assert_eq!(owner_commitment, h.owners.commitment);
    assert_eq!(gate_commitment, h.gates.commitment);
}

/// The subaddress check needs the view key, and it distinguishes the real
/// subaddress from any other index.
#[test]
fn the_subaddress_is_checkable_by_a_funder_holding_the_view_key() {
    let h = honest();
    let d = h.spend_public();

    let address = audit_address(&h.artifact, &parties(), &h.view, SUBADDRESS, &d).expect("real subaddress");
    assert_eq!(address.spend_public(), &d);
    assert_eq!(address.subaddress_index(), SUBADDRESS);
    assert_eq!(address.root().root(), h.artifact.declared_root());

    assert_eq!(
        audit_address(&h.artifact, &parties(), &h.view, SUBADDRESS + 1, &d).unwrap_err(),
        CeremonyError::SubaddressMismatch {
            index: SUBADDRESS + 1
        }
    );
}

// ---------------------------------------------------------------------------
// End to end: an honest composition signs and verifies.
// ---------------------------------------------------------------------------

/// **REQUIRED: an honest composition produces a root that signs and verifies
/// through the existing `mlsag` protocol, end to end.**
///
/// Every seat is built from ONE participant's own DKG share. No cohort holding
/// shares exists anywhere in this test, and the `CompositeSpend` the
/// coordinator holds refuses to produce one -- asserted below, so the claim is
/// not merely that the test happened not to ask.
#[test]
fn an_honest_composition_signs_and_verifies_through_the_mlsag_protocol() {
    let h = honest();
    let d = h.spend_public();
    let address = audit_address(&h.artifact, &parties(), &h.view, SUBADDRESS, &d).expect("audited address");
    let r = h.tx_public();

    let spend = CompositeSpend::from_ceremony(&address, &h.view, &r).expect("production spend");
    assert_eq!(spend.provenance(), Provenance::Ceremony(h.ceremony));
    assert_eq!(spend.spend_public(), &d);
    assert_eq!(spend.subaddress_index(), SUBADDRESS);

    let osub = h.owners.quorum(2);
    let gsub = h.gates.quorum(2);

    // The cohorts inside it are public-only: this process cannot form the
    // one-time key, and cannot be handed a set of signers, even though it holds
    // both cohorts' public material.
    assert_eq!(
        spend.onetime(&osub, &gsub).unwrap_err().kind(),
        &Error::SharesNotHeld
    );
    assert_eq!(
        quorum_signers(&spend, &osub, &gsub)
            .unwrap_err()
            .to_string(),
        "cohort refused the signing subset: cohort `owners`: this cohort's shares are held \
         by its participants, not by this process",
    );

    // ...while the PUBLIC composition still reaches the audited root.
    assert_eq!(
        spend
            .composite_root(&osub, &gsub)
            .expect("public interpolation"),
        address.root().root()
    );

    let (blinding, out_blinding) = (Scalar::from(9u64), Scalar::from(4u64));
    let (ring, gens) = make_ring_from_seed(&spend, RING_SIZE, REAL_INDEX, VALUE, &blinding, 77);
    let out_commitment = CompressedCommitment::from(&Commitment::new(VALUE, out_blinding, &gens));

    let mut guard = MemoryNonceGuard::new();
    let mut rng = ChaCha20Rng::seed_from_u64(0x51617);

    let sig = {
        let session_id = [7u8; 32];
        let params = SessionParams {
            session_id: &session_id,
            message: MESSAGE,
            ring: &ring,
            real_index: REAL_INDEX,
            output_commitment: &out_commitment,
        };
        sign(
            params,
            seats(&h, &spend, &osub, &gsub),
            MaskSigner::owner_held(&out_blinding, &blinding),
            &mut guard,
            &mut rng,
        )
        .expect("the two-cohort protocol produces a signature")
    };
    sig.verify(MESSAGE, &ring, &out_commitment)
        .expect("the unmodified MobileCoin verifier accepts it");

    // A different pair of qualifying quorums signs the same output, and lands
    // on the same key image -- the invariance the whole scheme rests on, now
    // over DKG shares rather than a dealing.
    let other_osub = vec![Owners::nth(1), Owners::nth(2)];
    let other_gsub = vec![Gates::nth(0), Gates::nth(2)];
    let sig2 = {
        let session_id = [8u8; 32];
        let params = SessionParams {
            session_id: &session_id,
            message: MESSAGE,
            ring: &ring,
            real_index: REAL_INDEX,
            output_commitment: &out_commitment,
        };
        sign(
            params,
            seats(&h, &spend, &other_osub, &other_gsub),
            MaskSigner::owner_held(&out_blinding, &blinding),
            &mut guard,
            &mut rng,
        )
        .expect("a different pair of quorums also signs")
    };
    sig2.verify(MESSAGE, &ring, &out_commitment)
        .expect("and it also verifies");
    assert_eq!(
        sig.key_image, sig2.key_image,
        "one output must have one key image whichever quorums sign"
    );
    assert!(sig != sig2, "different sessions, different signatures");
}

/// Every seat of one signing session, each built from one participant's own
/// share.
fn seats(h: &Honest, spend: &CompositeSpend, osub: &[u64], gsub: &[u64]) -> Vec<SpendSigner> {
    let mut signers = vec![SpendSigner::view(spend.common())];
    for &id in osub {
        signers.push(SpendSigner::owner(
            &h.owners.share_of(id).term(osub).expect("quorum member"),
        ));
    }
    for &id in gsub {
        signers.push(SpendSigner::gate(
            &h.gates.share_of(id).term(gsub).expect("quorum member"),
        ));
    }
    signers
}

/// A signing set missing the gate cohort does not even reach round one: the
/// coordinator's preflight sees that the published terms do not sum to the
/// output's target key.
///
/// The gate is inside the spend path, not layered on top of it.
#[test]
fn an_owner_quorum_alone_cannot_open_the_output() {
    let h = honest();
    let d = h.spend_public();
    let address = audit_address(&h.artifact, &parties(), &h.view, SUBADDRESS, &d).expect("audited");
    let spend =
        CompositeSpend::from_ceremony(&address, &h.view, &h.tx_public()).expect("production");

    let osub = h.owners.quorum(2);
    let gsub = h.gates.quorum(2);
    let (blinding, out_blinding) = (Scalar::from(9u64), Scalar::from(4u64));
    let (ring, gens) = make_ring_from_seed(&spend, RING_SIZE, REAL_INDEX, VALUE, &blinding, 78);
    let out_commitment = CompressedCommitment::from(&Commitment::new(VALUE, out_blinding, &gens));

    let mut guard = MemoryNonceGuard::new();
    let mut rng = ChaCha20Rng::seed_from_u64(0x9111);

    // Control: with the gates present, the same ring and commitment sign.
    let id_ok = [1u8; 32];
    let ok = SessionParams {
        session_id: &id_ok,
        message: MESSAGE,
        ring: &ring,
        real_index: REAL_INDEX,
        output_commitment: &out_commitment,
    };
    sign(
        ok,
        seats(&h, &spend, &osub, &gsub),
        MaskSigner::owner_held(&out_blinding, &blinding),
        &mut guard,
        &mut rng,
    )
    .expect("control: the full signing set signs")
    .verify(MESSAGE, &ring, &out_commitment)
    .expect("control: and verifies");

    // The gates removed, and nothing else changed.
    let id_bad = [2u8; 32];
    let bad = SessionParams {
        session_id: &id_bad,
        message: MESSAGE,
        ring: &ring,
        real_index: REAL_INDEX,
        output_commitment: &out_commitment,
    };
    let err = match sign(
        bad,
        seats(&h, &spend, &osub, &[]),
        MaskSigner::owner_held(&out_blinding, &blinding),
        &mut guard,
        &mut rng,
    ) {
        Ok(_) => panic!("an owner quorum alone must not produce a signature"),
        Err(e) => e,
    };
    assert!(
        matches!(err, SigningError::QuorumDoesNotOwnOutput { .. }),
        "expected the preflight to reject the incomplete signing set, got {err}"
    );
}

// ---------------------------------------------------------------------------
// Tampering. Each must be refused, with the specific error, at the specific
// step.
/// **REQUIRED: a revealed component that does not match its commitment is
/// refused.**
#[test]
fn a_revealed_component_that_does_not_match_its_commitment_is_refused() {
    let h = honest();
    h.sealed
        .open(h.owner_reveal.clone(), h.gate_reveal.clone(), &parties())
        .expect("control: the honest reveal opens its commitment");

    let doctored = ComponentReveal::from_parts(
        ComponentClaim::from_parts(
            "gates",
            h.gate_reveal.threshold(),
            h.gate_reveal.roster().to_vec(),
            // One point away from the sealed component.
            h.gate_reveal.component() + G,
            h.gate_reveal.verification_shares().to_vec(),
            h.gate_reveal.seat_keys().to_vec(),
        ),
        h.gate_reveal.pops().clone(),
        h.gate_reveal.seat_endorsements().clone(),
        *h.gate_reveal.salt(),
    );
    assert_eq!(
        h.sealed
            .open(h.owner_reveal.clone(), doctored.clone(), &parties())
            .unwrap_err(),
        CeremonyError::CommitmentMismatch { cohort: "gates" }
    );
    assert_eq!(
        audit(
            &CompositionArtifact::from_parts(h.sealed, h.owner_reveal.clone(), doctored),
            &parties(),
        )
        .unwrap_err(),
        CeremonyError::CommitmentMismatch { cohort: "gates" },
        "and an artifact carrying it does not audit"
    );
}

/// The salt is part of what the commitment binds: reopening the same claim
/// under a different salt is refused.
#[test]
fn a_reveal_under_a_different_salt_is_refused() {
    let h = honest();
    let reveal = ComponentReveal::from_parts(
        h.gate_reveal.claim().clone(),
        h.gate_reveal.pops().clone(),
        h.gate_reveal.seat_endorsements().clone(),
        [0x5A; 32],
    );
    assert_eq!(
        h.sealed
            .open(h.owner_reveal.clone(), reveal, &parties())
            .unwrap_err(),
        CeremonyError::CommitmentMismatch { cohort: "gates" }
    );
}

/// **REQUIRED: a proof of possession over the WRONG TRANSCRIPT is refused.**
///
/// The proofs are genuine: each gate participant really does know the share it
/// proves knowledge of. They are produced under a different
/// [`SealedComposition`] -- which is exactly what a cohort that proved
/// possession before it held the other cohort's commitment would have.
#[test]
fn a_pop_over_the_wrong_transcript_is_refused() {
    // A ceremony of its own rather than `honest()`'s, because each share
    // answers exactly ONE sealed composition -- see `prove_possession` -- and
    // this test needs gate proofs made under a composition that is not the one
    // the artifact is opened against. So the gates here prove once, under
    // `elsewhere`, and never under `sealed`.
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EA1ED);
    let ceremony = CeremonyId::draw("wrong-transcript composition", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);

    let sealed = SealedComposition::new(ceremony, owners.commitment, gates.commitment)
        .expect("well-formed");
    // Same gate commitment, a DIFFERENT owner commitment: the owner digest is
    // the thing a prover moving too early would not have had.
    let other_owner_commitment = seal_and_sign::<Owners>(&ceremony, &owners.claim, &[0xAB; 32]);
    let elsewhere = SealedComposition::new(ceremony, other_owner_commitment, gates.commitment)
        .expect("well-formed");
    assert_ne!(elsewhere, sealed);

    let owner_reveal = owners.reveal(&sealed);
    let stale: BTreeMap<u64, Pop> = gates.pops(&elsewhere);

    // CONTROL: those same proofs verify under the transcript they were made
    // for, so what is rejected below is the transcript and not a bad proof.
    ComponentReveal::assemble(
        &elsewhere,
        gates.claim.clone(),
        stale.clone(),
        gates.endorsements.clone(),
        gates.salt,
    )
    .expect("control: genuine under the transcript they were made for");

    let reveal = ComponentReveal::from_parts(
        gates.claim.clone(),
        stale,
        gates.endorsements.clone(),
        gates.salt,
    );
    assert_eq!(
        sealed.open(owner_reveal, reveal, &parties()).unwrap_err(),
        CeremonyError::PopFailed {
            cohort: "gates",
            participant: Gates::nth(0),
        }
    );
}

/// **REQUIRED: a proof of possession for a DIFFERENT COMPONENT is refused.**
///
/// A second, entirely honest gate cohort proves possession of its own shares
/// under THIS ceremony's sealed composition. Those proofs are then presented
/// alongside the first cohort's component and verification shares.
#[test]
fn a_pop_for_a_different_component_is_refused() {
    let h = honest();
    // A second honest gate cohort whose shares have answered nothing yet, so
    // their one proof can be spent under THIS ceremony's sealed composition.
    let mut rng = ChaCha20Rng::seed_from_u64(0xDEFACED);
    let other = CohortSide::<Gates>::generate(&h.ceremony, &gates_spec(), &mut rng);
    assert_ne!(other.claim.component(), h.gates.claim.component());

    // Genuine proofs, from a cohort that really holds the shares, over THIS
    // ceremony's sealed composition -- so the ceremony and both commitments in
    // the transcript are right, and only the component and shares behind them
    // belong to another key.
    let foreign: BTreeMap<u64, Pop> = other.pops(&h.sealed);

    // CONTROL: presented with the component they were made for, they verify.
    ComponentReveal::assemble(
        &h.sealed,
        other.claim.clone(),
        foreign.clone(),
        other.endorsements.clone(),
        other.salt,
    )
    .expect("control: genuine for their own component");

    let swapped = ComponentReveal::from_parts(
        h.gates.claim.clone(),
        foreign,
        h.gate_reveal.seat_endorsements().clone(),
        h.gates.salt,
    );
    assert_eq!(
        h.sealed
            .open(h.owner_reveal.clone(), swapped, &parties())
            .unwrap_err(),
        CeremonyError::PopFailed {
            cohort: "gates",
            participant: Gates::nth(0),
        },
        "a proof of one component's share must not verify against another's"
    );
}

/// A reveal missing one participant's proof is refused, naming the participant.
/// A component is proved only when EVERY share behind it is.
#[test]
fn a_missing_pop_is_refused() {
    let h = honest();
    let mut short = h.gate_reveal.pops().clone();
    short.remove(&Gates::nth(1));
    let reveal = ComponentReveal::from_parts(
        h.gates.claim.clone(),
        short,
        h.gate_reveal.seat_endorsements().clone(),
        h.gates.salt,
    );
    assert_eq!(
        h.sealed
            .open(h.owner_reveal.clone(), reveal, &parties())
            .unwrap_err(),
        CeremonyError::PopMissing {
            cohort: "gates",
            participant: Gates::nth(1),
        }
    );
}

/// The twin of the test above, and it had no test at all until an adversarial
/// review of an unrelated change noticed the gap.
///
/// A reveal carrying a proof from somebody the roster does not contain is
/// refused, naming them. Both arms of [`CeremonyError::PopUnexpected`] are
/// asserted, because they are different guards in different functions and only
/// one of them is reachable by an auditor:
///
///   * `ComponentReveal::check_pops` -- the AUDIT arm. An artifact with an extra
///     proof stapled on. Refused rather than ignored: a pop nobody on the roster
///     made is a proof about a share nobody on the roster holds, and an auditor
///     that silently drops it has been shown key material it did not account
///     for;
///   * `Pop::prove` -- the PROVER arm, and a courtesy rather than a boundary. A
///     holder asked to prove for a seat the claim publishes no share for is told
///     so instead of indexing into nothing.
///
/// CONTROL: the same reveal without the extra proof audits.
#[test]
fn a_pop_from_someone_off_the_roster_is_refused() {
    let h = honest();

    // Someone the gate roster does not contain -- an owner seat, so the id is
    // real and only its membership is wrong.
    let stranger = Owners::nth(0);
    assert!(!h.gates.claim.roster().contains(&stranger));

    let mut extra = h.gate_reveal.pops().clone();
    extra.insert(
        stranger,
        h.owner_reveal
            .pops()
            .get(&stranger)
            .expect("the owner cohort proved for it")
            .clone(),
    );
    let reveal = ComponentReveal::from_parts(
        h.gates.claim.clone(),
        extra,
        h.gate_reveal.seat_endorsements().clone(),
        h.gates.salt,
    );
    assert_eq!(
        h.sealed
            .open(h.owner_reveal.clone(), reveal, &parties())
            .unwrap_err(),
        CeremonyError::PopUnexpected {
            cohort: "gates",
            participant: stranger,
        },
    );

    // CONTROL: one input different -- the extra proof removed -- and the same
    // call succeeds.
    h.sealed
        .clone()
        .open(h.owner_reveal.clone(), h.gate_reveal.clone(), &parties())
        .expect("CONTROL: without the extra proof the same reveal audits");

    // The PROVER arm: asked to prove for a seat this claim has no share for.
    assert_eq!(
        Pop::prove_unchecked(
            &h.sealed,
            &h.gates.claim,
            stranger,
            &Scalar::from(1u64),
        )
        .expect_err("the claim publishes no verification share for this participant"),
        CeremonyError::PopUnexpected {
            cohort: "gates",
            participant: stranger,
        },
    );
}

/// Verification shares that do not lie on a polynomial of the declared degree
/// are refused, naming two quorums that disagree.
///
/// This is the inconsistent-dealing failure as a FUNDER meets it: an address
/// some quorums can spend and others cannot, caught before funding rather than
/// after. The gate cohort is built here from three secrets this test chooses,
/// so every proof of possession is genuine and the commitment is sealed over
/// exactly what is revealed -- the ONLY defect is the interpolation, and the
/// CONTROL below is the identical construction with the three points made
/// collinear.
#[test]
fn verification_shares_that_disagree_between_quorums_are_refused() {
    let roster: Vec<u64> = (0..3).map(Gates::nth).collect();

    // A degree-1 polynomial p(x) = c + m*x evaluated at 1, 2, 3 -- the DKG's
    // own evaluation points. Any two of the three interpolate to `c`.
    let (c, m) = (Scalar::from(11u64), Scalar::from(7u64));
    let consistent: Vec<Scalar> = (1..=3u64).map(|x| c + m * Scalar::from(x)).collect();

    // CONTROL: collinear shares audit.
    let ok = attempt(0x0C01, &roster, &consistent, c * G);
    assert!(
        ok.is_ok(),
        "control: shares on a degree-1 polynomial must audit, got {:?}",
        ok.err()
    );

    // The same construction with the third point moved off the line. Nothing
    // else changes: same roster, same threshold, same declared component, and
    // the third participant still knows the discrete log of what it publishes.
    let mut bent = consistent.clone();
    bent[2] += Scalar::ONE;

    // THE HARM, exhibited before it is defended against: with the bent shares,
    // two different qualifying quorums of the SAME cohort reconstruct two
    // different secrets, so they reach two different spend roots. An address
    // built on this is spendable by one quorum and not the other, and which is
    // which is invisible until an output has to move. Computed here with the
    // crate's public `lagrange_at_zero` over the DKG's evaluation points, not
    // with anything the ceremony provides.
    let interp = |q: [usize; 2]| -> Scalar {
        let points = [q[0] as u64 + 1, q[1] as u64 + 1];
        lagrange_at_zero(points[0], &points).unwrap() * bent[q[0]]
            + lagrange_at_zero(points[1], &points).unwrap() * bent[q[1]]
    };
    assert_eq!(
        {
            let points = [1u64, 2];
            lagrange_at_zero(points[0], &points).unwrap() * consistent[0]
                + lagrange_at_zero(points[1], &points).unwrap() * consistent[1]
        },
        c,
        "sanity: the untouched shares do reconstruct the intended secret"
    );
    assert_ne!(
        interp([0, 1]),
        interp([0, 2]),
        "the harm: two quorums of one cohort hold two different secrets"
    );

    let err = attempt(0x0BE7, &roster, &bent, c * G).unwrap_err();
    assert!(
        matches!(
            err,
            CeremonyError::InconsistentVerificationShares { cohort: "gates", .. }
        ),
        "expected two quorums to disagree, got {err}"
    );
}

/// Shares that ARE consistent but whose declared component is not what they
/// interpolate to is a separate rejection, so the two failures are not
/// conflated.
#[test]
fn a_component_the_shares_do_not_interpolate_to_is_refused() {
    let roster: Vec<u64> = (0..3).map(Gates::nth).collect();
    let (c, m) = (Scalar::from(11u64), Scalar::from(7u64));
    let consistent: Vec<Scalar> = (1..=3u64).map(|x| c + m * Scalar::from(x)).collect();

    let err = attempt(0x0FF, &roster, &consistent, (c + Scalar::ONE) * G).unwrap_err();
    assert_eq!(
        err,
        CeremonyError::ComponentNotInterpolated {
            cohort: "gates",
            quorum: vec![Gates::nth(0), Gates::nth(1)],
        }
    );
}

/// Build a gate reveal from chosen secrets at a chosen threshold, seal it,
/// prove it, and open the composition against a freshly generated honest owner
/// cohort.
///
/// Everything except the verification shares, the threshold and the declared
/// component is honest, so a rejection is attributable to those inputs.
///
/// The owner side is regenerated per call rather than shared with `honest()`
/// because each share answers exactly ONE sealed composition, and two calls with
/// different gate claims are two different compositions. Both owner sides are
/// ordinary honest 2-of-3 cohorts and every assertion below is about the GATE
/// claim, so the control and the defect still differ in one input each; they do
/// not share a group element that could carry the difference.
fn attempt_at(
    seed: u64,
    threshold: usize,
    roster: &[u64],
    secrets: &[Scalar],
    component: RistrettoPoint,
) -> Result<(), CeremonyError> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let ceremony = CeremonyId::draw("consistency probe", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);

    let claim = ComponentClaim::from_parts(
        "gates",
        threshold,
        roster.to_vec(),
        component,
        secrets.iter().map(|s| s * G).collect(),
        seat_keys_over::<Gates>(roster),
    );
    let salt = [0x33; 32];
    let sealed = SealedComposition::new(
        ceremony,
        owners.commitment,
        seal_and_sign::<Gates>(&ceremony, &claim, &salt),
    )?;
    let mut pops = BTreeMap::new();
    for (i, &id) in roster.iter().enumerate() {
        pops.insert(id, Pop::prove_unchecked(&sealed, &claim, id, &secrets[i])?);
    }
    // `assemble` re-checks the proofs, so reaching `open` at all already means
    // every participant proved possession.
    let endorsements = seat_endorsements::<Gates>(&ceremony, &claim, secrets);
    let reveal = ComponentReveal::assemble(&sealed, claim, pops, endorsements, salt)?;
    sealed
        // The funder's seats are THIS probe's roster, not the file's default:
        // a `Parties` naming other seats would be refused before any of the
        // consistency checks these probes are about could run.
        .open(
            owners.reveal(&sealed),
            reveal,
            &parties_over(owners_spec().ids(), roster),
        )
        .map(|_| ())
}

/// [`attempt_at`] at threshold 2, the shape most of these tests use.
fn attempt(
    seed: u64,
    roster: &[u64],
    secrets: &[Scalar],
    component: RistrettoPoint,
) -> Result<(), CeremonyError> {
    attempt_at(seed, 2, roster, secrets, component)
}

/// A component of the identity is refused: it contributes nothing to the sum,
/// so the "composite" root would be the other cohort's key outright -- and the
/// identity's discrete log is 0, which IS provable, so the proof check would
/// not catch it.
#[test]
fn an_identity_component_is_refused() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x1DE7);
    let ceremony = CeremonyId::draw("identity component", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);

    let claim = ComponentClaim::from_parts(
        "gates",
        1,
        vec![Gates::nth(0)],
        RistrettoPoint::identity(),
        vec![RistrettoPoint::identity()],
        seat_keys_over::<Gates>(&[Gates::nth(0)]),
    );
    let sealed = SealedComposition::new(
        ceremony,
        owners.commitment,
        seal_and_sign::<Gates>(&ceremony, &claim, &[0; 32]),
    )
    .expect("well-formed");
    let pop = Pop::prove_unchecked(&sealed, &claim, Gates::nth(0), &Scalar::ZERO)
        .expect("zero opens the identity, which is the point");
    // Zero endorses the identity too: `0*G` IS the identity, so the seat really
    // does hold the share behind its own verification share. The endorsement is
    // therefore genuine and the refusal below cannot be it.
    let endorsements = seat_endorsements::<Gates>(&ceremony, &claim, &[Scalar::ZERO]);
    let reveal = ComponentReveal::from_parts(
        claim,
        BTreeMap::from([(Gates::nth(0), pop)]),
        endorsements,
        [0; 32],
    );

    assert_eq!(
        sealed
            .open(
                owners.reveal(&sealed),
                reveal,
                &parties_over(owners_spec().ids(), &[Gates::nth(0)]),
            )
            .unwrap_err(),
        CeremonyError::IdentityComponent { cohort: "gates" }
    );
}

/// A gate id presented on an owner roster is refused. The auditor re-checks the
/// control domains itself rather than assuming the DKG did -- it sees only the
/// artifact.
///
/// The shape check runs BEFORE the commitment check, so this rejection is not
/// the commitment check in disguise; the assertion names which one fired.
#[test]
fn a_roster_from_the_wrong_domain_is_refused() {
    let h = honest();
    let claim = ComponentClaim::from_parts(
        "owners",
        h.owners.claim.threshold(),
        vec![Owners::nth(0), Gates::nth(0), Owners::nth(2)],
        h.owners.claim.component(),
        h.owners.claim.verification_shares().to_vec(),
        h.owner_reveal.seat_keys().to_vec(),
    );
    let reveal = ComponentReveal::from_parts(
        claim,
        h.owner_reveal.pops().clone(),
        h.owner_reveal.seat_endorsements().clone(),
        h.owners.salt,
    );

    assert_eq!(
        h.sealed
            .open(reveal, h.gate_reveal.clone(), &parties())
            .unwrap_err(),
        CeremonyError::IdOutsideDomain {
            cohort: "owners",
            id: Gates::nth(0),
            base: Owners::ID_BASE,
            end: Owners::ID_BASE + two_cohort::NAMESPACE_SPAN,
        }
    );
}

// ---------------------------------------------------------------------------
// Provenance, and the independent key-image check.
/// A production `CompositeSpend` records that it came from a ceremony, and a
/// simulated one records that it did not -- so a release path can refuse the
/// second with one match arm.
#[test]
fn provenance_distinguishes_a_ceremony_root_from_a_dealt_one() {
    let h = honest();
    let d = h.spend_public();
    let address = audit_address(&h.artifact, &parties(), &h.view, SUBADDRESS, &d).expect("audited");
    let production =
        CompositeSpend::from_ceremony(&address, &h.view, &h.tx_public()).expect("production");
    assert_eq!(production.provenance(), Provenance::Ceremony(h.ceremony));
    assert!(!production.owners().holds_shares());
    assert!(!production.gates().holds_shares());

    let simulated =
        CompositeSpend::simulate_from_seed(1, &owners_spec(), &gates_spec(), SUBADDRESS)
            .expect("simulated");
    assert_eq!(simulated.provenance(), Provenance::Simulated);
    assert!(simulated.owners().holds_shares());
}

/// The one-time key implied by a production spend's public data is the one
/// upstream MobileCoin derives, and every qualifying pair of quorums reaches
/// the same key image.
///
/// `x` is reconstructed HERE, in the test, only so there is an independent
/// value to check against. No production path forms it -- `spend.onetime` is
/// asserted to refuse in
/// [`an_honest_composition_signs_and_verifies_through_the_mlsag_protocol`].
#[test]
fn the_production_key_image_agrees_with_upstreams_own_derivation() {
    let h = honest();
    let d = h.spend_public();
    let address = audit_address(&h.artifact, &parties(), &h.view, SUBADDRESS, &d).expect("audited");
    let spend =
        CompositeSpend::from_ceremony(&address, &h.view, &h.tx_public()).expect("production");

    let mut image = None;
    for o in subsets_of(owners_spec().ids(), 2) {
        for g in subsets_of(gates_spec().ids(), 2) {
            let bo: Scalar = o
                .iter()
                .map(|&id| *h.owners.share_of(id).term(&o).unwrap().weight())
                .sum();
            let bg: Scalar = g
                .iter()
                .map(|&id| *h.gates.share_of(id).term(&g).unwrap().weight())
                .sum();
            let x = spend.common() + bo + bg;
            assert_eq!(
                x * G,
                *spend.target().as_ref(),
                "quorums {o:?} x {g:?} do not open the output's target key"
            );
            let this = KeyImage::from(&RistrettoPrivate::from(x));
            match image {
                None => image = Some(this),
                Some(first) => assert_eq!(
                    this, first,
                    "quorums {o:?} x {g:?} reach a different key image"
                ),
            }
        }
    }
    assert!(image.is_some());
}

// ---------------------------------------------------------------------------

/// A claim whose roster and verification-share lists disagree is refused
/// rather than indexed into.
///
/// `ComponentClaim::from_parts` is wire data and may say anything, and
/// `ComponentReveal::assemble` accepts one without an `audit` in front of it.
/// Both entry points are exercised here because they take different paths to
/// the same parallel-vector indexing.
#[test]
fn a_claim_with_mismatched_lengths_is_refused_rather_than_indexed() {
    let h = honest();
    let claim = ComponentClaim::from_parts(
        "gates",
        2,
        h.gates.claim.roster().to_vec(),
        h.gates.claim.component(),
        // One share short of the roster.
        h.gates.claim.verification_shares()[..2].to_vec(),
        h.gate_reveal.seat_keys().to_vec(),
    );
    let expected = CeremonyError::MalformedClaim {
        cohort: "gates",
        roster: 3,
        verification_shares: 2,
    };

    assert_eq!(
        ComponentReveal::assemble(
            &h.sealed,
            claim.clone(),
            BTreeMap::new(),
            BTreeMap::new(),
            h.gates.salt
        )
        .unwrap_err(),
        expected,
    );
    assert_eq!(
        h.sealed
            .open(
                h.owner_reveal.clone(),
                ComponentReveal::from_parts(claim, BTreeMap::new(), BTreeMap::new(), h.gates.salt),
                &parties(),
            )
            .unwrap_err(),
        expected,
    );
}

// ---------------------------------------------------------------------------
// The audit's statement about the THRESHOLD, in both directions.
// ---------------------------------------------------------------------------

/// A real DKG's verification shares lie on a polynomial of degree `t - 1`, so
/// every `t`-subset of a genuine 2-of-4 dealing interpolates to its component --
/// and so would every 3-subset.
///
/// "Exactly `t - 1`" holds with overwhelming probability rather than always:
/// PedPoP has each dealer sample a non-zero leading coefficient and then SUMS
/// them, so an aggregate whose leading coefficient is zero is possible at
/// probability about `2^-252`. Such a dealing really is lower-degree, and
/// `audit` correctly refuses it as an overstated threshold rather than
/// accepting it -- so the rare case fails safe. This test asserts the shape of
/// one sampled dealing, which is what it can honestly assert.
///
/// This is the PREMISE of the test below, established over a real
/// [`run_dkg`](two_cohort::dkg::run_dkg) rather than assumed, so that the
/// rejection there is a rejection of something a cohort can actually hold and
/// not of a shape only this file can build.
#[test]
fn a_real_two_of_four_dealing_satisfies_every_three_subset_test_as_well() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x2041);
    let ceremony = CeremonyId::draw("degree of a real dealing", &mut rng);
    let spec = CohortSpec::<Gates>::sequential(2, 4);
    let shares =
        two_cohort::dkg::run_dkg::<Gates, _>(
            &ceremony,
            &spec,
            &common::seats_for::<Gates>(&spec),
            &common::seat_identities_for::<Gates>(&spec),
            &mut rng,
        )
        .expect("honest");
    let key = shares[0].key();
    let v: Vec<RistrettoPoint> = key.verification_shares().into_iter().map(|(_, p)| p).collect();

    // Positions map to evaluation points 1..=4, as `dkg` documents.
    let interp = |positions: &[usize]| -> RistrettoPoint {
        let points: Vec<u64> = positions.iter().map(|&i| i as u64 + 1).collect();
        positions
            .iter()
            .zip(&points)
            .map(|(&i, &p)| lagrange_at_zero(p, &points).unwrap() * v[i])
            .sum()
    };

    assert_eq!(interp(&[0, 1]), key.component(), "2 of 4 reconstruct it");
    for triple in [[0, 1, 2], [0, 1, 3], [0, 2, 3], [1, 2, 3]] {
        assert_eq!(
            interp(&triple),
            key.component(),
            "so a one-sided check at threshold 3 would also be satisfied"
        );
    }
}

/// **A cohort cannot publish a threshold higher than the degree of its own
/// dealing.**
///
/// The harm is what a funder is told: [`AuditedRoot::structure`] reports the
/// declared threshold, so a 2-of-4 dealing published as 3-of-4 tells a funder
/// three seats are needed when two suffice. The CONTROL is the identical
/// dealing declared at the threshold it has.
#[test]
fn a_cohort_cannot_declare_a_threshold_above_the_degree_of_its_dealing() {
    let roster: Vec<u64> = (0..4).map(Gates::nth).collect();
    // A degree-1 polynomial over the DKG's own evaluation points 1..=4: the
    // shape the test above establishes a real 2-of-4 dealing has.
    let (c, m) = (Scalar::from(23u64), Scalar::from(5u64));
    let secrets: Vec<Scalar> = (1..=4u64).map(|x| c + m * Scalar::from(x)).collect();

    // CONTROL: at the threshold it actually has, the same dealing audits.
    let ok = attempt_at(0x2042, 2, &roster, &secrets, c * G);
    assert!(
        ok.is_ok(),
        "control: a 2-of-4 dealing declared 2-of-4 must audit, got {:?}",
        ok.err()
    );

    // THE HARM, exhibited before it is refused: with 3 declared, two seats
    // already hold the component. Computed with the crate's public
    // `lagrange_at_zero` over the DKG's evaluation points.
    let points = [1u64, 2];
    let two_seats = lagrange_at_zero(points[0], &points).unwrap() * secrets[0]
        + lagrange_at_zero(points[1], &points).unwrap() * secrets[1];
    assert_eq!(
        two_seats * G,
        c * G,
        "the harm: two of the four declared-necessary three already reconstruct it"
    );

    assert_eq!(
        attempt_at(0x2043, 3, &roster, &secrets, c * G).unwrap_err(),
        CeremonyError::ThresholdOverstated {
            cohort: "gates",
            threshold: 3,
            quorum: vec![Gates::nth(0), Gates::nth(1)],
        }
    );
}

// ---------------------------------------------------------------------------
// The roster ORDER is part of the dealing.
// ---------------------------------------------------------------------------

/// **A roster published out of ascending order is refused, because the order is
/// what says which seat holds which evaluation point.**
///
/// The harm is that one dealing would otherwise have `n!` audited components:
/// the audit interpolates the verification shares at points assigned BY
/// POSITION, and so does every holder's `CohortShare::term`. An address funded
/// against a permuted artifact is spendable by nobody -- the auditor's Lagrange
/// weights and the holders' are for different point sets.
///
/// The CONTROL is the identical claim in ascending order.
#[test]
fn a_roster_published_out_of_order_is_refused() {
    let roster: Vec<u64> = (0..3).map(Gates::nth).collect();
    let (c, m) = (Scalar::from(11u64), Scalar::from(7u64));
    let secrets: Vec<Scalar> = (1..=3u64).map(|x| c + m * Scalar::from(x)).collect();

    // CONTROL: the same participant-to-secret association, published in
    // ascending order, audits. It is not a byte-identical claim -- reversing the
    // roster necessarily reverses the verification-share vector and changes the
    // component, which is the harm below -- so what the control establishes is
    // that this dealing is otherwise well-formed and the rejection is the order.
    let ok = attempt(0x0A5C, &roster, &secrets, c * G);
    assert!(ok.is_ok(), "control: ascending must audit, got {:?}", ok.err());

    // THE HARM: the same three shares read in reverse sit at reversed points,
    // so they interpolate to a DIFFERENT component -- one dealing, two answers.
    let reversed: Vec<Scalar> = secrets.iter().rev().copied().collect();
    let points = [1u64, 2];
    let reversed_component = lagrange_at_zero(points[0], &points).unwrap() * reversed[0]
        + lagrange_at_zero(points[1], &points).unwrap() * reversed[1];
    assert_ne!(
        reversed_component * G,
        c * G,
        "the harm: the same shares in the other order are a different key"
    );

    let mut descending = roster.clone();
    descending.reverse();
    assert_eq!(
        attempt(0x0D5C, &descending, &reversed, reversed_component * G).unwrap_err(),
        CeremonyError::RosterNotCanonical {
            cohort: "gates",
            roster: descending,
        }
    );
}

// ---------------------------------------------------------------------------
// A seat with nothing behind it.
// ---------------------------------------------------------------------------

/// **A verification share of the identity is refused, because every proof of
/// possession satisfies it.**
///
/// `z*G == R + c*V` with `V = 0` is `z*G == R`, so `Pop::from_parts(z*G, z)`
/// passes for any `z` and the audit's claim that every participant proved
/// knowledge of its share would be vacuously true for that seat.
///
/// The CONTROL is the identical forgery against a real verification share,
/// which is refused as [`CeremonyError::PopFailed`] -- so what is being caught
/// below is the identity and not `Pop::from_parts`.
#[test]
fn an_identity_verification_share_is_refused() {
    let real = Scalar::from(4242u64);
    let forged = || Pop::from_parts(Scalar::from(5u64) * G, Scalar::from(5u64));
    let roster = vec![Gates::nth(0), Gates::nth(1)];

    // Each run needs its own owner side: the gate claims differ, so the two
    // compositions differ, and a share answers only one -- see
    // `prove_possession`. Both owner cohorts are honest 2-of-3 and the
    // assertions are about the gate seats.
    // Driven by the SECRETS rather than by the points, because a seat endorsement
    // now needs the share as well as the key: `secrets[k]*G` is the published
    // verification share, so seat 0 carrying `Scalar::ZERO` is the identity share
    // and the seats really do endorse what they hold. Asserted just below rather
    // than left to the reader.
    let run = |seed: u64, secrets: Vec<Scalar>| -> CeremonyError {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let ceremony = CeremonyId::draw("phantom seat", &mut rng);
        let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
        let claim = ComponentClaim::from_parts(
            "gates",
            2,
            roster.clone(),
            real * G,
            secrets.iter().map(|s| s * G).collect(),
            seat_keys_over::<Gates>(&roster),
        );
        let salt = [0x5A; 32];
        let sealed = SealedComposition::new(
            ceremony,
            owners.commitment,
            seal_and_sign::<Gates>(&ceremony, &claim, &salt),
        )
        .expect("well-formed");
        let pops = BTreeMap::from([(Gates::nth(0), forged()), (Gates::nth(1), forged())]);
        audit(
            &CompositionArtifact::from_parts(
                sealed,
                owners.reveal(&sealed),
                ComponentReveal::from_parts(
                    claim.clone(),
                    pops,
                    seat_endorsements::<Gates>(&ceremony, &claim, &secrets),
                    salt,
                ),
            ),
            &parties_over(owners_spec().ids(), &roster),
        )
        .unwrap_err()
    };

    // CONTROL: the same forgery against two real verification shares is caught
    // by the proof check, so `Pop::from_parts` is not what makes a proof
    // acceptable and the acceptance below would be about the identity.
    assert_eq!(
        run(0x1D3, vec![real, real + Scalar::ONE]),
        CeremonyError::PopFailed {
            cohort: "gates",
            participant: Gates::nth(0),
        }
    );

    // Seat 0 carries the identity. That forged proof VERIFIES against it --
    // asserted, so the rejection below cannot be the proof check in disguise.
    let phantom = forged();
    assert_eq!(
        phantom.response() * G,
        phantom.nonce_public() + Scalar::from(999u64) * RistrettoPoint::identity(),
        "a proof over the identity verifies against any challenge at all"
    );

    assert_eq!(
        run(0x1D4, vec![Scalar::ZERO, real]),
        CeremonyError::IdentityVerificationShare {
            cohort: "gates",
            participant: Gates::nth(0),
        }
    );
}

// ---------------------------------------------------------------------------
// The proof-of-possession nonce.
// ---------------------------------------------------------------------------

/// **One share does not answer two different claims with one nonce.**
///
/// The proof's challenge is a function of the whole claim; the nonce must
/// therefore be too. Anything less and a holder induced to prove under two
/// claims that differ in a field it cannot check -- a PEER's verification share,
/// say -- emits one `R` against two challenges, and the share is recovered by
/// division from public data alone.
///
/// The CONTROL is that determinism itself is intact: the same claim twice is
/// the same proof, which is what makes a derived nonce safe in the first place.
#[test]
fn one_nonce_does_not_answer_two_claims() {
    // THE HARM, as arithmetic and nothing else. A fact about Schnorr, stated
    // here so that the property below is a statement about a check rather than
    // about hope.
    let (s, k) = (Scalar::from(1234u64), Scalar::from(99u64));
    let (c1, c2) = (Scalar::from(7u64), Scalar::from(8u64));
    let (z1, z2) = (k + c1 * s, k + c2 * s);
    assert_eq!(
        (z1 - z2) * (c1 - c2).invert(),
        s,
        "one nonce over two challenges gives up the secret"
    );

    let mut rng = ChaCha20Rng::seed_from_u64(0xB0CE);
    let ceremony = CeremonyId::draw("nonce binding", &mut rng);
    let roster = vec![Gates::nth(0), Gates::nth(1), Gates::nth(2)];
    let secrets: Vec<Scalar> = (0..3).map(|_| Scalar::random(&mut rng)).collect();
    let shares: Vec<RistrettoPoint> = secrets.iter().map(|x| x * G).collect();
    let component = {
        let points = [1u64, 2];
        (lagrange_at_zero(points[0], &points).unwrap() * secrets[0]
            + lagrange_at_zero(points[1], &points).unwrap() * secrets[1])
            * G
    };

    let claim_a = ComponentClaim::from_parts(
        "gates",
        2,
        roster.clone(),
        component,
        shares.clone(),
        seat_keys_over::<Gates>(&roster),
    );
    // Identical except for a PEER's verification share -- seat 2's. The holder
    // is seat 0, and nothing it can check locally distinguishes the two.
    let mut tampered = shares.clone();
    tampered[2] = (secrets[2] + Scalar::ONE) * G;
    let claim_b = ComponentClaim::from_parts(
        "gates",
        2,
        roster.clone(),
        component,
        tampered,
        seat_keys_over::<Gates>(&roster),
    );
    assert_ne!(claim_a, claim_b);

    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    let sealed = SealedComposition::new(
        ceremony,
        owners.commitment,
        seal_and_sign::<Gates>(&ceremony, &claim_a, &[0x11; 32]),
    )
    .expect("well-formed");

    let a = Pop::prove_unchecked(&sealed, &claim_a, Gates::nth(0), &secrets[0]).expect("opens its own");
    let b = Pop::prove_unchecked(&sealed, &claim_b, Gates::nth(0), &secrets[0]).expect("opens its own");

    assert_ne!(
        a.nonce_public(),
        b.nonce_public(),
        "two claims must not share a nonce"
    );

    // CONTROL: the same claim twice is byte-for-byte the same proof, so the
    // difference above is the claim and not a fresh random draw.
    assert_eq!(
        Pop::prove_unchecked(&sealed, &claim_a, Gates::nth(0), &secrets[0]).expect("again"),
        a
    );
}

/// **A share-holder handed a claim that is not its own key generation's refuses
/// to sign it.**
///
/// [`Pop::prove`] signs whatever it is handed; [`Pop::prove_for`] is the entry
/// point for the deployment shape `ComponentClaim` documents, where a
/// coordinator assembles the claim and each holder proves against it. The
/// CONTROL is the holder's own claim, which is accepted.
#[test]
fn a_holder_refuses_to_prove_under_a_claim_that_is_not_its_own() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xC1A11);
    let ceremony = CeremonyId::draw("coordinator-supplied claim", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);
    let sealed = SealedComposition::new(ceremony, owners.commitment, gates.commitment)
        .expect("well-formed");
    let share = &gates.shares[0];

    // A claim differing from the holder's own in exactly one integer.
    let inflated = ComponentClaim::from_parts(
        "gates",
        gates.claim.threshold() + 1,
        gates.claim.roster().to_vec(),
        gates.claim.component(),
        gates.claim.verification_shares().to_vec(),
        gates.claim.seat_keys().to_vec(),
    );
    assert_eq!(
        Pop::prove_for(&sealed, share, &inflated, &gates.salt).unwrap_err(),
        CeremonyError::ClaimNotOwn {
            cohort: "gates",
            participant: share.id(),
        }
    );

    // A composition that does not seal this holder's claim is refused too, and
    // refused BEFORE the one proof is spent -- otherwise a coordinator could
    // burn every holder's shot on a composition no reveal can open.
    let elsewhere = SealedComposition::new(
        ceremony,
        owners.commitment,
        seal_and_sign::<Gates>(&ceremony, &gates.claim, &[0xC7; 32]),
    )
    .expect("well-formed");
    assert_eq!(
        Pop::prove_for(&elsewhere, share, &gates.claim, &gates.salt).unwrap_err(),
        CeremonyError::CommitmentMismatch { cohort: "gates" }
    );

    // CONTROL: its own claim under the composition that seals it is signed, so
    // neither refusal above consumed the share's one proof.
    Pop::prove_for(&sealed, share, &gates.claim, &gates.salt)
        .expect("control: its own claim, under the composition that seals it");
    assert_eq!(share.proved_under(), Some(sealed));
}

// ---------------------------------------------------------------------------
// The view key `from_ceremony` is given.
// ---------------------------------------------------------------------------

/// **`from_ceremony` refuses a view key that is not the one the address was
/// audited under.**
///
/// `audit_address` established `D_i = B + Hs(a||i)*G` for one `a`. A different
/// one here yields a `common` term belonging to some other address: a
/// well-formed `CompositeSpend` that cannot open the output it names, found at
/// signing rather than at construction. The CONTROL is the audited key.
#[test]
fn from_ceremony_refuses_a_view_key_that_is_not_the_audited_one() {
    let h = honest();
    let address = audit_address(&h.artifact, &parties(), &h.view, SUBADDRESS, &h.spend_public())
        .expect("the honest address audits");

    // CONTROL: the key the address was audited under builds a spend.
    CompositeSpend::from_ceremony(&address, &h.view, &h.tx_public())
        .expect("control: the audited view key is accepted");

    let other = RistrettoPrivate::from(h.view.as_ref() + Scalar::ONE);
    assert_eq!(
        CompositeSpend::from_ceremony(&address, &other, &h.tx_public()).unwrap_err(),
        Error::ViewKeyMismatch
    );
}

// ---------------------------------------------------------------------------
// The limit of the one-shot rule, performed rather than claimed.
// ---------------------------------------------------------------------------

/// **A share-holder can recover its own share through safe public API, so the
/// one-composition rule is a safety catch on the holder's software and not a
/// capability boundary.**
///
/// `CohortShare::term` returns `lambda_i * s_i`, `ParticipantTerm::weight`
/// hands over that scalar, and `lambda_i` is `lagrange_at_zero` over the
/// public roster. Divide, and the raw share is in hand; `Pop::prove` then
/// answers as many sealed compositions as the caller likes, with
/// `CohortShare::note_proved` never consulted.
///
/// This is exhibited rather than stated because the rule IS worth having --
/// the attacker in
/// `rogue_key_inverted.rs::the_owners_refuse_a_second_composition_so_a_late_seal_has_nobody_to_prove_with`
/// is a coordinator talking an honest holder into a second proof, and an honest
/// holder calls `prove_possession`. But a reader deciding whether to fund an
/// address must know that the artifact carries no evidence any holder observed
/// it, and a limitation nobody has performed is a limitation nobody has
/// measured.
#[test]
fn a_holder_can_recover_its_own_share_through_public_api() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xB1A5E);
    let ceremony = CeremonyId::draw("share recovery", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);
    let sealed = SealedComposition::new(ceremony, owners.commitment, gates.commitment)
        .expect("well-formed");

    let share = &gates.shares[0];
    let quorum = gates.quorum(2);

    // Nothing secret is used to do this: the roster is public, the evaluation
    // points are `1..=n` by position as `dkg` documents, and `lagrange_at_zero`
    // is a public function of those.
    let roster = share.key().roster();
    let points: Vec<u64> = quorum
        .iter()
        .map(|id| roster.iter().position(|r| r == id).unwrap() as u64 + 1)
        .collect();
    let mine = roster.iter().position(|r| *r == share.id()).unwrap() as u64 + 1;
    let lambda = lagrange_at_zero(mine, &points).expect("public arithmetic");

    let term = share.term(&quorum).expect("a quorum member's own term");
    let recovered = term.weight() * lambda.invert();

    // It really is the share: it opens the verification share the DKG published.
    assert_eq!(
        recovered * G,
        share
            .key()
            .verification_shares()
            .into_iter()
            .find(|(id, _)| *id == share.id())
            .expect("on the roster")
            .1,
        "the recovered scalar opens this participant's published verification share"
    );

    // The honest entry point spends the one shot...
    prove_possession(&sealed, share).expect("first proof");
    let elsewhere = SealedComposition::new(
        ceremony,
        owners.commitment,
        seal_and_sign::<Gates>(&ceremony, &gates.claim, &[0xEE; 32]),
    )
    .expect("well-formed");
    assert_ne!(elsewhere, sealed);
    assert_eq!(
        prove_possession(&elsewhere, share).unwrap_err(),
        CeremonyError::ProofAlreadyIssued {
            cohort: "gates",
            participant: share.id(),
        },
        "control: the rule does fire on the entry point it guards"
    );

    // ...and the recovered scalar walks straight past it, producing a proof that
    // the audit's own check accepts.
    let bypass = Pop::prove_unchecked(&elsewhere, &gates.claim, share.id(), &recovered)
        .expect("the recovered share opens its own verification share");
    assert_eq!(
        bypass,
        Pop::prove_unchecked(&elsewhere, &gates.claim, share.id(), &recovered).expect("again"),
        "and it is a real, deterministic proof, not a malformed one"
    );
    assert_eq!(
        share.proved_under(),
        Some(sealed),
        "the share's record still says it answered only the first composition"
    );
}

// ---------------------------------------------------------------------------
// The declared threshold is a minimum coalition size, not only a degree.
// ---------------------------------------------------------------------------

/// **A dealing at declared threshold 3 in which seat 1 alone holds the
/// component, refused.**
///
/// Found by review. `check_consistency`'s lower bound used to enumerate only
/// the `(t-1)`-subsets, which establishes that the polynomial's degree is
/// exactly `t-1` and nothing more. Degree is not the same claim as minimum
/// coalition size, and the two come apart from `t = 3` upward. Take
///
/// ```text
///     p(x) = b + a*x*(x - 1)
/// ```
///
/// over evaluation points `1, 2, 3`. It has degree 2, so a declared threshold
/// of 3 is not overstated as a DEGREE: no pair of seats interpolates to `b`.
/// But `p(1) = b`, so seat 1 holds the component scalar outright and a funder
/// reading `threshold = 3` from `AuditedRoot::structure` would be told three
/// seats are needed when one suffices.
///
/// The dealing here is genuine, not malformed: every verification share lies on
/// one polynomial of the declared degree, every seat can prove possession of its
/// own share, and the component really is `p(0)*G`. That is what makes it the
/// interesting case -- there is nothing else wrong with it to catch.
///
/// The decided production structure is not exposed to this: at owner threshold
/// 2 the old lower bound already enumerated the 1-subsets, and gate threshold 1
/// has nothing below it. The bug was in the general claim, which is what
/// `AuditedRoot::structure` reports to a funder.
#[test]
fn a_dealing_one_seat_can_open_is_refused_even_at_the_declared_degree() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x3E47);
    let ceremony = CeremonyId::draw("degree is not coalition size", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);

    let roster: Vec<u64> = (0..3).map(Gates::nth).collect();
    let b = Scalar::from(7777u64);
    let a = Scalar::from(31u64);
    // p(x) = b + a*x*(x-1), evaluated at the points the audit uses: 1, 2, 3.
    let secrets: Vec<Scalar> = (1u64..=3)
        .map(|x| {
            let x = Scalar::from(x);
            b + a * x * (x - Scalar::ONE)
        })
        .collect();
    let shares: Vec<RistrettoPoint> = secrets.iter().map(|s| s * G).collect();
    let claim = ComponentClaim::from_parts(
        Gates::NAME,
        3,
        roster.clone(),
        b * G,
        shares,
        seat_keys_over::<Gates>(&roster),
    );

    // The dealing is real: seat 1 (evaluation point 1) opens the component
    // outright, which is the whole defect, and it is stated here as arithmetic
    // rather than left for the audit to be believed about.
    assert_eq!(secrets[0], b);
    assert_eq!(claim.verification_share(roster[0]), Some(b * G));

    let salt = [0x3E; 32];
    let sealed = SealedComposition::new(
        ceremony,
        owners.commitment,
        seal_and_sign::<Gates>(&ceremony, &claim, &salt),
    )
    .expect("well-formed");
    let mut pops = BTreeMap::new();
    for (i, &id) in roster.iter().enumerate() {
        pops.insert(
            id,
            Pop::prove_unchecked(&sealed, &claim, id, &secrets[i]).expect("opens its own share"),
        );
    }
    // Every proof verifies: this is not caught anywhere in the proving path.
    let endorsements = seat_endorsements::<Gates>(&ceremony, &claim, &secrets);
    let reveal = ComponentReveal::assemble(&sealed, claim, pops, endorsements, salt)
        .expect("a genuine dealing on a genuine polynomial");

    let artifact =
        CompositionArtifact::from_parts(sealed, owners.reveal(&sealed), reveal);
    assert_eq!(
        audit(&artifact, &parties_over(owners_spec().ids(), &roster)).unwrap_err(),
        CeremonyError::ThresholdOverstated {
            cohort: Gates::NAME,
            threshold: 3,
            quorum: vec![roster[0]],
        },
        "seat 1 alone reaches the component, so `threshold = 3` is not the \
         minimum coalition size the funder is told it is",
    );

    // Control: the same shape dealt on a polynomial with no such seat -- an
    // ordinary degree-2 dealing -- audits. So the refusal is the property and
    // not the shape.
    let mut rng2 = ChaCha20Rng::seed_from_u64(0x3E48);
    let ceremony2 = CeremonyId::draw("degree is not coalition size", &mut rng2);
    let owners2 = CohortSide::<Owners>::generate(&ceremony2, &owners_spec(), &mut rng2);
    let (c1, c2) = (Scalar::from(5u64), Scalar::from(11u64));
    let secrets2: Vec<Scalar> = (1u64..=3)
        .map(|x| {
            let x = Scalar::from(x);
            b + c1 * x + c2 * x * x
        })
        .collect();
    // No seat is the component, and no pair reaches it either.
    for s in &secrets2 {
        assert_ne!(*s, b);
    }
    let claim2 = ComponentClaim::from_parts(
        Gates::NAME,
        3,
        roster.clone(),
        b * G,
        secrets2.iter().map(|s| s * G).collect(),
        seat_keys_over::<Gates>(&roster),
    );
    let salt2 = [0x3F; 32];
    let sealed2 = SealedComposition::new(
        ceremony2,
        owners2.commitment,
        seal_and_sign::<Gates>(&ceremony2, &claim2, &salt2),
    )
    .expect("well-formed");
    let mut pops2 = BTreeMap::new();
    for (i, &id) in roster.iter().enumerate() {
        pops2.insert(
            id,
            Pop::prove_unchecked(&sealed2, &claim2, id, &secrets2[i]).expect("opens its own"),
        );
    }
    let endorsements2 = seat_endorsements::<Gates>(&ceremony2, &claim2, &secrets2);
    let reveal2 =
        ComponentReveal::assemble(&sealed2, claim2, pops2, endorsements2, salt2).expect("genuine");
    let artifact2 =
        CompositionArtifact::from_parts(sealed2, owners2.reveal(&sealed2), reveal2);
    audit(&artifact2, &parties_over(owners_spec().ids(), &roster))
        .expect("an ordinary 3-of-3 dealing still audits");
}
