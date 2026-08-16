//! Forging an artifact that passes: the attacks, and the one that works.
//!
//! Every test here is an ATTACK, run to completion against the real `audit` and
//! the real `production::authorize_release`. The file is ordered so the refused
//! ones come first and the one that succeeds comes last, because the last one is
//! the finding and the others are what establishes that it is not simply a hole
//! anywhere else.
//!
//! Nothing here mutates library state or reaches into private fields. Every
//! attack is built out of the crate's own public API in the order a real
//! attacker would have it available.

mod common;

use std::collections::BTreeMap;

use common::{identity_of, parties, CohortSide, Honest, SUBADDRESS};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G, ristretto::RistrettoPoint, scalar::Scalar,
};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use two_cohort::{
    audit, audit_address,
    ceremony::{
        draw_salt, endorse_seat_unchecked, ComponentClaim, ComponentCommitment, ComponentReveal,
        Parties, SealedComposition, SeatEndorsement, SeatRoster, SignedCommitment,
    },
    identity::{IdentityKey, IdentityPublic},
    derive::subaddress_offset,
    production::{
        self, authorize_release, check_decided_structure, deposit_spend_key, ReleaseRefused,
        COMPROMISE_THRESHOLD, GATE_THRESHOLD, OWNER_COUNT, OWNER_THRESHOLD,
    },
    CeremonyError, CeremonyId, Cohort, CohortSpec, CompositeSpend, CompositionArtifact,
    ControlDomain, Error, Gates, Owners, Pop, Provenance,
};

fn decided_owners() -> CohortSpec<Owners> {
    production::owners()
}

fn decided_gates() -> CohortSpec<Gates> {
    production::gates()
}

fn decided_ceremony(seed: u64) -> Honest {
    Honest::run(seed, &decided_owners(), &decided_gates())
}

/// A `Parties` naming the two real organisations, the decided gate seat, and
/// whatever OWNER seat keys the caller says a funder collected.
///
/// The owner seats are the parameter because they are what these attacks vary:
/// everything else about the decided structure is held fixed so that a refusal
/// is attributable to the seat attribution and not to a shape nobody decided.
fn parties_naming_owner_seats(owner_seats: &[(u64, IdentityPublic)]) -> Parties {
    Parties::new(
        identity_of::<Owners>().public(),
        SeatRoster::<Owners>::new(owner_seats.iter().copied()).expect("decided owner ids"),
        identity_of::<Gates>().public(),
        common::seats_for::<Gates>(&decided_gates()),
    )
}

/// Three long-term identity keys the DEALER holds, one per owner seat.
///
/// Distinct keys, because two seats sharing one is refused by
/// `CeremonyError::SeatKeysNotDistinct` and that is a different finding. These
/// are what a dealer writes into its claim when it has to name somebody for
/// each seat and the only somebody it can sign as is itself.
fn dealer_owner_seat_keys(tag: u8) -> Vec<IdentityKey> {
    (0..OWNER_COUNT as u8)
        .map(|k| IdentityKey::from_seed(&[tag.wrapping_add(k); 32]))
        .collect()
}

/// Each seat's endorsement, made with `keys[k]` for roster position `k` and the
/// share the DEALER holds for that seat.
///
/// It goes through `endorse_seat_unchecked` rather than `endorse_seat`, because
/// an attacker does not use the checked entry point: `endorse_seat` refuses to
/// endorse a seat the claim attributes to somebody else (`SeatKeyNotOwn`), which
/// is the honest holder's protection and not a containment boundary. Whoever
/// holds both secrets can produce the proof without calling any of this, so a
/// test that could not do the same would be testing the wrong thing.
///
/// The dealer supplies the SHARES from its own dealing, so every endorsement
/// here is mathematically valid under the key that made it. That is what keeps
/// variant B below a statement about WHOSE key it is rather than about whether a
/// proof was well-formed: the dealer holds every share, and since the
/// endorsement became a linked proof, holding every share is exactly half of
/// what it needs.
fn endorsements_by(
    ceremony: &CeremonyId,
    claim: &ComponentClaim,
    keys: &[IdentityKey],
    dealt: &Cohort,
) -> BTreeMap<u64, SeatEndorsement> {
    claim
        .roster()
        .iter()
        .enumerate()
        .map(|(k, &id)| {
            (
                id,
                endorse_seat_unchecked(
                    ceremony,
                    claim,
                    id,
                    &keys[k],
                    &dealt.share(id).expect("the dealer dealt to this seat"),
                )
                .expect("the dealer holds this share; whose key it is, is the audit's question"),
            )
        })
        .collect()
}

/// The three view-side values a deployment supplies, drawn once per attack so
/// that two attacks cannot accidentally share an address.
struct Deposit {
    view: RistrettoPrivate,
    spend_public: RistrettoPublic,
    tx_public: RistrettoPublic,
}

impl Deposit {
    /// An output paid to subaddress [`SUBADDRESS`] of `root`.
    fn to(root: RistrettoPoint, rng: &mut ChaCha20Rng) -> Deposit {
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

/// The whole deployment path, from wire artifact to published deposit address.
///
/// One function because the attacks below differ only in the ARTIFACT they hand
/// it, and a path rewritten per test is a path that can be quietly weakened per
/// test. It is the sequence `production`'s module docs prescribe: audit the
/// address, build the spend, pass the release gate, publish.
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
    let auth = authorize_release(&spend, parties)?;
    let published = deposit_spend_key(&auth);
    Ok((spend, published))
}

// ---------------------------------------------------------------------------
// 1. Reusing a signature from an earlier ceremony.
// ---------------------------------------------------------------------------

/// **Attack.** The owner organisation endorsed a commitment in ceremony A. The
/// attacker lifts that endorsement, verbatim, into ceremony B.
///
/// Refused because [`commitment_signing_payload`] puts the ceremony id under the
/// signature. The reveal presented alongside it is ceremony A's own, so nothing
/// about the CONTENTS is wrong -- the only thing that changed is which ceremony
/// the endorsement is being read in.
#[test]
fn an_endorsement_from_an_earlier_ceremony_does_not_carry_into_a_later_one() {
    let a = decided_ceremony(0xA1);

    let mut rng = ChaCha20Rng::seed_from_u64(0xB2);
    let b = CeremonyId::draw("the second ceremony", &mut rng);
    let gates_b = CohortSide::<Gates>::generate(&b, &decided_gates(), &mut rng);

    // Ceremony A's owner endorsement, unmodified, inside ceremony B.
    let sealed = SealedComposition::new(b, a.owners.commitment, gates_b.commitment)
        .expect("both commitments are of the right cohorts");
    let forged = CompositionArtifact::from_parts(
        sealed,
        a.owner_reveal.clone(),
        gates_b.reveal(&sealed),
    );

    assert_eq!(
        audit(&forged, &parties()).unwrap_err(),
        CeremonyError::CommitmentSignatureInvalid {
            cohort: Owners::NAME,
            signer: identity_of::<Owners>().public(),
        },
        "an endorsement is a statement about ONE ceremony",
    );
}

/// **Attack.** The same commitment the honest owners are about to publish in
/// ceremony B, but endorsed under ceremony A's id.
///
/// This isolates the ceremony id in the signing payload from everything else:
/// the digest, the claim, the salt and the signer are all exactly what the
/// honest run produces, and the control below endorses the identical commitment
/// under B and audits.
#[test]
fn an_endorsement_over_a_different_ceremony_id_is_refused() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xC3);
    let a = CeremonyId::draw("the ceremony that was signed", &mut rng);
    let b = CeremonyId::draw("the ceremony that is presented", &mut rng);
    assert_ne!(a, b);

    let owners = CohortSide::<Owners>::generate(&b, &decided_owners(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&b, &decided_gates(), &mut rng);

    let over_a = SignedCommitment::create(&a, owners.commitment.commitment(), &identity_of::<Owners>());
    assert_eq!(
        over_a.commitment(),
        owners.commitment.commitment(),
        "the only difference from the honest endorsement is which ceremony was signed",
    );

    let sealed = SealedComposition::new(b, over_a, gates.commitment).expect("well-formed");
    let forged =
        CompositionArtifact::from_parts(sealed, owners.reveal(&sealed), gates.reveal(&sealed));
    assert_eq!(
        audit(&forged, &parties()).unwrap_err(),
        CeremonyError::CommitmentSignatureInvalid {
            cohort: Owners::NAME,
            signer: identity_of::<Owners>().public(),
        },
    );

    // The control: the same commitment, endorsed under the ceremony it is
    // presented in, audits. So the refusal above is the ceremony id and nothing
    // else. Fresh cohorts, because the honest shares have now spent their one
    // proof on `sealed`.
    let mut rng = ChaCha20Rng::seed_from_u64(0xC3 ^ 1);
    let owners = CohortSide::<Owners>::generate(&b, &decided_owners(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&b, &decided_gates(), &mut rng);
    let over_b =
        SignedCommitment::create(&b, owners.commitment.commitment(), &identity_of::<Owners>());
    let sealed = SealedComposition::new(b, over_b, gates.commitment).expect("well-formed");
    let honest =
        CompositionArtifact::from_parts(sealed, owners.reveal(&sealed), gates.reveal(&sealed));
    audit(&honest, &parties()).expect("endorsed under the ceremony it is presented in");
}

/// **Attack.** Keep the ceremony id -- so the earlier endorsement IS valid --
/// and replace only the other cohort's half.
///
/// This is the version of the replay that the signing payload cannot refuse: the
/// owner endorsement is genuine and is being read in the ceremony it was made
/// for. What refuses it is that the owners' proofs of possession name the gate
/// digest, so an artifact carrying a different gate commitment carries owner
/// proofs that do not verify -- and the owners' shares will not make new ones.
///
/// Both halves are performed, because either alone would leave the other
/// untested.
#[test]
fn replaying_an_owner_half_under_a_fresh_gate_half_fails_at_the_proofs() {
    let a = decided_ceremony(0xD4);
    let mut rng = ChaCha20Rng::seed_from_u64(0xD5);

    // The attacker is the gate side. It keeps the ceremony id -- so the owners'
    // endorsement stays valid -- and seals a different gate component.
    let gates2 = CohortSide::<Gates>::generate(&a.ceremony, &decided_gates(), &mut rng);
    assert_ne!(gates2.commitment, a.gates.commitment);

    let sealed2 = SealedComposition::new(a.ceremony, a.owners.commitment, gates2.commitment)
        .expect("well-formed");
    let forged = CompositionArtifact::from_parts(
        sealed2,
        a.owner_reveal.clone(),
        gates2.reveal(&sealed2),
    );

    // The endorsement is accepted -- it is genuine and in its own ceremony --
    // and the failure is at the owners' proofs.
    assert_eq!(
        audit(&forged, &parties()).unwrap_err(),
        CeremonyError::PopFailed {
            cohort: Owners::NAME,
            participant: Owners::nth(0),
        },
    );

    // And the owners will not answer the second composition, which is the half
    // that stops the attacker simply asking for fresh proofs.
    assert_eq!(
        a.owners.try_pops(&sealed2).unwrap_err(),
        CeremonyError::ProofAlreadyIssued {
            cohort: Owners::NAME,
            participant: Owners::nth(0),
        },
    );
}

// ---------------------------------------------------------------------------
// 2. Swapping the two cohorts.
// ---------------------------------------------------------------------------

/// **Attack.** Present each cohort's half in the other's slot, both ways round.
///
/// Two distinct places refuse it, and both are exercised: the composition
/// refuses commitments in the wrong slots, and the audit refuses a reveal whose
/// claim names the other cohort.
#[test]
fn the_two_cohorts_halves_cannot_be_swapped() {
    let a = decided_ceremony(0xE6);

    // Commitments transposed: refused at assembly.
    assert_eq!(
        SealedComposition::new(a.ceremony, a.gates.commitment, a.owners.commitment).unwrap_err(),
        CeremonyError::CohortMismatch {
            expected: Owners::NAME,
            found: Gates::NAME,
        },
    );

    // Commitments in their own slots, REVEALS transposed. The attribution check
    // passes -- each commitment really was endorsed by its own organisation --
    // and the shape check is what refuses it.
    let forged = CompositionArtifact::from_parts(
        a.sealed,
        a.gate_reveal.clone(),
        a.owner_reveal.clone(),
    );
    assert_eq!(
        audit(&forged, &parties()).unwrap_err(),
        CeremonyError::CohortMismatch {
            expected: Owners::NAME,
            found: Gates::NAME,
        },
    );

    // Transposing the funder's two keys instead is fail-closed for the same
    // reason: each key is checked against its own cohort's commitment.
    assert_eq!(
        audit(
            &a.artifact,
            &Parties::new(
                identity_of::<Gates>().public(),
                common::seats_for::<Owners>(&decided_owners()),
                identity_of::<Owners>().public(),
                common::seats_for::<Gates>(&decided_gates()),
            )
        )
        .unwrap_err(),
        CeremonyError::CommitmentSignerUnexpected {
            cohort: Owners::NAME,
            expected: identity_of::<Gates>().public(),
            found: identity_of::<Owners>().public(),
        },
    );
}

// ---------------------------------------------------------------------------
// 3. Rosters that audit, thresholds that were never decided.
// ---------------------------------------------------------------------------

/// **Attack.** A real ceremony, the decided ROSTERS, and an owner threshold of
/// one: any single operator plus the gate spends.
///
/// The audit accepts it, correctly -- it reports what the cohort is, and a
/// 1-of-3 cohort really is a 1-of-3 cohort. The refusal is the deployment's and
/// the funder's, and both are checked here because they are two different call
/// sites that must not drift apart.
#[test]
fn a_decided_roster_at_an_undecided_threshold_is_refused_on_both_paths() {
    let undecided = CohortSpec::<Owners>::with_ids(1, decided_owners().ids());
    let h = Honest::run(0xF7, &undecided, &decided_gates());

    let audited = audit(&h.artifact, &parties()).expect("a 1-of-3 cohort is a well-formed cohort");
    assert_eq!(audited.owner_structure().roster(), decided_owners().ids());
    assert_eq!(audited.owner_structure().threshold(), 1);

    let expected = ReleaseRefused::Threshold {
        cohort: Owners::NAME,
        expected: OWNER_THRESHOLD,
        found: 1,
    };

    // The funder's half.
    assert_eq!(check_decided_structure(&audited).unwrap_err(), expected);

    // The deployment's half, over the same artifact.
    let mut rng = ChaCha20Rng::seed_from_u64(0xF8);
    let deposit = Deposit::to(h.artifact.declared_root(), &mut rng);
    let err = deployment_publishes(&h.artifact, &parties(), &deposit)
        .expect_err("the decided structure is 2 of 3");
    assert_eq!(err.to_string(), expected.to_string());
}

/// **Attack.** A genuine 1-of-3 dealing published as a 2-of-3 one, so that the
/// artifact reports the decided threshold while one seat suffices.
///
/// This is the attack the two-sided consistency check exists for, aimed at the
/// release gate: get past `check_decided_structure` by DECLARING 2. Refused by
/// the lower bound -- a `(t-1)`-subset reaches the component.
#[test]
fn a_threshold_overstated_up_to_the_decided_one_is_refused_by_the_audit() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x109);
    let ceremony = CeremonyId::draw("overstated owner threshold", &mut rng);
    let ids = decided_owners().ids().to_vec();

    // A real 1-of-3 dealing: every share is the secret, so every seat alone
    // reconstructs it.
    let b_owner = Scalar::random(&mut rng);
    let dealt = Cohort::deal_in::<Owners, _>(&b_owner, 1, &ids, &mut rng).expect("dealt");
    let shares: Vec<RistrettoPoint> = ids
        .iter()
        .map(|&id| dealt.verification_share(id).expect("on the roster"))
        .collect();

    // ...published as 2-of-3, which is the decided threshold.
    //
    // The three seats are attributed to three keys the dealer holds, and the
    // funder below is given those same three keys. That is deliberate: this
    // test is about the THRESHOLD arm, so every other arm is made to pass. The
    // seat arm is what `a_dealt_owner_cohort_is_refused_at_the_seat_attribution`
    // is about, and it is a separate finding.
    let seat_keys = dealer_owner_seat_keys(0x60);
    let claim = ComponentClaim::from_parts(
        Owners::NAME,
        2,
        ids.clone(),
        b_owner * G,
        shares,
        seat_keys.iter().map(|k| k.public()).collect(),
    );
    let salt = draw_salt(&mut rng);
    let signed = SignedCommitment::create(
        &ceremony,
        ComponentCommitment::seal(&ceremony, &claim, &salt),
        &identity_of::<Owners>(),
    );
    let gates = CohortSide::<Gates>::generate(&ceremony, &decided_gates(), &mut rng);
    let sealed = SealedComposition::new(ceremony, signed, gates.commitment).expect("well-formed");

    // Every proof of possession is genuine: the dealer holds every share.
    let pops: BTreeMap<u64, Pop> = ids
        .iter()
        .map(|&id| {
            (
                id,
                Pop::prove_unchecked(&sealed, &claim, id, &dealt.share(id).expect("dealt")).expect("holds it"),
            )
        })
        .collect();
    let endorsements = endorsements_by(&ceremony, &claim, &seat_keys, &dealt);
    let named: Vec<(u64, IdentityPublic)> = ids
        .iter()
        .zip(&seat_keys)
        .map(|(&id, k)| (id, k.public()))
        .collect();
    let reveal = ComponentReveal::from_parts(claim, pops, endorsements, salt);
    let forged = CompositionArtifact::from_parts(sealed, reveal, gates.reveal(&sealed));

    assert_eq!(
        audit(&forged, &parties_naming_owner_seats(&named)).unwrap_err(),
        CeremonyError::ThresholdOverstated {
            cohort: Owners::NAME,
            threshold: 2,
            quorum: vec![Owners::nth(0)],
        },
        "a degree-0 polynomial is also a degree-1 polynomial; only the lower \
         bound separates them",
    );
}

// ---------------------------------------------------------------------------
// 4. Every constructor that is not the ceremony.
// ---------------------------------------------------------------------------

/// **Attack.** Reach the release gate through each of the crate's other
/// `CompositeSpend` constructors.
///
/// There are exactly three public ones -- `simulate`, `simulate_from_seed` and
/// `from_ceremony` -- and this drives the two that are not the ceremony, at the
/// decided shape, so the only thing left for the gate to refuse is provenance.
#[test]
fn the_constructors_that_are_not_the_ceremony_are_refused_at_the_decided_shape() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x11A);

    let seeded =
        CompositeSpend::simulate_from_seed(0x11B, &decided_owners(), &decided_gates(), SUBADDRESS)
            .expect("a dealer deals any shape");
    let drawn = CompositeSpend::simulate(&decided_owners(), &decided_gates(), SUBADDRESS, &mut rng)
        .expect("a dealer deals any shape");

    for spend in [&seeded, &drawn] {
        // Everything the gate compares apart from provenance is already right.
        assert_eq!(spend.owners().roster(), decided_owners().ids());
        assert_eq!(spend.owners().threshold(), OWNER_THRESHOLD);
        assert_eq!(spend.gates().roster(), decided_gates().ids());
        assert_eq!(spend.gates().threshold(), GATE_THRESHOLD);
        assert_eq!(spend.provenance(), Provenance::Simulated);
        assert_eq!(spend.endorsers(), None);
        assert_eq!(
            authorize_release(spend, &parties()).unwrap_err(),
            ReleaseRefused::NotFromCeremony,
        );
    }
}

// ---------------------------------------------------------------------------
// 5. THE FORGERY THAT USED TO PASS.
// ---------------------------------------------------------------------------

/// **The attack that no longer works, performed both ways round.**
///
/// The operator organisation runs no DKG. It picks `b_owner`, deals three shares
/// of it to itself at 2-of-3 over the decided roster, and endorses the result
/// with its OWN identity key -- the key a funder obtained from it, used honestly,
/// by its rightful holder. The gate side is a genuine independent party running
/// a real DKG under its own key.
///
/// Until per-seat identity existed this reached `deposit_spend_key` and the
/// address was published, after which TWO principals -- the dealing organisation
/// and the single gate -- opened an output paid to it, against a decided
/// [`COMPROMISE_THRESHOLD`] of three. That is the whole reason the claim now
/// names a key per seat.
///
/// Nothing about the ATTACK has been made impossible, and the first block below
/// says so in arithmetic: the dealer still holds `b_owner`, the claim is still
/// well-formed, every proof of possession is still genuine because the dealer
/// really does know every share. What changed is that a claim must now say WHO
/// holds each seat, and the dealer has only two things it can write there. Both
/// are performed:
///
///   * **its own keys**, which is what it can sign for -- refused as
///     [`CeremonyError::SeatUnexpected`], because the funder obtained a
///     different key from the party it believes holds that seat;
///   * **the real seat-holders' keys**, which are public and so free to copy --
///     refused as [`CeremonyError::SeatEndorsementInvalid`], because the dealer
///     cannot endorse as them.
///
/// **An earlier version of this doc said those were the only two options and
/// that there was "no third". That was FALSE and an adversarial review found
/// it.** There WAS a third mounting and it passed: write the real seat-holders'
/// keys, and obtain from each of those parties a genuine signature over public
/// bytes that revealed no secret and cost the signer nothing -- while the dealer
/// kept every share and made every proof of possession itself. Nothing in the
/// artifact bound the party that signed to a share.
///
/// That third mounting is now refused too, because a seat endorsement became a
/// proof of knowledge of the share as well as of the identity key. The two tests
/// that performed it are inverted:
/// `tests/seat_identity.rs::a_dealer_that_keeps_the_shares_is_refused_at_the_seat_endorsement`
/// and
/// `tests/seat_forgery.rs::a_seat_holder_with_a_real_share_cannot_endorse_a_substituted_dealing`.
/// Note what that does and does not do to THIS test's variants: nothing. The
/// dealer here holds every share, so it makes well-formed endorsements under its
/// own keys either way, and the two refusals below are still about WHOSE keys
/// they are. What did change is that variant B's dealer can no longer buy its
/// way past them with signatures collected for free.
///
/// The residual that remains, and is not this test's: a dealer that dealt REAL
/// shares to real parties and kept copies --
/// `tests/seat_identity.rs::a_dealer_that_dealt_real_shares_and_kept_copies_still_passes`.
///
/// Mixed vectors exist too -- `[real, real, dealer]` clears two comparisons
/// before failing on the third -- and are the same two refusals seat by seat.
///
/// **The qualifications from the original exhibit still hold**, and one is
/// added. The dealt seats' proofs are made with `Pop::prove_unchecked` rather
/// than `CohortShare::prove`, and the endorsements with `endorse_seat_unchecked`
/// rather than `endorse_seat`, because a dealer holds a `Cohort` and not a
/// `CohortShare`; gating either raw entry point does not close this and never
/// did. This test runs in one process holding every key, so "the real
/// seat-holders" is a MODELLED role. And what is established below is that the
/// bar moved from two keys to four -- NOT that four keys are four organisations.
/// A dealer that persuaded three real parties to hand over their seat keys, or
/// that dealt shares to three real parties while keeping copies, produces an
/// artifact that still audits. See the module docs of `two_cohort::ceremony`.
#[test]
fn a_dealt_owner_cohort_is_refused_at_the_seat_attribution() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x12C);
    let ceremony = CeremonyId::draw("two-cohort eUSD release address", &mut rng);
    let ids = decided_owners().ids().to_vec();

    // ---- the operator organisation, dealing to itself ----
    let b_owner = Scalar::random(&mut rng);
    let dealt =
        Cohort::deal_in::<Owners, _>(&b_owner, OWNER_THRESHOLD, &ids, &mut rng).expect("dealt");
    let verification: Vec<RistrettoPoint> = ids
        .iter()
        .map(|&id| dealt.verification_share(id).expect("on the roster"))
        .collect();

    // Each variant below gets its OWN gate cohort, drawn inside `mount`. It has
    // to: each variant seals a different owner half, so the two compositions
    // differ, and a share answers exactly one sealed composition. (An earlier
    // comment here claimed one gate cohort was generated and shared by both,
    // which the code never did -- review caught the discrepancy.)
    //
    // ---- variant A: the dealer names ITSELF at every seat ----
    let own_keys = dealer_owner_seat_keys(0x70);
    let a = mount(
        &mut rng,
        &ceremony,
        &ids,
        &b_owner,
        &dealt,
        &verification,
        own_keys.iter().map(|k| k.public()).collect(),
        |c, claim| endorsements_by(c, claim, &own_keys, &dealt),
    );

    // THE HARM IS STILL THERE, and it is stated before the refusal so that the
    // refusal is read as the thing that stops it. The dealer holds the discrete
    // log of the whole owner component, which no member of an honest 2-of-3
    // cohort does.
    assert_eq!(a.artifact.owners().component(), b_owner * G);

    // A funder that holds the keys of the three REAL seat-holders refuses it,
    // naming the first seat and both keys, so a human knows who to go and talk
    // to.
    let honest_seats = common::seats_for::<Owners>(&decided_owners());
    assert_eq!(
        audit(&a.artifact, &parties()).unwrap_err(),
        CeremonyError::SeatUnexpected {
            cohort: Owners::NAME,
            participant: ids[0],
            expected: honest_seats.key_of(ids[0]).expect("decided seat"),
            found: own_keys[0].public(),
        },
    );
    // ...and the whole deployment path refuses it at the same step, so this is
    // not an audit-only refusal that a funding path could walk past.
    let deposit = Deposit::to(a.artifact.declared_root(), &mut rng);
    let refused = deployment_publishes(&a.artifact, &parties(), &deposit)
        .expect_err("the dealt cohort must not reach the published address");
    assert_eq!(
        refused.downcast_ref::<CeremonyError>(),
        Some(&CeremonyError::SeatUnexpected {
            cohort: Owners::NAME,
            participant: ids[0],
            expected: honest_seats.key_of(ids[0]).expect("decided seat"),
            found: own_keys[0].public(),
        }),
        "the deployment path stops at `audit_address`, before any spend exists",
    );

    // ---- variant B: the dealer names the REAL seat-holders ----
    // Their public keys are public. Copying them is free, and it gets the
    // dealer past the comparison variant A failed -- and no further, because
    // the endorsement is checked under the key the FUNDER supplied.
    let b = mount(
        &mut rng,
        &ceremony,
        &ids,
        &b_owner,
        &dealt,
        &verification,
        ids.iter()
            .map(|&id| honest_seats.key_of(id).expect("decided seat"))
            .collect(),
        // Made with the keys the dealer actually has. It has no others -- and
        // with the shares it does have, which is why the proof is well-formed and
        // fails only under the funder's key.
        |c, claim| endorsements_by(c, claim, &own_keys, &dealt),
    );
    assert_eq!(
        b.artifact.owners().seat_keys(),
        ids.iter()
            .map(|&id| honest_seats.key_of(id).expect("decided seat"))
            .collect::<Vec<_>>(),
        "control: the claim really does name the real seat-holders, so the \
         comparison variant A failed is passed here",
    );
    assert_eq!(
        audit(&b.artifact, &parties()).unwrap_err(),
        CeremonyError::SeatEndorsementInvalid {
            cohort: Owners::NAME,
            participant: ids[0],
            signer: honest_seats.key_of(ids[0]).expect("decided seat"),
        },
        "copying a public key is not holding it",
    );

    // The control that makes both refusals mean something: the SAME funder
    // keys, over an honest ceremony at the same shape, still reach the
    // published address. Without it these would be evidence that the path
    // refuses things, not that it distinguishes them.
    let h = decided_ceremony(0x12D);
    let honest_deposit = Deposit::to(h.artifact.declared_root(), &mut rng);
    let (_, published) = deployment_publishes(&h.artifact, &parties(), &honest_deposit)
        .expect("an honest ceremony at the decided shape still publishes");
    assert_eq!(published, honest_deposit.spend_public);
    assert_eq!(COMPROMISE_THRESHOLD, 3);
}

/// One mounting of the dealt-owner forgery: everything but WHO the claim names
/// and who signs for them.
///
/// Both variants above differ in exactly those two inputs, so they are
/// parameters and the rest of the attack is one piece of code. A per-variant
/// copy could be quietly weakened per variant, which is the mistake this file's
/// `deployment_publishes` already exists to avoid one level up.
struct Mounted {
    artifact: CompositionArtifact,
}

#[allow(clippy::too_many_arguments)]
fn mount(
    rng: &mut ChaCha20Rng,
    ceremony: &CeremonyId,
    ids: &[u64],
    b_owner: &Scalar,
    dealt: &Cohort,
    verification: &[RistrettoPoint],
    seat_keys: Vec<IdentityPublic>,
    endorse: impl Fn(&CeremonyId, &ComponentClaim) -> BTreeMap<u64, SeatEndorsement>,
) -> Mounted {
    let claim = ComponentClaim::from_parts(
        Owners::NAME,
        OWNER_THRESHOLD,
        ids.to_vec(),
        b_owner * G,
        verification.to_vec(),
        seat_keys,
    );
    let salt = draw_salt(rng);
    let signed = SignedCommitment::create(
        ceremony,
        ComponentCommitment::seal(ceremony, &claim, &salt),
        // Its own organisation key. Nothing is stolen and nothing is
        // impersonated at the COHORT level, which is exactly the point: that
        // level was never the one the security argument counted.
        &identity_of::<Owners>(),
    );
    let gates = CohortSide::<Gates>::generate(ceremony, &decided_gates(), rng);
    let sealed = SealedComposition::new(*ceremony, signed, gates.commitment).expect("well-formed");

    // Every proof of possession is genuine: the dealer knows every share.
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
    let endorsements = endorse(ceremony, &claim);
    Mounted {
        artifact: CompositionArtifact::from_parts(
            sealed,
            ComponentReveal::from_parts(claim, pops, endorsements, salt),
            gates.reveal(&sealed),
        ),
    }
}

/// **The known residual, carried through to the release gate.**
///
/// `attribution.rs::the_residual_is_a_party_that_holds_both_organisations_identity_keys`
/// stops at `audit`, and at a shape nobody decided. This runs it at the decided
/// shape and all the way to the published address, so the statement "one party
/// holding both keys still passes" is a statement about the RELEASE PATH and not
/// only about the audit.
///
/// Both DKGs are real; the impostor satisfies every check because it genuinely
/// holds every share. It then opens the output alone.
#[test]
fn the_release_gate_admits_a_sole_party_holding_both_identity_keys() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x13D);
    let ceremony = CeremonyId::draw("both keys, decided shape", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &decided_owners(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &decided_gates(), &mut rng);

    let sealed =
        SealedComposition::new(ceremony, owners.commitment, gates.commitment).expect("well-formed");
    let artifact =
        CompositionArtifact::from_parts(sealed, owners.reveal(&sealed), gates.reveal(&sealed));

    let deposit = Deposit::to(artifact.declared_root(), &mut rng);
    let (spend, published) = deployment_publishes(&artifact, &parties(), &deposit)
        .expect("the residual reaches the funding path, not only the audit");
    assert_eq!(published, deposit.spend_public);

    // One process opens the output.
    let oq = owners.quorum(OWNER_THRESHOLD);
    let b_owner: Scalar = oq
        .iter()
        .map(|&id| *owners.share_of(id).term(&oq).expect("quorum member").weight())
        .sum();
    let gq = gates.quorum(GATE_THRESHOLD);
    let b_gate: Scalar = gq
        .iter()
        .map(|&id| *gates.share_of(id).term(&gq).expect("quorum member").weight())
        .sum();
    assert_eq!(
        (*spend.common() + b_owner + b_gate) * G,
        *spend.target().as_ref(),
        "one principal, against a decided COMPROMISE_THRESHOLD of {COMPROMISE_THRESHOLD}",
    );
}

/// The control for the two forgeries above: the same path, over an honest
/// ceremony at the decided shape, reaches the same address and reports the same
/// answers.
///
/// Without this, the two tests above would be evidence that the path accepts
/// things, not evidence that it fails to distinguish them.
///
/// **What it does NOT establish, corrected after review.** An earlier version of
/// this doc said "NOBODY can open it without convening a quorum of each cohort".
/// No in-process test can say that: this harness holds every `CohortShare` of
/// both cohorts, and `run_dkg` runs every participant in one process. What the
/// assertions below do establish is the ALGEBRAIC half -- that no single owner
/// seat's share opens the owner component, checked directly against the
/// published verification shares rather than through the API's own threshold
/// refusal, which would only be testing `term`'s argument validation. Real-world
/// custody separation is exactly the thing the artifact does not carry, which is
/// the finding these three tests exist to record.
#[test]
fn the_honest_ceremony_reaches_the_same_path_and_the_same_answers() {
    let h = decided_ceremony(0x14E);
    let mut rng = ChaCha20Rng::seed_from_u64(0x14F);
    let deposit = Deposit::to(h.artifact.declared_root(), &mut rng);

    let (spend, published) =
        deployment_publishes(&h.artifact, &parties(), &deposit).expect("honest");
    assert_eq!(published, deposit.spend_public);

    // The audited structure a funder reads is IDENTICAL to the forged one's.
    let audited = audit(&h.artifact, &parties()).expect("honest");
    let (o, g) = audited.structure();
    assert_eq!((o.roster(), o.threshold()), (decided_owners().ids(), OWNER_THRESHOLD));
    assert_eq!((g.roster(), g.threshold()), (decided_gates().ids(), GATE_THRESHOLD));
    assert_eq!(o.identity(), &identity_of::<Owners>().public());

    // The difference the artifact does not record, in the one form a test in
    // this process can actually check: no single operator seat's share is the
    // owner component. Asserted against the PUBLISHED verification shares, not
    // through `term`, because `term(&[id]).is_err()` only shows that the API
    // refuses a sub-threshold subset -- which it would do for a dealt cohort
    // too, and so distinguishes nothing.
    //
    // This is the same property `check_consistency`'s lower bound now enforces
    // for every subset below the declared threshold. Asserting it here on an
    // honest run is the positive side of that: the honest dealing has it, and
    // `composition.rs::a_dealing_one_seat_can_open_is_refused_even_at_the_declared_degree`
    // is the dealing that does not.
    for &id in decided_owners().ids() {
        assert_ne!(
            o.component(),
            h.owners
                .claim
                .verification_share(id)
                .expect("on the roster"),
            "seat {id}'s own share opens the owner component outright",
        );
    }
    assert!(matches!(
        spend.onetime(&[Owners::nth(0), Owners::nth(1)], &[Gates::nth(0)]),
        Err(Error::InCohort { .. }) | Err(Error::SharesNotHeld),
    ));
}
