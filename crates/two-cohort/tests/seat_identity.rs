//! Per-seat identity: who holds each seat, and what a funder can check about it.
//!
//! `tests/attribution.rs` is the same file one grain coarser -- it is about the
//! two ORGANISATION keys. This one is about the key per SEAT, which is the grain
//! `production::COMPROMISE_THRESHOLD` counts in.
//!
//! What entitles these tests to their conclusions:
//!
//!   * every rejection names the exact error, never `is_err()`. This repo has
//!     shipped a negative test satisfied by an error from the wrong layer, and
//!     several of the checks here are one `if` apart from each other;
//!   * every rejection carries a CONTROL that passes. Where the control is a
//!     one-input change to the same value it is stated as such; where building
//!     the attack needs a fresh ceremony -- because a share answers exactly one
//!     sealed composition -- the control is a fresh honest ceremony and is NOT
//!     a one-input comparison. Review corrected a preamble that claimed the
//!     stronger thing for every test in the file. Note also that `Honest::run`
//!     builds its artifact through `SealedComposition::open`, which calls
//!     `audit`: a control that just re-audits an `Honest` fixture is confirming
//!     a value that guard already accepted, so it establishes that the guard
//!     admits honest input, not that it is independent of it;
//!   * the endorsements in the attacks are made to VERIFY wherever the test is
//!     about something else, so a refusal is never the signature check standing
//!     in for the check under test.
//!
//! What none of it establishes: that four keys are four entities. See
//! `two_cohort::ceremony`'s module docs, and the last test in this file, which
//! performs the residual rather than describing it.

mod common;

use std::collections::BTreeMap;

use common::{
    identity_of, parties_over, seat_key_of, seat_keys_over, seal_and_sign, CohortSide, Honest,
};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, scalar::Scalar};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use two_cohort::{
    audit,
    ceremony::{
        endorse_seat, seat_endorsement_message, ComponentClaim, ComponentCommitment,
        ComponentReveal, SealedComposition, SeatRoster, MAX_AUDITED_ROSTER,
    },
    identity::{IdentityKey, IdentityPublic, IdentitySignature},
    CeremonyError, CeremonyId, CohortSpec, CompositionArtifact, ControlDomain, Gates, Owners,
    Parties,
};

fn owners_spec() -> CohortSpec<Owners> {
    CohortSpec::<Owners>::sequential(2, 3)
}

fn gates_spec() -> CohortSpec<Gates> {
    CohortSpec::<Gates>::sequential(1, 1)
}

fn honest(seed: u64) -> Honest {
    Honest::run(seed, &owners_spec(), &gates_spec())
}

fn parties() -> Parties {
    parties_over(owners_spec().ids(), gates_spec().ids())
}

/// Rebuild a claim with one seat re-attributed to `key`, changing nothing else.
fn reattributed(claim: &ComponentClaim, seat: u64, key: IdentityPublic) -> ComponentClaim {
    let mut seats = claim.seat_keys().to_vec();
    let pos = claim
        .roster()
        .iter()
        .position(|&id| id == seat)
        .expect("seat is on the roster");
    seats[pos] = key;
    ComponentClaim::from_parts(
        claim.cohort(),
        claim.threshold(),
        claim.roster().to_vec(),
        claim.component(),
        claim.verification_shares().to_vec(),
        seats,
    )
}

/// Endorsements that VERIFY against whatever `claim` says, signed with the key
/// the caller supplies per seat.
///
/// Raw signing rather than `endorse_seat`, for `tests/forgery.rs`'s reason:
/// the checked entry point refuses to sign a seat attributed to somebody else,
/// which protects an honest holder and constrains nobody who holds a key.
fn endorse_with(
    ceremony: &CeremonyId,
    claim: &ComponentClaim,
    key_of: impl Fn(u64) -> IdentityKey,
) -> BTreeMap<u64, IdentitySignature> {
    claim
        .roster()
        .iter()
        .map(|&id| {
            let msg = seat_endorsement_message(ceremony, claim, id).expect("on the roster");
            (id, key_of(id).sign(&msg))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 1. What the artifact now says, and what the funder now checks.
// ---------------------------------------------------------------------------

/// **The audited structure names a key per seat, and they are the keys the
/// funder supplied.**
///
/// The positive statement the rest of the file is a set of refusals around.
///
/// It compares against the keys the fixture's funder holds. It does NOT and
/// cannot establish that `structure().seats()` READS those keys rather than the
/// artifact's: a successful audit has just forced the two equal, so an
/// implementation that reported the artifact's copy would pass this unchanged.
/// Review pointed that out. `structure_of` takes them from `parties` for the
/// reason `identity` does -- so that a future edit cannot report the artifact's
/// claim by accident -- and that is a construction argument, not a tested one.
#[test]
fn an_audited_root_names_one_identity_per_seat() {
    let h = honest(0x5EA7);
    let audited = audit(&h.artifact, &h.parties).expect("honest");
    let (o, g) = audited.structure();

    assert_eq!(
        o.seats(),
        owners_spec()
            .ids()
            .iter()
            .map(|&id| (id, seat_key_of::<Owners>(id).public()))
            .collect::<Vec<_>>(),
    );
    assert_eq!(
        g.seats(),
        vec![(Gates::nth(0), seat_key_of::<Gates>(Gates::nth(0)).public())],
    );

    // Four seats, four keys, and none of them is either organisation's key.
    let all: Vec<IdentityPublic> = o
        .seats()
        .iter()
        .chain(g.seats())
        .map(|&(_, k)| k)
        .collect();
    assert_eq!(all.len(), production_seat_count());
    for (i, k) in all.iter().enumerate() {
        assert!(!all[..i].contains(k), "seat keys are distinct");
        assert_ne!(*k, identity_of::<Owners>().public());
        assert_ne!(*k, identity_of::<Gates>().public());
    }

    // And the artifact's own claim agrees with them -- which `audit` is what
    // established, since a disagreement is `SeatUnexpected`.
    assert_eq!(h.artifact.owners().seat_keys(), &all[..3]);
}

/// The decided structure's seat count, stated here so the assertion above is
/// against a number and not against its own input.
fn production_seat_count() -> usize {
    two_cohort::production::OWNER_COUNT + two_cohort::production::GATE_COUNT
}

// ---------------------------------------------------------------------------
// 2. The commitment seals the seat keys.
// ---------------------------------------------------------------------------

/// **A revealed claim whose seat keys are not the committed ones does not open
/// its commitment.**
///
/// The seat identities go into `absorb_claim`, so they are inside the commitment
/// digest exactly as the roster, threshold and component are. This is the
/// typed error a funder gets, and it is `CommitmentMismatch` rather than a
/// variant of its own on purpose: the incident is that the reveal is not what
/// was sealed, and which FIELD differs is not something the auditor can see.
#[test]
fn a_reveal_whose_seat_keys_differ_from_the_committed_ones_is_refused() {
    let h = honest(0x5EA8);
    let stranger = IdentityKey::from_seed(&[0xD1; 32]);
    let seat = Owners::nth(0);

    let swapped = reattributed(h.artifact.owners().claim(), seat, stranger.public());

    // The digest really is different, asserted directly. That does NOT isolate
    // the commitment check on its own -- the reused endorsements name the old
    // claim digest and would also fail -- so what this establishes is the
    // ORDER as well as the binding: a claim that is not the sealed one is
    // reported as that, rather than as a signature failure. Review pointed out
    // that an earlier version of this comment claimed isolation it did not have.
    assert_ne!(
        ComponentCommitment::seal(&h.ceremony, &swapped, h.artifact.owners().salt()),
        ComponentCommitment::seal(
            &h.ceremony,
            h.artifact.owners().claim(),
            h.artifact.owners().salt()
        ),
        "the seat identities are inside the commitment digest",
    );

    let doctored = ComponentReveal::from_parts(
        swapped,
        h.artifact.owners().pops().clone(),
        h.artifact.owners().seat_endorsements().clone(),
        *h.artifact.owners().salt(),
    );
    assert_eq!(
        audit(
            &CompositionArtifact::from_parts(
                h.sealed,
                doctored,
                h.artifact.gates().clone()
            ),
            &h.parties,
        )
        .unwrap_err(),
        CeremonyError::CommitmentMismatch {
            cohort: Owners::NAME
        },
    );

    // CONTROL: the untouched reveal, same everything else, audits.
    audit(&h.artifact, &h.parties).expect("control");
}

// ---------------------------------------------------------------------------
// 3. Every proof transcript binds them.
// ---------------------------------------------------------------------------

/// **Re-attributing a seat fails at the PROOF, not at a comparison.**
///
/// This is the property that makes the seat keys structural rather than a label
/// beside the artifact. A coordinator that re-attributes a seat and re-seals its
/// own commitment defeats the commitment check -- it controls the seal. What it
/// cannot do is re-make the honest seats' proofs of possession, because
/// `pop_challenge` absorbs the claim and the claim now contains the seat keys.
///
/// Everything else is arranged to PASS so the refusal is attributable: the
/// funder here is told the re-attributed key holds the seat, and every
/// endorsement verifies under the funder's keys. So the seat comparison passes,
/// the endorsement check passes, and the proofs are what refuse it.
///
/// **Scope, corrected after review.** `audit` reports the FIRST failing seat, so
/// what this exhibits is that one seat's proof does not survive re-attribution
/// of that seat -- not "every proof" and not the gate side. The general
/// statement is the mechanism rather than the assertion: `pop_challenge` calls
/// `absorb_claim`, which absorbs the whole seat-key vector, so no proof in
/// either cohort is taken over an attribution other than the one it was made
/// under. The mutation that removes those bytes from `absorb_claim` is caught
/// here and by `a_reveal_whose_seat_keys_differ_from_the_committed_ones_is_refused`.
///
/// The CONTROL is a fresh honest ceremony, not a one-input change: the owner
/// shares here have spent their one proof on the re-attributed composition, so
/// the same shares cannot answer a second one. See this file's preamble.
#[test]
fn re_attributing_a_seat_fails_at_the_proof() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EA9);
    let ceremony = CeremonyId::draw("seat re-attribution", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);

    let impostor = IdentityKey::from_seed(&[0xD2; 32]);
    let seat = Owners::nth(0);
    let swapped = reattributed(&owners.claim, seat, impostor.public());

    // The coordinator seals ITS version and endorses it with the real owner
    // organisation key, so the commitment check cannot fire.
    let salt = [0x77; 32];
    let signed = seal_and_sign::<Owners>(&ceremony, &swapped, &salt);
    let sealed =
        SealedComposition::new(ceremony, signed, gates.commitment).expect("well-formed");

    // The honest seats prove possession. `prove_possession` derives the claim
    // from each share's own key generation, so what they sign is THEIR claim --
    // the one naming the real seat-holder -- under this sealed composition.
    let pops = owners.pops(&sealed);
    let endorsements = endorse_with(&ceremony, &swapped, |id| {
        if id == seat {
            IdentityKey::from_seed(&[0xD2; 32])
        } else {
            seat_key_of::<Owners>(id)
        }
    });

    let named: Vec<(u64, IdentityPublic)> = owners_spec()
        .ids()
        .iter()
        .map(|&id| {
            (
                id,
                if id == seat {
                    impostor.public()
                } else {
                    seat_key_of::<Owners>(id).public()
                },
            )
        })
        .collect();
    let credulous = Parties::new(
        identity_of::<Owners>().public(),
        SeatRoster::<Owners>::new(named).expect("owner ids"),
        identity_of::<Gates>().public(),
        common::seats_for::<Gates>(&gates_spec()),
    );

    let artifact = CompositionArtifact::from_parts(
        sealed,
        ComponentReveal::from_parts(swapped, pops, endorsements, salt),
        gates.reveal(&sealed),
    );
    assert_eq!(
        audit(&artifact, &credulous).unwrap_err(),
        CeremonyError::PopFailed {
            cohort: Owners::NAME,
            participant: seat,
        },
        "the honest seats' proofs were taken over a claim naming their own \
         seat-holder, so they do not verify under one that names another",
    );

    // CONTROL: the same cohort, the same shares, under a composition that seals
    // the claim they actually made. Fresh sides, because a share answers one
    // sealed composition.
    let control = honest(0x5EAA);
    audit(&control.artifact, &control.parties).expect("control: the untouched attribution audits");
}

// ---------------------------------------------------------------------------
// 4. The endorsement is checked under the FUNDER's key.
// ---------------------------------------------------------------------------

/// **A seat endorsement made by the wrong key is refused, under the key the
/// funder supplied.**
///
/// The claim here names the REAL seat-holder -- so the comparison in
/// `check_seats` passes -- and the signature beside it is by somebody else.
///
/// One sentence was struck from this doc after review. It said "an audit that
/// verified under the key the artifact names would accept this", which is FALSE:
/// `check_seats` has just established that the artifact's key and the funder's
/// are equal, so the impostor's signature fails under either. What this test
/// establishes is that the signature is checked AT ALL. That the funder's copy
/// is the one passed is defence in depth and no test can distinguish it -- see
/// `check_seats`' own note.
#[test]
fn a_seat_endorsement_by_another_key_is_refused() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EAB);
    let ceremony = CeremonyId::draw("wrong signer", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);
    let sealed = SealedComposition::new(ceremony, owners.commitment, gates.commitment)
        .expect("well-formed");
    let seat = Owners::nth(1);

    // Every seat but one signs for itself; that one is signed by an impostor.
    let impostor = IdentityKey::from_seed(&[0xD3; 32]);
    let forged = endorse_with(&ceremony, &owners.claim, |id| {
        if id == seat {
            IdentityKey::from_seed(&[0xD3; 32])
        } else {
            seat_key_of::<Owners>(id)
        }
    });
    assert_ne!(
        forged.get(&seat),
        owners.endorsements.get(&seat),
        "control: the substituted signature really is a different one",
    );

    let artifact = CompositionArtifact::from_parts(
        sealed,
        ComponentReveal::from_parts(
            owners.claim.clone(),
            owners.pops(&sealed),
            forged,
            owners.salt,
        ),
        gates.reveal(&sealed),
    );
    assert_eq!(
        audit(&artifact, &parties()).unwrap_err(),
        CeremonyError::SeatEndorsementInvalid {
            cohort: Owners::NAME,
            participant: seat,
            signer: seat_key_of::<Owners>(seat).public(),
        },
    );
    let _ = impostor;

    // CONTROL: the same artifact with that one seat's own signature audits.
    let h = honest(0x5EAC);
    audit(&h.artifact, &h.parties).expect("control");
}

/// A seat that endorsed nothing is refused by name, and one that is not on the
/// roster is refused by name too.
///
/// Two directions of the same rule, in one test because they share a control:
/// the untouched map.
#[test]
fn a_missing_or_stray_seat_endorsement_is_refused() {
    let h = honest(0x5EAD);

    let mut short = h.artifact.owners().seat_endorsements().clone();
    let dropped = short
        .keys()
        .next()
        .copied()
        .expect("the owner cohort has seats");
    short.remove(&dropped);
    assert_eq!(
        audit(&rebuilt_owner_endorsements(&h, short), &h.parties).unwrap_err(),
        CeremonyError::SeatEndorsementMissing {
            cohort: Owners::NAME,
            participant: dropped,
        },
    );

    let mut stray = h.artifact.owners().seat_endorsements().clone();
    stray.insert(Owners::nth(9), IdentitySignature([0; 64]));
    assert_eq!(
        audit(&rebuilt_owner_endorsements(&h, stray), &h.parties).unwrap_err(),
        CeremonyError::SeatEndorsementUnexpected {
            cohort: Owners::NAME,
            participant: Owners::nth(9),
        },
    );

    // CONTROL: the untouched map.
    audit(&h.artifact, &h.parties).expect("control");
}

/// The same artifact with a different owner endorsement map.
fn rebuilt_owner_endorsements(
    h: &Honest,
    endorsements: BTreeMap<u64, IdentitySignature>,
) -> CompositionArtifact {
    CompositionArtifact::from_parts(
        h.sealed,
        ComponentReveal::from_parts(
            h.artifact.owners().claim().clone(),
            h.artifact.owners().pops().clone(),
            endorsements,
            *h.artifact.owners().salt(),
        ),
        h.artifact.gates().clone(),
    )
}

/// **An endorsement from another ceremony does not carry into this one.**
///
/// The ceremony id is under the seat signature for the same reason it is under
/// the commitment signature: the digest a seat endorses is opaque to everyone
/// else, so without it a genuine endorsement of the same claim in some previous
/// ceremony would be reusable here.
#[test]
fn a_seat_endorsement_from_another_ceremony_does_not_carry() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EAE);
    let a = CeremonyId::draw("first", &mut rng);
    let b = CeremonyId::draw("second", &mut rng);
    assert_ne!(a, b);

    let owners = CohortSide::<Owners>::generate(&b, &owners_spec(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&b, &gates_spec(), &mut rng);
    let sealed = SealedComposition::new(b, owners.commitment, gates.commitment)
        .expect("well-formed");

    // Genuine signatures by the genuine seat-holders -- over ceremony A.
    let stale = endorse_with(&a, &owners.claim, seat_key_of::<Owners>);

    let artifact = CompositionArtifact::from_parts(
        sealed,
        ComponentReveal::from_parts(
            owners.claim.clone(),
            owners.pops(&sealed),
            stale,
            owners.salt,
        ),
        gates.reveal(&sealed),
    );
    assert_eq!(
        audit(&artifact, &parties()).unwrap_err(),
        CeremonyError::SeatEndorsementInvalid {
            cohort: Owners::NAME,
            participant: Owners::nth(0),
            signer: seat_key_of::<Owners>(Owners::nth(0)).public(),
        },
    );

    // CONTROL: the same signatures over ceremony B, which is where they belong.
    let fresh = endorse_with(&b, &owners.claim, seat_key_of::<Owners>);
    let ok = CompositionArtifact::from_parts(
        sealed,
        ComponentReveal::from_parts(owners.claim.clone(), owners.pops(&sealed), fresh, owners.salt),
        gates.reveal(&sealed),
    );
    audit(&ok, &parties()).expect("control: the same seats, this ceremony");
}

/// **A seat endorsement does not carry from one claim to another in the same
/// ceremony.**
///
/// The endorsement names the whole claim, not just the seat and its
/// verification share. Without that, a coordinator could keep an honest seat's
/// signature and re-seal it beside a different threshold, component or set of
/// peers -- the seat would be recorded as standing behind a cohort it never saw.
///
/// The commitment is re-sealed over the altered claim, so the commitment check
/// cannot fire; and the seat KEYS are untouched, so the comparison in
/// `check_seats` cannot fire either. What is left is the signature.
///
/// Not fully isolated, and review was right to say so: the reused proofs of
/// possession name the old claim too, so they would fail as well if the audit
/// got that far. `check_seats` runs before `check_pops`, so the reported error
/// is the signature. What this establishes is that the endorsement is
/// claim-bound AND that a claim-bound failure is reported at the seat layer;
/// the mutation that removes `claim_digest` from the payload is caught here
/// because it turns this into `PopFailed`.
#[test]
fn a_seat_endorsement_does_not_carry_to_a_different_claim() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EB9);
    let ceremony = CeremonyId::draw("endorsement is claim-bound", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);

    // The same seats, the same shares, the same component -- one integer apart.
    let inflated = ComponentClaim::from_parts(
        owners.claim.cohort(),
        owners.claim.threshold() + 1,
        owners.claim.roster().to_vec(),
        owners.claim.component(),
        owners.claim.verification_shares().to_vec(),
        owners.claim.seat_keys().to_vec(),
    );
    let salt = [0x88; 32];
    let signed = seal_and_sign::<Owners>(&ceremony, &inflated, &salt);
    let sealed = SealedComposition::new(ceremony, signed, gates.commitment).expect("well-formed");

    let artifact = CompositionArtifact::from_parts(
        sealed,
        ComponentReveal::from_parts(
            inflated,
            owners.pops(&sealed),
            // The seats' genuine signatures -- over the claim they really made.
            owners.endorsements.clone(),
            salt,
        ),
        gates.reveal(&sealed),
    );
    assert_eq!(
        audit(&artifact, &parties()).unwrap_err(),
        CeremonyError::SeatEndorsementInvalid {
            cohort: Owners::NAME,
            participant: Owners::nth(0),
            signer: seat_key_of::<Owners>(Owners::nth(0)).public(),
        },
        "a seat's endorsement is a statement about the whole claim, so it does \
         not follow the seat into another one",
    );

    // CONTROL: those same signatures under the claim they were made over.
    let h = honest(0x5EBA);
    audit(&h.artifact, &h.parties).expect("control");
}

// ---------------------------------------------------------------------------
// 5. The funder's seat roster.
// ---------------------------------------------------------------------------

/// **A funder that has no key for a seat is refused, and so is one that names a
/// seat the artifact does not have.**
///
/// Both directions are needed. Without the first, a seat nobody vouches for is
/// admitted -- which is exactly where a dealer's extra hat would sit. Without
/// the second, a funder that believes it is auditing four seats can be handed a
/// pass over three.
#[test]
fn a_funder_seat_roster_that_does_not_match_the_artifact_is_refused() {
    let h = honest(0x5EAF);
    let spec = owners_spec();
    let ids = spec.ids();

    let short = Parties::new(
        identity_of::<Owners>().public(),
        SeatRoster::<Owners>::new(
            ids[..2]
                .iter()
                .map(|&id| (id, seat_key_of::<Owners>(id).public())),
        )
        .expect("two owner ids"),
        identity_of::<Gates>().public(),
        common::seats_for::<Gates>(&gates_spec()),
    );
    assert_eq!(
        audit(&h.artifact, &short).unwrap_err(),
        CeremonyError::SeatMissing {
            cohort: Owners::NAME,
            participant: ids[2],
        },
    );

    let extra = Parties::new(
        identity_of::<Owners>().public(),
        SeatRoster::<Owners>::new(
            ids.iter()
                .chain([Owners::nth(9)].iter())
                .map(|&id| (id, seat_key_of::<Owners>(id).public())),
        )
        .expect("four owner ids"),
        identity_of::<Gates>().public(),
        common::seats_for::<Gates>(&gates_spec()),
    );
    assert_eq!(
        audit(&h.artifact, &extra).unwrap_err(),
        CeremonyError::SeatNotOnRoster {
            cohort: Owners::NAME,
            participant: Owners::nth(9),
        },
    );

    // CONTROL: the roster that matches.
    audit(&h.artifact, &h.parties).expect("control");
}

/// **A seat roster larger than the audit will enumerate is refused at
/// construction.**
///
/// `Parties::check_distinct` is quadratic in the total seat count and runs at
/// the top of `audit`, BEFORE the artifact's own `RosterTooLargeToAudit` is
/// reached -- so without a cap on the INPUT a `Parties` assembled from untrusted
/// bytes imposes an unbounded allocation and an `n^2` scan on an auditor before
/// any refusal. Review found this; the first version claimed the bound in a
/// comment and enforced it nowhere.
///
/// The CONTROL is the largest roster that is allowed, which is built.
///
/// The `n` in the refusal is also checked at TWO input sizes, because the first
/// version reported the constant `MAX_AUDITED_ROSTER + 1` whatever it was
/// handed: with only the one-over case tested, a diagnostic that never measures
/// anything passes. A 100-seat input reported as 17 sends whoever is reading the
/// error looking for a roster that does not exist.
#[test]
fn a_seat_roster_past_the_audit_limit_is_refused() {
    let over = MAX_AUDITED_ROSTER + 1;
    let roster = |n: usize| {
        SeatRoster::<Owners>::new(
            (0..n as u64).map(|k| (Owners::nth(k), seat_key_of::<Owners>(Owners::nth(k)).public())),
        )
    };
    assert_eq!(
        roster(over).unwrap_err(),
        CeremonyError::RosterTooLargeToAudit {
            cohort: Owners::NAME,
            n: over,
        },
    );

    // Far over, and the count must follow the input rather than the cap.
    assert_eq!(
        roster(100).unwrap_err(),
        CeremonyError::RosterTooLargeToAudit {
            cohort: Owners::NAME,
            n: 100,
        },
    );

    // CONTROL: exactly at the limit.
    assert_eq!(
        SeatRoster::<Owners>::new((0..MAX_AUDITED_ROSTER as u64).map(|k| (
            Owners::nth(k),
            seat_key_of::<Owners>(Owners::nth(k)).public()
        )))
        .expect("at the limit")
        .len(),
        MAX_AUDITED_ROSTER,
    );
}

/// **Two seats named by one key are refused, across the two cohorts as well as
/// within one.**
///
/// The cross-cohort case is the expensive one and the reason the check does not
/// live on `SeatRoster`: an owner seat and the gate seat named with one key is a
/// spend one principal short of the decided `COMPROMISE_THRESHOLD`.
///
/// An earlier version of this doc added "and every other check in the module
/// passes on it", which review refused and was right to. The artifact under test
/// is honest and claims four distinct keys, so without this guard the run
/// reaches `SeatUnexpected` instead -- a refusal, just an unhelpful one. What
/// the guard buys is that the funder is told its own INPUT is degenerate, which
/// is the actionable report, rather than being told the artifact disagrees with
/// a roster the funder should not have assembled. Same argument, and the same
/// placement, as `PartiesNotDistinct`.
#[test]
fn two_seats_with_one_key_are_refused() {
    let h = honest(0x5EB0);
    let shared = seat_key_of::<Owners>(Owners::nth(0)).public();

    // Across the cohorts: the gate seat is the same party as owner seat 1.
    let collapsed = Parties::new(
        identity_of::<Owners>().public(),
        common::seats_for::<Owners>(&owners_spec()),
        identity_of::<Gates>().public(),
        SeatRoster::<Gates>::new([(Gates::nth(0), shared)]).expect("one gate seat"),
    );
    assert_eq!(
        audit(&h.artifact, &collapsed).unwrap_err(),
        CeremonyError::SeatKeysNotDistinct {
            a_cohort: Owners::NAME,
            a: Owners::nth(0),
            b_cohort: Gates::NAME,
            b: Gates::nth(0),
            key: shared,
        },
    );

    // Within one cohort: two owner seats, one party.
    let doubled = Parties::new(
        identity_of::<Owners>().public(),
        SeatRoster::<Owners>::new(
            owners_spec()
                .ids()
                .iter()
                .map(|&id| (id, if id == Owners::nth(1) { shared } else { seat_key_of::<Owners>(id).public() })),
        )
        .expect("owner ids"),
        identity_of::<Gates>().public(),
        common::seats_for::<Gates>(&gates_spec()),
    );
    assert_eq!(
        audit(&h.artifact, &doubled).unwrap_err(),
        CeremonyError::SeatKeysNotDistinct {
            a_cohort: Owners::NAME,
            a: Owners::nth(0),
            b_cohort: Owners::NAME,
            b: Owners::nth(1),
            key: shared,
        },
    );

    // CONTROL: four distinct keys.
    audit(&h.artifact, &h.parties).expect("control");
}

/// A claim carrying a different number of seat keys than roster members is
/// refused before anything indexes into them -- in BOTH directions.
///
/// The surplus half is not symmetry for its own sake: review pointed out that a
/// shortage-only test is satisfied by a regression that accepts extra keys, and
/// extra keys are the direction in which a claim can carry an attribution
/// nothing on the roster answers for.
#[test]
fn a_claim_with_the_wrong_number_of_seat_keys_is_refused() {
    let h = honest(0x5EB1);
    let claim = h.artifact.owners().claim();
    let with_seat_keys = |keys: Vec<IdentityPublic>| {
        CompositionArtifact::from_parts(
            h.sealed,
            ComponentReveal::from_parts(
                ComponentClaim::from_parts(
                    claim.cohort(),
                    claim.threshold(),
                    claim.roster().to_vec(),
                    claim.component(),
                    claim.verification_shares().to_vec(),
                    keys,
                ),
                h.artifact.owners().pops().clone(),
                h.artifact.owners().seat_endorsements().clone(),
                *h.artifact.owners().salt(),
            ),
            h.artifact.gates().clone(),
        )
    };

    assert_eq!(
        audit(&with_seat_keys(claim.seat_keys()[..2].to_vec()), &h.parties).unwrap_err(),
        CeremonyError::MalformedSeatKeys {
            cohort: Owners::NAME,
            roster: 3,
            seat_keys: 2,
        },
    );

    let mut surplus = claim.seat_keys().to_vec();
    surplus.push(IdentityKey::from_seed(&[0xD8; 32]).public());
    assert_eq!(
        audit(&with_seat_keys(surplus), &h.parties).unwrap_err(),
        CeremonyError::MalformedSeatKeys {
            cohort: Owners::NAME,
            roster: 3,
            seat_keys: 4,
        },
    );

    audit(&h.artifact, &h.parties).expect("control");
}

/// The same rule at the OTHER public entry point.
///
/// `ComponentReveal::assemble` does not run `check_shape`, so it carries its own
/// seat-key length guard; without it the endorsement loop indexes a short vector
/// and panics from safe public API. `composition.rs`'s mismatched-lengths test
/// exercises both entry points for the same reason.
///
/// The proofs here are made over the SHORT claim, so `check_pops` -- which runs
/// first inside `assemble` -- passes and the length guard is what refuses it.
/// Hand-made secrets, because a DKG's shares cannot be re-proved against a claim
/// that is not their own.
#[test]
fn assemble_refuses_a_short_seat_key_vector_rather_than_indexing_it() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EBD);
    let ceremony = CeremonyId::draw("assemble bounds", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);

    let roster = vec![Gates::nth(0), Gates::nth(1)];
    let secrets: Vec<Scalar> = (0..2).map(|_| Scalar::random(&mut rng)).collect();
    let short = ComponentClaim::from_parts(
        "gates",
        2,
        roster.clone(),
        secrets[0] * G,
        secrets.iter().map(|s| s * G).collect(),
        // One seat key for two seats.
        seat_keys_over::<Gates>(&roster[..1]),
    );
    let sealed = SealedComposition::new(
        ceremony,
        owners.commitment,
        seal_and_sign::<Gates>(&ceremony, &short, &[0x51; 32]),
    )
    .expect("well-formed");

    let pops: BTreeMap<u64, two_cohort::Pop> = roster
        .iter()
        .enumerate()
        .map(|(i, &id)| {
            (
                id,
                two_cohort::Pop::prove_unchecked(&sealed, &short, id, &secrets[i])
                    .expect("opens its own"),
            )
        })
        .collect();

    assert_eq!(
        ComponentReveal::assemble(&sealed, short, pops, BTreeMap::new(), [0x51; 32]).unwrap_err(),
        CeremonyError::MalformedSeatKeys {
            cohort: Gates::NAME,
            roster: 2,
            seat_keys: 1,
        },
    );
}

/// **The GATE cohort's seats are checked too.**
///
/// `check_seats` is generic over the control domain and `check_side` calls it
/// once per cohort, so this looks like it must hold -- but "looks like it must
/// hold" is how a per-cohort arm goes missing. Review pointed out that every
/// other negative test in this file mutates the OWNER side, so removing the gate
/// call would leave them all passing.
///
/// Both gate-side refusals, with the honest artifact as the control.
#[test]
fn the_gate_cohorts_seats_are_attributed_and_endorsed_too() {
    let h = honest(0x5EBC);
    let gate_seat = Gates::nth(0);
    let stranger = IdentityKey::from_seed(&[0xD9; 32]);

    // The funder was given a different key for the gate seat than the artifact
    // claims.
    let elsewhere = Parties::new(
        identity_of::<Owners>().public(),
        common::seats_for::<Owners>(&owners_spec()),
        identity_of::<Gates>().public(),
        SeatRoster::<Gates>::new([(gate_seat, stranger.public())]).expect("one gate seat"),
    );
    assert_eq!(
        audit(&h.artifact, &elsewhere).unwrap_err(),
        CeremonyError::SeatUnexpected {
            cohort: Gates::NAME,
            participant: gate_seat,
            expected: stranger.public(),
            found: seat_key_of::<Gates>(gate_seat).public(),
        },
    );

    // The gate seat's endorsement is somebody else's signature. Made over the
    // right message, by the wrong key, so what refuses it is the verification
    // and not the shape.
    let forged = endorse_with(&h.ceremony, h.artifact.gates().claim(), |_| {
        IdentityKey::from_seed(&[0xD9; 32])
    });
    let artifact = CompositionArtifact::from_parts(
        h.sealed,
        h.artifact.owners().clone(),
        ComponentReveal::from_parts(
            h.artifact.gates().claim().clone(),
            h.artifact.gates().pops().clone(),
            forged,
            *h.artifact.gates().salt(),
        ),
    );
    assert_eq!(
        audit(&artifact, &h.parties).unwrap_err(),
        CeremonyError::SeatEndorsementInvalid {
            cohort: Gates::NAME,
            participant: gate_seat,
            signer: seat_key_of::<Gates>(gate_seat).public(),
        },
    );

    audit(&h.artifact, &h.parties).expect("control");
}

// ---------------------------------------------------------------------------
// 6. The holder's side.
// ---------------------------------------------------------------------------

/// **A holder refuses to endorse a seat the claim attributes to another key, and
/// refuses a claim that is not its own key generation's.**
///
/// The seat-level twin of `Pop::prove_for`'s checks, and it matters for the same
/// reason: the deployment shape is a coordinator assembling the claim and each
/// holder signing it, which is safe only if each holder looks at what it is
/// signing. Neither refusal is a capability boundary -- `tests/forgery.rs` signs
/// the message directly -- and what they change is what an honest holder's
/// software does by default.
#[test]
fn a_holder_refuses_to_endorse_a_seat_that_is_not_its_own() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EB2);
    let ceremony = CeremonyId::draw("holder endorsement", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    let share = &owners.shares[0];

    // CONTROL: its own claim, its own key.
    share
        .endorse(&ceremony, &owners.claim, &seat_key_of::<Owners>(share.id()))
        .expect("control: the holder signs for its own seat");

    // The claim is its own; the KEY is not the one the claim names for it.
    let stranger = IdentityKey::from_seed(&[0xD4; 32]);
    assert_eq!(
        share
            .endorse(&ceremony, &owners.claim, &stranger)
            .unwrap_err(),
        CeremonyError::SeatKeyNotOwn {
            cohort: Owners::NAME,
            participant: share.id(),
        },
    );

    // The key is its own; the CLAIM is not.
    let elsewhere = reattributed(&owners.claim, Owners::nth(1), stranger.public());
    assert_eq!(
        share
            .endorse(&ceremony, &elsewhere, &seat_key_of::<Owners>(share.id()))
            .unwrap_err(),
        CeremonyError::ClaimNotOwn {
            cohort: Owners::NAME,
            participant: share.id(),
        },
        "a coordinator that re-attributes a PEER's seat does not get this \
         holder's signature over its version either",
    );
}

/// **A holder refuses to PROVE under a claim that re-attributes any seat.**
///
/// The seat keys are inside `ComponentClaim`, so `Pop::prove_for`'s existing
/// "this is not my own key generation's claim" check covers them without a new
/// arm. Asserted rather than assumed, because it is the reason a coordinator
/// cannot collect honest proofs over a re-attributed roster in the first place.
#[test]
fn a_holder_refuses_to_prove_under_a_re_attributed_claim() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EB3);
    let ceremony = CeremonyId::draw("holder proving", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);
    let sealed = SealedComposition::new(ceremony, owners.commitment, gates.commitment)
        .expect("well-formed");
    let share = &owners.shares[0];

    let stranger = IdentityKey::from_seed(&[0xD5; 32]);
    let swapped = reattributed(&owners.claim, Owners::nth(2), stranger.public());
    assert_eq!(
        share.prove(&sealed, &swapped, &owners.salt).unwrap_err(),
        CeremonyError::ClaimNotOwn {
            cohort: Owners::NAME,
            participant: share.id(),
        },
    );
    assert_eq!(
        share.proved_under(),
        None,
        "a refused claim does not spend the share's one proof"
    );

    // CONTROL: its own claim is proved.
    share
        .prove(&sealed, &owners.claim, &owners.salt)
        .expect("control");
}

/// The DKG will not run over a seat roster that is not its participant roster.
///
/// Refused before any key exists, because a `CohortKey` whose two rosters
/// disagreed could not produce a well-formed claim at all.
#[test]
fn the_dkg_refuses_a_seat_roster_that_is_not_its_participant_roster() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EB4);
    let ceremony = CeremonyId::draw("mismatched seats", &mut rng);
    let spec = owners_spec();
    let two = SeatRoster::<Owners>::new(
        spec.ids()[..2]
            .iter()
            .map(|&id| (id, seat_key_of::<Owners>(id).public())),
    )
    .expect("two owner ids");

    assert_eq!(
        two_cohort::dkg::run_dkg::<Owners, _>(&ceremony, &spec, &two, &mut rng).unwrap_err(),
        two_cohort::DkgError::SeatRosterMismatch {
            cohort: Owners::NAME,
            roster: spec.ids().to_vec(),
            seats: two.ids(),
        },
    );

    // CONTROL: the matching roster runs.
    two_cohort::dkg::run_dkg::<Owners, _>(
        &ceremony,
        &spec,
        &common::seats_for::<Owners>(&spec),
        &mut rng,
    )
    .expect("control");
}

/// **One nonce does not answer two claims that differ only in WHO holds a seat.**
///
/// `Pop::prove` derives its nonce deterministically, which is safe only if every
/// independent input to the CHALLENGE is absorbed into the nonce too. The seat
/// keys are now such an input. If they had been added to `pop_challenge` alone,
/// a holder induced to prove under two claims differing only in a peer's seat
/// attribution -- which no holder can check without re-running someone else's
/// key generation -- would emit one `R` against two challenges, and its share
/// falls out as `(z - z')/(c - c')`.
///
/// Both hashes call `absorb_claim`, which is what makes the divergence
/// unwritable; this is the assertion that the property holds today. The CONTROL
/// is that determinism itself is intact, so what moves the nonce is the
/// attribution and not a fresh random draw.
#[test]
fn one_nonce_does_not_answer_two_differently_attributed_claims() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EBB);
    let ceremony = CeremonyId::draw("nonce binding to seats", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);

    // Raw secrets, so `Pop::prove_unchecked` can be called twice: the one-proof
    // rule lives on `CohortShare` and would stop the second call first.
    let roster = vec![Gates::nth(0), Gates::nth(1)];
    let secrets: Vec<Scalar> = (0..2).map(|_| Scalar::random(&mut rng)).collect();
    let claim_a = ComponentClaim::from_parts(
        "gates",
        2,
        roster.clone(),
        secrets[0] * G, // any point; the nonce derivation does not check it
        secrets.iter().map(|s| s * G).collect(),
        seat_keys_over::<Gates>(&roster),
    );
    // Identical except for a PEER's seat identity -- seat 1's, while the prover
    // is seat 0.
    let stranger = IdentityKey::from_seed(&[0xD7; 32]);
    let claim_b = reattributed(&claim_a, roster[1], stranger.public());
    assert_ne!(claim_a, claim_b);

    let sealed = SealedComposition::new(
        ceremony,
        owners.commitment,
        seal_and_sign::<Gates>(&ceremony, &claim_a, &[0x41; 32]),
    )
    .expect("well-formed");

    let a = two_cohort::Pop::prove_unchecked(&sealed, &claim_a, roster[0], &secrets[0])
        .expect("opens its own");
    let b = two_cohort::Pop::prove_unchecked(&sealed, &claim_b, roster[0], &secrets[0])
        .expect("opens its own");
    assert_ne!(
        a.nonce_public(),
        b.nonce_public(),
        "two attributions must not share a nonce"
    );

    // CONTROL: the same claim twice is byte-for-byte the same proof.
    assert_eq!(
        two_cohort::Pop::prove_unchecked(&sealed, &claim_a, roster[0], &secrets[0])
            .expect("again"),
        a
    );
}

// ---------------------------------------------------------------------------
// 7. The release gate.
// ---------------------------------------------------------------------------

/// **`deposit_spend_key` cannot be reached with cohort-level attribution
/// alone.**
///
/// Scoped to `deposit_spend_key` deliberately. `CompositeSpend::spend_public`
/// and `AuditedAddress::spend_public` are public and return the same key without
/// any authorisation, so "the funding path" is only closed for a deployment that
/// routes it through the gate -- which is what `production`'s module docs
/// already say, and what
/// `release_gate.rs::a_simulated_root_reaches_the_funding_path_today` performs
/// for the provenance arm. Review corrected an earlier version of this sentence
/// that claimed the whole funding path.
///
/// The spend carries the `Parties` its audit ran against -- now including the
/// seats -- and `authorize_release` compares them against the ones the
/// deployment names. Both organisation keys match in every case below, so the
/// pre-existing endorser arm passes and each refusal is attributable to the seat
/// arm. BOTH cohorts' seat arms are exercised: a gate-only regression would
/// otherwise leave an owner-only test passing.
///
/// The CONTROL is the same spend against the seats it was actually audited
/// under, which is authorised.
#[test]
fn the_release_gate_refuses_a_spend_audited_under_other_seat_keys() {
    use two_cohort::{
        audit_address,
        production::{authorize_release, ReleaseRefused},
        CompositeSpend,
    };

    let mut rng = ChaCha20Rng::seed_from_u64(0x5EB5);
    let h = Honest::run(
        0x5EB6,
        &two_cohort::production::owners(),
        &two_cohort::production::gates(),
    );
    let d = h.spend_public();
    let address = audit_address(&h.artifact, &h.parties, &h.view, common::SUBADDRESS, &d)
        .expect("audits");
    let spend = CompositeSpend::from_ceremony(&address, &h.view, &h.tx_public()).expect("built");
    let _ = &mut rng;

    // CONTROL: the seats it was audited under.
    authorize_release(&spend, &h.parties).expect("control: the seats this deployment named");

    let stranger = IdentityKey::from_seed(&[0xD6; 32]);
    let seat = Owners::nth(1);
    let elsewhere = Parties::new(
        identity_of::<Owners>().public(),
        SeatRoster::<Owners>::new(two_cohort::production::owners().ids().iter().map(|&id| {
            (
                id,
                if id == seat {
                    stranger.public()
                } else {
                    seat_key_of::<Owners>(id).public()
                },
            )
        }))
        .expect("owner ids"),
        identity_of::<Gates>().public(),
        common::seats_for::<Gates>(&two_cohort::production::gates()),
    );
    assert_eq!(
        authorize_release(&spend, &elsewhere).unwrap_err(),
        ReleaseRefused::Seat {
            cohort: Owners::NAME,
            participant: seat,
            expected: stranger.public(),
            found: seat_key_of::<Owners>(seat).public(),
        },
    );

    // A deployment naming a different NUMBER of seats is a different incident,
    // reported as itself rather than as the first key that differs.
    let fewer = Parties::new(
        identity_of::<Owners>().public(),
        SeatRoster::<Owners>::new(
            two_cohort::production::owners().ids()[..2]
                .iter()
                .map(|&id| (id, seat_key_of::<Owners>(id).public())),
        )
        .expect("two owner ids"),
        identity_of::<Gates>().public(),
        common::seats_for::<Gates>(&two_cohort::production::gates()),
    );
    assert_eq!(
        authorize_release(&spend, &fewer).unwrap_err(),
        ReleaseRefused::SeatRoster {
            cohort: Owners::NAME,
            expected: two_cohort::production::owners().ids()[..2].to_vec(),
            found: two_cohort::production::owners().ids().to_vec(),
        },
    );

    // The GATE arm, with the owner seats left correct so it is the only thing
    // that can fire.
    let gate_seat = Gates::nth(0);
    let gate_elsewhere = Parties::new(
        identity_of::<Owners>().public(),
        common::seats_for::<Owners>(&two_cohort::production::owners()),
        identity_of::<Gates>().public(),
        SeatRoster::<Gates>::new([(gate_seat, stranger.public())]).expect("one gate seat"),
    );
    assert_eq!(
        authorize_release(&spend, &gate_elsewhere).unwrap_err(),
        ReleaseRefused::Seat {
            cohort: Gates::NAME,
            participant: gate_seat,
            expected: stranger.public(),
            found: seat_key_of::<Gates>(gate_seat).public(),
        },
    );
}

// ---------------------------------------------------------------------------
// 8. The residual, performed.
// ---------------------------------------------------------------------------

/// **THE RESIDUAL THAT MATTERS, and it is cheaper for the attacker than the one
/// below.**
///
/// A dealer runs no DKG for the OWNER cohort, deals every owner share to itself,
/// and keeps them. It does NOT hold the seat-holders' identity private keys and
/// never asks for them. It writes the three genuine owner seat keys into its
/// claim, produces every owner proof of possession itself -- it knows every
/// share -- and asks each named party for one signature over
/// [`seat_endorsement_message`], which is public bytes that reveal no secret and
/// cost the signer nothing.
///
/// **What this test asserts is that the artifact AUDITS**, and that the dealer
/// knows the discrete log of the whole owner component. It stops there: it does
/// not call `check_decided_structure` or `authorize_release`. The end-to-end
/// half -- audit, decided-structure check, release gate, `deposit_spend_key`,
/// and an output opened by two principals -- is
/// `seat_forgery.rs::a_seat_holder_with_a_real_share_endorses_a_substituted_dealing_and_it_audits`.
/// This doc said "reaches the release gate" of a test that never calls it, and
/// review caught it.
///
/// **This was missed in the first version of this work and an adversarial review
/// found it.** `tests/forgery.rs` claimed a dealer had exactly two options for
/// its seat keys -- its own, or the real holders' public keys with signatures it
/// cannot make -- and "no third option". This is the third: the real holders'
/// public keys with signatures they really made, about a cohort they were never
/// dealt into.
///
/// So the precise statement of what a seat endorsement buys is:
///
/// > seat `i`'s named key signed a statement naming `V_i` and this claim.
///
/// and NOT:
///
/// > seat `i`'s named party holds a share behind `V_i`.
///
/// The proof of possession says a share exists; the endorsement says a named key
/// signed; nothing in the artifact binds those to one actor. What the bar became
/// is the number of DISTINCT SIGNATURES a forgery needs, and the arithmetic is
/// per FORGERY, not per artifact -- review found this line inflating it:
///
///   * THIS test, which forges the owner cohort only: the owner organisation's
///     signature plus the THREE owner seats' -- four, up from one. The gate
///     cohort here is honest, so the gate organisation's signature and the gate
///     seat's endorsement are the honest gate's own and are not the forger's to
///     collect;
///   * a forgery that fabricates BOTH cohorts: six, up from two.
///
/// Either way it is a real cost -- parties must be induced to sign something --
/// and it is not custody evidence.
///
/// The CONTROL is the same dealer without those signatures, which is
/// `tests/forgery.rs::a_dealt_owner_cohort_is_refused_at_the_seat_attribution`:
/// it differs from this test in the signatures alone and is refused.
///
/// # If this test fails, it has been FIXED, not broken
///
/// It asserts that a forgery SUCCEEDS, which is the only way to keep a residual
/// measurable and is also a test that will one day go red for a good reason.
/// Binding a seat endorsement to possession of that seat's share is buildable
/// and is tracked as such in `proofs/tla/AttributionCoverage.tla`
/// (`EndorserHoldsShare`). When it is built, this test and
/// `seat_forgery.rs::a_seat_holder_with_a_real_share_endorses_a_substituted_dealing_and_it_audits`
/// fail together. Replace them with the refusal, asserted by exact error. Do not
/// weaken an assertion to make either pass again.
#[test]
fn a_dealer_that_keeps_the_shares_and_collects_signatures_still_passes() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EC0);
    let ceremony = CeremonyId::draw("signatures without shares", &mut rng);
    let ids = owners_spec().ids().to_vec();

    // The dealer's own secret, and a dealing of it to itself.
    let b_owner = Scalar::random(&mut rng);
    let dealt = two_cohort::Cohort::deal_in::<Owners, _>(&b_owner, 2, &ids, &mut rng)
        .expect("dealt");
    let claim = ComponentClaim::from_parts(
        Owners::NAME,
        2,
        ids.clone(),
        b_owner * G,
        ids.iter()
            .map(|&id| dealt.verification_share(id).expect("on the roster"))
            .collect(),
        // The REAL seat-holders' public keys. Public data, free to copy.
        seat_keys_over::<Owners>(&ids),
    );
    let salt = [0x91; 32];
    let signed = seal_and_sign::<Owners>(&ceremony, &claim, &salt);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);
    let sealed = SealedComposition::new(ceremony, signed, gates.commitment).expect("well-formed");

    // Every proof of possession is the DEALER's: it knows every share.
    let pops: BTreeMap<u64, two_cohort::Pop> = ids
        .iter()
        .map(|&id| {
            (
                id,
                two_cohort::Pop::prove_unchecked(
                    &sealed,
                    &claim,
                    id,
                    &dealt.share(id).expect("dealt"),
                )
                .expect("the dealer holds it"),
            )
        })
        .collect();

    // Every endorsement is the named party's own. `endorse_seat` is happy,
    // because the claim really does attribute the seat to the key doing the
    // signing. No share is involved, and none of the four parties learns
    // anything by signing.
    //
    // `endorse_seat` is the UNCHECKED entry point, not the checked one -- an
    // earlier version of this comment had it the other way round. The checked
    // one is `CohortShare::endorse`, and it is unavailable here for a reason
    // that is part of the residual rather than a fixture detail: these parties
    // hold no share, so there is no `CohortShare` to call it on. What makes the
    // residual sharper than that reading suggests is
    // `tests/seat_forgery.rs::a_seat_holder_with_a_real_share_endorses_a_substituted_dealing_and_it_audits`,
    // where the parties DO hold real shares, `CohortShare::endorse` refuses, and
    // `endorse_seat` signs anyway.
    let endorsements: BTreeMap<u64, IdentitySignature> = ids
        .iter()
        .map(|&id| {
            (
                id,
                endorse_seat(&ceremony, &claim, id, &seat_key_of::<Owners>(id))
                    .expect("the named party signs for its own seat"),
            )
        })
        .collect();

    let artifact = CompositionArtifact::from_parts(
        sealed,
        ComponentReveal::from_parts(claim, pops, endorsements, salt),
        gates.reveal(&sealed),
    );

    // It audits, under the keys a funder collected from the real parties.
    //
    // SCOPE, corrected after review. This forges the OWNER cohort only -- the
    // gate cohort is honest here -- so the signatures the dealer had to collect
    // are the THREE owner seats', not four. The gate seat's endorsement is the
    // honest gate's own. And the assertion below is over the owner structure,
    // which has THREE seats; its message said "four", which is the artifact's
    // total across both cohorts and not what is being compared.
    let audited = audit(&artifact, &parties()).expect("this is the residual");
    let (o, _) = audited.structure();
    assert_eq!(
        o.seats(),
        ids.iter()
            .map(|&id| (id, seat_key_of::<Owners>(id).public()))
            .collect::<Vec<_>>(),
        "the funder is told the three real parties hold the three owner seats",
    );
    assert_eq!(o.seats().len(), 3, "the owner cohort, not the whole artifact");

    // THE HARM: the dealer holds the discrete log of the whole owner component,
    // which no member of an honest 2-of-3 cohort does. The three named parties
    // hold nothing at all.
    assert_eq!(o.component(), b_owner * G);
    for &id in &ids {
        assert_ne!(
            o.component(),
            artifact
                .owners()
                .claim()
                .verification_share(id)
                .expect("on the roster"),
            "the dealing is a real 2-of-3, so this is not a degenerate shape the \
             threshold checks would have caught",
        );
    }
}

/// **A party holding all four seat keys produces an artifact that audits, while
/// holding every share of both cohorts.**
///
/// The exact limit of what per-seat identity buys, performed rather than
/// described, for the reason `tests/attribution.rs`'s last test performs the
/// two-organisation residual: a limitation nobody has executed is a limitation
/// nobody has measured.
///
/// What a funder gets is a change in what it must trust -- from "two
/// organisations endorsed this" to "four named parties each signed for their own
/// seat" -- and the thing it must still establish out of band is that those four
/// parties are four independent principals. Key custody is a question a funder
/// can put to a party. Bare bytes were not.
///
/// # If this test fails, it has been FIXED, not broken
///
/// Like the one above it asserts a forgery SUCCEEDS. Unlike the one above,
/// nobody knows how to close this one: "four keys are four entities" is
/// `MaxKeysPerPrincipal` in `proofs/tla/AttributionCoverage.tla`, which is a
/// fact about the world and not about this crate. So a red here almost
/// certainly means an unrelated change broke artifact construction, not that
/// the residual is gone -- check that before rewriting anything.
#[test]
fn the_residual_is_a_party_that_holds_every_seat_key() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EB7);
    let ceremony = CeremonyId::draw("all four seats, one hand", &mut rng);

    // One process runs both DKGs and holds all four seat keys. The seat keys
    // here are the fixture's own, so this really is the honest artifact -- which
    // is the finding: nothing distinguishes it from four parties.
    let h = honest(0x5EB8);
    let audited = audit(&h.artifact, &h.parties).expect("it audits");

    // The harm: the sole party interpolates both cohorts and holds the discrete
    // log of the root the audit reports.
    let oq: Vec<u64> = h.owners.shares.iter().take(2).map(|s| s.id()).collect();
    let b_owner: Scalar = oq
        .iter()
        .map(|&id| *h.owners.share_of(id).term(&oq).expect("quorum").weight())
        .sum();
    let gq: Vec<u64> = h.gates.shares.iter().take(1).map(|s| s.id()).collect();
    let b_gate: Scalar = gq
        .iter()
        .map(|&id| *h.gates.share_of(id).term(&gq).expect("quorum").weight())
        .sum();
    assert_eq!(
        (b_owner + b_gate) * G,
        audited.root(),
        "one process, one root scalar, four seats that audit cleanly",
    );

    // And the four seat keys the audit reports are four DISTINCT keys, which is
    // all the check ever claimed.
    let (o, g) = audited.structure();
    let keys: Vec<IdentityPublic> = o.seats().iter().chain(g.seats()).map(|&(_, k)| k).collect();
    // The length assertion is not decoration: without it an empty or partial
    // `seats()` satisfies the distinctness loop vacuously, which review caught.
    assert_eq!(keys.len(), production_seat_count());
    for (i, k) in keys.iter().enumerate() {
        assert!(!keys[..i].contains(k));
    }
    let _ = (ceremony, seat_keys_over::<Owners>(owners_spec().ids()));
}
