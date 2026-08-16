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
//!     about something else, so a refusal is never the endorsement check
//!     standing in for the check under test. That got harder, and better, when
//!     the endorsement became a linked proof: a fixture can no longer produce
//!     one from public data, so every test that endorses is driving a party that
//!     really holds the share -- see `common::own_share_scalar`.
//!
//! What none of it establishes: that four keys are four entities, and that the
//! party that endorses a seat is the only holder of its share. The last two
//! tests in this file perform those two residuals rather than describing them --
//! `a_dealer_that_dealt_real_shares_and_kept_copies_still_passes` and
//! `the_residual_is_a_party_that_holds_every_seat_key`. The one BETWEEN them and
//! the rest, `a_dealer_that_keeps_the_shares_is_refused_at_the_seat_endorsement`,
//! used to be a third residual and is now a refusal. See
//! `two_cohort::ceremony`'s module docs.

mod common;

use std::collections::BTreeMap;

use common::{
    identity_of, own_share_scalar, parties_over, seat_key_of, seat_keys_over, seal_and_sign,
    CohortSide, Honest,
};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, scalar::Scalar};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use two_cohort::{
    audit,
    ceremony::{
        endorse_seat, endorse_seat_unchecked, ComponentClaim, ComponentCommitment, ComponentReveal,
        SealedComposition, SeatEndorsement, SeatRoster, MAX_AUDITED_ROSTER,
    },
    identity::{IdentityKey, IdentityPublic},
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

/// Endorsements that VERIFY against whatever `claim` says, made with the key and
/// the share the caller supplies per seat.
///
/// `endorse_seat_unchecked` rather than `endorse_seat`, for `tests/forgery.rs`'s
/// reason: the checked entry point refuses to endorse a seat attributed to
/// somebody else, which protects an honest holder and constrains nobody who
/// holds a key. The SHARE check is not skipped and cannot be -- a proof taken
/// with a scalar that does not open `V_i` does not verify, so a caller here must
/// supply the real one, which is why every call site below has a share-holder
/// behind it.
fn endorse_with(
    ceremony: &CeremonyId,
    claim: &ComponentClaim,
    key_of: impl Fn(u64) -> IdentityKey,
    secret_of: impl Fn(u64) -> Scalar,
) -> BTreeMap<u64, SeatEndorsement> {
    claim
        .roster()
        .iter()
        .map(|&id| {
            (
                id,
                endorse_seat_unchecked(ceremony, claim, id, &key_of(id), &secret_of(id))
                    .expect("the caller supplies a share that opens this seat's own V_i"),
            )
        })
        .collect()
}

/// A seat endorsement that is not one: four values off the wire that no witness
/// produced.
///
/// `SeatEndorsement::from_parts` is public for exactly this, and an attacker is
/// not restricted to the crate's provers. Used where a test needs the SHAPE of an
/// endorsement and not a valid one.
fn junk_endorsement(tag: u8) -> SeatEndorsement {
    SeatEndorsement::from_parts(
        [tag; 32],
        Scalar::from(u64::from(tag) + 1) * G,
        Scalar::from(u64::from(tag) + 2),
        Scalar::from(u64::from(tag) + 3),
    )
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
    let endorsements = endorse_with(
        &ceremony,
        &swapped,
        |id| {
            if id == seat {
                IdentityKey::from_seed(&[0xD2; 32])
            } else {
                seat_key_of::<Owners>(id)
            }
        },
        // The real shares: the re-attribution leaves every `V_i` alone, so the
        // honest holders' own scalars still open them and every endorsement here
        // VERIFIES. Without that the refusal below could be the endorsement
        // check standing in for the proof check.
        |id| own_share_scalar(&owners, id),
    );

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

/// **BOTH halves of the linked endorsement are checked, and each one on its
/// own.**
///
/// The endorsement is an AND-composition: one challenge over two commitments,
/// two responses. An audit that verified only the identity equation would accept
/// an endorsement made without the share -- which is the Ed25519 signature this
/// replaced, and the two forgeries it admitted. An audit that verified only the
/// share equation would accept one made without the identity key, which is the
/// dealer that holds every share.
///
/// Both are performed on a GENUINE endorsement with one response perturbed, so
/// nothing else about the artifact changes and the two mutations differ from the
/// control in one scalar each. Perturbing a response leaves the challenge alone
/// -- `c` is a function of the two COMMITMENTS and the transcript -- so the other
/// equation still holds, and each half is therefore tested in isolation.
///
/// The CONTROL is the untouched endorsement in the same artifact, which audits.
#[test]
fn each_half_of_the_linked_endorsement_is_checked_on_its_own() {
    let h = honest(0x5EBE);
    let seat = Owners::nth(0);
    let genuine = h
        .artifact
        .owners()
        .seat_endorsements()
        .get(&seat)
        .copied()
        .expect("the honest owner cohort endorsed every seat");

    let perturbed = |identity: Scalar, share: Scalar| {
        let mut map = h.artifact.owners().seat_endorsements().clone();
        map.insert(
            seat,
            SeatEndorsement::from_parts(
                genuine.identity_commitment(),
                genuine.share_commitment(),
                genuine.identity_response() + identity,
                genuine.share_response() + share,
            ),
        );
        rebuilt_owner_endorsements(&h, map)
    };

    // Only the SHARE response is wrong: `z_d*B == A + c*Id` still holds, so an
    // audit that checked the identity half alone would accept this.
    assert_eq!(
        audit(&perturbed(Scalar::ZERO, Scalar::ONE), &h.parties).unwrap_err(),
        CeremonyError::SeatEndorsementInvalid {
            cohort: Owners::NAME,
            participant: seat,
            signer: seat_key_of::<Owners>(seat).public(),
        },
        "the share half of the endorsement is verified",
    );

    // Only the IDENTITY response is wrong: `z_s*G == R + c*V` still holds, so an
    // audit that checked the share half alone would accept this.
    assert_eq!(
        audit(&perturbed(Scalar::ONE, Scalar::ZERO), &h.parties).unwrap_err(),
        CeremonyError::SeatEndorsementInvalid {
            cohort: Owners::NAME,
            participant: seat,
            signer: seat_key_of::<Owners>(seat).public(),
        },
        "the identity half of the endorsement is verified",
    );

    // CONTROL: the same artifact with both responses as the holder made them.
    // Rebuilt through the same helper, so the control differs from the two
    // refusals in the perturbation alone.
    audit(
        &perturbed(Scalar::ZERO, Scalar::ZERO),
        &h.parties,
    )
    .expect("control: the untouched endorsement audits");
}

/// **A perturbation that CANCELS under a summed check, and does not under two.**
///
/// The guard this protects is not a line of code -- it is the shape of
/// `SeatEndorsement::verify`, which computes two booleans and conjoins them. A
/// future edit that "simplifies" it into one equal-weight equation,
/// `z*B == A + R + c*(Id + V)` or any fixed-coefficient sum, would be satisfied
/// by knowledge of `d + s` alone and the whole linkage would be gone. Nothing in
/// the suite noticed that shape until adversarial review named it.
///
/// The exhibit is one honest endorsement with `z_d += delta` and
/// `z_s -= delta`. Each equation fails by `delta*B` and `-delta*G`
/// respectively; a fixed equal-weight sum of the two cancels them exactly.
///
/// **What this test is, labelled honestly: a TRIPWIRE, not evidence.** No
/// mutation of the current `verify` makes it fail. The two equations live in two
/// groups, `RistrettoPoint` does not expose its Edwards representative outside
/// `curve25519-dalek`, and so the dangerous shape -- one scalar checked against
/// `A + R + c*(Id + V)` -- is not expressible here in one edit. Every mutation
/// that IS expressible (drop either equation, drop either commitment from the
/// challenge) is already killed by
/// [`each_half_of_the_linked_endorsement_is_checked_on_its_own`] and
/// `seat_challenge_coverage.rs`. This test costs one artifact and would go red
/// the day someone lifts one side into the other's group to "simplify" the
/// check, which is the only way that edit gets written. The repo's standard is
/// that an unfalsified guard says so; this is it saying so.
///
/// CONTROL: `delta = 0`, the same artifact through the same helper.
#[test]
fn an_equal_weight_collapse_of_the_two_equations_is_refused() {
    let h = honest(0x5E17);
    let seat = h.owners.claim.roster()[0];
    let genuine = *h
        .artifact
        .owners()
        .seat_endorsements()
        .get(&seat)
        .expect("the honest owner cohort endorsed every seat");

    let shifted = |delta: Scalar| {
        let mut map = h.artifact.owners().seat_endorsements().clone();
        map.insert(
            seat,
            SeatEndorsement::from_parts(
                genuine.identity_commitment(),
                genuine.share_commitment(),
                genuine.identity_response() + delta,
                genuine.share_response() - delta,
            ),
        );
        rebuilt_owner_endorsements(&h, map)
    };

    assert_eq!(
        audit(&shifted(Scalar::from(7u64)), &h.parties).unwrap_err(),
        CeremonyError::SeatEndorsementInvalid {
            cohort: Owners::NAME,
            participant: seat,
            signer: seat_key_of::<Owners>(seat).public(),
        },
        "a shift that cancels in a summed check must still be refused: the two \
         equations are checked separately and neither may be collapsed into the \
         other",
    );

    // CONTROL: delta = 0 is the untouched endorsement, through the same helper.
    audit(&shifted(Scalar::ZERO), &h.parties)
        .expect("control: the untouched endorsement audits");
}

/// **A seat endorsement does not carry from one SEAT to another.**
///
/// Asserted on an honest artifact by swapping two seats' endorsements, which is
/// the smallest form of the move.
///
/// **What separates the two seats, said accurately.** Not the participant id,
/// though that is in the challenge preamble: deleting it from the preamble
/// leaves this test passing, which was checked rather than assumed. What
/// separates them is each seat's own VERIFICATION SHARE, which is in the
/// preamble and is what its half of the proof is about, and each seat's own
/// signer key. So this test establishes the property -- an endorsement is bound
/// to one seat -- without establishing that any particular field is what binds
/// it. `seat_endorsement_preamble` lists which fields are falsifiable and which
/// are not.
///
/// The CONTROL is the same artifact unswapped.
#[test]
fn a_seat_endorsement_does_not_carry_to_another_seat() {
    let h = honest(0x5EBF);
    let ids = owners_spec().ids().to_vec();
    let mut swapped = h.artifact.owners().seat_endorsements().clone();
    let first = swapped[&ids[0]];
    let second = swapped[&ids[1]];
    swapped.insert(ids[0], second);
    swapped.insert(ids[1], first);
    assert_ne!(first, second, "the two seats really made different endorsements");

    assert_eq!(
        audit(&rebuilt_owner_endorsements(&h, swapped), &h.parties).unwrap_err(),
        CeremonyError::SeatEndorsementInvalid {
            cohort: Owners::NAME,
            participant: ids[0],
            signer: seat_key_of::<Owners>(ids[0]).public(),
        },
    );

    // CONTROL: unswapped.
    audit(&h.artifact, &h.parties).expect("control");
}

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
    let forged = endorse_with(
        &ceremony,
        &owners.claim,
        |id| {
            if id == seat {
                IdentityKey::from_seed(&[0xD3; 32])
            } else {
                seat_key_of::<Owners>(id)
            }
        },
        // Every endorsement is made with the REAL share, including the
        // impostor's: the impostor is a party that got hold of the share half
        // and not the identity half, which is the only thing left for this test
        // to be about now that the endorsement covers both.
        |id| own_share_scalar(&owners, id),
    );
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
    stray.insert(Owners::nth(9), junk_endorsement(0x11));
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
    endorsements: BTreeMap<u64, SeatEndorsement>,
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
    let stale = endorse_with(&a, &owners.claim, seat_key_of::<Owners>, |id| {
        own_share_scalar(&owners, id)
    });

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
    let fresh = endorse_with(&b, &owners.claim, seat_key_of::<Owners>, |id| {
        own_share_scalar(&owners, id)
    });
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
/// `check_seat_attribution` cannot fire either. What is left is the endorsement.
///
/// **Now fully isolated, which it was not before.** The earlier version reused
/// the honest proofs of possession, which name the old claim and would have
/// failed too -- it relied on the seat checks running first to decide which
/// error was reported. Since the linked endorsement moved after `check_pops`,
/// that would report `PopFailed` and prove nothing about the endorsement, so the
/// proofs here are re-made over the INFLATED claim with the holders' own share
/// scalars. They verify, and the mutation that removes `claim_digest` from the
/// endorsement transcript is what this test catches -- measured, it is the only
/// test that fails for it.
///
/// **What it is NOT is "the endorsement is the only invalid thing here", and an
/// earlier version said that.** Inflating the threshold from 2 to 3 leaves the
/// verification shares on a degree-1 polynomial, so `check_consistency` would
/// object to this artifact as well -- with
/// [`CeremonyError::ThresholdOverstated`], from a check that runs AFTER the
/// endorsements. The exact error asserted below therefore proves the endorsement
/// check runs and refuses first; it does not prove the rest of the artifact was
/// sound. Adversarial review made that distinction and it is worth keeping.
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

    // Proofs of possession over the INFLATED claim, made with the holders' own
    // shares, so every one of them verifies and the refusal below is the
    // endorsement alone.
    let pops: BTreeMap<u64, two_cohort::Pop> = owners
        .claim
        .roster()
        .iter()
        .map(|&id| {
            (
                id,
                two_cohort::Pop::prove_unchecked(
                    &sealed,
                    &inflated,
                    id,
                    &own_share_scalar(&owners, id),
                )
                .expect("each holder's own share opens its own verification share"),
            )
        })
        .collect();

    let artifact = CompositionArtifact::from_parts(
        sealed,
        ComponentReveal::from_parts(
            inflated,
            pops,
            // The seats' genuine endorsements -- over the claim they really made.
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
///
/// **One honest limit, which adversarial review named.** The endorsement map is
/// EMPTY. So without the length guard this would not reach the out-of-bounds
/// index it is described as preventing -- it would return
/// [`CeremonyError::SeatEndorsementMissing`] from the loop's first lookup
/// instead. What the assertion below establishes is that the length disagreement
/// is reported as a length disagreement, ahead of anything else. The panic it is
/// named for is prevented by the guard, and that is reasoning, not a
/// measurement; no test in this suite can reach the index, because the guard is
/// the only thing between it and every caller.
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
    let forged = endorse_with(
        &h.ceremony,
        h.artifact.gates().claim(),
        |_| IdentityKey::from_seed(&[0xD9; 32]),
        // With the gate seat's REAL share, so the endorsement is well-formed and
        // what refuses it is whose key it was made under.
        |id| own_share_scalar(&h.gates, id),
    );
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

/// **THE FORGERY THAT NO LONGER WORKS: a dealer keeps every share and collects
/// endorsements, and there is nothing left for the named parties to give it.**
///
/// # What this test used to assert
///
/// It was `a_dealer_that_keeps_the_shares_and_collects_signatures_still_passes`
/// and it PASSED. A dealer ran no DKG for the owner cohort, dealt every share to
/// itself, wrote the three genuine seat keys into its claim, produced every
/// proof of possession itself, and asked each named party for ONE SIGNATURE over
/// public bytes that revealed no secret and cost the signer nothing. The
/// artifact audited. Its doc said that when an endorsement was bound to
/// possession of the share, this test should be replaced by the refusal,
/// asserted by exact error. This is that replacement.
///
/// # The same attack, and the two places it now dies
///
/// The dealer holds every share of its own dealing and none of the three
/// parties' identity keys. The three parties hold their identity keys and, in
/// this mounting, NO SHARE AT ALL -- they were never dealt into anything.
///
///   * **the named party has nothing to endorse with.** `endorse_seat` now takes
///     a share, and the only scalars a party in this position has are ones it
///     invented. Any of them is refused with
///     [`CeremonyError::SeatShareNotOwn`], asserted below over a scalar the party
///     picks itself. There is no scalar it could pick that would work: the
///     refusal is `share*G != V_i`, and `V_i` is the dealer's;
///   * **the dealer cannot make up the difference.** It can answer the share half
///     of every endorsement -- it holds every share -- but not the identity half,
///     and one challenge covers both. That is the CAPABILITY statement, and it is
///     why there is no artifact of the shape the dealer wants.
///
///     How the artifact it CAN assemble dies is a different sentence, and an
///     earlier version of this comment ran the two together: it endorses with
///     three keys of its own, `Id` is in the challenge preamble, so verifying
///     under the named party's key recomputes a different `c` and **both**
///     equations fail. The refusal is
///     [`CeremonyError::SeatEndorsementInvalid`], which deliberately does not say
///     which half. Deleting either verification equation on its own leaves this
///     test passing, so what it establishes is that the endorsement check runs
///     and refuses this artifact -- not which equation did it.
///     [`each_half_of_the_linked_endorsement_is_checked_on_its_own`] is the ONLY
///     test in the suite that fails for either deletion -- measured -- and so the
///     only thing standing between the two equations and a future edit that drops
///     one.
///
/// # What did NOT change, and is a test of its own
///
/// The dealer's own arithmetic. It still holds `b_owner`, the discrete log of
/// the whole owner component, and every proof of possession in the artifact is
/// genuine. Nothing here makes the attack impossible; what it makes impossible
/// is an artifact a funder accepts. And a dealer that deals REAL shares to the
/// named parties and keeps copies is untouched --
/// [`a_dealer_that_dealt_real_shares_and_kept_copies_still_passes`], immediately
/// below, and it is the residual that remains.
///
/// The CONTROL is an honest ceremony at the same shape, audited under the same
/// funder keys.
#[test]
fn a_dealer_that_keeps_the_shares_is_refused_at_the_seat_endorsement() {
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

    // Every proof of possession is the DEALER's: it knows every share. This half
    // of the artifact is exactly what it always was, so the refusals below are
    // attributable to the endorsements and to nothing else.
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

    // ---- 1. the named party, asked to endorse, has nothing to endorse with ----
    //
    // It holds its own identity key and no share of this dealing -- of any
    // dealing. `endorse_seat` requires both, so the best it can do is offer a
    // scalar of its own, and that is refused by its own software rather than
    // signed. `CohortShare::endorse` is not even callable: there is no
    // `CohortShare` in this party's possession, which is the whole of what
    // "share-less bystander" means.
    let a_scalar_the_party_invented = Scalar::random(&mut rng);
    for &id in &ids {
        assert_eq!(
            endorse_seat(
                &ceremony,
                &claim,
                id,
                &seat_key_of::<Owners>(id),
                &a_scalar_the_party_invented,
            )
            .expect_err("this party holds no share behind the seat it is being asked to endorse"),
            CeremonyError::SeatShareNotOwn {
                cohort: Owners::NAME,
                participant: id,
            },
        );
    }
    // And it is not the scalar that is unlucky: the DEALER's share for that seat
    // is the one value that would work, and the party does not have it. Asserted
    // so that the refusal above reads as "no share" rather than "wrong call" --
    // one input changes, the share argument, and the call succeeds.
    //
    // **Nobody in this scenario can make this call.** An earlier version of this
    // line said it "succeeds for whoever holds the share -- which is the dealer",
    // and that is wrong: `endorse_seat` checks `claimed != key.public()` FIRST,
    // and the key passed here is `seat_key_of::<Owners>(ids[0])`, the named
    // party's. The dealer alone gets `SeatKeyNotOwn` from it; the named party
    // alone gets `SeatShareNotOwn`, which is the assertion above. What succeeds
    // here is a caller holding BOTH, which this test process does and no
    // participant in the attack does. That is the point of the whole file, and
    // stating it the other way turned the control into a claim about capability
    // it cannot support.
    endorse_seat(
        &ceremony,
        &claim,
        ids[0],
        &seat_key_of::<Owners>(ids[0]),
        &dealt.share(ids[0]).expect("dealt"),
    )
    .expect("CONTROL: the share argument is the only thing wrong above");

    // ---- 2. so the dealer endorses with what it has: shares, and its own keys ----
    let its_own_keys: Vec<IdentityKey> = (0..3u8)
        .map(|k| IdentityKey::from_seed(&[0xC0 + k; 32]))
        .collect();
    let endorsements: BTreeMap<u64, SeatEndorsement> = ids
        .iter()
        .enumerate()
        .map(|(k, &id)| {
            (
                id,
                endorse_seat_unchecked(
                    &ceremony,
                    &claim,
                    id,
                    &its_own_keys[k],
                    &dealt.share(id).expect("dealt"),
                )
                .expect("it holds every share, and these are its OWN keys -- so this call \
                         succeeds and produces a proof bound to the wrong signer"),
            )
        })
        .collect();

    // Each of those endorsements is WELL FORMED under the key that made it.
    // Asserted before the refusal below, because `SeatEndorsementInvalid` is
    // deliberately generic: without this, a prover bug that produced garbage
    // whenever the signer differs from the claim's key would give exactly the
    // same expected error, and the test would pass for the wrong reason.
    // Adversarial review asked for this and it was not there.
    for (k, &id) in ids.iter().enumerate() {
        let v = claim.verification_share(id).expect("on the roster");
        assert!(
            endorsements[&id].verify(&ceremony, &claim, id, &v, &its_own_keys[k].public()),
            "the dealer's endorsement of seat {id} verifies under the dealer's OWN \
             key -- what it cannot do is verify under the named party's",
        );
    }

    let artifact = CompositionArtifact::from_parts(
        sealed,
        ComponentReveal::from_parts(claim, pops, endorsements, salt),
        gates.reveal(&sealed),
    );

    // ---- and the funder refuses it, under the keys it collected from the real
    // parties ----
    assert_eq!(
        audit(&artifact, &parties()).expect_err("the residual is closed"),
        CeremonyError::SeatEndorsementInvalid {
            cohort: Owners::NAME,
            participant: ids[0],
            signer: seat_key_of::<Owners>(ids[0]).public(),
        },
        "holding every share is half of an endorsement, and the other half is a \
         key this dealer does not have",
    );

    // THE HARM THAT DID NOT HAPPEN. The dealer still holds the discrete log of
    // the whole owner component -- the arithmetic is untouched -- but the
    // component never becomes an audited root.
    assert_eq!(artifact.owners().component(), b_owner * G);
    for &id in &ids {
        assert_ne!(
            artifact.owners().component(),
            artifact
                .owners()
                .claim()
                .verification_share(id)
                .expect("on the roster"),
            "the dealing is a real 2-of-3, so this is not a degenerate shape the \
             threshold checks would have caught",
        );
    }

    // CONTROL: an honest ceremony at the same shape, under the same funder keys.
    let h = honest(0x5EC1);
    audit(&h.artifact, &h.parties).expect("control: an honest 2-of-3 owner cohort still audits");
}

/// **THE RESIDUAL THAT REMAINS: a dealer that deals REAL shares to the named
/// parties and keeps copies produces an artifact that audits.**
///
/// Named, and kept passing, because a reader who has just seen two forgeries
/// inverted will otherwise assume this one was closed with them. It was not, and
/// it cannot be by anything an artifact carries.
///
/// The dealer deals a secret it chose to the three real parties over the decided
/// roster and KEEPS EVERY SHARE. Each party then endorses honestly: it holds the
/// identity key the claim names for it, and it holds a share that really does
/// open the verification share published for it, so the linked proof is
/// available to it and it is genuine. Every proof of possession is genuine too.
/// The artifact audits, and the dealer alone can spend, because it holds enough
/// shares to reconstruct.
///
/// **Why no proof can close this.** A proof of possession -- linked or not --
/// establishes that a witness was available to whoever made it. Possession is
/// copyable: `s_i` in two places is the same scalar, and the two are
/// indistinguishable in any transcript either can produce. What would be needed
/// is a proof of EXCLUSIVE possession, which no group element carries. The
/// remedy is the DKG, where no dealer ever holds a share -- and whether a cohort
/// ran one is precisely what `dkg`'s own module docs say the published bytes
/// cannot show.
///
/// # If this test fails, check the harness before rewriting anything
///
/// Like the two-organisations residual in `tests/attribution.rs`, it asserts
/// that something SUCCEEDS. A red here almost certainly means an unrelated
/// change broke artifact construction, not that the residual is gone.
#[test]
fn a_dealer_that_dealt_real_shares_and_kept_copies_still_passes() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EC2);
    let ceremony = CeremonyId::draw("dealt, and copies kept", &mut rng);
    let ids = owners_spec().ids().to_vec();

    // The dealer's secret, dealt 2-of-3 to the three real parties. It keeps
    // `dealt`, which is every share.
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
        seat_keys_over::<Owners>(&ids),
    );
    let salt = [0x92; 32];
    let signed = seal_and_sign::<Owners>(&ceremony, &claim, &salt);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);
    let sealed = SealedComposition::new(ceremony, signed, gates.commitment).expect("well-formed");

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
                .expect("a share behind every seat, because the parties really were dealt one"),
            )
        })
        .collect();

    // Each named party endorses with its OWN identity key and the share it was
    // DEALT. Through `endorse_seat`, the entry point an honest party reaches
    // for -- nothing here is unchecked, and nothing here is a forgery of any
    // kind. Every one of these endorsements is exactly what an honest seat
    // produces.
    let endorsements: BTreeMap<u64, SeatEndorsement> = ids
        .iter()
        .map(|&id| {
            (
                id,
                endorse_seat(
                    &ceremony,
                    &claim,
                    id,
                    &seat_key_of::<Owners>(id),
                    &dealt.share(id).expect("this party was dealt a real share"),
                )
                .expect("it holds the key AND a share that opens its own verification share"),
            )
        })
        .collect();

    let artifact = CompositionArtifact::from_parts(
        sealed,
        ComponentReveal::from_parts(claim, pops, endorsements, salt),
        gates.reveal(&sealed),
    );

    let audited = audit(&artifact, &parties()).expect("THIS IS THE RESIDUAL: it audits");
    let (o, _) = audited.structure();
    assert_eq!(
        o.seats(),
        ids.iter()
            .map(|&id| (id, seat_key_of::<Owners>(id).public()))
            .collect::<Vec<_>>(),
        "the funder is told the three real parties hold the three owner seats, \
         and they do",
    );

    // THE HARM: the dealer kept copies, so it holds the discrete log of the
    // whole owner component, which no member of a cohort that ran a DKG would.
    // Every check in the module passes and nothing in the artifact differs from
    // the honest case.
    assert_eq!(o.component(), b_owner * G);
    let quorum = [ids[0], ids[1]];
    let reconstructed: Scalar = quorum
        .iter()
        .map(|&id| {
            two_cohort::lagrange_at_zero(
                ids.iter().position(|&r| r == id).unwrap() as u64 + 1,
                &quorum
                    .iter()
                    .map(|&q| ids.iter().position(|&r| r == q).unwrap() as u64 + 1)
                    .collect::<Vec<_>>(),
            )
            .expect("public arithmetic")
                * *dealt.share(id).expect("dealt")
        })
        .sum();
    assert_eq!(
        reconstructed, b_owner,
        "the dealer's copies reconstruct the owner component by themselves",
    );
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
