//! Adversarial pass over per-seat attribution: forge an artifact that passes
//! with fewer real principals than `COMPROMISE_THRESHOLD`.
//!
//! `tests/seat_identity.rs` is the file that BUILT the seat rosters and states
//! their residual. This one attacks that statement. Everything here was written
//! against the crate's public API only, from the position of a party that holds
//! what the attack says it holds and nothing else.
//!
//! All three tests are refusals with a named error and a control. The first was
//! not: it PASSED, deliberately, because it was a forgery that reached a
//! published deposit address and it was here so that the residual was a value
//! this suite produced rather than a paragraph in a doc comment. It is now the
//! inverse of itself -- the endorsement became a proof of knowledge of the SHARE
//! as well as of the identity key, so the real seat-holders' own key material
//! refuses the substituted dealing.
//!
//! What is left of that residual has moved next door: a dealer that dealt REAL
//! shares to the named parties and kept copies still passes, by name, in
//! `tests/seat_identity.rs::a_dealer_that_dealt_real_shares_and_kept_copies_still_passes`.
//! Nothing in this file closes that and nothing can.

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
        draw_salt, endorse_seat, endorse_seat_unchecked, ComponentClaim, ComponentReveal,
        SealedComposition, SeatEndorsement, SeatRoster,
    },
    derive::subaddress_offset,
    dkg::run_dkg,
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

/// **The attack that no longer works: three real seat-holders are asked to
/// endorse a SUBSTITUTED dealing, and their own key material refuses.**
///
/// # What this test used to assert
///
/// It was `a_seat_holder_with_a_real_share_endorses_a_substituted_dealing_and_it_audits`,
/// and it PASSED. The endorsement was an Ed25519 signature over public bytes, so
/// a party holding a real share of a real DKG could still sign for a claim that
/// substituted a different dealing entirely -- the signature never consulted the
/// share. Two principals then reached a published deposit address against a
/// decided [`COMPROMISE_THRESHOLD`] of three. The test's own doc said that the
/// day something bound an endorser to a share-holder, it should be replaced by
/// its inverse, asserted by exact error. This is that inverse.
///
/// # The same attack, unchanged
///
/// Who holds what is exactly as it was:
///
///   1. the owner cohort's DKG runs for real. `P1`, `P2`, `P3` each finish with
///      a `CohortShare` and each holds its own long-term seat key. The gate runs
///      its own cohort honestly;
///   2. the attacker is the operator ORGANISATION -- it holds the owners'
///      organisation identity key and NOT ONE SEAT KEY. It deals a secret `b'`
///      of its own to itself over the same three ids, and writes the three real
///      seat-holders' public keys into the claim, which are public values it is
///      free to copy;
///   3. it asks each of `P1`, `P2`, `P3` to endorse its own seat.
///
/// Step 3 is where it now dies, and it dies at BOTH entry points rather than at
/// one of two:
///
///   * [`two_cohort::dkg::CohortShare::endorse`] refuses with
///     [`CeremonyError::ClaimNotOwn`], as it always did -- it compares the claim,
///     field for field, against the one this share's own key generation
///     produced;
///   * [`endorse_seat`], the free function a holder whose long-term key lives
///     away from its share must reach for, refuses with
///     [`CeremonyError::SeatShareNotOwn`]. It now takes the share as well as the
///     key, and the share these parties hold does not open the verification
///     share the substituted claim publishes for them.
///
/// The second is the whole of the fix. The asymmetry that made this forgery work
/// -- a checked entry point that needed key material and an unchecked one that
/// needed only a signature -- is gone, because there is no longer any way to
/// endorse without the share.
///
/// # And the attacker cannot make up the difference
///
/// The CAPABILITY statement: it holds every share of the dealing it substituted,
/// so it can answer the share half of every endorsement; it cannot answer the
/// identity half under a key it does not hold, and one challenge binds the two.
/// That is what makes the artifact below unassemblable in the form it wants.
///
/// **How the artifact it CAN assemble actually dies is a different sentence, and
/// an earlier version of this comment ran the two together.** It endorses with
/// three keys of its own, and the audit verifies under the real parties' keys.
/// `Id` is in the challenge preamble, so verifying under a different signer
/// recomputes a different `c` and **both** equations fail, not just the identity
/// one. The refusal is [`CeremonyError::SeatEndorsementInvalid`], which
/// deliberately does not say which half -- see that variant's own note.
///
/// Said plainly because it bears on what this test covers: deleting EITHER
/// verification equation on its own leaves this test passing. It establishes
/// that the endorsement check runs and refuses this artifact, not which equation
/// did it. `seat_identity.rs::each_half_of_the_linked_endorsement_is_checked_on_its_own`
/// is the ONLY test in the suite that fails for either deletion -- measured, and
/// so the only thing standing between the two equations and a future edit that
/// drops one.
///
/// The CONTROL is an honest ceremony at the same shape, through the same
/// `deployment_publishes` sequence, which still reaches its published address.
#[test]
fn a_seat_holder_with_a_real_share_cannot_endorse_a_substituted_dealing() {
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

    // ---- 3. the endorsements, through both entry points, and both refuse ----
    for share in &real_shares {
        // The checked one sees the substitution, as it always did.
        assert_eq!(
            share
                .endorse(&ceremony, &forged_claim, &seat_key_of::<Owners>(share.id()))
                .expect_err("a real holder's own key material contradicts this claim"),
            CeremonyError::ClaimNotOwn {
                cohort: Owners::NAME,
                participant: share.id(),
            },
        );

        // THE FIX: the free function refuses too, and for a reason the holder
        // can check without re-running anyone else's key generation -- the share
        // it holds does not open the verification share it is being asked to
        // stand behind.
        let id = share.id();
        assert_eq!(
            endorse_seat(
                &ceremony,
                &forged_claim,
                id,
                &seat_key_of::<Owners>(id),
                &own_share_of(&real_shares, id, &real_claim),
            )
            .expect_err("the share this party holds is of a different dealing"),
            CeremonyError::SeatShareNotOwn {
                cohort: Owners::NAME,
                participant: id,
            },
        );

        // CONTROL, one input changed: the same key and the same share, over the
        // claim the DKG actually produced. So what refuses above is the
        // substitution and not the call.
        endorse_seat(
            &ceremony,
            &real_claim,
            id,
            &seat_key_of::<Owners>(id),
            &own_share_of(&real_shares, id, &real_claim),
        )
        .expect("control: its own claim, its own key, its own share");
    }

    // ---- what the attacker can still assemble, and where it dies ----
    //
    // It holds every share of its own dealing, so the share half of every
    // endorsement is available to it. The identity half is not: these are the
    // real parties' keys. It makes the endorsements with the only keys it has --
    // three it invented -- and the claim still names the real parties, because
    // naming itself is `forgery.rs`'s variant A and a different refusal.
    //
    // What the audit then sees fails BOTH equations, not only the identity one:
    // `Id` is in the challenge preamble, so verifying under the real party's key
    // recomputes a different `c` than the one these responses answer. See this
    // test's own doc comment.
    let its_own_keys: Vec<_> = (0..3u8)
        .map(|k| two_cohort::identity::IdentityKey::from_seed(&[0xB0 + k; 32]))
        .collect();
    let endorsements: BTreeMap<u64, SeatEndorsement> = ids
        .iter()
        .enumerate()
        .map(|(k, &id)| {
            (
                id,
                endorse_seat_unchecked(
                    &ceremony,
                    &forged_claim,
                    id,
                    &its_own_keys[k],
                    &dealt.share(id).expect("the attacker dealt to this seat"),
                )
                .expect("it holds this share; the key it uses is its own"),
            )
        })
        .collect();

    // Each of those is WELL FORMED under the key that made it. Asserted before
    // the refusal, because `SeatEndorsementInvalid` is deliberately generic:
    // without this, a prover bug that produced garbage whenever the signer
    // differs from the claim's key would give exactly the same expected error
    // and this test would pass for the wrong reason. Adversarial review asked
    // for it and it was not there.
    for (k, &id) in ids.iter().enumerate() {
        let v = forged_claim
            .verification_share(id)
            .expect("the substituted claim publishes one for every seat");
        assert!(
            endorsements[&id].verify(&ceremony, &forged_claim, id, &v, &its_own_keys[k].public()),
            "the attacker's endorsement of seat {id} verifies under the attacker's \
             OWN key -- what it cannot do is verify under the real party's",
        );
    }

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
                // The attacker dealt, so the attacker knows every share. This
                // half of the artifact is as genuine as it ever was, which is
                // why the refusal below is attributable to the endorsements.
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
    assert_eq!(
        audit(&artifact, &parties()).expect_err("THE FORGERY IS REFUSED"),
        CeremonyError::SeatEndorsementInvalid {
            cohort: Owners::NAME,
            participant: ids[0],
            signer: seat_key_of::<Owners>(ids[0]).public(),
        },
        "the proofs of possession are genuine and the seat keys are the funder's \
         own, so what is left is the endorsement -- and holding every share is \
         only half of one",
    );

    // ---- and it does not reach a published deposit address ----
    let deposit = Deposit::to(artifact.declared_root(), &mut rng);
    let refused = deployment_publishes(&artifact, &parties(), &deposit)
        .map(|_| ())
        .expect_err("the forgery must not reach the funding path");
    assert_eq!(
        refused.downcast_ref::<CeremonyError>(),
        Some(&CeremonyError::SeatEndorsementInvalid {
            cohort: Owners::NAME,
            participant: ids[0],
            signer: seat_key_of::<Owners>(ids[0]).public(),
        }),
        "the deployment path stops at `audit_address`, before any spend exists",
    );

    // ---- THE HARM THAT DID NOT HAPPEN, stated as arithmetic ----
    //
    // The attacker still holds `b_forged`, the discrete log of the component it
    // published; nothing about the ATTACK has been made impossible. What it no
    // longer has is an artifact a funder accepts, so that component never
    // becomes an address.
    assert_eq!(artifact.owners().component(), b_forged * G);
    assert_ne!(
        artifact.owners().component(),
        real_claim.component(),
        "the component it published is not the one the real DKG produced",
    );
    assert_eq!(COMPROMISE_THRESHOLD, 3);

    // ---- CONTROL: an honest ceremony at the same shape still publishes ----
    //
    // Without this the test would establish that the path refuses things, not
    // that it distinguishes them.
    let h = Honest::run(0x50C, &owners_spec(), &gates_spec());
    let honest_deposit = Deposit::to(h.artifact.declared_root(), &mut rng);
    let (_, published) = deployment_publishes(&h.artifact, &h.parties, &honest_deposit)
        .expect("an honest ceremony at the same shape still publishes");
    assert_eq!(published, honest_deposit.spend_public);
}

/// One real seat-holder's own share scalar, recovered as a holder recovers it.
///
/// `CohortShare::secret` is `pub(crate)`; a holder outside the crate divides its
/// own Lagrange-weighted term by the public weight. See
/// `composition.rs::a_holder_can_recover_its_own_share_through_public_api`. It is
/// spelled out here rather than taken from the harness because these three
/// parties are not a `CohortSide` -- they are a bare DKG output, which is the
/// point of this test.
fn own_share_of(
    shares: &[two_cohort::dkg::CohortShare<Owners>],
    id: u64,
    claim: &ComponentClaim,
) -> Scalar {
    let share = shares.iter().find(|s| s.id() == id).expect("on the roster");
    let roster = claim.roster().to_vec();
    let mut quorum: Vec<u64> = vec![id];
    for &r in &roster {
        if quorum.len() == claim.threshold() {
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
    let lambda = two_cohort::lagrange_at_zero(mine, &points).expect("public arithmetic");
    let recovered = *share
        .term(&quorum)
        .expect("a quorum member's own term")
        .weight()
        * lambda.invert();
    assert_eq!(
        recovered * G,
        claim.verification_share(id).expect("on the roster"),
        "the recovered scalar opens this seat's own published verification share",
    );
    recovered
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
        // Endorsed by whoever the claim names at that position, with the share
        // that position really carries -- the dealer holds every share, so both
        // halves of the linked proof are available. Every endorsement therefore
        // VERIFIES, and the refusal below cannot be the endorsement check
        // standing in for the attribution check.
        let endorsements: BTreeMap<u64, SeatEndorsement> = ids
            .iter()
            .zip(assign)
            .map(|(&id, &signer)| {
                (
                    id,
                    endorse_seat(
                        &ceremony,
                        &claim,
                        id,
                        &seat_key_of::<Owners>(signer),
                        &dealt.share(id).expect("dealt"),
                    )
                    .expect("the claim names this key at this position and the share opens it"),
                )
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
