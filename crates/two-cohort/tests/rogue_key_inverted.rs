//! **THE EXHIBIT, INVERTED.** The rogue-key attack in `tests/rogue_key.rs`,
//! attempted against the composition ceremony, and refused.
//!
//! `tests/rogue_key.rs` is the attack, performed, and it still passes: nothing
//! about the ARITHMETIC has changed. `B_mine = t*G - B_theirs` is still an
//! ordinary non-identity group element, the sum is still `t*G`, and an attacker
//! holding `t` and the view key would still open every output paid to a
//! subaddress of it. This file asserts both halves of that -- the algebra still
//! works, and the ceremony refuses to produce the address anyway.
//!
//! The same attacker, with the same `t`, is run against the same shape of
//! honest cohort. Each test names the step at which it dies and the error it
//! dies with.
//!
//! # Where the attack dies, and why it takes two checks
//!
//! ```text
//!   ATTEMPT 1  the attacker seals a component it can open, and then reveals
//!              the rogue one it computed after seeing B_owner
//!              -> CeremonyError::CommitmentMismatch { cohort: "gates" }
//!
//!   ATTEMPT 2  the attacker is allowed to seal LATE -- it computes the rogue
//!              component first and seals that, so its commitment does bind
//!              what it reveals. It must then prove possession of a discrete
//!              log it does not have.
//!              -> CeremonyError::PopFailed { cohort: "gates", participant }
//!              ...and it cannot endorse the seat either, since a seat
//!              endorsement became a proof of knowledge of the share as well
//!              as of the identity key.
//!              -> CeremonyError::SeatShareNotOwn { cohort, participant }
//!
//!   ATTEMPT 3  the attacker publishes a component it CAN prove. Then the
//!              composition succeeds, and is worthless to it: the root is not
//!              `t*G`, and `t` opens nothing.
//!
//!   ATTEMPT 4  the attacker seals a THROWAWAY component, waits for the honest
//!              reveal, grinds its own DKG against what it saw, and asks the
//!              honest cohort to prove again under the composition it now
//!              wants. The honest shares refuse the second one.
//!              -> CeremonyError::ProofAlreadyIssued { cohort, participant }
//! ```
//!
//! Attempt 4 is the one the artifact cannot decide. Attempts 1-3 are refused by
//! [`audit`] on the bytes alone; attempt 4 is refused at the SHARE, because two
//! commitment values in hand say nothing about whether one had already been
//! opened. It buys the attacker only a choice among roots it can prove -- never
//! a chosen discrete log -- but the ordering was claimed to be enforced by the
//! type, and it is not.
//!
//! The audit reports attempt 2 as `PopFailed` and not as the endorsement
//! failure, because `check_side` runs the proofs of possession first --
//! deliberately, and for the reason given there. Both refuse it, and
//! `the_attacker_cannot_even_endorse_the_rogue_component` asserts the second one
//! directly rather than leaving it to be inferred from an error that never
//! mentions it.
//!
//! Attempt 2 is why commit-then-reveal alone is not enough, and attempt 1 is
//! why a proof of possession alone is not enough -- a cohort free to seal after
//! seeing the other component can run its own DKG repeatedly and keep the draw
//! it likes. The two checks are welded rather than stacked: the proof
//! transcript names BOTH commitments, so a proof cannot be produced before the
//! other cohort's component is sealed, and what is being proved is already
//! sealed inside the prover's own commitment.
//!
//! # What the attacker is given
//!
//! Exactly what `tests/rogue_key.rs` gave it, and nothing more: a scalar `t` it
//! invents, and the view private key -- which is not a cohort secret in this
//! design. It holds no share, and it runs no gate DKG in the attempts that
//! matter, because a rogue component has no scalar to share.

mod common;

use std::collections::BTreeMap;

use common::{identity_of, parties_over, seal_and_sign, CohortSide, Honest};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G, ristretto::RistrettoPoint, scalar::Scalar,
    traits::Identity,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use two_cohort::{
    audit,
    ceremony::{endorse_seat, prove_possession, SealedComposition, SeatEndorsement, SeatRoster},
    identity::IdentityKey,
    CeremonyError, CeremonyId, CohortSpec, CompositionArtifact, ComponentClaim, ComponentReveal,
    ControlDomain, Gates, Owners, Parties, Pop,
};

fn owners_spec() -> CohortSpec<Owners> {
    CohortSpec::<Owners>::sequential(2, 3)
}

fn gates_spec() -> CohortSpec<Gates> {
    CohortSpec::<Gates>::sequential(2, 3)
}

/// Everyone a funder of an artifact at this file's shape holds a key for.
fn parties() -> Parties {
    parties_over(owners_spec().ids(), gates_spec().ids())
}

/// An honest owner cohort whose shares have not yet answered any composition.
///
/// Attempts 2 and 3 hand the attacker adaptivity a real ceremony denies it: it
/// waits until `B_owner` is public and only THEN seals, so the composition the
/// owners are asked to prove under is not the one their own commitment first
/// went into. In a real ceremony those owners would already have answered one,
/// and [`prove_possession`] would refuse the second -- which is
/// [`the_owners_refuse_a_second_composition_so_a_late_seal_has_nobody_to_prove_with`],
/// below. The owner side here is therefore fresh, so each test below is about
/// the ONE check it names and not about that refusal firing first.
fn fresh_owners(seed: u64) -> (CeremonyId, CohortSide<Owners>) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let ceremony = CeremonyId::draw("rogue-key inversion", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    (ceremony, owners)
}

/// Everything the attacker holds. No cohort, no share, no honest secret --
/// the type is the claim, exactly as in `tests/rogue_key.rs`.
struct Attacker {
    /// The discrete log the attacker wants for the WHOLE composite root.
    t: Scalar,
    /// The attacker's own long-term seat identity key.
    ///
    /// Not stolen and not impersonated: the attacker here IS the gate
    /// organisation and its single seat, and a funder that audits its artifacts
    /// has been given this key for that seat. Carrying it makes the attempts
    /// below turn on what the attacker can PROVE rather than on whether it can
    /// sign its own name -- which it obviously can.
    seat: IdentityKey,
}

impl Attacker {
    fn new(seed: u64) -> Attacker {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        Attacker {
            t: Scalar::random(&mut rng),
            seat: IdentityKey::from_seed(&[0xE7; 32]),
        }
    }

    /// `B_mine = t*G - B_theirs`. The attacker knows no discrete log of this
    /// point, and in the original exhibit it never needed one.
    fn rogue_component(&self, theirs: &RistrettoPoint) -> RistrettoPoint {
        self.t * G - theirs
    }

    /// The rogue component dressed as a one-member gate cohort. A single
    /// participant at threshold 1 is the smallest thing that has to be proved,
    /// so it is the attacker's best case.
    fn rogue_claim(&self, theirs: &RistrettoPoint) -> ComponentClaim {
        let rogue = self.rogue_component(theirs);
        ComponentClaim::from_parts(
            "gates",
            1,
            vec![Gates::nth(0)],
            rogue,
            // At threshold 1 over one participant, the verification share IS
            // the component. There is nowhere to hide an unopenable term.
            vec![rogue],
            vec![self.seat.public()],
        )
    }

    /// Everyone a funder auditing THIS attacker's artifacts holds a key for:
    /// the honest owner cohort and its three seats, and the attacker as the
    /// gate organisation and its one seat.
    fn parties(&self) -> Parties {
        Parties::new(
            identity_of::<Owners>().public(),
            common::seats_for::<Owners>(&owners_spec()),
            identity_of::<Gates>().public(),
            SeatRoster::<Gates>::new([(Gates::nth(0), self.seat.public())])
                .expect("one gate seat"),
        )
    }

    /// The attacker's endorsement of its own seat, for a claim whose
    /// verification share it can OPEN with `share`.
    ///
    /// It holds its own seat key outright, so before the endorsement became a
    /// linked proof this always succeeded and the attempts below were refused
    /// purely at the proof of possession. It no longer always succeeds: the
    /// endorsement now proves knowledge of the share as well, so the attacker
    /// can only produce one for a component it can open -- which is attempt 3,
    /// the one that gains it nothing. The rogue attempts use
    /// [`Attacker::forged_endorsement`], and
    /// [`the_attacker_cannot_even_endorse_the_rogue_component`] asserts why.
    fn endorsement(
        &self,
        ceremony: &CeremonyId,
        claim: &ComponentClaim,
        share: &Scalar,
    ) -> BTreeMap<u64, SeatEndorsement> {
        BTreeMap::from([(
            Gates::nth(0),
            endorse_seat(ceremony, claim, Gates::nth(0), &self.seat, share)
                .expect("the attacker holds its own seat key and this share"),
        )])
    }

    /// A proof of possession the attacker fabricates out of nothing, since it
    /// has no scalar to make a real one from. A real attacker is not restricted
    /// to this crate's constructors; `Pop::from_parts` is what it would send.
    fn forged_pop(&self) -> Pop {
        let mut rng = ChaCha20Rng::seed_from_u64(0xF00);
        Pop::from_parts(Scalar::random(&mut rng) * G, Scalar::random(&mut rng))
    }

    /// A seat endorsement fabricated the same way and for the same reason: the
    /// attacker cannot open the rogue verification share, so it cannot make a
    /// real one, and `SeatEndorsement::from_parts` is what it would send.
    ///
    /// The artifacts below are refused at [`CeremonyError::PopFailed`] rather
    /// than at this, because `check_side` runs the proofs of possession first.
    /// Both fail. That ordering is deliberate and documented there; what matters
    /// here is that nothing in these attempts turns on the endorsement being
    /// accepted.
    fn forged_endorsement(&self) -> BTreeMap<u64, SeatEndorsement> {
        let mut rng = ChaCha20Rng::seed_from_u64(0xF01);
        BTreeMap::from([(
            Gates::nth(0),
            SeatEndorsement::from_parts(
                [0x5C; 32],
                Scalar::random(&mut rng) * G,
                Scalar::random(&mut rng),
                Scalar::random(&mut rng),
            ),
        )])
    }
}

// ---------------------------------------------------------------------------
// The arithmetic is unchanged. Only the acceptance is.
// ---------------------------------------------------------------------------

/// The attack's algebra still works exactly as `tests/rogue_key.rs` exhibits
/// it. Nothing here has been made impossible; what follows is a set of CHECKS,
/// and this test is what makes the rest of the file a statement about checks
/// rather than about arithmetic.
#[test]
fn the_rogue_component_is_still_a_perfectly_ordinary_group_element() {
    let h = Honest::run(0xA11CE, &owners_spec(), &gates_spec());
    let attacker = Attacker::new(0xBADCA7);
    let b_owner = h.owners.claim.component();

    let rogue = attacker.rogue_component(&b_owner);
    assert_ne!(
        rogue,
        RistrettoPoint::identity(),
        "an ordinary-looking, non-identity component"
    );
    assert_eq!(
        b_owner + rogue,
        attacker.t * G,
        "the composite root would still collapse to a key the attacker chose"
    );
    // And it is still adaptive: a response to what it saw, computable only
    // after seeing it.
    let other = Honest::run(0x0FF1CE, &owners_spec(), &gates_spec());
    assert_ne!(
        rogue,
        attacker.rogue_component(&other.owners.claim.component()),
        "the component is a function of the honest one, so it cannot be published first"
    );
}

// ---------------------------------------------------------------------------
// ATTEMPT 1: adaptive choice, refused by the commitment.
// ---------------------------------------------------------------------------

/// **The attacker cannot choose its component after seeing the honest one.**
///
/// It seals a real gate cohort of its own -- one it genuinely ran a DKG for, so
/// its commitment is beyond reproach -- because at seal time `B_owner` is not
/// yet published and the rogue component does not exist. When the owners
/// reveal, it computes `t*G - B_owner` and tries to open its commitment onto
/// that instead.
///
/// This is `mount_attack`'s step 1 becoming unreachable: the point exists, and
/// the ceremony will not carry it.
#[test]
fn the_attacker_cannot_substitute_the_rogue_component_at_reveal_time() {
    let h = Honest::run(0xA11CE, &owners_spec(), &gates_spec());
    let attacker = Attacker::new(0xBADCA7);

    // CONTROL: the gate cohort's own, honest reveal opens its own commitment.
    // So what is refused below is the substitution, not the sealing.
    h.sealed
        .clone()
        .open(h.owner_reveal.clone(), h.gate_reveal.clone(), &parties())
        .expect("control: the sealed gate cohort opens its own commitment");

    // The owners reveal. NOW the attacker knows B_owner.
    let b_owner = h.owner_reveal.component();
    assert_eq!(b_owner, h.owners.claim.component());

    let rogue = attacker.rogue_claim(&b_owner);
    let substituted = ComponentReveal::from_parts(
        rogue.clone(),
        BTreeMap::new(),
        attacker.forged_endorsement(),
        *h.gate_reveal.salt(),
    );

    assert_eq!(
        h.sealed
            .open(h.owner_reveal.clone(), substituted.clone(), &parties())
            .unwrap_err(),
        CeremonyError::CommitmentMismatch { cohort: "gates" },
        "the rogue component must not open the commitment the gate cohort published"
    );

    // And an artifact carrying it does not audit, so a funder handed one
    // reaches the same answer without having been present.
    assert_eq!(
        audit(
            &CompositionArtifact::from_parts(h.sealed, h.owner_reveal.clone(), substituted),
            &parties(),
        )
        .unwrap_err(),
        CeremonyError::CommitmentMismatch { cohort: "gates" }
    );
}

/// The refusal does not depend on which honest cohort was attacked.
///
/// `tests/rogue_key.rs::exhibit_the_attack_is_independent_of_the_honest_cohort`
/// showed the attack producing a byte-identical signature against two different
/// honest cohorts. Inverted: two different honest cohorts, one attacker, and
/// the same refusal at the same step -- while the rogue components still
/// differ, so the attacker is still adapting and still getting nowhere.
#[test]
fn the_refusal_is_independent_of_the_honest_cohort() {
    let attacker = Attacker::new(0xBADCA7);
    let a = Honest::run(0xA11CE, &owners_spec(), &gates_spec());
    let b = Honest::run(0x0FF1CE, &CohortSpec::<Owners>::sequential(4, 5), &gates_spec());

    let rogue_a = attacker.rogue_claim(&a.owner_reveal.component());
    let rogue_b = attacker.rogue_claim(&b.owner_reveal.component());
    assert_ne!(
        rogue_a.component(),
        rogue_b.component(),
        "the attacker adapted its component to each honest cohort"
    );

    for (h, rogue) in [(&a, rogue_a), (&b, rogue_b)] {
        assert_eq!(
            h.sealed
                .clone()
                .open(
                    h.owner_reveal.clone(),
                    ComponentReveal::from_parts(
                        rogue.clone(),
                        BTreeMap::new(),
                        attacker.forged_endorsement(),
                        *h.gate_reveal.salt(),
                    ),
                    // Each honest run has its own owner roster -- `b` is 4-of-5
                    // -- so the funder's seats are that run's, not this file's
                    // default. A `Parties` naming the wrong owner seats would be
                    // refused on the OWNER side, which is not what this test is
                    // about.
                    &parties_over(h.owner_reveal.roster(), &[Gates::nth(0)]),
                )
                .unwrap_err(),
            CeremonyError::CommitmentMismatch { cohort: "gates" },
        );
    }
}

// ---------------------------------------------------------------------------
// ATTEMPT 2: sealed late, refused by the proof of possession.
// ---------------------------------------------------------------------------

/// **Even sealing the rogue component honestly does not help: the attacker
/// cannot prove possession of it.**
///
/// Here the attacker is GIVEN the thing attempt 1 denies it. It sees `B_owner`
/// first, computes `t*G - B_owner`, and seals THAT -- so its commitment binds
/// exactly what it reveals and [`CeremonyError::CommitmentMismatch`] cannot be
/// what refuses it. What it cannot do is open the component: `dlog(B_mine) = t
/// - dlog(B_owner)`, and it does not have `dlog(B_owner)`.
///
/// This is why proof of possession is needed in addition to commit-then-reveal,
/// and why the exhibit's conclusion says the ordering alone would only be a
/// governance rule.
#[test]
fn the_attacker_cannot_prove_possession_of_the_rogue_component() {
    let (ceremony, owners) = fresh_owners(0xA11CE);
    let attacker = Attacker::new(0xBADCA7);

    let rogue = attacker.rogue_claim(&owners.claim.component());
    // Sealed AFTER seeing B_owner -- the attacker is handed the adaptivity
    // attempt 1 denies it, so that this test is about the proof and nothing
    // else.
    let sealed = SealedComposition::new(
        ceremony,
        owners.commitment,
        seal_and_sign::<Gates>(&ceremony, &rogue, &[0x99; 32]),
    )
    .expect("well-formed commitments");

    // The honest API will not even build the proof: `t` is not the discrete log
    // of what the attacker is publishing, and `Pop::prove` says so rather than
    // emitting a proof that fails later.
    assert_eq!(
        Pop::prove_unchecked(&sealed, &rogue, Gates::nth(0), &attacker.t).unwrap_err(),
        CeremonyError::PopFailed {
            cohort: "gates",
            participant: Gates::nth(0),
        }
    );

    // So the attacker forges one, as it would on the wire.
    let forged = ComponentReveal::from_parts(
        rogue.clone(),
        BTreeMap::from([(Gates::nth(0), attacker.forged_pop())]),
        attacker.forged_endorsement(),
        [0x99; 32],
    );
    // The commitment DOES bind this reveal -- asserted, so the rejection below
    // cannot be the commitment check.
    assert_eq!(
        forged.commitment(&ceremony),
        seal_and_sign::<Gates>(&ceremony, &rogue, &[0x99; 32]).commitment()
    );

    let artifact = CompositionArtifact::from_parts(sealed, owners.reveal(&sealed), forged);
    assert_eq!(
        audit(&artifact, &attacker.parties()).unwrap_err(),
        CeremonyError::PopFailed {
            cohort: "gates",
            participant: Gates::nth(0),
        },
        "a component nobody can open must not be composed into a spend root"
    );

    // The root that artifact WOULD have declared is exactly the capture the
    // original exhibit achieved. Asserted so the reader can see what the
    // refusal is worth.
    assert_eq!(artifact.declared_root(), attacker.t * G);
}

/// **The attacker cannot even ENDORSE the rogue seat, since the endorsement
/// began proving knowledge of the share.**
///
/// A second, independent refusal of the same attempt, and it is asserted here
/// rather than left implicit because the audit above reports `PopFailed` and a
/// reader could conclude the endorsement was accepted. It was not: the attempts
/// above pass a FABRICATED endorsement, and this is why they have to.
///
/// The attacker holds its own seat identity key -- the funder collected that key
/// from it -- so before the endorsement was linked to the share, `endorse_seat`
/// handed it a valid one for any claim it liked. What it does not hold is a
/// scalar opening `V = t*G - B_owner`, and there is nothing else it could
/// substitute: the only scalar in its possession is `t`.
///
/// The CONTROL is the same call over the component it CAN open, which is
/// attempt 3's claim -- one input, the verification share, changed.
#[test]
fn the_attacker_cannot_even_endorse_the_rogue_component() {
    let (ceremony, owners) = fresh_owners(0xA11CE);
    let attacker = Attacker::new(0xBADCA7);
    let rogue = attacker.rogue_claim(&owners.claim.component());

    assert_eq!(
        endorse_seat(&ceremony, &rogue, Gates::nth(0), &attacker.seat, &attacker.t)
            .expect_err("`t` does not open the rogue verification share"),
        CeremonyError::SeatShareNotOwn {
            cohort: "gates",
            participant: Gates::nth(0),
        },
    );

    // CONTROL: the same key, the same scalar, over a claim whose verification
    // share that scalar opens.
    let openable = ComponentClaim::from_parts(
        "gates",
        1,
        vec![Gates::nth(0)],
        attacker.t * G,
        vec![attacker.t * G],
        vec![attacker.seat.public()],
    );
    endorse_seat(
        &ceremony,
        &openable,
        Gates::nth(0),
        &attacker.seat,
        &attacker.t,
    )
    .expect("control: a seat that holds its own share endorses it");
}

/// Omitting the proof entirely does not get past it either: a component with no
/// proof behind it is refused by name.
#[test]
fn a_rogue_component_with_no_proof_at_all_is_refused() {
    let (ceremony, owners) = fresh_owners(0xA11CE);
    let attacker = Attacker::new(0xBADCA7);
    let rogue = attacker.rogue_claim(&owners.claim.component());
    let salt = [0x77; 32];
    let sealed = SealedComposition::new(
        ceremony,
        owners.commitment,
        seal_and_sign::<Gates>(&ceremony, &rogue, &salt),
    )
    .expect("well-formed");

    assert_eq!(
        audit(
            &CompositionArtifact::from_parts(
                sealed,
                owners.reveal(&sealed),
                ComponentReveal::from_parts(
                    rogue.clone(),
                    BTreeMap::new(),
                    attacker.forged_endorsement(),
                    salt,
                ),
            ),
            &attacker.parties(),
        )
        .unwrap_err(),
        CeremonyError::PopMissing {
            cohort: "gates",
            participant: Gates::nth(0),
        }
    );
}

// ---------------------------------------------------------------------------
// ATTEMPT 3: publish something provable, and gain nothing.
// ---------------------------------------------------------------------------

/// **The only component the attacker can prove is one that does not capture the
/// root.**
///
/// It publishes `t*G`, whose discrete log it does know. The composition then
/// succeeds -- and the root is `B_owner + t*G`, not `t*G`. The attacker holds a
/// component, exactly as intended, and the honest cohort's contribution is
/// still in the sum.
///
/// This is the positive half of the argument: the ceremony does not refuse
/// everything, it refuses precisely the components their publisher cannot open.
#[test]
fn a_component_the_attacker_can_prove_does_not_capture_the_root() {
    let (ceremony, owners) = fresh_owners(0xA11CE);
    let attacker = Attacker::new(0xBADCA7);
    let b_owner = owners.claim.component();

    let honest_shape = ComponentClaim::from_parts(
        "gates",
        1,
        vec![Gates::nth(0)],
        attacker.t * G,
        vec![attacker.t * G],
        vec![attacker.seat.public()],
    );
    let salt = [0x11; 32];
    let sealed = SealedComposition::new(
        ceremony,
        owners.commitment,
        seal_and_sign::<Gates>(&ceremony, &honest_shape, &salt),
    )
    .expect("well-formed");
    let pop = Pop::prove_unchecked(&sealed, &honest_shape, Gates::nth(0), &attacker.t)
        .expect("the attacker really does hold this one");

    let audited = audit(
        &CompositionArtifact::from_parts(
            sealed,
            owners.reveal(&sealed),
            ComponentReveal::from_parts(
                honest_shape.clone(),
                BTreeMap::from([(Gates::nth(0), pop)]),
                attacker.endorsement(&ceremony, &honest_shape, &attacker.t),
                salt,
            ),
        ),
        &attacker.parties(),
    )
    .expect("a component its publisher can open is accepted");

    assert_eq!(audited.root(), b_owner + attacker.t * G);
    assert_ne!(
        audited.root(),
        attacker.t * G,
        "the honest cohort is still in the sum: `t` alone does not open this root"
    );
}

// ---------------------------------------------------------------------------
// ATTEMPT 4: seal junk, wait for the reveal, grind, ask for a second proof.
// ---------------------------------------------------------------------------

/// **A cohort that seals a throwaway component and grinds after the other side
/// reveals has to ask its victim to prove a second time, and the victim
/// refuses.**
///
/// This is the attack that survives commit-then-reveal as a TYPE. Holding two
/// commitment values proves nothing about whether one of them had already been
/// opened, and [`ComponentCommitment::seal`] takes any claim, so a cohort can
/// commit to something it intends to discard. What it cannot do is make the
/// victim's proofs carry to the composition it actually wants -- the challenge
/// names both digests -- so the attack reduces entirely to step 5.
///
/// The refusal is at the SHARE, not in the artifact: nothing an auditor can see
/// distinguishes the resulting artifact from an honest one, which is why
/// [`prove_possession`] carries the rule and the module docs say the artifact
/// does not establish it.
///
/// Unlike the rogue-key attempts above, this one buys only a CHOICE among roots
/// the attacker can prove -- never a chosen discrete log. It is exhibited here
/// anyway, because "the type is the ordering rule" was the claim, and it is not.
#[test]
fn the_owners_refuse_a_second_composition_so_a_late_seal_has_nobody_to_prove_with() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x6217D);
    let ceremony = CeremonyId::draw("grind by re-proving", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);

    // STEP 1. The gates seal a component they intend to throw away. Nothing
    // stops them: the salt hides which claim a digest is over.
    let junk = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);
    let first = SealedComposition::new(ceremony, owners.commitment, junk.commitment)
        .expect("well-formed");

    // STEP 2. The owners follow the protocol exactly. `B_owner` is now public.
    let owner_reveal = owners.reveal(&first);
    let b_owner = owner_reveal.component();

    // STEP 3. With `B_owner` in hand the gates take as many draws as they like
    // and keep the one they prefer. Every draw is a genuine DKG, so every one is
    // provable; the choice is the only thing being bought.
    let draws: Vec<CohortSide<Gates>> = (0..8)
        .map(|_| CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng))
        .collect();
    let best = draws
        .iter()
        .min_by_key(|d| (b_owner + d.claim.component()).compress().to_bytes())
        .expect("eight draws");
    assert_ne!(
        best.claim.component(),
        draws[0].claim.component(),
        "the grind is real: the kept draw is not simply the first one"
    );

    // STEP 4. The composition the gates actually want an artifact over.
    let second = SealedComposition::new(ceremony, owners.commitment, best.commitment)
        .expect("well-formed");
    assert_ne!(second, first);

    // CONTROL, and the reason step 5 IS the attack: the owners' existing proofs
    // do not carry over, so the gates cannot simply reuse the reveal they have.
    assert_eq!(
        audit(
            &CompositionArtifact::from_parts(second, owner_reveal.clone(), best.reveal(&second)),
            &parties(),
        )
        .unwrap_err(),
        CeremonyError::PopFailed {
            cohort: "owners",
            participant: Owners::nth(0),
        },
        "the owners' first proofs must not verify under a second composition"
    );

    // STEP 5. So the gates tell the owners the first exchange failed and ask
    // them to prove again. Every owner refuses, by name.
    for share in &owners.shares {
        assert_eq!(
            prove_possession(&second, share).unwrap_err(),
            CeremonyError::ProofAlreadyIssued {
                cohort: "owners",
                participant: share.id(),
            }
        );
    }

    // CONTROL: the composition they already answered is still answered, because
    // a lost message is not an attack and a refusal there would be a liveness
    // bug rather than a defence.
    for share in &owners.shares {
        prove_possession(&first, share)
            .expect("idempotent for the composition already answered");
        assert_eq!(share.proved_under(), Some(first));
    }
}

// ---------------------------------------------------------------------------
// The other half of the exhibit: the honest cohort is no longer locked out.
// ---------------------------------------------------------------------------

/// `tests/rogue_key.rs::exhibit_the_honest_cohort_is_locked_out_of_its_own_address`
/// showed the honest cohort unable to spend an address it believed it
/// co-controlled. Inverted: the honest composition audits, and the address it
/// produces is the sum of both cohorts' components -- so the honest cohort's
/// contribution is in the key, not cancelled out of it.
///
/// That it can actually SIGN that address, end to end through the unmodified
/// MobileCoin verifier, is
/// `composition.rs::an_honest_composition_signs_and_verifies_through_the_mlsag_protocol`.
#[test]
fn the_honest_cohorts_contribution_survives_into_the_root() {
    let h = Honest::run(0xA11CE, &owners_spec(), &gates_spec());
    let audited = audit(&h.artifact, &parties()).expect("the honest composition audits");

    assert_eq!(
        audited.root(),
        h.owners.claim.component() + h.gates.claim.component()
    );
    // Neither component alone is the root, so neither cohort was cancelled.
    assert_ne!(audited.root(), h.owners.claim.component());
    assert_ne!(audited.root(), h.gates.claim.component());
}
