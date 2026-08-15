//! **Who produced this artifact.**
//!
//! Every other check in `ceremony` is a statement about KEY MATERIAL: that the
//! verification shares interpolate, that each seat proved knowledge of its
//! share, that each reveal opens its commitment. One process that runs both
//! cohorts' DKGs satisfies all of them, because it genuinely holds every share
//! of both cohorts -- so the published bytes could not distinguish a
//! composition between two organisations from a solo performance of one.
//!
//! [`one_process_can_produce_an_artifact_that_passes_every_structural_check`]
//! performs that gap before anything here closes it, and performs the harm as
//! well: the sole party reconstructs the whole root scalar out of the shares it
//! holds, so the address it published is one it can spend by itself.
//!
//! The rest of the file is the closure and its exact residual. Identity
//! signatures over the commitments, checked by [`audit`] against keys the funder
//! obtained FROM the two organisations, refuse that artifact -- unless the sole
//! party also holds both organisations' long-term private keys, which
//! [`the_residual_is_a_party_that_holds_both_organisations_identity_keys`]
//! performs rather than describes.
//!
//! The identity keys are `two_cohort::identity`, the same primitive
//! `crates/ceremony` signs its round messages with. There is no second identity
//! notion in this workspace.

mod common;

use common::{identity_of, parties, seal_and_sign, CohortSide, Honest};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, scalar::Scalar};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use two_cohort::{
    audit,
    ceremony::{
        ComponentCommitment, ComponentReveal, Parties, SealedComposition, SignedCommitment,
    },
    identity::{IdentityKey, IdentitySignature},
    CeremonyError, CeremonyId, CohortSpec, CompositionArtifact, ControlDomain, Gates, Owners,
};

fn owners_spec() -> CohortSpec<Owners> {
    CohortSpec::<Owners>::sequential(2, 3)
}

fn gates_spec() -> CohortSpec<Gates> {
    CohortSpec::<Gates>::sequential(2, 3)
}

/// Re-endorse an existing seal under a different identity key.
///
/// The DIGEST is untouched, so everything the commitment binds -- component,
/// roster, threshold, verification shares, salt -- is identical and the only
/// thing that changes is who says so. That is what makes the rejections below
/// attributable to the endorsement rather than to the contents.
fn endorsed_by(
    ceremony: &CeremonyId,
    signed: &SignedCommitment,
    key: &IdentityKey,
) -> SignedCommitment {
    SignedCommitment::create(ceremony, signed.commitment(), key)
}

/// The composite root scalar, reconstructed from one qualifying quorum of each
/// cohort.
///
/// Only a party that holds all of them can compute this, which is the point of
/// computing it: it is the difference between "two organisations control this
/// address" and "one process does".
fn sole_party_root(owners: &CohortSide<Owners>, gates: &CohortSide<Gates>) -> Scalar {
    let oq = owners.quorum(2);
    let gq = gates.quorum(2);
    let b_owner: Scalar = oq
        .iter()
        .map(|&id| *owners.share_of(id).term(&oq).expect("quorum member").weight())
        .sum();
    let b_gate: Scalar = gq
        .iter()
        .map(|&id| *gates.share_of(id).term(&gq).expect("quorum member").weight())
        .sum();
    b_owner + b_gate
}

/// A complete, otherwise-honest artifact whose GATE half is endorsed by
/// `gate_org` instead of by the gate organisation.
///
/// Fresh cohorts on every call, and that is not incidental: the two identities
/// are inside the proof-of-possession transcript, so a composition naming a
/// different gate organisation is a DIFFERENT composition, and a share answers
/// exactly one. Re-attributing an existing artifact's commitment without
/// re-proving therefore fails at the proofs rather than at the attribution --
/// which is itself a property, and the one
/// [`a_holders_proof_is_bound_to_the_counterparty_it_dealt_with`] is about.
/// Here the proofs are made under the composition being audited, so what the
/// audit rejects is the endorsement and nothing else.
fn artifact_with_gate_endorsed_by(seed: u64, gate_org: &IdentityKey) -> CompositionArtifact {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let ceremony = CeremonyId::draw("gate endorsement probe", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);
    let sealed = SealedComposition::new(
        ceremony,
        owners.commitment,
        endorsed_by(&ceremony, &gates.commitment, gate_org),
    )
    .expect("well-formed");
    CompositionArtifact::from_parts(sealed, owners.reveal(&sealed), gates.reveal(&sealed))
}

// ---------------------------------------------------------------------------
// THE GAP, performed.
// ---------------------------------------------------------------------------

/// **One process running both sides produces an artifact that satisfies every
/// check that is about key material, and the address it publishes is one that
/// process can spend alone.**
///
/// Nothing is faked here. Both DKGs are real
/// [`run_dkg`](two_cohort::dkg::run_dkg) runs, every proof of possession is
/// genuine, both commitments seal exactly what is revealed, the verification
/// shares interpolate at exactly the declared thresholds, and the rosters are
/// from disjoint control domains. The impostor satisfies all of it because it
/// really does hold every share -- which is also why the address is not jointly
/// controlled by anybody.
///
/// The second half of the test is the close: the same artifact, presented to a
/// funder holding the two organisations' published identity keys, is refused by
/// name.
#[test]
fn one_process_can_produce_an_artifact_that_passes_every_structural_check() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x501E);
    let ceremony = CeremonyId::draw("one process, both cohorts", &mut rng);

    // Both cohorts, generated by this one process. It keeps every share.
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);

    // ...and it endorses both halves with identity keys it made up itself,
    // because it has no access to either organisation's key.
    let fake_owners_key = IdentityKey::from_seed(&[0xF1; 32]);
    let fake_gates_key = IdentityKey::from_seed(&[0xF2; 32]);
    let sealed = SealedComposition::new(
        ceremony,
        endorsed_by(&ceremony, &owners.commitment, &fake_owners_key),
        endorsed_by(&ceremony, &gates.commitment, &fake_gates_key),
    )
    .expect("well-formed");

    let artifact = CompositionArtifact::from_parts(
        sealed,
        owners.reveal(&sealed),
        gates.reveal(&sealed),
    );

    // THE GAP. Audited against the impostor's OWN two keys -- which is exactly
    // the position of a funder that takes the keys out of the artifact, or of
    // an audit that has no keys at all -- every structural property holds.
    let self_attested = Parties::new(fake_owners_key.public(), fake_gates_key.public());
    let audited = audit(&artifact, &self_attested)
        .expect("the gap: one process satisfies every check about key material");

    let (o, g) = audited.structure();
    assert_eq!((o.threshold(), o.roster()), (2, owners_spec().ids()));
    assert_eq!((g.threshold(), g.roster()), (2, gates_spec().ids()));
    assert!(o.roster().iter().all(|id| !g.roster().contains(id)));
    assert_eq!(
        audited.root(),
        owners.claim.component() + gates.claim.component(),
        "the root really is the sum of two real cohorts' components"
    );

    // THE HARM, and it is not hypothetical. The sole party interpolates both
    // cohorts out of the shares it kept and holds the discrete log of the root
    // this artifact describes. Everything a funder could check said "two
    // rosters at two thresholds"; one process can spend it.
    let b = sole_party_root(&owners, &gates);
    assert_eq!(
        b * G,
        audited.root(),
        "the harm: one process holds the root's discrete log"
    );

    // THE CLOSE. The funder does not take the keys from the artifact; it holds
    // the two organisations' published keys. Under those, the same artifact is
    // refused, naming the cohort and both keys so a human knows who to ask.
    assert_eq!(
        audit(&artifact, &parties()).unwrap_err(),
        CeremonyError::CommitmentSignerUnexpected {
            cohort: "owners",
            expected: identity_of::<Owners>().public(),
            found: fake_owners_key.public(),
        }
    );

    // ...and it is refused on the gate side too, not merely on whichever side
    // is checked first: an artifact whose owner half IS genuinely endorsed but
    // whose gate half is not still fails, so the check is per-cohort rather than
    // one gate that a single honest half satisfies. Compromising one
    // organisation is not enough.
    assert_eq!(
        audit(
            &artifact_with_gate_endorsed_by(0x501F, &fake_gates_key),
            &parties()
        )
        .unwrap_err(),
        CeremonyError::CommitmentSignerUnexpected {
            cohort: "gates",
            expected: identity_of::<Gates>().public(),
            found: fake_gates_key.public(),
        }
    );
}

/// **The honest two-party ceremony audits under the two organisations' keys.**
///
/// The control for everything above and below: the refusals are refusals of the
/// attribution, not of the signature check being unsatisfiable.
#[test]
fn an_honest_two_party_ceremony_audits_under_the_two_organisations_keys() {
    let h = Honest::run(0xC0FFEE, &owners_spec(), &gates_spec());
    let audited = audit(&h.artifact, &parties()).expect("the honest artifact audits");

    let (o, g) = audited.structure();
    assert_eq!(o.identity(), &identity_of::<Owners>().public());
    assert_eq!(g.identity(), &identity_of::<Gates>().public());

    // The endorsements in the artifact really are over the commitments the two
    // cohorts published, so a funder that also saw the commit broadcast is
    // comparing signed values rather than bare hashes.
    let (owner_signed, gate_signed) = h.artifact.commitments();
    assert_eq!(owner_signed, h.owners.commitment);
    assert_eq!(gate_signed, h.gates.commitment);
    assert_eq!(
        owner_signed.commitment(),
        h.owner_reveal.commitment(&h.ceremony)
    );
}

// ---------------------------------------------------------------------------
// An endorsement that is not one.
// ---------------------------------------------------------------------------

/// **A commitment carrying the expected key but no signature behind it is a
/// typed error, distinct from one signed by the wrong party.**
///
/// This is the attacker that knows exactly which keys the funder will check
/// against and writes them into the artifact. It cannot produce the signature,
/// so the two failures are separated: [`CeremonyError::CommitmentSignerUnexpected`]
/// is a commitment somebody else endorsed,
/// [`CeremonyError::CommitmentSignatureInvalid`] is one nobody did.
///
/// The CONTROL is the identical artifact with the genuine endorsement, which
/// audits -- so what is rejected is the signature and not the surrounding
/// composition.
#[test]
fn a_commitment_the_expected_party_did_not_sign_is_refused() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5169);
    let ceremony = CeremonyId::draw("unsigned commitment", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);

    // The gate commitment, with the real gate organisation's key named and the
    // signature replaced by zeroes. Every other byte of the composition is the
    // honest one, INCLUDING the digest -- so the proofs below are made under a
    // composition the honest side would also have produced.
    let unsigned = SignedCommitment::from_parts(
        gates.commitment.commitment(),
        identity_of::<Gates>().public(),
        IdentitySignature([0u8; 64]),
    );
    let sealed = SealedComposition::new(ceremony, owners.commitment, unsigned)
        .expect("well-formed");

    let artifact =
        CompositionArtifact::from_parts(sealed, owners.reveal(&sealed), gates.reveal(&sealed));
    assert_eq!(
        audit(&artifact, &parties()).unwrap_err(),
        CeremonyError::CommitmentSignatureInvalid {
            cohort: "gates",
            signer: identity_of::<Gates>().public(),
        }
    );

    // CONTROL: the same digest with the genuine endorsement audits. The proofs
    // are re-made because the composition differs -- the identities are in the
    // proof transcript -- so a fresh pair of cohorts is generated for it, and
    // both cohorts are ordinary honest ones.
    let mut rng = ChaCha20Rng::seed_from_u64(0x516A);
    let ceremony = CeremonyId::draw("unsigned commitment control", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);
    let sealed = SealedComposition::new(ceremony, owners.commitment, gates.commitment)
        .expect("well-formed");
    audit(
        &CompositionArtifact::from_parts(sealed, owners.reveal(&sealed), gates.reveal(&sealed)),
        &parties(),
    )
    .expect("control: the same shape, genuinely endorsed, audits");
}

/// **An endorsement is bound to the ceremony, the cohort and the digest, so a
/// genuine signature by the right organisation still does not transplant.**
///
/// Three transplants, each a signature the named key really did produce:
///
///   * the gate organisation's signature over the OWNER slot's digest;
///   * the gate organisation's signature over the same claim under a DIFFERENT
///     ceremony id;
///   * the owner organisation's signature over the gate digest, presented with
///     the owners named as the signer.
///
/// The first two are [`CeremonyError::CommitmentSignatureInvalid`] -- the key is
/// the expected one, the message is not. The third is
/// [`CeremonyError::CommitmentSignerUnexpected`], because the artifact is
/// honest about who signed it and that party is not the gate organisation.
#[test]
fn a_genuine_endorsement_of_something_else_does_not_transplant() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x7A11);
    let ceremony = CeremonyId::draw("transplanted endorsement", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);
    let sealed = SealedComposition::new(ceremony, owners.commitment, gates.commitment)
        .expect("well-formed");
    let owner_reveal = owners.reveal(&sealed);
    let gate_reveal = gates.reveal(&sealed);

    // CONTROL: untouched, this audits. Asserted first so that each transplant
    // below differs from an accepted artifact in exactly one field.
    audit(
        &CompositionArtifact::from_parts(sealed, owner_reveal.clone(), gate_reveal.clone()),
        &parties(),
    )
    .expect("control: the untransplanted artifact audits");

    let cross_slot = SignedCommitment::from_parts(
        gates.commitment.commitment(),
        identity_of::<Gates>().public(),
        // A real signature by the gate organisation -- over the OWNER digest.
        *endorsed_by(&ceremony, &owners.commitment, &identity_of::<Gates>()).signature(),
    );

    let elsewhere = CeremonyId::draw("some other composition", &mut rng);
    let cross_ceremony = SignedCommitment::from_parts(
        gates.commitment.commitment(),
        identity_of::<Gates>().public(),
        // A real signature by the gate organisation over this same digest, made
        // in a different ceremony.
        *SignedCommitment::create(
            &elsewhere,
            gates.commitment.commitment(),
            &identity_of::<Gates>(),
        )
        .signature(),
    );

    // Both forgeries keep the gate organisation named as the signer, so the
    // proof-of-possession transcript is unchanged (it absorbs the signer KEYS,
    // not the signature bytes -- see `absorb_composition`) and the honest
    // reveals still carry. The audit therefore reaches the signature check,
    // which is what these two cases are about.
    for (what, forged) in [("cross-slot", cross_slot), ("cross-ceremony", cross_ceremony)] {
        let artifact = CompositionArtifact::from_parts(
            SealedComposition::new(ceremony, owners.commitment, forged).expect("well-formed"),
            owner_reveal.clone(),
            gate_reveal.clone(),
        );
        assert_eq!(
            audit(&artifact, &parties()).unwrap_err(),
            CeremonyError::CommitmentSignatureInvalid {
                cohort: "gates",
                signer: identity_of::<Gates>().public(),
            },
            "{what} endorsement must not verify"
        );
    }

    // The third: honestly attributed to the owner organisation, which is not
    // who a funder expects on the gate side. Built from its own cohorts, so the
    // proofs are made under this composition and the rejection is the
    // attribution rather than a stale transcript.
    assert_eq!(
        audit(
            &artifact_with_gate_endorsed_by(0x7A12, &identity_of::<Owners>()),
            &parties()
        )
        .unwrap_err(),
        CeremonyError::CommitmentSignerUnexpected {
            cohort: "gates",
            expected: identity_of::<Gates>().public(),
            found: identity_of::<Owners>().public(),
        }
    );
}

// ---------------------------------------------------------------------------
// The identities are in the proof transcript, not beside it.
// ---------------------------------------------------------------------------

/// **A holder's proof of possession names its counterparty, so an honest
/// cohort's reveal cannot be re-attributed to a different organisation.**
///
/// The two compositions here carry BYTE-IDENTICAL digests: the same two seals,
/// the same salts, the same claims. They differ in exactly one thing -- who the
/// gate half is attributed to -- and that is asserted, so the rejection cannot
/// be a commitment mismatch in disguise.
///
/// Without the identities in [`pop_challenge`], the owners' reveal would carry
/// unchanged into a composition naming some other organisation as the gate, and
/// that organisation would only have to be willing to endorse the same digest.
/// The owners would then appear to have jointly generated an address with a
/// party they never dealt with.
#[test]
fn a_holders_proof_is_bound_to_the_counterparty_it_dealt_with() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xC0DA);
    let ceremony = CeremonyId::draw("counterparty binding", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);

    let other_gate_org = IdentityKey::from_seed(&[0xA9; 32]);
    let dealt_with = SealedComposition::new(ceremony, owners.commitment, gates.commitment)
        .expect("well-formed");
    let re_attributed = SealedComposition::new(
        ceremony,
        owners.commitment,
        endorsed_by(&ceremony, &gates.commitment, &other_gate_org),
    )
    .expect("well-formed");

    assert_ne!(dealt_with, re_attributed);
    assert_eq!(
        dealt_with.commitments().1.commitment(),
        re_attributed.commitments().1.commitment(),
        "the two compositions seal the identical gate commitment: only the \
         organisation it is attributed to differs"
    );

    // The owners prove possession under the composition they were shown, which
    // names the real gate organisation.
    let owner_pops = owners.pops(&dealt_with);
    // CONTROL: those proofs are genuine under that composition.
    ComponentReveal::assemble(
        &dealt_with,
        owners.claim.clone(),
        owner_pops.clone(),
        owners.salt,
    )
    .expect("control: the owners' proofs verify under the composition they were made for");
    let owner_reveal =
        ComponentReveal::from_parts(owners.claim.clone(), owner_pops, owners.salt);

    // The gate shares have not proved yet, so they answer the re-attributed
    // composition -- which is what a colluding second organisation would do.
    let gate_reveal = gates.reveal(&re_attributed);

    // A funder holding the OTHER organisation's key: the attribution check
    // passes, because the artifact honestly says who signed the gate half. What
    // refuses it is the owners' proofs, which were never made under a
    // composition naming that party.
    let artifact =
        CompositionArtifact::from_parts(re_attributed, owner_reveal, gate_reveal);
    assert_eq!(
        audit(
            &artifact,
            &Parties::new(identity_of::<Owners>().public(), other_gate_org.public())
        )
        .unwrap_err(),
        CeremonyError::PopFailed {
            cohort: "owners",
            participant: Owners::nth(0),
        },
        "the owners never proved possession in a composition with this counterparty"
    );
}

/// **One share does not answer two differently-attributed compositions with one
/// nonce.**
///
/// The counterpart of
/// `composition.rs::one_nonce_does_not_answer_two_claims`, for the input this
/// file added. The proof's challenge names both organisations, so the derived
/// nonce must too: a holder induced to prove under two compositions that seal
/// the IDENTICAL digests but attribute the other half to different parties would
/// otherwise emit one `R` against two challenges, and its share falls out by
/// division from public data. That arithmetic is performed in the composition.rs
/// test and is not repeated here; what is checked here is that the nonce moves.
///
/// The CONTROL is that determinism itself is intact -- the same composition
/// twice is byte-for-byte the same proof -- so the difference below is the
/// attribution and not a fresh random draw.
#[test]
fn one_nonce_does_not_answer_two_differently_attributed_compositions() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xB1AD);
    let ceremony = CeremonyId::draw("nonce binding to parties", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);

    // A gate claim from secrets this test chooses, so `Pop::prove` can be called
    // directly with the raw share -- the one-proof rule lives on `CohortShare`
    // and would otherwise stop the second call before the nonce is reached.
    let roster = vec![Gates::nth(0), Gates::nth(1)];
    let secrets: Vec<Scalar> = (0..2).map(|_| Scalar::random(&mut rng)).collect();
    let claim = two_cohort::ComponentClaim::from_parts(
        "gates",
        2,
        roster.clone(),
        secrets[0] * G, // any point; the nonce derivation does not check it
        secrets.iter().map(|s| s * G).collect(),
    );
    let gate_seal = seal_and_sign::<Gates>(&ceremony, &claim, &[0x31; 32]);

    // Two compositions with identical digests on BOTH sides. Only the owner
    // half's attribution differs.
    let other_owner_org = IdentityKey::from_seed(&[0xB4; 32]);
    let a = SealedComposition::new(ceremony, owners.commitment, gate_seal).expect("well-formed");
    let b = SealedComposition::new(
        ceremony,
        endorsed_by(&ceremony, &owners.commitment, &other_owner_org),
        gate_seal,
    )
    .expect("well-formed");
    assert_eq!(
        a.commitments().0.commitment(),
        b.commitments().0.commitment(),
        "the two compositions seal identical commitments"
    );

    let pa = two_cohort::Pop::prove_unchecked(&a, &claim, Gates::nth(0), &secrets[0]).expect("opens its own");
    let pb = two_cohort::Pop::prove_unchecked(&b, &claim, Gates::nth(0), &secrets[0]).expect("opens its own");
    assert_ne!(
        pa.nonce_public(),
        pb.nonce_public(),
        "two attributions must not share a nonce"
    );

    // CONTROL: the same composition twice is the same proof.
    assert_eq!(
        two_cohort::Pop::prove_unchecked(&a, &claim, Gates::nth(0), &secrets[0]).expect("again"),
        pa
    );
}

// ---------------------------------------------------------------------------
// What the audit hands back.
// ---------------------------------------------------------------------------

/// **The audit returns the rosters, thresholds, identities and components it
/// established, so a caller compares values instead of reaching into the
/// artifact.**
///
/// The comparison is shown to be non-vacuous: a second honest ceremony at a
/// different gate shape produces a structure that differs, so `==` here is
/// deciding something.
#[test]
fn the_audit_returns_the_rosters_and_thresholds_it_established() {
    let h = Honest::run(0xC0FFEE, &owners_spec(), &gates_spec());
    let audited = audit(&h.artifact, &parties()).expect("audits");
    let (o, g) = audited.structure();

    assert_eq!(o.cohort(), "owners");
    assert_eq!(o.threshold(), 2);
    assert_eq!(o.roster(), owners_spec().ids());
    assert_eq!(o.identity(), &identity_of::<Owners>().public());
    assert_eq!(o.component(), h.owners.claim.component());

    assert_eq!(g.cohort(), "gates");
    assert_eq!(g.threshold(), 2);
    assert_eq!(g.roster(), gates_spec().ids());
    assert_eq!(g.identity(), &identity_of::<Gates>().public());
    assert_eq!(g.component(), h.gates.claim.component());

    assert_eq!(o.component() + g.component(), audited.root());

    // Non-vacuous: a 3-of-4 gate cohort is a different structure, and the
    // caller sees it without opening the artifact.
    let other = Honest::run(0xDECAF, &owners_spec(), &CohortSpec::<Gates>::sequential(3, 4));
    let other_audited = audit(&other.artifact, &parties()).expect("audits");
    let (_, other_gates) = other_audited.structure();
    assert_ne!(other_gates, g);
    assert_eq!(other_gates.threshold(), 3);
    assert_eq!(other_gates.roster().len(), 4);
}

// ---------------------------------------------------------------------------
// The residual, performed.
// ---------------------------------------------------------------------------

/// **A party that holds BOTH organisations' identity private keys produces an
/// artifact that audits, while holding every share of both cohorts.**
///
/// This is the exact limit of what commitment signatures buy, and it is
/// performed rather than described because a limitation nobody has executed is
/// a limitation nobody has measured. The audit's statement is *these two keys
/// endorsed these two halves*; it is not, and cannot be, *two independent
/// organisations were in the room*.
///
/// So what a funder actually gets is a change of the thing it must trust: from
/// "somebody says these are two cohorts" to "whoever produced this holds the
/// long-term keys of both named organisations". Key custody is a question a
/// funder can put to an organisation. Bare bytes were not.
#[test]
fn the_residual_is_a_party_that_holds_both_organisations_identity_keys() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x8071);
    let ceremony = CeremonyId::draw("both keys in one hand", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);

    // One process: both DKGs, both seals, and -- the assumption being made
    // explicit -- both organisations' signing keys.
    let sealed = SealedComposition::new(ceremony, owners.commitment, gates.commitment)
        .expect("well-formed");
    let artifact =
        CompositionArtifact::from_parts(sealed, owners.reveal(&sealed), gates.reveal(&sealed));

    let audited = audit(&artifact, &parties())
        .expect("the residual: with both identity keys, this passes");

    // And it is the same harm as in the first test: the sole party holds the
    // root's discrete log while the audit reports two rosters at two
    // thresholds.
    assert_eq!(sole_party_root(&owners, &gates) * G, audited.root());
    let (o, g) = audited.structure();
    assert_eq!((o.threshold(), g.threshold()), (2, 2));
}

/// **One organisation endorsing both cohorts is refused, and the refusal is the
/// only thing separating it from the residual above.**
///
/// The residual test one above passes: a sole party holding two DISTINCT
/// identity keys signs both halves and the audit certifies two cohorts. That is
/// as far as signatures can reach, and it is stated as the limit.
///
/// This is the case one step further down, and it was accepted until now. A
/// funder that names the SAME key for both cohorts gets an `AuditedRoot` whose
/// two `CohortStructure`s report the same `identity()` -- an audit that says
/// "these two organisations jointly control the root" about one organisation.
///
/// The construction is deliberately minimal so that the refusal is attributable
/// to the funder's input and to nothing about the artifact. Both commitments
/// carry the honest cohorts' own digests; only the endorsing key is changed, and
/// both proofs of possession are produced UNDER the composition being audited,
/// so the transcript binding is satisfied rather than broken.
///
/// Two controls make the refusal non-vacuous:
///
///   * the identical artifact under a funder naming two distinct keys, one of
///     which is the sole key -- it reaches attribution and is refused there, on
///     the OTHER cohort, which is evidence that the endorsements really are the
///     one key rather than something malformed earlier;
///   * the sole party's root, reconstructed, which is the harm the audit would
///     otherwise certify away.
#[test]
fn one_organisation_named_for_both_cohorts_is_refused() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x1D0C);
    let ceremony = CeremonyId::draw("one organisation, two hats", &mut rng);
    let owners = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);

    // The single organisation. It holds every share of both cohorts and one
    // long-term key, and it endorses both halves with it.
    let sole = IdentityKey::from_seed(&[0x5E; 32]);
    let sealed = SealedComposition::new(
        ceremony,
        endorsed_by(&ceremony, &owners.commitment, &sole),
        endorsed_by(&ceremony, &gates.commitment, &sole),
    )
    .expect("well-formed");
    let artifact =
        CompositionArtifact::from_parts(sealed, owners.reveal(&sealed), gates.reveal(&sealed));

    // The harm, performed: one party holds the discrete log of the root the
    // audit would report.
    assert_eq!(
        sole_party_root(&owners, &gates) * G,
        artifact.declared_root(),
    );

    assert_eq!(
        audit(&artifact, &Parties::new(sole.public(), sole.public())).unwrap_err(),
        CeremonyError::PartiesNotDistinct { key: sole.public() },
    );

    // Control one: the same artifact, a funder naming two distinct keys. It gets
    // past the distinctness check and is refused at attribution -- on `gates`,
    // whose commitment really is endorsed by `sole`.
    assert_eq!(
        audit(
            &artifact,
            &Parties::new(sole.public(), identity_of::<Gates>().public()),
        )
        .unwrap_err(),
        CeremonyError::CommitmentSignerUnexpected {
            cohort: Gates::NAME,
            expected: identity_of::<Gates>().public(),
            found: sole.public(),
        },
    );

    // Control two: **one artifact, two `Parties` values.** The same sole party
    // holds every share of both cohorts and both identity keys, and endorses the
    // two halves under two DISTINCT keys. That one artifact is then audited
    // twice, and the ONLY thing that differs between the two calls is what the
    // funder named:
    //
    //   Parties::new(sole, sole)   -> PartiesNotDistinct
    //   Parties::new(sole, other)  -> Ok, the residual
    //
    // An earlier version of this control built a second artifact from fresh
    // DKGs, fresh components, fresh proofs and a fresh signer, and claimed
    // "everything else is identical" -- which review pointed out was false. Two
    // audits of one value is the isolation the claim needs.
    //
    // Fresh cohorts are still needed to BUILD this artifact, because a share
    // answers exactly one sealed composition and the ones above have answered
    // theirs. The isolation is between the two audits, not between the two
    // artifacts.
    let other = IdentityKey::from_seed(&[0x5F; 32]);
    let owners2 = CohortSide::<Owners>::generate(&ceremony, &owners_spec(), &mut rng);
    let gates2 = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);
    let sealed2 = SealedComposition::new(
        ceremony,
        endorsed_by(&ceremony, &owners2.commitment, &sole),
        endorsed_by(&ceremony, &gates2.commitment, &other),
    )
    .expect("well-formed");
    let artifact2 =
        CompositionArtifact::from_parts(sealed2, owners2.reveal(&sealed2), gates2.reveal(&sealed2));

    assert_eq!(
        audit(&artifact2, &Parties::new(sole.public(), sole.public())).unwrap_err(),
        CeremonyError::PartiesNotDistinct { key: sole.public() },
        "the degenerate naming is refused before the artifact is read at all",
    );
    let audited2 = audit(&artifact2, &Parties::new(sole.public(), other.public()))
        .expect("the SAME artifact, named honestly: two distinct keys in one hand \
                 is the residual, and it still passes");
    assert_eq!(
        sole_party_root(&owners2, &gates2) * G,
        audited2.root(),
        "and the residual is the same harm: one party, one root scalar",
    );
}

// The claim that this crate and `crates/ceremony` share ONE identity primitive
// rather than holding two copies is checked from the other side, in
// `crates/ceremony/tests/identity_kat.rs::the_identity_primitive_is_two_cohorts_own`.
// It has to be there: `ceremony` depends on `two-cohort`, so only `ceremony` can
// see both types at once, and a dev-dependency back the other way would be a
// cycle that forces this workspace's pinned lockfile to re-resolve.

// ---------------------------------------------------------------------------
// The hand-built path used by the other test files.
// ---------------------------------------------------------------------------

/// `common::seal_and_sign` produces exactly what an honest cohort publishes.
///
/// The consistency and threshold tests in `composition.rs` build claims by hand
/// and go through that helper. Pinning it against a real cohort's own published
/// commitment is what stops those tests from drifting onto a path the honest
/// protocol does not take -- an artifact endorsed by a key nobody audits
/// against, say, which would make their rejections say less than they appear to.
///
/// **The expected value is spelled out from the crate's own primitives, not
/// taken from the helper.** The earlier version of this test compared
/// `seal_and_sign(ceremony, claim, salt)` against `CohortSide::generate`'s
/// `commitment` -- which `generate` had built by calling `seal_and_sign` on the
/// same three arguments. Both sides were the same function on the same inputs,
/// so it asserted only that Ed25519 signing is deterministic: mutating
/// `seal_and_sign` to seal under a fixed wrong salt AND sign with the wrong
/// organisation's key left it passing while seven other tests in this file
/// failed.
#[test]
fn the_hand_built_seal_matches_what_an_honest_cohort_publishes() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x4A11);
    let ceremony = CeremonyId::draw("hand-built claim", &mut rng);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gates_spec(), &mut rng);

    // Written out without going through `seal_and_sign`: seal the cohort's own
    // claim under the cohort's own salt, and endorse it with the gate
    // organisation's key. This is the honest protocol's own sequence, and it is
    // what `seal_and_sign` must equal.
    //
    // It is independent of `seal_and_sign`, which is the helper under test --
    // not of `common` wholesale: the claim, the salt and `identity_of::<Gates>`
    // still come from the harness, and they are the inputs, not the operation.
    let expected = SignedCommitment::create(
        &ceremony,
        ComponentCommitment::seal(&ceremony, &gates.claim, &gates.salt),
        &identity_of::<Gates>(),
    );

    // The helper agrees with the spelled-out sequence...
    assert_eq!(
        seal_and_sign::<Gates>(&ceremony, &gates.claim, &gates.salt),
        expected,
    );
    // ...and the honest cohort's own published commitment agrees with both, so
    // the hand-built path and the DKG path meet.
    assert_eq!(gates.commitment, expected);

    // Non-vacuous in the two directions the doc claims. A different salt is a
    // different seal, and a key nobody audits against is a different
    // endorsement -- so a helper that drifted on either would be caught here
    // rather than only in whichever test happened to notice.
    assert_ne!(
        SignedCommitment::create(
            &ceremony,
            ComponentCommitment::seal(&ceremony, &gates.claim, &[0xA5; 32]),
            &identity_of::<Gates>(),
        ),
        expected,
    );
    assert_ne!(
        SignedCommitment::create(
            &ceremony,
            ComponentCommitment::seal(&ceremony, &gates.claim, &gates.salt),
            &IdentityKey::from_seed(&[0x99; 32]),
        ),
        expected,
    );
}
