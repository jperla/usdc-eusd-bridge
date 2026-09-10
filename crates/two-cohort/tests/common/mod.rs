//! Shared harness: one honest composition ceremony, driven end to end.
//!
//! Only the sequence lives here. Every ASSERTION is in the test that makes the
//! claim, so nothing in this file can quietly assert itself, and every check
//! that decides a test's outcome is visible in that test.

#![allow(dead_code)]

use curve25519_dalek::scalar::Scalar;
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use two_cohort::{
    ceremony::{
        draw_salt, endorse_seat, prove_possession, ComponentClaim, ComponentCommitment,
        ComponentReveal, CompositionArtifact, Parties, Pop, SealedComposition, SeatEndorsement,
        SeatRoster, SignedCommitment,
    },
    dkg::{run_dkg, CohortShare},
    identity::{IdentityKey, IdentityPublic},
    CeremonyId, CohortSpec, ControlDomain, Gates, Owners,
};

/// The subaddress the bridge publishes for a depositor.
pub const SUBADDRESS: u64 = 7;

/// The long-term identity key of the organisation running cohort `C` in these
/// tests.
///
/// Fixed rather than drawn, and keyed on the cohort NAME rather than on the
/// ceremony, because that is what an organisation's identity key is: the same
/// key across every ceremony it takes part in. A test that wants a key an
/// organisation does NOT hold makes its own -- see `tests/attribution.rs`.
pub fn identity_of<C: ControlDomain>() -> IdentityKey {
    // Distinct seeds, so the two organisations are two KEYS. Whether they are
    // two organisations is not something a fixture can arrange -- this process
    // holds both. The values are arbitrary; that they DIFFER is not.
    if C::NAME == Owners::NAME {
        IdentityKey::from_seed(&[0x01; 32])
    } else {
        IdentityKey::from_seed(&[0x02; 32])
    }
}

/// The long-term identity key of the party holding seat `id` of cohort `C`.
///
/// One key per SEAT, not per cohort. Fixed rather than drawn for
/// [`identity_of`]'s reason -- a seat-holder's key is the same key across every
/// ceremony it takes part in -- and derived from the id so that the seats are
/// four different KEYS. Not four different parties: one process owns every seed
/// in this file, which is exactly the residual `tests/seat_identity.rs`
/// performs, and a fixture cannot manufacture a fact about the world. The seed
/// pattern is disjoint from the two organisation seeds above, so no seat key is
/// accidentally an organisation key.
pub fn seat_key_of<C: ControlDomain>(id: u64) -> IdentityKey {
    let mut seed = [0xA5u8; 32];
    seed[..8].copy_from_slice(&id.to_le_bytes());
    IdentityKey::from_seed(&seed)
}

/// The seat roster a funder holds for cohort `C` at `spec`'s shape.
pub fn seats_for<C: ControlDomain>(spec: &CohortSpec<C>) -> SeatRoster<C> {
    seats_over::<C>(spec.ids())
}

/// The seat roster over an explicit list of ids, for the tests that build a
/// cohort by hand rather than from a [`CohortSpec`].
pub fn seats_over<C: ControlDomain>(ids: &[u64]) -> SeatRoster<C> {
    SeatRoster::<C>::new(ids.iter().map(|&id| (id, seat_key_of::<C>(id).public())))
        .expect("the ids come from a control domain and do not repeat")
}

/// The seat keys for `ids`, in `ids` order -- the parallel vector a
/// [`ComponentClaim`] carries.
pub fn seat_keys_over<C: ControlDomain>(ids: &[u64]) -> Vec<IdentityPublic> {
    ids.iter().map(|&id| seat_key_of::<C>(id).public()).collect()
}

/// Every seat's PRIVATE identity key, which is what [`run_dkg`] needs in order
/// to drive every participant of a cohort from one process.
///
/// That this file can build it is the residual, not a convenience: a single
/// process holding every seat's long-term key can run the whole DKG, and
/// `tests/dkg.rs::a_party_that_holds_every_seat_key_still_runs_the_whole_dkg_alone`
/// performs exactly that. The harness needs it because the harness IS that
/// process.
pub fn seat_identities_over<C: ControlDomain>(
    ids: &[u64],
) -> std::collections::HashMap<u64, IdentityKey> {
    ids.iter().map(|&id| (id, seat_key_of::<C>(id))).collect()
}

/// [`seat_identities_over`] at a spec's shape.
pub fn seat_identities_for<C: ControlDomain>(
    spec: &CohortSpec<C>,
) -> std::collections::HashMap<u64, IdentityKey> {
    seat_identities_over::<C>(spec.ids())
}

/// Everyone a funder auditing an artifact of THIS shape holds a key for: the
/// two organisations and every seat.
pub fn parties_for(owners: &CohortSpec<Owners>, gates: &CohortSpec<Gates>) -> Parties {
    Parties::new(
        identity_of::<Owners>().public(),
        seats_for::<Owners>(owners),
        identity_of::<Gates>().public(),
        seats_for::<Gates>(gates),
    )
}

/// [`parties_for`] over explicit id lists, for the tests that build a cohort by
/// hand at a shape no [`CohortSpec`] in the file describes.
pub fn parties_over(owner_ids: &[u64], gate_ids: &[u64]) -> Parties {
    Parties::new(
        identity_of::<Owners>().public(),
        seats_over::<Owners>(owner_ids),
        identity_of::<Gates>().public(),
        seats_over::<Gates>(gate_ids),
    )
}

/// The funder's keys for the shape most of these tests use: 2-of-3 owners and
/// 1-of-1 gates.
///
/// A convenience over [`parties_for`], and NOT a default: a `Parties` names
/// seats, so it is only meaningful against a matching roster. A test at another
/// shape must build its own, which is the point -- an audit run with the wrong
/// seat roster now fails, and silently reusing this one would hide that.
pub fn parties() -> Parties {
    parties_for(
        &CohortSpec::<Owners>::sequential(2, 3),
        &CohortSpec::<Gates>::sequential(1, 1),
    )
}

/// Every seat's linked endorsement of its own verification share, made with
/// that seat's own identity key AND the share behind it.
///
/// `secrets` is parallel to the claim's roster. It is a PARAMETER because an
/// endorsement is no longer something a fixture can produce from public data:
/// since `endorse_seat` began proving knowledge of the share, a caller that has
/// no share has nothing to pass, which is the property under test in
/// `seat_identity.rs` and `seat_forgery.rs`. Every test that builds a claim by
/// hand already holds the secrets it dealt.
pub fn seat_endorsements<C: ControlDomain>(
    ceremony: &CeremonyId,
    claim: &ComponentClaim,
    secrets: &[Scalar],
) -> std::collections::BTreeMap<u64, SeatEndorsement> {
    assert_eq!(
        secrets.len(),
        claim.roster().len(),
        "one share per seat: a fixture that endorses without them is the forgery, not the harness",
    );
    claim
        .roster()
        .iter()
        .zip(secrets)
        .map(|(&id, secret)| {
            (
                id,
                endorse_seat(ceremony, claim, id, &seat_key_of::<C>(id), secret)
                    .expect("the fixture's seat keys and shares are the ones in the claim"),
            )
        })
        .collect()
}

pub fn identity_public<C: ControlDomain>() -> IdentityPublic {
    identity_of::<C>().public()
}

/// A holder's own share scalar, recovered from public material.
///
/// `CohortShare::secret` is `pub(crate)`, so this is how a holder outside the
/// crate reaches its own secret -- and it is not a trick: the roster is public,
/// the evaluation points are `1..=n` by position as `dkg` documents, and
/// `lagrange_at_zero` is a public function of those.
/// `composition.rs::a_holder_can_recover_its_own_share_through_public_api` is
/// the test that owns this property.
///
/// It lives here rather than in one test file because the seat endorsement now
/// needs a share as well as a key, so every test that endorses a hand-built
/// claim over a DKG'd cohort's verification shares needs the scalar. Note what
/// that means and does not mean: the recovery is a HOLDER's, not an outsider's
/// -- `term` comes off a secret-bearing `CohortShare` -- so a test using it is
/// modelling a party that holds the share, which is exactly the party a linked
/// endorsement is supposed to be available to.
pub fn own_share_scalar<C: ControlDomain>(side: &CohortSide<C>, id: u64) -> Scalar {
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
    let lambda = two_cohort::lagrange_at_zero(mine, &points).expect("public arithmetic");

    let recovered = *share
        .term(&quorum)
        .expect("a quorum member's own term")
        .weight()
        * lambda.invert();
    assert_eq!(
        recovered * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT,
        side.claim.verification_share(id).expect("on the roster"),
        "the recovered scalar opens this seat's published verification share",
    );
    recovered
}

/// Every seat's share scalar of a DKG'd cohort, in roster order.
///
/// The parallel vector [`seat_endorsements`] takes.
pub fn own_share_scalars<C: ControlDomain>(side: &CohortSide<C>) -> Vec<Scalar> {
    side.claim
        .roster()
        .iter()
        .map(|&id| own_share_scalar(side, id))
        .collect()
}

/// Seal a claim and endorse it as cohort `C`'s organisation.
///
/// For the tests that build a claim by hand rather than from a DKG: sealing and
/// signing travel together, because a commitment nobody endorsed is not
/// something the honest protocol ever produces.
pub fn seal_and_sign<C: ControlDomain>(
    ceremony: &CeremonyId,
    claim: &ComponentClaim,
    salt: &[u8; 32],
) -> SignedCommitment {
    SignedCommitment::create(
        ceremony,
        ComponentCommitment::seal(ceremony, claim, salt),
        &identity_of::<C>(),
    )
}

/// One cohort's DKG output plus the salt it sealed under.
pub struct CohortSide<C: ControlDomain> {
    pub shares: Vec<CohortShare<C>>,
    pub claim: ComponentClaim,
    pub salt: [u8; 32],
    /// The seal, endorsed by this cohort's organisation.
    pub commitment: SignedCommitment,
    /// Each seat's linked endorsement of its own verification share.
    pub endorsements: std::collections::BTreeMap<u64, SeatEndorsement>,
    pub ceremony: CeremonyId,
}

impl<C: ControlDomain> CohortSide<C> {
    /// Run this cohort's DKG, seal its component, and sign the seal as its
    /// organisation.
    pub fn generate(ceremony: &CeremonyId, spec: &CohortSpec<C>, rng: &mut ChaCha20Rng) -> Self {
        let shares = run_dkg::<C, _>(
            ceremony,
            spec,
            &seats_for::<C>(spec),
            &seat_identities_for::<C>(spec),
            rng,
        )
        .expect("honest dkg");
        let claim = ComponentClaim::of(shares[0].key());
        let salt = draw_salt(rng);
        let commitment = seal_and_sign::<C>(ceremony, &claim, &salt);
        // Each seat endorses for itself, through the checked holder entry point,
        // so the harness produces what a deployment would rather than a shortcut
        // around it. That entry point is on `CohortShare`, which is what makes
        // the honest path the one where the endorser holds the share.
        let endorsements = shares
            .iter()
            .map(|s| {
                (
                    s.id(),
                    s.endorse(ceremony, &claim, &seat_key_of::<C>(s.id()))
                        .expect("each seat holds the key AND the share the claim attributes to it"),
                )
            })
            .collect();
        CohortSide {
            shares,
            claim,
            salt,
            commitment,
            endorsements,
            ceremony: *ceremony,
        }
    }

    /// Every participant's proof of possession, under `sealed`.
    ///
    /// `prove_possession` answers ONE sealed composition per share, so a test
    /// that wants proofs from this cohort under a second one must build a fresh
    /// `CohortSide`. That is the rule under test, not an inconvenience to work
    /// around, so there is no bypass here.
    pub fn pops(&self, sealed: &SealedComposition) -> std::collections::BTreeMap<u64, Pop> {
        self.shares
            .iter()
            .map(|s| {
                (
                    s.id(),
                    prove_possession(sealed, s).expect("this share has not proved before"),
                )
            })
            .collect()
    }

    /// Every participant's proof, or the first refusal.
    pub fn try_pops(
        &self,
        sealed: &SealedComposition,
    ) -> Result<std::collections::BTreeMap<u64, Pop>, two_cohort::CeremonyError> {
        self.shares
            .iter()
            .map(|s| Ok((s.id(), prove_possession(sealed, s)?)))
            .collect()
    }

    /// This cohort's reveal, under `sealed`.
    pub fn reveal(&self, sealed: &SealedComposition) -> ComponentReveal {
        ComponentReveal::assemble(
            sealed,
            self.claim.clone(),
            self.pops(sealed),
            self.endorsements.clone(),
            self.salt,
        )
        .expect("honest cohort's own proofs and seat endorsements verify")
    }

    /// A quorum of ids: the first `threshold` of the roster.
    pub fn quorum(&self, threshold: usize) -> Vec<u64> {
        self.shares.iter().take(threshold).map(|s| s.id()).collect()
    }

    pub fn share_of(&self, id: u64) -> &CohortShare<C> {
        self.shares
            .iter()
            .find(|s| s.id() == id)
            .expect("id is on the roster")
    }
}

/// One honest ceremony: two DKGs, two seals, two reveals, one artifact.
pub struct Honest {
    pub ceremony: CeremonyId,
    pub owners: CohortSide<Owners>,
    pub gates: CohortSide<Gates>,
    pub sealed: SealedComposition,
    pub owner_reveal: ComponentReveal,
    pub gate_reveal: ComponentReveal,
    pub artifact: CompositionArtifact,
    /// Everyone a funder of THIS ceremony holds a key for. Carried on the
    /// fixture because it names the seats, and the seats are this ceremony's.
    pub parties: Parties,
    /// The view private key. Not a cohort secret -- see the crate docs.
    pub view: RistrettoPrivate,
    /// The depositor's per-output secret `r`. Held here only so a test can
    /// construct a real output; neither cohort ever sees it.
    pub tx_private: Scalar,
}

impl Honest {
    pub fn run(seed: u64, owners: &CohortSpec<Owners>, gates: &CohortSpec<Gates>) -> Honest {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let ceremony = CeremonyId::draw("two-cohort eUSD release address", &mut rng);

        let owner_side = CohortSide::<Owners>::generate(&ceremony, owners, &mut rng);
        let gate_side = CohortSide::<Gates>::generate(&ceremony, gates, &mut rng);

        let sealed =
            SealedComposition::new(ceremony, owner_side.commitment, gate_side.commitment)
                .expect("commitments are of the right cohorts");

        let owner_reveal = owner_side.reveal(&sealed);
        let gate_reveal = gate_side.reveal(&sealed);
        let parties = parties_for(owners, gates);
        let artifact = sealed
            .open(owner_reveal.clone(), gate_reveal.clone(), &parties)
            .expect("honest composition");

        Honest {
            ceremony,
            owners: owner_side,
            gates: gate_side,
            sealed,
            owner_reveal,
            gate_reveal,
            artifact,
            parties,
            view: RistrettoPrivate::from(Scalar::random(&mut rng)),
            tx_private: Scalar::random(&mut rng),
        }
    }

    /// `D_i`, the subaddress spend key a depositor pays.
    pub fn spend_public(&self) -> RistrettoPublic {
        let root = self.artifact.declared_root();
        RistrettoPublic::from(
            root + two_cohort::derive::subaddress_offset(self.view.as_ref(), SUBADDRESS)
                * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT,
        )
    }

    /// `R = r * D_i`, the tx public key of an output paid to that subaddress.
    pub fn tx_public(&self) -> RistrettoPublic {
        RistrettoPublic::from(self.tx_private * self.spend_public().as_ref())
    }
}
