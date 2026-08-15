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
        ComponentReveal, CompositionArtifact, Parties, Pop, SealedComposition, SeatRoster,
        SignedCommitment,
    },
    dkg::{run_dkg, CohortShare},
    identity::{IdentityKey, IdentityPublic, IdentitySignature},
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

/// Every seat's endorsement of its own verification share, signed with that
/// seat's own key.
pub fn seat_endorsements<C: ControlDomain>(
    ceremony: &CeremonyId,
    claim: &ComponentClaim,
) -> std::collections::BTreeMap<u64, IdentitySignature> {
    claim
        .roster()
        .iter()
        .map(|&id| {
            (
                id,
                endorse_seat(ceremony, claim, id, &seat_key_of::<C>(id))
                    .expect("the fixture's seat keys are the ones in the claim"),
            )
        })
        .collect()
}

pub fn identity_public<C: ControlDomain>() -> IdentityPublic {
    identity_of::<C>().public()
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
    /// Each seat's endorsement of its own verification share.
    pub endorsements: std::collections::BTreeMap<u64, IdentitySignature>,
    pub ceremony: CeremonyId,
}

impl<C: ControlDomain> CohortSide<C> {
    /// Run this cohort's DKG, seal its component, and sign the seal as its
    /// organisation.
    pub fn generate(ceremony: &CeremonyId, spec: &CohortSpec<C>, rng: &mut ChaCha20Rng) -> Self {
        let shares =
            run_dkg::<C, _>(ceremony, spec, &seats_for::<C>(spec), rng).expect("honest dkg");
        let claim = ComponentClaim::of(shares[0].key());
        let salt = draw_salt(rng);
        let commitment = seal_and_sign::<C>(ceremony, &claim, &salt);
        // Each seat signs for itself, through the checked holder entry point, so
        // the harness produces what a deployment would rather than a shortcut
        // around it.
        let endorsements = shares
            .iter()
            .map(|s| {
                (
                    s.id(),
                    s.endorse(ceremony, &claim, &seat_key_of::<C>(s.id()))
                        .expect("each seat holds the key the claim attributes to it"),
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
