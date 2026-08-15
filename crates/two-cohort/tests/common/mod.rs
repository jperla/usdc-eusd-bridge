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
        draw_salt, prove_possession, ComponentClaim, ComponentCommitment, ComponentReveal,
        CompositionArtifact, Pop, SealedComposition,
    },
    dkg::{run_dkg, CohortShare},
    CeremonyId, CohortSpec, ControlDomain, Gates, Owners,
};

/// The subaddress the bridge publishes for a depositor.
pub const SUBADDRESS: u64 = 7;

/// One cohort's DKG output plus the salt it sealed under.
pub struct CohortSide<C: ControlDomain> {
    pub shares: Vec<CohortShare<C>>,
    pub claim: ComponentClaim,
    pub salt: [u8; 32],
    pub commitment: ComponentCommitment,
}

impl<C: ControlDomain> CohortSide<C> {
    /// Run this cohort's DKG and seal its component.
    pub fn generate(ceremony: &CeremonyId, spec: &CohortSpec<C>, rng: &mut ChaCha20Rng) -> Self {
        let shares = run_dkg::<C, _>(ceremony, spec, rng).expect("honest dkg");
        let claim = ComponentClaim::of(shares[0].key());
        let salt = draw_salt(rng);
        let commitment = ComponentCommitment::seal(ceremony, &claim, &salt);
        CohortSide {
            shares,
            claim,
            salt,
            commitment,
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
        ComponentReveal::assemble(sealed, self.claim.clone(), self.pops(sealed), self.salt)
            .expect("honest cohort's own proofs verify")
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
        let artifact = sealed
            .open(owner_reveal.clone(), gate_reveal.clone())
            .expect("honest composition");

        Honest {
            ceremony,
            owners: owner_side,
            gates: gate_side,
            sealed,
            owner_reveal,
            gate_reveal,
            artifact,
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
