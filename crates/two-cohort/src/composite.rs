//! The composite spend root `b = b_owner + b_gate`, and the one-time key and
//! key image derived from it.

use core::{fmt, marker::PhantomData};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_crypto_ring_signature::KeyImage;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use zeroize::Zeroizing;

use crate::{
    cohort::{random_scalar, Cohort},
    control::{ControlDomain, Gates, Owners},
    derive::{hash_to_point, hash_to_scalar, subaddress_offset},
    error::Result,
};

/// How to deal one cohort: who is on it and how many of them are needed.
///
/// Parameterised by the control domain, so an owner spec and a gate spec are
/// different types. Handing [`CompositeSpend::simulate`] its two arguments the
/// wrong way round is a compile error rather than a scheme that quietly
/// degrades to one cohort:
///
/// ```compile_fail
/// use two_cohort::{CohortSpec, CompositeSpend, Gates, Owners};
///
/// let owners = CohortSpec::<Owners>::sequential(2, 3);
/// let gates = CohortSpec::<Gates>::sequential(2, 3);
/// // the two arguments the wrong way round
/// let _ = CompositeSpend::simulate_from_seed(0, &gates, &owners, 0);
/// ```
///
/// Nor can both halves be drawn from the same domain, which is what "two
/// cohorts" degenerates into when the separation is only a naming convention:
///
/// ```compile_fail
/// use two_cohort::{CohortSpec, CompositeSpend, Owners};
///
/// let a = CohortSpec::<Owners>::sequential(2, 3);
/// let b = CohortSpec::<Owners>::sequential(2, 3);
/// let _ = CompositeSpend::simulate_from_seed(0, &a, &b, 0);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CohortSpec<C> {
    threshold: usize,
    ids: Vec<u64>,
    domain: PhantomData<C>,
}

impl<C: ControlDomain> CohortSpec<C> {
    /// The first `n` ids of this domain's band.
    pub fn sequential(threshold: usize, n: usize) -> Self {
        CohortSpec::with_ids(threshold, &(0..n as u64).map(C::nth).collect::<Vec<_>>())
    }

    /// An explicit roster.
    ///
    /// The ids are absolute -- use [`ControlDomain::nth`] to name them by
    /// position. They are not validated here: a spec is inert data, and the
    /// rejection belongs where the cohort is actually dealt, so that one error
    /// path covers specs built by any route.
    pub fn with_ids(threshold: usize, ids: &[u64]) -> Self {
        CohortSpec {
            threshold,
            ids: ids.to_vec(),
            domain: PhantomData,
        }
    }

    pub fn name(&self) -> &'static str {
        C::NAME
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn ids(&self) -> &[u64] {
        &self.ids
    }
}

/// The per-participant pieces of one key image, before anything is summed.
///
/// A production signer combines these in the group and never forms the scalar
/// they correspond to. This crate exposes them so such a signer can be written
/// against a shape that is already correct; it does not implement one.
#[derive(Clone, Debug)]
pub struct KeyImageTerms {
    /// `common * Hp(P)`. Derived from the view key, so it belongs to whoever
    /// runs the view service and to neither cohort.
    pub view_term: RistrettoPoint,
    pub owner_terms: Vec<(u64, RistrettoPoint)>,
    pub gate_terms: Vec<(u64, RistrettoPoint)>,
}

impl KeyImageTerms {
    /// The assembled image point.
    pub fn sum(&self) -> RistrettoPoint {
        let owners: RistrettoPoint = self.owner_terms.iter().map(|(_, p)| p).sum();
        let gates: RistrettoPoint = self.gate_terms.iter().map(|(_, p)| p).sum();
        self.view_term + owners + gates
    }

    /// The assembled image in the form consensus compares.
    pub fn key_image(&self) -> KeyImage {
        KeyImage {
            point: self.sum().compress(),
        }
    }
}

/// One output paid to a subaddress of a composite two-cohort spend root.
///
/// ```text
///     b        = b_owner + b_gate           composite spend root
///     b_owner  shared k-of-n across OWNERS  (own roster, own threshold)
///     b_gate   shared g-of-m across GATES   (own roster, own threshold)
///     d_i      = b + Hs(a || i)             subaddress spend key
///     x        = Hs(a * R) + d_i            one-time key for this output
///     I        = x * Hp(P)                  key image
/// ```
///
/// The property the whole scheme rests on: `I` must be identical for every
/// (owner-subset x gate-subset) pair. An image that varied with the signing
/// subset would let one output be spent twice under two different images, and
/// consensus deduplicates on the image.
pub struct CompositeSpend {
    /// Private so the pair cannot be reassigned after construction. The
    /// disjointness of the two rosters is established once, at
    /// [`CompositeSpend::simulate`], and a `pub` field would let a caller
    /// replace one cohort with a clone of the other afterwards.
    owners: Cohort,
    gates: Cohort,
    view_private: RistrettoPrivate,
    subaddress_index: u64,
    spend_public: RistrettoPublic,
    tx_public: RistrettoPublic,
    target: RistrettoPublic,
    /// `Hs(a * R) + Hs(a || i)`: everything in the one-time key that comes
    /// from the view key. Neither cohort secret appears in it.
    common: Zeroizing<Scalar>,
}

impl CompositeSpend {
    /// Deal both cohorts over a fresh composite root and pay an output to
    /// subaddress `subaddress_index` of it.
    ///
    /// This is a TRUSTED DEALER: the two component secrets and the view key
    /// are generated here, in this process, and the shares never leave it.
    /// See the crate-level limitations.
    pub fn simulate<R: RngCore + CryptoRng>(
        owners: &CohortSpec<Owners>,
        gates: &CohortSpec<Gates>,
        subaddress_index: u64,
        rng: &mut R,
    ) -> Result<CompositeSpend> {
        let view = Zeroizing::new(random_scalar(rng));
        let b_owner = Zeroizing::new(random_scalar(rng));
        let b_gate = Zeroizing::new(random_scalar(rng));
        // The sender's per-output secret. Not ours -- modelled only so there is
        // a real output to spend.
        let tx_private = Zeroizing::new(random_scalar(rng));

        let owner_cohort =
            Cohort::deal_in::<Owners, _>(&b_owner, owners.threshold, &owners.ids, rng)?;
        let gate_cohort = Cohort::deal_in::<Gates, _>(&b_gate, gates.threshold, &gates.ids, rng)?;

        let root = *b_owner * RISTRETTO_BASEPOINT_POINT + *b_gate * RISTRETTO_BASEPOINT_POINT;
        Ok(Self::from_parts(
            owner_cohort,
            gate_cohort,
            &view,
            &root,
            subaddress_index,
            &tx_private,
        ))
    }

    /// Deterministic convenience wrapper over [`CompositeSpend::simulate`].
    ///
    /// Seeded so failures reproduce; do not mistake it for key generation.
    pub fn simulate_from_seed(
        seed: u64,
        owners: &CohortSpec<Owners>,
        gates: &CohortSpec<Gates>,
        subaddress_index: u64,
    ) -> Result<CompositeSpend> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        CompositeSpend::simulate(owners, gates, subaddress_index, &mut rng)
    }

    fn from_parts(
        owners: Cohort,
        gates: Cohort,
        view: &Scalar,
        root: &RistrettoPoint,
        subaddress_index: u64,
        tx_private: &Scalar,
    ) -> CompositeSpend {
        let g = RISTRETTO_BASEPOINT_POINT;
        let offset = Zeroizing::new(subaddress_offset(view, subaddress_index));

        // D_i = B + Hs(a || i) * G ; C_i = a * D_i
        let spend_public = RistrettoPublic::from(root + *offset * g);
        let view_public = RistrettoPublic::from(view * spend_public.as_ref());

        // R = r * D_i ; P = Hs(r * C_i) * G + D_i
        let tx_public = RistrettoPublic::from(tx_private * spend_public.as_ref());
        let target = RistrettoPublic::from(
            hash_to_scalar(tx_private * view_public.as_ref()) * g + spend_public.as_ref(),
        );

        let common = Zeroizing::new(hash_to_scalar(view * tx_public.as_ref()) + *offset);

        CompositeSpend {
            owners,
            gates,
            view_private: RistrettoPrivate::from(*view),
            subaddress_index,
            spend_public,
            tx_public,
            target,
            common,
        }
    }

    /// The OWNER cohort. Its roster lies in the [`Owners`] id band.
    pub fn owners(&self) -> &Cohort {
        &self.owners
    }

    /// The GATE cohort. Its roster lies in the [`Gates`] id band, which is
    /// disjoint from the owners', so no owner subset is a gate quorum.
    pub fn gates(&self) -> &Cohort {
        &self.gates
    }

    pub fn subaddress_index(&self) -> u64 {
        self.subaddress_index
    }

    /// `D_i`, the subaddress spend public key funds are paid to.
    pub fn spend_public(&self) -> &RistrettoPublic {
        &self.spend_public
    }

    /// `R`, the output's tx public key.
    pub fn tx_public(&self) -> &RistrettoPublic {
        &self.tx_public
    }

    /// `P`, the output's one-time (target) public key.
    pub fn target(&self) -> &RistrettoPublic {
        &self.target
    }

    /// The view private key `a`. Secret, but it authorises nothing on its own.
    pub fn view_private(&self) -> &RistrettoPrivate {
        &self.view_private
    }

    /// `Hs(a * R) + Hs(a || i)` -- the view-derived part of the one-time key.
    pub fn common(&self) -> &Scalar {
        &self.common
    }

    /// `B = B_owner + B_gate`, each half assembled from its own subset.
    pub fn composite_root(
        &self,
        owner_subset: &[u64],
        gate_subset: &[u64],
    ) -> Result<RistrettoPoint> {
        Ok(self.owners.public(owner_subset)? + self.gates.public(gate_subset)?)
    }

    /// The one-time private key `x` for a given pair of qualifying subsets.
    ///
    /// This MATERIALISES the scalar. It exists so the stock MobileCoin signer
    /// can be driven; a production signer must not call it.
    pub fn onetime(&self, owner_subset: &[u64], gate_subset: &[u64]) -> Result<Zeroizing<Scalar>> {
        let owner = self.owners.reconstruct(owner_subset)?;
        let gate = self.gates.reconstruct(gate_subset)?;
        Ok(Zeroizing::new(*self.common + *owner + *gate))
    }

    /// The per-participant key-image terms for a pair of qualifying subsets.
    ///
    /// Every term is a group element. No participant's scalar appears, and no
    /// subset of the terms sums to the one-time key.
    pub fn key_image_terms(
        &self,
        owner_subset: &[u64],
        gate_subset: &[u64],
    ) -> Result<KeyImageTerms> {
        // Against the ACTUAL output being spent, not against G -- the image is
        // only a nullifier because it is bound to this output.
        let hp = hash_to_point(&self.target);
        Ok(KeyImageTerms {
            view_term: *self.common * hp,
            owner_terms: self.owners.point_terms(owner_subset, &hp)?,
            gate_terms: self.gates.point_terms(gate_subset, &hp)?,
        })
    }

    /// The key image assembled from per-participant terms.
    pub fn key_image_from_shares(
        &self,
        owner_subset: &[u64],
        gate_subset: &[u64],
    ) -> Result<RistrettoPoint> {
        Ok(self.key_image_terms(owner_subset, gate_subset)?.sum())
    }

    /// What an OWNER quorum alone can assemble: the gate cohort's terms are
    /// simply absent from the sum.
    ///
    /// This is what a compromised operator majority reaches without the gates.
    /// It is a well-formed point and a useless one -- consensus checks the
    /// image against the ring, and this image belongs to no ring member.
    pub fn key_image_without_gates(&self, owner_subset: &[u64]) -> Result<RistrettoPoint> {
        let hp = hash_to_point(&self.target);
        let owners: RistrettoPoint = self
            .owners
            .point_terms(owner_subset, &hp)?
            .into_iter()
            .map(|(_, p)| p)
            .sum();
        Ok(*self.common * hp + owners)
    }
}

/// Redacted: `common` and the view key are secret, and the cohorts redact
/// themselves.
impl fmt::Debug for CompositeSpend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompositeSpend")
            .field("owners", &self.owners)
            .field("gates", &self.gates)
            .field("subaddress_index", &self.subaddress_index)
            .field("target", &self.target)
            .field("view_private", &"<redacted>")
            .field("common", &"<redacted>")
            .finish()
    }
}
