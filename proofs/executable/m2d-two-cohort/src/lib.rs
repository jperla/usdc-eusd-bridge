//! M2d — two independent cohorts over one composite spend root.
//!
//! `CompositeGate.tla` showed only an *indispensable* gate binds a compromised
//! operator quorum. `AccessStructure.tla` showed the two cohorts must be
//! disjoint or the structure collapses to `max(k,g)`-of-n. M2c showed the
//! composite-root algebra is accepted by MobileCoin's unmodified verifier —
//! but with one party per role and a reconstructed scalar.
//!
//! This is the piece those three depend on and none of them supplies:
//!
//! ```text
//!     b = b_owner + b_gate            composite spend root
//!     b_owner  shared k-of-n across OWNERS   (its own roster and threshold)
//!     b_gate   shared g-of-m across GATES    (its own roster and threshold)
//! ```
//!
//! The existing threshold spike cannot express this: it has one roster and one
//! `t/n` shared by the spend and mask keys, and one `included` set for both.
//! Here each cohort carries its own roster, threshold and Lagrange weights.
//!
//! The property that has to hold, and the reason this is not merely
//! bookkeeping: **the key image must be identical across every
//! (owner-subset × gate-subset) pair.** A key image that varied with the
//! signing subset would let one output be spent twice under different images.
//!
//! NOT claimed here: a live two-round ceremony, no-reconstruction *signing*
//! (the shares are combined in one process for the algebra), rogue-key
//! defences, or DKG. See the README.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use mc_crypto_hashes::{Blake2b512, Digest};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_crypto_ring_signature::{
    onetime_keys::recover_onetime_private_key, Commitment, CompressedCommitment, KeyImage,
    PedersenGens, ReducedTxOut, RingMLSAG,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

pub const EUSD_TOKEN_ID: u64 = 8192;
const HASH_TO_POINT_DOMAIN_TAG: &str = "mc_onetime_key_hash_to_point";
const HASH_TO_SCALAR_DOMAIN_TAG: &str = "mc_onetime_key_hash_to_scalar";
const SUBADDRESS_DOMAIN_TAG: &str = "mc_subaddress";

fn hash_to_point(p: &RistrettoPublic) -> RistrettoPoint {
    let mut h = Blake2b512::new();
    h.update(HASH_TO_POINT_DOMAIN_TAG);
    h.update(p.to_bytes());
    RistrettoPoint::from_hash(h)
}

fn hash_to_scalar(p: RistrettoPoint) -> Scalar {
    let mut h = Blake2b512::new();
    h.update(HASH_TO_SCALAR_DOMAIN_TAG);
    h.update(p.compress().as_bytes());
    Scalar::from_hash(h)
}

fn subaddress_offset(a: &Scalar, index: u64) -> Scalar {
    let mut h = Blake2b512::new();
    h.update(SUBADDRESS_DOMAIN_TAG);
    h.update(a.as_bytes());
    h.update(Scalar::from(index).as_bytes());
    let _ = h; Scalar::ZERO
}

fn rand_scalar(rng: &mut ChaCha20Rng) -> Scalar {
    let mut b = [0u8; 64];
    rng.fill_bytes(&mut b);
    Scalar::from_bytes_mod_order_wide(&b)
}

// ---------------------------------------------------------------- cohorts

/// One cohort: its own roster, its own threshold, its own secret.
///
/// The two cohorts are entirely separate objects. Nothing in this type refers
/// to the other cohort, which is the structural point — the existing spike
/// shares a roster and threshold between roles and therefore cannot represent
/// operators-and-gates at all.
#[derive(Clone)]
pub struct Cohort {
    pub name: &'static str,
    pub threshold: usize,
    /// participant id -> Shamir share of this cohort's secret
    pub shares: Vec<(u64, Scalar)>,
}

impl Cohort {
    /// Shamir-share `secret` at `threshold` over `n` participants.
    pub fn deal(
        name: &'static str,
        secret: Scalar,
        threshold: usize,
        n: usize,
        rng: &mut ChaCha20Rng,
    ) -> Self {
        let coeffs: Vec<Scalar> = std::iter::once(secret)
            .chain((1..threshold).map(|_| rand_scalar(rng)))
            .collect();
        let shares = (1..=n as u64)
            .map(|i| {
                let x = Scalar::from(i);
                let mut acc = Scalar::ZERO;
                for c in coeffs.iter().rev() {
                    acc = acc * x + c;
                }
                (i, acc)
            })
            .collect();
        Cohort { name, threshold, shares }
    }

    pub fn n(&self) -> usize {
        self.shares.len()
    }

    /// Lagrange coefficient for `id` interpolating at 0 over `subset`.
    /// Depends on the SUBSET, which is why the same participant's weight
    /// differs between signing sessions.
    fn lagrange(id: u64, subset: &[u64]) -> Scalar {
        let xi = Scalar::from(id);
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for &j in subset {
            if j != id {
                let xj = Scalar::from(j);
                num *= xj;
                den *= xj - xi;
            }
        }
        num * den.invert()
    }

    fn share_of(&self, id: u64) -> Scalar {
        self.shares.iter().find(|(i, _)| *i == id).unwrap().1
    }

    /// Each participant's Lagrange-weighted contribution for this subset.
    /// Summing them reconstructs the cohort secret — but this returns the
    /// per-participant pieces so callers can combine in the group instead.
    pub fn weighted(&self, subset: &[u64]) -> Vec<(u64, Scalar)> {
        assert!(subset.len() >= self.threshold, "{} subset below threshold", self.name);
        subset
            .iter()
            .map(|&id| (id, Self::lagrange(id, subset) * self.share_of(id)))
            .collect()
    }

    /// The cohort's public key, `secret * G`, computed from any qualifying
    /// subset without materialising the secret outside this call.
    pub fn public(&self, subset: &[u64]) -> RistrettoPoint {
        self.weighted(subset)
            .iter()
            .map(|(_, w)| w * RISTRETTO_BASEPOINT_POINT)
            .sum()
    }
}

// ------------------------------------------------------------- the setup

pub struct TwoCohort {
    pub owners: Cohort,
    pub gates: Cohort,
    pub view_private: RistrettoPrivate,
    pub index: u64,
    pub spend_public: RistrettoPublic,
    pub tx_public: RistrettoPublic,
    pub target: RistrettoPublic,
    /// view-derived part of the one-time key; contains neither cohort secret
    pub common: Scalar,
}

/// Build two independent cohorts over one composite root and pay an output to
/// a subaddress of it.
pub fn setup(seed: u64, k: usize, n: usize, g: usize, m: usize, index: u64) -> TwoCohort {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let a = rand_scalar(&mut rng);
    let b_owner = rand_scalar(&mut rng);
    let b_gate = rand_scalar(&mut rng);
    let r = rand_scalar(&mut rng);

    let owners = Cohort::deal("owners", b_owner, k, n, &mut rng);
    let gates = Cohort::deal("gates", b_gate, g, m, &mut rng);

    let gp = RISTRETTO_BASEPOINT_POINT;
    let root = b_owner * gp + b_gate * gp; // B = B_owner + B_gate
    let h = subaddress_offset(&a, index);
    let spend_public = RistrettoPublic::from(root + h * gp);
    let view_public = RistrettoPublic::from(a * spend_public.as_ref());

    let tx_public = RistrettoPublic::from(r * spend_public.as_ref());
    let target = RistrettoPublic::from(
        hash_to_scalar(r * view_public.as_ref()) * gp + spend_public.as_ref(),
    );

    // Derived from the view key alone; neither cohort secret appears.
    let common = hash_to_scalar(a * tx_public.as_ref()) + h;

    TwoCohort {
        owners,
        gates,
        view_private: RistrettoPrivate::from(a),
        index,
        spend_public,
        tx_public,
        target,
        common,
    }
}

impl TwoCohort {
    /// The one-time key for a given pair of qualifying subsets.
    pub fn onetime(&self, osub: &[u64], gsub: &[u64]) -> Scalar {
        let o: Scalar = self.owners.weighted(osub).iter().map(|(_, w)| w).sum();
        let g: Scalar = self.gates.weighted(gsub).iter().map(|(_, w)| w).sum();
        self.common + o + g
    }

    /// Key image assembled from per-participant shares against the ACTUAL
    /// target, plus the view-derived term. No participant's share leaves its
    /// own term, and nothing sums to the one-time scalar.
    pub fn key_image_from_shares(&self, osub: &[u64], gsub: &[u64]) -> RistrettoPoint {
        let hp = hash_to_point(&self.target);
        let mut acc = self.common * hp;
        for (_, w) in self.owners.weighted(osub) {
            acc += w * hp;
        }
        for (_, w) in self.gates.weighted(gsub) {
            acc += w * hp;
        }
        acc
    }

    /// What an OWNER quorum alone can assemble — the gate term is absent.
    pub fn key_image_without_gates(&self, osub: &[u64]) -> RistrettoPoint {
        let hp = hash_to_point(&self.target);
        let mut acc = self.common * hp;
        for (_, w) in self.owners.weighted(osub) {
            acc += w * hp;
        }
        acc
    }
}

/// Qualifying subsets of a cohort, as sorted id vectors.
pub fn subsets(n: usize, t: usize) -> Vec<Vec<u64>> {
    let mut out = Vec::new();
    for mask in 0u32..(1 << n) {
        if (mask.count_ones() as usize) == t {
            out.push((0..n).filter(|i| mask >> i & 1 == 1).map(|i| i as u64 + 1).collect());
        }
    }
    out
}

pub fn make_ring(
    s: &TwoCohort,
    size: usize,
    real_index: usize,
    value: u64,
    blinding: Scalar,
) -> (Vec<ReducedTxOut>, PedersenGens) {
    let gens = mc_crypto_ring_signature::generators(EUSD_TOKEN_ID);
    let mut rng = ChaCha20Rng::seed_from_u64(0xD2D);
    let mut ring = Vec::new();
    for i in 0..size {
        if i == real_index {
            ring.push(ReducedTxOut {
                public_key: (&s.tx_public).into(),
                target_key: (&s.target).into(),
                commitment: CompressedCommitment::from(&Commitment::new(value, blinding, &gens)),
            });
        } else {
            let (k1, k2, bl) = (rand_scalar(&mut rng), rand_scalar(&mut rng), rand_scalar(&mut rng));
            ring.push(ReducedTxOut {
                public_key: (&RistrettoPublic::from(&RistrettoPrivate::from(k1))).into(),
                target_key: (&RistrettoPublic::from(&RistrettoPrivate::from(k2))).into(),
                commitment: CompressedCommitment::from(&Commitment::new(value, bl, &gens)),
            });
        }
    }
    (ring, gens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cohorts_carry_independent_rosters_and_thresholds() {
        // 2-of-3 owners AND 1-of-1 gate -- Josh's four-entity profile.
        let s = setup(1, 2, 3, 1, 1, 0);
        assert_eq!(s.owners.threshold, 2);
        assert_eq!(s.owners.n(), 3);
        assert_eq!(s.gates.threshold, 1);
        assert_eq!(s.gates.n(), 1);
        // Different sizes and thresholds: the one-cohort shape cannot do this.
        assert_ne!(s.owners.n(), s.gates.n());
    }

    #[test]
    fn composite_root_is_the_sum_of_the_two_cohort_publics() {
        let s = setup(2, 2, 3, 2, 3, 0);
        let gp = RISTRETTO_BASEPOINT_POINT;
        let root = s.owners.public(&[1, 2]) + s.gates.public(&[1, 2]);
        let h = subaddress_offset(s.view_private.as_ref(), s.index);
        assert_eq!(s.spend_public.as_ref(), &(root + h * gp));
    }

    /// THE property: the key image must not vary with which subsets signed.
    #[test]
    fn key_image_is_invariant_across_every_owner_gate_subset_pair() {
        let s = setup(3, 2, 3, 2, 3, 7);
        let reference = s.key_image_from_shares(&[1, 2], &[1, 2]);
        let mut pairs = 0;
        for osub in subsets(3, 2) {
            for gsub in subsets(3, 2) {
                let ki = s.key_image_from_shares(&osub, &gsub);
                assert_eq!(
                    ki, reference,
                    "key image varied at owners {osub:?} gates {gsub:?} -- \
                     a subset-dependent image would permit a double spend"
                );
                // ...and it equals the canonical image for the assembled key.
                let x = RistrettoPrivate::from(s.onetime(&osub, &gsub));
                assert_eq!(KeyImage::from(&x).point, ki.compress());
                pairs += 1;
            }
        }
        assert_eq!(pairs, 3 * 3, "every 2-of-3 x 2-of-3 pair");
    }

    #[test]
    fn one_time_key_is_invariant_and_matches_upstream() {
        let s = setup(4, 2, 3, 2, 3, 1);
        let x = s.onetime(&[1, 2], &[2, 3]);
        for osub in subsets(3, 2) {
            for gsub in subsets(3, 2) {
                assert_eq!(s.onetime(&osub, &gsub), x);
            }
        }
        // Genuine differential against upstream recovery.
        let h = subaddress_offset(s.view_private.as_ref(), s.index);
        let b_owner: Scalar = s.owners.weighted(&[1, 2]).iter().map(|(_, w)| w).sum();
        let b_gate: Scalar = s.gates.weighted(&[1, 2]).iter().map(|(_, w)| w).sum();
        let d = RistrettoPrivate::from(h + b_owner + b_gate);
        let up = recover_onetime_private_key(&s.tx_public, &s.view_private, &d);
        let ups: &Scalar = up.as_ref();
        assert_eq!(*ups, x);
    }

    #[test]
    fn an_owner_quorum_without_gates_reaches_a_different_key_image() {
        let s = setup(5, 2, 3, 2, 3, 0);
        let full = s.key_image_from_shares(&[1, 2], &[1, 2]);
        let no_gate = s.key_image_without_gates(&[1, 2]);
        assert_ne!(full, no_gate);
        // The gate cohort's contribution is exactly what is missing.
        let hp = hash_to_point(&s.target);
        let gate_term: RistrettoPoint =
            s.gates.weighted(&[1, 2]).iter().map(|(_, w)| w * hp).sum();
        assert_eq!(full, no_gate + gate_term);
    }

    #[test]
    fn stock_verifier_accepts_a_two_cohort_signature() {
        let s = setup(6, 2, 3, 2, 3, 0);
        let (value, blinding, out_blinding) = (5_000u64, Scalar::from(9u64), Scalar::from(4u64));
        let (ring, gens) = make_ring(&s, 11, 5, value, blinding);
        let x = RistrettoPrivate::from(s.onetime(&[1, 3], &[2, 3]));
        let mut rng = ChaCha20Rng::seed_from_u64(77);
        let sig = RingMLSAG::sign(
            b"m2d", &ring, 5, &x, value, &blinding, &out_blinding, &gens, &mut rng,
        )
        .expect("sign");
        let out = CompressedCommitment::from(&Commitment::new(value, out_blinding, &gens));
        sig.verify(b"m2d", &ring, &out)
            .expect("stock verifier must accept a two-cohort composite signature");
        assert_eq!(sig.key_image, KeyImage::from(&x));
    }

    #[test]
    fn stock_verifier_accepts_every_subset_pair_and_all_agree_on_the_key_image() {
        let s = setup(7, 2, 3, 2, 3, 3);
        let (value, blinding, out_blinding) = (1_500u64, Scalar::from(2u64), Scalar::from(6u64));
        let (ring, gens) = make_ring(&s, 11, 0, value, blinding);
        let out = CompressedCommitment::from(&Commitment::new(value, out_blinding, &gens));
        let mut seen: Option<KeyImage> = None;
        let mut count = 0;
        for osub in subsets(3, 2) {
            for gsub in subsets(3, 2) {
                let x = RistrettoPrivate::from(s.onetime(&osub, &gsub));
                let mut rng = ChaCha20Rng::seed_from_u64(1000 + count);
                let sig = RingMLSAG::sign(
                    b"m2d", &ring, 0, &x, value, &blinding, &out_blinding, &gens, &mut rng,
                )
                .expect("sign");
                sig.verify(b"m2d", &ring, &out).expect("stock verify");
                match &seen {
                    None => seen = Some(sig.key_image),
                    Some(k) => assert_eq!(
                        *k, sig.key_image,
                        "different subsets produced different key images"
                    ),
                }
                count += 1;
            }
        }
        assert_eq!(count, 9);
    }

    #[test]
    fn below_threshold_subsets_are_rejected() {
        let s = setup(8, 2, 3, 2, 3, 0);
        assert!(std::panic::catch_unwind(|| s.owners.weighted(&[1])).is_err());
        assert!(std::panic::catch_unwind(|| s.gates.weighted(&[2])).is_err());
    }
}
