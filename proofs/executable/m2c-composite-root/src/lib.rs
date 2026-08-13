//! M2c — does a composite spend root produce a key image the UNCHANGED
//! MobileCoin verifier accepts?
//!
//! `CompositeGate.tla` showed that only an *indispensable* gate contribution
//! binds a compromised owner threshold: a detached signature or an advisory
//! policy is enforced by the party being constrained, so a colluding
//! coordinator simply omits it. That was an access-structure result, and it
//! explicitly assumed the algebra worked. This spike tests the assumption.
//!
//! The claim under test:
//!
//! ```text
//!     b = b_owner + b_gate                          (composite spend root)
//!     x = Hs(a*R) + b_owner + b_gate                (one-time private key)
//!     I = x * Hp(P)                                 (key image)
//! ```
//!
//! so the key image decomposes additively into per-party shares, and the
//! gate's share is *required* to form it. Omitting the gate does not yield an
//! unauthorized spend — it yields no valid spend at all, which is the entire
//! point of putting the gate where consensus already looks.
//!
//! Everything is checked against MobileCoin's own crates, and every signature
//! is verified by the stock `RingMLSAG::verify` with no modification.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use mc_crypto_hashes::{Blake2b512, Digest};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_crypto_ring_signature::{
    onetime_keys::{recover_onetime_private_key, recover_public_subaddress_spend_key},
    Commitment, CompressedCommitment, KeyImage, PedersenGens, ReducedTxOut, RingMLSAG,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

/// MobileCoin's `hash_to_point`, replicated because the module that exports it
/// is private. Same domain tag and construction as upstream, and the tests
/// below confirm agreement with the canonical `KeyImage::from`.
const HASH_TO_POINT_DOMAIN_TAG: &str = "mc_onetime_key_hash_to_point";
const HASH_TO_SCALAR_DOMAIN_TAG: &str = "mc_onetime_key_hash_to_scalar";
const SUBADDRESS_DOMAIN_TAG: &str = "mc_subaddress";

/// eUSD. The first version used generators(0), which is MOB.
pub const EUSD_TOKEN_ID: u64 = 8192;

/// `Hs(a || i)` -- the subaddress offset. Review found the first version of
/// this spike missing it entirely: it called `(b_owner + b_gate) * G` the root
/// and then used that value directly as the subaddress spend public `D`, which
/// silently composed the FINAL SUBADDRESS scalar `d` while claiming to compose
/// the account ROOT `b`. Every real address, including the default one, goes
/// through this derivation -- there is no zero-offset exception.
fn subaddress_offset(a: &Scalar, index: u64) -> Scalar {
    let n = Scalar::from(index);
    let mut digest = Blake2b512::new();
    digest.update(SUBADDRESS_DOMAIN_TAG);
    digest.update(a.as_bytes());
    digest.update(n.as_bytes());
    Scalar::from_hash(digest)
}

fn hash_to_scalar(point: RistrettoPoint) -> Scalar {
    let mut hasher = Blake2b512::new();
    hasher.update(HASH_TO_SCALAR_DOMAIN_TAG);
    hasher.update(point.compress().as_bytes());
    Scalar::from_hash(hasher)
}

fn hash_to_point(public: &RistrettoPublic) -> RistrettoPoint {
    let mut hasher = Blake2b512::new();
    hasher.update(HASH_TO_POINT_DOMAIN_TAG);
    hasher.update(public.to_bytes());
    RistrettoPoint::from_hash(hasher)
}

/// A public address. Built directly rather than through `RingCtAddress`, so
/// this spike depends only on the ring-signature crate.
pub struct Addr {
    pub view_public: RistrettoPublic,
    pub spend_public: RistrettoPublic,
}

/// `R = r * D` -- MobileCoin's tx_out_public_key for a subaddress.
fn tx_out_public_key(r: &Scalar, spend_public: &RistrettoPublic) -> RistrettoPublic {
    RistrettoPublic::from(r * spend_public.as_ref())
}

/// `P = Hs(r * C) * G + D` -- MobileCoin's tx_out_target_key.
fn tx_out_target_key(r: &Scalar, addr: &Addr) -> RistrettoPublic {
    let shared = r * addr.view_public.as_ref();
    let hs = hash_to_scalar(shared);
    RistrettoPublic::from(hs * RISTRETTO_BASEPOINT_POINT + addr.spend_public.as_ref())
}

/// The one-time private key, split by who holds each part.
///
/// `common` is derivable by anyone holding the view key; the two root shares
/// are not. This decomposition is what the whole design rests on.
pub struct OneTimeParts {
    pub common: Scalar,
    pub owner: Scalar,
    pub gate: Scalar,
}

impl OneTimeParts {
    pub fn full(&self) -> Scalar {
        self.common + self.owner + self.gate
    }
    /// What an owner quorum can compute WITHOUT the gate.
    pub fn without_gate(&self) -> Scalar {
        self.common + self.owner
    }
}

/// Key-image share for one additive component: `s * Hp(P)`.
pub fn key_image_share(s: &Scalar, target: &RistrettoPublic) -> RistrettoPoint {
    s * hash_to_point(target)
}

pub struct Setup {
    pub view_private: RistrettoPrivate,
    pub b_owner: Scalar,
    pub b_gate: Scalar,
    /// The account ROOT spend public `B = (b_owner + b_gate) * G`.
    pub root_spend_public: RistrettoPublic,
    pub index: u64,
    pub addr: Addr,
    pub tx_public: RistrettoPublic,
    pub target: RistrettoPublic,
    pub parts: OneTimeParts,
}

fn rand_scalar(rng: &mut ChaCha20Rng) -> Scalar {
    let mut b = [0u8; 64];
    rng.fill_bytes(&mut b);
    Scalar::from_bytes_mod_order_wide(&b)
}

/// Build a composite-root account, take a subaddress of it, and pay an output
/// to that subaddress.
///
/// This is the faithful chain:
/// ```text
///     B   = (b_owner + b_gate) * G                     account root
///     h_i = Hs_subaddress(a || i)
///     D_i = B + h_i * G                                subaddress spend public
///     C_i = a * D_i                                    subaddress view public
///     d_i = h_i + b_owner + b_gate                     subaddress spend private
///     x_i = Hs_onetime(a * R) + d_i                    one-time private key
/// ```
/// so the composite root shares survive the subaddress derivation additively,
/// and `common` absorbs BOTH view-derived terms.
pub fn setup_at(seed: u64, index: u64) -> Setup {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let a = rand_scalar(&mut rng); // root view private
    let b_owner = rand_scalar(&mut rng); // owner root spend share
    let b_gate = rand_scalar(&mut rng); // gate root spend share
    let r = rand_scalar(&mut rng); // tx private key

    let g = RISTRETTO_BASEPOINT_POINT;
    // THE COMPOSITE ROOT, formed on the public side.
    let root_spend_public = RistrettoPublic::from(b_owner * g + b_gate * g);

    // Subaddress derivation, exactly as upstream does it.
    let h = subaddress_offset(&a, index);
    let spend_public = RistrettoPublic::from(root_spend_public.as_ref() + h * g);
    let view_public = RistrettoPublic::from(a * spend_public.as_ref());
    let addr = Addr { view_public, spend_public };

    let view_private = RistrettoPrivate::from(a);
    let tx_public = tx_out_public_key(&r, &addr.spend_public);
    let target = tx_out_target_key(&r, &addr);

    // `common` is derived INDEPENDENTLY from the view key: the one-time
    // shared-secret term plus the subaddress offset. Neither the full
    // subaddress scalar `d` nor the full one-time scalar `x` is ever formed
    // here -- which matters, because a real two-cohort ceremony must never
    // reconstruct either. The earlier version computed `d`, handed it to
    // upstream recovery, and subtracted the shares back out; that both
    // reconstructed the secret and made the upstream comparison circular.
    let hs_onetime = hash_to_scalar(a * tx_public.as_ref());
    let common = hs_onetime + h;

    Setup {
        view_private, b_owner, b_gate, root_spend_public, index, addr,
        tx_public, target,
        parts: OneTimeParts { common, owner: b_owner, gate: b_gate },
    }
}

/// Default index, for tests that do not care which subaddress.
pub fn setup(seed: u64) -> Setup {
    setup_at(seed, 0)
}

/// Build a ring with the real input at `real_index`; decoys are unrelated.
pub fn make_ring(
    s: &Setup,
    size: usize,
    real_index: usize,
    value: u64,
    blinding: Scalar,
) -> (Vec<ReducedTxOut>, PedersenGens) {
    let gens = mc_crypto_ring_signature::generators(EUSD_TOKEN_ID);
    let mut rng = ChaCha20Rng::seed_from_u64(0xDEC0);
    let mut ring = Vec::new();
    for i in 0..size {
        if i == real_index {
            ring.push(ReducedTxOut {
                public_key: (&s.tx_public).into(),
                target_key: (&s.target).into(),
                commitment: CompressedCommitment::from(&Commitment::new(value, blinding, &gens)),
            });
        } else {
            let k = rand_scalar(&mut rng);
            let k2 = rand_scalar(&mut rng);
            let bl = rand_scalar(&mut rng);
            ring.push(ReducedTxOut {
                public_key: (&RistrettoPublic::from(&RistrettoPrivate::from(k))).into(),
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
    fn composite_root_derives_the_subaddress_and_the_onetime_key() {
        let s = setup_at(1, 7);
        let g = RISTRETTO_BASEPOINT_POINT;
        let a: &Scalar = s.view_private.as_ref();

        // The ROOT is the sum of the two shares.
        let root: &RistrettoPoint = s.root_spend_public.as_ref();
        assert_eq!(root, &((s.b_owner + s.b_gate) * g));

        // The SUBADDRESS adds the view-derived offset on top of the root.
        let h = subaddress_offset(a, s.index);
        let d_pub: &RistrettoPoint = s.addr.spend_public.as_ref();
        assert_eq!(d_pub, &(root + h * g), "D_i = B + Hs(a||i)*G");

        // INDEPENDENT of upstream recovery: the one-time public key really is
        // the target key. The earlier version of this test derived `common`
        // from upstream and then added the parts back, which was circular.
        let x = s.parts.full();
        let target: &RistrettoPoint = s.target.as_ref();
        assert_eq!(target, &(x * g), "P = x * G");

        // And the split puts NEITHER root share in the view-derived part.
        assert_eq!(s.parts.common, x - s.b_owner - s.b_gate);

        // Now a genuine differential: `common` was built without ever forming
        // `d` or `x`, so comparing the assembled key against upstream recovery
        // actually tests something. (The earlier fixture derived `common` FROM
        // this call, which made the same assertion circular.)
        let d = subaddress_offset(a, s.index) + s.b_owner + s.b_gate;
        let upstream = recover_onetime_private_key(
            &s.tx_public, &s.view_private, &RistrettoPrivate::from(d));
        let us: &Scalar = upstream.as_ref();
        assert_eq!(*us, x, "independently derived x must match upstream recovery");
    }

    #[test]
    fn recipient_check_passes_for_the_composite_address() {
        let s = setup(2);
        // The predicate the return leg depends on, against a composite root.
        let recovered =
            recover_public_subaddress_spend_key(&s.view_private, &s.target, &s.tx_public);
        assert_eq!(recovered, s.addr.spend_public);
    }

    #[test]
    fn key_image_is_the_sum_of_per_party_shares() {
        let s = setup(3);
        let x = RistrettoPrivate::from(s.parts.full());
        let canonical = KeyImage::from(&x);

        // Each party computes its share against the SAME target key; they sum.
        let summed = key_image_share(&s.parts.common, &s.target)
            + key_image_share(&s.parts.owner, &s.target)
            + key_image_share(&s.parts.gate, &s.target);
        assert_eq!(
            canonical.point,
            summed.compress(),
            "key image must decompose additively into party shares"
        );
    }

    #[test]
    fn omitting_the_gate_share_yields_a_different_key_image() {
        let s = setup(4);
        let x = RistrettoPrivate::from(s.parts.full());
        let i_full = KeyImage::from(&x);

        // Both images must use the ACTUAL target as the Hp base. An earlier
        // version called KeyImage::from(x_no_gate), which hashes x_no_gate*G --
        // a different point -- so it varied the scalar AND the base. That is
        // not the dropped-share failure mode.
        let i_no_gate = key_image_share(&s.parts.common, &s.target)
            + key_image_share(&s.parts.owner, &s.target);
        let i_gate = key_image_share(&s.parts.gate, &s.target);

        assert_ne!(i_full.point, i_no_gate.compress(),
                   "an owner quorum without the gate must not reach the real key image");
        // The gate's share is exactly what is missing.
        assert_eq!(i_full.point, (i_no_gate + i_gate).compress());
        // Preconditions, so the inequality is not holding for a trivial reason.
        assert_ne!(s.parts.gate, Scalar::ZERO);
        assert_ne!(i_gate.compress(), (Scalar::ZERO * RISTRETTO_BASEPOINT_POINT).compress());
    }

    #[test]
    fn stock_verifier_accepts_the_composite_signature() {
        let s = setup(5);
        let (value, blinding, out_blinding) = (9_000u64, Scalar::from(7u64), Scalar::from(11u64));
        let (ring, gens) = make_ring(&s, 11, 4, value, blinding);
        let x = RistrettoPrivate::from(s.parts.full());
        let mut rng = ChaCha20Rng::seed_from_u64(99);

        let sig = RingMLSAG::sign(
            b"m2c", &ring, 4, &x, value, &blinding, &out_blinding, &gens, &mut rng,
        )
        .expect("signing with the composite one-time key");

        let out_commit = CompressedCommitment::from(&Commitment::new(value, out_blinding, &gens));
        // UNCHANGED verifier.
        sig.verify(b"m2c", &ring, &out_commit)
            .expect("stock RingMLSAG::verify must accept a composite-root signature");
        assert_eq!(sig.key_image, KeyImage::from(&x));
    }

    #[test]
    fn stock_verifier_rejects_a_signature_built_without_the_gate() {
        let s = setup(6);
        let (value, blinding, out_blinding) = (4_200u64, Scalar::from(3u64), Scalar::from(5u64));
        let (ring, gens) = make_ring(&s, 11, 2, value, blinding);
        let mut rng = ChaCha20Rng::seed_from_u64(1234);

        // The owner quorum signs with everything it has EXCEPT the gate share.
        let x_no_gate = RistrettoPrivate::from(s.parts.without_gate());
        let sig = RingMLSAG::sign(
            b"m2c", &ring, 2, &x_no_gate, value, &blinding, &out_blinding, &gens, &mut rng,
        );

        let out_commit = CompressedCommitment::from(&Commitment::new(value, out_blinding, &gens));
        // Signing must SUCCEED -- the point is that the VERIFIER rejects, not
        // that the signer happened to error. Mapping every error to "not
        // accepted" would green this test on an unrelated failure.
        let sg = sig.expect("stock signer should still produce a signature");
        let err = sg
            .verify(b"m2c", &ring, &out_commit)
            .expect_err("omitting the gate share must yield NO VALID SPEND");
        assert!(
            matches!(err, mc_crypto_ring_signature::Error::InvalidSignature),
            "expected InvalidSignature, got {err:?}"
        );
    }

    /// The construction DESIGN-FINAL actually specifies: R and F are separate
    /// VIEW roots sharing ONE composite spend root. Neither the earlier spike
    /// nor any other artifact exercised this.
    #[test]
    fn two_view_roots_share_one_composite_spend_root() {
        let g = RISTRETTO_BASEPOINT_POINT;
        let mut rng = ChaCha20Rng::seed_from_u64(4242);
        let b_owner = rand_scalar(&mut rng);
        let b_gate = rand_scalar(&mut rng);
        let root = RistrettoPublic::from((b_owner + b_gate) * g);

        // Two independent view roots over the SAME spend root.
        for (label, a) in [("R", rand_scalar(&mut rng)), ("F", rand_scalar(&mut rng))] {
            for index in [0u64, 1, 12345] {
                let h = subaddress_offset(&a, index);
                let spend_public = RistrettoPublic::from(root.as_ref() + h * g);
                let view_public = RistrettoPublic::from(a * spend_public.as_ref());
                let addr = Addr { view_public, spend_public };
                let view_private = RistrettoPrivate::from(a);

                let r = rand_scalar(&mut rng);
                let tx_public = tx_out_public_key(&r, &addr.spend_public);
                let target = tx_out_target_key(&r, &addr);

                // The recipient predicate the return leg depends on.
                assert_eq!(
                    recover_public_subaddress_spend_key(&view_private, &target, &tx_public),
                    addr.spend_public,
                    "{label} index {index}: recipient check must hold"
                );

                // And the one-time key still decomposes with both root shares.
                let d = h + b_owner + b_gate;
                let full = recover_onetime_private_key(
                    &tx_public, &view_private, &RistrettoPrivate::from(d));
                let fs: &Scalar = full.as_ref();
                let tgt: &RistrettoPoint = target.as_ref();
                assert_eq!(tgt, &(fs * g), "{label} index {index}: P = x*G");
            }
        }
    }

    /// The stock-verifier matrix: every ring position, several ring sizes.
    #[test]
    fn stock_verifier_matrix_over_positions_and_sizes() {
        let mut checked = 0;
        // Only 11 is a production consensus ring size; 3 and 5 are
        // library-level edge coverage and are labelled as such.
        for size in [3usize, 5, 11] {
            for real_index in 0..size {
                let s = setup(1000 + (size * 100 + real_index) as u64);
                let (value, blinding, out_blinding) =
                    (1_234u64, Scalar::from(13u64), Scalar::from(17u64));
                let (ring, gens) = make_ring(&s, size, real_index, value, blinding);
                let x = RistrettoPrivate::from(s.parts.full());
                let mut rng = ChaCha20Rng::seed_from_u64(7 * size as u64 + real_index as u64);
                let sig = RingMLSAG::sign(
                    b"matrix", &ring, real_index, &x, value, &blinding, &out_blinding, &gens,
                    &mut rng,
                )
                .expect("sign");
                let out_commit =
                    CompressedCommitment::from(&Commitment::new(value, out_blinding, &gens));
                sig.verify(b"matrix", &ring, &out_commit)
                    .unwrap_or_else(|e| panic!("size {size} index {real_index}: {e:?}"));
                assert_eq!(sig.key_image, KeyImage::from(&x));
                checked += 1;
            }
        }
        assert_eq!(checked, 3 + 5 + 11);
    }
}
