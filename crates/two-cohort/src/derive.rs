//! The MobileCoin key derivations this crate needs, restated locally.
//!
//! Upstream keeps all three of these private: `hash_to_point` and the domain
//! separators live behind `mc-crypto-ring-signature`'s private
//! `ring_signature`/`domain_separators` modules, and the subaddress offset
//! lives inside `mc-core`'s `Subaddress` trait impls, which are not reachable
//! without pulling in that crate's default `bip39` feature set.
//!
//! Restating them is therefore forced, and it is the obvious place for this
//! crate to drift away from consensus. Two things pin it:
//!
//!   * `hash_to_point` is pinned by every key-image test, which compares a
//!     point assembled here against `KeyImage::from(&RistrettoPrivate)` --
//!     upstream code using upstream's own private `hash_to_point`.
//!   * `subaddress_offset` and `hash_to_scalar` are pinned by
//!     `tests/vectors.rs` against MobileCoin's published account-key test
//!     vectors, and by a differential against upstream
//!     `recover_onetime_private_key`.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use mc_crypto_hashes::{Blake2b512, Digest};
use mc_crypto_keys::RistrettoPublic;

/// `mc-crypto-ring-signature::domain_separators::HASH_TO_POINT_DOMAIN_TAG`.
pub const HASH_TO_POINT_DOMAIN_TAG: &str = "mc_onetime_key_hash_to_point";

/// `mc-crypto-ring-signature::domain_separators::HASH_TO_SCALAR_DOMAIN_TAG`.
pub const HASH_TO_SCALAR_DOMAIN_TAG: &str = "mc_onetime_key_hash_to_scalar";

/// `mc-core::consts::SUBADDRESS_DOMAIN_TAG`.
pub const SUBADDRESS_DOMAIN_TAG: &str = "mc_subaddress";

/// `Hp(P)` -- the base point the key image is taken against.
///
/// The key image is `x * Hp(P)` rather than `x * G` precisely so that it is
/// bound to the output being spent; that binding is what makes the image a
/// usable double-spend nullifier.
pub fn hash_to_point(target: &RistrettoPublic) -> RistrettoPoint {
    let mut hasher = Blake2b512::new();
    hasher.update(HASH_TO_POINT_DOMAIN_TAG);
    hasher.update(target.to_bytes());
    RistrettoPoint::from_hash(hasher)
}

/// `Hs(P)` -- the shared-secret hash used for one-time keys.
pub fn hash_to_scalar(point: RistrettoPoint) -> Scalar {
    let mut hasher = Blake2b512::new();
    hasher.update(HASH_TO_SCALAR_DOMAIN_TAG);
    hasher.update(point.compress().as_bytes());
    Scalar::from_hash(hasher)
}

/// `Hs(a || i)` -- the offset from the root spend key to the i-th subaddress
/// spend key, so that `d_i = b + Hs(a || i)`.
///
/// This offset is derived from the VIEW key alone. That is what lets the
/// bridge hand out subaddresses without either cohort participating: the
/// cohorts only ever contribute `b`.
pub fn subaddress_offset(view_private: &Scalar, index: u64) -> Scalar {
    let mut hasher = Blake2b512::new();
    hasher.update(SUBADDRESS_DOMAIN_TAG);
    hasher.update(view_private.as_bytes());
    hasher.update(Scalar::from(index).as_bytes());
    Scalar::from_hash(hasher)
}
