//! Oracle for `contracts/src/Ristretto255.sol` and the on-chain recipient check.
//!
//! Nothing here is re-derived. Points come from curve25519-dalek, the scalar
//! hash from MobileCoin's own `hash_to_scalar` domain tag, and the recipient
//! relation from `recover_public_subaddress_spend_key` in
//! crypto/ring-signature/src/onetime_keys.rs. If the Solidity agrees with this
//! file it agrees with MobileCoin.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto,
    ristretto::RistrettoPoint, scalar::Scalar,
};
use mc_crypto_hashes::{Blake2b512, Digest};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde_json::{json, Value};

const HASH_TO_SCALAR_DOMAIN_TAG: &str = "mc_onetime_key_hash_to_scalar";

fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// MobileCoin's `hash_to_scalar`: Blake2b512 over the domain tag and the
/// COMPRESSED point, reduced wide. The compression is why the Solidity needs
/// Ristretto encoding and not just decoding.
fn hash_to_scalar(p: RistrettoPoint) -> Scalar {
    let mut h = Blake2b512::new();
    h.update(HASH_TO_SCALAR_DOMAIN_TAG);
    h.update(p.compress().as_bytes());
    Scalar::from_hash(h)
}

fn rand_scalar(rng: &mut ChaCha20Rng) -> Scalar {
    let mut b = [0u8; 64];
    rng.fill_bytes(&mut b);
    Scalar::from_bytes_mod_order_wide(&b)
}

fn main() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x5152);

    // -- encode/decode round trips over multiples of the basepoint ----------
    // The published ristretto255 vectors: the first sixteen multiples of B.
    let mut multiples = Vec::new();
    let mut acc = RistrettoPoint::default();
    for i in 0..16u32 {
        multiples.push(json!({
            "n": i,
            "encoded": hx(acc.compress().as_bytes()),
        }));
        acc += RISTRETTO_BASEPOINT_POINT;
    }

    // -- encodings that MUST be rejected ------------------------------------
    // From the ristretto255 draft: non-canonical field elements, negative s,
    // and s values whose decode has a non-square or negative t.
    let bad: Vec<&str> = vec![
        // non-canonical field encodings
        "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        // negative field elements
        "0100000000000000000000000000000000000000000000000000000000000000",
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        // non-square x^2
        "26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371",
        "4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f",
        // negative xy
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        // s = -1, which would yield t = 0
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];
    let rejects: Vec<Value> = bad
        .iter()
        .map(|h| {
            let raw = hex::decode(h).unwrap();
            let mut b = [0u8; 32];
            b.copy_from_slice(&raw);
            // Confirm dalek really rejects it, so the list cannot rot.
            assert!(
                CompressedRistretto(b).decompress().is_none(),
                "vector {h} was expected to be rejected but decompressed"
            );
            json!({ "encoded": format!("0x{h}") })
        })
        .collect();

    // -- scalar multiplication ----------------------------------------------
    let mut mults = Vec::new();
    for i in 0..6 {
        let k = rand_scalar(&mut rng);
        let p = RistrettoPoint::mul_base(&rand_scalar(&mut rng));
        mults.push(json!({
            "case": i,
            "scalar": hx(k.as_bytes()),
            "point": hx(p.compress().as_bytes()),
            "product": hx((k * p).compress().as_bytes()),
            "base_product": hx(RistrettoPoint::mul_base(&k).compress().as_bytes()),
        }));
    }

    // -- hash_to_scalar -------------------------------------------------------
    let mut hashes = Vec::new();
    for i in 0..4 {
        let p = RistrettoPoint::mul_base(&rand_scalar(&mut rng));
        hashes.push(json!({
            "case": i,
            "point": hx(p.compress().as_bytes()),
            "scalar": hx(hash_to_scalar(p).as_bytes()),
        }));
    }

    // -- the recipient check itself ------------------------------------------
    // Build an output genuinely paid to (C, D), then assert the relation the
    // Solidity must reproduce: target_key - Hs(a*R)*G == D.
    let mut recipients = Vec::new();
    for i in 0..4 {
        let a = rand_scalar(&mut rng); // view private key, published for R
        let d = rand_scalar(&mut rng); // subaddress spend private
        let big_d = RistrettoPoint::mul_base(&d);
        let big_c = a * big_d; // subaddress view public C = a*D
        let r = rand_scalar(&mut rng); // tx private key

        let tx_public = r * big_d; // R = r*D
        let target = hash_to_scalar(r * big_c) * RISTRETTO_BASEPOINT_POINT + big_d;

        // The recipient's side of the same computation must agree.
        let recovered = target - hash_to_scalar(a * tx_public) * RISTRETTO_BASEPOINT_POINT;
        assert_eq!(recovered, big_d, "recipient relation failed to close");

        // A different spend key must NOT satisfy it.
        let other_d = RistrettoPoint::mul_base(&rand_scalar(&mut rng));
        assert_ne!(recovered, other_d);

        recipients.push(json!({
            "case": i,
            "view_private_key": hx(a.as_bytes()),
            "tx_public_key": hx(tx_public.compress().as_bytes()),
            "target_key": hx(target.compress().as_bytes()),
            "spend_public_key": hx(big_d.compress().as_bytes()),
            "wrong_spend_public_key": hx(other_d.compress().as_bytes()),
        }));
    }

    let out = json!({
        "note": "Generated by tools/ristretto-fixtures from curve25519-dalek and \
                 MobileCoin's hash_to_scalar. Do not hand-edit.",
        "basepoint": hx(RISTRETTO_BASEPOINT_POINT.compress().as_bytes()),
        "multiples": multiples,
        "rejects": rejects,
        "scalarMul": mults,
        "hashToScalar": hashes,
        "recipients": recipients,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
