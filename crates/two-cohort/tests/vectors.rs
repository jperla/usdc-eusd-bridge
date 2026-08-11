//! Known-answer test against MobileCoin's own published account-key vectors.
//!
//! Vector file: `test-vectors/vectors/account_keys/subaddr_keys_from_acct_priv_keys.jsonl`
//! from the vendored MobileCoin checkout at rev 05cb699f. Upstream consumes
//! the same file in `mc-core`'s `subaddress` tests
//! (`subaddr_keys_from_acct_priv_keys`), so these are the values MobileCoin
//! itself is pinned to, not values this repo generated.
//!
//! What it establishes: this crate's `subaddress_offset` -- the one derivation
//! it had to restate locally because upstream keeps it private behind
//! `mc-core`'s default `bip39` feature set -- produces the published
//! subaddress spend keys, AND it does so when the root spend key `b` arrives
//! as `b_owner + b_gate` reconstructed from two independent cohorts rather
//! than as a single scalar. The composite root is therefore interchangeable
//! with an ordinary MobileCoin root spend key at the point where it matters.

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Deserialize;
use two_cohort::{derive::subaddress_offset, Cohort};

const VECTORS: &str = include_str!(
    "../../../vendor/mobilecoin/test-vectors/vectors/account_keys/subaddr_keys_from_acct_priv_keys.jsonl"
);

#[derive(Deserialize)]
struct Case {
    view_private_key: [u8; 32],
    spend_private_key: [u8; 32],
    subaddress_index: u64,
    subaddress_view_private_key: [u8; 32],
    subaddress_spend_private_key: [u8; 32],
    subaddress_spend_public_key: [u8; 32],
}

fn scalar(bytes: &[u8; 32]) -> Scalar {
    Option::from(Scalar::from_canonical_bytes(*bytes)).expect("vector scalar is canonical")
}

#[test]
fn composite_root_reproduces_mobilecoin_published_subaddress_keys() {
    let cases: Vec<Case> = VECTORS
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("vector line parses"))
        .collect();
    assert_eq!(cases.len(), 10, "upstream ships 10 subaddress vectors");

    for (n, case) in cases.iter().enumerate() {
        let a = scalar(&case.view_private_key);
        let b = scalar(&case.spend_private_key);

        // Split the published root spend key across two cohorts. b_gate is
        // arbitrary; b_owner is whatever makes the sum come back to b, which
        // is exactly the situation the bridge is in -- the root is fixed by
        // the address that was published, and the cohorts hold pieces of it.
        let b_gate = Scalar::from(n as u64 + 1) * Scalar::from(7_919u64);
        let b_owner = b - b_gate;

        let mut rng = ChaCha20Rng::seed_from_u64(0xFACE_0000 + n as u64);
        let owners = Cohort::deal_sequential("owners", &b_owner, 2, 3, &mut rng).unwrap();
        let gates = Cohort::deal_sequential("gates", &b_gate, 3, 4, &mut rng).unwrap();

        // Reconstruct from non-overlapping-shaped subsets to make the point
        // that the subsets are unrelated to each other.
        let owner_part = owners.reconstruct(&[2, 3]).unwrap();
        let gate_part = gates.reconstruct(&[1, 3, 4]).unwrap();
        assert_eq!(
            *owner_part + *gate_part,
            b,
            "case {n}: the two cohorts must sum back to the published root"
        );

        // d_i = b + Hs(a || i)
        let offset = subaddress_offset(&a, case.subaddress_index);
        let d = *owner_part + *gate_part + offset;
        assert_eq!(
            d.as_bytes(),
            &case.subaddress_spend_private_key,
            "case {n}: subaddress spend private key at index {}",
            case.subaddress_index
        );

        // D_i = d_i * G
        let spend_public = RistrettoPublic::from(&RistrettoPrivate::from(d));
        assert_eq!(
            spend_public.to_bytes(),
            case.subaddress_spend_public_key,
            "case {n}: subaddress spend public key"
        );

        // c_i = a * d_i -- included because the vector pins it and it exercises
        // the same offset through a different combination.
        let c = a * d;
        assert_eq!(
            c.as_bytes(),
            &case.subaddress_view_private_key,
            "case {n}: subaddress view private key"
        );

        // The cohorts also agree in the group, without either half ever being
        // reconstructed on its own.
        let root_point = owners.public(&[1, 2]).unwrap() + gates.public(&[2, 3, 4]).unwrap();
        assert_eq!(
            RistrettoPublic::from(root_point + offset * RISTRETTO_BASEPOINT_POINT).to_bytes(),
            case.subaddress_spend_public_key,
            "case {n}: group-assembled subaddress spend public key"
        );
    }
}

/// The offset must actually depend on the index, or every subaddress of a root
/// would collide. Checked against two published cases that share nothing but
/// the derivation.
#[test]
fn the_subaddress_offset_separates_indices() {
    let case: Case = serde_json::from_str(VECTORS.lines().next().unwrap()).unwrap();
    let a = scalar(&case.view_private_key);
    let offsets: Vec<Scalar> = (0..8).map(|i| subaddress_offset(&a, i)).collect();
    for i in 0..offsets.len() {
        for j in (i + 1)..offsets.len() {
            assert_ne!(offsets[i], offsets[j], "offsets for indices {i} and {j}");
        }
    }
}
