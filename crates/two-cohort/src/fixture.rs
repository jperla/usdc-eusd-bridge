//! Ring construction for exercising the stock MobileCoin verifier.
//!
//! Not part of the scheme. It exists so tests -- here and in sibling crates --
//! can hand a real ring to `RingMLSAG::sign`/`verify` without each of them
//! reinventing decoy generation.

use curve25519_dalek::scalar::Scalar;
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_crypto_ring_signature::{
    generators, Commitment, CompressedCommitment, PedersenGens, ReducedTxOut,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

use crate::{cohort::random_scalar, composite::CompositeSpend, EUSD_TOKEN_ID};

/// A ring of `size` outputs with the spend's real output at `real_index`.
///
/// Decoys carry the same `value` under different blindings, which is what an
/// MLSAG needs to balance: the signature proves the real input's commitment
/// differs from the output commitment by a known blinding, so every ring
/// member must be a plausible amount.
pub fn make_ring<R: RngCore + CryptoRng>(
    spend: &CompositeSpend,
    size: usize,
    real_index: usize,
    value: u64,
    blinding: &Scalar,
    rng: &mut R,
) -> (Vec<ReducedTxOut>, PedersenGens) {
    assert!(real_index < size, "real output must be inside the ring");
    let gens = generators(EUSD_TOKEN_ID);

    let ring = (0..size)
        .map(|i| {
            if i == real_index {
                ReducedTxOut {
                    public_key: spend.tx_public().into(),
                    target_key: spend.target().into(),
                    commitment: CompressedCommitment::from(&Commitment::new(
                        value, *blinding, &gens,
                    )),
                }
            } else {
                let decoy_tx = random_scalar(rng);
                let decoy_target = random_scalar(rng);
                let decoy_blinding = random_scalar(rng);
                ReducedTxOut {
                    public_key: (&RistrettoPublic::from(&RistrettoPrivate::from(decoy_tx))).into(),
                    target_key: (&RistrettoPublic::from(&RistrettoPrivate::from(decoy_target)))
                        .into(),
                    commitment: CompressedCommitment::from(&Commitment::new(
                        value,
                        decoy_blinding,
                        &gens,
                    )),
                }
            }
        })
        .collect();

    (ring, gens)
}

/// Seeded [`make_ring`], so a failing ring is reproducible.
pub fn make_ring_from_seed(
    spend: &CompositeSpend,
    size: usize,
    real_index: usize,
    value: u64,
    blinding: &Scalar,
    seed: u64,
) -> (Vec<ReducedTxOut>, PedersenGens) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    make_ring(spend, size, real_index, value, blinding, &mut rng)
}
