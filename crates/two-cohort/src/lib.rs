//! Two independent cohorts over one composite MobileCoin spend root.
//!
//! Releasing eUSD from the bridge's MobileCoin side requires a composite spend
//! key held by two structurally different groups:
//!
//! ```text
//!     b = b_owner + b_gate                  composite spend root
//!     b_owner  shared k-of-n across OWNERS  (own roster, own threshold)
//!     b_gate   shared g-of-m across GATES   (own roster, own threshold)
//! ```
//!
//! The gate cohort's share enters the one-time key, so it enters the KEY
//! IMAGE. That is the point: a release attempted without the gates does not
//! produce a rejected signature, it produces a signature over a key image that
//! belongs to no output in the ring. Consensus itself refuses it. The gate is
//! not a policy check layered on top of the spend path -- it is inside it.
//!
//! # The load-bearing property
//!
//! **The key image must be identical for every (owner-subset x gate-subset)
//! pair.** MobileCoin deduplicates spends on the key image. An image that
//! varied with which quorum happened to sign would mean one output has many
//! images, and one output could be spent once per distinct image. Invariance
//! across the full product of qualifying subsets is therefore not bookkeeping;
//! it is the correctness condition for the scheme.
//!
//! [`CompositeSpend::key_image_from_shares`] assembles the image from
//! per-participant group terms, and the tests check it against upstream
//! MobileCoin's own [`KeyImage`](mc_crypto_ring_signature::KeyImage)
//! derivation over every subset pair.
//!
//! # Example
//!
//! ```
//! use two_cohort::{CohortSpec, CompositeSpend};
//!
//! // 2-of-3 owners AND 2-of-3 gates over one root.
//! let owners = CohortSpec::sequential("owners", 2, 3);
//! let gates = CohortSpec::sequential("gates", 2, 3);
//! let spend = CompositeSpend::simulate_from_seed(42, &owners, &gates, 7)?;
//!
//! // Different quorums, same image.
//! let a = spend.key_image_from_shares(&[1, 2], &[2, 3])?;
//! let b = spend.key_image_from_shares(&[2, 3], &[1, 3])?;
//! assert_eq!(a, b);
//!
//! // An owner quorum alone reaches somewhere else entirely.
//! assert_ne!(a, spend.key_image_without_gates(&[1, 2])?);
//! # Ok::<(), two_cohort::Error>(())
//! ```
//!
//! # What this crate does NOT establish
//!
//! Carried forward verbatim from the spike this was promoted from. None of
//! these got easier because the code became a library.
//!
//! * **No live ceremony.** Shares are dealt and combined in ONE PROCESS.
//!   [`Cohort`] holds every share; [`Cohort::share`] hands them out. This is
//!   the algebra, not a two-round protocol with round-one packages, commitment
//!   transcripts, or any notion of a participant that can go offline or lie.
//! * **No non-reconstruction signing.** [`CompositeSpend::onetime`]
//!   materialises the one-time scalar so the stock MobileCoin signer can be
//!   driven. The per-participant terms a real signer would combine in the
//!   group are exposed ([`Cohort::point_terms`],
//!   [`CompositeSpend::key_image_terms`]) so such a signer can be written
//!   against the right shape -- but that signer does not exist here, and a
//!   threshold MLSAG needs distributed nonces as well as distributed keys.
//! * **Trusted dealer, no DKG.** [`CompositeSpend::simulate`] generates both
//!   component secrets itself. There is no distributed key generation, no
//!   proof-of-possession, and therefore no rogue-key defence: a cohort able to
//!   choose its component after seeing the other's public value could steer
//!   the sum. Defending that needs authenticated DKG with PoP and a
//!   non-adaptive ceremony.
//! * **No mask-row split.** MLSAG row 1 (the commitment mask) is not split
//!   across cohorts. Only the spend row and the key image are two-cohort here.
//! * **No transaction-level acceptance.** The tests drive
//!   `RingMLSAG::verify`, which is low-level signature compatibility. It is
//!   not consensus validation of a whole transaction: no range proofs, no fee
//!   or balance check, no membership proofs, no enclave.
//! * **Best-effort zeroization.** Secret-bearing types zeroize on drop, but
//!   `curve25519_dalek::Scalar` is `Copy`, so intermediate copies made by the
//!   compiler in registers or on the stack are outside this crate's reach.
//!   Zeroization here reduces the residue; it does not eliminate it.

pub mod cohort;
pub mod composite;
pub mod derive;
pub mod error;
pub mod fixture;

pub use cohort::{lagrange_at_zero, Cohort, ParticipantTerm};
pub use composite::{CohortSpec, CompositeSpend, KeyImageTerms};
pub use error::{Error, Result};

/// MobileCoin token id for eUSD. Releases from the bridge are denominated in
/// it, and the Pedersen generators are token-specific, so it is part of the
/// signature's domain rather than a label.
pub const EUSD_TOKEN_ID: u64 = 8192;

/// Every subset of `ids` of size exactly `size`, as sorted id vectors.
///
/// Used to enumerate the full product of qualifying quorums, which is what the
/// key-image invariance claim is quantified over.
pub fn subsets_of(ids: &[u64], size: usize) -> Vec<Vec<u64>> {
    assert!(
        ids.len() < 32,
        "subset enumeration is exponential; keep rosters small"
    );
    let mut out = Vec::new();
    for mask in 0u32..(1u32 << ids.len()) {
        if mask.count_ones() as usize == size {
            out.push(
                ids.iter()
                    .enumerate()
                    .filter(|(i, _)| mask >> i & 1 == 1)
                    .map(|(_, &id)| id)
                    .collect(),
            );
        }
    }
    out
}
