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
//! # Control-domain independence
//!
//! "Different entities" is the entire premise, and it is not something the
//! algebra can check: interpolation over `{1,2,3}` is the same arithmetic
//! whichever roster those ids were meant to name. If both cohorts are dealt
//! over `{1,2,3}` then every owner subset is also a qualifying gate subset,
//! `gates.weighted(owner_subset)` succeeds, and the gate argument is dead code
//! that no test can distinguish from a live one.
//!
//! [`control`] therefore makes cohort identity structural. [`Owners`] and
//! [`Gates`] are distinct types -- passing a gate spec where an owner spec
//! belongs does not compile -- and each owns a disjoint band of participant
//! ids, so a subset that reaches the wrong cohort at runtime is rejected
//! instead of interpolated.
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
//! use two_cohort::{CohortSpec, CompositeSpend, ControlDomain, Gates, Owners};
//!
//! // 2-of-3 owners AND 2-of-3 gates over one root.
//! let owners = CohortSpec::<Owners>::sequential(2, 3);
//! let gates = CohortSpec::<Gates>::sequential(2, 3);
//! let spend = CompositeSpend::simulate_from_seed(42, &owners, &gates, 7)?;
//!
//! // Ids are per-domain, so `o` and `g` are different integers.
//! let (o, g) = (Owners::nth, Gates::nth);
//!
//! // Different quorums, same image.
//! let a = spend.key_image_from_shares(&[o(0), o(1)], &[g(1), g(2)])?;
//! let b = spend.key_image_from_shares(&[o(1), o(2)], &[g(0), g(2)])?;
//! assert_eq!(a, b);
//!
//! // An owner quorum alone reaches somewhere else entirely.
//! assert_ne!(a, spend.key_image_without_gates(&[o(0), o(1)])?);
//!
//! // And an owner quorum is not a gate quorum: the ids are not gate ids.
//! assert!(spend.key_image_from_shares(&[o(0), o(1)], &[o(0), o(1)]).is_err());
//! # Ok::<(), two_cohort::Error>(())
//! ```
//!
//! # What this crate does NOT establish
//!
//! Carried forward from the spike this was promoted from, minus the one
//! [`mlsag`] closed. None of the rest got easier because the code became a
//! library.
//!
//! * **No DEALING ceremony.** Shares are dealt in ONE PROCESS. [`Cohort`] holds
//!   every share; [`Cohort::share`] hands them out. [`mlsag`] made SIGNING a
//!   live two-round protocol over explicit round messages, with participants
//!   that can go offline or lie and are named when they do -- but the shares
//!   that protocol drives still come from a single-process dealing.
//! * **~~No non-reconstruction signing.~~ CLOSED by [`mlsag`].** It produces a
//!   `RingMLSAG` the unmodified verifier accepts without any process forming
//!   the one-time scalar: each participant emits only `alpha_i - c*w_i`, and
//!   the coordinator sums those. [`CompositeSpend::onetime`] remains, because
//!   the tests need an independently computed `x` to check the key image
//!   against, and a production signer still must not call it.
//! * **No policy over a decoded transaction.** [`mlsag`] participants hold the
//!   session they are signing -- message, ring, real index, output commitment
//!   -- and derive the challenge from it themselves, so a coordinator cannot
//!   carry round one into a different transaction. But the message is opaque
//!   bytes to them. Reading amounts and recipients out of it needs
//!   MobileCoin's `TxSummary` and its streaming verifier, which is not wired
//!   up here. Until it is, a gate can refuse a session; it cannot refuse a
//!   PAYEE.
//! * **No concurrency defence.** [`mlsag`] aggregates one nonce commitment per
//!   participant linearly, with no binding factor, and nothing bounds how many
//!   sessions a share-holder may have open. That is the ROS/Drijvers setting.
//!   The shape in `crates/ceremony/src/frost.rs` -- two commitments and a
//!   per-participant binding factor over the whole round-one package -- is the
//!   known fix and is not ported.
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

pub mod production;
pub mod cohort;
pub mod composite;
pub mod control;
pub mod derive;
pub mod error;
pub mod fixture;
pub mod mlsag;

pub use cohort::{lagrange_at_zero, Cohort, ParticipantTerm};
pub use composite::{CohortSpec, CompositeSpend, KeyImageTerms};
pub use control::{ControlDomain, Gates, Owners, NAMESPACE_SPAN};
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
