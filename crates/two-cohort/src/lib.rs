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
//! belongs to no output in the ring. Consensus itself refuses it. The gate
//! COHORT is not a policy check layered on top of the spend path -- it is
//! inside it.
//!
//! **Two different things in this crate are called a gate, and only one of them
//! is inside anything.** The sentence above is about the gate COHORT and its
//! share of `b`; it is a statement about the algebra and it holds. The RELEASE
//! GATE, [`production::authorize_release`], is the other one: it is an ordinary
//! `Result` a caller must remember to ask for, several public routes to a
//! fundable key do not pass through it, and `production`'s module docs list
//! them. A review reading "the gate is inside the spend path" here took it for
//! the second claim, which would be false; hence this paragraph.
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
//! * **~~No DEALING ceremony.~~ CLOSED by [`dkg`] and [`ceremony`].** Each
//!   cohort now runs Serai's PedPoP independently, so no process holds a
//!   cohort's secret WHEN THE PARTICIPANTS ARE SEPARATE PROCESSES -- the
//!   qualifier matters, because [`dkg::run_dkg`] deliberately runs every
//!   participant in one and hands back every share, which is what the tests and
//!   single-host simulations use. Every participant checks its share against the
//!   dealer's published VSS commitments. The two components are then composed
//!   by a commit-then-reveal ceremony with a cross-cohort proof of possession,
//!   whose output is a [`CompositionArtifact`] any third party can [`audit`].
//!   [`Cohort::deal`] remains, and [`CompositeSpend::simulate`] and
//!   [`dkg::run_dkg`] with them, for the tests and the single-host simulations
//!   that need a dealing to compare against. They are ordinary `pub` functions
//!   with no feature gate, so **the dealer is gone from the honest path, not
//!   from the crate**: one process can call `run_dkg` twice and produce an
//!   artifact that satisfies every check about key material, which is exactly
//!   what `tests/composition.rs`'s end-to-end test is. What that process cannot
//!   do is get the artifact past [`audit`], because the audit now takes the two
//!   organisations' identity public keys and each cohort's commitment must be
//!   signed by its own --
//!   `tests/attribution.rs::one_process_can_produce_an_artifact_that_passes_every_structural_check`
//!   performs both halves. The residual OF THAT ARM is a party holding BOTH
//!   organisations' identity private keys, which the same file performs rather
//!   than glosses -- and since the per-seat rework it is no longer the residual
//!   of the AUDIT, because every seat's endorsement must verify too. This
//!   sentence stood unqualified after that stopped being true; the audit's own
//!   residual is `tests/seat_identity.rs::the_residual_is_a_party_that_holds_every_seat_key`
//!   and the sharper `tests/seat_forgery.rs`. A production
//!   [`CompositeSpend`] is built by [`CompositeSpend::from_ceremony`], and its
//!   [`provenance`](CompositeSpend::provenance) records which route it came by.
//!   [`production::authorize_release`] READS that field: it refuses
//!   [`Provenance::Simulated`] and pins both rosters and thresholds to the
//!   decided structure, and it is the only thing that can issue the
//!   [`ReleaseAuthorization`](production::ReleaseAuthorization) a funding path
//!   takes -- so a simulated root is no longer indistinguishable from a
//!   ceremony root at the point of use. What that does NOT do is stop a caller
//!   inside this crate from calling `simulate`; the dealer is gone from the
//!   honest path and from the release path, not from the crate.
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
//! * **~~Trusted dealer, no DKG.~~ CLOSED by [`dkg`] and [`ceremony`].** The
//!   rogue-key attack is exhibited, performed, in `tests/rogue_key.rs` and
//!   refused in `tests/rogue_key_inverted.rs`. What remains open is stated
//!   precisely in [`ceremony`]'s "What a funder can check, and what it still
//!   cannot": the artifact does not prove the commitments preceded the reveals
//!   (that half is enforced at the share, by
//!   [`ceremony::prove_possession`] refusing to answer a second sealed
//!   composition, and is therefore a property of holders running THIS code
//!   rather than of the published bytes), **does not distinguish a cohort that
//!   ran a DKG from one that used a dealer** -- a dealer that KEPT the secret,
//!   not merely one that deleted it, which is the case that matters. What that
//!   dealer must now COLLECT is a signature from every named SEAT key as well as
//!   its own organisation signature, because the artifact carries one identity
//!   per seat and each seat signs for its own verification share --
//!   `tests/forgery.rs` mounts the dealer forgery the two ways a dealer with no
//!   such signatures can mount it and both are refused. It need not hold those
//!   private keys: the signed bytes are public and reveal nothing, so parties
//!   that sign without ever being dealt a share are enough, which
//!   `tests/seat_identity.rs::a_dealer_that_keeps_the_shares_and_collects_signatures_still_passes`
//!   performs -- that test forges the OWNER cohort and therefore collects THREE
//!   seat signatures plus the owner organisation's, the honest gate supplying
//!   the artifact's fourth seat endorsement itself. So the audit does not
//!   establish that the two organisation keys
//!   are two independent organisations, does not establish that the four seat
//!   keys are four independent principals, and does not bind a seat's signer to
//!   a seat's share-holder -- what changed is the number of distinct signatures
//!   a forgery must collect: from one to FOUR for a dealt-owner forgery at the
//!   decided shape, or from two to six if both cohorts are fabricated. ("From
//!   one to five" stood here and was neither; `ceremony`'s module docs write the
//!   arithmetic out, and
//!   `tests/seat_forgery.rs::a_seat_holder_with_a_real_share_endorses_a_substituted_dealing_and_it_audits`
//!   counts it. That test is also the sharper residual: the named parties hold
//!   REAL shares from a real DKG and endorse a substituted dealing anyway,
//!   because `ceremony::endorse_seat` consults no share and
//!   `dkg::CohortShare::endorse` is the only entry point that does.) It also
//!   does not make the VIEW service accountable -- a service that publishes a
//!   `D_i` which is not a subaddress of the audited root sends deposits
//!   somewhere the cohorts cannot sign for. **It CAN spend them.** This line
//!   said "unlike a rogue cohort it cannot spend it", which [`ceremony`]'s own
//!   module docs had already struck as false and review found still standing
//!   here: nothing forces a lying publisher to derive `D` from `B`, so it can
//!   publish `D = d*G` of its own and open anything paid there with
//!   `Hs(a*R) + d`. A funder holding the view key closes it with
//!   [`ceremony::audit_address`], which is why that key is not optional.
//! * **Both DKGs assume an authenticated broadcast channel.** PedPoP requires
//!   one and this crate does not supply one. A participant that sends two
//!   different commitment messages to two different peers is faulty and
//!   invisible here.
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
pub mod ceremony;
pub mod cohort;
pub mod composite;
pub mod control;
pub mod derive;
pub mod dkg;
pub mod error;
pub mod fixture;
pub mod identity;
pub mod mlsag;

pub use ceremony::{
    audit, audit_address, AuditedAddress, AuditedRoot, CeremonyError, CeremonyId, CohortStructure,
    ComponentClaim, ComponentCommitment, ComponentReveal, CompositionArtifact, Parties, Pop,
    SealedComposition, SeatRoster, SignedCommitment,
};
pub use identity::{IdentityKey, IdentityPublic, IdentitySignature};
pub use cohort::{lagrange_at_zero, Cohort, ParticipantTerm};
pub use composite::{CohortSpec, CompositeSpend, KeyImageTerms, Provenance};
pub use control::{ControlDomain, Gates, Owners, NAMESPACE_SPAN};
pub use dkg::{CohortKey, CohortShare, DkgError};
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
