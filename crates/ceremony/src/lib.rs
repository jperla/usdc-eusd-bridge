//! Threshold signing ceremony for the bridge's MobileCoin side.
//!
//! Releases from the MobileCoin side require a composite spend key -- (k-of-n
//! operators) AND (g-of-m gates) -- and the gate share enters the key image, so
//! consensus itself rejects a release that skipped the gates. What this crate
//! owns is the *ceremony*: the sequencing that turns a set of signers into one
//! signature without any of them losing a key along the way.
//!
//! Four properties, each model-checked in TLA+ and each with a test here that
//! fails if its guard is removed:
//!
//!   1. One-time values are never reused. Keyed on the FULL signing context --
//!      statement, subset, and the complete round-one package. See
//!      `store::BindingStore` and `tests/one_time_values.rs`, which shows the
//!      narrower (statement, subset) key permitting three replays that recover
//!      the long-term share by Gaussian elimination.
//!
//!   2. Anti-rollback. The one-time value is durably committed before anything
//!      observable happens, and a store restored from an earlier snapshot is
//!      caught by an anchor that did not roll back with it. See `store::Anchor`
//!      and `tests/rollback.rs`.
//!
//!   3. Identifiable abort. Round messages are signed under per-participant
//!      IDENTITY keys, separate from the threshold shares, because a threshold
//!      transcript is forgeable by the quorum it would incriminate. See
//!      `identity` and `tests/identifiable_abort.rs`.
//!
//!   4. Sub-threshold subsets cannot complete a ceremony. See
//!      `tests/threshold.rs`.
//!
//! The authorisation backend is a trait (`authorizer::Authorizer`), so the
//! machine can be tested without a real signer. `frost` is a reference
//! implementation that is real enough to fail: below threshold its aggregate
//! genuinely does not verify.

pub mod authorizer;
pub mod context;
pub mod frost;
pub mod identity;
pub mod machine;
pub mod store;

pub use authorizer::Authorizer;
pub use context::{
    Commitment, ContextId, ParticipantId, RoundOnePackage, Share, SigningContext, SlotId,
    Statement, Subset,
};
pub use identity::{IdentityKey, IdentityPublic, IdentitySignature, SignedRoundOne, SignedRoundTwo};
pub use machine::{AbortEvidence, Ceremony, Error, EvidenceError, Roster, State};
pub use store::{Anchor, AnchorError, BindingStore, MemoryAnchor, MemoryStore, Receipt, StoreError};
