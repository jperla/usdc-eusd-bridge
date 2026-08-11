//! Errors raised while building or self-checking a return-leg proof.

use mc_blockchain_types::BlockID;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// A block header in the chain does not hash to the id it carries.
    #[error("block {index} carries an id that is not the hash of its own fields")]
    BlockIdNotSelfConsistent { index: u64 },

    /// Consecutive headers do not link.
    #[error("block {index} does not name block {expected_index} as its parent")]
    ChainBroken { index: u64, expected_index: u64 },

    #[error("header chain must contain at least two blocks, got {0}")]
    ChainTooShort(usize),

    /// The anchor's `root_element` does not cover the TxOut index. A block's
    /// root_element is the ledger root the block was *validated against*, so it
    /// commits to the TxOuts that existed BEFORE the block, not to the block's
    /// own outputs.
    #[error(
        "anchor block {anchor_index} commits to TxOuts [0,{covered}) which does not include {index}"
    )]
    AnchorDoesNotCover {
        anchor_index: u64,
        covered: u64,
        index: u64,
    },

    #[error("TxOut index {index} is not in the tree, which holds {len} outputs")]
    IndexOutOfBounds { index: u64, len: u64 },

    #[error("membership proof for index {index} does not reproduce the expected root")]
    MembershipProofInvalid { index: u64 },

    // MembershipProofError does not implement std::error::Error upstream, so it
    // cannot be a #[source]; carry its rendering instead of dropping it.
    #[error("membership proof for index {index} is malformed: {detail}")]
    MembershipProofMalformed { index: u64, detail: String },

    #[error("signature {position} over block {block_id} does not verify")]
    BadBlockSignature { position: usize, block_id: BlockID },

    #[error("signature {position} is from a key that is not in the declared signer set")]
    UnknownSigner { position: usize },

    #[error("signer at position {position} already signed; a duplicate cannot count twice")]
    DuplicateSigner { position: usize },

    #[error("{got} valid signatures does not meet the threshold of {threshold}")]
    ThresholdNotMet { got: usize, threshold: u32 },

    #[error("declared threshold {threshold} cannot be met by {signers} signers")]
    UnsatisfiableThreshold { threshold: u32, signers: usize },

    /// Raised by MobileCoin's own `TrustedValidatorSet`.
    #[error("MobileCoin's light-client verifier rejected the metadata quorum: {0}")]
    MetadataQuorum(String),

    #[error("the tree is empty, so it has no root")]
    EmptyTree,

    #[error("TxOut index {index} exceeds what a u64-indexed binary tree can address")]
    TreeCapacityExceeded { index: u64 },

    #[error("could not open the output's amount commitment with the supplied view key: {0}")]
    AmountNotRecoverable(String),

    /// The recovered value does not re-derive the commitment in the TxOut. If
    /// this fires the bundle would have published an amount that the chain does
    /// not actually commit to.
    #[error("recovered amount does not reproduce the output's commitment")]
    CommitmentMismatch,

    #[error("memo is {len} bytes of payload data, too short to carry a 20-byte address")]
    MemoTooShort { len: usize },

    #[error("memo type is {got:02x?}, not the bridge return memo {want:02x?}")]
    MemoWrongType { got: [u8; 2], want: [u8; 2] },

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = core::result::Result<T, Error>;
