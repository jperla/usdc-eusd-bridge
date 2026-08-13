//! The two ways a MobileCoin block can be shown to a quorum of validators, and
//! why the choice is in the API rather than buried in a default.
//!
//! MobileCoin signs a finalized block twice, with different shapes:
//!
//! `BlockSignature` (blockchain/types/src/block_signature.rs) is Ed25519 over
//! `block.digest32::<MerlinTranscript>(b"block-sig")`. That digest is a
//! function of the block alone, so every validator that signs block N signs the
//! *same* 32 bytes. An Ethereum verifier drives merlin once and then does k
//! cheap `ed25519` verifications against one message. The per-signature cost is
//! a signature check and nothing else.
//!
//! `BlockMetadata` (blockchain/types/src/block_metadata.rs) is Ed25519 over
//! `contents.digest32::<MerlinTranscript>(b"block_metadata")`, where `contents`
//! carries that node's own responder id, its own quorum set, and its own
//! attestation evidence (an IAS report or DCAP evidence). Two validators never
//! sign the same bytes. This is the route MobileCoin's light client uses
//! (`light-client/verifier/src/trusted_validator_set.rs`), and it buys real
//! things -- the signature is bound to an attested enclave and to the quorum
//! set in force at externalization -- but on Ethereum it means k independent
//! merlin transcripts over k independent, attacker-sized preimages. Nothing
//! amortizes.
//!
//! Both are supported. Neither is the default, because picking one is a
//! decision about what the bridge trusts and what it is willing to pay for, and
//! that decision should be visible at the call site.

use mc_blockchain_types::{Block, BlockID, BlockMetadata, BlockSignature};
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::Ed25519Public;
use mc_transaction_core::tx::TxOut;
use mc_light_client_verifier::TrustedValidatorSet;

use crate::{
    error::{Error, Result},
    transcript::{record, TranscriptScript},
};

/// Which family of validator signature the bundle carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationRoute {
    /// One digest, k signatures. See module docs.
    BlockSignature,
    /// k digests, k signatures, each over that node's own metadata.
    BlockMetadata,
}

impl AttestationRoute {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlockSignature => "block_signature",
            Self::BlockMetadata => "block_metadata",
        }
    }
}

/// The merlin script for `block.digest32(b"block-sig")` -- the single message
/// every `BlockSignature` over this block is made against.
pub fn block_sig_script(block: &Block) -> TranscriptScript {
    // `Digestible::digest32` opens the transcript with b"digestible" and
    // squeezes under b"digest32"; `Recorder::new` matches that, and `record`
    // is handed the same labels so the recording cannot silently drift.
    record(b"digestible", b"digest32", |t| {
        block.append_to_transcript(b"block-sig", t)
    })
}

/// The merlin script for `compute_block_id`.
///
/// Note this is *not* a `digest32` call: `compute_block_id` opens its own
/// transcript under `b"mobilecoin-block-id"` and appends the six header fields
/// by hand, so the recording has to be built the same way rather than by
/// digesting the `Block`.
pub fn block_id_script(block: &Block) -> TranscriptScript {
    record(b"mobilecoin-block-id", b"digest32", |t| {
        block.version.append_to_transcript(b"version", t);
        block.parent_id.append_to_transcript(b"parent_id", t);
        block.index.append_to_transcript(b"index", t);
        block
            .cumulative_txo_count
            .append_to_transcript(b"cumulative_txo_count", t);
        block.root_element.append_to_transcript(b"root_element", t);
        block
            .contents_hash
            .append_to_transcript(b"contents_hash", t);
    })
}

/// The merlin script for `TxOut::hash()`, which is the preimage of the Merkle
/// leaf hash -- the leaf cannot be recomputed without it.
pub fn tx_out_digest_script(tx_out: &TxOut) -> TranscriptScript {
    record(b"digestible", b"digest32", |t| {
        tx_out.append_to_transcript(b"mobilecoin-txout", t)
    })
}

/// The merlin script for one node's `BlockMetadataContents` digest.
pub fn block_metadata_script(meta: &BlockMetadata) -> TranscriptScript {
    record(b"digestible", b"digest32", |t| {
        meta.contents().append_to_transcript(b"block_metadata", t)
    })
}

/// A k-of-n set of `BlockSignature`s over one block.
///
/// MobileCoin itself never assembles this: a node's `ArchiveBlock` carries that
/// node's single signature, and there is no upstream type for "k of them". The
/// relayer collects one from each of n independently-run archive endpoints. The
/// threshold logic below is therefore ours, not upstream's -- but the part that
/// matters cryptographically, `BlockSignature::verify`, is upstream's, and the
/// tests exercise the threshold logic directly rather than assuming it.
#[derive(Clone, Debug)]
pub struct BlockSignatureQuorum {
    /// The signing keys the bridge trusts, in a fixed published order.
    pub signers: Vec<Ed25519Public>,
    /// How many distinct members of `signers` must have signed.
    pub threshold: u32,
    pub signatures: Vec<BlockSignature>,
}

impl BlockSignatureQuorum {
    /// Verify every signature against the block with upstream's verifier, then
    /// count distinct trusted signers against the threshold.
    pub fn verify(&self, block: &Block) -> Result<()> {
        if self.threshold as usize > self.signers.len() {
            return Err(Error::UnsatisfiableThreshold {
                threshold: self.threshold,
                signers: self.signers.len(),
            });
        }

        let mut seen: Vec<&Ed25519Public> = Vec::new();
        for (position, sig) in self.signatures.iter().enumerate() {
            // Upstream's check: recomputes the block-sig digest and verifies.
            sig.verify(block).map_err(|_| Error::BadBlockSignature {
                position,
                block_id: block.id.clone(),
            })?;

            if !self.signers.contains(sig.signer()) {
                return Err(Error::UnknownSigner { position });
            }
            // A relayer that repeats one node's signature k times must not
            // reach the threshold; k-of-n means k distinct nodes.
            if seen.contains(&sig.signer()) {
                return Err(Error::DuplicateSigner { position });
            }
            seen.push(sig.signer());
        }

        if seen.len() < self.threshold as usize {
            return Err(Error::ThresholdNotMet {
                got: seen.len(),
                threshold: self.threshold,
            });
        }
        Ok(())
    }
}

/// A quorum of `BlockMetadata`, checked by MobileCoin's own light client.
#[derive(Clone, Debug)]
pub struct BlockMetadataQuorum {
    pub validator_set: TrustedValidatorSet,
    pub metadata: Vec<BlockMetadata>,
}

impl BlockMetadataQuorum {
    /// Delegates wholesale to `TrustedValidatorSet::verify_block_id_signatures`
    /// -- signature validity, block-id agreement and the recursive SCP quorum
    /// count are all upstream's.
    pub fn verify(&self, block_id: &BlockID) -> Result<()> {
        self.validator_set
            .verify_block_id_signatures(block_id, &self.metadata)
            .map_err(|e| Error::MetadataQuorum(format!("{e:?}")))
    }
}

/// The quorum evidence carried by a bundle. One variant per route; there is no
/// "either" case, because a verifier that accepts either accepts the weaker.
#[derive(Clone, Debug)]
pub enum QuorumEvidence {
    BlockSignature(BlockSignatureQuorum),
    BlockMetadata(BlockMetadataQuorum),
}

impl QuorumEvidence {
    pub fn route(&self) -> AttestationRoute {
        match self {
            Self::BlockSignature(_) => AttestationRoute::BlockSignature,
            Self::BlockMetadata(_) => AttestationRoute::BlockMetadata,
        }
    }

    pub fn verify(&self, block: &Block) -> Result<()> {
        match self {
            Self::BlockSignature(q) => q.verify(block),
            Self::BlockMetadata(q) => q.verify(&block.id),
        }
    }
}
