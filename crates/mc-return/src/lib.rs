//! The relayer-side half of the bridge's RETURN leg.
//!
//! A user sends eUSD to the bridge's MobileCoin return address `R`. This crate
//! takes the resulting on-chain state and produces the artifact an Ethereum
//! verifier consumes: a proof that a particular eUSD output was paid to `R` and
//! is finalized in the MobileCoin ledger, together with everything needed to
//! recompute -- rather than believe -- every hash in it.
//!
//! Three things have to hold, and this crate proves each of them separately so
//! that a failure names which one broke:
//!
//!   1. INCLUSION. The output sits at a global TxOut index whose Merkle path
//!      folds to the `root_element` of a block. `merkle` builds the path;
//!      MobileCoin's own `is_membership_proof_valid` checks it.
//!
//!   2. FINALITY. That block was signed by a quorum of validators. `attestation`
//!      offers the two routes MobileCoin actually provides and makes the caller
//!      choose; the metadata route is checked by MobileCoin's own light-client
//!      verifier.
//!
//!   3. PROVENANCE. The output was created by a specific block, and that block
//!      is an ancestor of the signed one. `chain` gets this from the chained
//!      `cumulative_txo_count` fields without opening any block's contents.
//!
//! A `ReturnProof` can only be produced by [`ReturnProof::build`], which runs
//! all three plus the disclosure checks. There is no way to assemble one from
//! parts that have not been checked.

pub mod attestation;
pub mod bundle;
pub mod chain;
pub mod disclosure;
pub mod error;
pub mod merkle;
pub mod transcript;

use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_transaction_core::{
    membership_proofs::is_membership_proof_valid,
    tx::{TxOut, TxOutMembershipProof},
};

pub use attestation::{
    AttestationRoute, BlockMetadataQuorum, BlockSignatureQuorum, QuorumEvidence,
};
pub use chain::HeaderChain;
pub use disclosure::{Disclosure, BRIDGE_RETURN_MEMO_TYPE};
pub use error::{Error, Result};
pub use merkle::TxOutTree;
pub use transcript::TranscriptScript;

/// The merlin script behind `TxOut::hash()`, which is the preimage of the
/// Merkle leaf hash.
pub fn tx_out_digest_script(tx_out: &TxOut) -> TranscriptScript {
    bundle::tx_out_digest_script_inner(tx_out)
}

/// A checked return-leg proof.
#[derive(Debug)]
pub struct ReturnProof {
    pub chain: HeaderChain,
    pub tx_out: TxOut,
    pub tx_out_index: u64,
    pub membership_proof: TxOutMembershipProof,
    pub quorum: QuorumEvidence,
    pub disclosure: Disclosure,
    /// Index of the block that created the output, derived from the chain.
    pub origin_block_index: u64,
}

impl ReturnProof {
    /// Assemble and self-check.
    ///
    /// `tree` must be the TxOut tree as of the anchor -- i.e. holding exactly
    /// the outputs the anchor's `root_element` commits to. That is not taken on
    /// trust: the membership proof is checked against the anchor's root hash,
    /// which fails if the tree is a different size or shape.
    pub fn build(
        chain: HeaderChain,
        tree: &TxOutTree,
        tx_out_index: u64,
        quorum: QuorumEvidence,
        view_private_key: &RistrettoPrivate,
        return_subaddress_spend_public: &RistrettoPublic,
    ) -> Result<Self> {
        let anchor = chain.anchor().clone();

        // (3) Provenance first, because it is the check most likely to catch a
        // caller that picked the wrong anchor, and its error says so.
        chain.require_covers(tx_out_index)?;
        let origin_block_index = chain
            .block_creating_txout(tx_out_index)
            .ok_or(Error::AnchorDoesNotCover {
                anchor_index: anchor.index,
                covered: chain.anchor_covers(),
                index: tx_out_index,
            })?
            .index;

        let tx_out = tree
            .get(tx_out_index)
            .ok_or(Error::IndexOutOfBounds {
                index: tx_out_index,
                len: tree.len(),
            })?
            .clone();

        // (1) Inclusion, adjudicated by upstream.
        let membership_proof = tree.proof_of_membership(tx_out_index)?;
        let ok = is_membership_proof_valid(
            &tx_out,
            &membership_proof,
            anchor.root_element.hash.as_ref(),
        )
        .map_err(|e| Error::MembershipProofMalformed {
            index: tx_out_index,
            detail: format!("{e}"),
        })?;
        if !ok {
            return Err(Error::MembershipProofInvalid {
                index: tx_out_index,
            });
        }

        // (2) Finality.
        quorum.verify(&anchor)?;

        let disclosure = Disclosure::open(&tx_out, view_private_key)?;
        disclosure.require_paid_to(return_subaddress_spend_public)?;

        Ok(Self {
            chain,
            tx_out,
            tx_out_index,
            membership_proof,
            quorum,
            disclosure,
            origin_block_index,
        })
    }

    /// Write the fixture the Solidity suite reads.
    pub fn write_fixture(&self, path: &std::path::Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, bundle::to_pretty_string(&self.to_json())?)?;
        Ok(())
    }
}
