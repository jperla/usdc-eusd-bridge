//! The header chain, and the reason the return leg needs more than one block.
//!
//! A `Block`'s `root_element` is documented upstream as "root hash of the
//! membership proofs provided by the untrusted local system for validation",
//! and `consensus/service/src/byzantine_ledger/worker.rs` reads it from the
//! ledger *before* handing the block to the enclave to be formed. So block N's
//! `root_element` commits to the TxOuts that existed before block N -- it does
//! NOT commit to block N's own outputs.
//!
//! That has a sharp consequence for anyone building a return proof: you cannot
//! prove that the return output is in the ledger using the header of the block
//! that created it. You need a later block. The smallest useful chain is three
//! headers,
//!
//! ```text
//! parent(origin)  ->  origin  ->  anchor
//! ```
//!
//! where `origin` is the block that created the output and `anchor` is any
//! later block whose `root_element` therefore covers it. What the chain buys:
//!
//!   * `anchor.root_element` is the root the membership proof is checked
//!     against, and `anchor` is the block the validator quorum signs. This is
//!     the inclusion proof.
//!
//!   * TxOut indices are assigned in block order and `cumulative_txo_count` is
//!     "including this block", so
//!
//!     ```text
//!     parent(origin).cumulative_txo_count <= i < origin.cumulative_txo_count
//!     ```
//!
//!     pins the output at global index `i` to block `origin` -- without opening
//!     `contents_hash`. Each header hashes to the id it carries and names its
//!     predecessor, so the two counts cannot be moved independently.
//!
//! This is why `blockIndex` in a `VerifiedReturn` can be the block that created
//! the output rather than merely the block that was signed.

use mc_blockchain_types::Block;

use crate::error::{Error, Result};

/// A contiguous, verified run of block headers, ascending by index.
#[derive(Clone, Debug)]
pub struct HeaderChain {
    headers: Vec<Block>,
}

impl HeaderChain {
    /// Build and verify. Nothing else in this crate can construct a
    /// `HeaderChain`, so possession of one means the checks below have run.
    pub fn new(headers: Vec<Block>) -> Result<Self> {
        if headers.len() < 2 {
            return Err(Error::ChainTooShort(headers.len()));
        }
        for (position, header) in headers.iter().enumerate() {
            // Upstream's own check that the header's `id` is the hash of the
            // header's other fields.
            if !header.is_block_id_valid() {
                return Err(Error::BlockIdNotSelfConsistent {
                    index: header.index,
                });
            }
            if position > 0 {
                let prev = &headers[position - 1];
                if header.parent_id != prev.id || header.index != prev.index + 1 {
                    return Err(Error::ChainBroken {
                        index: header.index,
                        expected_index: prev.index + 1,
                    });
                }
            }
        }
        Ok(Self { headers })
    }

    pub fn headers(&self) -> &[Block] {
        &self.headers
    }

    /// The block whose `root_element` the membership proof is checked against,
    /// and the block the quorum signs.
    pub fn anchor(&self) -> &Block {
        self.headers.last().expect("checked non-empty in new()")
    }

    /// How many TxOuts `anchor.root_element` commits to: everything that
    /// existed before the anchor was formed, i.e. the cumulative count as of
    /// the anchor's parent.
    pub fn anchor_covers(&self) -> u64 {
        self.headers[self.headers.len() - 2].cumulative_txo_count
    }

    /// The block that created the TxOut at global index `index`, established
    /// from the chained cumulative counts. `None` if no header in the chain
    /// brackets it.
    pub fn block_creating_txout(&self, index: u64) -> Option<&Block> {
        self.headers.windows(2).find_map(|w| {
            let (before, block) = (&w[0], &w[1]);
            (before.cumulative_txo_count <= index && index < block.cumulative_txo_count)
                .then_some(block)
        })
    }

    /// The anchor must actually commit to the output, or the membership proof
    /// is being checked against a root that predates it.
    pub fn require_covers(&self, index: u64) -> Result<()> {
        let covered = self.anchor_covers();
        if index >= covered {
            return Err(Error::AnchorDoesNotCover {
                anchor_index: self.anchor().index,
                covered,
                index,
            });
        }
        Ok(())
    }
}
