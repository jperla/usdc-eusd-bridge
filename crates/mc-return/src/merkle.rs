//! An in-memory TxOut Merkle tree that matches the one MobileCoin's ledger
//! keeps.
//!
//! The relayer has to produce a `TxOutMembershipProof` that MobileCoin's own
//! validator accepts against a block's `root_element`. Upstream's tree lives in
//! `mc-ledger-db`, welded to LMDB; pulling LMDB into a relayer to hash 2^k
//! values is not worth it, so this module reproduces the structure and nothing
//! else. It is a mirror of `ledger/db/src/tx_out_store.rs` at rev 05cb699f --
//! `containing_range`, `containing_ranges`, `update_merkle_hashes`,
//! `get_merkle_proof_of_membership` and `get_root_merkle_hash` -- using
//! upstream's `hash_leaf` / `hash_nodes` / `NIL_HASH` (Blake2b-256 under the
//! `mc_tx_out_merkle_{leaf,node,nil}` domain tags) so the hash function itself
//! is not reimplemented at all.
//!
//! Being a mirror, it is only worth as much as the cross-check: every proof
//! this module emits is run through upstream's `is_membership_proof_valid`
//! before it leaves the process, and the tests additionally pin the shape of
//! the tree against hand-computed hashes so that "mirror agrees with mirror"
//! is not the whole of the evidence.

use std::collections::BTreeMap;

use mc_transaction_core::{
    membership_proofs::{hash_leaf, hash_nodes, Range, NIL_HASH},
    tx::{TxOut, TxOutMembershipElement, TxOutMembershipProof},
};

use crate::error::{Error, Result};

/// The leaves in a subtree of the given depth that contains `index`.
///
/// Mirror of `tx_out_store::containing_range`.
fn containing_range(index: u64, depth: u32) -> (u64, u64) {
    let mask: u64 = (1u64 << depth) - 1;
    (index & !mask, index | mask)
}

/// Every enclosing range of `index`, smallest first.
///
/// Mirror of `tx_out_store::containing_ranges`.
fn containing_ranges(index: u64, num_leaves: u64) -> Result<Vec<(u64, u64)>> {
    if index >= num_leaves {
        return Err(Error::IndexOutOfBounds {
            index,
            len: num_leaves,
        });
    }
    let full = num_leaves
        .checked_next_power_of_two()
        .ok_or(Error::TreeCapacityExceeded { index })?;
    let depth: u32 = 64 - full.leading_zeros() - 1;
    Ok((0..=depth).map(|d| containing_range(index, d)).collect())
}

/// The append-only TxOut tree.
#[derive(Default)]
pub struct TxOutTree {
    leaves: Vec<TxOut>,
    /// Hash of the node spanning `(from, to)`. Keyed by the inclusive range,
    /// exactly as upstream keys its LMDB table.
    hashes: BTreeMap<(u64, u64), [u8; 32]>,
}

impl TxOutTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn get(&self, index: u64) -> Option<&TxOut> {
        self.leaves.get(index as usize)
    }

    /// Append a TxOut and return the global index it was assigned.
    pub fn push(&mut self, tx_out: TxOut) -> Result<u64> {
        let index = self.len();
        self.leaves.push(tx_out);
        let n = self.len();

        // Only the nodes on this leaf's root path change, which is why the
        // ledger can do this incrementally. Bottom-up, so each parent reads
        // children that were either written a moment ago or written by an
        // earlier append.
        for (low, high) in containing_ranges(index, n)? {
            let hash = if low == high {
                hash_leaf(&self.leaves[index as usize])
            } else {
                let mid = (low + high) / 2;
                let left = self.hash_at(low, mid)?;
                // A right subtree that starts past the end of the ledger is
                // *nil*, not absent: the tree is always a full binary tree of
                // the next power of two, padded with the nil hash.
                let right = if mid + 1 >= n {
                    *NIL_HASH
                } else {
                    self.hash_at(mid + 1, high)?
                };
                hash_nodes(&left, &right)
            };
            self.hashes.insert((low, high), hash);
        }
        Ok(index)
    }

    fn hash_at(&self, low: u64, high: u64) -> Result<[u8; 32]> {
        self.hashes
            .get(&(low, high))
            .copied()
            .ok_or(Error::IndexOutOfBounds {
                index: low,
                len: self.len(),
            })
    }

    /// The root as a block carries it: the range covers the whole padded tree,
    /// not just the occupied leaves.
    pub fn root_element(&self) -> Result<TxOutMembershipElement> {
        let n = self.len();
        if n == 0 {
            return Err(Error::EmptyTree);
        }
        let full = n
            .checked_next_power_of_two()
            .ok_or(Error::TreeCapacityExceeded { index: n })?;
        let range = Range::new(0, full - 1).map_err(|_| Error::EmptyTree)?;
        let hash = self.hash_at(0, full - 1)?;
        Ok(TxOutMembershipElement {
            range,
            hash: hash.into(),
        })
    }

    /// A proof of membership for the TxOut at `index`, in the order upstream's
    /// validator folds the elements: leaf first, then each sibling on the way
    /// up.
    pub fn proof_of_membership(&self, index: u64) -> Result<TxOutMembershipProof> {
        let n = self.len();
        if index >= n {
            return Err(Error::IndexOutOfBounds { index, len: n });
        }

        let mut ranges = vec![(index, index)];
        for (low, high) in containing_ranges(index, n)?.iter().skip(1) {
            let mid = (low + high) / 2;
            if index <= mid {
                ranges.push((mid + 1, *high));
            } else {
                ranges.push((*low, mid));
            }
        }

        let mut elements = Vec::with_capacity(ranges.len());
        for (low, high) in ranges {
            let range = Range::new(low, high).map_err(|_| Error::IndexOutOfBounds { index, len: n })?;
            // A sibling range entirely past the end of the ledger has no
            // stored hash; it is the nil hash by construction.
            let hash = if low >= n { *NIL_HASH } else { self.hash_at(low, high)? };
            elements.push(TxOutMembershipElement {
                range,
                hash: hash.into(),
            });
        }

        Ok(TxOutMembershipProof::new(index, n - 1, elements))
    }
}
