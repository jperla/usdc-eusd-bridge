//! The TxOut Merkle tree, checked two ways: against a whole-tree definition
//! written out declaratively here, and against MobileCoin's own proof
//! validator.
//!
//! The declarative check matters because `TxOutTree::push` is incremental --
//! it rewrites only the nodes on the new leaf's root path. An incremental
//! algorithm and a "hash the whole tree from scratch" definition are different
//! computations; agreeing on trees of many shapes is evidence. Checking the
//! incremental algorithm against itself would not be.

mod common;

use common::*;
use mc_transaction_core::{
    membership_proofs::{
        compute_implied_merkle_root, hash_leaf, hash_nodes, is_membership_proof_valid, NIL_HASH,
    },
    tx::{TxOut, TxOutMembershipHash},
};
use mc_return::TxOutTree;

/// The hash of the node spanning `[from, to]` of a tree holding `leaves`,
/// defined top-down over the whole padded tree.
///
/// The one rule that is not "just hash the children" is upstream's: a right
/// subtree containing no leaves at all is the NIL hash, not `H(nil, nil)`.
/// See `tx_out_store::update_merkle_hashes`.
fn expected_hash(leaves: &[TxOut], from: u64, to: u64) -> [u8; 32] {
    let n = leaves.len() as u64;
    if from == to {
        return if from < n {
            hash_leaf(&leaves[from as usize])
        } else {
            *NIL_HASH
        };
    }
    let mid = (from + to) / 2;
    let left = expected_hash(leaves, from, mid);
    let right = if mid + 1 >= n {
        *NIL_HASH
    } else {
        expected_hash(leaves, mid + 1, to)
    };
    hash_nodes(&left, &right)
}

fn build(n: usize) -> (TxOutTree, Vec<TxOut>) {
    let mut r = rng(3);
    let leaves: Vec<TxOut> = (0..n).map(|i| filler_tx_out(&mut r, i as u64)).collect();
    let mut tree = TxOutTree::new();
    for leaf in &leaves {
        tree.push(leaf.clone()).unwrap();
    }
    (tree, leaves)
}

#[test]
fn root_matches_whole_tree_definition() {
    for n in 1..=9usize {
        let (tree, leaves) = build(n);
        let root = tree.root_element().unwrap();
        let full = (n as u64).next_power_of_two();
        assert_eq!(root.range.from, 0, "n={n}");
        assert_eq!(root.range.to, full - 1, "n={n}");
        assert_eq!(
            root.hash,
            TxOutMembershipHash::from(expected_hash(&leaves, 0, full - 1)),
            "root disagrees with the whole-tree definition at n={n}"
        );
    }
}

#[test]
fn two_leaf_root_is_hash_of_the_two_leaves() {
    // Spelled out with no recursion anywhere, as a floor under the test above.
    let (tree, leaves) = build(2);
    let want = hash_nodes(&hash_leaf(&leaves[0]), &hash_leaf(&leaves[1]));
    assert_eq!(tree.root_element().unwrap().hash.as_ref(), &want);
}

#[test]
fn three_leaf_root_pads_the_missing_sibling_with_nil() {
    let (tree, leaves) = build(3);
    let left = hash_nodes(&hash_leaf(&leaves[0]), &hash_leaf(&leaves[1]));
    let right = hash_nodes(&hash_leaf(&leaves[2]), &NIL_HASH);
    assert_eq!(
        tree.root_element().unwrap().hash.as_ref(),
        &hash_nodes(&left, &right)
    );
}

#[test]
fn upstream_validates_every_proof() {
    for n in 1..=9usize {
        let (tree, leaves) = build(n);
        let root = tree.root_element().unwrap();
        for i in 0..n as u64 {
            let proof = tree.proof_of_membership(i).unwrap();
            assert_eq!(proof.index, i);
            assert_eq!(proof.highest_index, n as u64 - 1);
            assert_eq!(
                is_membership_proof_valid(&leaves[i as usize], &proof, root.hash.as_ref()),
                Ok(true),
                "upstream rejected a proof for index {i} of {n}"
            );
            // The ledger's own invariant: folding the proof reproduces the
            // root element exactly, range included.
            assert_eq!(compute_implied_merkle_root(&proof).unwrap(), root, "n={n} i={i}");
        }
    }
}

#[test]
fn a_tampered_proof_element_is_rejected() {
    let (tree, leaves) = build(5);
    let root = tree.root_element().unwrap();
    // Every element above the leaf, one at a time -- so the test cannot pass
    // by only ever catching the first.
    for pos in 1..tree.proof_of_membership(1).unwrap().elements.len() {
        let mut proof = tree.proof_of_membership(1).unwrap();
        proof.elements[pos].hash.0[0] ^= 0x01;
        assert_eq!(
            is_membership_proof_valid(&leaves[1], &proof, root.hash.as_ref()),
            Ok(false),
            "flipping a bit in element {pos} still validated"
        );
    }
}

#[test]
fn a_proof_does_not_carry_over_to_another_output() {
    let (tree, leaves) = build(5);
    let root = tree.root_element().unwrap();
    let proof = tree.proof_of_membership(1).unwrap();
    // Same proof, different TxOut: upstream must catch the leaf mismatch.
    assert!(
        is_membership_proof_valid(&leaves[2], &proof, root.hash.as_ref()).is_err(),
        "a proof for output 1 was accepted for output 2"
    );
}

#[test]
fn a_proof_does_not_survive_the_tree_growing() {
    // A proof is against one root. If the relayer builds the path from a tree
    // that has moved on from the block it is anchoring to, the check must fail
    // -- this is what makes `ReturnProof::build` unable to lie about which
    // ledger state it used.
    let mut r = rng(3);
    let leaves: Vec<TxOut> = (0..6).map(|i| filler_tx_out(&mut r, i)).collect();

    let mut small = TxOutTree::new();
    for leaf in &leaves[..5] {
        small.push(leaf.clone()).unwrap();
    }
    let mut big = TxOutTree::new();
    for leaf in &leaves {
        big.push(leaf.clone()).unwrap();
    }

    let small_root = small.root_element().unwrap();
    let big_root = big.root_element().unwrap();
    assert_ne!(small_root.hash, big_root.hash);

    let proof = big.proof_of_membership(1).unwrap();
    assert_eq!(
        is_membership_proof_valid(&leaves[1], &proof, small_root.hash.as_ref()),
        Ok(false),
        "a proof from the 6-leaf tree validated against the 5-leaf root"
    );
}

#[test]
fn index_past_the_end_is_an_error() {
    let (tree, _) = build(4);
    assert!(tree.proof_of_membership(4).is_err());
    assert!(tree.get(4).is_none());
}

#[test]
fn empty_tree_has_no_root() {
    assert!(TxOutTree::new().root_element().is_err());
}
