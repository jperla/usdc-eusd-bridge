//! The recorded merlin scripts must reproduce MobileCoin's digests exactly,
//! and must stop reproducing them the moment anything in the recording moves.
//!
//! The second half is the part that makes the first half worth anything. A
//! recorder that quietly ignored its input and called upstream would pass every
//! equality test here; the mutation tests are what rule that out.

mod common;

use common::*;
use mc_blockchain_types::compute_block_id;
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_return::{
    attestation::{block_id_script, block_metadata_script, block_sig_script},
    tx_out_digest_script,
};

#[test]
fn block_sig_script_reproduces_the_upstream_digest() {
    let s = Scenario::build();
    for block in &s.ledger.blocks {
        let want = block.digest32::<MerlinTranscript>(b"block-sig");
        assert_eq!(
            block_sig_script(block).replay(),
            want,
            "recorded script and Digestible::digest32 disagree for block {}",
            block.index
        );
    }
}

#[test]
fn block_id_script_reproduces_compute_block_id() {
    let s = Scenario::build();
    for block in &s.ledger.blocks {
        let script = block_id_script(block);
        // Against the header's own id...
        assert_eq!(&script.replay(), block.id.as_ref());
        // ...and against upstream's function directly, so a block whose id
        // field had been forged could not make this pass.
        let recomputed = compute_block_id(
            block.version,
            &block.parent_id,
            block.index,
            block.cumulative_txo_count,
            &block.root_element,
            &block.contents_hash,
        );
        assert_eq!(script.replay(), recomputed.0);
    }
}

#[test]
fn tx_out_digest_script_reproduces_tx_out_hash() {
    let s = Scenario::build();
    let tx_out = s.ledger.tree.get(s.return_index).unwrap();
    assert_eq!(tx_out_digest_script(tx_out).replay(), tx_out.hash());
}

#[test]
fn metadata_script_reproduces_what_the_node_signed() {
    let s = Scenario::build();
    let anchor = s.ledger.block(2);
    let q = block_metadata_quorum(&s.validators, &[0, 1, 2], 3, anchor);
    for meta in &q.metadata {
        let script = block_metadata_script(meta);
        // `MetadataSigner::sign_metadata` signs
        // contents.digest32::<MerlinTranscript>(b"block_metadata").
        let want = meta.contents().digest32::<MerlinTranscript>(b"block_metadata");
        assert_eq!(script.replay(), want);
        // And that digest is really the signed message: verifying the node's
        // signature over it with the raw key must succeed.
        use mc_crypto_keys::Verifier;
        assert!(meta.node_key().verify(&script.replay(), meta.signature()).is_ok());
    }
}

#[test]
fn changing_one_byte_of_the_script_changes_the_digest() {
    let s = Scenario::build();
    let block = s.ledger.block(2);
    let base = block_sig_script(block);
    let want = base.replay();

    for i in 0..base.ops.len() {
        if base.ops[i].data.is_empty() {
            continue;
        }
        let mut mutated = base.clone();
        mutated.ops[i].data[0] ^= 0x01;
        assert_ne!(
            mutated.replay(),
            want,
            "flipping a bit in op {i} left the digest unchanged"
        );
    }
}

#[test]
fn dropping_or_reordering_ops_changes_the_digest() {
    let s = Scenario::build();
    let base = block_id_script(s.ledger.block(2));
    let want = base.replay();

    let mut dropped = base.clone();
    dropped.ops.remove(0);
    assert_ne!(dropped.replay(), want, "dropping the first op was invisible");

    let mut swapped = base.clone();
    swapped.ops.swap(0, 2);
    assert_ne!(swapped.replay(), want, "reordering ops was invisible");
}

#[test]
fn the_protocol_and_challenge_labels_are_load_bearing() {
    let s = Scenario::build();
    let base = block_id_script(s.ledger.block(2));
    let want = base.replay();

    let mut other_protocol = base.clone();
    other_protocol.protocol_label = b"digestible";
    assert_ne!(
        other_protocol.replay(),
        want,
        "the block-id transcript is domain-separated from the digestible one; \
         swapping the label must change the result"
    );

    let mut other_challenge = base.clone();
    other_challenge.challenge_label = b"not-digest32";
    assert_ne!(other_challenge.replay(), want);
}

#[test]
fn block_id_script_appends_the_header_fields_in_order() {
    // Documents the shape the Solidity side has to replay. The labels come from
    // `compute_block_id`; the interleaved type names come from `Digestible`'s
    // primitive framing.
    let s = Scenario::build();
    let script = block_id_script(s.ledger.block(2));
    let labels: Vec<String> = script
        .ops
        .iter()
        .take(8)
        .map(|o| String::from_utf8_lossy(o.label).into_owned())
        .collect();
    assert_eq!(
        labels,
        vec![
            "version", "uint", "parent_id", "bytes", "index", "uint", "cumulative_txo_count",
            "uint"
        ]
    );
    assert_eq!(script.protocol_label, b"mobilecoin-block-id");
}
