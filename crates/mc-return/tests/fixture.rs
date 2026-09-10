//! Emits `fixtures/return.json` (and its BlockMetadata-route sibling) and then
//! reads the emitted file back, checking every number in it against MobileCoin
//! computed independently.
//!
//! Writing and checking in one test binary is deliberate: the file the Solidity
//! suite loads is the file that was just adjudicated, not one that happened to
//! be committed at some point.

mod common;

use common::*;
use mc_blockchain_types::compute_block_id;
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_return::{attestation::AttestationRoute, chain::HeaderChain, QuorumEvidence, ReturnProof};
use mc_transaction_core::membership_proofs::{hash_leaf, is_membership_proof_valid};
use serde_json::Value;
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn make_proof(route: AttestationRoute) -> (Scenario, ReturnProof) {
    let s = Scenario::build();
    let chain: HeaderChain = s.ledger.chain(0, 2).unwrap();
    let quorum: QuorumEvidence = match route {
        AttestationRoute::BlockSignature => {
            signature_evidence(&s.validators, &[0, 1, 2], 3, chain.anchor())
        }
        AttestationRoute::BlockMetadata => {
            metadata_evidence(&s.validators, &[0, 1, 2], 3, chain.anchor())
        }
    };
    let proof = ReturnProof::build(
        chain,
        &s.anchor_tree(),
        s.return_index,
        quorum,
        s.view_key(),
        &s.return_spend_public(),
        &REDEMPTION_DOMAIN,
    )
    .expect("scenario should produce a valid return proof");
    (s, proof)
}

fn hex_field(v: &Value, path: &[&str]) -> Vec<u8> {
    let mut cur = v;
    for p in path {
        cur = &cur[*p];
    }
    let s = cur
        .as_str()
        .unwrap_or_else(|| panic!("{path:?} is not a string"));
    hex::decode(s.trim_start_matches("0x")).expect("hex")
}

fn str_field(v: &Value, path: &[&str]) -> String {
    let mut cur = v;
    for p in path {
        cur = &cur[*p];
    }
    cur.as_str()
        .unwrap_or_else(|| panic!("{path:?} is not a string"))
        .to_string()
}

#[test]
fn writes_the_fixture_and_every_field_in_it_checks_out() {
    let (s, proof) = make_proof(AttestationRoute::BlockSignature);
    let path = fixtures_dir().join("return.json");
    proof.write_fixture(&path).expect("write fixture");

    let raw = std::fs::read_to_string(&path).expect("read back");
    let v: Value = serde_json::from_str(&raw).expect("valid json");

    let anchor = s.ledger.block(2);
    let tx_out = s.ledger.tree.get(s.return_index).unwrap();

    // --- the digests, against MobileCoin computed here and now ---
    assert_eq!(
        hex_field(&v, &["digests", "block_sig", "digest"]),
        anchor.digest32::<MerlinTranscript>(b"block-sig").to_vec(),
        "the block-sig digest in the file is not the one the block implies"
    );
    let recomputed_id = compute_block_id(
        anchor.version,
        &anchor.parent_id,
        anchor.index,
        anchor.cumulative_txo_count,
        &anchor.root_element,
        &anchor.contents_hash,
    );
    assert_eq!(
        hex_field(&v, &["digests", "block_id", "digest"]),
        recomputed_id.0.to_vec()
    );
    assert_eq!(
        hex_field(&v, &["tx_out_digest", "digest"]),
        tx_out.hash().to_vec()
    );

    // --- the merkle material ---
    assert_eq!(
        hex_field(&v, &["merkle", "leaf_hash"]),
        hash_leaf(tx_out).to_vec()
    );
    assert_eq!(
        hex_field(&v, &["merkle", "known_root", "hash"]),
        anchor.root_element.hash.as_ref().to_vec(),
        "the root in the file is not the anchor block's root_element"
    );

    // --- the proof itself, re-adjudicated by upstream from the FILE ---
    let elements = v["membership_proof"]["elements"].as_array().unwrap();
    let mut rebuilt = Vec::new();
    for e in elements {
        let from: u64 = e["range"]["from"].as_str().unwrap().parse().unwrap();
        let to: u64 = e["range"]["to"].as_str().unwrap().parse().unwrap();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(
            &hex::decode(e["hash"].as_str().unwrap().trim_start_matches("0x")).unwrap(),
        );
        rebuilt.push(mc_transaction_core::tx::TxOutMembershipElement {
            range: mc_transaction_core::membership_proofs::Range::new(from, to).unwrap(),
            hash: hash.into(),
        });
    }
    let rebuilt_proof = mc_transaction_core::tx::TxOutMembershipProof::new(
        v["membership_proof"]["index"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
        v["membership_proof"]["highest_index"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
        rebuilt,
    );
    assert_eq!(
        is_membership_proof_valid(tx_out, &rebuilt_proof, anchor.root_element.hash.as_ref()),
        Ok(true),
        "the membership proof as SERIALIZED does not validate"
    );

    // --- the fields Escrow.release will act on ---
    assert_eq!(
        hex_field(&v, &["expected", "outputPublicKey"]),
        tx_out.public_key.as_bytes().to_vec()
    );
    assert_eq!(
        hex_field(&v, &["expected", "beneficiary"]),
        s.beneficiary.to_vec()
    );
    assert_eq!(str_field(&v, &["expected", "amount"]), s.value.to_string());
    assert_eq!(
        str_field(&v, &["expected", "tokenId"]),
        EUSD_TOKEN_ID.to_string()
    );
    // The block that CREATED the output, not the block that was signed.
    assert_eq!(str_field(&v, &["expected", "blockIndex"]), "1");
    assert_eq!(str_field(&v, &["anchor_block_index"]), "2");

    // --- route and signatures ---
    assert_eq!(str_field(&v, &["quorum", "route"]), "block_signature");
    assert_eq!(v["quorum"]["signatures"].as_array().unwrap().len(), 3);
    assert_eq!(v["quorum"]["signers"].as_array().unwrap().len(), 5);
    assert_eq!(v["quorum"]["threshold"], 3);
    // One transcript for the whole quorum: the amortization, in the file.
    assert_eq!(v["quorum_cost"]["transcripts"], 1);

    // --- headers ---
    let chain = v["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 3);
    for (i, header) in chain.iter().enumerate() {
        let block = s.ledger.block(i);
        assert_eq!(
            hex::decode(header["id"].as_str().unwrap().trim_start_matches("0x")).unwrap(),
            block.id.as_ref().to_vec()
        );
        assert_eq!(
            header["cumulative_txo_count"].as_str().unwrap(),
            block.cumulative_txo_count.to_string()
        );
    }
}

#[test]
fn writes_the_block_metadata_route_fixture() {
    let (_s, proof) = make_proof(AttestationRoute::BlockMetadata);
    let path = fixtures_dir().join("return-block-metadata.json");
    proof.write_fixture(&path).expect("write fixture");

    let v: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).expect("valid json");
    assert_eq!(str_field(&v, &["quorum", "route"]), "block_metadata");
    let metadata = v["quorum"]["metadata"].as_array().unwrap();
    assert_eq!(metadata.len(), 3);

    // Three signers, three DIFFERENT signed messages. If these ever collapsed
    // to one value the route would have become the cheap one by accident, and
    // the Solidity cost model built on this file would be wrong.
    let digests: std::collections::BTreeSet<String> = metadata
        .iter()
        .map(|m| m["signed_message"]["digest"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(digests.len(), 3);
    assert_eq!(v["quorum_cost"]["transcripts"], 3);
}

#[test]
fn every_u64_in_the_fixture_survives_json_parse() {
    // The reason u64s are strings: `JSON.parse` would round anything above
    // 2^53. Assert the file contains no bare JSON number that a JS reader
    // could silently mangle.
    let (_s, proof) = make_proof(AttestationRoute::BlockSignature);
    let v = proof.to_json();

    fn walk(v: &Value, path: String, bad: &mut Vec<String>) {
        match v {
            Value::Number(n) => {
                if let Some(u) = n.as_u64() {
                    if u > (1u64 << 53) {
                        bad.push(path);
                    }
                }
            }
            Value::Array(a) => {
                for (i, e) in a.iter().enumerate() {
                    walk(e, format!("{path}[{i}]"), bad);
                }
            }
            Value::Object(o) => {
                for (k, e) in o {
                    walk(e, format!("{path}.{k}"), bad);
                }
            }
            _ => {}
        }
    }
    let mut bad = Vec::new();
    walk(&v, "$".into(), &mut bad);
    assert!(bad.is_empty(), "unsafe JSON numbers at {bad:?}");
}
