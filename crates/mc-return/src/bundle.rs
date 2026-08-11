//! The JSON the Solidity suite reads.
//!
//! Rule for what goes in: if the verifier has to *recompute* something, the
//! inputs to that computation are in the file, and the expected output is in
//! the file too, next to it. A fixture that carries only outputs teaches a
//! Solidity test to assert what the fixture already says, which proves nothing
//! about either side.
//!
//! Every `u64` is emitted as a DECIMAL STRING, not a JSON number. `masked_value`
//! is a full-range u64 and `JSON.parse` would silently round it through an IEEE
//! double; making all of them strings means no field in the file has a
//! different rule from its neighbour, and `BigInt(x)` reads them all.

use mc_blockchain_types::{Block, BlockMetadata};
use mc_transaction_core::{
    membership_proofs::{hash_leaf, NIL_HASH},
    tx::{TxOut, TxOutMembershipElement, TxOutMembershipProof},
    MaskedAmount,
};
use serde_json::{json, Map, Value};

use crate::{
    attestation::{
        block_id_script, block_metadata_script, block_sig_script, tx_out_digest_script,
        AttestationRoute, QuorumEvidence,
    },
    transcript::TranscriptScript,
    ReturnProof,
};

fn hx(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn u64s(v: u64) -> String {
    v.to_string()
}

fn element_json(e: &TxOutMembershipElement) -> Value {
    json!({
        "range": { "from": u64s(e.range.from), "to": u64s(e.range.to) },
        "hash": hx(e.hash.as_ref()),
    })
}

fn header_json(b: &Block) -> Value {
    json!({
        "id": hx(b.id.as_ref()),
        "version": b.version,
        "parent_id": hx(b.parent_id.as_ref()),
        "index": u64s(b.index),
        "cumulative_txo_count": u64s(b.cumulative_txo_count),
        "root_element": element_json(&b.root_element),
        "contents_hash": hx(b.contents_hash.as_ref()),
    })
}

fn masked_amount_json(m: &MaskedAmount) -> Value {
    let version = match m {
        MaskedAmount::V1(_) => 1,
        MaskedAmount::V2(_) => 2,
    };
    json!({
        "version": version,
        "commitment": hx(m.commitment().point.as_bytes()),
        "masked_value": u64s(*m.get_masked_value()),
        "masked_token_id": hx(m.masked_token_id()),
    })
}

fn tx_out_json(tx_out: &TxOut) -> Value {
    let mut v = Map::new();
    if let Ok(m) = tx_out.get_masked_amount() {
        v.insert("masked_amount".into(), masked_amount_json(m));
    } else {
        v.insert("masked_amount".into(), Value::Null);
    }
    v.insert("target_key".into(), Value::String(hx(tx_out.target_key.as_bytes())));
    v.insert("public_key".into(), Value::String(hx(tx_out.public_key.as_bytes())));
    v.insert("e_fog_hint".into(), Value::String(hx(tx_out.e_fog_hint.as_ref())));
    v.insert(
        "e_memo".into(),
        match &tx_out.e_memo {
            Some(m) => Value::String(hx(m.as_ref())),
            None => Value::Null,
        },
    );
    Value::Object(v)
}

fn proof_json(p: &TxOutMembershipProof) -> Value {
    json!({
        "index": u64s(p.index),
        "highest_index": u64s(p.highest_index),
        "elements": p.elements.iter().map(element_json).collect::<Vec<_>>(),
    })
}

/// A transcript script, plus the digest replaying it produces.
fn script_json(s: &TranscriptScript) -> Value {
    json!({
        "protocol_label": String::from_utf8_lossy(s.protocol_label),
        "ops": s.ops.iter().map(|o| json!({
            "label": String::from_utf8_lossy(o.label),
            "data": hx(&o.data),
        })).collect::<Vec<_>>(),
        "challenge_label": String::from_utf8_lossy(s.challenge_label),
        "digest": hx(&s.replay()),
    })
}

fn metadata_json(m: &BlockMetadata) -> Value {
    let script = block_metadata_script(m);
    json!({
        "block_id": hx(m.contents().block_id().as_ref()),
        "responder_id": m.contents().responder_id().to_string(),
        "node_key": hx(m.node_key().as_ref()),
        "signature": hx(m.signature().as_ref()),
        // The message this signature is over. Distinct per node -- that is the
        // whole point of carrying it.
        "signed_message": script_json(&script),
    })
}

fn quorum_json(q: &QuorumEvidence) -> Value {
    match q {
        QuorumEvidence::BlockSignature(s) => json!({
            "route": AttestationRoute::BlockSignature.as_str(),
            "threshold": s.threshold,
            "signers": s.signers.iter().map(|k| hx(k.as_ref())).collect::<Vec<_>>(),
            "signatures": s.signatures.iter().map(|sig| json!({
                "signer": hx(sig.signer().as_ref()),
                "signature": hx(sig.signature().as_ref()),
                "signed_at": u64s(sig.signed_at()),
            })).collect::<Vec<_>>(),
        }),
        QuorumEvidence::BlockMetadata(m) => json!({
            "route": AttestationRoute::BlockMetadata.as_str(),
            "metadata": m.metadata.iter().map(metadata_json).collect::<Vec<_>>(),
        }),
    }
}

/// Ops and appended bytes an Ethereum verifier must push through STROBE to
/// authenticate this block under each route.
///
/// This is the amortization claim made checkable. Under `block_signature` the
/// cost is one transcript regardless of k; under `block_metadata` it is the sum
/// over the k nodes, because no two nodes sign the same message.
fn transcript_cost(scripts: &[TranscriptScript]) -> Value {
    let ops: usize = scripts.iter().map(|s| s.ops.len()).sum();
    let bytes: usize = scripts
        .iter()
        .flat_map(|s| s.ops.iter())
        .map(|o| o.data.len())
        .sum();
    json!({
        "transcripts": scripts.len(),
        "append_ops": ops,
        "appended_bytes": bytes,
    })
}

impl ReturnProof {
    /// Serialize to the fixture format.
    pub fn to_json(&self) -> Value {
        let anchor = self.chain.anchor();
        let id_script = block_id_script(anchor);
        let sig_script = block_sig_script(anchor);

        let quorum_cost = match &self.quorum {
            QuorumEvidence::BlockSignature(_) => transcript_cost(&[sig_script.clone()]),
            QuorumEvidence::BlockMetadata(m) => transcript_cost(
                &m.metadata
                    .iter()
                    .map(block_metadata_script)
                    .collect::<Vec<_>>(),
            ),
        };

        let tx_out_script = tx_out_digest_script(&self.tx_out);

        json!({
            "schema": "mc-return/1",
            "source": {
                "crate": "mc-return",
                "mobilecoin_rev": "05cb699f8f4cc1bc21186392545820c5b38408db",
                "note": "every u64 is a decimal string; every byte string is 0x-prefixed hex",
            },

            "chain": self.chain.headers().iter().map(header_json).collect::<Vec<_>>(),
            "origin_block_index": u64s(self.origin_block_index),
            "anchor_block_index": u64s(anchor.index),

            // The two block digests, with the merlin script that produces each.
            // `block_id` is what BlockMetadata signatures commit to;
            // `block_sig` is what BlockSignature signatures commit to.
            "digests": {
                "block_id": script_json(&id_script),
                "block_sig": script_json(&sig_script),
            },

            "tx_out": tx_out_json(&self.tx_out),
            "tx_out_index": u64s(self.tx_out_index),
            // TxOut::hash() is itself a merlin digest, and it is the preimage
            // of the Merkle leaf -- so the leaf cannot be recomputed without
            // this script.
            "tx_out_digest": script_json(&tx_out_script),

            "membership_proof": proof_json(&self.membership_proof),
            "merkle": {
                "hash": "blake2b-256",
                "leaf_domain_tag": "mc_tx_out_merkle_leaf",
                "node_domain_tag": "mc_tx_out_merkle_node",
                "nil_domain_tag": "mc_tx_out_merkle_nil",
                "nil_hash": hx(&*NIL_HASH),
                "leaf_hash": hx(&hash_leaf(&self.tx_out)),
                "known_root": element_json(&anchor.root_element),
            },

            "quorum": quorum_json(&self.quorum),
            "quorum_cost": quorum_cost,

            // The disclosure. NOT verifiable on Ethereum as it stands -- see
            // the crate README. Present so the Solidity side can be written and
            // tested against real numbers while that gap is closed.
            "disclosure": {
                "shared_secret": hx(&self.disclosure.shared_secret.to_bytes()),
                "blinding": hx(self.disclosure.blinding.as_bytes()),
                "recovered_subaddress_spend_key":
                    hx(&self.disclosure.recovered_subaddress_spend_key.to_bytes()),
                "memo_type": hx(&self.disclosure.memo_type),
                "memo_data": hx(&self.disclosure.memo_data),
                "on_chain_verifiable": false,
            },

            // What Escrow.release must end up with.
            "expected": {
                "outputPublicKey": hx(self.tx_out.public_key.as_bytes()),
                "beneficiary": hx(&self.disclosure.beneficiary),
                "amount": u64s(self.disclosure.amount.value),
                "tokenId": u64s(*self.disclosure.amount.token_id),
                "blockIndex": u64s(self.origin_block_index),
            },
        })
    }
}

/// Pretty-print with a trailing newline, so the file is diff-friendly.
pub fn to_pretty_string(value: &Value) -> Result<String, serde_json::Error> {
    Ok(format!("{}\n", serde_json::to_string_pretty(value)?))
}
