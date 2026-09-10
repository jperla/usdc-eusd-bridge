//! Shared scaffolding: a real MobileCoin ledger, built with upstream types.
//!
//! Nothing here fakes a hash or a signature. Blocks come from `Block::new*`,
//! signatures from `BlockSignature::from_block_and_keypair` and
//! `BlockMetadata::from_contents_and_keypair`, outputs from `TxOut::new_with_memo`.
//! The point of the tests is to check this crate against MobileCoin, so the
//! MobileCoin side has to be genuine.

#![allow(dead_code)] // each integration test binary uses a different subset

use mc_blockchain_types::{
    AttestationEvidence, Block, BlockContents, BlockMetadata, BlockMetadataContents,
    BlockSignature, QuorumSet,
};
use mc_common::{NodeID, ResponderId};
use mc_consensus_scp_types::QuorumSetMember;
use mc_crypto_keys::{Ed25519Pair, Ed25519Public, RistrettoPrivate};
use mc_light_client_verifier::TrustedValidatorSet;
use mc_return::{
    create_return_tx_out, BlockMetadataQuorum, BlockSignatureQuorum, HeaderChain, QuorumEvidence,
    TxOutTree,
};
use mc_transaction_core::{
    encrypted_fog_hint::EncryptedFogHint,
    membership_proofs::{hash_leaf, hash_nodes, NIL_HASH},
    tx::TxOut,
    AccountKey, Amount, BlockVersion, MemoPayload, PublicAddress, TokenId,
};
use mc_util_from_random::FromRandom;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

/// The eUSD token id the bridge accepts. Arbitrary here; it only has to be
/// consistent between the fixture and the escrow's `eusdTokenId`.
pub const EUSD_TOKEN_ID: u64 = 1;

/// Chain 1, escrow [0x71;20], namespace bytes32("mc-bridge-return-v1").
/// The Solidity suite independently checks this against redemptionDomain.
pub const REDEMPTION_DOMAIN: [u8; 32] = [
    0x9d, 0x79, 0x1b, 0xf9, 0xdc, 0x21, 0x48, 0x9f, 0xfb, 0x25, 0x9f, 0xcf, 0xe5, 0x02, 0xa0, 0x88,
    0xcd, 0x0e, 0xae, 0xe2, 0xb1, 0xa8, 0x46, 0x57, 0x0c, 0xc4, 0x3d, 0xd4, 0xac, 0xeb, 0x67, 0xc6,
];

pub fn rng(seed: u8) -> ChaChaRng {
    ChaChaRng::from_seed([seed; 32])
}

/// Build a return output: `value` eUSD to `recipient`, carrying the bridge
/// return memo naming `beneficiary` on Ethereum.
pub fn return_tx_out(
    rng: &mut ChaChaRng,
    recipient: &PublicAddress,
    value: u64,
    beneficiary: [u8; 20],
) -> TxOut {
    return_tx_out_for_domain(rng, recipient, value, beneficiary, REDEMPTION_DOMAIN)
}

pub fn return_tx_out_for_domain(
    rng: &mut ChaChaRng,
    recipient: &PublicAddress,
    value: u64,
    beneficiary: [u8; 20],
    domain: [u8; 32],
) -> TxOut {
    let tx_private_key = RistrettoPrivate::from_random(rng);
    create_return_tx_out(
        Amount::new(value, TokenId::from(EUSD_TOKEN_ID)),
        recipient,
        &tx_private_key,
        EncryptedFogHint::fake_onetime_hint(rng),
        beneficiary,
        domain,
    )
    .expect("TxOut::new_with_memo")
}

/// An unrelated output, so blocks are not all one TxOut wide and the Merkle
/// paths in the fixture have real siblings.
pub fn filler_tx_out(rng: &mut ChaChaRng, value: u64) -> TxOut {
    let other = AccountKey::random(rng);
    let mut memo_data = [0u8; 64];
    memo_data[0] = 0xff;
    let tx_private_key = RistrettoPrivate::from_random(rng);
    TxOut::new_with_memo(
        BlockVersion::MAX,
        Amount::new(value, TokenId::from(EUSD_TOKEN_ID)),
        &other.default_subaddress(),
        &tx_private_key,
        EncryptedFogHint::fake_onetime_hint(rng),
        |_ctx| Ok(MemoPayload::new([0x00, 0x00], memo_data)),
    )
    .expect("TxOut::new_with_memo")
}

/// A ledger: blocks, the outputs they created in global index order, and the
/// TxOut Merkle tree over all of them.
pub struct Ledger {
    pub blocks: Vec<Block>,
    pub leaves: Vec<TxOut>,
    /// The tree as of the tip. NOT the tree any block's `root_element` names --
    /// see `tree_anchored_at`.
    pub tree: TxOutTree,
}

impl Ledger {
    /// Start from an origin block. Upstream's origin block has version 0 and a
    /// default root element, which is exactly what a real chain looks like.
    pub fn origin(outputs: Vec<TxOut>) -> Self {
        let block = Block::new_origin_block(&outputs);
        let mut tree = TxOutTree::new();
        for o in &outputs {
            tree.push(o.clone()).unwrap();
        }
        Self {
            blocks: vec![block],
            leaves: outputs,
            tree,
        }
    }

    /// The first `n` outputs as a tree.
    pub fn tree_of_first(&self, n: u64) -> TxOutTree {
        let mut tree = TxOutTree::new();
        for leaf in &self.leaves[..n as usize] {
            tree.push(leaf.clone()).unwrap();
        }
        tree
    }

    /// The ledger state block `i`'s `root_element` commits to: everything that
    /// existed before block `i` was formed.
    pub fn tree_anchored_at(&self, i: usize) -> TxOutTree {
        self.tree_of_first(self.blocks[i - 1].cumulative_txo_count)
    }

    /// Append a block. The root element is read from the tree BEFORE the new
    /// outputs land -- that is what
    /// `consensus/service/src/byzantine_ledger/worker.rs` does, and getting it
    /// wrong is precisely the mistake `chain.rs` exists to prevent.
    pub fn append(&mut self, outputs: Vec<TxOut>) -> &Block {
        let root_element = self.tree.root_element().expect("non-empty ledger");
        let contents = BlockContents {
            outputs: outputs.clone(),
            ..Default::default()
        };
        let parent = self.blocks.last().unwrap();
        let block = Block::new_with_parent(BlockVersion::MAX, parent, &root_element, &contents);
        for o in outputs {
            self.tree.push(o.clone()).unwrap();
            self.leaves.push(o);
        }
        self.blocks.push(block);
        self.blocks.last().unwrap()
    }

    pub fn block(&self, index: usize) -> &Block {
        &self.blocks[index]
    }

    /// Headers `[from ..= to]` as a verified chain.
    pub fn chain(&self, from: usize, to: usize) -> mc_return::Result<HeaderChain> {
        HeaderChain::new(self.blocks[from..=to].to_vec())
    }
}

/// A validator: an Ed25519 message-signing key plus the responder id it is
/// known by.
pub struct Validator {
    pub keypair: Ed25519Pair,
    pub responder_id: ResponderId,
}

impl Validator {
    pub fn set(rng: &mut ChaChaRng, n: usize) -> Vec<Validator> {
        (0..n)
            .map(|i| Validator {
                keypair: Ed25519Pair::from_random(rng),
                responder_id: ResponderId(format!("node{i}.test.mobilecoin.com:443")),
            })
            .collect()
    }

    pub fn public(&self) -> Ed25519Public {
        self.keypair.public_key()
    }

    pub fn node_id(&self) -> NodeID {
        NodeID {
            responder_id: self.responder_id.clone(),
            public_key: self.keypair.public_key(),
        }
    }
}

/// `BlockSignature` route: `signing` of `validators` each sign `block`.
pub fn block_signature_quorum(
    validators: &[Validator],
    signing: &[usize],
    threshold: u32,
    block: &Block,
) -> BlockSignatureQuorum {
    let signatures = signing
        .iter()
        .map(|&i| {
            let mut sig = BlockSignature::from_block_and_keypair(block, &validators[i].keypair)
                .expect("sign block");
            // Untrusted code stamps this after the enclave signs; it is not
            // covered by the signature, and the fixture carries it as-is.
            sig.set_signed_at(1_700_000_000 + i as u64);
            sig
        })
        .collect();
    BlockSignatureQuorum {
        signers: validators.iter().map(|v| v.public()).collect(),
        threshold,
        signatures,
    }
}

/// The SCP quorum set the light client would be configured with.
pub fn quorum_set(validators: &[Validator], threshold: u32) -> QuorumSet {
    QuorumSet::new(
        threshold,
        validators
            .iter()
            .map(|v| QuorumSetMember::Node(v.node_id()))
            .collect(),
    )
}

/// `BlockMetadata` route: `signing` of `validators` each sign their OWN
/// metadata contents for `block`.
pub fn block_metadata_quorum(
    validators: &[Validator],
    signing: &[usize],
    threshold: u32,
    block: &Block,
) -> BlockMetadataQuorum {
    let qs = quorum_set(validators, threshold);
    let metadata = signing
        .iter()
        .map(|&i| {
            let contents = BlockMetadataContents::new(
                block.id.clone(),
                qs.clone(),
                AttestationEvidence::VerificationReport(Default::default()),
                validators[i].responder_id.clone(),
            );
            BlockMetadata::from_contents_and_keypair(contents, &validators[i].keypair)
                .expect("sign metadata")
        })
        .collect();
    BlockMetadataQuorum {
        validator_set: TrustedValidatorSet { quorum_set: qs },
        metadata,
    }
}

pub fn metadata_evidence(
    validators: &[Validator],
    signing: &[usize],
    threshold: u32,
    block: &Block,
) -> QuorumEvidence {
    QuorumEvidence::BlockMetadata(block_metadata_quorum(validators, signing, threshold, block))
}

pub fn signature_evidence(
    validators: &[Validator],
    signing: &[usize],
    threshold: u32,
    block: &Block,
) -> QuorumEvidence {
    QuorumEvidence::BlockSignature(block_signature_quorum(
        validators, signing, threshold, block,
    ))
}

/// The standard scenario the tests share.
///
/// Block 0 origin (2 outputs), block 1 carries the return output plus a filler,
/// block 2 is the anchor. Block 2's `root_element` is the tree as of the end of
/// block 1, so it covers the return output; block 1's does not.
pub struct Scenario {
    pub ledger: Ledger,
    pub bridge: AccountKey,
    pub validators: Vec<Validator>,
    pub return_index: u64,
    pub value: u64,
    pub beneficiary: [u8; 20],
}

impl Scenario {
    pub fn build() -> Self {
        Self::with_domain(REDEMPTION_DOMAIN)
    }

    pub fn with_domain(domain: [u8; 32]) -> Self {
        let mut r = rng(7);
        let bridge = AccountKey::random(&mut r);
        let beneficiary: [u8; 20] = hex_20("742d35cc6634c0532925a3b844bc454e4438f44e");
        let value = 1_500_000u64;

        // Three outputs in the origin block, two in block 1. That leaves the
        // anchor committing to FIVE outputs, so the padded tree is eight wide
        // and the fixture exercises the nil-padded subtrees. A power-of-two
        // ledger would let a verifier that mishandles padding pass.
        let mut ledger = Ledger::origin(vec![
            filler_tx_out(&mut r, 10),
            filler_tx_out(&mut r, 11),
            filler_tx_out(&mut r, 12),
        ]);
        // Return output is index 3 in the global TxOut ordering.
        ledger.append(vec![
            return_tx_out_for_domain(
                &mut r,
                &bridge.default_subaddress(),
                value,
                beneficiary,
                domain,
            ),
            filler_tx_out(&mut r, 13),
        ]);
        ledger.append(vec![filler_tx_out(&mut r, 14)]);

        let validators = Validator::set(&mut r, 5);
        Self {
            ledger,
            bridge,
            validators,
            return_index: 3,
            value,
            beneficiary,
        }
    }

    pub fn view_key(&self) -> &RistrettoPrivate {
        self.bridge.view_private_key()
    }

    pub fn return_spend_public(&self) -> mc_crypto_keys::RistrettoPublic {
        *self.bridge.default_subaddress().spend_public_key()
    }

    /// The tree the anchor block (index 2) was validated against.
    pub fn anchor_tree(&self) -> TxOutTree {
        self.ledger.tree_anchored_at(2)
    }
}

/// The hash of the node spanning `[from, to]` of a tree holding `leaves`,
/// defined top-down over the whole padded tree.
///
/// The one rule that is not "just hash the children" is upstream's: a right
/// subtree containing no leaves at all is the NIL hash, not `H(nil, nil)`.
/// See `tx_out_store::update_merkle_hashes`.
pub fn expected_hash(leaves: &[TxOut], from: u64, to: u64) -> [u8; 32] {
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

pub fn hex_20(s: &str) -> [u8; 20] {
    let bytes = hex::decode(s).expect("hex");
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    out
}
