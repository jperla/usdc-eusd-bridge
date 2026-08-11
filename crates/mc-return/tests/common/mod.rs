//! Shared scaffolding: a real MobileCoin ledger, built with upstream types.
//!
//! Nothing here fakes a hash or a signature. Blocks come from `Block::new*`,
//! signatures from `BlockSignature::from_block_and_keypair` and
//! `BlockMetadata::from_contents_and_keypair`, outputs from `TxOut::new_with_memo`.
//! The point of the tests is to check this crate against MobileCoin, so the
//! MobileCoin side has to be genuine.

#![allow(dead_code)] // each integration test binary uses a different subset

use mc_blockchain_types::{
    AttestationEvidence, Block, BlockContents, BlockMetadata, BlockMetadataContents, BlockSignature,
    QuorumSet,
};
use mc_common::{NodeID, ResponderId};
use mc_consensus_scp_types::QuorumSetMember;
use mc_crypto_keys::{Ed25519Pair, Ed25519Public, RistrettoPrivate};
use mc_light_client_verifier::TrustedValidatorSet;
use mc_return::{
    disclosure::BRIDGE_RETURN_MEMO_TYPE, BlockMetadataQuorum, BlockSignatureQuorum, HeaderChain,
    QuorumEvidence, TxOutTree,
};
use mc_transaction_core::{
    encrypted_fog_hint::EncryptedFogHint, tx::TxOut, AccountKey, Amount, BlockVersion, MemoPayload,
    PublicAddress, TokenId,
};
use mc_util_from_random::FromRandom;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

/// The eUSD token id the bridge accepts. Arbitrary here; it only has to be
/// consistent between the fixture and the escrow's `eusdTokenId`.
pub const EUSD_TOKEN_ID: u64 = 1;

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
    let mut memo_data = [0u8; 64];
    memo_data[..20].copy_from_slice(&beneficiary);
    let tx_private_key = RistrettoPrivate::from_random(rng);
    TxOut::new_with_memo(
        BlockVersion::MAX,
        Amount::new(value, TokenId::from(EUSD_TOKEN_ID)),
        recipient,
        &tx_private_key,
        EncryptedFogHint::fake_onetime_hint(rng),
        |_ctx| Ok(MemoPayload::new(BRIDGE_RETURN_MEMO_TYPE, memo_data)),
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

/// A ledger: blocks plus the TxOut Merkle tree they were validated against.
pub struct Ledger {
    pub blocks: Vec<Block>,
    pub tree: TxOutTree,
}

impl Ledger {
    /// Start from an origin block. Upstream's origin block has version 0 and a
    /// default root element, which is exactly what a real chain looks like.
    pub fn origin(outputs: Vec<TxOut>) -> Self {
        let block = Block::new_origin_block(&outputs);
        let mut tree = TxOutTree::new();
        for o in outputs {
            tree.push(o).unwrap();
        }
        Self {
            blocks: vec![block],
            tree,
        }
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
            self.tree.push(o).unwrap();
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
    QuorumEvidence::BlockSignature(block_signature_quorum(validators, signing, threshold, block))
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
        let mut r = rng(7);
        let bridge = AccountKey::random(&mut r);
        let beneficiary: [u8; 20] = hex_20("742d35cc6634c0532925a3b844bc454e4438f44e");
        let value = 1_500_000u64;

        let mut ledger = Ledger::origin(vec![
            filler_tx_out(&mut r, 10),
            filler_tx_out(&mut r, 11),
        ]);
        // Return output is index 2 in the global TxOut ordering.
        ledger.append(vec![
            return_tx_out(&mut r, &bridge.default_subaddress(), value, beneficiary),
            filler_tx_out(&mut r, 12),
        ]);
        ledger.append(vec![filler_tx_out(&mut r, 13)]);

        let validators = Validator::set(&mut r, 5);
        Self {
            ledger,
            bridge,
            validators,
            return_index: 2,
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
}

pub fn hex_20(s: &str) -> [u8; 20] {
    let bytes = hex::decode(s).expect("hex");
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    out
}
