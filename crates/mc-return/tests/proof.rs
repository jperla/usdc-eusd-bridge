//! End-to-end: assembling a `ReturnProof`, and the ways it must refuse.
//!
//! The negatives here are not decoration. `ReturnProof::build` is the only
//! constructor, so anything it lets through is something the Solidity verifier
//! will be handed as if it were sound.

mod common;

use common::*;
use mc_return::{chain::HeaderChain, Error, ReturnProof, TxOutTree};

fn build_with(
    s: &Scenario,
    chain: HeaderChain,
    tree: &TxOutTree,
    index: u64,
) -> mc_return::Result<ReturnProof> {
    let quorum = signature_evidence(&s.validators, &[0, 1, 2], 3, chain.anchor());
    ReturnProof::build(
        chain,
        tree,
        index,
        quorum,
        s.view_key(),
        &s.return_spend_public(),
    )
}

#[test]
fn a_well_formed_return_is_accepted_on_the_block_signature_route() {
    let s = Scenario::build();
    let chain = s.ledger.chain(0, 2).unwrap();
    let proof = build_with(&s, chain, &s.ledger.tree, s.return_index).unwrap();

    assert_eq!(proof.tx_out_index, s.return_index);
    assert_eq!(proof.disclosure.amount.value, s.value);
    assert_eq!(*proof.disclosure.amount.token_id, EUSD_TOKEN_ID);
    assert_eq!(proof.disclosure.beneficiary, s.beneficiary);
    // Derived from the chained cumulative counts, not supplied by the caller.
    assert_eq!(proof.origin_block_index, 1);
    assert_eq!(proof.chain.anchor().index, 2);
}

#[test]
fn a_well_formed_return_is_accepted_on_the_block_metadata_route() {
    let s = Scenario::build();
    let chain = s.ledger.chain(0, 2).unwrap();
    let quorum = metadata_evidence(&s.validators, &[0, 1, 2], 3, chain.anchor());
    let proof = ReturnProof::build(
        chain,
        &s.ledger.tree,
        s.return_index,
        quorum,
        s.view_key(),
        &s.return_spend_public(),
    )
    .expect("metadata route should accept the same return");
    assert_eq!(proof.disclosure.amount.value, s.value);
}

#[test]
fn the_block_that_created_the_output_cannot_anchor_it() {
    // The structural fact the whole `chain` module exists for: block 1's
    // root_element is the ledger BEFORE block 1, so it does not commit to the
    // output block 1 created. A relayer that anchors to the origin block must
    // be refused, not quietly produce a proof against the wrong root.
    let s = Scenario::build();
    let chain = s.ledger.chain(0, 1).unwrap();
    let err = build_with(&s, chain, &s.ledger.tree, s.return_index).unwrap_err();
    assert!(
        matches!(
            err,
            Error::AnchorDoesNotCover {
                anchor_index: 1,
                covered: 2,
                index: 2
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn a_tree_that_has_moved_past_the_anchor_is_refused() {
    // Same chain, but the relayer hands over a tree that already contains
    // block 2's outputs. Its root is not the anchor's root, so the membership
    // proof cannot validate -- there is no way to anchor to block 2 while
    // proving against a later ledger.
    let s = Scenario::build();
    let mut r = rng(21);
    let mut ahead = TxOutTree::new();
    for i in 0..s.ledger.tree.len() {
        ahead.push(s.ledger.tree.get(i).unwrap().clone()).unwrap();
    }
    ahead.push(filler_tx_out(&mut r, 99)).unwrap();

    let chain = s.ledger.chain(0, 2).unwrap();
    let err = build_with(&s, chain, &ahead, s.return_index).unwrap_err();
    assert!(
        matches!(err, Error::MembershipProofInvalid { index: 2 }),
        "got {err:?}"
    );
}

#[test]
fn a_header_whose_fields_were_edited_is_refused() {
    let s = Scenario::build();
    let mut headers = s.ledger.blocks[0..=2].to_vec();
    // Move the count that decides which block created the output. The id no
    // longer hashes to the header, which is exactly what upstream's
    // is_block_id_valid detects.
    headers[1].cumulative_txo_count += 1;
    let err = HeaderChain::new(headers).unwrap_err();
    assert!(
        matches!(err, Error::BlockIdNotSelfConsistent { index: 1 }),
        "got {err:?}"
    );
}

#[test]
fn a_chain_with_a_missing_block_is_refused() {
    let s = Scenario::build();
    let headers = vec![s.ledger.block(0).clone(), s.ledger.block(2).clone()];
    let err = HeaderChain::new(headers).unwrap_err();
    assert!(matches!(err, Error::ChainBroken { index: 2, .. }), "got {err:?}");
}

#[test]
fn a_single_header_is_not_a_chain() {
    let s = Scenario::build();
    assert!(matches!(
        HeaderChain::new(vec![s.ledger.block(2).clone()]).unwrap_err(),
        Error::ChainTooShort(1)
    ));
}

#[test]
fn an_output_that_is_not_ours_is_refused() {
    // Index 3 is the filler output in block 1: same block, same Merkle tree,
    // valid membership proof, paid to someone else.
    let s = Scenario::build();
    let chain = s.ledger.chain(0, 2).unwrap();
    let err = build_with(&s, chain, &s.ledger.tree, 3).unwrap_err();
    assert!(
        matches!(err, Error::AmountNotRecoverable(_)),
        "an output paid to a third party was accepted: {err:?}"
    );
}

#[test]
fn an_output_to_us_without_the_bridge_memo_is_refused() {
    // Paid to the bridge, openable by the bridge's view key, but not a return:
    // no memo naming a beneficiary. Accepting it would mean paying USDC to
    // whatever the first 20 bytes of an unrelated memo happened to be.
    let mut r = rng(5);
    let bridge = mc_transaction_core::AccountKey::random(&mut r);
    let stray = {
        let mut memo = [0u8; 64];
        memo[..20].copy_from_slice(&hex_20("00000000000000000000000000000000deadbeef"));
        mc_transaction_core::tx::TxOut::new_with_memo(
            mc_transaction_core::BlockVersion::MAX,
            mc_transaction_core::Amount::new(
                7,
                mc_transaction_core::TokenId::from(EUSD_TOKEN_ID),
            ),
            &bridge.default_subaddress(),
            &<mc_crypto_keys::RistrettoPrivate as mc_util_from_random::FromRandom>::from_random(
                &mut r,
            ),
            mc_transaction_core::encrypted_fog_hint::EncryptedFogHint::fake_onetime_hint(&mut r),
            |_| Ok(mc_transaction_core::MemoPayload::new([0x00, 0x00], memo)),
        )
        .unwrap()
    };

    let mut ledger = Ledger::origin(vec![filler_tx_out(&mut r, 1)]);
    ledger.append(vec![stray]);
    ledger.append(vec![filler_tx_out(&mut r, 2)]);
    let validators = Validator::set(&mut r, 5);

    let chain = ledger.chain(0, 2).unwrap();
    let quorum = signature_evidence(&validators, &[0, 1, 2], 3, chain.anchor());
    let err = ReturnProof::build(
        chain,
        &ledger.tree,
        1,
        quorum,
        bridge.view_private_key(),
        bridge.default_subaddress().spend_public_key(),
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::MemoWrongType { .. }),
        "got {err:?}"
    );
}

#[test]
fn a_return_paid_to_a_different_subaddress_is_refused() {
    // Same view key, different spend key: `view_key_match` would be happy, so
    // this is the case `require_paid_to` exists for.
    let s = Scenario::build();
    let chain = s.ledger.chain(0, 2).unwrap();
    let quorum = signature_evidence(&s.validators, &[0, 1, 2], 3, chain.anchor());
    let wrong = s.bridge.subaddress(7);
    let err = ReturnProof::build(
        chain,
        &s.ledger.tree,
        s.return_index,
        quorum,
        s.view_key(),
        wrong.spend_public_key(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::AmountNotRecoverable(_)), "got {err:?}");
}

#[test]
fn an_unsigned_anchor_is_refused() {
    let s = Scenario::build();
    let chain = s.ledger.chain(0, 2).unwrap();
    // Two signatures, threshold three.
    let quorum = signature_evidence(&s.validators, &[0, 1], 3, chain.anchor());
    let err = ReturnProof::build(
        chain,
        &s.ledger.tree,
        s.return_index,
        quorum,
        s.view_key(),
        &s.return_spend_public(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::ThresholdNotMet { .. }), "got {err:?}");
}

#[test]
fn a_forged_signature_is_refused() {
    let s = Scenario::build();
    let chain = s.ledger.chain(0, 2).unwrap();
    let mut q = block_signature_quorum(&s.validators, &[0, 1, 2], 3, chain.anchor());
    // Corrupt one signature's bytes while leaving the signer field intact --
    // the shape a relayer-side bug or a splice attack would take.
    let raw: &[u8] = q.signatures[1].signature().as_ref();
    let mut bytes = raw.to_vec();
    bytes[0] ^= 0x01;
    let bad = mc_crypto_keys::Ed25519Signature::try_from(&bytes[..]).unwrap();
    q.signatures[1] = mc_blockchain_types::BlockSignature::new(bad, *q.signatures[1].signer(), 0);

    let err = ReturnProof::build(
        chain,
        &s.ledger.tree,
        s.return_index,
        mc_return::QuorumEvidence::BlockSignature(q),
        s.view_key(),
        &s.return_spend_public(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::BadBlockSignature { position: 1, .. }), "got {err:?}");
}
