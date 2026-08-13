//! Both quorum routes, and the property that separates them.
//!
//! The `BlockSignature` route's whole appeal is that k validators sign ONE
//! message, so an Ethereum verifier pays for one merlin transcript and k
//! signature checks. The `BlockMetadata` route's cost is that they do not. Both
//! claims are asserted here on real signatures rather than asserted in a
//! comment.

mod common;

use common::*;
use mc_blockchain_types::{BlockID, BlockSignature};
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_keys::Verifier;
use mc_return::{
    attestation::{block_metadata_script, block_sig_script},
    Error,
};
use std::collections::BTreeSet;

// ---------------------------------------------------------- BlockSignature

#[test]
fn every_validator_signs_the_same_block_digest() {
    // The amortization claim, stated as an experiment: take the ONE digest the
    // block implies, and verify all five signatures against it with the raw
    // ed25519 verifier -- no per-signer message anywhere.
    let s = Scenario::build();
    let anchor = s.ledger.block(2);
    let digest = block_sig_script(anchor).replay();
    assert_eq!(digest, anchor.digest32::<MerlinTranscript>(b"block-sig"));

    let q = block_signature_quorum(&s.validators, &[0, 1, 2, 3, 4], 3, anchor);
    assert_eq!(q.signatures.len(), 5);
    for sig in &q.signatures {
        assert!(
            sig.signer().verify(&digest, sig.signature()).is_ok(),
            "a validator's signature was not over the shared block digest"
        );
    }
}

#[test]
fn a_quorum_of_block_signatures_is_accepted() {
    let s = Scenario::build();
    let anchor = s.ledger.block(2);
    block_signature_quorum(&s.validators, &[0, 2, 4], 3, anchor)
        .verify(anchor)
        .expect("3 of 5 should satisfy a threshold of 3");
}

#[test]
fn too_few_block_signatures_is_rejected() {
    let s = Scenario::build();
    let anchor = s.ledger.block(2);
    let err = block_signature_quorum(&s.validators, &[0, 2], 3, anchor)
        .verify(anchor)
        .unwrap_err();
    assert!(
        matches!(err, Error::ThresholdNotMet { got: 2, threshold: 3 }),
        "got {err:?}"
    );
}

#[test]
fn one_validator_cannot_sign_twice_to_reach_the_threshold() {
    let s = Scenario::build();
    let anchor = s.ledger.block(2);
    let mut q = block_signature_quorum(&s.validators, &[0, 1], 3, anchor);
    // Replay node 0's real, valid signature a third time. Every signature in
    // the set verifies; only distinctness stands between this and a forged
    // quorum.
    q.signatures.push(q.signatures[0].clone());
    let err = q.verify(anchor).unwrap_err();
    assert!(matches!(err, Error::DuplicateSigner { position: 2 }), "got {err:?}");
}

#[test]
fn a_signature_from_outside_the_signer_set_does_not_count() {
    let s = Scenario::build();
    let anchor = s.ledger.block(2);
    let mut r = rng(99);
    let outsider = Validator::set(&mut r, 1);

    let mut q = block_signature_quorum(&s.validators, &[0, 1], 3, anchor);
    // A perfectly valid signature over the right block, from a key the bridge
    // never trusted.
    q.signatures.push(
        BlockSignature::from_block_and_keypair(anchor, &outsider[0].keypair).unwrap(),
    );
    let err = q.verify(anchor).unwrap_err();
    assert!(matches!(err, Error::UnknownSigner { position: 2 }), "got {err:?}");
}

#[test]
fn signatures_over_a_sibling_block_do_not_verify() {
    let s = Scenario::build();
    let anchor = s.ledger.block(2);
    let other = s.ledger.block(1);
    let q = block_signature_quorum(&s.validators, &[0, 1, 2], 3, other);
    let err = q.verify(anchor).unwrap_err();
    assert!(matches!(err, Error::BadBlockSignature { position: 0, .. }), "got {err:?}");
}

#[test]
fn a_threshold_larger_than_the_signer_set_is_refused_up_front() {
    let s = Scenario::build();
    let anchor = s.ledger.block(2);
    let mut q = block_signature_quorum(&s.validators, &[0, 1, 2], 3, anchor);
    q.threshold = 6;
    assert!(matches!(
        q.verify(anchor).unwrap_err(),
        Error::UnsatisfiableThreshold { threshold: 6, signers: 5 }
    ));
}

// ----------------------------------------------------------- BlockMetadata

#[test]
fn mobilecoins_own_light_client_accepts_a_metadata_quorum() {
    let s = Scenario::build();
    let anchor = s.ledger.block(2);
    // Adjudicated entirely by TrustedValidatorSet::verify_block_id_signatures.
    block_metadata_quorum(&s.validators, &[1, 3, 4], 3, anchor)
        .verify(&anchor.id)
        .expect("MobileCoin's verifier should accept 3 of 5");
}

#[test]
fn mobilecoins_own_light_client_rejects_a_short_metadata_quorum() {
    let s = Scenario::build();
    let anchor = s.ledger.block(2);
    let err = block_metadata_quorum(&s.validators, &[1, 3], 3, anchor)
        .verify(&anchor.id)
        .unwrap_err();
    // Upstream's NotAQuorum, surfaced through our wrapper.
    assert!(format!("{err}").contains("NotAQuorum"), "got {err}");
}

#[test]
fn metadata_for_one_block_is_not_evidence_for_another() {
    let s = Scenario::build();
    let q = block_metadata_quorum(&s.validators, &[0, 1, 2], 3, s.ledger.block(2));
    let err = q.verify(&BlockID([9u8; 32])).unwrap_err();
    assert!(format!("{err}").contains("BlockIdMismatch"), "got {err}");
}

#[test]
fn no_two_validators_sign_the_same_metadata_message() {
    // The counterpart of `every_validator_signs_the_same_block_digest`, and the
    // reason the metadata route cannot amortize: five nodes, five distinct
    // preimages, because each contents embeds that node's responder id.
    let s = Scenario::build();
    let anchor = s.ledger.block(2);
    let q = block_metadata_quorum(&s.validators, &[0, 1, 2, 3, 4], 3, anchor);

    let digests: BTreeSet<[u8; 32]> = q
        .metadata
        .iter()
        .map(|m| block_metadata_script(m).replay())
        .collect();
    assert_eq!(digests.len(), 5, "metadata digests collided across nodes");

    // And none of them is the block-sig digest, so a verifier cannot satisfy
    // one route with the other's material.
    let block_digest = block_sig_script(anchor).replay();
    assert!(!digests.contains(&block_digest));
}

#[test]
fn the_two_routes_disagree_about_how_much_work_scales() {
    // Same block, quorums of 1, 3 and 5. Under `block_signature` the verifier
    // drives one transcript however many signed; under `block_metadata` it
    // drives one per signer.
    //
    // The block-sig half is stated as an experiment rather than as an equality
    // between two copies of the same expression: for each k, ONE replayed
    // digest is verified against every signature in the quorum. If any node
    // were signing something of its own the loop would fail, and the route
    // would not amortize.
    let s = Scenario::build();
    let anchor = s.ledger.block(2);
    let sig_ops = block_sig_script(anchor).ops.len();
    let mut meta_ops = Vec::new();

    for k in [1usize, 3, 5] {
        let signing: Vec<usize> = (0..k).collect();

        let digest = block_sig_script(anchor).replay();
        for (i, sig) in block_signature_quorum(&s.validators, &signing, 3, anchor)
            .signatures
            .iter()
            .enumerate()
        {
            assert!(
                sig.signer().verify(&digest, sig.signature()).is_ok(),
                "at k={k}, signer {i} did not sign the one shared block digest"
            );
        }

        let meta = block_metadata_quorum(&s.validators, &signing, 3, anchor);
        assert_eq!(meta.metadata.len(), k, "one metadata message per signer");
        meta_ops.push(
            meta.metadata
                .iter()
                .map(|m| block_metadata_script(m).ops.len())
                .sum::<usize>(),
        );
    }

    // Metadata work strictly increases with k; the single block-sig transcript
    // is already smaller than the metadata cost of the smallest quorum.
    assert!(
        meta_ops[0] < meta_ops[1] && meta_ops[1] < meta_ops[2],
        "metadata transcript work did not grow with the quorum size: {meta_ops:?}"
    );
    assert!(meta_ops[2] > sig_ops);
}
