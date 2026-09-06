//! Synthetic ledger generator for local integration only. Deterministic test keys.
#[allow(dead_code, unused_imports)]
#[path = "../tests/common/mod.rs"]
mod common;
use common::*;
use mc_return::ReturnProof;
fn main() {
    let raw = std::env::args()
        .nth(1)
        .expect("redemption domain hex required");
    let domain: [u8; 32] = hex::decode(raw.trim_start_matches("0x"))
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let s = Scenario::with_domain(domain);
    let chain = s.ledger.chain(0, 2).unwrap();
    let quorum = signature_evidence(&s.validators, &[0, 1, 2], 3, chain.anchor());
    let proof = ReturnProof::build(
        chain,
        &s.anchor_tree(),
        s.return_index,
        quorum,
        s.view_key(),
        &s.return_spend_public(),
        &domain,
    )
    .unwrap();
    println!("{}", proof.to_json());
}
