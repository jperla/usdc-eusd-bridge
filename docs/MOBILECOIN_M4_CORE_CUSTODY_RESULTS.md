# M4 CoreCustody executable result

Date: 2026-08-08

## Verdict

**PASS at the stated CoreCustody boundary.**

The executable test uses a real Serai PedPoP 2-of-3 ceremony to create the
MobileCoin root spend threshold shares. It creates no complete root,
subaddress, or one-time spend secret. The tested offset-only API derives
`delta`, and the adapter checks `P = B + delta*G` before starting any M2b nonce
reservation. Every exact 2-of-3 subset signs the same real two-input
MobileCoin v4 transaction; all three complete signatures and all six MLSAGs
pass stock cryptographic validation.

Two unit tests passed:

- `pedpop_core_custody_two_real_v4_inputs_pass_stock_validation`
- `source_has_no_central_spend_reconstruction_escape_hatch`

The dependency's four offset/KDF conformance tests were also replayed locked
and offline: 4 passed, 0 failed.

The positive and negative assertions are enumerated in `README.md`.

## Source and environment

- MobileCoin: `05cb699f8f4cc1bc21186392545820c5b38408db`
- Serai: `4b89cf0206184886e96d0663861596312e5b47d2`
- M2b `strict.rs`: `76092f20bc1c5d706add15e3151b016d80f5a1857572d0dd5e0f01350d0a2ab8`
- offset API `src/lib.rs`: `79a58d8418e4611af784e9f10f09d736844a93417d9246f79ec8607862042599`
- rustc: `1.87.0-nightly (287487624 2025-02-28)`
- protoc: `25.3`
- no `RUSTC_BOOTSTRAP`

The final test and Clippy executions used the exact locked/offline commands in
`README.md`. Tests: 2 passed, 0 failed. Clippy: passed with
`--no-deps --all-targets -- -D warnings`; the pinned Serai dependency graph
emits an upstream unknown-lint warning under this nightly, but this crate has
no Clippy warnings.

The MobileCoin, Serai, M2b, and offset crates are local path dependencies;
`Cargo.lock` does not content-address their directory contents. The revisions/hashes above are
therefore part of the reproduction contract. The source escape-hatch test is only a regression
guard against three known centralized helper names; the no-reconstruction claim also depends on
manual audit of the frozen source hash and must not be inferred from that substring test alone.

## Non-claims

The result uses synthetic membership proofs and does not prove private
view/mask custody, participant process or HSM isolation, DKG
networking/completion consensus, real ledger membership, consensus-visible
threshold authorization, on-chain wardens, slashing, bridge safety, or network
activation. The complete view scalar `a`, input blinding, and pseudo-output
blinding are visible at the adapter boundary, so the complete mask difference
`z` is materialized. All PedPoP participants are simulated in one process. In
particular, existing consensus sees only an ordinary valid MLSAG and cannot
infer or prove that a threshold ceremony created it.

## M3 regression coverage

All M3 transaction-level negative cases were retained: wrong subaddress,
wrong mask group, under-threshold and unknown participants, mutated prefix,
masked output, fee, fee token, pseudo-output commitment and range proof, plus
value imbalance. M4 adds a direct corrupted-delta case and proves both delta
failures occur before any M2b nonce reservation starts. No M3 transaction
negative was omitted. Exact row-0/row-1 corrupt-share attribution is not
duplicated here; it remains covered by the frozen M2b tests.

The M3 canonical key-image comparison against a locally reconstructed
one-time secret was intentionally removed because reconstructing that secret
would violate this gate. Stock MLSAG verification and equality of key images
across all exact signer subsets replace that test without weakening the stated
no-complete-spend-secret boundary.

Honest label:

> **Real PedPoP root-spend shares and additive one-time offsets produce three
> verifier-accepted MobileCoin v4 two-input signatures without constructing a
> complete spend key; complete view/mask privacy, participant isolation,
> ledger membership, protocol-level authorization, wardens, accountability,
> and network activation remain unproved.**
