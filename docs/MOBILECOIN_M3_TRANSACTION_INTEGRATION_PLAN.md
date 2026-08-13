# M3: real MobileCoin transaction integration plan

Status: **executed; focused pass with production blockers**. See
[`MOBILECOIN_M3_TRANSACTION_RESULTS.md`](MOBILECOIN_M3_TRANSACTION_RESULTS.md)
for the frozen code hashes, complete result matrix, and exact claim boundary.

The implementation satisfied every positive assertion and every directly
exercisable transaction mutation below. Exact corrupt-share attribution still
passes in M2b but is not preserved through MobileCoin's current `RingSigner`
error type, so that row remains an end-to-end integration requirement rather
than being counted as an M3 pass.

Pinned sources:

- MobileCoin `05cb699f8f4cc1bc21186392545820c5b38408db`
- Serai `4b89cf0206184886e96d0663861596312e5b47d2`

## Question M3 answers

M2 proves the MLSAG algebra in isolation. M3 must answer the next, materially
different question:

> Can the two-row threshold signer replace MobileCoin's local ring signer in a
> real two-input transaction while retaining MobileCoin's exact signing
> digest, `MaskedAmountV2` openings, pseudo-output balance, range proofs, and
> full unmodified transaction-signature verification?

Passing M3 is necessary but insufficient for strict custody. Current MobileCoin
interfaces hand a `RingSigner` complete input and pseudo-output blindings. M3
will Shamir-share their difference inside the test adapter; it will not pretend
that the complete scalars were never materialized.

## Stock construction path

1. Target `BlockVersion::FOUR`, the maximum version in the pinned repository.
   It selects `MaskedAmountV2` and the mixed-token `range_proofs` layout.
2. Generate a fixture root spend scalar `b`, distribute it with a fixed-secret
   Shamir polynomial, and retain `B = bG`. Construct the receiving account with
   `ViewAccountKey::new(a, B)` and two distinct subaddress indices. This proves
   MobileCoin can generate receive addresses from the public threshold spend
   key without reconstructing it during receipt.
3. Create two real eUSD `TxOut`s with `TxOut::new`/`new_with_memo`. Each output
   must contain a v2 masked amount. Add ten unrelated decoys to each real output
   and attach fixture membership proofs, yielding two 11-member rings.
4. Build `InputCredentials` with
   `OneTimeKeyDeriveData::SubaddressIndex(i)` and the view private key. The stock
   constructor sorts each ring, recomputes the real index, derives the shared
   secret, and calls `MaskedAmount::get_value`. Record and assert the recovered
   value, token ID, and real input blinding.
5. Use the stock `TransactionBuilder` to add both inputs and create a recipient
   output plus change. Call `build_unsigned`, then
   `UnsignedTx::get_signing_data`. Do not create a parallel digest. This path
   selects the actual pseudo-output blindings, generates range proofs, checks
   value/blinding conservation, and computes MobileCoin's version-selected
   MLSAG signing digest.
6. Implement a test `RingSigner` adapter around M2b. For each signable input it
   receives the exact MobileCoin digest, sorted `ReducedTxOut` ring, real input
   amount/blinding, and chosen pseudo-output blinding. It constructs
   `C_pseudo`, computes `z = b_pseudo - b_input`, creates fixed-secret Shamir
   shares of `z`, and invokes M2b `reserve -> sign -> aggregate`.
7. Pass that adapter to `SigningData::sign`, assemble the ordinary
   `SignatureRctBulletproofs` and `Tx`, then require stock
   `validation::validate_signature(BlockVersion::FOUR, &tx, rng)` to succeed.
   That final call recomputes the digest and verifies the range proofs, global
   commitment balance, and both unchanged MLSAGs.

## Exact one-time-key offset

For output public key `R`, private view key `a`, root spend scalar `b`, and
subaddress index `i`, the one-time secret is

```text
x = Hs(aR) + b + Hs(a || i).
```

The threshold shares therefore need the public additive offset

```text
delta = Hs(aR) + Hs(a || i),   so xG = B + delta G.
```

The pinned MobileCoin API exposes recovery of the complete one-time private
key and recovery of the public subaddress point, but not the two scalar offsets
as a canonical public function. M3 should avoid duplicating private domain-tag
logic: use the fixture's known `b` and stock `recover_onetime_private_key` as an
oracle, compute `delta = x - b`, offset every threshold share, and assert that
the resulting group key equals the real `TxOut.target_key`.

Production needs a reviewed MobileCoin API such as
`recover_onetime_key_offset(R, a, i)` or two canonical scalar-offset helpers.
Copying private hash/domain code into bridge software is a consensus-adjacent
fork hazard.

## Required success assertions

1. Both real outputs use `MaskedAmount::V2`.
2. Stock unmasking returns the exact fixture value, token ID, and blinding for
   both inputs.
3. The two inputs use different subaddresses/offsets and have distinct key
   images; every qualifying signer subset for one input has the same key image.
4. For each input, `zG = C_pseudo - C_input`.
5. `sum(b_pseudo) = sum(b_output)` and the full value/fee commitment
   conservation difference is the identity point.
6. At v4, `range_proofs` is nonempty and legacy `range_proof_bytes` is empty.
7. Both M2b MLSAG artifacts pass the public `RingMLSAG::verify`.
8. The complete transaction passes stock `validate_signature`.

## Mandatory failure conditions

| Mutation | Required result |
|---|---|
| wrong view key or subaddress index / one-time offset | reject before nonce generation because the threshold group key does not equal the real target key |
| wrong fixed-secret `z` shares | reject because the mask group does not open `C_pseudo - C_input` |
| changed prefix, output, fee, or token ID after signing | full signature validation rejects after digest recomputation |
| changed pseudo-output commitment | range/balance/signature verification rejects |
| changed range-proof bytes | range-proof verification rejects |
| corrupt row-0 share | M2b returns the exact bad round-map participant before aggregation |
| corrupt row-1 share | M2b returns the exact bad round-map participant before aggregation |
| input/output value imbalance | `SigningData::new_with_summary(..., true, ...)` returns `ValueNotConserved` |
| fewer than `t` participants | reject before any nonce package is exposed |

“Exact bad participant” is protocol-local detection only. It becomes slashable
evidence only after round messages are signed by registered identity keys.

## Source anchors

- `account-keys/src/account_keys.rs`: `ViewAccountKey::new`, `subaddress`
- `transaction/core/src/tx.rs`: `TxOut::new`, `new_with_memo`
- `transaction/types/src/masked_amount/{mod.rs,v2.rs}`: v2 selection,
  unmasking, HKDF-derived commitment blinding
- `transaction/builder/src/input_credentials.rs`: ring sorting and real amount
  recovery
- `transaction/extra/src/unsigned_tx.rs`: `get_signing_data`
- `transaction/core/src/ring_ct/rct_bulletproofs.rs`:
  `SigningData::new_with_summary`, `compute_pseudo_output_blindings`,
  `SigningData::sign`, `SignatureRctBulletproofs::verify`
- `crypto/ring-signature/signer/src/traits.rs`: `RingSigner`, `InputSecret`
- `crypto/ring-signature/src/onetime_keys.rs`: stock one-time key recovery
- `transaction/core/src/validation/validate.rs`: `validate_signature`

## Dependencies for the standalone M3 crate

Add the relevant path dependencies for `mc-account-keys`,
`mc-crypto-ring-signature-signer`, `mc-transaction-core`,
`mc-transaction-builder` with its `test-only` feature,
`mc-transaction-extra`, and MobileCoin's membership/Fog test utilities. Retain
the M2 cryptographic dependencies. Activate both root patches used by the
MobileCoin workspace: the pinned `bulletproofs-og` revision and the existing
`schnorrkel-og` revision.

## Claim boundary after a pass

The strongest honest M3 verdict will be:

> **Real MobileCoin multi-input transaction integration pass, with existing
> builder-time scalar exposure. Strict distributed masked-amount custody and
> production on-chain multisig remain unproved.**

The next milestone, M4, must eliminate the scalar-exposure boundary by jointly
deriving/constructing amount masks and pseudo-output blindings, or Josh must
explicitly accept that row-1 custody is weaker than the spend-key custody.
