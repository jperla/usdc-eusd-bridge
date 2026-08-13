# amount-fixtures

Generates `contracts/test/fixtures/amount.json`, the oracle for opening a
MobileCoin TxOut's **amount**, **token id** and **beneficiary** on chain.

```
cd tools/amount-fixtures && cargo run --offline
```

That is the whole regeneration command; it writes the JSON in place and prints
the path. It needs the repo's pinned nightly on PATH, same as `cargo test`:

```
export PATH="$HOME/.rustup/toolchains/nightly-2024-10-11-aarch64-apple-darwin/bin:$PATH"
```

Deliberately outside the root Cargo workspace (its own empty `[workspace]`
table, and `tools` is in the root manifest's `exclude`), so `cargo test` never
builds it. Output is deterministic — a seeded ChaCha20 RNG — so a regeneration
that changes a byte means a dependency changed, not that the fixture drifted.

## Why this file exists

`MobileCoinVerifier` currently pays `Proof.amount` to `Proof.beneficiary` in
`Proof.tokenId`, all three supplied by whoever relays the proof. The TxOut
digest binds only their *encrypted* forms. One genuine quorum-signed return is
therefore enough to drain the escrow. Closing that means deriving all three on
chain from bytes the digest actually commits to.

That derivation is not obvious, and an oracle for it must not be a second
hand-written transcription of the same spec — two transcriptions can agree with
each other and both be wrong. So nothing in `src/main.rs` re-derives anything.
Every published byte comes out of MobileCoin's own crates:

| what | produced by |
| --- | --- |
| masked value, masked token id, commitment | `MaskedAmountV2::new` |
| value, token id, blinding | `MaskedAmountV2::get_value` |
| amount shared secret | `MaskedAmountV2::compute_amount_shared_secret` |
| `B_token`, `B_blinding` | `mc_crypto_ring_signature::generators` |
| `S = a·R` | `mc_transaction_core::get_tx_out_shared_secret` |
| memo ciphertext / plaintext | `MemoPayload::encrypt` / `decrypt_from` |
| curve arithmetic, encodings | curve25519-dalek |

## What is in the JSON

* **`maskedAmounts`** — eight complete `MaskedAmountV2` cases. Token id 0 and
  three non-zero ids (1, 8192 = eUSD, `u64::MAX`); value 0, value 1, a
  realistic eUSD amount, and `u64::MAX`. Each carries `S`, the masked value,
  the masked token id, the commitment, and the value / token id / blinding they
  open to.

  Each also carries the **intermediates**, so a Solidity failure localises
  instead of just saying "wrong": `amountSharedSecret`, `valueMaskBytes`,
  `tokenIdMaskBytes`, and the 64 `blindingWide` bytes the blinding is reduced
  from. Every case additionally publishes the `viewPrivateKey` and
  `txPublicKey` it was built from, so a test can start where
  `ristretto.json`'s recipient check ends — compute `S = a·R` itself — rather
  than taking `S` on faith.

* **`maskedAmountRejects`** — six cases that must not pay out.

  `commitment-does-not-open-to-masked-value` is the attack: `masked_value`
  unmasks to 500,000,000,000 while the commitment commits to 1,000,000. This is
  what the on-chain commitment check exists to stop, and the generator asserts
  upstream answers `InconsistentCommitment`. Four `masked-token-id-length-*`
  cases (0, 4, 7, 9 bytes) pin `InvalidMaskedTokenId` — v2 has no short form and
  must not zero-extend. `well-formed-but-wrong-token-id` opens *cleanly* under
  MobileCoin and must still be refused by the bridge, whose `B_token` is pinned
  to `eusdTokenId`.

* **`generators`** — `B_blinding` and `B_token` for each token id used, plus
  each one's 32-byte hash preimage. This is what the immutable pinned at
  deployment must equal; **the JS test has to assert that**, or the constant is
  unfounded.

* **`hkdf`** — the four calls the constructions actually make
  (`mc_amount_value` / `mc_amount_token_id` / `mc_amount_blinding` under the
  `mc_amount_blinding_factors` salt, and `mc-memo-okm`), each keyed on a real
  case in this same file so a test can walk straight from the vector into
  `maskedAmounts[3]` / `memos[0]`. Plus RFC 5869 test cases 1–3.

* **`memos`** — four cases with `S`, the 66-byte plaintext, the 66-byte
  ciphertext, the 48-byte OKM, and the AES key / nonce / counter blocks /
  keystream it decomposes into. Three are real bridge memos (type `0x8001`
  with a 20-byte address in the first 20 data bytes, per
  `crates/mc-return/src/disclosure.rs`); the fourth is type `0x0100`, which
  decrypts fine and must be refused anyway.

* **`memoCipher`** — see below.

* **`domainSeparators`** — the literal tag bytes, so the JSON is self-contained.

## The counter-mode trap

MobileCoin encrypts memos with `Ctr64BE<Aes256>` (`transaction/core/src/memo.rs:37`).
Only bytes 8..16 of the 16-byte nonce are the counter; they increment
big-endian and **wrap without carrying** into bytes 0..8.

The obvious implementation is Ctr128BE — one 128-bit counter over the whole
block. That is what OpenSSL's `aes-256-ctr`, Node's `createCipheriv` and most
Solidity AES ports do. On a real memo the two always agree, because a memo is
five blocks and a divergence needs the OKM's low 64 bits to land within 4 of
`u64::MAX`. A Ctr128BE verifier would therefore pass every test built from real
memos and still be wrong, with a failure that sampling cannot find.

So `memoCipher` sets the nonce by hand instead of deriving it, and two of its
three cases straddle the wrap. `wrapsCounter` marks the cases where the two
modes must disagree, and the generator asserts they do — and that the
non-wrapping case does not — so these cannot rot into vectors that prove
nothing.

## Why the intermediates are safe to publish

`amountSharedSecret`, the masks, `blindingWide`, the OKM, the AES key/nonce and
the counter blocks are not returned by MobileCoin's public API. The generator
recomputes them with the same `hkdf` / `sha2` / `aes` / `ctr` versions
MobileCoin's own workspace pins, and then **asserts each one reproduces what
the MobileCoin API already returned**:

* the masks, by XOR-ing them back off `masked_value` / `masked_token_id` and
  requiring the original value and token id;
* `blindingWide`, by reducing it and requiring the scalar `get_value` returned;
* the commitment, by recomputing `value·B_token + blinding·B_blinding` with
  plain dalek arithmetic and requiring the point in the masked amount (a
  different dalek code path from `PedersenGens::commit`, which uses Straus
  multiscalar);
* the OKM/key/nonce, by running AES-CTR over the plaintext and requiring
  `MemoPayload::encrypt`'s ciphertext.

Every case round-trips through `get_value` / `decrypt_from` before anything is
written. An intermediate that did not reconstruct the API's answer aborts the
program instead of being written out.

The domain-separator literals are asserted equal to
`mc_transaction_types::domain_separators`. `HASH_TO_POINT_DOMAIN_TAG` is not
`pub`, so it is retyped — but the spelled-out `B_token` construction is
asserted to reproduce `generators(id)`, which a wrong tag cannot do.

## Evidence the guards are not vacuous

Sixteen deliberate mutations were applied one at a time and each aborted the
generator: a flipped byte in a published RFC 5869 OKM; an off-by-one in the
commitment relation; corrupted value and token-id masks; an inverted blinding;
a wrong hash-to-point tag; a wrong basepoint encoding; Ctr128BE substituted for
Ctr64BE in the wrap check; a wrong AES key in the memo decomposition; a
tampered domain separator; an 8-byte length in the token-id reject list; a
broken `get_value` round trip; a forged masked value that was not actually
forged; a broken memo round trip; and a self-comparison in the `B_token`
orthogonality check. Source and output were restored byte-identically
afterwards and confirmed with `cmp`.

Separately, the emitted JSON was checked against Node's OpenSSL-backed
primitives — 66 checks of HKDF-SHA512/SHA-256, Blake2b-512 and AES-CTR, and 22
more rebuilding every keystream from AES-**ECB** over the published counter
blocks (CTR from first principles, sharing no code with the `ctr` crate). All
88 agreed.

## What is still not pinned

The curve arithmetic rests on curve25519-dalek alone. MobileCoin publishes no
known-answer vector for `generators(token_id)` — `test_generator0` in
`crypto/ring-signature/src/ring_signature/mod.rs:238` only checks
`generators(0).B == hash_to_point(basepoint)`, which is the same computation
again. The one external anchor under this section is the ristretto255 draft's
published basepoint encoding `e2f2ae0a…2d76`, which is the preimage every
`B_token` is built from and which the generator asserts. That is the same
footing `ristretto.json` stands on.

The `[patch.crates-io]` block here carries three of the six entries the root
manifest does. `mbedtls`, `mbedtls-sys-auto` and `lmdb-rkv` are reached only by
the enclave and ledger crates, which this generator does not link; leaving them
in made cargo warn on every run.
