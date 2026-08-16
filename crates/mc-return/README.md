# mc-return

The relayer-side half of the bridge's RETURN leg. Given a MobileCoin ledger in
which a user has paid eUSD to the bridge's return address `R`, this crate
produces the proof an Ethereum verifier consumes, and writes it to
`fixtures/return.json`.

```
cd crates/mc-return && ./scripts/test.sh
```

That script exists only because `cargo test --offline -p mc-return` does not
work from the repo root today, for three reasons in files this component does
not own. They are spelled out at the top of `scripts/test.sh`; the short
version is that the root `[workspace]` needs `exclude = ["vendor"]`, the root
`[patch.crates-io]` needs MobileCoin's `bulletproofs-og` and `serde_cbor`
entries, and the build needs the `nightly-2024-10-11` toolchain MobileCoin
pins. Once the root manifest carries the first two, the plain cargo command
works with that toolchain and this script can be deleted.

## What the proof actually claims

Three separable claims, each with its own failure mode:

| claim | mechanism | adjudicated by |
| --- | --- | --- |
| the output is in the ledger | Blake2b Merkle path to a block's `root_element` | upstream `is_membership_proof_valid` |
| that block is final | k-of-n validator signatures | upstream `BlockSignature::verify`, or upstream `TrustedValidatorSet` |
| the output was created by block N | chained `cumulative_txo_count` across self-hashing headers | this crate, tested in `tests/proof.rs` |

### Why a return proof needs three block headers

A block's `root_element` is the ledger root the block was *validated against* —
`byzantine_ledger/worker.rs` reads it before the block is formed. So block N's
`root_element` does **not** commit to the outputs block N created. Proving a
return output is in the ledger requires a *later* block's root. The chain
`parent(origin) -> origin -> anchor` gives both the anchor's root and, from the
cumulative counts, which block created the output — without opening any block's
`contents_hash`.

`tests/proof.rs::the_block_that_created_the_output_cannot_anchor_it` is the
test that pins this; it is the mistake a straightforward implementation makes.

### Two attestation routes, and why the caller must choose

`AttestationRoute::BlockSignature` — every validator signs
`block.digest32::<MerlinTranscript>(b"block-sig")`, the same 32 bytes for all
of them. One merlin transcript, k signature checks.

`AttestationRoute::BlockMetadata` — the route MobileCoin's own light client
uses. Each validator signs its own `BlockMetadataContents`, which embeds that
node's responder id, quorum set and attestation evidence. Nothing amortizes.

Measured on the two fixtures, at a quorum of three:

| route | transcripts | merlin append ops | appended bytes |
| --- | --- | --- | --- |
| `block_signature` | 1 | 30 | 294 |
| `block_metadata` | 3 | 441 | 4443 |

Those numbers are `quorum_cost` in each fixture, and the tests assert the
underlying properties (`every_validator_signs_the_same_block_digest`,
`no_two_validators_sign_the_same_metadata_message`) rather than the numbers.
The metadata route buys enclave attestation and the externalization-time quorum
set; it costs roughly 15x the hashing at k=3 and grows with k.

## The fixture

`fixtures/return.json` (BlockSignature route) and
`fixtures/return-block-metadata.json` (BlockMetadata route). Both are written
and then re-verified by `tests/fixture.rs` in the same run, so the committed
file is one that was adjudicated, not one that happened to be committed.

Conventions:

* every `u64` is a **decimal string** — `JSON.parse` rounds anything above
  2^53, and `masked_value` is full-range. `every_u64_in_the_fixture_survives_json_parse`
  enforces that no bare JSON number in the file can be mangled.
* every byte string is `0x`-prefixed hex, which `harness.mjs`'s `b32()` accepts
  directly.

The unusual part is the `ops` arrays. MobileCoin's digests are **merlin**
transcripts — STROBE-128 over Keccak-f[1600] — and Solidity's `keccak256` is
the sponge, not the permutation. An Ethereum verifier has to drive its own
STROBE state machine, and it cannot derive the call sequence from a Rust
`derive(Digestible)`. So the fixture carries the sequence: `protocol_label`,
then the ordered `append_message(label, data)` calls, then `challenge_label`.
`digests.block_sig`, `digests.block_id`, `tx_out_digest` and each metadata
`signed_message` each carry one, next to the digest replaying it produces.
`tests/transcript.rs` asserts each script reproduces the upstream digest AND
that mutating any op, dropping one, reordering two, or changing either label
breaks it.

Note that `block.digest32(b"block-sig")` includes the block's own `id` field.
A verifier must therefore *also* check `id == compute_block_id(...)` — the
`digests.block_id` script is there for exactly that, and a verifier that skips
it accepts a header whose id was chosen freely.

## Limitations

**The disclosure is a convenience, not the on-chain mechanism.** `disclosure`
carries the recovered shared secret, blinding, memo and the resulting amount /
token id / beneficiary, and `Disclosure::open` proves they match the chain —
here, in Rust. **Ethereum does not consume any of it.**

An earlier version of this section claimed the amount and beneficiary could not
be established on chain without a discrete-log-equality proof that the supplied
`s` really is `a·R`. That was wrong, and the assumption behind it was that
Ethereum would be *given* `s`. It is not. The bridge's view private key `a` is
public by design — a view key confers the ability to recognize payments, never
to spend them — so `contracts/src/RecipientCheck.sol` holds `a` and computes
`S = [a]R` itself, as a by-product of the recipient check it already had to
perform. There is no supplied `s` to prove anything about. From that one point,
`contracts/src/AmountOpener.sol` re-derives the MaskedAmountV2 masks and the
memo key, and *requires* `value·B_token + blinding·B_blinding` to equal the
block's Pedersen commitment — so a wrong `S` is fatal rather than merely
unattested. See `contracts/test/verifier.mjs`.

`disclosure.on_chain_verifiable` is still `false` in the fixture, and that flag
is now narrower than it sounds: it means this crate does not *emit* an on-chain
proof object, not that the quantities are unverifiable on chain. The Ethereum
verifier derives `amount`, `tokenId` and `beneficiary` from the output's own
encrypted fields and trusts the relayer for none of them.

The **pairing of `eusdTokenId` with `eusdValueGenerator`** used to be open here,
and is not any more. The contract took `B_token` as a constructor argument
because deriving it needs hash-to-curve, so a mispaired deployment verified
commitments in the wrong group -- an amount MobileCoin rejects verified on
chain. `MobileCoinVerifier` now implements the ristretto255 one-way map
(RFC 9496 §4.3.4) and derives `B_token` from `eusdTokenId` in its constructor.
`eusdValueGenerator` survives as a getter, but it is derived, not supplied:
there is no argument left to mispair. The derivation costs ~160k gas once at
deployment and nothing at redemption.

**The Merkle tree is a mirror, not upstream's code.** `merkle.rs` reproduces
`mc-ledger-db`'s `tx_out_store.rs` (rev 05cb699f) rather than depending on it,
because upstream's is welded to LMDB. The hash functions themselves are
upstream's (`hash_leaf`, `hash_nodes`, `NIL_HASH`). Every proof is checked by
upstream's `is_membership_proof_valid` before it leaves the process, and
`tests/merkle.rs` pins the tree against a whole-tree definition written
independently of the incremental build. What is **not** checked is agreement
with a real LMDB `TxOutStore` on a real chain; there is no such cross-check
here, and a divergence in tree shape that both formulations shared would go
unnoticed.

**Ledger roots in the tests are self-produced.** The scenario ledger's blocks
carry root elements this crate computed, so "block root matches tree" cannot be
an independent check of MobileCoin's ledger. `each_block_commits_to_exactly_the_outputs_that_preceded_it`
narrows it to the declarative Merkle definition, but a fixture built from a
real MobileCoin block would be strictly better evidence and is not available
offline.

**k-of-n over `BlockSignature`s is this crate's construction.** MobileCoin has
no "k BlockSignatures over one block" type — a node's `ArchiveBlock` carries
one signature, and the relayer collects one per archive endpoint. The threshold
and distinctness logic in `BlockSignatureQuorum` is ours (the signature
verification is upstream's), and is tested directly, including that a replayed
signature from one node cannot make up a quorum. The `BlockMetadata` route has
no such gap: quorum counting there is upstream's `TrustedValidatorSet`,
including recursive inner sets.

**The memo type is unregistered.** `BRIDGE_RETURN_MEMO_TYPE = 0x8001` sits
outside MobileCoin's allocated 0x00xx–0x02xx range but is not registered with
anyone. A future collision would misrender the memo in wallets; it is not a
bridge security boundary, because the escrow pays out only for an output the
bridge's own view key opens and only the creator of that output could have
written its memo.

**Attestation evidence is not examined.** On the `BlockMetadata` route the
fixture uses a default `VerificationReport`. Upstream's `TrustedValidatorSet`
does not inspect the evidence either — it checks the signature and the quorum.
Deciding whether the attesting enclave is one the bridge accepts is a separate
problem this crate does not address.
