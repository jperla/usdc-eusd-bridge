# merlin-fixtures

Generates `contracts/test/fixtures/merlin.json`, the oracle for
`contracts/src/Merlin.sol`.

```
cd tools/merlin-fixtures && cargo run --offline
```

It is deliberately outside the root Cargo workspace (its own empty
`[workspace]` table), so `cargo test -p <bridge crate>` never builds it.

## What is actually being proved

Everything in the JSON is produced by the crates MobileCoin itself links,
through their public APIs:

* `merlin` 3.0.0, resolved from crates.io with checksum
  `58c38e2799fc0978b65dfff8023ec7843e2330bb462f19198840b34b6582397d` --
  the same checksum in `vendor/mobilecoin/Cargo.lock`.
* `mc-crypto-digestible` 7.1.0, by path into `vendor/mobilecoin`, including
  its `derive` macro.

Nothing here reimplements STROBE, Merlin or the digestible AST framing. The
Solidity does; the JS test asserts they agree byte for byte.

The `digestibleKats` entries go one step further. Their expected values are
hardcoded in MobileCoin's own `crypto/digestible/tests/basic.rs`, and this
generator **asserts** that replaying its op scripts through the real crates
reproduces them before writing them out. So those cases pin the Solidity to
values MobileCoin published, not to values this repository computed.

## The gap

`compute_block_id` is transcribed, not linked.

The real function lives in `mc-blockchain-types`, which depends on `mc-common`,
which enables hashbrown's `nightly` feature. hashbrown 0.14.x's use of
`min_specialization` (`impl<T: Copy, A: Allocator + Clone> RawTableClone`) no
longer compiles on current rustc, and there is no nightly toolchain here.
`RUSTC_BOOTSTRAP=1` gets past the feature gate but not past the specialization
error. So `src/main.rs` re-declares the five types the block ID touches --
`Range`, `TxOutMembershipHash`, `TxOutMembershipElement`, `BlockID`,
`BlockContentsHash` -- and copies `compute_block_id` verbatim, each with a
file-and-line citation to `vendor/mobilecoin`.

What that leaves unproved: if a field name, field order, type name or
`#[digestible]` attribute were mis-transcribed, this generator and
`MobileCoinBlockId.compute` would agree with each other and both differ from
MobileCoin. The `#[derive(Digestible)]` expansion and the merlin transcript
under it are still the real ones; only the *shape* of the struct is asserted by
reading rather than by linking.

MobileCoin does publish a block-ID known-answer vector
(`test_hashing_is_consistent_block_version_one` in `blockchain/types/src/block.rs`),
but its `contents_hash` input comes from a seeded RNG driving TxOut
construction, so the inputs cannot be reconstructed without the same
dependency tree that will not build. Closing this gap needs a nightly
toolchain, or a hashbrown patch, or MobileCoin publishing a block ID together
with its six header inputs.

## Also worth knowing

The generated `Cargo.lock` resolves `ed25519-dalek` and some other transitive
crates to newer versions than `vendor/mobilecoin/Cargo.lock` pins. That does
not affect any byte in the output -- only `merlin` and the digestible framing
do, and `merlin` is pinned to the same checksum -- but it is why this lock file
is not identical to MobileCoin's.
