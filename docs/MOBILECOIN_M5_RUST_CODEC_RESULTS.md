# MobileCoin M5 Rust codec / validated-history checkpoint

## Status

**FOCUSED PASS.** `/Users/jperla/josh/m5-rust-codec-spike` independently
reproduces the frozen Python M5 candidate codec and ID derivations and adds a
security-typed whole-history validator. The detailed executable evidence
contract is `m5-rust-codec-spike/RESULTS.md`.

This is a portability and local validation result, not completion of M5 or
implementation of Josh's protocol-level FROST + warden + nullifier design.

## Evidence

- 110 static named vectors cover BLAKE2b-512 transcripts, mixed endianness,
  both source directions, alias behavior, assets/recipients, eUSD
  `TokenId(8192)`, TxOut identity, full-`u64` ledger indexes, full-`u16`
  ordinals, reservations, every entry state, semantic-invalid encodings, and
  malformed wires.
- Python 3.10.9, 3.12.3, and 3.14.6 regenerate the exact committed corpus,
  round-trip the supported positive codecs, and reject the Python-side
  malformed cases.
- Rust 1.97.1 and exact Rust 1.83.0 pass all 29 tests under the locked graph;
  all 110 vectors are consumed without invoking Python at Rust test time.
- Rust independently constructs the full two-input reservation and its first
  two entries from typed primitives, so encoder/decoder agreement cannot hide
  an equal-width field permutation relative to Python.
- Exhaustive structural tests reject 4,701 strict prefixes and 4,608 possible
  one-byte trailing extensions across 18 canonical objects.
- Five legal history shapes pass. Empty/illegal/extended histories, version
  gaps, random predecessors, cross-reservation entries, malformed request
  vectors, and malformed terminal/abort payloads fail.
- Homebrew Clippy 0.1.97 passes all targets with warnings denied; rustfmt 1.9.0
  and Ruff 0.15.12 pass. Python 3.14.6 also passes development mode with
  warnings promoted to errors.

## Review counterexample and repair

The first local-shape API accepted a caller-provided `input_count`. The frozen
`entry_authorized_one_request` commits to the two-input reservation but carries
one request digest; passing `1` made it appear valid in isolation.

The repaired API admits reservations through opaque
`ValidatedReservationCore` and validates complete histories. Request count is
derived from that reservation; every entry must commit to its exact digest and
to the exact previous entry digest. The regression now fails against the
two-input reservation for cardinality and against a real one-input reservation
for reservation mismatch.

Review also caused these permanent changes:

1. `SourceTerms` fields became private/read-only;
2. arbitrary caller bytes can no longer be combined with unrelated source
   fields when deriving a source-record digest;
3. safe reservation digest access moved to a validated newtype, while raw byte
   hashes are explicitly named unchecked;
4. Authorized request-vector validation no longer allocates nested vectors;
5. reservation count is bounded before allocation; and
6. list-item and entry-payload encoder/decoder limits are symmetric.

## Frozen core hashes

- upstream frozen Python oracle:
  `5e880bfcdd85142bec8937191777791d4026e9c5340e29ab73789e0fff11d4ad`
- `Cargo.toml`: `e65ec6165007cbd20bc58f855c71672acfede2497b3e0927aaa76be75d9427c4`
- `Cargo.lock`: `72263f407b4c3a643bd34d17743d7d3668873af3c6d83c22aa56f51aac2f4085`
- `src/lib.rs`: `6711ca7cef8def7cc247b8bf843b58f2c1140ad510d06ae67f5b19ee3fab6915`
- vector corpus: `dbe21588819dadbdd345210eac47c0c115cf393ee245bb55f5bfe0763fe0cd8f`
- Python generator/check: `67a927d1cd5a42fc49e46fc690ccf486a106cb817bfc2b937128651d364cdf6a` /
  `6228233d381c6f5719baa9a996850d9aabf7ef86080b2b5cc54f2e2c5f799073`
- Rust differential/rejection/history/truncation tests:
  `c325b8b907b0ef5092f0a189b212b1fd1e802cecb16f795478953c08773c860b`,
  `99e1aa69118e4fa7e7fe2652989114a94f9205813f33af20e613b3dc0abc1ca4`,
  `bc80f78fb556836474b806b8d242397a256dc076892e518c5db1a97395596b8d`,
  and `5ae87b68fea97bbd6fbcc4c758dd30b8b9bd5b50e747d31f65b8e12daca08d58`.

## Boundary and next gate

The complete suite executed with `rustc 1.83.0 (90b35a623 2024-11-26)` and
`cargo 1.83.0 (5ffbef321 2024-10-29)`. The declared minimum-toolchain
compatibility gate therefore passes for this bounded crate; future integration
still needs the project's pinned CI environment.

This checkpoint does not prove production point/Fog validation, authenticated
source/ledger/finality/non-inclusion/liveness proofs, durable or replicated
state, nonce custody, process isolation, authenticated networking, DKG/catalog
lifecycle, evidence adjudication, MLSAG/FROST, bonded wardens, penalties,
MobileCoin consensus rules, activation, Ethereum escrow, or the end-to-end
USDC -> eUSD -> USDC cycle.

The next bounded step is a Rust durable state-machine port behind these
validated types, with state/receipt traces checked against the frozen 53-test
Python/SQLite oracle. M6 remains the separate network-upgrade milestone where
consensus makes threshold authorization, attributable warden receipts, and the
source-event nullifier mandatory.
