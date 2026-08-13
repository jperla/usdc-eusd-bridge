# MobileCoin M5 durable Rust journal checkpoint

## Status

**FOCUSED CONTROL-PLANE PASS.**

`/Users/jperla/josh/m5-rust-journal-spike` ports the bounded monotone operation
journal behind the validated Rust codec types. The detailed executable evidence
and failure contract is `m5-rust-journal-spike/RESULTS.md`.

This is not a production FROST signer and not completion of M5 or M6.

## Executed result

- Rust 1.97.1 and exact Rust 1.83.0 pass all 28 tests.
- The committed 490-line Python corpus regenerates byte-for-byte and passes all
  four independent reference checks.
- Representative Python/Rust accept, replay, authorize, permit, snapshot, and
  pending-outbox projections match exactly.
- One transaction reserves the authenticated source and entire ordered
  UTXO/child set or reserves nothing.
- One operation-wide transition binds every ordered request before any
  response permit exists.
- Response persistence consumes exactly one bound child and writes its exact
  bytes to an anchored recoverable outbox before external observation.
- Exact retry is state preserving. Changed source, transaction, ledger,
  policy, request, permit, or response data cannot masquerade as replay.
- Schema weakening, lifecycle erasure, row tampering, database/anchor
  disagreement, corrupt sinks, and stale preflight fail closed.
- Same-source and overlapping-UTXO races serialize; normalized process-local
  path locks also serialize independent file-adapter instances.

Review found and permanently tested defects involving schema self-repair,
stale preflight, path aliases, authorization return loss, lifecycle erasure,
error classification, and inconsistent multi-query reads.

## Exact success criterion

The result succeeds only if no tested execution can:

1. partially reserve a multi-input operation;
2. authorize an incomplete/reordered request vector;
3. create a response for an unbound child or stale permit;
4. observe response bytes before their database state is durably anchored;
5. produce two external observations for one message identity;
6. revive a consumed symbolic nonce or erase a persisted lifecycle event;
7. continue after authenticated state, schema, anchor, or sink corruption; or
8. publish from a stale exact replay during another writer's commit/anchor gap.

Every listed counterexample has a deterministic regression test. These are
local control-plane conditions, not FROST-security or product-level conditions.

## The two P0 blockers

### Raw response injection

`OperationJournal::emit_round2` accepts caller-provided bytes. In the fixture,
a valid permit plus arbitrary non-empty bytes consumes a child. A real signer
outside the journal could also generate or leak a signature share before
persistence. Therefore this API is not a production signing boundary.

### No cryptographic nonce custody

The database records only symbolic `RESERVED -> BOUND -> CONSUMED` state. It
does not durably identify the FROST nonce, hiding/binding commitments,
participant/share, DKG epoch, or exact transcript. Two responses made with one
effective nonce under distinct challenges reveal the secret share; three
generic reuses of one two-nonce FROST pair also suffice when binding factors
change.

The next gate must replace raw response injection with an isolated
`produce_once` signer/HSM primitive. It must atomically bind one globally unique
nonce to the exact canonical transcript, persist or internally retain the exact
response across crashes, erase/retire secrets monotonically, and expose no new
share before the journal/anchor/outbox permits release.

## Remaining failure boundary

The ordinary-file anchor/sink establish neither cross-process nor distributed
linearizability. Injected errors are not `SIGKILL`, torn-write, power-loss, or
filesystem fault evidence. The DB/anchor dual-write gap is safely fail-closed
but lacks an independently justified recovery protocol. Current 16 MiB response
bounds and repeated global scans are not production resource limits. Digest-only
binding requires persisted canonical proof bytes or a formally specified
immutable content authority. A near-tombstone liveness check can race later
persistence/publication without a conservative block-height margin.

Still open are real source/finality/non-inclusion verification, authenticated
network ceremony, signer/HSM isolation, durable nonce vault, DKG/share/catalog
lifecycle, standalone culprit evidence, a replicated monotone authority,
MLSAG/FROST integration, and all M6 consensus/network changes.

## Relation to Josh's goal

M6 remains the actual MobileCoin protocol change: a new transaction format and
coordinated network upgrade in which consensus requires all of:

1. policy-bound threshold authorization;
2. a compact FROST gate;
3. a separate signer-attributable bonded warden receipt set; and
4. exactly-once source-event nullifier consumption.

Only the later Ethereum integration and full acceptance test can prove one
eUSD release per finalized USDC deposit and one USDC release per authenticated
eUSD return.
