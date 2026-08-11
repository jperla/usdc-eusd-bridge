# MobileCoin M5 operation-journal checkpoint

Date: 2026-08-08

## Decision

**FOCUSED BOUNDED PASS: the single-host durable operation-journal reference model satisfies its stated safety invariants across the final 53-test deterministic falsifier suite. Full M5, consensus-level multisig/wardens, the MobileCoin network upgrade, and the bidirectional bridge remain open.**

The executable artifact is `../m5-operation-journal-spike/`. Its complete result and nonclaim contract is [`RESULTS.md`](../m5-operation-journal-spike/RESULTS.md).

## Frozen evidence

| File | SHA-256 |
|---|---|
| `m5_journal.py` | `5e880bfcdd85142bec8937191777791d4026e9c5340e29ab73789e0fff11d4ad` |
| `test_m5_journal.py` | `29d77b20c8fd32edfd88f921291bfa6295e326336fbbf5bced2395161e52bc4a` |
| `README.md` | `2d185b4f4fa04b46a0b6e1899b1c8daebcedbcd112417d4d5713ee592c981da5` |

All 53 tests passed independently under Python/SQLite 3.10.9/3.41.1, 3.12.3/3.53.3, and 3.14.6/3.53.3. Python 3.14.6 also passed with development mode and warnings promoted to errors. Ruff 0.15.12 lint and format checks passed. Two independent final reviews reproduced the suite and reported no P0/P1 finding within the explicit single-host scope.

```sh
cd /Users/jperla/josh/m5-operation-journal-spike
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -q test_m5_journal.py
ruff check --no-cache m5_journal.py test_m5_journal.py
ruff format --check --no-cache m5_journal.py test_m5_journal.py
```

## What this establishes

Within the modeled single-process boundary:

1. Admission atomically reserves one authenticated source liability and its complete ordered real-UTXO/child set, or reserves none of them.
2. Source-event, raw MobileCoin return-nullifier, canonical real-UTXO, operation, and child identities are independently derived and uniqueness-constrained.
3. One operation-wide `Accepted -> Authorized` transition durably binds the complete request vector before any new modeled round-2 response can be persisted or transmitted.
4. Authorization cannot ordinarily abort or rebind. Post-authorization replacement requires authenticated non-inclusion/expiry, monotonically invalidates the old unsigned-transaction digest, and requires a distinct registered-live replacement.
5. Response recovery is persist-before-transmit and byte-identical: the modeled nonce is consumed with an idempotent outbox entry before external observation.
6. Semantic preflight runs on open, before mutation, and again before commit. It closes authenticated source/family, operation history, terminal proof, ledger/TxOut, child, nonce, UTXO, outbox, and global lifecycle projections.
7. Global authorization and retry lifecycle records name the exact operation attempt; authorization also binds the resulting entry digest and complete request vector. Dedicated regressions prove that coherent cross-operation reassignment fails and rolls back.
8. A database-only rollback fails against the modeled independent monotone anchor. A surviving external response also fails preflight if its byte-identical durable outbox cause was removed or changed.

## Counterexamples repaired before freeze

The test oracle was strengthened after reviewers constructed concrete failures involving same-transaction reuse after expiry, incomplete semantic projection checks, deletion/mutation of authenticated source-family identity, inexact idempotent authorization retry, coherent cross-network UTXO rewriting, completed-state/global-history erasure, and cross-operation authorization ambiguity. Every accepted correction is represented by a regression; the final suite additionally includes an explicit retry-reassignment regression.

## Failure conditions

This checkpoint must be revoked if a permitted modeled execution can create duplicate liability ownership, partially reserve an input set, authorize an incomplete/different request vector, emit before exact operation-wide authorization, revive an expired transaction, mutate persisted response bytes, reopen a completed tombstone, transfer authorization/retry history between operations, accept a stale database against the independent evidence, or commit a semantically orphaned projection.

Rejection by itself is not success: adversarial tests inspect the durable post-failure state and require transaction rollback with no losing reservation, child, nonce, or outbox residue.

## Nonclaims and remaining gates

This checkpoint does **not** implement or prove:

- a replicated linearizable/BFT journal, quorum intersection, multi-host behavior, or protection when all modeled independent evidence is rolled back together;
- production Ethereum finality/deposit proofs, MobileCoin ledger/nullifier proofs, tombstone non-inclusion, or durable transaction-liveness evidence;
- real nonce-secret generation, sealed storage/erasure, signer process/HSM isolation, authenticated ceremony networking, PedPoP/share/catalog lifecycle, or signed culprit evidence;
- MLSAG/FROST/DKG cryptography or an independently implemented/finalized Rust consensus codec;
- the consensus-mandatory compact FROST authorization, distinct signer-attributable bonded warden receipts, source-event nullifier, economic penalties, caps, pause, or rotation;
- the new MobileCoin transaction format/validation rules and coordinated activation; or
- the Ethereum escrow contract and complete finalized USDC -> eUSD -> USDC cycle.

The next implementation gate is the remaining authenticated/distributed M5 machinery: a Rust port and cross-language vectors, real proof boundaries, replicated or hardware-backed monotonicity, sealed nonce custody, isolated signers, and a networked multi-input ceremony. M6 then introduces the new on-chain policy format and coordinated network upgrade. Only after those gates and the Ethereum leg pass their own falsifiers may the product claim Josh's complete bridge outcome.
