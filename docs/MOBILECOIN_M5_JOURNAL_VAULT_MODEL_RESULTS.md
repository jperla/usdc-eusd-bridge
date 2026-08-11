# M5 journal / sealed-vault bounded model results

## Status

**Executed bounded symbolic-projection model: PASS.**

This result evaluates the one-child ordering contract in
`MOBILECOIN_M5_JOURNAL_VAULT_INTEGRATION_PLAN.md`. It does not implement or
claim canonical bytes, filesystem durability, SQLite semantics, authenticated
checkpoint proofs, an HSM, cryptography, FROST/MLSAG, replication, or
MobileCoin consensus.

## Bound and state

The immutable Python state represents:

- Jc: one exact authenticated pre-commit nonce statement with separate DB and
  operation-authority-anchor steps;
- C: one observed fully bound commitment;
- J0: one exact commitment-dependent operation authorization with separate DB
  and anchor steps before J1;
- journal stages J1 (request), J2 (sealed receipt), J3 (release certificate),
  O (outbox), and D (delivery), each with distinct symbolic DB and anchor
  projections;
- vault states Empty, Committed, Sealed, and Released;
- distinct current-DB and previously anchored J1 identities, so an attempted
  changed-request DB write cannot erase the old anchored identity;
- symbolic Exact, Changed, and Caller identities for vault/journal receipt,
  certificate, vault-retained response, returned response capability, outbox,
  publication, and delivery;
- distinct transitions for symbolic release persistence, response return
  across the vault boundary, and publisher observation, including a crash
  after release persistence and before response return;
- crash/restart and lost-return-ack/exact-retry states; and
- terminal fail-closed handling for DB/anchor and vault-checkpoint disagreement,
  including an explicit anchor-ahead mismatch flag.

The honest exhaustive search reached **128 states and 192 labeled edges**, with
**4 safe delivered-state variants** and no invariant violation. Edge counting
includes rejected changed-value stutters, crash/restart, lost-ack/retry, and
fail-closed detection branches.

## Checked invariants

1. An observable commitment requires the exact authenticated Jc identity to be
   authority-anchored; J0 requires Jc/C; J1 requires anchored exact J0.
2. Every J1-or-later DB projection retains the exact request, and every
   J1-or-later anchor retains its prior exact identity.
3. `SEALED` or later implies exact anchored J1; J2 or later implies a sealed
   vault plus exact retained and journal receipt identities.
4. One semantic nonce slot retains only one exact anchored request binding.
5. Certificate existence requires anchored exact J2; every J3-or-later DB
   projection retains the exact certificate.
6. `RELEASED` implies the exact retained response and anchored exact J3.
   Response return across the vault boundary separately implies persisted
   release.
7. O implies anchored J3 and the exact returned response identity; publisher
   observation separately requires anchored exact O.
8. D retains the exact publication identity, and anchored delivery requires
   exact append-once publication.
9. An explicit anchor-ahead mismatch must be terminal fail-closed; otherwise an
   anchor never leads its DB projection and a live call has at most one
   unanchored DB mutation.

## Deliberate-defect witnesses

Each defect was enabled alone. Breadth-first search produced and the tests
freeze the complete invariant set at the shortest counterexample:

| Defect | Exact violated invariant set | Edges |
|---|---|---:|
| skip exact pre-commit authorization | `CommitmentRequiresAnchoredAuthorization` | 1 |
| ignore explicit anchor-ahead mismatch | `AnchorAheadMismatchMustFailClosed` | 1 |
| seal before J1 anchor | `SealedRequiresAnchoredExactJ1` | 7 |
| persist J2 before vault seal | `J2RequiresSealedExactReceipt` | 8 |
| write changed J1 while retaining old anchored J1 | `J1DatabaseRequiresExactRequest` | 8 |
| issue certificate before J2 anchor | `CertificateRequiresAnchoredReceipt`; `AtMostOneLiveUnanchoredMutation` | 10 |
| persist changed J3 certificate | `J3DatabaseRequiresExactCertificate` | 11 |
| persist release before J3 anchor | `ReleasedRequiresAnchoredExactJ3` | 12 |
| persist O before J3 anchor | `OutboxRequiresAnchoredJ3`; `OutboxDatabaseRequiresExactReturnedResponse`; `AtMostOneLiveUnanchoredMutation` | 12 |
| publish raw response before release | `RawObservationRequiresPersistedRelease`; `PublisherRequiresAnchoredExactOutbox` | 13 |
| return response before release persistence | `ResponseReturnRequiresPersistedRelease` | 13 |
| enqueue caller-chosen bytes | `OutboxDatabaseRequiresExactReturnedResponse` | 15 |
| persist changed D identity | `DeliveryDatabaseRequiresExactPublication` | 18 |

The exact traces are asserted in the test suite. Within this symbolic bound,
changed receipt, certificate, response, and retry identities are rejection
stutters; exact lost-ack retry preserves the retained identity; a stable sealed
or released orphan converges after restart; a crash after R and before response
return converges without selecting a second identity; and a crash with the DB
ahead of the anchor terminates fail-closed without a repair edge.

## Reproduction

Executed with CPython 3.14.6:

```bash
cd /Users/jperla/josh/spec
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v \
  test_m5_journal_vault_model.py
/opt/homebrew/anaconda3/bin/ruff check --no-cache \
  m5_journal_vault_model.py test_m5_journal_vault_model.py
/opt/homebrew/anaconda3/bin/ruff format --check --no-cache \
  m5_journal_vault_model.py test_m5_journal_vault_model.py
```

Result: **15/15 tests pass; Ruff check and format check pass.**

SHA-256 at this checkpoint:

```text
m5_journal_vault_model.py
  44a199baaae7fe1209c9ba67ec352354124f0dff284e70ca4b4798029d906aa3
test_m5_journal_vault_model.py
  48ddc1608a5d4e2cee2eddc814d526488bf72ee6580a4e815747a76a8dcd315d
```

## Interpretation

This is evidence only about symbolic retained identities and the enumerated
state projection. `db_stage` and `anchor_stage` are ordinals, not encoded rows,
roots, or proofs. The anchor-ahead and vault-checkpoint cases are injected
oracles; the model does not derive disagreement by verifying a real event
chain. Vault seal/release persistence also collapses the vault's internal
DB-commit/anchor sequence into one semantic transition. “Exact retry” means the
same symbolic identity, not byte equality or absence of recomputation in a
process.

The Rust implementation must still realize and test these relationships with
canonical bytes, authenticated SQLite projections, independent journal/vault
stores and anchors, cold restart, computation counters and nonce tombstones,
and ultimately real threshold cryptography.
