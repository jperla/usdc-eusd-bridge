# `ceremony`

The threshold signing ceremony state machine for the MobileCoin side of the
bridge. It sequences rounds against an abstract authorisation backend
(`authorizer::Authorizer`), so it can be exercised end to end without a real
signer -- which matters, because the real signer is an HSM plus a quorum of
people.

```
begin ---------> CollectingRoundOne ---------> CollectingRoundTwo ---------> Complete
   |  reserve slot      |  bind slot to           |  verify each share          |
   |  (durable)         |  the full context       |  on arrival                 |
   |                    |  (durable)              |                             |
   +--> SubThreshold    +--> OneTimeValueReuse    +--> Aborted(culprit)         +--> UnattributableAggregateFailure
                        +--> Rollback  =>  Failed (terminal)
```

## The four properties, and the tests that kill them

Each guard was checked by deleting it and confirming the named test fails.

| Property | Guard | Test that fails without it |
| --- | --- | --- |
| 1. One-time values never reused | `MemoryStore::bind` refuses a second context | `one_time_values::the_machine_refuses_to_bind_one_one_time_value_to_two_contexts` |
| 1. Key is the FULL context | length-prefixed `SigningContext::encode` | `context_encoding::{the_statement_subset_boundary,commitment_boundaries}_cannot_be_shifted` |
| 2. Durable before observable | store write precedes the backend call | `rollback::every_durable_write_precedes_the_observable_step_it_protects` |
| 2. Anti-rollback (rewind) | `MemoryAnchor::observe` rejects a rewound sequence | `rollback::a_rolled_back_store_makes_the_signer_fail_closed` |
| 2. Anti-rollback (fork) | `MemoryAnchor::commit` compare-and-swaps the record-chain head | `rollback::{a_rollback_the_counter_has_caught_up_with_is_still_refused, a_divergent_record_at_the_same_sequence_is_refused}` |
| 2. Torn records | `RecordLog::check` refuses a record the write-ahead log did not log | `rollback::a_torn_record_is_refused_rather_than_rebound` |
| 2. No share without a durable write | `Receipt` has no constructor outside `store` | the `compile_fail` doctests on `store::Receipt`, and `capability.rs` |
| 2. Fail closed | `Ceremony::fail` makes `State::Failed` terminal | `one_time_values::the_machine_refuses_to_bind_one_one_time_value_to_two_contexts` |
| 3. Identifiable abort | identity-signature checks + per-share verification | `identifiable_abort::{an_invalid_share_is_attributed_to_its_sender, a_round_message_signed_by_the_wrong_identity_key_is_refused, evidence_with_an_unauthenticated_round_one_message_is_rejected}` |
| 3. Only a fault accuses | `Rejection::Fault` vs `Rejection::Error` | `identifiable_abort::{a_backend_outage_accuses_no_one, a_checker_that_cannot_check_does_not_convict}` |
| 4. Sub-threshold cannot complete | `subset.len() < threshold` in `begin` | `threshold::a_sub_threshold_subset_is_refused_before_any_one_time_value_exists` |
| Per-seat identity configuration | reject duplicate/zero participant ids, duplicate identity keys, and a local key that differs from its roster entry before round one | `roster_identity.rs` |

Each of the four configuration guards was disabled individually in an isolated
checkout. Each mutation failed exactly its corresponding test in
`roster_identity.rs`, while the other three passed; the unmodified and restored
controls passed all four. Without the local identity check, a separate witness
completed a one-seat ceremony even though both of its identity signatures
failed against the roster's key. The guard now refuses before a nonce exists.
Moving that guard after the backend's round-one call also fails the regression:
an instrumented real signer counts nonce allocations, with an honest control
that demonstrates the counter increments.

Two tests carry the weight of the whole file set, because they show the guards
are not bookkeeping:

* `one_time_values::three_responses_under_one_one_time_value_recover_the_long_term_share`
  runs the attack to the end -- three responses under one one-time value, three
  linear equations, the participant's long-term share recovered by Cramer's rule
  and compared against the dealer's value.
* `identifiable_abort::a_quorum_can_forge_a_valid_signature_with_no_ceremony_at_all`
  reconstructs the group secret from a quorum's shares and emits a signature
  that verifies, which is why attribution cannot rest on the transcript.

`identity_kat.rs` pins the identity primitive to RFC 8032 section 7.1 TEST 1 and
TEST 2, so the roster's seed -> public-key derivation is the standard Ed25519
one.

## Running the tests

```
cargo test --offline -p ceremony
```

Run `./scripts/setup.sh` from the checkout root first so the vendored sources
and locked dependencies are present. `--offline` deliberately fails if a
required package is not already cached; such a failure is not a test result.

## What this crate does NOT establish

* **Composite two-cohort authorisation.** The machine enforces one roster and
  one threshold. The bridge's release rule is (k-of-n operators) AND (g-of-m
  gates); composing the two is `crates/two-cohort`'s and the backend's business.
  Passing this machine's threshold check is not evidence that the gate cohort
  participated.
* **Rollback detection beyond the anchor.** A store cannot detect its own
  rewind; `Anchor` is the seam for something that did not rewind with it. The
  anchor holds a chained digest and advances by compare-and-swap, so a fork at
  the same sequence is caught -- but the in-memory anchor used by the tests
  starts empty, so a process restart combined with an equally old store snapshot
  is invisible to it. Production needs a hardware monotonic counter or an
  append-only log elsewhere, and this crate does not verify that one exists.
* **Recovery from a detected fork or tear.** Both fail closed, permanently. A
  crash between the store's commit and the anchor's compare-and-swap is
  recoverable only by re-presenting the receipt for the last durable write; the
  reconstitution of a receipt from persisted bytes is a production store's
  problem and `MemoryStore` does not model it.
* **The reference backend against a published vector.** `frost` is FROST-shaped
  but not RFC 9591's ciphersuite (Blake2b, Ristretto, this crate's own
  transcript encoding), so no known-answer vector applies to it. Its algebra is
  tested; its interoperability is not claimed. It is also a trusted-dealer
  sharing with no DKG, no proof of possession and no rogue-key defence.
* **Concurrent sessions.** One machine runs one ceremony. Several concurrent
  ceremonies against one store are safe by construction (distinct slots) but are
  not tested, and the ROS/Wagner line of attack on concurrent threshold Schnorr
  sessions has not been analysed here.
* **Liveness.** There are no timeouts and no transport. A coordinator that
  withholds messages stalls the ceremony; the machine fails closed by design and
  makes no attempt to make progress without a full subset.
* **Identity key management.** Rotation, revocation and the consequences of an
  identity key compromise (attribution silently fails) are out of scope.
