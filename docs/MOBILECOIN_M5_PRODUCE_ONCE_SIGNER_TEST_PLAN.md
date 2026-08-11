# MobileCoin M5 produce-once signer / nonce-vault protocol and test plan

## 0. Status and decision

**Design and executable-test contract; implementation pending.**

The durable Rust journal checkpoint proves that an authorized response *byte
string* can be persisted, anchored, recovered, and observed monotonically. It
does not prove that those bytes are a valid FROST/MLSAG share or that a real
nonce was used exactly once. Its public fixture method accepts arbitrary bytes.

The next M5 boundary therefore must not be an API that returns a signature
share and asks the caller to save it afterward. The required primitive is a
**sealed produce-once signer**:

> An isolated signer binds one durable nonce record to one fully authenticated
> transcript, computes and self-verifies exactly one response, retains that
> response internally, and returns only an attested opaque receipt. It releases
> the raw response only after verifying that the operation authority durably
> authorized that exact receipt for publication.

This handshake resolves the unavoidable dual-store problem between an
operation journal and an HSM. It does not require an atomic transaction across
the two systems: an interrupted phase may strand availability, but it cannot
release a share early or reuse/rebind exposed nonce material.

## 1. Threat model

The protocol must remain safe when:

- the coordinator is malicious, equivocates, reorders messages, loses replies,
  or concurrently submits conflicting signing packages;
- processes crash at any instruction boundary and either side receives an
  acknowledgement that the other side loses;
- the journal and nonce vault restart independently;
- stale backups of either store are presented;
- two otherwise valid operations race for one source event, real UTXO, child,
  nonce ID, or round-one commitment;
- a caller supplies malformed or cryptographically invalid response bytes;
- one transcript field, participant, epoch, nonce domain, commitment, challenge,
  or operation-wide authorization entry changes; and
- the transaction approaches its MobileCoin tombstone while the ceremony runs.

The protocol cannot make a deliberately compromised signer/HSM obey. A corrupt
threshold can always sign; Josh's response to that fact is the separate
consensus-mandatory attributable warden certificate, bonds, caps, pause, and
rotation. This protocol protects honest signer instances from coordinators,
crashes, rollback, and nonce-state mistakes.

## 2. Components and authority boundaries

### Operation authority

The operation authority owns source-event and UTXO uniqueness, the complete
ordered child set, the irreversible operation-wide `Authorized` transition,
and the release outbox. The single-host SQLite/file-anchor implementation is a
test fixture. Production needs a replicated linearizable/consensus authority
or a hardware-backed monotone proof every signer can authenticate.

### Nonce vault / isolated signer

The vault holds:

- long-lived DKG share material;
- nonce seeds/scalars and their public commitments;
- a globally unique nonce ID and purpose/domain for every nonce plan;
- the exact transcript to which an exposed nonce is bound;
- a sealed canonical response and its digest; and
- an attestation key registered to the participant and DKG epoch.

Secret key shares, nonce seeds/scalars, and unsealed responses never enter the
coordinator process or ordinary journal database.

### Publisher

The publisher has no signing authority. It carries an authority release
certificate to the vault, obtains only the already sealed response, and appends
it idempotently to the authenticated ceremony channel. A crash may cause an
exact retransmission, never response regeneration.

## 3. Canonical objects

All integers are fixed-width big-endian; all lists have explicit bounded counts
and canonical ordering; points/scalars use the one canonical encoding admitted
by the selected curve suite. Every decoder rejects unknown versions, unknown
domains, duplicates, trailing bytes, noncanonical points/scalars, and
oversized payloads before state mutation.

The bounded v1 spike freezes BLAKE2b-512 with the existing M5 tagged-hash
framing: each tag/value is length-framed, and every object has a distinct
domain tag. Canonical object/list lengths use `u32` big-endian counts, scalar
identities use their fixed declared widths, and all configured maxima are
checked before allocation. The production codec may change only by versioning
the object and domain tag; it may not silently inherit a generic serializer.

### 3.1 `NonceSlotIdentityV1`, `NonceComponentPlanV1`, `NoncePlanV1`, and commit idempotency

`NonceSlotIdentityV1` is a separate canonical object containing only the stable
semantic slot coordinates:

```text
protocol_version
network_id
operation_id
operation_attempt
input_spend_id
child_attempt
ceremony_id
participant_id
share_id
nonce_domain                 // row0 | row1 | proof:<type>; never caller text
```

The vault derives
`nonce_slot_key = H("mc/m5/vault-nonce-slot/v1", canonical_slot_identity)`.
Plan attributes that must not change on retry—such as algorithm revision, DKG
epoch, key package, and generator/component plan—are deliberately excluded from
the slot-key derivation. Consequently, changing one of them under the same
semantic slot reaches the existing record and returns `Conflict`; it cannot
silently allocate a second nonce under a newly derived idempotency key. A
legitimate new signing attempt has a new operation/child attempt or ceremony
identity and therefore a new slot.

`NonceComponentPlanV1` is a separate canonical object containing the exact
ordered purpose/generator components the cryptographic adapter will derive.
`component_plan_digest` is its tagged digest. Keeping it separate avoids a
self-referential “nonce plan contains its own digest” definition.

```text
protocol_version
network_id
algorithm_id                 // exact reviewed MLSAG/FROST adapter revision
nonce_domain                 // row0 | row1 | proof:<type>; never caller text
component_plan_digest        // digest of NonceComponentPlanV1
dkg_epoch
key_package_digest
registry_root
selected_participant_set_digest
participant_id
share_id
operation_id
operation_attempt
input_spend_id
child_attempt
ceremony_id
manifest_digest
round1_request_digest
```

The canonical slot identity, not the complete plan bytes, derives
`nonce_slot_key`; that stable key is the idempotency identity used to recover a
lost commit reply. `NoncePlanV1` binds the slot identity/key to the complete
plan attributes above, and the vault rejects any cross-field inconsistency.
The vault derives a random 256-bit `nonce_id` internally and identifies it globally as
`(vault_id, nonce_id)`. Uniqueness is enforced inside one vault; independent
vaults need no synchronous global registry because `vault_id` prevents aliasing.

The durable commit reply is `CommittedNonceReceiptV1`, containing the slot key,
vault/nonce IDs, plan digest, exact public commitments, vault sequence/root,
and a vault attestation. Exact commit retry returns the same receipt bytes. One
seed used to derive several internal FROST nonce components remains one
indivisible plan: exposure or consumption of any component retires all of it.

The commit call carries the exact canonical `NonceComponentPlanV1` bytes as
well as the `NoncePlanV1` bytes. The vault recomputes
`component_plan_digest`; a caller-supplied digest without its preimage is not
authority. Before returning the public commitment, the vault also verifies that
the plan's manifest, round-one request, registry root, selected participant set,
key package, participant/share, and ceremony identities agree with the
authenticated operation/ceremony context. Thus `COMMITTED` means
**round-one-transcript-bound and durably committed**, not merely “some random
nonce exists.” A changed manifest, round-one request, registry, roster, or
component plan under the same semantic slot conflicts and can never reuse the
exposed commitment.

### 3.2 `ProduceRequestCoreV1`

```text
protocol_version
network_id
operation_id
operation_attempt
source_event_id
source_record_content_envelope
reservation_core_bytes
reservation_core_digest
authorization_entry_bytes
authorization_state_version
authorization_entry_digest
authorization_proof
complete_ordered_request_core_digests

input_spend_id
child_attempt
input_ordinal
request_core_bytes
request_core_digest

unsigned_transaction_bytes_or_authenticated_content_proof
unsigned_tx_digest
bridge_action_bytes_or_authenticated_content_proof
bridge_action_digest
policy_bytes_or_authenticated_content_proof
policy_id
transaction_tombstone
minimum_release_margin_blocks

ceremony_id
manifest_bytes_or_authenticated_content_proof
manifest_digest
dkg_epoch
key_package_bytes_or_authenticated_content_proof
key_package_digest
participant_id
share_id
selected_participants
nonce_id
nonce_domain
nonce_plan_digest             // digest of exact NoncePlanV1 bytes
component_plan_digest
own_commitments
complete_ordered_signed_commitment_set
algorithm_transcript_bytes
```

Every `*_content_envelope` is a canonical tagged union of either exact inline
bytes or `(content_digest, authority_id, authenticated_lookup_proof)`. The vault
must possess and verify one form for every claimed preimage; a bare digest is
not proof. The bounded in-memory spike uses explicit mock authenticators and
must label that boundary.

The vault parses canonical bytes and recomputes every available digest, participant
binding factor, interpolation coefficient, generator, commitment, challenge,
and expected verification share. A coordinator-supplied digest or challenge is
never authoritative. The authorization proof must bind the *complete* ordered
request vector, not merely this child.

### 3.3 `SealedResponseReceiptV1`

```text
protocol_version
vault_id
response_handle
produce_request_digest
operation_id
operation_attempt
authorization_entry_digest
input_spend_id
child_attempt
request_core_digest
dkg_epoch
participant_id
share_id
nonce_id
nonce_domain
nonce_plan_digest
component_plan_digest
commitments_digest
canonical_response_digest
vault_monotone_sequence
vault_state_root
vault_attestation_signature
```

The receipt contains no response scalar. Define
`receipt_core_digest = H("mc/m5/vault-receipt-core/v1", canonical_receipt_core)`;
the vault attestation signs that digest. Define the exact persisted receipt
identity as `H("mc/m5/vault-receipt/v1", canonical_core, attestation_bytes)`.
The attestation asserts that the configured vault self-verified the
sealed response equations. The operation authority cannot independently verify
hidden response bytes. This is not consensus-level proof that a hardware vendor
or deliberately corrupt vault is trustworthy.

### 3.4 `ResponseReleaseCertificateV1`

```text
protocol_version
message_id
sealed_response_receipt_digest
canonical_response_digest
operation_authority_sequence
operation_authority_state_root
operation_authority_proof_or_quorum_signature
minimum_valid_block_height
maximum_valid_block_height
response_retention_height
```

Define `response_digest = H("mc/m5/vault-response/v1", canonical_response)` and
`certificate_core_digest = H("mc/m5/release-certificate-core/v1",
canonical_certificate_core)`. The operation authority signs and durably stores
the exact certificate before returning it; the full certificate identity also
commits to the signature/proof bytes. Alternate valid proof/quorum encodings are
conflicts in v1. This costs liveness but makes exact retry unambiguous.

The certificate proves that the operation authority consumed the exact child
and anchored the exact sealed receipt. The historical checkpoint proof must
match its claimed sequence/root and remain at or above the vault's pinned
monotone floor; it need not equal the authority's latest head after unrelated
activity. It is the only object that enables raw-response release.

## 4. State machines

### 4.1 Vault state

```text
Absent
  -> COMMITTED(round1_bound_plan, nonce_id, sealed_nonce, commitments)
  -> BOUND(produce_request_digest)        // exact round-two request lock
  -> SEALED(response_handle, response_bytes, response_digest)
  -> RELEASED(release_certificate_digest)
  -> ARCHIVED(response_digest, receipt_digest, certificate_digest)
```

Additional safe terminal path:

```text
COMMITTED | BOUND -> RETIRED_WITHOUT_RESPONSE
```

Rules:

1. `COMMITTED` is durable before any round-one commitment leaves the vault and
   binds the exact authenticated manifest, round-one request, registry/roster,
   participant/share, component plan, and ceremony identity.
2. No state at or after `COMMITTED` can return to `Absent` or become available
   to another transcript, even if no acknowledgement was received.
3. `BOUND` names exactly one request digest. Exact retry is allowed; any changed
   request conflicts.
4. Response generation is deterministic from the retained request, key share,
   and nonce plan. Auxiliary proof randomness is itself part of the same
   one-shot plan and never comes from an untracked RNG call.
5. The vault self-verifies all participant response equations before sealing.
   Invalid output transitions to durable
   `RETIRED_WITHOUT_RESPONSE(SelfVerificationFailed)` without returning a
   receipt or response.
6. `SEALED` durably retains exact canonical response bytes before returning the
   receipt. Secret nonce material is then erased or cryptographically retired;
   its tombstone remains.
7. `RELEASED` occurs before returning response bytes. Exact release retry
   returns the retained identical bytes; it never recomputes them.
8. A response remains recoverable through `response_retention_height`.
   `ARCHIVED` afterwards is a typed permanent result and retains nonce/receipt,
   response, and certificate digests plus the nonce tombstone. It never revives
   the nonce or promises plaintext recovery after the declared horizon.

### 4.2 Operation-journal child state

```text
BOUND(request_core_digest)
  -> SEALED_RECEIPT_PERSISTED(receipt_digest, response_digest)
  -> RELEASE_AUTHORIZED(release_certificate_digest)
  -> DELIVERED
```

The fixture `emit_round2(permit, arbitrary_bytes)` is removed from the
production surface. Only a canonically decoded, vault-attested receipt for the
exact permit can consume the child. Invalid receipt bytes leave the child
`BOUND`.

## 5. Protocol sequence and crash outcomes

### Phase A — nonce creation and round one

1. The signer validates the accepted operation/child, exact manifest and
   round-one request, registry/selected set, key package, component-plan bytes,
   and calls `vault.commit_nonce(component_plan, plan, authenticated_context)`.
2. The vault recomputes every binding and atomically generates and stores the
   secret nonce plan, commitments, nonce ID, state root, and round-one-bound
   `COMMITTED` state.
3. Only after durable commit does it return the public commitment message.

A crash before step 2 exposes nothing and creates no slot. A crash after step 2
but before step 3 causes exact commitment recovery. Loss/abort after commitment
exposure retires the slot permanently.

### Phase B — bind and seal

1. After the operation-wide journal CAS reaches `Authorized`, the caller sends
   the full `ProduceRequestCoreV1`.
2. The vault verifies canonical content, complete authorization proof,
   liveness margin, exact own commitments, roster/epoch/share, transcript, and
   request digest.
3. It durably binds the nonce ID to that digest before response generation can
   have an externally visible effect.
4. It generates, self-verifies, seals, and durably stores the exact response,
   erases/retires nonce secrets, then returns only the receipt.

A crash after bind but before seal may resume only the identical retained
request. The bounded v1 spike requires deterministic exact resume and records a
response-computation counter. A production HSM incapable of that guarantee may
instead enter `RETIRED_WITHOUT_RESPONSE`, but must advertise that availability
semantics explicitly. A crash after seal but before receipt return recovers the
identical receipt without recomputation.

### Phase C — persist receipt and authorize release

1. The journal verifies the vault registration/attestation and every receipt
   binding against the exact `ResponsePermit`.
2. One transaction consumes the child and persists the receipt/handle/digest
   outbox record; the operation authority advances its monotone anchor.
3. Only the anchored authority state durably creates and then returns an exact
   `ResponseReleaseCertificateV1`. V1 issuance is per child after the one
   operation-wide authorization already bound every child request; it need not
   wait for every sibling sealed receipt.

A DB commit without anchor advancement fails closed. An orphan sealed vault
response is safe: it has no release certificate.

Bounded v1 deliberately defines **no recovery transition** for any database /
monotone-anchor disagreement. This includes both database-ahead-of-anchor and
anchor-ahead-of-database states on either the nonce-vault side or the
operation-authority side. Open, mutation, certificate issuance, and release all
fail closed. An operator must never repair the mismatch by copying either
database head into an anchor, copying one store's head/root into the other
store's anchor, choosing the numerically greater head, or otherwise treating an
unauthenticated local value as authority.

Production recovery remains out of scope until it defines a concrete,
versioned authenticated recovery record and a deterministic selection rule.
The record must name the store/authority identity, the observed database and
anchor heads, the authenticated predecessor and proposed unique successor, the
quorum/hardware/consensus evidence authorizing that successor, and a monotone
recovery sequence. The selection rule must admit exactly one authorized
successor and reject missing, ambiguous, stale, or conflicting evidence. Until
that record, rule, implementation, and adversarial tests exist, the only safe v1
outcome is permanent fail-closed unavailability for the mismatched instance.

### Phase D — release and publish

1. On the first release, the vault authenticates the release certificate,
   checks the exact sealed record/digests and the inclusive
   `[minimum_valid_block_height, maximum_valid_block_height]` interval, then
   durably marks `RELEASED`.
2. It returns the retained canonical response bytes.
3. The publisher validates the response again and appends it once to the
   authenticated ceremony sink; delivery marking is recoverable. If a validly
   attested but invalid response emerges, it is attributable signer/vault
   evidence and an availability failure, not an excuse to create another
   response from the retired nonce.

A crash after `RELEASED` but before return or after return but before sink
acknowledgement causes only byte-identical retransmission. Once legitimately
released, exact replay remains allowed through `response_retention_height`
even if the first-release window later closes; after archival it returns the
typed `Archived` result rather than recomputing.

### 5.1 Safety argument and explicit assumptions

Let the following durable or observable events use one exact nonce slot,
request, response, receipt, and certificate identity:

```text
C  vault commits a non-revivable nonce plan
K  its public commitment becomes observable
B  vault durably binds the plan to one ProduceRequest digest
S  vault durably seals the self-verified response and retires nonce secrets
R  sealed receipt becomes observable
J  operation authority durably persists that exact receipt
A  operation authority anchors the unique successor containing J
X  exact release certificate for A and R becomes observable
L  vault durably records RELEASED for X
O  raw response becomes observable
```

The protocol requires these happens-before edges:

```text
C -> K
B -> S -> R
J -> A -> X
(S and X) -> L -> O
```

It follows mechanically that `O` implies both `S` and `A`: the only raw-byte
API is release; release requires a valid certificate `X`; and `X` authenticates
the anchored successor `A` containing the exact receipt persisted at `J`.
Likewise, `R` implies `S`, so a receipt cannot name bytes that an honest vault
has not already retained. There is no required atomic transaction between the
vault and operation authority. A crash can stop between any two edges and
strand progress, but it cannot create a path to `O` that bypasses `S` or `A`.

The at-most-one-response argument is separate. The stable nonce-slot key has
one linearizable record; `COMMITTED -> BOUND` is a compare-and-swap over the
exact request digest; no later state transitions backwards; and `SEALED`
contains the only response bytes ever returned for that slot. Exact retries
read the existing record. Changed retries conflict. Thus one honest,
non-rollbackable vault record cannot answer two distinct request digests.

This is a conditional safety argument, not a proof about arbitrary hardware.
It assumes: linearizable durable transitions inside each authority; sound and
unforgeable vault/operation-authority authentication; correct canonical
decoding and digest binding; no secret-export or side-channel interface;
anti-rollback enforcement for the vault record and authority checkpoint; and
an honest response producer/self-verifier. The executable in-memory model can
test transition order, binding, retry, and concurrency. It cannot establish
durability, unforgeability, side-channel resistance, or hardware anti-rollback.

## 6. Success conditions

The gate passes only if all executed backends prove every condition below:

1. No commitment is observable before its nonce plan is durably non-revivable.
2. No nonce ID/seed/component can bind to two distinct transcripts, rows,
   inputs, proof purposes, participants, shares, or epochs.
3. No raw response is observable before the exact response is sealed and its
   attested receipt is durably authorized by the operation authority.
4. Exact retry after any lost acknowledgement returns identical commitments,
   receipt, handle, response digest, and response bytes.
5. A changed request, challenge, binding factor, roster, transaction, policy,
   authorization entry, participant/share, epoch, domain, or commitment
   conflicts before response release.
6. Invalid or noncanonical receipt bytes do not consume the journal child. An
   honest vault never issues a receipt for an internally invalid response. A
   Byzantine vault can attest garbage; that case must be attributable and fail
   final share validation, but cannot be cryptographically prevented by the
   journal while the response remains sealed.
7. A checkpoint proof that does not match its claimed historical root/sequence,
   or falls below a pinned monotone floor, fails closed. Vault and journal roots
   are different state machines and are never required to equal each other.
8. Restore of either stale backup cannot revive an exposed nonce or release an
   unanchored response.
9. Near-tombstone requests lacking the conservative release margin are rejected
   before binding a fresh nonce.
10. Every accepted response independently verifies against the exact registered
    verification share, commitments, transcript, and operation-wide request.

## 7. Immediate failure conditions

The gate fails if any test can:

- receive a raw response before receipt persistence and authority anchoring;
- make one effective nonce answer two challenges;
- obtain three responses from one reused two-nonce FROST preprocessing pair;
- regenerate a response after losing its acknowledgement rather than recover
  the retained exact bytes;
- bind one nonce plan across row 0, row 1, or an auxiliary proof domain;
- consume a child using arbitrary caller bytes or an invalid vault attestation;
- omit another input's request core from the operation-wide authorization;
- continue after the vault and operation authority disagree about sequence,
  state root, handle, response digest, or nonce identity;
- let an abort, process restart, backup restore, DKG refresh, roster rotation,
  or database repair make an exposed nonce available; or
- count a clean exception while leaving a partial state mutation as a passing
  race test.

## 8. Executable adversarial matrix

### 8.1 Canonical and binding tests

- Cross-language vectors for every object and digest.
- Mutate every field independently; the proper digest changes and the old
  signature/proof fails.
- Reject all strict prefixes, all one-byte suffixes, unknown versions/domains,
  duplicate/unsorted participant lists, noncanonical scalars/points, and
  asymmetric encoder/decoder size limits.
- Prove the vault recomputes binding factors, challenges, interpolation, and
  response verification from exact bytes rather than trusting supplied values.

### 8.2 Nonce extraction witnesses

Run `python3 spec/frost_nonce_reuse_witness.py --selftest`.

The executable witness distinguishes two cases for
`s_i = d + rho_i*e - p_i*x`:

- two responses recover `x` when the same effective nonce
  `r = d + rho*e` answers two challenges; and
- three nondegenerate responses recover `e` and `x` when one `(d,e)` pair is
  reused with transcript-dependent `rho_i` values.

It also demonstrates that two generic changing-`rho` responses alone leave one
scalar degree of freedom; public commitments bind the actual opening but do not
reveal its scalar without solving discrete logarithms. Tests must use the
precise case rather than repeating the overbroad two-response slogan.

### 8.3 Crash/fault points

Use subprocess death (`SIGKILL`/`_exit`) and filesystem fault injection, not
only clean Rust unwinding, before and after:

1. nonce secret write;
2. nonce-state commit/fsync/monotone-anchor advance;
3. commitment return;
4. request-binding commit;
5. response computation;
6. sealed-response write and nonce erasure;
7. receipt return;
8. journal receipt/outbox commit;
9. operation-authority anchor advancement;
10. release-certificate creation;
11. vault `RELEASED` commit;
12. raw-response return;
13. external sink append; and
14. delivery marker.

After every recovery, assert either exact progress or safe permanent
unavailability; never infer success merely from an error.

### 8.4 Concurrency and equivocation

- 16-way exact retry returns one receipt/response identity.
- 16 changed requests racing for one nonce admit exactly one binding; every
  loser conflicts without raw output.
- Race exact retry against journal commit/anchor and vault release.
- Race two operation IDs sharing a source/UTXO, two child attempts, two DKG
  epochs, and two nonce domains.
- Run with distinct client objects/processes and path aliases; process-local
  locks alone are not accepted as production evidence.

### 8.5 Rollback and replica disagreement

- Restore every older vault snapshot against current journal state and every
  older journal snapshot against current vault state.
- Delete/tamper each lifecycle event, nonce tombstone, sealed response,
  receipt, release certificate, outbox record, and materialized projection.
- Exercise DB-ahead-of-anchor and anchor-ahead-of-DB states independently on
  both sides; bounded v1 has no recovery transition and must fail closed.
- Treat “set anchor to either database head,” “copy one store's root into the
  other anchor,” and “select the larger head” as failing mutants. A future
  production repair path is conforming only after the concrete authenticated
  recovery record and deterministic unique-successor rule in Phase C are
  specified and tested.

### 8.6 Cryptographic integration

The orchestration model may start with a deterministic mock signer only if its
results are labeled state-machine evidence. The cryptographic gate additionally
must:

- wrap the pinned Serai modular-FROST `AlgorithmMachine` and MobileCoin MLSAG
  adapter without exposing `CachedPreprocess` or nonce scalars outside the
  vault;
- test every qualifying subset and every real ring index used by M2/M4;
- verify each returned row/share equation before sealing;
- prove stable key images and stock MobileCoin verifier acceptance; and
- run an instrumented guard showing no complete root/one-time key, nonce seed,
  or unsealed response crosses the vault API.

The negative producer test injects an invalid internal response into the honest
vault implementation and requires it to retire the nonce without issuing a
receipt. A separate Byzantine-vault test signs a receipt for invalid hidden
bytes and requires later validation to produce exact attributable evidence; it
must not claim that the operation journal could inspect sealed plaintext.

### 8.7 Bounded v1 acceptance checklist (38 named tests)

These are required test names and behaviors for the implementation gate. Their
presence here is a test contract only; the signer/vault implementation is still
pending, and this plan does not claim that any of these tests currently pass.

Canonical codec and binding (7):

1. `codec_v1_golden_vectors_are_frozen`
2. `codec_decode_reencode_is_byte_identical`
3. `codec_rejects_noncanonical_matrix_before_mutation`
4. `codec_rejects_ordering_duplicates_and_bounds`
5. `codec_field_mutation_rebinds_digest_and_invalidates_auth`
6. `codec_recomputes_nested_content_digests`
7. `codec_domains_and_variant_tags_are_noninterchangeable`

Vault lifecycle (11):

8. `commit_is_durable_before_commitment_observable`
9. `commit_exact_retry_after_restart_returns_same_slot`
10. `commit_same_slot_changed_plan_conflicts`
11. `nonce_id_and_response_handle_collision_never_alias`
12. `bind_exact_retry_is_noop_and_changed_request_conflicts`
13. `bind_validation_matrix_is_side_effect_free`
14. `seal_is_atomic_before_receipt_observable`
15. `seal_retry_returns_stored_receipt_without_recompute`
16. `internal_verification_failure_retires_without_output`
17. `nonce_plan_is_indivisible_across_components_and_domains`
18. `public_api_exposes_only_opaque_receipt_until_release`

Journal, certificate, and release (12):

19. `journal_persists_exact_receipt_once`
20. `journal_exact_receipt_retry_is_idempotent`
21. `journal_receipt_mutation_matrix_is_side_effect_free`
22. `journal_rejects_wrong_registration_permit_and_authorization`
23. `journal_conflicting_receipts_consume_child_at_most_once`
24. `certificate_requires_receipt_commit_and_authority_anchor`
25. `cross_store_checkpoint_disagreement_fails_closed`
26. `release_commits_before_raw_response_observable`
27. `release_exact_retry_returns_stored_bytes_without_recompute`
28. `release_certificate_mutation_replay_and_height_matrix_is_side_effect_free`
29. `publisher_append_once_and_delivery_recovery_are_idempotent`
30. `byzantine_vault_invalid_hidden_response_yields_evidence_only`

Crash boundaries (4):

31. `crash_matrix_phase_a_never_exposes_uncommitted_commitment`
32. `crash_matrix_phase_b_never_exposes_unsealed_response`
33. `crash_matrix_phase_c_never_issues_unanchored_certificate`
34. `crash_matrix_phase_d_only_replays_identical_bytes`

Concurrency and rollback (4):

35. `race_16_exact_calls_collapse_to_one_identity`
36. `race_16_changed_requests_admits_one_binding`
37. `race_retire_bind_seal_and_conflicting_receipts_is_monotone`
38. `rollback_tamper_and_multi_client_matrix_fails_closed`

## 9. Library decision gate

The implementation must pin one reviewed baseline. The selection criteria are:

1. support for a custom multi-generator MLSAG/CLSAG `Algorithm`, not only
   standard Schnorr FROST;
2. compatibility with MobileCoin's Rust 1.83 baseline and Ristretto/dalek graph;
3. explicit access to canonical commitments/shares needed by the evidence
   verifier;
4. no unavoidable preprocessing cache outside sealed storage; and
5. an auditable nonce lifecycle that this protocol can wrap without copying
   secret material into the host.

The provisional implementation decision is:

- use Serai `modular-frost` 0.10.1 at repository revision
  `4b89cf0206184886e96d0663861596312e5b47d2` as the signer-state-machine
  baseline, while retaining its pinned Monero-oxide reference revision
  `32e6b5fe5ba9e1ea3e68da882550005122a11d22` for the pattern comparison;
- port the CLSAG `Algorithm` pattern into a MobileCoin two-row MLSAG adapter
  over the already demonstrated shared dalek/Ristretto graph; and
- retain Zcash FROST revision `0966bd1529aa062ad3b621af99e277f976b1c0f0`
  as an independent standard-FROST and serialization reference, not as the
  first MLSAG adapter dependency.

The reasons are source-visible. Serai's `Algorithm` trait explicitly permits a
custom ordered list of nonce generators and custom `sign_share`, `verify`, and
`verify_share` equations (`repos/serai/crypto/frost/src/algorithm.rs:28-94`).
Its cached preprocess type warns that reuse or disclosure recovers the private
share (`repos/serai/crypto/frost/src/sign.rs:83-92,209-224`). The Monero CLSAG
adapter uses one nonce represented against both the base generator and key-image
generator (`repos/monero-oxide/monero-oxide/ringct/clsag/src/multisig.rs:197-200`)
and verifies both response equations (`:367-425`). Serai 0.10.1 declares Rust
1.80, compatible with MobileCoin's 1.83 baseline.

The checked Zcash FROST tree is version 3.0.0 and declares Rust 1.86
(`repos/zcash-frost/Cargo.toml:16-26`), so adding it directly to MobileCoin's
1.83 graph would raise the minimum toolchain. Its Ristretto implementation is a
standard Schnorr FROST suite rather than the custom MLSAG algorithm Josh needs.
It remains useful because `SigningNonces` explicitly models hiding/binding
nonces, zeroizes on drop, warns that reuse leaks the long-lived key, and exposes
serialization that our design would have to place inside authenticated sealed
storage (`repos/zcash-frost/frost-core/src/round1.rs:209-296`).

This is a baseline decision, not a cryptographic approval. The exact dependency
snapshot, custom adapter, vault wrapper, and codec still require implementation,
differential tests, review, and frozen hashes.

## 10. Non-claims

Passing a local mock vault will not prove HSM firmware, power-loss behavior,
remote attestation, distributed operation-authority safety, production
availability, authenticated finality/non-inclusion, bonded penalty collection,
MobileCoin consensus enforcement, or the USDC -> eUSD -> USDC product cycle.

After this M5 signer gate passes with the real cryptographic adapter, M6 can
use it to construct the new transaction format whose consensus rules require
the compact threshold gate, signer-attributable bonded warden certificate, and
source-event nullifier together.
