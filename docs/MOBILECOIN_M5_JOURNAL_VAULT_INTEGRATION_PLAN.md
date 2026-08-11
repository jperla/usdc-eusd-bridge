# M5 durable journal / sealed vault integration plan

## Status

**Design and falsifiable implementation contract; not executed code.**

This is the smallest next slice that can remove
`OperationJournal::emit_round2(permit, arbitrary_bytes)` without pretending to
solve the full distributed signer. It integrates one authorized child, one
single-input Row-0 nonce domain, deterministic mock cryptography, a refactored
schema-v2 journal, and a new reopenable vault-v2 fixture.

The slice succeeds only when the public journal path cannot consume
caller-supplied response bytes and crash/restart at every observation boundary
recovers one exact safe result—retained response identity, typed retirement, or
declared fail-closed mismatch—without nonce regeneration or rebinding.

It does not implement Row 1, proof-worker nonces, real Ristretto/FROST/MLSAG,
an HSM, replication, source-chain finality, or MobileCoin consensus.

## 1. Dependency and trust-boundary layout

Do not create a journal/vault dependency cycle and do not mutate the frozen M5
checkpoint crates in place. Introduce:

```text
m5-rust-produce-once-types-spike
    canonical wire objects; no SQLite, vault, or transport

m5-rust-durable-io-spike
    AnchorRecord, MonotoneAnchor, FileAnchor, append-once sink interfaces

m5-rust-journal-vault-integration-spike
    schema-v2 journal + durable vault-v2 + integration adapter
    + deterministic fixture authorities
       |-> m5-rust-produce-once-types-spike
       |-> m5-rust-durable-io-spike
```

The existing journal and signer-vault remain immutable comparison oracles.
Their state traces should be replayed in differential tests where the v2 path
has an equivalent prefix. Their current public/private boundaries cannot be
composed into this protocol: journal mutation/schema internals and the vault's
general authority/producer interfaces are crate-private. V2 therefore refactors
the reviewed algorithms into new `JournalV2` and `VaultV2` implementations; it
does not claim that an external adapter can extend the frozen objects.

The vault must never own an `OperationJournal` or a `rusqlite::Connection`.
It does own an independent durable `VaultStoreV2` fixture plus a distinct
monotone vault anchor. The integration adapter supplies authenticated,
read-only operation-authority checkpoints; the vault verifies their proofs and
its own retained receipt identity. Destroying and reconstructing both journal
and vault objects from their separate stores is mandatory in restart tests;
retaining the same `Arc<Mutex<...>>` is not restart evidence.

## 2. Canonical protocol objects

Move and version the current signer-vault objects in the neutral types crate:

- `NonceDomainV1`;
- `NonceSlotIdentityV1`;
- `NonceComponentPlanV1`;
- `NoncePlanV1`;
- `Round1CommitRequestCoreV1`;
- `NonceCommitStatementV1`;
- `CommittedNonceReceiptV1` (renamed from `CommitmentReceiptV1`);
- `AnchoredCommittedNonceReceiptV1`;
- `ProduceRequestStatementV1`;
- `ProduceRequestCoreV1`;
- `SealedResponseReceiptV1`;
- `AnchoredSealedResponseReceiptV1`;
- `ResponseReleaseCertificateV1`;
- `ReleaseAuthorizationV1`;
- `CanonicalResponseV1`;
- `VaultRegistrationStatementV1`;
- `VaultRegistrationV1`;
- `VaultRevocationV1`;
- `HistoricalCheckpointProofV1`;
- `AuthenticatedLedgerHeightV1`; and
- `ReleaseWindowV1`.

Every object has a distinct domain-separated digest, canonical bounded encoding,
decode/re-encode equality, and no map/set representation whose ordering depends
on a host language.

`CommittedNonceReceiptV1` explicitly binds
`network_and_genesis_id`, `vault_id`, `vault_store_id`,
`vault_registration_digest`, `nonce_commit_statement_digest`, slot/nonce IDs,
exact plan/component digests, commitment bytes, and the prior anchored
vault-commit **semantic-core** checkpoint. `SealedResponseReceiptV1` similarly
propagates the registration/commit-statement digests and names the prior sealed
semantic-core checkpoint. Neither receipt is allowed to name a root whose
event/projection already contains that exact receipt.

After constructing and signing each receipt, the vault performs a second
mutation that persists/anchors the exact receipt bytes/digest. The corresponding
`AnchoredCommittedNonceReceiptV1` or `AnchoredSealedResponseReceiptV1` wrapper
carries that later checkpoint proof. Journal APIs accept the anchored wrapper,
not the bare receipt. The wrapper proof remains external to the receipt/event it
proves, avoiding `receipt -> root -> event containing receipt`.

Conceptual additions:

```text
VaultRegistrationStatementV1 {
    version,
    network_and_genesis_id,
    vault_id,
    vault_store_id,
    checkpoint_verifier_id,
    attestation_scheme,
    attestation_verifier,
    dkg_epoch,
    key_package_digest,
    participant_id,
    share_id,
    activation_height,
    expiry_height
}

VaultRegistrationV1 {
    statement,
    registry_authority_id,
    registry_authority_proof
}

VaultRevocationV1 {
    registration_digest,
    revocation_sequence,
    effective_height,
    reason_code,
    registry_authority_id,
    registry_authority_proof
}

HistoricalCheckpointProofV1 {
    protocol_version,
    network_and_genesis_id,
    authority_id,
    store_id,
    schema_version,
    state_projection_version,
    sequence,
    prior_event_chain_head,
    event_chain_head,
    event_kind,
    exact_object_digest,
    state_projection_digest,
    checkpoint_proof
}

AuthenticatedLedgerHeightV1 {
    network_and_genesis_id,
    finalized_height,
    view_sequence,
    view_root,
    authority_id,
    proof
}

ReleaseWindowV1 {
    minimum_valid_block_height,
    maximum_valid_block_height,
    response_retention_height
}
```

`Round1CommitRequestCoreV1` is a pre-commit object. It may bind operation,
ceremony, registry, roster, algorithm, key package, policy, manifest, and
component plan, but it **excludes** nonce ID, own commitments,
committed-receipt/nonce-plan digests, and any value derived from them. This
prevents the fixed point `round1 request -> plan -> commitment -> round1
request`.

The operation-journal and vault constructors receive configured registry and
ledger-height authenticators. Registration/revocation proofs are not
self-authenticating fields. Every liveness, activation, expiry, tombstone, and
release-window check consumes an authenticated height view and pins its network
and genesis identity.

The production commit/request contracts must carry bounded authenticated
preimages, not only unresolvable digests:

```text
source_record_content_envelope
reservation_core_bytes
authorization_entry_bytes
operation_authority_id
authorization_checkpoint
nonce_component_plan_bytes
nonce_plan_bytes
policy_content_envelope
manifest_content_envelope
key_package_content_envelope
registry_membership_content_envelope
selected_participant_set_bytes
round1_request_content_envelope
unsigned_transaction_content_envelope
bridge_action_content_envelope
complete_ordered_signed_commitment_set
algorithm_transcript_bytes
```

It also retains the pre-commit binding fields already implemented:
`registry_root`, `selected_participant_set_digest`, `manifest_digest`, and
`round1_request_digest`.

Those fields cannot first become authoritative in the later round-two request:
the public commitment already exists by then. Before commitment exposure, the
journal constructs and anchors an exact `NonceCommitStatementV1` containing the
slot identity, component plan, nonce plan, vault registration, and authenticated
manifest/round-one/registry/roster/key-package/ceremony context. `VaultV2`
recomputes every digest from those exact preimages and verifies the returned
authority checkpoint proof before committing nonce material.

Round-two authorization uses a non-circular statement/proof split. The existing
operation-wide authorization entry commits the complete ordered
`ProduceRequestStatementV1` digest vector. `ProduceRequestCoreV1` carries one
exact statement plus a proof against that **prior operation-authorization
checkpoint**. It does not contain the state root produced by persisting itself.
The journal constructs and persists the final request wrapper after the
operation-wide CAS. The vault never treats a coordinator-assembled digest,
challenge, binding factor, commitment-set digest, transcript, or proof as
authoritative; it parses the exact signed commitment list and algorithm
transcript and recomputes all derived values supported by this Row-0 adapter.

Opaque capability wrappers have private fields:

```rust
pub struct PreparedNonceCommit { /* exact plans/context + anchored proof */ }
pub struct ResponsePermitV2 { /* statement digest + J0 historical proof */ }
pub struct PreparedProduceRequest { /* exact request + J1 persistence proof */ }
pub struct PersistedSealedReceipt { /* exact receipt + anchored checkpoint */ }
pub struct ReleaseAuthorization { /* certificate + J3 persistence checkpoint */ }
pub struct ReleasedResponse { /* private fields; minted only by VaultV2::release */ }
```

`ResponsePermitV2` replaces the under-bound frozen v1 permit and is the only
capability from operation-wide authorization into request preparation.

`CanonicalResponseV1` defines bytes and one canonical digest domain,
`mc/m5/vault-response/v1`; it is not itself an authorization capability.
Receipt, release certificate, outbox, and publisher all compare that exact
digest. The older journal domain `mc/m5/persisted-round2-response/v1` is not
used in v2. A frozen golden vector must prove cross-module equality. The
append-once sink may additionally hash its observation record under a separate
domain, but that digest cannot replace the canonical response digest.
Golden vectors and field-mutation matrices include vault store/checkpoint
verifier IDs, registry/operation/ledger authority IDs, schema and state-
projection versions, historical event kinds, and network/genesis identity.

## 3. Schema v2

Bump the journal schema version. Refuse to open a v1 database as v2; this spike
uses a fresh database and leaves the frozen v1 result reproducible. Add all new
tables to the authenticated global-state projection.

### `vault_registrations`

```text
registration_digest       BLOB(64) PRIMARY KEY
registration_bytes        BLOB UNIQUE NOT NULL
vault_id                  BLOB(32) NOT NULL
vault_store_id            BLOB(32) NOT NULL
checkpoint_verifier_id    BLOB(32) NOT NULL
network_and_genesis_id    BLOB(32) NOT NULL
dkg_epoch                 BLOB(8) NOT NULL
key_package_digest        BLOB(64) NOT NULL
participant_id            INTEGER NOT NULL
share_id                  INTEGER NOT NULL
attestation_scheme        INTEGER NOT NULL
attestation_verifier      BLOB NOT NULL
activation_height         BLOB(8) NOT NULL
expiry_height             BLOB(8) NOT NULL
status                    TEXT NOT NULL CHECK(status IN ('ACTIVE','REVOKED'))
revocation_digest         BLOB(64)
revocation_sequence       INTEGER
revocation_effective_height BLOB(8)
UNIQUE(vault_id,dkg_epoch,participant_id,share_id)
```

No new receipt may be accepted under `REVOKED`; exact historical verification
must remain possible.

`vault_revocations` stores the exact immutable `VaultRevocationV1` bytes and
digest. `revoke_vault` is a monotone `ACTIVE -> REVOKED` journal event;
reactivation and changed revocation replay conflict. Race rule: a receipt first
persisted before the revocation event remains exactly replayable and may finish
certificate/release; a receipt whose first persistence linearizes after
revocation is rejected even if the vault sealed it earlier. Activation/expiry
and effective-height checks use `AuthenticatedLedgerHeightV1`, not caller
integers.

Registration status/lifetime is rechecked transactionally at Jc, J0, J1, and
first J2 receipt persistence. Only exact replay of a receipt whose first J2
linearization preceded revocation may continue through J3/R; an earlier plan,
commitment, J0 permit, J1 request, or vault seal does not grandfather a new J2
acceptance.

### `nonce_commit_statements`

```text
nonce_slot_key              BLOB(64) PRIMARY KEY
operation_id               BLOB(32) NOT NULL
operation_attempt          INTEGER NOT NULL
input_spend_id             BLOB(32) NOT NULL
child_attempt              INTEGER NOT NULL
ceremony_id                BLOB(32) NOT NULL
nonce_domain               INTEGER NOT NULL
participant_id             INTEGER NOT NULL
share_id                   INTEGER NOT NULL
vault_registration_digest   BLOB(64) NOT NULL
slot_identity_bytes         BLOB UNIQUE NOT NULL
component_plan_bytes        BLOB NOT NULL
component_plan_digest       BLOB(64) NOT NULL
nonce_plan_bytes            BLOB UNIQUE NOT NULL
nonce_plan_digest           BLOB(64) UNIQUE NOT NULL
authenticated_context_bytes BLOB NOT NULL
authenticated_context_digest BLOB(64) NOT NULL
statement_bytes             BLOB UNIQUE NOT NULL
statement_digest            BLOB(64) UNIQUE NOT NULL
authorization_sequence      INTEGER NOT NULL
UNIQUE(operation_id,operation_attempt,input_spend_id,child_attempt,
       ceremony_id,vault_registration_digest,participant_id,share_id,nonce_domain)
```

The statement does not contain the authority state root that includes this row.
After DB commit and anchor advancement, `PreparedNonceCommit` carries an
external checkpoint/membership proof for `statement_digest`. Exact plan/context
bytes are therefore recoverable after cold restart; a digest alone is not.
The same reviewed component plan may be reused across slots; its bytes/digest
are not globally unique. The bounded implementation uses one vault/share/domain
per child attempt. A retry that legitimately allocates a new nonce uses a new
child attempt or ceremony identity and therefore a new semantic slot.

### `produce_requests`

```text
(operation_id, operation_attempt, input_spend_id, child_attempt) PRIMARY KEY
nonce_commit_statement_digest BLOB(64) UNIQUE NOT NULL
vault_registration_digest BLOB(64) NOT NULL
committed_receipt_bytes   BLOB UNIQUE NOT NULL
committed_receipt_digest  BLOB(64) UNIQUE NOT NULL
committed_receipt_wrapper_bytes BLOB UNIQUE NOT NULL
committed_receipt_wrapper_digest BLOB(64) UNIQUE NOT NULL
nonce_slot_key            BLOB(64) UNIQUE NOT NULL
vault_id                  BLOB(32) NOT NULL
nonce_id                  BLOB(32) NOT NULL
nonce_plan_digest         BLOB(64) NOT NULL
produce_request_bytes     BLOB UNIQUE NOT NULL
produce_request_digest    BLOB(64) UNIQUE NOT NULL
UNIQUE(vault_id,nonce_id)
```

### `operation_authorizations_v2`

```text
(operation_id, operation_attempt) PRIMARY KEY
ordered_committed_receipt_bytes BLOB NOT NULL
ordered_committed_receipt_vector_digest BLOB(64) NOT NULL
ordered_produce_statement_bytes BLOB NOT NULL
ordered_produce_statement_digest_vector BLOB NOT NULL
authorization_entry_bytes BLOB UNIQUE NOT NULL
authorization_entry_digest BLOB(64) UNIQUE NOT NULL
authenticated_height_digest BLOB(64) NOT NULL
authorization_sequence INTEGER NOT NULL
```

This is J0. Exact statement bytes/digests and the commitment receipts on which
they depend are durable and recoverable; a caller cannot present only a digest.
The post-J0 historical proof remains external to the row it proves.

### `sealed_receipts`

```text
sealed_receipt_digest     BLOB(64) PRIMARY KEY
(operation_id, operation_attempt, input_spend_id, child_attempt) UNIQUE
produce_request_digest    BLOB(64) UNIQUE NOT NULL
receipt_bytes             BLOB UNIQUE NOT NULL
receipt_wrapper_bytes     BLOB UNIQUE NOT NULL
receipt_wrapper_digest    BLOB(64) UNIQUE NOT NULL
vault_registration_digest BLOB(64) NOT NULL
vault_id                  BLOB(32) NOT NULL
response_handle           BLOB(32) NOT NULL
nonce_id                  BLOB(32) NOT NULL
canonical_response_digest BLOB(64) NOT NULL
vault_semantic_sequence   BLOB(8) NOT NULL
vault_semantic_chain_head BLOB(64) NOT NULL
vault_receipt_persist_sequence BLOB(8) NOT NULL
vault_receipt_persist_chain_head BLOB(64) NOT NULL
receipt_journal_sequence  INTEGER NOT NULL
UNIQUE(vault_id,response_handle)
```

### `release_certificates`

```text
release_certificate_digest BLOB(64) PRIMARY KEY
(operation_id, operation_attempt, input_spend_id, child_attempt) UNIQUE
sealed_receipt_digest       BLOB(64) UNIQUE NOT NULL
certificate_bytes           BLOB UNIQUE NOT NULL
message_id                  BLOB(32) UNIQUE NOT NULL
canonical_response_digest   BLOB(64) NOT NULL
receipt_checkpoint_bytes    BLOB UNIQUE NOT NULL
receipt_checkpoint_digest   BLOB(64) UNIQUE NOT NULL
minimum_valid_height        BLOB(8) NOT NULL
maximum_valid_height        BLOB(8) NOT NULL
retention_height            BLOB(8) NOT NULL
```

The certificate core binds the prior `J2` receipt checkpoint. The returned
`ReleaseAuthorization` wrapper separately binds/proves the `J3` checkpoint at
which the exact certificate was persisted. `VaultV2::release` accepts this
wrapper, not a bare certificate. The wrapper/checkpoint is reconstructed from
the authenticated J3 journal event and anchor history; it is not inserted into
the certificate row whose root it proves. One sequence/root pair cannot safely
serve both purposes.

Every v2 table uses explicit `NOT NULL`, fixed-width `CHECK(length(...)=N)`,
enum/range checks, and `FOREIGN KEY` constraints with SQLite foreign keys
enabled: produce request -> nonce-commit statement/registration/live child;
sealed receipt -> produce request/registration; certificate -> sealed receipt;
outbox -> certificate. Uniqueness is vault-scoped where appropriate, including
`(vault_id, nonce_id)` and `(vault_id, response_handle)`. The exact
`STATE_TABLES_V2` order, canonical row projection, semantic event projection,
and whole-history verifier are frozen and mutation-tested; adding rows to an
unauthenticated table is a test failure.

### Independent durable vault-v2 schema

The integration gate also defines a separate durable vault store and anchor;
journal durability cannot substitute for signer durability:

```text
vault_meta
  schema_version, vault_id, cached_current_sequence,
  cached_event_chain_head, cached_state_projection_digest,
  pinned_operation_authority_chain_head,
  pinned_registry_authority_id, pinned_registry_view_sequence,
  pinned_registry_view_root,
  pinned_ledger_authority_id, pinned_ledger_view_sequence,
  pinned_ledger_view_root, pinned_finalized_height

nonce_records
  nonce_slot_key BLOB(64) PRIMARY KEY
  nonce_commit_statement_digest BLOB(64) UNIQUE NOT NULL
  component_plan_bytes BLOB NOT NULL
  nonce_plan_bytes BLOB NOT NULL
  nonce_id BLOB(32) UNIQUE NOT NULL
  commitment_receipt_bytes BLOB UNIQUE
  state TEXT CHECK(state IN
    ('COMMIT_CORE_ANCHORED','COMMITTED','BOUND','COMPUTING',
     'SEAL_CORE_ANCHORED','SEALED','RELEASED','ARCHIVED',
     'RETIRED_WITHOUT_RESPONSE'))
  request_bytes, request_digest
  sealed_response_bytes, canonical_response_digest, response_handle
  sealed_receipt_bytes, sealed_receipt_digest
  nonce_secret_fixture_bytes
  nonce_tombstone_digest
  release_authorization_digest
  response_retention_height
  terminal_evidence_bytes, terminal_evidence_digest

vault_events
  sequence PRIMARY KEY, prior_root, event_type,
  event_payload_bytes, event_payload_digest, next_root
```

The deterministic nonce-secret fixture is present only while
`COMMIT_CORE_ANCHORED`, `COMMITTED`, `BOUND`, or `COMPUTING`.
`SEAL_CORE_ANCHORED` atomically stores the exact response core and replaces the
secret with the permanent tombstone; exact receipt persistence follows in the
second step below. The vault anchor authenticates its event head.

Receipt construction is acyclic. `COMMIT_CORE_ANCHORED` first commits the
semantic nonce/commitment core and advances the vault anchor. The vault then
constructs `CommittedNonceReceiptV1` naming that prior checkpoint; a second
`PersistCommittedReceipt` event commits the exact receipt digest and reaches
`COMMITTED`. Its external anchored wrapper proves the second event. Sealing uses
the same two-step pattern: `SEAL_CORE_ANCHORED` commits response digest and
nonce tombstone, then `PersistSealedReceipt` commits exact receipt bytes and
reaches `SEALED`. No event/projection contains a receipt that names the root of
that same event.

This software-vault slice chooses fail-safe ambiguous-computation semantics.
Before scalar/fixture computation begins it durably enters and anchors
`COMPUTING` and increments a persisted attempt counter. Normal completion moves
directly to `SEALED`. If the process dies after that marker—including after
response calculation but before seal commit—cold reopen converts `COMPUTING` to
`RETIRED_WITHOUT_RESPONSE(AmbiguousComputationCrash)` and never re-executes the
calculation. This costs availability but avoids claiming an impossible atomic
compute+SQLite-persist primitive. A future HSM may advertise a genuinely atomic
compute-and-seal command under a separately tested profile.
Receipt verification in the journal requires both the registered attestation
and an exact historical vault checkpoint proof. A receipt signature naming an
unanchored or rolled-back vault head is insufficient.

`VaultV2::open` validates schema, event chain, materialized state, and external
vault anchor before serving any method. DB/head disagreement fails closed.
Crash points exist after durable commit, bind, seal, release, and archive
mutations, including DB-commit-before-vault-anchor and post-anchor return loss.
`vault_meta.cached_current_sequence/cached_event_chain_head/
cached_state_projection_digest` are derived caches and are
excluded from the materialized-state projection; open recomputes them from the
last exact event. The projection cannot hash a row containing the root it is
trying to derive. Exact event payload bytes are retained so a cold audit can
replay transition semantics, not merely trust an opaque payload digest.

The exact state projection also enforces transition-dependent nullability:
nonce-secret fixture bytes exist only before `SEAL_CORE_ANCHORED`; request
bytes/digest exist from `BOUND`; response bytes/digest and the tombstone exist
from `SEAL_CORE_ANCHORED`; exact sealed-receipt bytes exist from `SEALED`;
release authorization exists from `RELEASED`; and typed terminal evidence is
mandatory in `ARCHIVED`/`RETIRED_WITHOUT_RESPONSE`. Every forbidden early/late
field combination fails open-time integrity validation.

Journal-v2 metadata pins the same registry/ledger authority identities and
monotone view heads. A lower sequence/height, same-sequence equivocation, or
network/genesis mismatch fails closed; an accepted newer view advances the pin
transactionally. A historical J0/J2/J3 proof remains usable after unrelated
later events only when it includes verifiable membership/chain evidence to the
pinned newer authority head. A simplistic `historical_sequence >= current_floor`
rule is incorrect because it would reject legitimate exact recovery. These pins
prevent replay after a newer view has been observed; initial freshness still
depends on the configured authority/maximum-view-age assumption and must be
stated in deployment policy.

### Child and outbox transitions

Replace symbolic `nonce_status` with:

```text
response_state IN (
  'RESERVED',
  'BOUND',
  'SEALED_RECEIPT_PERSISTED',
  'RELEASE_AUTHORIZED',
  'DELIVERED',
  'SIGNER_RETIRED'
)
```

```text
accept_initial:          RESERVED
authorize:               RESERVED -> BOUND
persist_sealed_receipt:  BOUND -> SEALED_RECEIPT_PERSISTED
persist_vault_failure:   BOUND -> SIGNER_RETIRED
issue_release:           SEALED_RECEIPT_PERSISTED -> RELEASE_AUTHORIZED
mark_delivered:          RELEASE_AUTHORIZED -> DELIVERED
```

The nonce is cryptographically consumed inside `VaultV2` when response
computation is sealed and the nonce secret is tombstoned at `Vs`. `J2` consumes
the journal child authorization by accepting/anchoring the exact receipt; it is
not the moment of nonce consumption. An attested
`RetiredWithoutResponseEvidenceV1` is separately persisted as `SIGNER_RETIRED`
so recovery does not retry response computation forever; a fresh attempt needs
a new child/ceremony identity.

Add `sealed_receipt_digest` and `release_certificate_digest` to `outbox`.
Retain exact response bytes/digest only as the append-once delivery payload.
Require one outbox row per certificate/message ID.

## 4. Journal API

Remove `emit_round2` from the integrated public API. Add:

```rust
pub fn register_vault(
    &mut self,
    registration_bytes: &[u8],
    crash_at: Option<CrashPoint>,
) -> Result<VaultRegistrationReceipt, JournalError>;

pub fn revoke_vault(
    &mut self,
    revocation_bytes: &[u8],
    height: &AuthenticatedLedgerHeightV1,
    crash_at: Option<CrashPoint>,
) -> Result<VaultRevocationReceipt, JournalError>;

pub fn prepare_nonce_commit(
    &mut self,
    accepted: &AcceptedReceipt,
    child: &ChildSlot,
    vault: &VaultRegistrationReceipt,
    context: &NonceCommitContextV1,
    height: &AuthenticatedLedgerHeightV1,
    crash_at: Option<CrashPoint>,
) -> Result<PreparedNonceCommit, JournalError>;

pub fn authorize_produce_statements(
    &mut self,
    accepted: &AcceptedReceipt,
    committed_receipts: &[AnchoredCommittedNonceReceiptV1],
    statements: &[ProduceRequestStatementV1],
    height: &AuthenticatedLedgerHeightV1,
    crash_at: Option<CrashPoint>,
) -> Result<(AuthorizedReceiptV2, Vec<ResponsePermitV2>), JournalError>;

pub fn prepare_produce_request(
    &mut self,
    permit: &ResponsePermitV2,
    crash_at: Option<CrashPoint>,
) -> Result<PreparedProduceRequest, JournalError>;

pub fn persist_sealed_receipt(
    &mut self,
    permit: &ResponsePermitV2,
    anchored_sealed_receipt_bytes: &[u8],
    height: &AuthenticatedLedgerHeightV1,
    crash_at: Option<CrashPoint>,
) -> Result<PersistedSealedReceipt, JournalError>;

pub fn persist_vault_failure_evidence(
    &mut self,
    permit: &ResponsePermitV2,
    evidence_bytes: &[u8],
    crash_at: Option<CrashPoint>,
) -> Result<PersistedVaultFailure, JournalError>;

pub fn issue_release_certificate(
    &mut self,
    receipt: &PersistedSealedReceipt,
    height: &AuthenticatedLedgerHeightV1,
    crash_at: Option<CrashPoint>,
) -> Result<ReleaseAuthorization, JournalError>;

pub fn enqueue_released_response(
    &mut self,
    authorization: &ReleaseAuthorization,
    response: &ReleasedResponse,
    crash_at: Option<CrashPoint>,
) -> Result<MessageId, JournalError>;
```

`persist_sealed_receipt` decodes and re-encodes before mutation, resolves the
historical registration, verifies the vault attestation **and exact historical
vault-anchor proof**, revalidates the exact permit and liveness inside the write
transaction, and compares every receipt projection with the stored nonce-commit
statement, commitment, and produce request. Exact byte replay is idempotent; an
alternate receipt conflicts without changing child state.

`authorize_produce_statements` is the executable J0 CAS. It parses the complete
ordered statements and signed commitment receipts, resolves every Jc statement,
recomputes commitment-set and algorithm-transcript values, validates the exact
operation-wide sibling vector and trusted height, persists the exact bytes, and
anchors their canonical vector. Each `ResponsePermitV2` privately binds one
statement digest, its committed receipt/Jc identity, and the deterministic
historical J0 proof. `prepare_produce_request` takes no caller context; it
reconstructs the final request from those stored objects and that proof.
After persisting/anchoring the exact request at J1 it returns
`PreparedProduceRequest` with an external J1 object-membership proof.
`VaultV2::produce_once` accepts only that wrapper and independently verifies
both its J1 proof and the embedded historical J0 authorization proof.

`enqueue_released_response` accepts the opaque, private-field
`ReleasedResponse` capability minted only by `VaultV2::release`, never a byte
slice or publicly constructible canonical value. It resolves the stored
certificate and receipt, checks message ID and the single canonical response
digest, verifies the external R checkpoint proof that the vault durably anchored
`RELEASED`, and only then inserts the outbox payload. The private capability
contains the already retained canonical bytes plus that proof; it is returned
only after vault DB commit and anchor advancement.

`prepare_nonce_commit` resolves the accepted operation/child and an active vault
registration; validates every bounded context envelope; derives the exact slot,
component plan, and nonce plan; persists the exact statement; advances the
operation-authority anchor; and only then returns the wrapper accepted by
`VaultV2::commit_nonce`. Exact replay is byte-identical. Any changed plan or
context under the same semantic slot is a conflict. A registration revoked
before this mutation or before a new sealed receipt is accepted fails closed;
revocation does not prevent historical verification of a receipt already
persisted under that registration.

`register_vault` and `revoke_vault` verify their external registry-authority
proofs against a configured trust root, network/genesis identity, and
authenticated height; a self-declared verifier is rejected. Both journal and
vault checkpoint verifiers authenticate the authority/store identity, schema
and projection versions, event kind, exact object digest, and event-chain head.
They pin monotone floors while accepting a valid historical proof after
unrelated later events. The ordinary-file v1 `FileAnchor` is not sufficient;
v2 needs an authenticated append-only checkpoint log or equivalent fixture that
can reconstruct historical object/event proofs.

The bounded fixture uses one canonical deterministic proof encoding for each
`(authority, store, sequence, event kind, object digest, chain head)` tuple and
retains its exact bytes in the append-only checkpoint log. Post-anchor return
loss therefore reconstructs byte-identical wrappers. A production quorum whose
valid aggregate proof bytes can vary must either canonicalize signer/proof
selection or durably retain the selected proof artifact; “generate another
valid proof” is a conflict, not exact retry.

`VaultV2` exposes proof-verification interfaces but not certificate issuance or
arbitrary response-production injection. Its public commit method accepts only
`PreparedNonceCommit`; its release method is
`release(&ReleaseAuthorization, &AuthenticatedLedgerHeightV1)` and accepts no
caller integer. It verifies and pins the height view before the inclusive first-
release/retention decision.

`issue_release_certificate` does not accept a caller-selected window. It
derives `ReleaseWindowV1` from the stored policy, transaction tombstone,
minimum-release margin, registration lifetime, and authenticated ledger height.
Exact receipt retry with the same derived window is byte-identical; a changed
policy/window is a conflict. `message_id` is derived from stable pre-J3 fields
(child identity, receipt and response digests, J2 checkpoint, and derived
window), never from the certificate digest or J3 root.

## 5. Non-circular happens-before relation

```text
A   accepted operation/child reservation is anchored
Jc  exact nonce-commit statement DB commit -> operation-authority anchor
Vc  vault verifies Jc, recomputes context/plans, anchors commitment core
VrC vault persists/anchors exact committed receipt; wrapper returned
C   public commitment/anchored receipt becomes observable
J0  operation-wide commitment-dependent round-two authorization is anchored
J1  exact authorized produce request DB commit -> operation-authority anchor
B   vault durably binds exact request
Q   vault durably/externally anchors COMPUTING marker; one attempt begins
S   vault computes and self-verifies with no observable output
Vs  vault stores/anchors sealed response core and nonce tombstone
VrS vault persists/anchors exact sealed receipt; wrapper returned
J2  exact receipt/child DB commit -> operation-authority anchor
J3  exact release certificate DB commit -> operation-authority anchor;
    ReleaseAuthorization wrapper returned
R   vault durably marks Released
O   exact outbox DB commit -> authority anchor
P   append-once publisher observes raw response
D   delivery marker DB commit -> authority anchor

A -> Jc -> Vc -> VrC -> C -> J0 -> J1 -> B -> Q -> S -> Vs -> VrS
  -> J2 -> J3 -> R -> O -> P -> D
```

`Vc`/`C` may not precede `Jc`: authenticating complete preimages only at `J1` would
occur after commitment exposure and leave the Phase-A binding hole open. `J0`
follows `C` because its ordered round-two statements depend on the complete
signed commitment set; putting `J0` before `C` would be circular.

The `PreparedNonceCommit` wrapper references the checkpoint produced by `Jc`,
outside the statement that checkpoint authenticates. The authorized round-two
request references the prior `J0` checkpoint. The certificate core references
the already anchored receipt checkpoint from `J2`,
not the checkpoint containing the certificate at `J3`. Otherwise the encoding
would be circular:

```text
statement/certificate -> authority root -> state containing that same object
```

The same two-level rule applies inside the vault: Vc/Vs authenticate semantic
cores; VrC/VrS authenticate the exact receipt bytes that name those prior cores.

For every journal mutation, reuse the existing pattern: preflight validation,
`BEGIN IMMEDIATE`, validation repeated inside the transaction, state mutation,
global event append, database commit, anchor compare-and-swap, then return.

## 6. Restart protocol

Add deterministic recovery enumerators:

```rust
pub fn pending_nonce_commits(&mut self)
    -> Result<Vec<PreparedNonceCommit>, JournalError>;

pub fn pending_produce_requests(&mut self)
    -> Result<Vec<PreparedProduceRequest>, JournalError>;

pub fn sealed_receipts_pending_certificate(&mut self)
    -> Result<Vec<PersistedSealedReceipt>, JournalError>;

pub fn release_authorizations_pending_outbox(&mut self)
    -> Result<Vec<ReleaseAuthorization>, JournalError>;
```

Every recovery query has an explicit total order. Use canonical bytewise keys:
`(operation_id, operation_attempt, input_ordinal, input_spend_id,
child_attempt, vault_id, participant_id, share_id, nonce_domain, message_id)`
with only the applicable suffix for each enumerator. No query relies on SQLite
row order.

Keep the existing permit reconstruction and outbox recovery. Recovery order is:

1. reconstruct and replay the stored exact nonce-commit wrapper into
   `vault.commit_nonce`;
2. recover/verify the exact commitment and operation-wide request authorization;
3. replay the stored exact request into `vault.produce_once` only from
   `COMMITTED`/`BOUND`; a recovered `COMPUTING` record retires with typed
   evidence and is never recomputed;
4. persist the returned or already stored receipt;
5. issue or recover the exact certificate-persistence wrapper;
6. replay `vault.release`;
7. enqueue the identical typed response; and
8. run append-once outbox recovery.

A vault-committed or sealed orphan is safe and converges through exact
authorization/request retry. A lost release return converges through exact
certificate retry. Every restart test closes/drops both v2 objects, reopens both
independent stores, and reloads both external anchors. A DB-ahead-of-anchor,
anchor-ahead-of-DB, vault-checkpoint disagreement, or unknown recovery fork
fails closed; this slice does not authorize blind head advancement.

## 7. Minimum adversarial test gate

1. `commitment_requires_anchored_exact_nonce_plan_preimages`.
2. `nonce_commit_statement_after_anchor_return_loss_is_recoverable`.
3. `changed_nonce_commit_context_conflicts_under_same_slot`.
4. `vault_commit_crash_and_cold_reopen_recovers_exact_commitment`.
5. `prepared_request_after_anchor_return_loss_is_recoverable`.
6. `unregistered_revoked_or_wrong_vault_receipt_is_side_effect_free`.
7. `journal_persists_exact_receipt_once`.
8. `journal_conflicting_receipts_consume_child_at_most_once`.
9. `vault_computing_crash_retires_without_reexecution_or_second_identity`.
10. `receipt_internal_crash_rolls_back`.
11. `receipt_db_ahead_of_anchor_fails_closed`.
12. `receipt_anchor_complete_return_loss_recovers_exactly`.
13. `certificate_requires_anchored_receipt_checkpoint`.
14. `release_wrapper_requires_certificate_persistence_checkpoint`.
15. `certificate_exact_retry_is_byte_identical`.
16. `certificate_crash_matrix_never_exposes_unanchored_certificate`.
17. `vault_release_rejects_wrong_or_rolled_back_authority_checkpoint`.
18. `vault_release_commit_and_anchor_precede_raw_response`.
19. `enqueue_rejects_response_or_certificate_digest_mismatch`.
20. `outbox_anchor_and_sink_crash_windows_recover_once`.
21. `orphan_committed_sealed_and_released_states_converge_after_cold_restart`.
22. `sixteen_exact_and_conflicting_receipt_calls_admit_one_identity`.

Add four journal-specific injection points:

- `AfterNonceCommitStatementInsert`;
- `AfterProduceRequestInsert`;
- `AfterSealedReceiptInsert`; and
- `AfterReleaseCertificateInsert`.

Add vault-specific points after commit, bind, seal, release, DB commit before
vault-anchor advancement, and vault-anchor advancement before method return.
Also inject immediately after the durable `COMPUTING` marker and immediately
after response calculation but before the seal mutation; both must cold-reopen
as the same typed retirement, with one persisted computation attempt.

Retain the generic pre-journal, pre-commit, DB-commit-before-anchor, post-anchor,
outbox, and sink-before-delivery points.

The tests are non-vacuous only with the following instrumentation:

- an external observation hook at commitment, receipt, certificate, raw-release,
  outbox, sink, and delivery boundaries;
- a crash immediately after durable/anchored vault `RELEASED` and before the
  response is cloned or returned;
- a persisted response-computation counter and nonce tombstone;
- cold reconstruction in a new process from separate journal/vault disks and
  anchors (not reuse of one `Arc<Mutex<...>>`);
- sixteen independent journal/vault handles released behind a barrier; and
- conflicting receipts that are independently well-formed and validly attested,
  target the **same child, permit, registration, semantic slot, and nonce ID**,
  but have different exact receipt identities—not different children and not
  merely malformed byte mutations.

External compile-fail tests must prove that another crate cannot construct
`PreparedNonceCommit`, `PreparedProduceRequest`, `PersistedSealedReceipt`,
`ReleaseAuthorization`, or `ReleasedResponse` capabilities and cannot invoke an
arbitrary response producer/certificate issuer.

Required one-defect fixtures/mutants independently demonstrate that the gate
detects: skipped pre-commit authorization; a mutated context preimage with an
unchanged claimed digest; changed/missing J0 statement bytes; changed-request
rebinding; omitted v2 state table; self-referential Vc or Vs receipt; certificate
issuance before J2; release with a J2-only certificate; a self-referential J3
certificate; raw observation before anchored vault release; caller-byte
injection; canonical-response digest-domain mismatch; first receipt after
revocation; changed release-window replay; and regressed/equivocating trusted
height. Historical J2/J3 proofs
must remain valid after unrelated later heads, while a rolled-back or unproved
fork fails closed.

Freeze `CommonAdmissionTraceV1` before claiming differential coverage. It
projects the exact accept/reservation and operation-wide authorization events,
child/request identities, and semantic phase while deliberately excluding
schema-specific roots and v1 `PersistRound2` versus v2 receipt/certificate
events. The comparison must reach both nontrivial common phases for every test
profile; an empty or admission-only trace is not evidence.
Its request identity is the shared canonical request-core digest present in both
v1 and v2, not the v2-only `ProduceRequestStatementV1` digest.

## 8. Success and failure conditions

### Success

The slice passes when both supported Rust compilers, Clippy, rustfmt, all 22
named tests, all required mutants/compile-fail cases, nonempty differential
prefix traces, and cold-reopen/tamper checks are green; the integrated public
API contains no arbitrary response-byte input; every **recoverable
observation-loss** crash returns the same stored identity/bytes; every declared
DB/anchor or unproved-fork mismatch remains terminal fail-closed; and no raw
response can reach the sink before the exact receipt checkpoint, certificate
persistence checkpoint, and vault release are authenticated and anchored.

### Failure

The slice fails if any of the following is possible:

- a caller-chosen byte string consumes a child or enters the outbox;
- a commitment is observable before the exact authenticated round-one context,
  component plan, and nonce plan are authority-anchored and recomputed;
- one semantic nonce slot binds two plan/request digests;
- an unregistered, revoked, wrongly attested, or mismatched vault receipt
  advances child state;
- a certificate refers to an unanchored receipt or to its own state root;
- crash/restart recomputes a response instead of recovering it;
- raw response bytes cross the vault or publisher boundary before release
  persistence;
- exact retry produces a different receipt, certificate, message ID, or bytes;
- a caller controls the trusted height or release window;
- a bare `(sequence, root)` without object/event membership and authority
  authentication is accepted as a checkpoint;
- an exact plan/context/commitment-set/transcript preimage is absent after cold
  restart or a changed preimage is accepted under a stale digest;
- a public caller can construct any integration capability;
- journal/vault/anchor disagreement is automatically “repaired” without an
  authenticated unique-successor recovery record; or
- archived/retired evidence loses the permanent nonce tombstone identity.

## 9. Implementation order

1. Freeze the neutral type crate and cross-language vectors.
2. Extract neutral durable-I/O traits without semantic changes.
3. Implement fresh journal-v2 and vault-v2 schemas plus authenticated heads.
4. Implement vault registration and exact nonce-commit statement authorization.
5. Make `VaultV2` authenticate/recompute that statement before commitment.
6. Implement non-circular operation authorization and produce-request persistence.
7. Implement durable vault bind/seal, receipt proof, and nonce tombstone.
8. Implement receipt verification/persistence and child transition.
9. Implement the two-checkpoint release certificate/wrapper.
10. Implement typed response enqueue and append-once delivery recovery.
11. Add cold-restart enumerators and all 22 adversarial tests.
12. Run the exact Rust 1.83 minimum toolchain and freeze hashes.
13. Only after this slice passes, replace deterministic production with the
    pinned Serai `modular-frost` / MobileCoin MLSAG adapter.
