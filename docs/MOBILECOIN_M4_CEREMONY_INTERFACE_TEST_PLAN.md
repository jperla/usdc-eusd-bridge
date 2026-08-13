# MobileCoin M4: authenticated threshold-MLSAG ceremony interface and test plan

Status: design/audit plan, not an implementation or a security proof  
Date: 2026-08-08  
MobileCoin source: `05cb699f8f4cc1bc21186392545820c5b38408db` (clean)  
Serai source: `4b89cf0206184886e96d0663861596312e5b47d2` (clean)  
M2b `strict.rs`: SHA-256 `76092f20bc1c5d706add15e3151b016d80f5a1857572d0dd5e0f01350d0a2ab8`  
M2a `lib.rs`: SHA-256 `2f51234386f5e23e9b43e375c6e1eb75352a062ba380fea4338f664a052a353d`

## 1. Decision

The production signer must be a durable, asynchronous, authenticated protocol state machine. It cannot be implemented honestly as only a `RingSigner::sign` method.

The stock `RingSigner` remains useful as a narrow terminal adapter: once a ceremony has already completed, it can return the cached `RingMLSAG` to existing transaction assembly code. It is not a sufficient protocol boundary for session identifiers, attempts, round messages, durable nonce state, coordinator equivocation, or blame evidence.

M4 must preserve a typed `CeremonyFailure` and an authenticated `EvidenceBundle` outside the stock builder error. Converting every M2b failure to `RingSignerError::Unknown` is acceptable only at the final legacy facade, after the exact failure and evidence have been durably committed. It is a production failure if `Unknown` is the sole surviving record.

This plan supports two explicit row-1 profiles:

1. `CoreCustodyKnownZ`: the one-time spend scalar `x` remains threshold-held, while a view-key service, coordinator, or designated row-1 authority may know the complete mask difference `z = r_pseudo - r_input`. This matches the narrower custody claim of the Serai-style/M2a construction. Knowing the ring and real index is already permitted by the stated requirements. Knowing `z` alone does not authorize a spend because MLSAG row 0 still requires `x`.
2. `PrivateThresholdZ`: both `x` and `z` remain threshold-held, as in M2b. No process may first materialize `z` and then merely Shamir-share it. The pseudo-output mask `p` must be jointly shared; the row-1 key can then be derived either by subtracting input-mask shares or by applying the complete, quorum-confidential `b_input` as Serai's public-to-the-ceremony key offset. The latter permits signers to know `b_input` but still leaves `z = p-b_input` shared because no signer knows complete `p`. Otherwise this profile has not been achieved.

The second profile is privacy hardening, not a prerequisite for threshold spend custody. The authenticated transcript, coordinator accountability, one-shot nonce state, retry rules, and final verifier requirements are the same in both profiles.

## 2. Source findings that constrain the design

### 2.1 MobileCoin's interface is synchronous and lossy

At the pinned MobileCoin revision:

- `crypto/ring-signature/signer/src/traits.rs:16-42` places the complete real index, input amount, and input blinding in `SignableInputRing`/`InputSecret`.
- `crypto/ring-signature/signer/src/traits.rs:76-109` defines one synchronous `sign(&self, message, ring, output_blinding, rng) -> Result<RingMLSAG, Error>` call. There is no session, attempt, participant set, state transition, pending result, transcript, or evidence return.
- `crypto/ring-signature/signer/src/traits.rs:125-142` has only local/device-shaped errors and ends in `Unknown`.
- `transaction/core/src/ring_ct/rct_bulletproofs.rs:116-163` exposes `SigningData`, including the MLSAG signing digest, complete pseudo-output blindings, commitments, and range proofs.
- `transaction/core/src/ring_ct/rct_bulletproofs.rs:478-525` calls `RingSigner` once per signable input and collects only final `RingMLSAG` values.
- `transaction/core/src/ring_ct/error.rs:85-89` and `transaction/builder/src/error.rs:68-69` can retain only the stock signer error, not an authenticated participant accusation.

Therefore a threshold protocol hidden inside `RingSigner::sign` would either block across multiple network rounds or smuggle an asynchronous state machine behind a synchronous call. It would also receive complete mask scalars at the wrong trust boundary and collapse exact M2b failures into a generic error.

### 2.2 M2b has the right algebraic checks but not authenticated evidence

M2b already establishes several required invariants:

- `strict.rs:33-57` introduces a bonded participant mapping and key context.
- `strict.rs:182-199` makes the exact network, epoch, key IDs, roster, session, MobileCoin message, ring, real index, pseudo-output commitment, and decoy responses part of the statement.
- `strict.rs:231-265` rejects malformed statements before signing.
- `strict.rs:268-287` defines participant-indexed two-row round messages.
- `strict.rs:289-296` returns `MissingParticipant(p)` and `InvalidShare(p)` rather than only a boolean.
- `strict.rs:306-317` explicitly says that Rust ownership is only an in-memory one-shot mechanism and production still needs durable `AVAILABLE -> RESERVED -> BURNED` state.
- `strict.rs:320-405` validates signer-local key/roster policy, the real target key, and the commitment difference before sampling nonces.
- `strict.rs:413-450` binds the reserved statement and signer set, rejects replacement of the signer's own round-1 package, and produces both response shares.
- `strict.rs:562-650` (the reserved-statement hash) length-frames and tags all immutable authorization fields.
- `strict.rs:830-884` verifies each participant's row-0 and row-1 response equations and returns the first exact invalid participant before requiring MobileCoin's ordinary verifier to accept.
- `strict.rs:1060-1113` tests corruption of either response row and checks exact culprit attribution.
- `strict.rs:1160-1335` tests field binding and statement/roster substitution after reservation.

What M2b does **not** supply is equally important: `Round1` and `Round2` are plain Rust values. They have no canonical network encoding, identity signature, authenticated delivery receipt, coordinator signature, durable replay record, or public evidence verifier. An in-memory `HashMap<Participant, Round2>` plus `InvalidShare(p)` identifies the map entry that is invalid; it does not prove that participant `p` authored those bytes.

### 2.3 Serai's useful pattern, and the limit of the analogy

The useful Serai DKG pattern is:

- a `(session, attempt)` identifier (`processor/messages/src/lib.rs:20-27`);
- typed stages consuming prior state (`crypto/dkg/pedpop/src/lib.rs:136-202`, `275-380`, `383-388`, `535-573`);
- authenticated broadcast/direct messages and an explicit warning that duplicate broadcasts must be detected by the caller (`pedpop/src/lib.rs:96-106`, `152-159`);
- participant-indexed malformed commitment/share errors (`pedpop/src/lib.rs:297-355`, `457-499`);
- a blame verifier that resolves either the accused sender or a false accuser, provided the original message was authenticated (`pedpop/src/lib.rs:575-632`, `638-681`);
- persistence of parameters and commitment sets so a DKG can resume/reconstruct after reboot (`processor/src/key_gen.rs:184-230`, `310-382`, `504-563`);
- explicit acknowledgement that final completion requires a consensus/confirmation layer outside the cryptographic library (`pedpop/src/lib.rs:561-570`).

The nonce rule must **not** be copied blindly from DKG. Serai FROST says a cached preprocess must be used exactly once or the private share can be recovered (`crypto/frost/src/sign.rs:83-92`, `209-224`). Serai's transaction signer deliberately aborts an in-flight signing attempt after reboot instead of reconstructing it from a deterministic RNG because a mistake can leak the secret share (`processor/src/signer.rs:407-428`). M4 may resume only an exact, durably persisted attempt and must retransmit identical signed bytes. It must never regenerate a new response under an old nonce commitment.

### 2.4 Private row-1 and the v4 range-proof witness boundary

`PrivateThresholdZ` does not make stock v4 transaction construction share-native. The pinned
MobileCoin path materializes every pseudo-output blinding and gives complete `(value, blinding)`
witnesses to `generate_range_proofs`. Therefore a complete private-Z transaction must select and
bind one of three explicit modes:

1. a role-separated no-view proof worker reconstructs each `p_j`, receives the minimal typed
   `ProofJobView`, and is assumed not to collude with any `b_input`/view holder;
2. a new threshold/MPC Bulletproof consumes shared witnesses (absent from the pinned trees); or
3. a reviewed vNext rule changes which commitments are range-proved.

Mode 1 preserves stock v4 verification but introduces an operational non-collusion boundary and
must follow the data-minimization/capability rules in `MOBILECOIN_M4_MASK_PROTOCOL_DESIGN.md`.
Modes 2 and 3 are new cryptographic/protocol milestones. Stock `SigningData::new` is not evidence
for either. The M4 baseline may complete `CoreCustodyKnownZ` without private-Z; a private-Z claim is
conditional on one selected mode passing its own tests.

## 3. Roles and registry snapshot

Each ceremony has the following roles:

- `Proposer`: constructs the full unsigned MobileCoin transaction and bridge authorization context.
- `Coordinator`: collects messages and signs canonical round bundles. It has no authority to change a manifest after acceptance. It is replaceable on a fresh attempt.
- `SpendParticipant(i)`: holds share `x_i` and an identity signing key registered to participant index `i`.
- `Row1Authority`: present only in `CoreCustodyKnownZ`; holds or can derive complete `z` and a one-shot row-1 nonce. It may be the coordinator, but the roles and signatures remain distinct.
- `MaskParticipant(i)`: present only in `PrivateThresholdZ`; holds `z_i`. Normally it is the same bonded identity as `SpendParticipant(i)` and uses the same included set.
- `EvidenceVerifier`: a deterministic, versioned verifier that consumes registry snapshot plus signed transcript bytes and returns one typed `EvidenceVerdict`: a nonempty canonical `FaultSet`, `NotProvable`, or non-attributable `InternalProtocolFailure`.

The registry snapshot is signer-local authority, not coordinator-supplied authority. It fixes:

- network/genesis identifier;
- protocol and codec versions;
- DKG/key epoch;
- spend group-key ID and group point, interpolation mode, DKG commitment/registry root, and the
  ordered original per-participant spend verification shares needed to derive each selected
  signer's Lagrange-weighted `X_i`, plus the canonical one-time-key offset-point recipe and its
  lowest-selected-participant allocation rule;
- for `PrivateThresholdZ`, the per-input mask-share context ID, group point `Z = zG`, mask
  commitment/registry root, interpolation mode, and ordered original mask verification shares
  needed to derive each selected signer's `Z_i`, plus the frozen input-mask subtraction/offset
  recipe and its lowest-selected-participant allocation rule;
- ordered `(participant index, identity verification key, bond account)` entries;
- threshold and roster size;
- activation and expiry heights.

The manifest carries the snapshot root, but every signer resolves and verifies the snapshot independently. This preserves M2b's signer-local `KeyContext` principle.

## 4. Canonical message schema

Do not sign an implementation-dependent `serde` encoding. Define a versioned canonical codec with fixed-width integers, canonical compressed Ristretto points/scalars, explicit lengths/counts, sorted participant lists, no duplicate fields, and rejection of trailing or unknown bytes. All hashes below use length-framed tagged fields, following M2b's reservation hash. A concrete choice is full 64-byte `Blake2b512`; 32-byte IDs are domain-separated truncations of that digest.

### 4.1 Signed envelope

```text
SignedEnvelope {
  codec_version: u16,
  network_id: [u8; 32],
  ceremony_id: [u8; 32],
  attempt: u32,
  sender_role: enum,
  sender_id: RegistryIdentityId,
  kind: enum,
  payload_len: u32,
  payload: bytes,
  identity_signature: [u8; 64],
}
```

The signature is Ed25519 (or another registry-frozen scheme) over:

```text
H("mc/threshold-mlsag/envelope/v1",
  codec_version, network_id, ceremony_id, attempt,
  sender_role, sender_id, kind, payload_len, payload)
```

Version 1 permits exactly one semantic message slot per `(ceremony_id, attempt, sender_role,
sender_id, kind)`. Retransmission is byte-identical. A sender-controlled sequence counter is
deliberately absent: otherwise a malicious signer could evade equivocation detection by assigning
different counters to two conflicting messages.

The fixed outer header must remain parseable even when `payload` is malformed. That allows a valid identity signature over malformed round bytes to be evidence. An invalid identity signature is not evidence against the claimed sender.

### 4.2 Manifest

```text
Manifest {
  protocol_version: u32,
  block_version: u32,
  network_id: [u8; 32],
  source_event_id: [u8; 32],
  source_record_digest: [u8; 64],
  operation_id: [u8; 32],
  operation_attempt: u32,
  reservation_core_digest: [u8; 64],
  ordered_input_spend_ids: Vec<[u8; 32]>,
  input_spend_id: [u8; 32],
  utxo_spend_id: [u8; 32],
  request_nonce: [u8; 32],
  ceremony_id: [u8; 32],
  attempt: u32,
  prior_attempt: Option<[u8; 32]>,
  coordinator_id: RegistryIdentityId,

  dkg_epoch: u64,
  spend_key_id: [u8; 32],
  registry_snapshot_root: [u8; 32],
  spend_share_registry_root: [u8; 32],
  spend_offset_context_id: [u8; 32],
  spend_offset_point: CompressedRistrettoPoint, // delta*G; confidential
  interpolation: Lagrange,
  offset_allocation: LowestIncludedAfterInterpolation,
  bonded_roster_root: [u8; 32],
  threshold: u16,
  roster_size: u16,
  included: sorted Vec<Participant>,

  profile: Row1Profile,

  unsigned_tx_digest: [u8; 64],
  mlsag_signing_digest: bytes,
  input_ordinal: u16,
  statement: M2bStatement,

  policy_output_ref: bytes,
  bridge_action_digest: [u8; 64],
  warden_certificate_digest: [u8; 64],
  authorization_policy_digest: [u8; 64],

  not_before_height: u64,
  expires_at_height: u64,
}

Row1Profile =
  CoreCustodyKnownZ {
    row1_authority: RegistryIdentityId,
    z_commitment: CompressedRistrettoPoint
  }
| PrivateThresholdZ {
    derivation: MaskDerivationMode,
    mask_share_context_id: [u8; 32],
    mask_group_key: CompressedRistrettoPoint,
    mask_registry_root: [u8; 32]
  }

MaskDerivationMode =
  KnownInputMaskOffset {
    input_opening_digest: [u8; 64],
    input_blinding_point: CompressedRistrettoPoint
  }
| FullyDistributedMasks {
    input_mask_registry_root: [u8; 32]
  }
```

`M2bStatement` contains every field currently covered by M2b's reservation digest: exact message bytes, all reduced ring members in order, real index, pseudo-output commitment, and every decoy response with canonical zero placeholders at the real index.

None of the safety IDs is coordinator-chosen. Every signer and the operation journal independently
parses the authenticated source record and selected real TxOut bytes with the frozen canonical codec
and recomputes these tagged formulas:

```text
eth_source_event_id = Trunc32(H("mc/bridge/source/eth-usdc-deposit/v1",
  ethereum_chain_id_u256_be, escrow_contract_20, usdc_contract_20,
  escrow_deposit_record_key_32))

mob_source_event_id = Trunc32(H("mc/bridge/source/mob-eusd-return/v1",
  mobilecoin_network_or_genesis_id_32, immutable_bridge_escrow_lane_id_32,
  consensus_unique_bridge_return_nullifier_32))

source_record_digest = H("mc/bridge/source-record/v1",
  source_kind_u8, canonical_authenticated_source_record)

operation_id = Trunc32(H("mc/bridge/operation/v1",
  bridge_instance_id_32, direction_u8, source_event_id,
  source_asset_id, source_amount_u128_be,
  destination_asset_id, destination_amount_u128_be,
  canonical_destination_recipient, authorization_policy_digest))

utxo_spend_id = Trunc32(H("mc/threshold-mlsag/utxo/v1",
  mobilecoin_network_or_genesis_id_32, ledger_tx_out_index_u64_be,
  H("mc/threshold-mlsag/txout-identity/v1", canonical_real_TxOut_identity)))

input_spend_id = Trunc32(H("mc/threshold-mlsag/input/v1",
  operation_id, logical_input_ordinal_u16_be, utxo_spend_id))
```

`canonical_real_TxOut_identity` length-frames every consensus TxOut field in the protocol-defined
order; it is not protobuf/serde output. `source_asset_id`, `destination_asset_id`, and recipient are
fixed tagged unions with one canonical encoding. For this bridge the pair is the configured USDC
contract and MobileCoin eUSD `TokenId(8192)`. The authenticated source record supplies and must
agree with direction, amounts, asset pair, recipient, and record key/nullifier; the journal does not
accept caller-proposed economic fields independently. A future fee/conversion rule binds both gross
source and net destination amounts plus its policy digest rather than silently changing `amount`.

`escrow_deposit_record_key_32` is an immutable, contract-enforced never-reused identifier stored in
the Ethereum escrow's readable state (for example a monotonically unique deposit ID); it is not an
unverified log alias. A `(transaction_hash, log_index)` may be recorded as evidence, but the state
record and its key are authoritative. `immutable_bridge_escrow_lane_id_32` is fixed when the bridge
lane is created and never changes across policy/roster/version epochs. Authorization policy is
deliberately absent from `mob_source_event_id` and remains bound in `operation_id` and the
reservation core. The journal additionally unique-indexes the raw
`(mobilecoin_network_or_genesis_id, consensus_unique_bridge_return_nullifier)` pair, so neither a
lane nor policy alias can authorize the same return twice.

`source_event_id` is the stable source/nullifier identity and has its own unique journal index,
independent of `operation_id`; the same authenticated source event cannot create two operation
families even if other proposed fields differ. The source-family record has one monotone
`family_attempt`, byte-equal to the current `OperationReservationCore.operation_attempt`, and at
most one current operation ID. Before its first acceptance, competing
proposals are only candidates. After `Accepted`, policy/economic terms are frozen. A
pre-authorization `Aborted` entry may atomically tombstone that operation ID and rebind the same
source family to one newly derived operation ID at the next `family_attempt`; this transition
requires journal proof that the old operation never reached `Authorized`, atomically retires every
old child/nonce reservation and releases or reassigns each old UTXO reservation, and leaves all old
IDs permanently stale.
After `Authorized` or `Completed`, rebinding is forbidden. This permits a safe policy correction
before any round-2 share without permitting two live or executable releases. `operation_id` is the stable bridge
liability/release identity and top-level exactly-once key, not merely a namespace for input
ceremonies. `input_spend_id` is its confidential stable child ID. `utxo_spend_id` is a separate
confidential global real-output ID and deliberately does **not** contain `operation_id`. None of
these IDs contains `attempt`, `request_nonce`, coordinator, fee/tombstone choice, ring decoys, or
signer subset. Every retry therefore reaches the same durable indexes. A supplied ID that differs
from independent derivation is rejected before operation acceptance or nonce allocation.

Before any input manifest is acknowledged, a safety-critical linearizable authorization journal
must atomically accept an operation-journal record whose immutable core binds:

```text
OperationReservationCore {
  source_event_id,
  source_record_digest,
  operation_id,
  operation_attempt,
  ordered_input_spend_ids,
  ordered_utxo_spend_ids,
  unsigned_tx_digest,
  bridge_action_digest,
  authorization_policy_digest
}

OperationJournalEntryCore {
  reservation_core_digest,
  state_version,
  previous_entry_digest,
  state: Accepted | Authorized | Completed | ExpiredUnincluded | Aborted,
  transition_payload: enum {
    Accepted,
    Authorized { ordered_child_round2_request_core_digests },
    Completed { destination_finality_proof_digest },
    ExpiredUnincluded { tombstone_noninclusion_proof_digest },
    Aborted { preauthorization_reason }
  }
}

AuthenticatedOperationJournalEntry {
  core: OperationJournalEntryCore,
  authenticated_transition_proof
}
```

The digest rules are non-circular and byte-exact:

```text
reservation_core_digest = H("mc/threshold-mlsag/operation-core/v1",
                            canonical_OperationReservationCore)
journal_entry_digest    = H("mc/threshold-mlsag/operation-entry/v1",
                            canonical_OperationJournalEntryCore)
```

`authenticated_transition_proof` is outside the hashed entry core and attests
`journal_entry_digest`; the replicated-board inclusion/consensus proof likewise names that digest.
`previous_entry_digest` is absent only for the first entry and otherwise equals the exact prior
`journal_entry_digest`. The canonical codec rejects any proof that is embedded into or recursively
changes the object it signs.

There is exactly one live accepted/authorized transaction attempt per `operation_id`. Every input
manifest must name the immutable `reservation_core_digest`, same operation attempt, exact ordered input
set, and unsigned transaction digest. Changing the transaction or input selection requires
atomically aborting the whole operation attempt before accepting a fresh one; aborting a single
child is insufficient. `reservation_core_digest` hashes only the immutable core; mutable state is a
versioned, hash-chained journal transition against that core, so state changes never alter ceremony
IDs or invalidate evidence.

Before **any** round-2 response share for **any** child leaves an honest signer, the journal must
atomically compare-and-swap the whole operation from `Accepted` to `Authorized`, binding the
immutable core plus the complete ordered set of child round-2 request digests. `Authorized` is the
irreversible permission to create a complete transaction signature, not a retrospective label
applied after a coordinator may already possess one. It cannot transition to ordinary `Aborted`.
A replacement attempt is forbidden until authenticated ledger evidence proves the authorized
transaction passed its tombstone without inclusion and advances it to `ExpiredUnincluded` (or a
future consensus cancellation rule makes it permanently unspendable). `Completed` means the bridge
release was finalized, not merely that MLSAG aggregation succeeded, and is a permanent operation
tombstone.
The same journal atomically unique-indexes `source_event_id` to its one operation family, prevents
one `utxo_spend_id` from being live under two operations, and preserves both final associations
after completion.

Signer-local source-event/operation/UTXO records are required defense in depth but do not, by themselves, give
global exactly-once safety when two qualifying signer sets can avoid every honest common member.
Production therefore anchors these reservations/completions in an authenticated linearizable
replicated bulletin board or the future consensus state consulted by every signer. A deployment
that substitutes only signer-local state must prove, for every pair of concurrently valid
qualifying same- or cross-generation quorums `Q_a,Q_b`, the actual honest-intersection condition
`|Q_a intersection Q_b| > f_intersection`. For one fixed `t`-of-`n` roster, `2*t-n>f` is only the
usual lower-bound shorthand; it is not a cross-generation proof. The all-selected round-1 view rule
prevents split views inside one accepted manifest; it does not replace this cross-manifest
operation lock.

The signer and evidence verifier resolve `registry_snapshot_root`, derive the selected-set Lagrange
weights from the exact `included` list, derive each weighted root-spend verification share, and add
`spend_offset_point` exactly once to the lowest included participant. They reject unless the
resulting shares sum to the selected real target and the offset context binds the exact
`(R, view-key epoch, subaddress index, root spend group, target, transaction, input)` recipe. No
coordinator-supplied derived share is authoritative.

The projection into M2b is normative, not an informal nested object:

```text
Statement.protocol_version = Manifest.protocol_version
Statement.network_id       = Manifest.network_id
Statement.dkg_epoch        = Manifest.dkg_epoch
Statement.spend_key_id     = Trunc32(H("mc/m2b/spend-context/v1",
                                      spend_key_id, spend_offset_context_id))
Statement.bonded_roster_id = Manifest.bonded_roster_root
Statement.threshold/n      = Manifest.threshold/roster_size
Statement.session_id       = Manifest.ceremony_id
Statement.message          = Manifest.mlsag_signing_digest
Statement.ring/real/output/responses = Manifest.statement corresponding fields
```

Every equality is byte-exact and independently recomputed. In `PrivateThresholdZ`, the M2b
`mask_key_id` is a tagged hash of the selected derivation mode,
`mask_share_context_id`, and `mask_registry_root`, and both
rows use the canonical M2b participant binding factors over the same signed round-1 set. In
`CoreCustodyKnownZ`, `mask_key_id` is a tagged hash of `KnownZ`, the authority, and
`z_commitment`; only spend participants use the M2b row-0 binding formula, while the authority's
row-1 nonce/response uses a separate `mc/threshold-mlsag/known-z-row1/v1` transcript binding the
same manifest, complete signed round-1 set, authority identity, and nonce slot. The final ordinary
MLSAG challenge is then computed from the combined row-0 commitments and authority row-1 point.
Exact byte formulas and cross-profile golden vectors remain a required formal-specification gate.

`z_commitment`/`mask_group_key` must equal `C_pseudo - C_input(real)`. In `PrivateThresholdZ`, each mask verification share is resolved from the mask-share registry snapshot and the included shares must interpolate to this point. `KnownInputMaskOffset` keeps complete `b_input` confidential to the authorized cohort while `p` and `z` remain shared; `FullyDistributedMasks` additionally keeps `b_input` shared. The manifest and evidence verifier freeze which derivation and offset allocation were used.

`ceremony_id` is recomputed as:

```text
Trunc32(H("mc/threshold-mlsag/id/v1",
  network_id, operation_id, operation_attempt, reservation_core_digest,
  ordered_input_spend_ids, input_spend_id, utxo_spend_id,
  dkg_epoch, spend_key_id, registry_snapshot_root,
  spend_share_registry_root, spend_offset_context_id,
  spend_offset_point, interpolation, offset_allocation, bonded_roster_root,
  unsigned_tx_digest, input_ordinal, attempt, request_nonce))
```

A participant keeps the journal-backed top-level operation record, a global UTXO-family record
keyed by `utxo_spend_id`, and a permanent child attempt-family record keyed by
`(operation_id, input_spend_id)`. The child record includes the one allowed live ceremony and the
highest accepted/completed child attempt, plus uniqueness indexes for each `ceremony_id` and nonce
slot. A reused ID with different manifest bytes, a second parallel live operation/child attempt, an
input not in the exact operation reservation, or a stale attempt after a newer accepted/completed
attempt is rejected before nonce allocation.

### 4.3 Round messages

All collection payloads contain the sorted complete signed envelopes, not merely a coordinator-created `HashMap`.

```text
ManifestAck {
  manifest_digest: [u8; 64],
  decision: Accept,
  local_policy_snapshot: [u8; 64]
}

Round1Request {
  manifest_digest: [u8; 64],
  ack_set_digest: [u8; 64],
  ack_envelopes: sorted Vec<SignedEnvelope<ManifestAck>>
}

Round1Spend {
  manifest_digest: [u8; 64],
  round1_request_digest: [u8; 64],
  participant: Participant,
  nonce_slot_id: [u8; 32],
  spend_verification_share: Point,
  key_image_share: Point,
  d0_g: Point, d0_h: Point,
  e0_g: Point, e0_h: Point,
  commitment_consistency_proof: bytes
}
```

For `PrivateThresholdZ`, `Round1Spend` additionally contains:

```text
  mask_verification_share: Point,
  d1_g: Point, e1_g: Point,
  row1_commitment_knowledge_proof: bytes
```

For `CoreCustodyKnownZ`, the row-1 authority separately sends:

```text
Round1KnownZ {
  manifest_digest: [u8; 64],
  round1_request_digest: [u8; 64],
  authority_nonce_slot_id: [u8; 32],
  k1_g: Point,
  nonce_knowledge_proof: bytes
}
```

Exact round-1 accountability requires three **independent-witness** DLEQ proofs:

```text
PoK d0: log_G(d0_g) == log_H(d0_h)
PoK e0: log_G(e0_g) == log_H(e0_h)
PoK x_hat_i: log_G(spend_verification_share) == log_H(key_image_share)
```

The three witnesses are respectively `d0`, `e0`, and the selected-set weighted spend share
`x_hat_i`; they are not equal to one another. Private-row points `d1_g` and `e1_g`, and the known-Z
authority point `k1_g`, each require a separate Schnorr proof of knowledge. Every proof is
Fiat-Shamir-bound to the manifest, registry snapshot, participant/role, exact point tuple, nonce
slot, and round-1 request. These proofs are mandatory for M4 conformance and exact round-1 blame.
They are not present in M2b and require a separate formal specification, implementation, test
vectors, and cryptographic audit. Until that work passes, M4 authenticated accountability remains
unproved rather than silently falling back to an optional-proof profile.

Each DLEQ/Schnorr proof also needs independent secret proof randomness. Derive it from the same
durably reserved one-shot seed only through a reviewed PRF/KDF with the complete transcript and a
unique full-purpose label (proof type, witness role, row, participant, input, attempt), or reserve a
separate durable proof-nonce slot. Never reuse proof randomness across proofs or ceremonies, and
never use `d0`, `e0`, `d1`, `e1`, or `k1` themselves as proof randomness—especially not for the
long-term `x_hat_i` DLEQ. Reusing a Fiat-Shamir proof nonce for `x_hat_i` exposes that share; leaking
a signing nonce can then expose the spend share through `s = k-c*x_hat_i`. Proof randomness follows
the same bind-before-release, anti-rollback, crash-recovery, erasure, and tombstone rules as the
MLSAG nonce material.

```text
Round1Bundle {
  manifest_digest: [u8; 64],
  round1_request_digest: [u8; 64],
  round1_set_digest: [u8; 64],
  messages: canonical sorted complete Round1 envelopes
}

Round1ViewAck {
  manifest_digest: [u8; 64],
  round1_set_digest: [u8; 64],
  participant_or_authority: RegistryIdentityId
}

Round2RequestCore {
  manifest_digest: [u8; 64],
  round1_set_digest: [u8; 64],
  round1_view_ack_set_digest: [u8; 64],
  view_acks: canonical sorted complete Round1ViewAck envelopes
}

Round2Request {
  core: Round2RequestCore,
  operation_authorization_entry: AuthenticatedOperationJournalEntry(Authorized),
  journal_inclusion_or_consensus_proof: bytes
}

Round2PrivateZ {
  manifest_digest: [u8; 64],
  round1_set_digest: [u8; 64],
  round2_request_digest: [u8; 64],
  participant: Participant,
  s0: Scalar,
  s1: Scalar
}

Round2CoreSpend {
  manifest_digest: [u8; 64],
  round1_set_digest: [u8; 64],
  round2_request_digest: [u8; 64],
  participant: Participant,
  s0: Scalar
}

Round2KnownZ {
  manifest_digest: [u8; 64],
  round1_set_digest: [u8; 64],
  round2_request_digest: [u8; 64],
  authority: RegistryIdentityId,
  s1: Scalar
}

Round2Bundle {
  manifest_digest: [u8; 64],
  round1_set_digest: [u8; 64],
  round2_request_digest: [u8; 64],
  round2_set_digest: [u8; 64],
  messages: canonical sorted complete Round2 envelopes
}

Completed {
  manifest_digest: [u8; 64],
  round1_set_digest: [u8; 64],
  round1_view_ack_set_digest: [u8; 64],
  round2_request_digest: [u8; 64],
  round2_set_digest: [u8; 64],
  final_transcript_digest: [u8; 64],
  ring_mlsag: canonical RingMLSAG bytes,
  ring_mlsag_digest: [u8; 64]
}

Abort {
  manifest_digest: [u8; 64],
  last_accepted_state: enum,
  last_bundle_digest: [u8; 64],
  reason_code: enum,
  evidence_digest: Option<[u8; 64]>
}
```

The coordinator signs `Manifest`, `Round1Request`, `Round1Bundle`, `Round2Request`, `Round2Bundle`, `Completed`, and `Abort`. Every selected participant/authority signs its manifest ack, round-1 contribution, round-1 view ack, and round-2 contribution. Round 2 binds an all-selected, identically acknowledged round-1 view, so two different coordinator views cannot silently merge or induce two responses from one nonce slot.

### 4.4 Transcript roots

```text
manifest_digest = H("mc/threshold-mlsag/manifest/v1", canonical_manifest)
ack_set_digest = H("mc/threshold-mlsag/acks/v1", sorted_signed_ack_bytes)
round1_request_digest = H("mc/threshold-mlsag/r1-request/v1", signed_request_bytes)
round1_set_digest = H("mc/threshold-mlsag/r1-set/v1", sorted_signed_r1_bytes)
round1_view_ack_set_digest = H("mc/threshold-mlsag/r1-view-acks/v1",
  sorted_signed_round1_view_ack_bytes)
round2_request_core_digest = H("mc/threshold-mlsag/r2-request-core/v1",
  canonical_round2_request_core)
round2_request_digest = H("mc/threshold-mlsag/r2-request/v1", signed_request_bytes)
round2_set_digest = H("mc/threshold-mlsag/r2-set/v1", sorted_signed_r2_bytes)
final_transcript_digest = H("mc/threshold-mlsag/final/v1",
  manifest_digest, ack_set_digest, round1_request_digest,
  round1_set_digest, round1_view_ack_set_digest, round2_request_digest,
  round2_set_digest, ring_mlsag_digest)
```

M2b's reservation/binding-factor transcript must absorb `manifest_digest` and the canonical round-1 set. The MobileCoin MLSAG challenge itself remains the stock challenge over the exact `mlsag_signing_digest`, key image, and MLSAG commitment points; changing that challenge would stop compatibility with the stock verifier. Signers must recompute that transaction digest from the manifest. External bridge-policy fields are bound by the signed ceremony transcript and future consensus authorization certificate, not by an ordinary legacy MLSAG unless the new transaction format incorporates them. There must not be one encoding of the manifest/round set for identity signatures, a second for binding factors, and a third for evidence verification.

## 5. Durable state machines

### 5.1 Signer state

```text
Absent
  -> ManifestValidated
  -> AckPersisted
  -> NonceBound
  -> Round1Persisted
  -> Round1Locked
  -> Round1ViewAckPersisted
  -> Round2RequestLocked
  -> Round2PersistedAndNonceErased
  -> Completed | Aborted
```

Rules:

1. `ManifestValidated`: authenticate/finality-check the canonical source record; independently derive its source-event/operation IDs and every real-input UTXO/child ID; then recompute all digests, MobileCoin signing data, ring shape, real target equality, commitment-difference equality, bridge/warden authorization, local key epoch, and exact included set. Resolve the linearizable operation journal and reject unless its accepted record binds the exact source record, operation attempt, ordered input/UTXO set, unsigned transaction digest, bridge action, and policy; independently verify that this child and UTXO are reserved to that record. No nonce has been touched.
2. `AckPersisted`: persist the signed ack in an fsynced outbox before sending it.
3. `NonceBound`: in one database transaction, compare-and-swap an `AVAILABLE` nonce slot to `BOUND(ceremony_id, manifest_digest, round1_request_digest)`. A bound slot can never return to `AVAILABLE`, even if nothing was sent.
4. `Round1Persisted`: persist the exact signed round-1 bytes and an outbox marker before network transmission. Recovery retransmits these exact bytes.
5. `Round1Locked`: accept exactly one valid coordinator-signed round-1 bundle containing the signer's own byte-identical message and the exact manifest signer set. A second, different signed bundle is coordinator-equivocation evidence. No response is produced until this state is durable.
6. `Round1ViewAckPersisted`: sign the one accepted round-1 root, persist it, and reliably broadcast it to every selected signer/authority, not only the coordinator.
7. `Round2RequestLocked`: first construct and sign the request core containing a valid view ack from **every identity selected in the manifest** for the same round-1 root. This all-selected rule avoids a split-view attack even when the threshold is at most half of the registry. The operation journal must then atomically transition the common immutable reservation from `Accepted` to `Authorized`, binding the exact ordered request-core digest for **every transaction input**. Accept the final request only after verifying its authenticated journal/consensus proof, exact state version/core, and inclusion of this child core. A second request/root is evidence. No nonce response is produced before this state is durable.
8. `Round2PersistedAndNonceErased`: immediately re-resolve the authoritative journal and require the same operation core to remain `Authorized`, the transaction tombstone to remain live, and the same complete child-core list to remain bound. Then compute one response bound to the final round-2 request, persist the signed response bytes plus permanent nonce tombstone, erase the nonce seed/scalars, and commit before transmission. Recovery retransmits the persisted response; it never recomputes it. There is no `Authorized -> Aborted` transition with which this check can race.
9. `Completed` requires the ordinary MobileCoin verifier to accept the final MLSAG and all final digests to match. `Aborted` never releases a nonce slot.

The storage must be transactional and crash consistent. The operation record, every referenced
UTXO reservation, and the accepted manifest-set commitment are one atomic journal transition; no
input may become signable after a partial reservation. The outbox write precedes transmission.
Backups and replicas must carry operation, UTXO, child-attempt, and nonce tombstones; restoring an
old backup must not resurrect an operation or make a consumed slot available. Production needs an
anti-rollback mechanism appropriate to the key store (monotonic hardware counter, append-only
replicated log, or equivalent).

`CoreCustodyKnownZ` applies the same state machine to the row-1 authority's nonce. `PrivateThresholdZ` applies it to all four M2b nonce scalars per participant. Both profiles include every DLEQ/Schnorr proof nonce in the same durable one-shot lifecycle; proof randomness is never an untracked auxiliary RNG output. The difference is secret distribution, not nonce discipline.

### 5.2 Coordinator state

```text
ProposedManifest
  -> CollectingAcks
  -> Round1Requested
  -> CollectingRound1
  -> Round1Bundled
  -> CollectingRound1ViewAcks
  -> Round2Requested
  -> CollectingRound2
  -> Round2Bundled
  -> Aggregated
  -> Completed | Aborted
```

The coordinator uses append-only state and an fsynced signed outbox. It first obtains the atomic
top-level `OperationReservationCore` journal entry; it cannot assemble input ceremonies independently and later call
them one transaction. It never silently swaps a participant within an attempt. If a child selected
set changes, the child attempt aborts and gets a fresh ceremony ID and fresh nonces while retaining
the same accepted operation record. If the unsigned transaction, ordered input set, or any selected
real UTXO changes, the **entire operation attempt** aborts in the linearizable journal before a new
operation attempt can be accepted. Signed manifests, bundle roots, and view acknowledgements must
travel over authenticated reliable broadcast/gossip or an access-controlled replicated append-only
bulletin board. Private coordinator-to-signer delivery alone leaves equivocation evidence
undiscovered and cannot prove omission. Public logging of full payloads is forbidden because the
manifest contains the real index; a board may log encrypted payloads and signed content hashes,
with full bytes revealed only under the selected dispute policy.

After every child has an all-selected round-1 view, the coordinator canonically constructs every
child `Round2RequestCore` and performs one journal CAS from `Accepted` to `Authorized` binding their
complete ordered digest list. It then attaches that same authenticated authorization entry/proof to
each final round-2 request. It is invalid to authorize one input at a time, to omit a child, or to
emit/share a response using a request core not in that single transition.

The coordinator may run aggregate verification as a cheap early rejection, but a valid aggregate is
not sufficient for `Completed`. Before aggregation/finalization it verifies every authenticated
participant equation individually in canonical order (or uses a separately specified sound
randomized batch that cannot permit canceling errors and still expands to individual checks for
blame). The baseline uses unconditional individual checks and emits/preserves evidence for every
invalid signed share. This deliberately differs from a fast-success-only Serai path: two colluders
can otherwise submit `+delta`/`-delta` invalid responses whose errors cancel in the aggregate,
leaving a valid MLSAG but a falsely clean accountability transcript.

Before operation authorization, coordinator replacement is a new child attempt under the same
accepted operation record when the transaction and input set are byte-identical. It may reuse the
unsigned transaction and signer set but not any prior round-1 commitment or nonce slot. After the
operation-wide authorization CAS, a replacement coordinator may only resume/rebroadcast the exact
authorized request cores and already persisted transcripts; it cannot create a fresh child attempt.
Any transaction/input change, or any post-authorization signer/core change after authenticated
expiry/non-inclusion, is a new top-level operation attempt and follows the journal rule above.

### 5.3 Typed implementation boundary

A Rust implementation should encode legal transitions in types, for example:

```text
ManifestMachine::validate(...) -> Result<ValidatedMachine, CeremonyFailure>
ValidatedMachine::ack(store) -> Result<(AckedMachine, SignedAck), CeremonyFailure>
AckedMachine::reserve_and_round1(store, request)
  -> Result<(Round1Machine, SignedRound1), CeremonyFailure>
Round1Machine::accept_bundle_and_ack_view(store, bundle)
  -> Result<(ViewAckMachine, SignedRound1ViewAck), CeremonyFailure>
ViewAckMachine::accept_round2_request_and_share(store, request)
  -> Result<(Round2Machine, SignedRound2), CeremonyFailure>
Round2Machine::complete(store, completed)
  -> Result<CompletedCeremony, CeremonyFailure>
```

The durable database state, not Rust ownership alone, is authoritative after a crash.

## 6. Evidence and attribution

### 6.1 Evidence types

```text
EvidenceBundle =
  ParticipantEquivocation { two valid signed envelopes for same semantic message slot }
| CoordinatorEquivocation { two valid signed manifests/requests/bundles/finals for same slot }
| InvalidRound1 { manifest, registry_snapshot, signed_round1, proof_failure }
| InvalidRound2 {
    manifest, registry_snapshot, signed_round1_bundle,
    signed_round2_set: canonical nonempty Vec<SignedRound2>,
    failed_equations: canonical nonempty Vec<(identity, equation_code)>
  }
| InvalidKnownZResponse {
    manifest, registry_snapshot, signed_round1_bundle,
    signed_known_z_r1, signed_known_z_r2, equation
  }
| FalseAccusation {
    accusation: SignedAccusation {
      codec_version, registry_snapshot_root, operation_id, input_spend_id,
      ceremony_id, attempt, accuser, accused, claimed_fault_code,
      primary_evidence_digest, policy_epoch, identity_signature
    },
    primary_evidence,
    authenticated_transcript
}

EvidenceVerdict =
  FaultSet { canonical sorted nonempty Vec<FaultRecord> }
| NotProvable { reason_code }
| InternalProtocolFailure { transcript_digest, failure_code }

FaultRecord { identity, fault_code, primary_evidence_digest }
```

The standalone verifier must:

1. verify canonical encodings and identity signatures;
2. resolve identities from the frozen registry snapshot;
3. recompute ceremony and transcript digests;
4. recompute the exact M2b binding factors and MLSAG challenge;
5. verify registry-derived verification shares and every mandatory round-1 DLEQ/knowledge proof;
6. check the participant equations;
7. return exactly one deterministic `EvidenceVerdict`; `FaultSet` may contain multiple canonically
   sorted fault records and deduplicates identities only when the penalty layer values bonds.

`SignedAccusation` uses its own `mc/threshold-mlsag/accusation/v1` identity-signature domain. An
accusation is matched to the exact `(accused identity, claimed_fault_code)` pair, not merely to an
identity that committed some other fault. Verdict precedence is deterministic: authenticate/admit
the accusation and primary evidence; derive the complete actual `FaultRecord` set; if the claimed
pair is present, return the actual set without blaming the accuser. If that exact pair is absent and
the admitted transcript affirmatively proves it false, additionally return the accuser's
`FalseAccusation` record only when the frozen policy enables that fault. Other independently proved
faults remain in the same set. Invalid signatures, missing bytes, unsupported codecs, or evidence
that proves neither the claimed pair nor its falsity return `NotProvable`, never a guessed culprit.
If all participant equations pass but the final MLSAG does not, return
`InternalProtocolFailure`, never any participant record.

For `PrivateThresholdZ`, participant `i` is invalid if any of these fail:

```text
G*s0_i + c*X_i == R0G_i
H*s0_i + c*I_i == R0H_i
G*s1_i + c*Z_i == R1G_i
```

For `CoreCustodyKnownZ`, spend participants use the first two equations, and the row-1 authority is invalid if:

```text
G*s1 + c*(C_pseudo - C_input(real)) != K1G
```

All evidence is self-contained or names content-addressed objects whose bytes are included when adjudicated. A database string saying `InvalidShare(7)` is not evidence.

### 6.2 Slashable with objective signed evidence

Subject to the registry and adjudication policy, the following are cryptographically attributable:

- two different valid identity-signed messages from one identity for the same
  `(ceremony, attempt, role, sender, kind)` semantic slot;
- two different coordinator-signed manifests, round requests, round bundles, final results, or abort/final combinations for one slot;
- a valid identity-signed malformed/noncanonical round payload;
- a valid identity-signed round-1 payload with a verification share inconsistent with the frozen registry;
- a valid identity-signed round-1 payload with a failed mandatory consistency/knowledge proof;
- a valid identity-signed round-2 share that fails its equation against the authenticated manifest and round-1 bundle;
- in the core profile, a valid signed row-1-authority response that fails the row-1 equation;
- a signed accusation that the deterministic evidence verifier proves false, if the governance rules explicitly make false accusations punishable.

### 6.3 Explicitly non-slashable from this protocol alone

These conditions may justify abort, retry, rate limiting, loss of a service fee, or a separately defined availability penalty. They are not cryptographic fraud proofs by themselves:

- silence, timeout, crash, network partition, or refusal to send round 1 or round 2;
- a coordinator's claimed non-receipt of a message without an authenticated receipt or replicated bulletin-board inclusion proof;
- a participant's claim that the coordinator omitted its message when there is no coordinator receipt or public inclusion log;
- invalid identity-signature bytes (they do not prove the named identity authored anything);
- malformed unsigned bytes that were never validly signed by the accused;
- `MissingParticipant(p)` caused only by a coordinator-created map;
- `MobileCoinVerifierRejected` after every participant equation passes; that is an implementation/transcript inconsistency until proven otherwise, not participant fraud;
- local registry corruption, stale key epoch, operator misconfiguration, disk rollback, or a software bug without a conflicting signed statement;
- disagreement about Ethereum finality, a later Ethereum reorganization, oracle data, bridge pricing, or policy meaning unless the disputed external fact has a separately specified objectively verifiable proof;
- a valid but economically undesirable transaction that satisfied the manifest policy the signers actually accepted;
- a coherent, proof-valid round-1 contribution followed by withholding; the proofs establish
  knowledge/consistency, not that the participant will later answer;
- use of `CoreCustodyKnownZ` where someone learns `z`; that is the declared profile, not misbehavior.

An availability bond can impose a deterministic penalty for missed publicly logged assignments and deadlines, but that is a service-level rule, not proof that a party attempted theft.

### 6.4 Privacy cost of public blame

The equations for an invalid threshold-MLSAG share require the exact confidential statement, including ring and real index. Publishing that particular evidence on MobileCoin or Ethereum reveals which ring member was real and destroys privacy for the disputed spend. Hashes alone do not let a public contract verify those share equations.

In particular, `Z = zG` and the one-time spend offset point `delta*G` are safe only inside the confidential authenticated ceremony (or an intentional dispute reveal). Never place `Z`, `delta*G`, `b_input*G`, the real index, or the mask/one-time-key derivation recipe in the normal public transaction beside the ordered ring: `Z` selects the member through `Z == C_pseudo-C_i`, while `B+delta*G` selects the target key directly. The future public authorization format must use a hiding commitment/zero-knowledge construction or omit this linkage.

There are only three honest choices:

1. accept privacy loss only on a fault and reveal the transcript for public slashing;
2. use a confidential adjudication committee/TEE and accept that the penalty is not publicly trustless; or
3. design a zero-knowledge fraud proof that proves an authenticated share equation failed without revealing the real index.

M4 preserves exact evidence, but it must not claim publicly trustless, privacy-preserving slashing until one of these adjudication designs is selected and tested.

This limitation is specific to adjudicating the internal threshold-MLSAG share equations. The mandatory attributable warden receipt set and the separate compact FROST gate signature can both sign only the canonical public transaction/bridge-intent digest; that does not inherently disclose the real ring index. The receipts prove which registered wardens approved, while the compact FROST signature proves only group-key authorization and not its contributor identities. The later consensus design must keep both public authorization artifacts separate from confidential invalid-share evidence.

## 7. Retry and abort rules

- Byte-identical retransmission within one state/attempt is idempotent and returns the already persisted response.
- Same `(ceremony_id, attempt, sender_role, sender_id, kind)` semantic slot with different bytes is equivocation or coordinator substitution; never process both.
- Before operation authorization, any child-level change to message, ring decoys, profile, key epoch, signer set, or coordinator requires a fresh child attempt and fresh nonce slots. After authorization, no child request core or selected set may change; a replacement coordinator may only resume the exact authorized transcript. Any change to real input selection, ordered input/UTXO IDs, unsigned transaction digest, bridge action, destination, asset, amount, recipient, or policy requires a fresh top-level operation attempt under the atomic journal rules.
- Timeout before `Round1Persisted`: abort attempt; any bound slot remains retired conservatively.
- Timeout after `Round1Persisted`: abort attempt and erase/retire the nonce. Never carry the commitment into another signer set or message.
- Timeout while collecting all-selected round-1 view acknowledgements: abort and retire every bound nonce; do not relax the view-ack rule within the attempt.
- Timeout after `Round2Persisted`: retransmit the exact signed round-2 bytes; never recompute.
- A bad signed round-1 or round-2 payload aborts the attempt and emits evidence. All honest participants retire their bound slots.
- Before the operation-wide authorization CAS, a missing participant aborts that child and retries with another qualifying set; absence is non-slashable unless a separate public availability rule applies. After authorization, a missing round-2 signer cannot be replaced: the operation remains locked until the exact authorized transcript completes or authenticated expiry/non-inclusion/cancellation permits a new top-level attempt.
- An old child attempt can never complete after a newer child attempt for the same transaction/input has been accepted. Parallel child or operation attempts are forbidden in the initial implementation.
- For a multi-input transaction, each input has its own ceremony ID and nonce slots but binds the same journal-backed operation reservation and unsigned-transaction digest. Transaction assembly succeeds only when every listed input ceremony completes against the same digest; an unlisted, missing, duplicated, or differently ordered child prevents assembly.
- The top-level operation advances from `Accepted` to non-abortable `Authorized` before any child round-2 response is generated. A completed signing ceremony does not create a new state or relax that lock. Only final destination-chain inclusion advances it to permanent `Completed`; a safely expired, never-included authorization may advance through the authenticated `ExpiredUnincluded` rule before replacement.

## 8. DKG, refresh, and epoch transition

Mirror Serai DKG in these respects:

- use explicit `session/epoch + attempt` identifiers;
- use consuming typed stages;
- authenticate every broadcast and direct message;
- persist parameters, registry snapshots, accepted message bytes, and stage markers;
- detect duplicate/equivocating broadcasts outside the algebra library;
- return participant-indexed errors;
- provide an independent blame verifier that can fault either accused or false accuser;
- require a final agreed confirmation before activating keys.

Do not mirror DKG's deterministic restart RNG for signing nonces. Exact signed-message replay from a durable outbox is safe; regeneration is not.

`PrivateThresholdZ` additionally needs a specified share derivation protocol for each input's `z`. Two linear forms are valid:

```text
z_keys = pseudo_mask_keys.offset(-b_input)              // complete b_input is ceremony-confidential
z_i    = pseudo_output_blinding_share_i - input_blinding_share_i  // stronger share-native input mask
```

No process may possess both a complete pseudo mask and the corresponding complete input blinding, and no dealer/coordinator may reconstruct `z`. The stronger variant also keeps the input blinding shared, but that is not necessary to keep `z` shared when `p` is already shared. In either form, the resulting verification shares must interpolate to the confidential ceremony point `C_pseudo-C_input(real)`. This share derivation has its own authenticated messages and epoch/context ID.

A concrete candidate is a pool of one-shot PedPoP-generated pseudo-mask slots. For an `m`-input transaction, consume `m-1` independent slot secrets `r_j`; use shares of `p_j=r_j` for the first inputs and shares of `p_m=B_out-sum(r_j)` for the last input, then derive `z_j` keys by applying either the complete ceremony-confidential `-b_input_j` offset or a verified linear subtraction of input-blinding shares. The manifest's `mask_share_context_id` must commit to the mask-pool epoch, ordered consumed slot IDs, transaction/bridge approval digest, input ordinal, output-blinding commitment, input-blinding derivation reference/profile, every `P_j=p_jG` and `Z_j=P_j-b_jG`, roster, and threshold. Because Serai key offsets are not self-serializing state, persist the derivation recipe and slot IDs and recompute/verify it on recovery. Slot state is atomically `AVAILABLE -> RESERVED(transaction) -> CONSUMED/BURNED`. This is a proposed mask-state construction, not something supplied by M2b or the pinned Serai DKG.

The pinned Serai tree provides DKG, blame, recovery, and generator promotion, but it does not supply a ready-made MobileCoin spend/mask share-refresh protocol. A refresh must therefore be specified separately. If it preserves the public key, use zero-constant refresh polynomials and prove the aggregate constant is zero. If it rotates the public key, treat it as a new DKG epoch and migrate policy outputs explicitly.

Epoch rules:

- never mix spend shares, mask shares, identity registry entries, or verification shares from different epochs;
- an activation height fixes which epoch a manifest may use;
- in-flight ceremonies at cutoff either complete under a clearly bounded grace rule or abort and burn nonces;
- old nonce slots never move into the new epoch;
- refresh/DKG complaints and signing complaints use different domain tags and evidence types.

## 9. Where ordinary `RingSigner` compatibility ends

Compatibility remains possible only at these points:

1. MobileCoin's unsigned-transaction path can produce the exact MLSAG digest, rings, pseudo-output commitments, and range proofs.
2. A completed ceremony produces an ordinary `RingMLSAG` that the stock verifier accepts.
3. A terminal cache adapter may implement `RingSigner` by looking up `(manifest digest/input ordinal)` and returning an already completed MLSAG.

Compatibility ends before distributed signing because the stock trait:

- is synchronous;
- has no session/attempt or participant set;
- has no durable state/storage transaction;
- has no authenticated round message or pending result;
- takes complete input and pseudo-output blindings;
- cannot express `CoreCustodyKnownZ` versus `PrivateThresholdZ`;
- cannot return exact authenticated evidence;
- cannot coordinate multiple inputs;
- returns only an ordinary MLSAG, which is indistinguishable from a single-party MLSAG.

The production API should therefore operate on `UnsignedTx`/`SigningData`, execute all input ceremonies, and assemble `SignatureRctBulletproofs` only after completion. A new builder method such as `assemble_with_ring_signatures(...)` or threshold-specific signing-data API is preferable to making `RingSigner::sign` perform network I/O.

Most importantly, a verifier-accepted ordinary MLSAG does **not** prove to consensus that a quorum participated. Protocol-level on-chain multisig needs a new transaction/input authorization format and consensus rule. The ceremony transcript can support that rule, but it is not the rule. The two public gates are distinct: a compact FROST signature proves authorization under the registered group key but does not identify its contributing shares, while a separately mandatory bonded warden receipt set (canonical signer identities/bitmap plus independently verifiable identity signatures or an equivalent attributable aggregate) provides the penalty handle. Both sign the same canonical public transaction/bridge digest and need not reveal the real ring member. The hard consensus problem is making both artifacts unavoidable for the hidden policy-bound input without opening the real member. Homogeneous-policy rings or a separately reviewed hiding policy proof are candidate mechanisms. Internal `Z`, verification-share, or real-index data must not be copied into either public certificate. This remains a separate protocol-format milestone.

## 10. Success conditions

M4 succeeds only if all of the following are demonstrated:

1. Every accepted manifest field is canonical and transcript-bound; mutation of any field changes the manifest or later bundle root.
2. Every round message has a verifiable bonded-identity signature and canonical participant identity.
3. All signers derive identical binding factors, MLSAG challenge, and transcript roots from identical bytes.
4. Every qualifying signer subset produces a stock-verifier-accepted MLSAG with stable key image.
5. Every authenticated row-0/row-1 share is checked individually before completion; each corrupt share returns its exact author and a self-contained authenticated evidence bundle, even when multiple corruptions cancel in the aggregate.
6. A malicious coordinator cannot give honest signers different manifests or round-1 sets without leaving two signed conflicting objects.
7. No statement/signer-set/profile substitution can occur after nonce binding.
8. Crash recovery at every storage/send boundary either retransmits identical bytes or aborts; it never reuses/regenerates a nonce for a different transcript.
9. `CoreCustodyKnownZ` never reconstructs `x`; a claimed `PrivateThresholdZ` mode reconstructs neither `x` nor `z` anywhere, including the proposer/coordinator, and enforces its selected range-proof witness boundary.
10. At the M4 baseline integration boundary, a complete `CoreCustodyKnownZ` MobileCoin transaction passes the stock signature/range-proof validators. `PrivateThresholdZ` must additionally pass the tests for one explicit §2.4 mode before claiming complete-transaction integration. Neither result is protocol-level completion: the later vNext milestone must separately make the threshold and warden artifacts consensus-mandatory and reject an otherwise valid ordinary MLSAG when either gate is absent.
11. Detailed errors/evidence survive any conversion to stock `RingSignerError`; `Unknown` is never the only record.
12. Explicit non-slashable failures return `NotProvable` rather than framing a participant.
13. A linearizable operation journal admits at most one live/authorized transaction for one stable
    `operation_id`, and the destination ledger can finalize at most one release for that ID. Its
    permanent completion tombstone survives restart, stale-backup restoration, coordinator/roster
    change, and cross-generation quorum selection.
14. A global `utxo_spend_id` is live under at most one operation, and accepting an operation plus
    all of its ordered UTXO/child reservations is atomic: no partial operation makes any input
    signable.
15. A local-state-only deployment is rejected unless every concurrently valid same- and
    cross-generation quorum pair proves `|Q_a intersection Q_b| > f_intersection`; `2*t-n>f` is
    accepted only as the fixed-roster lower-bound shorthand. The baseline shared journal serializes
    even two qualifying quorums whose overlap is entirely Byzantine.
16. Source-event, operation, UTXO, and child IDs are independently and canonically derived from
    authenticated source/real-input bytes. One source event has exactly one operation family and
    one real TxOut has exactly one global UTXO ID regardless of any coordinator-supplied alias.

## 11. Failure conditions

M4 fails immediately if any of these are observed:

- one nonce slot/seed/commitment is used for two different manifest or round-set digests;
- one proof nonce is reused across proofs/ceremonies, omitted from durable anti-rollback state, or
  aliases an MLSAG signing nonce/witness;
- restart or backup rollback can make a bound/consumed nonce available;
- a signer emits round 2 before persisting the exact round-1 bundle it accepted;
- a coordinator can relabel an unsigned share as another participant's evidence;
- a participant can be faulted without a valid registry identity signature on the offending bytes;
- a coordinator can substitute signer set, message, ring, profile, key epoch, or bridge action after round 1;
- two different transaction/input attempts for one stable `operation_id` can both become
  accepted/authorized/completed, or one source operation can cause two destination releases;
- one `utxo_spend_id` can be live under two operation IDs, or a crash exposes a partially accepted
  operation in which only some child/UTXO reservations are signable;
- two encodings/claimed IDs for the same authenticated Ethereum deposit, MobileCoin return, or real
  TxOut bypass the source-event/operation/UTXO unique indexes, or any signer accepts a supplied
  safety ID without independently deriving it from canonical authenticated bytes;
- a completed operation/UTXO tombstone can be reopened after restart, rollback, roster rotation, or
  coordinator replacement;
- a deployment relies only on signer-local operation state while admitting any qualifying same- or
  cross-generation quorum pair without `|Q_a intersection Q_b| > f_intersection` (using
  `2*t-n>f` only for one fixed roster);
- any child emits a round-2 response before the single operation-wide `Accepted -> Authorized` CAS,
  against an authorization entry that omits another child, or without re-resolving that entry and
  the live tombstone immediately before durable response generation;
- an otherwise valid bridge release can omit the consensus-verifiable, signer-attributable bonded
  warden receipt set, or a compact FROST/MLSAG group signature is treated as proof of which
  individuals participated;
- an invalid share becomes only `RingSignerError::Unknown` and exact evidence is lost;
- `PrivateThresholdZ` materializes complete `z` at any layer;
- `CoreCustodyKnownZ` is mislabeled as hiding `z`;
- missing/late messages are treated as cryptographic theft evidence without an external availability proof;
- `MobileCoinVerifierRejected` with all shares valid is assigned to an arbitrary participant;
- the project claims on-chain threshold enforcement merely because an ordinary MLSAG verifies.

## 12. Executable test matrix

### 12.1 Codec and transcript tests

- Golden vectors for every envelope and payload, in Rust and one independent implementation.
- Golden vectors for `OperationReservationCore`, `reservation_core_digest`, every
  `OperationJournalEntryCore` state, `journal_entry_digest`, transition proof, state version, and
  previous-entry link. The transition proof is outside the hashed core and signs its digest.
- Cross-language golden vectors for both source-event variants, the source-record digest,
  operation ID, UTXO ID, and child input ID, including eUSD `TokenId(8192)`, fixed-width Ethereum
  chain/address/record-key encoding, MobileCoin return nullifier, ledger index, and full canonical
  TxOut identity.
- Reject noncanonical points/scalars, duplicate fields, unsorted participants, duplicate participants, unknown enum values, wrong counts, trailing bytes, integer overflow, and oversized payloads.
- Mutate every operation-core field, entry-core field, state version, prior link, transition
  payload, proof, and inclusion proof independently; each mutation must either change the proper
  digest and fail the old proof or fail canonical decoding. Explicitly reject recursive encodings
  in which an entry digest includes its own transition proof.
- Present arbitrary IDs, leading-zero/variable-width integers, alternate address/recipient forms,
  protobuf/serde TxOut bytes, reordered TxOut fields, aliased asset IDs, and alternate encodings of
  the same source event or real UTXO; independent derivation or canonical decoding must reject all
  aliases before operation acceptance/nonce allocation.
- Verify a malformed but validly identity-signed payload remains attributable; verify invalid identity signature returns `NotProvable`.
- Mutation test every manifest field, every ring member component, every response, each profile field, every signed envelope header, and every collection order; the relevant digest must change.
- Cross-network, cross-epoch, cross-input, cross-attempt, cross-profile, and cross-protocol replay must fail.

### 12.2 Honest cryptographic tests

- Retain M2b's all-real-index and all-qualifying-subset tests, including the 8-of-11 target policy.
- Run both row-1 algebra/ceremony profiles for all 11 real indices and at least all 2-of-3 subsets.
- Confirm stable key image across qualifying subsets.
- Confirm every participant equation independently and the final stock `RingMLSAG::verify` result.
- Integrate `CoreCustodyKnownZ` with a real two-input MobileCoin transaction; bind both input ceremonies to one unsigned-transaction digest and run stock signature/range-proof validation.
- In `PrivateThresholdZ`, instrument the process and assert no API/value contains complete `z`; inject/derive pseudo-mask shares rather than dealer-generating from complete `z`, and run the selected §2.4 mode's proof-worker/MPC/vNext acceptance and isolation tests before claiming a complete transaction.

### 12.3 Byzantine participant tests

For every included participant, independently mutate:

- identity key/index;
- registry verification share;
- key-image share;
- every row-0 commitment point;
- every row-1 commitment point in private mode;
- each mandatory consistency/knowledge proof;
- `s0` and `s1` independently;
- manifest, round-request, and round-set digests inside the signed payload;
- nonce-slot identifier and any field that changes the fixed semantic message slot.

Each validly signed invalid message must return the exact author. A forged/invalid identity signature must never fault that claimed author.

Add paired canceling-corruption vectors: mutate two bonded participants' `s0` values by
`+delta`/`-delta`, and separately their `s1` values, so the aggregate response and final MLSAG would
remain valid. Completion must still reject and the standalone verifier must identify both signed
invalid contributions.

In core mode, separately corrupt the row-1 authority's commitment/proof and `s1`; fault the authority, not a spend participant.

### 12.4 Coordinator-equivocation tests

- Same ceremony/attempt with two manifests.
- Same manifest with two `Round1Request` signer/ack sets.
- Same request with two round-1 bundles.
- Same round-1 bundle with two incompatible round-1 view-ack sets or round-2 requests.
- Same round-1 root with two round-2 bundles or final MLSAGs.
- `Completed` versus `Abort` for one transcript.
- Omit/replace an honest participant's signed message.

Two valid conflicting coordinator signatures must verify as coordinator evidence. Omission without a receipt must return `NotProvable`.

### 12.5 Crash and storage linearizability tests

Inject process death before and after every database commit, fsync, nonce erasure, and network send:

- atomic operation + ordered UTXO + child reservation acceptance;
- operation transition from accepted to authorized and from authorized to completed/expired;
- manifest validation;
- ack persistence/send;
- nonce CAS;
- round-1 persistence/send;
- round-1 bundle persistence;
- round-1 view-ack persistence/reliable broadcast;
- round-2 request persistence;
- round-2 persistence + nonce erasure/send;
- completion/abort.

After recovery, assert exact-byte retransmission or safe abort. Scan the entire database history and assert no nonce slot transitioned from `BOUND`/`CONSUMED` back to `AVAILABLE` and no slot is associated with two transcript roots. Also assert that operation acceptance is all-or-nothing across every ordered UTXO/child, no completed operation or UTXO association reopens, and no stale replica can authorize an alternate transaction. Restore stale backups and verify anti-rollback rejects them.

The scan includes DLEQ/Schnorr proof-randomness derivation labels/slots. Add cross-proof,
cross-row, cross-input, cross-attempt, and proof/signing-nonce alias mutants; each must fail before
any round-1 bytes leave the outbox.

### 12.6 Retry/liveness tests

- Missing signer before round 1 or after round 1 but before operation authorization: retire all old
  child slots and start a fresh child attempt with a different qualifying set.
- Missing signer after operation authorization: no signer-set/core substitution and no ordinary
  abort; resume the exact authorized transcript or remain locked until authenticated
  expiry/non-inclusion/cancellation permits a new top-level attempt.
- Missing coordinator before operation authorization: replacement coordinator starts a fresh child
  attempt. Missing coordinator after authorization: replacement may only rebroadcast/resume the
  exact authorized cores and persisted messages.
- Duplicate delivery and arbitrary reordering: idempotent handling, no additional share.
- Delayed old-attempt message after new attempt: reject without state regression.
- Two different ceremony IDs/request nonces for the same `(operation_id,input_spend_id)` cannot be
  live concurrently; after a newer attempt is accepted/completed, every older attempt remains stale
  across restart, backup restoration, coordinator replacement, fee/tombstone change, and ring change.
- Race two concurrent reservations with the same `operation_id` but different unsigned transaction
  digests, ordered inputs, and real UTXOs; exactly one compare-and-swap reaches `Accepted`, and no
  child of the loser reaches nonce allocation.
- Race two different claimed `operation_id` values/encodings derived from the same authenticated
  `source_event_id`; the unique source-event index and independent formula admit only the canonical
  operation family. Mutating destination economics changes the derived operation ID but cannot
  create a second family for the already indexed source event.
- Present the same consensus MobileCoin return nullifier under old/new policy IDs, roster epochs,
  and accepted protocol versions. Policy changes may alter the operation/core, but they cannot alter
  the source-event ID or bypass the raw `(network, return_nullifier)` unique index. Concurrent
  candidates serialize. A pre-authorization abort may rebind only through the monotone source-family
  transition with the old operation tombstoned; after authorization, every rebind rejects.
- Race two different operation IDs that contain the same global `utxo_spend_id`; exactly one reaches
  `Accepted`. Mutating the ordered input IDs, ordered UTXO IDs, operation attempt, or reservation
  digest after acceptance rejects before nonce allocation.
- Present two claimed `utxo_spend_id` values for the same ledger index/canonical real TxOut and two
  alternative encodings of that TxOut; all signers derive the same one ID and only one reservation
  reaches `Accepted`.
- Race `Accepted -> Aborted` against the operation-wide `Accepted -> Authorized` CAS while all child
  round-2 request cores are ready; exactly one transition wins. If authorization wins, no ordinary
  abort or replacement is accepted, even when the coordinator withholds every resulting share or a
  complete transaction signature.
- Crash after operation authorization and after receiving any strict subset of child round-2
  shares, including after the coordinator has secretly assembled a valid transaction but before it
  reports completion. Recovery keeps the operation non-abortable/nonreplaceable; a second input set
  cannot be signed, and only authenticated final inclusion or tombstone expiry/non-inclusion moves
  the state.
- Give different children different otherwise-valid authorization entries or omit one child core
  from the authorized list; every signer rejects before round-2 generation. All children must use
  the same core digest, state version, transition proof, and ordered child-core list.
- Mark an operation/destination release `Completed`, restart from every retained replica and a stale
  backup, change coordinator and roster generation, and verify that neither the operation nor any
  completed UTXO association can reopen.
- Construct two qualifying same-generation quorums and two cross-generation quorums whose
  intersection is entirely Byzantine. The shared linearizable journal still serializes exactly one
  operation attempt. Disable the journal and verify deployment validation rejects the configuration
  unless each actual quorum pair satisfies `|Q_a intersection Q_b| > f_intersection`; only the
  fixed-roster case may derive that bound from `2*t-n>f`.
- At least `t` responsive honest signers plus a responsive row-1 authority in core mode eventually complete under a fair, non-equivocating coordinator.
- Silence and partitions produce abort/availability records, never invalid-share evidence.

### 12.7 Evidence-verifier differential tests

- The online coordinator and standalone evidence verifier must agree on every generated valid/invalid transcript.
- Independently reconstruct equations from serialized bytes; do not reuse the coordinator's in-memory maps.
- A valid accused message plus signed false accusation selects the accuser only when the frozen governance rule enables false-accusation blame.
- All shares valid but final MLSAG invalid returns `InternalProtocolFailure`, never a participant.
- Fuzz the evidence parser and require deterministic `FaultSet`/`NotProvable`/`InternalProtocolFailure` results with no panic or participant blame from the internal-failure branch.

### 12.8 DKG/refresh/epoch tests

- Registry snapshot and local shares disagree: reject before nonce allocation.
- Mix old/new spend or mask verification shares: reject.
- Activate new epoch with ceremonies at every state; enforce the selected grace/abort rule and burn affected nonces.
- For private mode, prove mask-share derivation interpolates to `C_pseudo-C_input` without reconstructing `z`.
- If refresh is implemented, verify public-key preservation, zero aggregate refresh constant, exact invalid-dealer attribution, restart behavior, and old-share erasure.

## 13. Recommended implementation sequence

1. Implement the canonical codec, signed envelope, registry snapshot resolver, transcript digest functions, and standalone evidence verifier with golden vectors.
2. Wrap M2b in typed in-memory machines that accept/return signed bytes while preserving `StrictError` exactly.
3. Add durable nonce-slot/outbox storage and exhaustive crash injection before any real network transport.
4. Implement `CoreCustodyKnownZ` first as the minimum threshold-spend-custody profile, with a separately signed row-1 authority contribution.
5. Implement `PrivateThresholdZ` only after dealerless pseudo-mask shares exist. Start with
   `KnownInputMaskOffset`, applying the complete ceremony-confidential `b_input` only as the frozen
   Serai key offset; treat `FullyDistributedMasks` as stronger later hardening. Neither mode may
   promote the M3 materialize-then-share fixture.
6. If complete private-Z transaction integration is in scope, select and implement exactly one
   §2.4 range-proof witness mode; do not pass shared masks to stock `SigningData::new` and call that
   share-native.
7. Add the unsigned-transaction assembly API and terminal legacy `RingSigner` adapter.
8. Specify the new consensus-visible threshold authorization format separately. Do not call the result protocol-level/on-chain multisig until consensus rejects a valid ordinary MLSAG that lacks the required threshold authorization.

## 14. Narrow conclusion

The algebraic core is ready to be wrapped, but the production boundary is a DKG-like authenticated state machine, not a custom `RingSigner` implementation. The decisive M4 property is not merely “the aggregate tells us participant 7 was wrong.” It is “a standalone verifier can prove, from canonical bytes signed by participant 7 and a frozen registry/transcript, exactly which equation participant 7 violated, while crash recovery cannot reuse a nonce.”

That property is common to both row-1 profiles. Threshold-sharing `z` strengthens privacy; it does not replace the authenticated ceremony, and it must not be claimed if any coordinator first reconstructs `z`.
