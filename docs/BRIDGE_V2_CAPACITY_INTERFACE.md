# Bridge V2 synchronous core-to-capacity interface — replacement draft

> **STATUS: PROSPECTIVE / UNVERIFIED.** This is a review draft, not an
> acceptance result and not an active MobileCoin specification. No TLA+, Python,
> composition, scenario, or falsifier result may be inferred from it. It must be
> reconciled with the amended Bridge V2 acceptance contract, implemented
> independently in both models, rehashed, and exercised by the final runner
> before any status changes to `PASS`.

## 1. Purpose and normative boundary

This interface joins two responsibilities without weakening either:

- the **core** validates canonical requests, direction-specific cryptographic
  artifacts, typed source nullifiers, claims, verdicts, and exact penalties;
- the **capacity projection** validates inventory provenance, liability backing,
  reserved and finalized-but-uncleared exposure, generation lifecycle, correlated
  failure-domain limits, and collectible bonded capacity.

The capacity projection is an admission authority, not a post-hoc auditor. Every
transition that can change capital, source inventory, backing eligibility,
liability state, release exposure, `I_d`, `L_w`, `B_min[f,window]`, a bond window, a policy
pause, or a generation phase uses this logical transaction:

```text
PROPOSE(canonical_event, core_prestate, capacity_prestate)
    -> REJECT(exact_reason)                       # neither state commits
     | ACCEPT(acceptance_receipt, capacity_poststate)
          -> ATOMIC_COMMIT(core_poststate,
                           capacity_poststate,
                           canonical_event)
```

`ACCEPT` binds exactly one event hash, one core prestate commitment, one capacity
prestate commitment, and one derived capacity poststate commitment. It cannot be
replayed for another event or prestate. In the abstract state machine, acceptance
and commit are one atomic transition **within `event_chain_id`'s consensus
state**. An event that the capacity transition rejects never appears in that
chain's committed log and never changes a source nullifier, reserve position,
liability, bond, or release.

```text
AcceptanceReceipt = {
    acceptance_id, event_chain_id, event_hash,
    chain_sequence_no, prev_chain_event_hash,
    causal_event_refs_hash,
    core_state_hash_before, capacity_state_hash_before,
    core_state_hash_after, capacity_state_hash_after
}
```

All fields are recomputed inside the same local consensus transition. The receipt
is not valid evidence of a remote event and is never a substitute for a typed
`CausalEventRef`.

This interface does not assume an atomic transaction spanning Ethereum and
MobileCoin. Cross-chain safety uses immutable allocation manifests described in
section 7.3: each destination chain synchronously enforces its own reserved share,
while the profile-specific authenticated proof or explicit governance premise
supplies global manifest validity. The abstract product and composition runner
test that premise; they are never an activation oracle.

### 1.1 Reservation precedes every executable authorization

Capacity must be consumed in consensus before a destination spend or call can
become executable. The release path is therefore deliberately two-stage:

```text
OPEN_LIABILITY
    -> RESERVE_RELEASE_INTENT                 # consensus-recorded capacity first
         -> FINALIZE_RELEASE | safe CANCEL_PENDING_RELEASE
```

`RESERVE_RELEASE_INTENT` deterministically derives `reservation_id` from the
complete unsigned destination intent, liability, source nullifier, allocation
manifest, policy/generation, amount, and committed expiry/tombstone. It changes
the liability `Open -> CapacityReserved`, backing
`Available -> ReservedIntent`, and the claimed source nullifier
`Free -> Reserved` in one local consensus commit. It records full release risk
before any spend-capable MLSAG/FROST or Ethereum execution authorization is
usable. Bond-bound WARDEN and ACCOUNT receipts necessarily precede the
reservation. To prevent an unauthenticated request from locking bridge capacity,
the candidate carries the exact threshold of individually signed, bond-bound
WARDEN and ACCOUNT receipts under their distinct role domains, each binding the
same deterministic canonical digest `D` containing `reservation_id`. All
candidate capacity lots, MobileCoin key images, lease tags, exact destination
wire bytes, ring/pseudo-output/range-proof commitments, deadline, and
destination semantics are selected off chain before any state mutation, so `D`
is already acyclically derivable. `OPEN_LIABILITY` validates and stores those
exact D-bound receipt
references while acquiring the claim lock. `RESERVE_RELEASE_INTENT` revalidates
the byte-identical stored receipts and `D` while reserving exactly those already
committed candidates. WARDEN and ACCOUNT each emit one role-domain signature;
there is no second
source-versus-reservation approval domain whose signer set could differ. Those
receipts assume liability but cannot by themselves execute the destination spend
or call.

Every ownership MLSAG, MobileCoin FROST gate signature, Ethereum multisig
authorization, WARDEN approval, and ACCOUNT approval binds the same base
canonical digest containing that exact `reservation_id` and allocation-manifest
ID. MLSAG and the Ethereum native execution authorization verify the base `D`;
FROST, WARDEN, and ACCOUNT verify their respective domain-separated artifact
digest over `D`, role, and exact manifest ID. Thus one signature cannot satisfy
two roles even when an identity or public key legitimately overlaps roles.
There is deliberately no committed intermediate authorization state and no
consensus inference from a coordinator, mempool, or partial-signature
observation. After reservation, parties may construct signatures off chain, but
only the final MobileCoin `EscrowSpendTx` or Ethereum escrow `execute` call
validates the complete artifact bundle, rechecks the live reservation and active
policy epoch, and atomically commits `ReservedIntent -> Spent` plus
`CapacityReserved -> FinalizedUncleared`. It rejects a different digest, absent
or expired reservation, or stale allocation. If signing aborts after any
signature could exist, the consensus reservation remains live until a safe
cancellation proof establishes that the exact action is permanently
non-executable.

Unknown event kinds, unknown payload variants, malformed sentinels, failed field
derivations, stale manifests, and arithmetic overflow reject closed.

## 2. Truth and source-chain boundary

Neither `ObjectiveSourceHistory` nor `GroundTruthFault` is a field, derivation
input, or admission guard in this interface. A signed source assertion can open a
liability and, with all mandatory quorums, reach a false destination release even
when no matching source inflow exists. Capacity admission therefore does not
silently repair false attestation by consulting ghost truth.

An actual source-escrow transition is different from a signed assertion. Its
local bridge deposit/typed-return inclusion atomically commits
`RECORD_ESCROW_SOURCE_INFLOW` and creates an `EncumberedSource` position:

- an `ETH_TO_MOB` inflow is USDC held by the Ethereum escrow;
- a `MOB_TO_ETH` inflow is an eUSD output held by the MobileCoin escrow.

The event is generated by source-chain consensus, not a warden claim or
ghost-history lookup. It carries no claim that its own inclusion is already
final; a same-chain reorg removes both the deposit/return and its capacity
projection together. Its presence is **not** required to authorize the
destination release. It creates encumbered, never free, capital. A later
`PROMOTE_SETTLED_SOURCE_INFLOW` requires typed finalized causal evidence for
both this exact local inflow and the paired remote `FINALIZE_RELEASE`/clearance.
Only an exact match to a settled paired liability can promote it to reusable
inventory. A false assertion can therefore cause bounded outflow but cannot mint
phantom backing.

`ClaimedLiability` and `SourceInventory` are independent state maps. None of
`OPEN_LIABILITY`, `RESERVE_RELEASE_INTENT`, or `FINALIZE_RELEASE` requires a
matching source-inventory position, objective source proof, public checkpoint,
or ghost fact. Their only source-side input is the immutable signed `SourceAssertion`
inside the canonical digest. This keeps a fully signed false assertion reachable,
including `MOB_TO_ETH/V1`. In the honest cycle, a matching real encumbered source
position becomes Available only after the paired liability settles. In the false
cycle, settlement succeeds within the cap but promotes no source value.

`RECORD_ESCROW_SOURCE_INFLOW` is itself capacity-affecting and must preserve the
active chain/asset/direction allocation and every failure-domain cap. Its source
adapter verifies the canonical source escrow, typed event/output locator,
asset/amount, same-chain inclusion, and exact-once position ID. A forged adapter
event or checkpoint is a model/implementation defect even though release
admission remains truth-independent. A direct or unsolicited MobileCoin transfer
that lacks an accepted typed `BridgeReturn`/intent, and an ERC-20 transfer that
bypasses the bridge deposit method, creates neither a customer liability nor
eligible reusable inventory. Once detected it is tracked separately as
ineligible external holdings and cannot make a capacity check pass.

Public checkpoints and source proofs may enter `CLEAR_FINALIZED_RISK` or
`FAULT_BOND_FREEZE`; they never enter `OPEN_LIABILITY`,
`RESERVE_RELEASE_INTENT`, or `FINALIZE_RELEASE`. If MobileCoin v2 promises automatic proof for an
absent return, its checkpoint commits an authenticated dictionary supporting
both membership and non-membership proofs. A plain receipt inclusion tree is
insufficient for that claim.

The v2 authenticated dictionary has distinct typed key spaces for both
`BridgeReturnReceipt(source_nullifier)` and
`BridgeReleaseReceipt(release_id, reservation_id)`. The former supports proving
whether eUSD entered the MobileCoin escrow; the latter supports proving whether
an eUSD destination release finalized. Membership and non-membership statements
bind the MobileCoin block/checkpoint, policy epoch, canonical event bytes, and
finality rule. A v1 deployment without this receipt map cannot relabel a
contractual warden/adjudicator assertion as an automatically verifiable fact.

## 3. Canonical immutable envelope

Every committed event has the following **31 top-level fields**. Each identifier
occupies a distinct finite type. A field that is inapplicable to an event contains
its type-specific `ABSENT_*` sentinel; it is never omitted or inferred later from
mutable state.

```text
CapacityEvent = {
    schema_version,             # 1
    bridge_id,                  # 2
    event_id,                   # 3
    proposal_id,                # 4
    acceptance_id,              # 5
    event_chain_id,             # 6: ETHEREUM | MOBILECOIN
    chain_sequence_no,          # 7
    prev_chain_event_hash,      # 8
    causal_event_refs,          # 9: canonical ordered set of CausalEventRef
    event_hash,                 # 10
    kind,                       # 11
    producer,                   # 12
    producer_action,            # 13
    chain_logical_time,         # 14: metadata; never a global ordering oracle
    direction,                  # 15: ETH_TO_MOB | MOB_TO_ETH | ABSENT_DIRECTION
    protocol_version,           # 16
    policy_id,                  # 17
    policy_epoch,               # 18
    generation_id,              # 19
    release_id,                 # 20
    liability_id,               # 21
    reservation_id,             # 22
    source_nullifier,           # 23
    canonical_digest,           # 24
    risk_window_id,             # 25
    manifest_bundle_id,         # 26
    core_state_hash_before,     # 27
    core_state_hash_after,      # 28
    capacity_state_hash_before, # 29
    capacity_state_hash_after,  # 30
    payload                     # 31: exactly one typed payload variant
}
```

Each causal edge is itself immutable and typed:

```text
CausalEventRef = {
    event_chain_id,
    event_hash,
    chain_sequence_no,
    evidence_kind,
    evidence_body,
    verifier_manifest_id
}

evidence_kind in {
    SAME_CHAIN,
    CHECKPOINT,
    FINALITY_PROOF,
    ROLE_ATTESTATION
}

SAME_CHAIN body = {
    expected_local_prefix_hash
}

CHECKPOINT body = {
    checkpoint_chain_id, checkpoint_id, checkpoint_height,
    authenticated_state_root, typed_inclusion_or_noninclusion_key,
    proof_commitment, checkpoint_finality_ref
}

FINALITY_PROOF body = {
    consensus_protocol_id, finalized_block_id, finalized_height,
    event_inclusion_proof_commitment, consensus_finality_proof_commitment
}

ROLE_ATTESTATION body = {
    attestation_domain, attested_event_digest, ordered_signer_ids,
    ordered_signature_commitments, roster_manifest_id, threshold,
    attestation_expiry
}
```

`causal_event_refs` is the canonical lexicographically ordered, duplicate-free
set of prior events whose effects this event consumes. A same-chain reference
must already be in the local committed prefix. A cross-chain reference must be
validated according to exactly one closed evidence variant and must name the
exact remote chain, sequence, event hash, and committed event bytes. Evidence
kind and body must agree; an unknown kind, mixed body, wrong verifier, stale
attestation, insufficient role threshold, or proof for another event rejects.
`ROLE_ATTESTATION` is allowed only where the selected profile explicitly declares
that operational trust boundary. Neither a coordinator assertion nor an
unauthenticated product-replay observation is a valid causal edge.

The immutable `ManifestBundle` contains exactly these content-addressed
references:

```text
ManifestBundle = {
    owner_manifest,
    gate_manifest,
    ethereum_escrow_manifest,
    warden_manifest,
    accountability_manifest,
    bond_manifest,
    failure_domain_manifest,
    valuation_and_cap_manifest,
    capacity_allocation_manifest
}
```

The `accountability_manifest` fixes the fault-verdict rules, typed remote-proof
adapters, contractual adjudicators, and exact signer liability. The
`owner_manifest` content-addresses the allowed threshold ownership protocol,
per-output VSS/MPC share-provisioning manifests, and reserve-accounting backend
manifests; the intent's selected IDs must be members of that immutable allowlist.
They are not a tenth mutable bundle reference. The
`valuation_and_cap_manifest` and `capacity_allocation_manifest` jointly fix the
detection, proof-delivery/fairness, local inclusion/finality, and pause-propagation
bounds used to compute maximum fault-delay exposure. Changing any such bound
requires a new content hash and delayed activation; it is not mutable runtime
metadata.

There are **12 payload schemas**:

1. `AuthorityPayload`
2. `GenerationPayload`
3. `CapitalPayload`
4. `SourceInflowPayload`
5. `LiabilityPayload`
6. `ReleasePayload`
7. `RiskClearancePayload`
8. `IncidentPayload`
9. `BondPayload`
10. `PenaltyPayload`
11. `RotationPayload`
12. `CapValuationAllocationPayload`

### 3.1 Canonical hashing and partial ordering

```text
event_id  = H("BRIDGE_CAPACITY_EVENT_V2", bridge_id, event_chain_id,
              producer_action,
              canonical primary object ID, transition ordinal)

CanonicalProposalBody = CanonicalEncode({
    schema_version, bridge_id, event_id,
    event_chain_id, chain_sequence_no, prev_chain_event_hash,
    causal_event_refs, kind, producer, producer_action, chain_logical_time,
    direction, protocol_version, policy_id, policy_epoch, generation_id,
    release_id, liability_id, reservation_id, source_nullifier,
    canonical_digest, risk_window_id, manifest_bundle_id, payload
})

proposal_id = H("BRIDGE_CAPACITY_PROPOSAL_V2", CanonicalProposalBody)

core_state_hash_before/after = H(
    "BRIDGE_CORE_SEMANTIC_PROJECTION_V2",
    canonical core semantic maps before/after the provisional transition
)

capacity_state_hash_before/after = H(
    "BRIDGE_CAPACITY_SEMANTIC_PROJECTION_V2",
    canonical capacity semantic maps before/after the provisional transition
)

acceptance_id = H(
    "BRIDGE_CAPACITY_ACCEPTANCE_V2",
    proposal_id, event_id, event_chain_id,
    chain_sequence_no, prev_chain_event_hash, H(causal_event_refs),
    core_state_hash_before, core_state_hash_after,
    capacity_state_hash_before, capacity_state_hash_after
)

EventEnvelope = CanonicalEncode(the exact 31-field CapacityEvent,
    with proposal_id and acceptance_id set as above,
    core_state_hash_before/after set as above,
    capacity_state_hash_before/after set as above,
    event_hash = ZERO_EVENT_HASH)

event_hash = H("BRIDGE_CAPACITY_EVENT_BYTES_V2", event_chain_id,
               EventEnvelope)

AcceptanceReceiptBytes = CanonicalEncode(AcceptanceReceipt including event_hash)
```

`EventEnvelope` reconstitutes the 31 scalar/aggregate fields in the exact
declared `CapacityEvent` order; it does **not** encode `CanonicalProposalBody` as
one nested blob followed by the excluded fields. `ZERO_EVENT_HASH` is the unique
fixed-width all-zero value of the `EventHash` type and is used only in the
`event_hash` slot for this computation. No other envelope field is zeroed,
omitted, or replaced for event hashing. Consensus stores the populated event
containing the computed hash, but never recursively rehashes those populated
bytes as `EventEnvelope`.

The semantic projection hashes explicitly exclude both append-only event logs,
all proposal/acceptance-receipt stores, consensus block/header roots, and the
currently staged event/receipt. They include every safety-relevant semantic map
(lots, liabilities, nullifiers, leases, risk, bonds, policies, generations, and
manifests). After `event_hash` is computed, consensus appends the event and stores
the receipt; neither resulting log/root hash feeds back into an envelope field.
`acceptance_id` excludes `event_hash` and receipt bytes. The receipt is the only
object in this DAG that contains `event_hash`, and nothing hashed by the event
contains the receipt. An implementation that instead hashes its full poststate
root must define and verify an equivalent zero-current-event/zero-current-receipt
convention; otherwise it is nonconforming.

For each `event_chain_id` independently, `chain_sequence_no` is the previous
committed local number plus one and `prev_chain_event_hash` equals that chain's
preceding event hash. Each chain has a distinct genesis sentinel. There is no
global `sequence_no`, no global previous-event hash, and no shared ETH+MobileCoin
event ledger. An identical rebroadcast returns the historical local result
without appending. Reusing an `event_id`, `proposal_id`, or `acceptance_id` with
different bytes rejects. Deletion, duplication, mutation, and same-chain
reordering must change the local log commitment or violate an event precondition.

The product history is the causal partial order generated by (a) each chain's
local predecessor edges and (b) authenticated `causal_event_refs`. A valid
global audit view is a causally closed cut, not an arbitrary pair of local
prefixes and not one privileged total order. The runner explores every relevant
linear extension of that partial order, or proves that omitted permutations
commute because their events touch disjoint typed state. Two concurrent events
that contend for the same liability, nullifier, capacity lot, input-lease
tag, reservation, allocation segment, bond, or policy state do not commute and
must be explored.

### 3.2 Deterministic fields are verified, not trusted

The capacity transition recomputes and byte-compares every derived field:

- `event_chain_id` from the event kind, producer, and state objects mutated;
- `chain_sequence_no` and `prev_chain_event_hash` from that chain's committed
  prefix, and every mandatory causal reference from the effects consumed;
- `source_nullifier` from the canonical **claimed** source identity bytes carried
  in `SourceAssertion`, without looking up whether that event/output exists;
- `liability_id` from bridge, direction, source nullifier, assets, amounts, and
  canonical destination obligation;
- `reservation_id` from the complete unsigned intent, committed deadline,
  destination chain, liability, and capacity-allocation manifest;
- `release_id` and `canonical_digest` from the complete settlement request;
- capacity-lot IDs from the capitalization/provenance event, deterministic lot
  split ordinal, chain, generation, asset, native amount, and risk value;
- MobileCoin canonical key images from the verified pre-intent threshold
  key-image/DLEQ transcript, then input-lease tags from those canonical bytes and
  the network genesis domain at reservation and again at finalization, without
  inferring the private real ring member;
- risk-position IDs from the unique public capacity lot and risk window,
  not from a retry or role name;
- role signer sets from already-validated ordered distinct signature slots;
- failure domains from the immutable failure-domain manifest;
- native-asset and common-risk values from the immutable valuation manifest;
- slashable bond positions from the historical bond manifest and exact visible
  liable approval identities; and
- phase, liability, release, and position pre/post states from current immutable
  records.

An event cannot choose a smaller failure-domain set, a larger valuation, a
different quorum, or a duplicated bond/lot/tag ID to make an invariant pass.

The reservation and signing digests have this acyclic construction order. A
commitment to selected fields is never substituted for the destination
verifier's actual wire object.

```text
source_chain_id, destination_chain_id = ExactChainIds(direction,
    ethereum_chain_id, mobile_network_genesis_id)

source_assertion_commitment = H(
    "BRIDGE_SOURCE_ASSERTION_V2", CanonicalEncode(SourceAssertion))

MobilePreReservationTxPrefix = exact canonical vNext TxPrefix wire object {
    inputs: ordered full TxIn values, including every ordered ring TxOut,
            membership proof, and input_rules value,
    outputs: ordered full TxOut values, including masked amount, target/public
             keys, fog hint, memo, spend_policy_id, and
             bridge_lot_commitment_or_absent,
             threshold_witness_package_commitment_or_absent,
    fee, tombstone_block, fee_token_id,
    bridge_extension: {
        network_genesis_id, bridge_id, direction, policy_id, policy_epoch,
        generation_id, liability_id, source_nullifier,
        capacity_allocation_manifest_id,
        reservation_id = ZERO_RESERVATION_ID
    }
}

EthereumPreReservationExecute = exact canonical EIP-712 Execute value {
    reservation_id = ZERO_RESERVATION_ID,
    policy_id, policy_epoch, generation_id, liability_id, source_nullifier,
    token, amount, recipient, fee_or_call_value, escrow_contract_nonce,
    deadline, capacity_allocation_manifest_id, calldata_hash
}

destination_pre_reservation_object_commitment =
    (destination_chain == MOBILECOIN)
      ? H("BRIDGE_MOBILE_PRERESERVATION_TXPREFIX_V2",
          network_genesis_id, block_version,
          CanonicalEncode(MobilePreReservationTxPrefix),
          pseudo_output_commitments, range_proof_commitments)
      : H("BRIDGE_ETH_PRERESERVATION_EXECUTE_V2",
          CanonicalEncode(EthereumPreReservationExecute))

PreIntentKeyImageContext = {
    network_genesis_id, block_version,
    destination_pre_reservation_object_commitment,
    owner_manifest_id, ownership_equality_profile,
    ownership_share_provisioning_profile,
    ownership_share_package_ids,
    ordered_input_ordinals, ring_set_commitments
}

(canonical_key_images, pre_intent_key_image_transcript_commitments) =
    (destination_chain == MOBILECOIN)
      ? ThresholdAggregateKeyImagesAndDleqShares(
            "BRIDGE_PREINTENT_KEY_IMAGE_DLEQ_V2",
            CanonicalEncode(PreIntentKeyImageContext),
            fresh durable pre-intent nonce records)
      : (ABSENT_KEY_IMAGE_VECTOR, ABSENT_KEY_IMAGE_TRANSCRIPT_VECTOR)

input_lease_tags =
    Map(canonical_key_images,
        ki -> H("MC_INPUT_LEASE_TAG_V1", network_genesis_id,
                canonical_key_image_bytes(ki)))

IntentBindingCore = {
    bridge_id, destination_chain, direction,
    source_chain_id, destination_chain_id,
    mobile_network_genesis_id_or_absent,
    mobile_block_version_or_absent,
    ethereum_chain_id_or_absent,
    policy_id, policy_epoch, generation_id, liability_id, source_nullifier,
    source_assertion_commitment,
    destination_asset_and_amount, recipient, fee_or_value,
    committed_tombstone_or_expiry,
    destination_pre_reservation_object_commitment,
    capacity_lot_ids, canonical_key_images, input_lease_tags,
    pre_intent_key_image_transcript_commitments,
    spend_policy_id, bridge_lot_commitments,
    ring_set_commitments, pseudo_output_commitments,
    range_proof_commitments,
    ownership_equality_profile,
    ownership_share_provisioning_profile,
    ownership_share_package_ids,
    accounting_backend_profile,
    accounting_backend_manifest_id,
    output_classification_commitments, gross_lot_depletion_commitment,
    manifest_bundle_id, capacity_allocation_manifest_id
}

unsigned_intent_commitment =
    H("BRIDGE_UNSIGNED_INTENT_V2", CanonicalEncode(IntentBindingCore))

reservation_id = H(
    "BRIDGE_RESERVATION_V2",
    bridge_id, destination_chain, direction, policy_id, policy_epoch,
    generation_id, liability_id, source_nullifier,
    unsigned_intent_commitment,
    committed_tombstone_or_expiry,
    manifest_bundle_id, capacity_allocation_manifest_id
)

FinalTxPrefix = ReplaceTypedReservationId(
    MobilePreReservationTxPrefix, ZERO_RESERVATION_ID, reservation_id)

FinalEthereumExecute = ReplaceTypedReservationId(
    EthereumPreReservationExecute, ZERO_RESERVATION_ID, reservation_id)

final_destination_object_commitment =
    (destination_chain == MOBILECOIN)
      ? H("BRIDGE_MOBILE_FINAL_TXPREFIX_V2", CanonicalEncode(FinalTxPrefix))
      : H("BRIDGE_ETH_FINAL_EXECUTE_V2", CanonicalEncode(FinalEthereumExecute))

final_tx_prefix_commitment =
    (destination_chain == MOBILECOIN)
      ? final_destination_object_commitment
      : ABSENT_MOBILECOIN_FINAL_PREFIX_COMMITMENT

(D_MOB, DerivedTxSummary, DerivedExtendedMessageDigest) =
    (destination_chain == MOBILECOIN)
      ? compute_mlsag_signing_digest_vNext(
            network_genesis_id,
            block_version,
            FinalTxPrefix,
            exact pseudo_output_commitments,
            exact legacy_range_proof_bytes_or_empty,
            exact ordered_range_proofs_or_empty)
      : ABSENT_MOBILECOIN_DIGEST_TUPLE

derived_tx_summary_hash =
    (destination_chain == MOBILECOIN)
      ? H("BRIDGE_DERIVED_MOBILE_TX_SUMMARY_V2",
          CanonicalEncode(DerivedTxSummary))
      : ABSENT_DERIVED_MOBILE_TX_SUMMARY_HASH

derived_extended_message_digest =
    (destination_chain == MOBILECOIN)
      ? exact bytes of DerivedExtendedMessageDigest
      : ABSENT_DERIVED_EXTENDED_MESSAGE_DIGEST

D_ETH = (destination_chain == ETHEREUM)
      ? EIP712Hash(
            domain = {destination_chain_id, escrow_contract,
                      bridge_id, protocol_version},
            Execute = FinalEthereumExecute)
      : ABSENT_ETHEREUM_DIGEST

D = (destination_chain == MOBILECOIN) ? D_MOB : D_ETH

RoleArtifactDigest(role, role_manifest_id, D) = H(
    "BRIDGE_ROLE_ARTIFACT_V2", role, role_manifest_id, D)

FrostGateDigest(gate_manifest_id, D) = H(
    "MOBILECOIN_BRIDGE_FROST_GATE_V2", gate_manifest_id, D)

M_WARDEN = RoleArtifactDigest(WARDEN, warden_manifest_id, D)
M_ACCOUNT = RoleArtifactDigest(ACCOUNT, account_role_manifest_id, D)
M_GATE = (destination_chain == MOBILECOIN)
      ? FrostGateDigest(gate_manifest_id, D)
      : ABSENT_FROST_GATE_MESSAGE

ReserveInputStatementCore = {
    network_genesis_id, block_version, reservation_id, canonical_digest = D,
    spend_policy_id,
    destination_pre_reservation_object_commitment,
    final_tx_prefix_commitment,
    ring_set_commitments, pseudo_output_commitments, range_proof_commitments,
    derived_tx_summary_hash, derived_extended_message_digest,
    output_classification_commitments,
    ordered_canonical_key_images, ordered_input_lease_tags,
    pre_intent_key_image_transcript_commitments,
    ordered_capacity_lot_ids, gross_lot_depletion_commitment,
    protocol_fee_commitment, native_amount_and_risk_commitment,
    ownership_equality_profile,
    ownership_share_provisioning_profile, ownership_share_package_ids,
    accounting_backend_profile, accounting_backend_manifest_id,
    zk_circuit_id_or_absent, zk_verifying_key_id_or_absent,
    enclave_measurement_or_absent,
    enclave_attestation_chain_commitment_or_absent,
    enclave_freshness_checkpoint_or_absent
}

ThresholdOwnershipEqualityProofDigest = H(
    "BRIDGE_THRESHOLD_MLSAG_OWNERSHIP_EQUALITY_V2",
    D, CanonicalEncode(ReserveInputStatementCore)
)

ReserveAccountingProofDigest = H(
    "BRIDGE_RESERVE_ACCOUNTING_V2",
    accounting_backend_profile,
    accounting_backend_manifest_id,
    D, CanonicalEncode(ReserveInputStatementCore)
)

ReserveInputProofDigest = H(
    "BRIDGE_NONSPEND_RESERVE_INPUT_BUNDLE_V2",
    D, ThresholdOwnershipEqualityProofDigest, ReserveAccountingProofDigest
)

ReserveOwnershipChallengeTranscript = NewTranscript(
    "BRIDGE_THRESHOLD_MLSAG_OWNERSHIP_EQUALITY_CHALLENGE_V2",
    network_genesis_id, block_version, reservation_id,
    ReserveInputProofDigest, canonical ring and point encodings)

ownership_equality_proof_commitment = H(
    "BRIDGE_RESERVE_OWNERSHIP_PROOF_BYTES_V2", exact ownership proof bytes)

accounting_proof_or_attestation_commitment = H(
    "BRIDGE_RESERVE_ACCOUNTING_PROOF_BYTES_V2", exact accounting artifact bytes)

bundle_commitment = H(
    "BRIDGE_RESERVE_INPUT_BUNDLE_BYTES_V2",
    CanonicalEncode(ReserveInputStatementCore),
    ownership_equality_proof_commitment,
    accounting_proof_or_attestation_commitment)

RoleApprovalReceipt = {
    role, role_manifest_id, identity_id, role_public_key_id,
    base_destination_digest = D,
    role_artifact_digest = RoleArtifactDigest(role, role_manifest_id, D),
    signature_bytes
}

role in { WARDEN, ACCOUNT }
```

The MobileCoin pre-reservation object is the actual proposed wire prefix with
one typed zero placeholder; it is not `CanonicalEncode(IntentBindingCore)` and
cannot replace full ring members, membership proofs, outputs, or any other wire
field with a storage commitment. The commitment vector for range proofs is
computed over the exact block-version-selected representation. Before the
signing digest is derived, every supplied byte string must open that vector and
the legacy single-proof/multiple-proof alternatives must satisfy the same
empty/non-empty rule as MobileCoin consensus.

For MobileCoin, the exact zero-ID prefix/rings and threshold witness packages
are fixed before the pre-intent key-image ceremony. Participants use fresh
durable nonces under `BRIDGE_PREINTENT_KEY_IMAGE_DLEQ_V2`, publish canonical
key-image/DLEQ shares bound to `PreIntentKeyImageContext`, and verify every share
before aggregation. The resulting ordered canonical key images, lease tags, and
transcript commitments are ancestors in `IntentBindingCore`. This ceremony uses
neither `reservation_id` nor `D`, emits no spend authorization, and cannot be
rerun with a different set while retaining the old transcript commitment. Thus
key-image aggregation precedes the reservation/signing DAG instead of depending
on its own descendant digest.

`IntentBindingCore` and `unsigned_intent_commitment` exclude `reservation_id`,
the final destination object, and every signature or proof that signs or proves
a descendant digest. The typed zero is replaced exactly once; a zero or second
replacement rejects. MobileCoin consensus also requires
`network_genesis_id` to equal its local immutable genesis ID, and the vNext
digest domain binds that value. `destination_chain = MOBILECOIN` alone is not a
network replay boundary.

`ReserveInputStatementCore` contains no proof bytes, proof commitment, or
`bundle_commitment`; those three descendants are computed only after both
statement digests. They are not included and then zeroed by convention. The
reserve ownership verifier initializes the distinct top-level
`BRIDGE_THRESHOLD_MLSAG_OWNERSHIP_EQUALITY_CHALLENGE_V2` transcript. It never delegates its
challenge to, aliases, or accepts bytes under MobileCoin's spend-domain
`mc_ring_mlsag_challenge`, even if lower-level point operations are shared. The
ordinary RingMLSAG verifier rejects the reserve artifact type before parsing
responses, and the reserve verifier symmetrically rejects an ordinary spend
signature.
For a MobileCoin intent, the ownership, mask-share-provisioning, and accounting
backend profile/manifest fields are mandatory and are ancestors of
`unsigned_intent_commitment`, `reservation_id`, and `D_MOB`; Ethereum uses typed
absent sentinels. No coordinator may swap a VSS/MPC or ZK/SGX backend after role
approval.

`DerivedTxSummary` is constructed internally by
`compute_mlsag_signing_digest_vNext` from the final prefix and pseudo outputs,
exactly as selected by the block version. It is not an input commitment in
`IntentBindingCore` or `FinalTxPrefix`. A stored `derived_tx_summary_hash` or
`DerivedExtendedMessageDigest` is a recomputed descendant only and feeds no
ancestor. This prevents the fixed point that would result from asking a prefix
to commit to the summary derived from that same prefix. The vNext `TxSummary`
derivation itself includes the new bridge-extension, policy/lot, and threshold-
witness-package fields (or their exact typed summaries) so hardware/signature
verification cannot display or bind a legacy projection that omits them.

WARDEN and ACCOUNT sign their respective `RoleArtifactDigest` before
`OPEN_LIABILITY`; Open validates and stores the canonical ordered receipt
references, and Reserve revalidates the identical bytes without requesting
another approval signature. A role manifest binds each ordered slot to one
unique `(role, identity_id, public_key)` tuple and rejects duplicate identities
or public keys within that role. Cross-role identity/key overlap, where policy
permits it, still requires a fresh signature under each distinct role digest.
FROST signs `FrostGateDigest`; native MLSAG and Ethereum execution verify `D`.
All artifacts therefore bind the identical direction-specific base `D` without
making their signature bytes interchangeable.

The two `ReserveInputProof` artifacts prove their distinct non-spend digests.
The later
MLSAG/FROST or Ethereum execution artifact is valid only after the reservation
commits. No signature, proof bytes, receipt ID, transaction ID, derived summary,
or extended-message result feeds an ancestor digest. A cyclic or fixed-point
encoding is invalid even if some implementation happens to serialize it.

For MobileCoin, `D_MOB` is the first exact output of the vNext implementation
of `compute_mlsag_signing_digest`; it is not merely a hash of `TxPrefix`.
The actual final prefix, pseudo outputs, and every range-proof byte are consumed
exactly as the block-version rule requires; `DerivedTxSummary` is produced and
bound internally by that same algorithm. For Ethereum, `D_ETH` is the exact
escrow execution EIP-712 digest. `ReserveInputProof` bytes are deliberately
excluded from `D`; only its separate public statement commits to `D` under the
non-spend proof domain.

For every release-path `CapacityEvent`, top-level `canonical_digest` is this
direction-specific base `D`. Role receipts/artifacts carry `M_WARDEN`,
`M_ACCOUNT`, or `M_GATE` in their payload fields and never replace the event's
base digest with a role wrapper.

### 3.3 Exact payload field sets

Payload encoding is a closed tagged union. Within a selected variant every field
below is present; an inapplicable member contains its typed sentinel. Lists are
canonically sorted by their declared typed key and reject duplicates.

```text
AuthorityPayload = {
  authority_kind, authority_key_id, ordered_roster, threshold,
  ordered_identity_role_key_bindings,
  allowed_share_provisioning_manifest_ids,
  allowed_accounting_backend_manifest_ids,
  participant_key_commitments, ceremony_id, dkg_transcript_hash,
  effective_checkpoint, retirement_checkpoint_or_absent
}

GenerationPayload = {
  phase_before, phase_after, predecessor_generation_or_absent,
  authority_event_refs, capacity_lot_ids, bond_manifest_id,
  allocation_manifest_id, outstanding_liability_ids,
  outstanding_reservation_ids, outstanding_risk_position_ids
}

CapitalPayload = {
  capitalization_kind, external_allocation_ref_or_absent,
  predecessor_event_ref_or_absent, consumed_capacity_lot_ids,
  created_capacity_lot_ids, asset_id, native_amounts, risk_values,
  policy_output_creation_kind_or_absent, created_txout_commitments,
  spend_policy_ids_or_absent, bridge_lot_commitments,
  threshold_witness_package_commitments,
  eligibility_class, custody_locators, position_states_before,
  position_states_after
}

SourceInflowPayload = {
  source_chain, canonical_escrow_id, adapter_manifest_id, source_event_kind,
  source_event_locator, source_inclusion_commitment,
  asset_id, native_amount, risk_value, source_position_id, capacity_lot_id,
  policy_output_creation_kind_or_absent,
  source_txout_commitment_or_absent, spend_policy_id_or_absent,
  bridge_lot_commitment_or_absent,
  threshold_witness_package_commitment_or_absent,
  paired_liability_id_or_absent, eligibility_class,
  position_state_before, position_state_after
}

LiabilityPayload = {
  source_assertion, source_assertion_commitment, source_receipt_locator,
  destination_chain, mobile_network_genesis_id_or_absent,
  mobile_block_version_or_absent,
  ethereum_chain_id_or_absent,
  obligation_asset_id, obligation_native_amount,
  obligation_risk_value, recipient, fee_or_call_value,
  unsigned_intent_commitment,
  destination_pre_reservation_object_commitment,
  final_destination_object_commitment,
  capacity_lot_ids, input_lease_tags,
  pre_intent_key_image_transcript_commitments,
  reserve_input_proof_or_absent,
  ring_set_commitments, pseudo_output_commitments,
  range_proof_commitments, output_classification_commitments,
  gross_lot_depletion_commitment,
  ownership_equality_profile_or_absent,
  ownership_share_provisioning_profile_or_absent,
  ownership_share_package_ids,
  accounting_backend_profile_or_absent,
  accounting_backend_manifest_id_or_absent,
  warden_receipt_refs,
  account_receipt_refs,
  liability_state_before, liability_state_after,
  claimed_liability_binding_before, claimed_liability_binding_after
}

ReleasePayload = {
  destination_chain, mobile_network_genesis_id_or_absent,
  mobile_block_version_or_absent,
  ethereum_chain_id_or_absent, unsigned_intent_commitment,
  destination_pre_reservation_object_commitment,
  final_destination_object_commitment,
  local_allocation_segment_id,
  committed_deadline, spend_policy_id_or_absent,
  created_txout_commitments, created_output_policy_classes,
  threshold_witness_package_commitments,
  capacity_lot_ids, ordered_canonical_key_images, input_lease_tags,
  pre_intent_key_image_transcript_commitments,
  ring_set_commitments, pseudo_output_commitments, range_proof_commitments,
  ownership_equality_profile_or_absent,
  ownership_share_provisioning_profile_or_absent,
  ownership_share_package_ids,
  accounting_backend_profile_or_absent,
  accounting_backend_manifest_id_or_absent,
  derived_tx_summary_hash_or_absent,
  derived_extended_message_digest_or_absent,
  output_classification_commitments, gross_lot_depletion_commitment,
  reserve_input_proof_commitment_or_absent,
  warden_receipt_refs,
  account_receipt_refs, owner_mlsag_artifact_or_absent,
  frost_gate_artifact_or_absent, ethereum_multisig_artifact_or_absent,
  destination_finality_receipt_or_absent, safe_cancellation_proof_or_absent,
  release_state_before, release_state_after,
  source_nullifier_state_before, source_nullifier_state_after,
  input_lease_states_before, input_lease_states_after,
  capacity_lot_states_before, capacity_lot_states_after
}

RiskClearancePayload = {
  risk_position_ids, clearance_kind, policy_deadlines,
  proof_or_checkpoint_refs, verdict_id_or_absent,
  realized_loss_state_before, realized_loss_state_after,
  loss_fixed, local_allocation_usage_before, local_allocation_usage_after
}

IncidentPayload = {
  incident_id, incident_kind, affected_position_ids,
  affected_liability_ids, affected_reservation_ids, affected_release_ids,
  affected_failure_domains, state_before_by_object, state_after_by_object,
  observation_or_proof_commitment
}

BondPayload = {
  identity_id, bond_position_ids, bond_asset_ids, native_amounts,
  pre_haircut_risk_values, collectible_risk_values, lock_start,
  maximum_release_not_before, bound_policy_epochs, bound_risk_window_ids,
  bond_states_before, bond_states_after
}

PenaltyPayload = { exact fields in section 8 }

RotationPayload = {
  affected_policy_epoch, old_manifest_ids, new_manifest_ids,
  old_gate_key_id, new_gate_key_id, dkg_transcript_hash,
  ordered_new_roster, threshold, excluded_identity_ids,
  remote_fault_causal_ref_or_absent, role_attestation_ref_or_absent,
  local_activation_checkpoint
}

CapValuationAllocationPayload = {
  manifest_operation, deployment_profile, proposed_manifest_id,
  predecessor_manifest_or_absent,
  valuation_table, haircut_table, per_asset_domain_caps,
  common_risk_domain_caps, chain_direction_generation_segments,
  segment_native_allocations, segment_risk_allocations,
  detection_and_pause_propagation_bounds,
  activation_not_before_by_chain, retirement_not_before_by_chain,
  local_activation_checkpoint_or_absent, remote_activation_refs,
  proof_carrying_remote_state_or_absent,
  governance_assumption_attestation_or_absent,
  conservative_stagger_union
}
```

Each variant has a normative field-derivation table in the executable test
manifest. A conforming implementation recomputes all identifiers, amounts,
state transitions, signer sets, causal references, and before/after commitments;
parsing a well-typed payload does not make any member authoritative.

## 4. Typed state machines

### 4.1 Public capacity lots and source positions

Consensus reserves public `capacity_lot_id` values, not hidden MobileCoin ring
members. A lot is an immutable, splittable accounting slice with one asset,
native amount, common-risk value, generation, custody domain, and provenance.
An Ethereum USDC lot may refine to an exact escrow balance lot. A MobileCoin
eUSD lot refines only to an aggregate attested custody pool; it never identifies
which ring member is real.

MobileCoin vNext implements policy eligibility directly in `TxOut`. Every output
has an immutable cleartext `spend_policy_id` and a typed
`bridge_lot_commitment_or_absent` plus
`threshold_witness_package_commitment_or_absent`. Consensus validates all three
at **output creation**, not only when an output is later selected for a ring.
Every ordinary transaction output is exactly
`(ABSENT_SPEND_POLICY, ABSENT_BRIDGE_LOT_COMMITMENT,
ABSENT_THRESHOLD_WITNESS_PACKAGE)`; a caller cannot self-label an ordinary
output as bridge inventory. A non-absent tuple is valid only under
one of these closed creation rules:

```text
PolicyOutputCreationKind =
    EXTERNAL_CAPITALIZATION
  | PREDECESSOR_TRANSFER
  | TYPED_BRIDGE_RETURN
  | SAME_LOT_BRIDGE_CHANGE
```

- `EXTERNAL_CAPITALIZATION` is created by the authorized MobileCoin
  capitalization transaction that atomically commits
  `CAPITALIZE_EXTERNAL_EUSD`; consensus derives the active policy, owner,
  generation, asset, newly conserved capacity-lot ID, and valid threshold
  witness package from that event.
- `PREDECESSOR_TRANSFER` consumes the exact cited authorized predecessor
  positions and atomically commits `CAPITALIZE_PREDECESSOR_TRANSFER`; consensus
  derives the successor policy/owner/generation/lot commitments and enforces
  value conservation plus successor-roster share provisioning.
- `TYPED_BRIDGE_RETURN` pays the canonical MobileCoin escrow under the exact
  active return adapter and atomically commits `RECORD_ESCROW_SOURCE_INFLOW`.
  Consensus, not the caller, derives the recipient, policy, generation, owner,
  `source_position_id`, and stable `capacity_lot_id`; the new lot starts only as
  `EncumberedSource`. Promotion may later make that same lot `Available` but
  never changes its on-output provenance. The typed return also carries the
  sender-created, consensus-verified share package selected by the active
  profile; absence makes the return ineligible for bridge replenishment.
- `SAME_LOT_BRIDGE_CHANGE` is an output of an exact authorized bridge spend.
  `ReserveInputProof` and final validation prove that it preserves the input's
  policy, asset, generation, owner manifest, and capacity-lot ID, with the exact
  residual amount and provisions the successor output's threshold witness
  package; it cannot manufacture a second lot or relabel an external output as
  change.

The non-absent `bridge_lot_commitment` binds creation kind, asset, generation,
owner manifest, stable capacity-lot ID, amount commitment, blinding, share-
provisioning profile, and threshold-witness-package commitment. An
unsolicited/standard transfer—even one addressed to the escrow—must create only
absent tags and is ineligible inventory. A malformed special creation rejects
the whole transaction and its paired capacity event atomically. Standard
transactions may form rings only from `ABSENT_SPEND_POLICY` outputs. A bridge
reserve/final ring must contain members with one exact non-absent policy ID. The
`ReserveInputProof` privately opens the real member's lot commitment and proves
that every real input and every escrow change output has the exact reserved
asset, generation, owner manifest, and capacity lot. A mutable operator label is
never eligibility evidence.

The public lot state is exactly one of:

```text
Available
ReservedIntent(reservation_id, liability_id, committed_expiry)
EncumberedSource(source_nullifier, liability_id_or_absent)
Spent(release_id)
RetiredSplit(ordered_child_capacity_lot_ids)
Unsafe(previous_state, incident_id)
Stranded(previous_state, incident_id)
```

`Available -> ReservedIntent -> Spent` is the only ordinary public backing
path. Safe cancellation alone returns `ReservedIntent -> Available` while
retaining immutable reservation history. `EncumberedSource -> Available` is permitted only by
`PROMOTE_SETTLED_SOURCE_INFLOW`. Unsafe and Stranded value never backs a new
liability. Declaration preserves the previous binding so an incident cannot
erase an obligation, reservation, or historical exposure.

If an available lot is larger than a reservation, the reserve transition may
atomically change the parent to `RetiredSplit` and create one reserved child plus
available change children. Child IDs derive from the parent and split ordinal;
their native amounts and risk values sum exactly to the parent, and the retired
parent contributes zero thereafter. No other split/merge path exists in this
version.

`RECORD_ESCROW_SOURCE_INFLOW` atomically creates the stable `capacity_lot_id`
and changes the local source-position map `Absent -> EncumberedSource` after
same-chain adapter, policy-output-creation, and cap validation. The position is
not promotion-eligible merely because it is included. Its chain may
roll the event and position back under the declared reorg model; promotion later
requires typed finality evidence and therefore cannot race this provisional
inclusion.

For a MobileCoin destination, consensus reserves aggregate capacity without
revealing the true ring member. `ReserveInputProof` is an explicit two-artifact
bundle whose components bind the same public statement and `D` under distinct
non-spend domains:

1. `ThresholdOwnershipEqualityProof` is the adapted threshold-MLSAG proof of
   the hidden real-member secret `x`, its canonical key image, and the MLSAG
   row-1 equality witness `z = b_pseudo - b_input` for each input. It proves no
   capacity-lot identity, output classification, gross depletion, range-proof
   validity/accounting binding, or same-lot change fact.
2. `ReserveAccountingProof` proves those accounting facts under exactly one
   closed backend profile: `ZK_ACCOUNTING_CIRCUIT_V1` or
   `SGX_ATTESTED_ACCOUNTING_V1`. The ZK profile verifies the exact circuit and
   verifying-key manifest; the SGX profile verifies the exact enclave
   measurement, attestation chain, verifier manifest, and anti-rollback/freshness
   policy. Unknown, absent, hybrid, or `FROST_ONLY` profiles reject closed.

Stock Zcash FROST is therefore not accepted as a reserve accounting proof, and
the Serai-style disclosure of complete mask/opening material to each signer is
not silently treated as a privacy-preserving accounting construction. A backend
may implement a distributed witness protocol, but this interface claims only
the two independently verified properties above. Neither artifact emits a
spend-capable MLSAG/FROST signature share. For
each canonical ordinary key image it derives the stable network-global lease tag:

```text
input_lease_tag = H("MC_INPUT_LEASE_TAG_V1",
                    network_genesis_id,
                    canonical_key_image_bytes)

InputLeaseTagState:
Free
  -> Live(reservation_id, ring_set_commitment)
  -> Consumed(release_id)
```

The tag excludes bridge ID, policy, epoch, generation, protocol version, retry,
and salt, so the same hidden input cannot acquire distinct live leases under any
bridge or after rotation. `RESERVE_RELEASE_INTENT` publishes the raw ordinary key
image and the recomputed tag. The verifier rejects a tag already present in the
live-lease index or in the tag set derived from **all** finalized spent key
images. Network-upgrade activation first backfills every historical canonical
BlockContents key image into that spent-tag index before accepting a reservation.
Each reserve artifact uses its own transcript domain, neither of which any
MLSAG/FROST spend verifier accepts.

```text
ReserveInputProof = {
    bundle_domain,
    statement_core = ReserveInputStatementCore,
    ownership_equality_proof_bytes,
    ownership_equality_proof_commitment,
    accounting_proof_or_attestation_bytes,
    accounting_proof_or_attestation_commitment,
    bundle_commitment
}

ThresholdWitnessPackage = {
    package_id, policy_id, generation_id, owner_manifest_id,
    tx_out_public_key, masked_amount_commitment,
    provisioning_profile, ordered_participant_ids,
    x_share_commitments, b_input_share_commitments,
    encrypted_authenticated_share_commitments,
    vss_or_mpc_correctness_proof_commitment,
    activation_checkpoint, retirement_checkpoint_or_absent
}

ThresholdOwnershipParticipantWitnessShare[participant_id, input_ordinal] = {
    x_share_i,
    b_input_share_i,
    b_pseudo_share_i,
    z_share_i = b_pseudo_share_i - b_input_share_i,
    local_nonce_state,
    local_vss_or_mpc_openings
}

ThresholdOwnershipPublicProof = {
    pre-intent canonical-key-image/DLEQ transcript refs and aggregate binding,
    row-1 z-share commitment and relation proofs,
    exact input-ordinal/ring-set binding,
    aggregated two-row threshold MLSAG ownership/equality proof
}

ReserveAccountingPrivateWitness = {
    bridge_lot_commitment_openings,
    input/output amount and change openings,
    output classification and gross-depletion witness
}

ownership_equality_profile = THRESHOLD_MLSAG_OWNERSHIP_EQUALITY_V1

bundle_domain = BRIDGE_NONSPEND_RESERVE_INPUT_BUNDLE_V2

ownership_share_provisioning_profile in {
    TXOUT_VSS_MASK_SHARES_V1,
    APPROVED_MPC_MASK_DERIVATION_V1
}

accounting_backend_profile in {
    ZK_ACCOUNTING_CIRCUIT_V1,
    SGX_ATTESTED_ACCOUNTING_V1
}
```

The ownership/equality protocol has two independent threshold secret/share
families, `x_i` and `z_i`; an implementation that supplies only one FROST
`ThresholdKeys` object and returns one scalar is not this protocol. In
particular, current MobileCoin/Serai code does not derive additive
`b_input_share_i` values from ordinary spend-key shares. For `MaskedAmountV2`,
the input blinding is obtained through a nonlinear KDF of the shared secret
`aR`, so shares of `x` do not imply shares of `b_input`.

Every non-absent policy TxOut must therefore be born with a valid
`ThresholdWitnessPackage` under `TXOUT_VSS_MASK_SHARES_V1`, or its active
manifest must name a concrete approved MPC protocol that derives and proves the
same shares without reconstruction. The package/protocol is provisioned during
external capitalization, predecessor transfer, typed BridgeReturn, and
same-lot bridge change and is bound into the TxOut, lot commitment, intent, and
`D`. Historical outputs without a verified package require an explicit migration
and are ineligible. If neither profile is implemented for every selected real
input, the strict protocol is **release-blocked**; aggregate capacity, stock
Zcash FROST, or a direct Serai CLSAG multisig port cannot bypass that prerequisite.
The creation transaction supplies the exact VSS-correctness proof or finalized
MPC transcript artifact; consensus verifies it against the masked amount,
owner roster, and package before creating the TxOut and stores only its immutable
commitment. A hash naming an unavailable or unverified proof is not a valid
package.

No single `ThresholdOwnershipEqualityPrivateWitness` is reconstructed. Each
participant retains only its authenticated `x_i`, `b_input_i`, `b_pseudo_i`, and
`z_i` shares plus fresh nonce state. The consensus verifier receives the exact
public rings, `ReserveInputStatementCore`, and proof bundle, never the real-input
index, full spend secret, reconstructed masks, or lot/opening witnesses. A ZK or
SGX accounting prover may receive the private accounting witness according to
its declared trust profile; that is a separate disclosure boundary and not a
property of threshold MLSAG.

The exact range-proof bytes/proof vectors are public ordinary RingCT verifier
inputs. Consensus first applies the block-version-selected MobileCoin
Bulletproof/range-proof verifier to those exact bytes and output commitments.
The accounting backend separately proves private amount/lot/change
classification facts and binds the already public proof commitments; it does
not claim that public range-proof bytes require a private opening.

The mandatory order is: validate each selected TxOut's share package/profile and
roster; complete the pre-intent key-image/DLEQ aggregation under its own fresh
nonces and commit its exact ordered transcript; derive key images/tags,
`IntentBindingCore`, `reservation_id`, and `D`; begin a new reserve-only nonce
round; revalidate the pre-intent aggregate/set binding; publish D-bound
ownership-row responses and input-ordinal-bound `z_i` relation shares; aggregate
the two-row proof under the reserve-only top-level challenge; verify ordinary
RingCT; verify the selected accounting artifact; and durably consume or burn all
round nonces before releasing the bundle. Set, ring, or input ordinals may never
be reindexed between rounds.

```text
PreIntentKeyImageRoundState:
Provisioned
  -> KeyImageNonceCommitted
  -> KeyImageDleqShared
  -> KeyImageAggregateCommitted

KeyImageNonceCommitted | KeyImageDleqShared
  -> KeyImageAbortedBurned(blame_or_abort_receipt)

ReserveParticipantRoundState:
IntentBound(pre_intent_key_image_transcript_commitment, D)
  -> ReserveNonceCommitted
  -> OwnershipRowShared
  -> ZRelationShared
  -> AggregateVerified
  -> Consumed

ReserveNonceCommitted | OwnershipRowShared | ZRelationShared
  -> ReserveAbortedBurned(blame_or_abort_receipt)
```

Each pre-intent message carries its previous-round commitment, participant/input
ordinal, exact zero-ID prefix/ring/package set, owner manifest, and pre-intent
domain, but cannot carry the not-yet-derived reservation or `D`. Each reserve
message additionally carries the committed pre-intent aggregate,
`reservation_id`, `D`, and reserve challenge domain. Out-of-order, duplicate,
cross-set, cross-input, cross-phase, or post-abort messages reject
deterministically, matching the monotone DKG-style state-machine discipline
rather than coordinator memory.

Public `BlockContents` emits only the lease tags, capacity-lot IDs, reservation,
ordinary key images, ring/pseudo-output/range-proof/receipt commitments,
recomputed derived-summary hash and extended-message digest, the bundle and both
typed reserve-artifact commitments, and the selected accounting-backend
manifest. It does not emit the real ring member, ring opening/salt, or amount
opening. `RESERVE_RELEASE_INTENT` verifies both artifacts and their common
statement and atomically
reserves the duplicate-free tag vector and sufficient public eUSD capacity lots.

Final `EscrowSpendTx` supplies the ring data normal for a spend. Consensus derives
the exact tag vector from its ordinary key-image vector, byte-compares both
vectors and
the final-prefix/full-ring/membership-proof/pseudo-output/range-proof
commitments and recomputed signing outputs to the reservation, and only then
changes every tag `Live -> Consumed` and every lot `ReservedIntent -> Spent`.
Safe cancellation returns tags `Live -> Free` and lots
`ReservedIntent -> Available`. A retry may reuse a tag only after that objective
cancellation and only by reopening the permanent historical salted binding
commitment to the identical canonical ring-member set and order. The same salt
and opening are reused; otherwise `RetryLeaseSound` rejects to avoid
ring-intersection leakage. Any later permitted policy-aware bridge spend of a
cancelled tag is subject to that same ring-commitment rule. A retry may instead
choose a genuinely
different unspent private input.

Candidate-block validation is against parent state and a deterministic in-block
conflict set. It rejects two reservations for one tag; a reserve and any spend of
that key image in the same block; finalization whose reservation is not in a
prior block; any non-exact full key-image/tag vector; cancel plus retry, cancel
plus spend, or cancel plus finalize in one block; and a later spend of a
cancelled tag with a different ring-set commitment. Transaction ordering inside
one proposed block cannot bypass these rules.

This strong profile makes double private-input selection a consensus rejection,
not a liability promise: live lease-tag sets are pairwise disjoint, spent tags
cannot be leased, and final key images must match the reserved vector. A weaker
attestation-only fake-tag profile is outside this baseline and cannot inherit its
safety claims.

The threshold ownership/equality artifact verifies the amount-commitment witness
that MLSAG ordinarily uses to relate each real input to its exact pseudo-output.
The independently selected accounting backend verifies the larger transaction
accounting statement. A FROST or ownership/equality proof by itself is
insufficient. For a reservation:

```text
gross_lot_depletion =
    recipient_release
  + protocol_fee
  + Sum(value of every output not proved to be change to the same capacity lot)

reserved_lot_charge = gross_lot_depletion
```

Every pseudo-output/input amount equality is checked by the ownership/equality
artifact; output sum, fee, asset, binding to the independently verified public
range-proof commitments, output classification, change opening, lot identity,
and gross depletion are checked by the selected ZK or SGX accounting artifact.
Both bind the same public statement. Change proved
back to the same lot remains in that lot;
all other outputs are depletion. Undercharging a fee or disguising an external
output as change violates conservation.

Threshold signing uses a fresh durable nonce record for every participant,
key epoch, artifact domain, exact context digest (pre-intent context or later
reservation digest), input ordinal, share family, and signing round:

```text
NonceUnused -> NonceCommitted -> NonceConsumed
                            -> NonceAbortedBurned(blame_or_abort_receipt)
```

Neither retry nor abort may reuse a nonce. The two reserve artifacts,
WARDEN/ACCOUNT receipts, gate FROST, and MLSAG use distinct transcript domains
and canonical key-
image encodings. Abort/blame records are durable before any nonce-dependent
message is released. A reserve-round nonce is burned for every final-spend
domain and vice versa; changing only a domain label never makes old nonce
material reusable.

This design makes no availability claim from aggregate free capacity alone:
private UTXO fragmentation, insufficient policy-homogeneous decoys, or inability
to form exact change may reject a reservation even when a public lot has enough
value. It also narrows bridge inputs to the public policy-tagged anonymity set;
the roster/profile-bound witness-package commitment can further partition that
set, and this privacy degradation is explicit. Because retry pins the canonical ring set,
a ring-size upgrade must grandfather the old size until every live/retry binding
terminates or provide a separately specified migration proof. This interface
does not silently rewrite a pinned ring.

### 4.2 Liabilities

Every signed settlement obligation has one stable `liability_id` and follows:

```text
Open
  -> CapacityReserved(reservation_id, capacity_lot_ids, committed_expiry)
  -> Settled(release_id)
```

A safe cancellation returns only:

```text
CapacityReserved -> Open
ReservedIntent   -> Available
```

It does not erase the customer obligation or source inflow. A liability can
bind only capacity lots that are `Available`, eligible, exact-asset, sufficient
in native amount and risk value, and not bound to another live liability.

The claimed-liability index is distinct from the executable source-nullifier
reservation map and is injective:

```text
ClaimedLiabilityBinding[source_nullifier]:
Unbound -> Bound(liability_id) -> Settled(liability_id, release_id)
```

`OPEN_LIABILITY` verifies the one exact bond-bound WARDEN and ACCOUNT quorum over
their distinct role-artifact digests binding final `D`, stores its ordered
receipt refs/candidate commitments, and atomically
changes `Unbound -> Bound`. A second liability for the
same source nullifier rejects across directions, versions, generations, and
policy epochs. Safe cancellation does not return this binding to `Unbound`; a
retry continues the same liability and may obtain a fresh reservation only after
the old artifact is proved non-executable. There is no separately committed
backing state or event that can leave multiple obligations competing for one
source. An unauthenticated caller cannot reserve the binding merely to deny
service.

Open does not reserve a lot, nullifier, or lease. If any preselected candidate is
no longer admissible, Reserve rejects atomically and Open remains capacity-free;
this interface makes no liveness claim that the same candidate later becomes
available. No executable ownership/escrow artifact is valid before reservation,
so the stored approval alone cannot spend.

The live reservation relation is a partial bijection:

```text
LiveReservationByLiability[liability_id] = reservation_id | ABSENT
LiabilityByLiveReservation[reservation_id] = liability_id | ABSENT
```

`RESERVE_RELEASE_INTENT` requires both entries absent and writes both in the
same commit. Finalization or safe cancellation removes the live pair but retains
the immutable historical pair. A retry creates a new reservation for the same
still-bound liability only after the old pair terminates.

### 4.3 Releases and risk windows

```text
Proposed                         # not committed state
CapacityReserved
    -> FinalizedUncleared
    -> Cancelled                 # only with SafeCancellationProof
FinalizedUncleared -> Cleared -> ResolvedAudit
```

`CapacityReserved` begins when `RESERVE_RELEASE_INTENT` is accepted and atomically
records the deterministic reservation in destination-chain consensus.
Off-chain signature existence is deliberately absent from committed state.
`FINALIZE_RELEASE` is the MobileCoin `EscrowSpendTx` or Ethereum escrow `execute`
transition itself: it validates every complete artifact against the existing
reservation and final digest, atomically consumes the reservation and destination
capacity lots, settles the liability and enduring claim binding, creates the
typed source-nullifier consumption in the core, and moves the same stable risk
positions directly to `FinalizedUncleared`.

Finalization does **not** remove the outflow from `L_q`. It remains there until
`CLEAR_FINALIZED_RISK` proves one of the policy-declared conditions:

- the committed finality, detection, evidence, challenge, and safety deadlines
  all elapsed with no admitted proof;
- an admitted objective proof reached an exact applied fault resolution; or
- the explicitly modeled v1 contractual window ended under its declared
  non-automatic policy.

No release-chosen deadline may shorten a policy minimum. `Cleared` is the first
state removed from `L_q`; `ResolvedAudit` is an immutable terminal record and
never re-enters capacity. Fault collateral distribution requires every
implicated risk position to have reached `Cleared` or `ResolvedAudit`, not merely
to carry a provisional loss estimate.

The source-nullifier reservation map is independent of the final consumption
map and follows exactly:

```text
Free
  -> Reserved(reservation_id, liability_id, committed_expiry)
  -> Consumed(release_id)
```

`RESERVE_RELEASE_INTENT` is the only action that changes `Free -> Reserved` and
there may be at most one live reservation for a source nullifier across versions,
attempts, policy epochs, and destination transaction variants. Finalization
atomically changes the same entry to `Consumed`. Safe cancellation may return it
to `Free` only after proving the reserved action non-executable; it never changes
a consumed nullifier. A later retry reuses the same source nullifier and must
obtain a new valid consensus reservation.

### 4.4 Safe cancellation

`CANCEL_PENDING_RELEASE` requires a deterministic `SafeCancellationProof`
bound to the exact reservation, unsigned intent, final direction-specific
digest, and allocation manifest. Supported kinds are finite and explicit:

```text
SafeCancellationProof = {
    proof_kind,
    reservation_id,
    unsigned_intent_commitment,
    canonical_digest,
    capacity_allocation_manifest_id,
    destination_chain,
    destination_artifact_locator,
    evidence_kind,
    evidence_body,
    verifier_manifest_id
}

proof_kind in {
MOBILECOIN_TOMBSTONE_FINAL
ETHEREUM_CALL_EXPIRY_FINAL
ETHEREUM_NONCE_CONSUMED_BY_CANONICAL_REPLACEMENT
POLICY_EPOCH_PERMANENTLY_INVALIDATED
}
```

The verifier must establish that the signed destination action can no longer
finalize under the stated reorg/finality assumption. Coordinator intent,
mempool absence, a local timeout, a pause alone, or creation of a replacement
does not suffice. For `MOBILECOIN_TOMBSTONE_FINAL`, merely passing the tombstone
height is insufficient: the proof must authenticate finality beyond the
tombstone **and** finalized non-inclusion of the exact release/spend (or an
equivalent authenticated unspent/reservation-unconsumed statement), while the
local source-nullifier entry is still `Reserved` rather than `Consumed`. A
deployment without that finalized non-inclusion capability cannot use this
automatic cancellation kind. An uncommitted off-chain proposal expiring is
projection-preserving and does not use `CANCEL_PENDING_RELEASE`, because no
consensus reservation exists. In particular, an off-chain signing abort by
itself does not prove that no signature was created. Failed or unsupported cancellation leaves the
reservation, reserved risk, liability, and bond window unchanged.

`ETHEREUM_NONCE_CONSUMED_BY_CANONICAL_REPLACEMENT` refers only to the escrow
contract's consensus nonce that the exact reserved call commits and that **every**
mutually exclusive escrow execution path checks and consumes. Consumption of an
EOA transaction nonce, a coordinator counter, or a nonce bypassable by another
contract entry point proves nothing. `POLICY_EPOCH_PERMANENTLY_INVALIDATED` is
sound only because both MobileCoin `EscrowSpendTx` validation and Ethereum
escrow `execute` recheck the active policy epoch and live reservation at final
execution; a pause flag not enforced there is not a cancellation proof.

### 4.5 Bonds, faults, and epochs

Bond positions follow:

```text
Locked -> ExitRequested -> Released
Locked | ExitRequested -> Frozen(verdict_id, fault_collateral_id)

FaultResolutionCollateral:
Held(fault_collateral_id, bond_position_id, frozen_native_amount,
     frozen_risk_value)
  -> Distributed(distribution_id, restitution_entries, proof_cost_entries,
                 bounty_entries, insurance_surplus_entries)
```

`FAULT_BOND_FREEZE` atomically creates exactly one `Held` collateral position
for each frozen unique bond position; this is a state reclassification, not a
second asset. `DISTRIBUTE_FAULT_COLLATERAL` consumes each Held amount into a
complete, disjoint distribution partition and applies the corresponding bond
debit. No other event may spend, release, revalue upward, or duplicate it.

Bond release is permitted only after every bound reservation, finalized-uncleared,
evidence, challenge, adjudication, and safety window has discharged. A later
manifest cannot rebind historical liability.

Policy epochs follow:

```text
Active -> Paused -> RotationRequired -> Reopenable -> Active
```

Pause state is chain-local. Only after `PAUSE_POLICY_EPOCH` commits on a given
chain are new liability admission, intent reservation, and destination
finalization on that chain rejected. The same local ordering rule also rejects
`FINALIZE_RELEASE` under that paused epoch: a destination action ordered before
the pause may finalize, while one ordered after it may not, even if its
off-chain signatures were created earlier. A remote fault verdict or bond freeze is not
an instantaneous local pause. The local pause event must carry either an
authenticated finalized causal reference to the exact remote
`FAULT_BOND_FREEZE`, or the policy's exact threshold role attestation over that
verdict and remote checkpoint. Pre-pause reservation records are preserved after
pause and remain charged until an objective permanent-epoch-invalidation or
other supported non-executability proof safely cancels them; pause never erases
them merely to improve the bound.

Reopening requires a separately committed local rotation/manifest sequence, a
fresh distinct gate key produced by the authorized DKG path, exclusion of every
permanently expelled identity, restored capacity bounds, and no stale acceptance
receipt. If a chain cannot authenticate the remote bond registry, delivery of
the fault proof and eventual local pause/rotation are explicit operational trust
and fairness assumptions; safety does not assume zero delivery latency.

## 5. Canonical event vocabulary

The replacement interface has exactly **28 committed event kinds**:

| # | Event kind | Producer | Required effect |
|---:|---|---|---|
| 1 | `OWNER_AUTHORITY_READY` | generation control | records exact owner key, roster, threshold, ceremony, generation binding, and content-addressed ownership/share/accounting backend allowlists |
| 2 | `GATE_ROLE_AUTHORITY_READY` | generation control | records exact gate, Ethereum, WARDEN, ACCOUNT, and policy manifests |
| 3 | `LOCK_BOND_MANIFEST` | bond administration | locks unique identity bond positions under the exact manifest and maximum possible window |
| 4 | `CAPITALIZE_EXTERNAL_EUSD` | reserve administration | after owner authority, creates conserved public eUSD capacity lots whose custody outputs carry the exact vNext policy/bridge-lot and verified threshold-witness-package commitments; it does not reveal real future ring inputs |
| 5 | `CAPITALIZE_PREDECESSOR_TRANSFER` | finalized authorized settlement | consumes cited predecessor positions and creates consensus-derived successor policy outputs/positions with valid successor-roster witness packages, without duplication or value creation |
| 6 | `RECORD_ESCROW_SOURCE_INFLOW` | source escrow consensus + same-chain adapter | atomically records exact accepted bridge-method/typed-return inclusion and creates one stable capacity lot in `EncumberedSource` after local cap checks; a MobileCoin typed return has consensus-derived escrow recipient/policy/lot commitment plus a verified witness package, carries no self-finality claim, and reorgs with the source transition |
| 7 | `OPEN_LIABILITY` | bridge admission | verifies one exact bond-bound WARDEN+ACCOUNT quorum under distinct role domains binding the already derived final `D`, stores the immutable assertion/obligation plus exact candidate destination-object/lot/key-image/tag/ring/pseudo-output/range-proof commitments and receipt refs, and acquires the one-live-liability claim lock; it reserves no capacity and does not require objective inflow |
| 8 | `RESERVE_RELEASE_INTENT` | destination-chain capacity consensus | byte-revalidates the identical Open-stored `D`/receipt refs and MobileCoin `ReserveInputProof`, then atomically changes liability `Open -> CapacityReserved`, the exact precommitted lots `Available -> ReservedIntent`, nullifier `Free -> Reserved`, and lease tags `Free -> Live` after local allocation/cap/bond/pause checks, without a second WARDEN/ACCOUNT signing round or objective source lookup |
| 9 | `FINALIZE_RELEASE` | MobileCoin `EscrowSpendTx` or Ethereum escrow `execute` | while the bound local epoch and reservation are live, verifies all reservation-bound artifacts and exact final transaction/call match, admits only absent-tag customer outputs plus proved exact same-lot MobileCoin escrow change with a valid successor witness package, then atomically removes the live reservation pair, changes lots `ReservedIntent -> Spent`, liability `CapacityReserved -> Settled`, claim binding `Bound -> Settled`, nullifier `Reserved -> Consumed`, applicable MobileCoin input leases `Live -> Consumed`, and release/risk `CapacityReserved -> FinalizedUncleared`; local ordering after pause rejects |
| 10 | `CANCEL_PENDING_RELEASE` | destination settlement | after valid objective non-executability proof, removes the live reservation pair and changes liability `CapacityReserved -> Open`, lots `ReservedIntent -> Available`, nullifier `Reserved -> Free`, applicable MobileCoin input leases `Live -> Free`, and release `CapacityReserved -> Cancelled`, while retaining claim lock and immutable reservation history |
| 11 | `PROMOTE_SETTLED_SOURCE_INFLOW` | reserve accounting | with typed finalized references to the exact local inflow and paired remote finalization/clearance, changes one matching encumbered source position to reusable `Available` exactly once |
| 12 | `CLEAR_FINALIZED_RISK` | risk-window administration | after exact committed clearance/loss proof, changes `FinalizedUncleared -> Cleared` and only then removes the position from `L_q` |
| 13 | `ACTIVATE_GENERATION` | generation control | activates only after owner, capital, gate/role, bond, valuation, allocation, and cap checks |
| 14 | `CLOSE_GENERATION_DEPOSITS` | generation control | stops new liability/reservation admissions for the generation |
| 15 | `DRAIN_GENERATION` | generation control | requires zero live inventory bindings, open/reserved liabilities, reservations, and uncleared risk |
| 16 | `DEACTIVATE_GENERATION` | generation control | deactivates a drained generation without erasing any historical record |
| 17 | `DECLARE_UNSAFE` | incident observation | marks exact lots ineligible while retaining prior bindings and gross exposure |
| 18 | `DECLARE_STRANDED` | incident observation | marks exact lots unavailable/ineligible while retaining realized-loss and obligation history |
| 19 | `REQUEST_BOND_EXIT` | bond administration | starts an exit without reducing historical or reserved coverage |
| 20 | `COMPLETE_BOND_EXIT` | bond administration | releases only after all exact bound windows and liabilities discharge |
| 21 | `PROPOSE_CAPACITY_ALLOCATION` | cross-chain policy administration | records a future immutable per-chain/direction/generation allocation and valuation manifest without changing active capacity |
| 22 | `ACTIVATE_CAPACITY_ALLOCATION` | each chain's policy consensus | after local predecessor-window and segment checks, activates a content hash whose global validity/common-hash agreement is either authenticated by remote-state proof or supplied as the explicit deployment/governance precondition of section 7.3 |
| 23 | `PAUSE_POLICY_EPOCH` | each chain's containment consensus | after an authenticated causal proof or exact threshold role attestation, closes new local liability/reservation/finalization without erasing reservations or charged risk; it does not claim an atomic remote pause |
| 24 | `FAULT_BOND_FREEZE` | Ethereum bond registry / deterministic penalty machine | freezes exact implicated bonds, creates fault-resolution collateral, and records the verdict and required exclusions; it neither atomically pauses MobileCoin nor performs a bounty or final distribution |
| 25 | `DISTRIBUTE_FAULT_COLLATERAL` | deterministic penalty machine | only after all implicated reservations terminate and all implicated risk is `Cleared`/`ResolvedAudit` with authenticated loss results, applies exact slash accounting, restitution first, then proof cost/capped bounty and insurance surplus |
| 26 | `APPLY_CHALLENGER_FAULT` | deterministic penalty machine | applies only the exact challenge-bond consequence; never closes operator capacity by itself |
| 27 | `REGISTER_FRESH_GATE_EPOCH` | authorized DKG/rotation | records a distinct gate key/manifest and excludes expelled identities |
| 28 | `REOPEN_POLICY_EPOCH` | policy control | reopens only after fresh gate registration and all activation/allocation/cap preconditions pass |

Every row denotes one chain-local commit. An operation affecting both chains is
represented by two or more committed events joined by typed causal references;
it is never encoded as one cross-chain atomic event. In particular,
`PAUSE_POLICY_EPOCH`, allocation activation, rotation/manifest installation, and
reopening commit independently on each affected chain, while
`FAULT_BOND_FREEZE` commits at the Ethereum bond registry.

### 5.1 Generation ordering

For every successor generation:

```text
OWNER_AUTHORITY_READY
    -> { CAPITALIZE_EXTERNAL_EUSD | CAPITALIZE_PREDECESSOR_TRANSFER }
    -> ACTIVATE_GENERATION

OWNER_AUTHORITY_READY
    -> GATE_ROLE_AUTHORITY_READY
    -> LOCK_BOND_MANIFEST
    -> ACTIVATE_CAPACITY_ALLOCATION
    -> ACTIVATE_GENERATION

ACTIVATE_GENERATION
    -> CLOSE_GENERATION_DEPOSITS
    -> DRAIN_GENERATION
    -> DEACTIVATE_GENERATION
```

The capitalization and gate/role/bond branches are conjunctive and may
interleave only after owner authority. Capitalization itself must preserve all
domain caps. `DRAIN_GENERATION` additionally requires no `Open` or
`CapacityReserved` liability and no `FinalizedUncleared` risk for that generation.
A USDC customer inflow is not eUSD capitalization.

## 6. Full customer flow and inventory provenance

### 6.1 `ETH_TO_MOB`

1. The Ethereum bridge deposit method holds USDC and atomically commits
   `RECORD_ESCROW_SOURCE_INFLOW(USDC, EncumberedSource)` with its local inclusion;
   it makes no self-finality claim and reorgs with that deposit.
2. Off chain, the exact zero-ID rings/packages first complete their pre-intent
   key-image/DLEQ aggregation; the complete candidate intent/lots/key
   images/tags/transcript commitments then determine `reservation_id` and `D`.
   Bond-bound WARDEN and ACCOUNT quorums each
   sign their distinct role-artifact digest binding `D` once. `OPEN_LIABILITY`
   validates those exact receipts, claim-locks the
   stable nullifier, and stores the candidate without reserving capacity; absence
   of step 1 still does not prevent a captured quorum from expressing a false release.
3. `RESERVE_RELEASE_INTENT` byte-revalidates the Open-stored `D`/receipt refs and
   `ReserveInputProof`, then atomically reserves the exact public aggregate eUSD
   lots and duplicate-free proof-bound lease tags in MobileCoin consensus.
   The true ring members remain private; canonical ordinary key images and their
   network-global lease tags become public in the reservation.
4. The exact MLSAG verifies base `D`; the MobileCoin FROST artifact verifies its
   gate-domain digest over that same `D`. The
   final `EscrowSpendTx` revalidates all role predicates, the live reservation,
   active epoch, capacity lots, and final key-image/lease-tag vector, then directly
   commits spend, settlement, nullifier consumption, and `FinalizedUncleared` risk.
5. Only an exact real USDC source position with authenticated finalized refs to
   both step 1 and the paired remote v2
   release receipt may then be promoted to reusable
   USDC inventory for `MOB_TO_ETH`.

### 6.2 `MOB_TO_ETH`

1. The typed MobileCoin `BridgeReturn` output uses the consensus-derived
   canonical escrow recipient, active policy, and bridge-lot commitment and
   atomically commits `RECORD_ESCROW_SOURCE_INFLOW(eUSD, EncumberedSource)` with
   local inclusion; it makes no self-finality claim and reorgs with that return.
2. The complete candidate intent/lots/call determines `reservation_id` and `D`.
   Bond-bound WARDEN and ACCOUNT quorums each sign their role-domain digest over
   `D` once;
   `OPEN_LIABILITY` validates/stores those receipts and claim-locks the stable
   nullifier independently of objective source truth.
3. `RESERVE_RELEASE_INTENT` byte-revalidates the identical Open-stored
   `D`/receipt refs and atomically reserves the exact eligible public USDC escrow
   capacity lots in Ethereum consensus.
4. The Ethereum multisig then signs the base reservation-bound `D`. The final
   escrow `execute` call revalidates the exact multisig/role artifacts, live
   reservation, active epoch, and escrow-contract nonce, then directly commits
   USDC spend, liability settlement, nullifier consumption, and
   `FinalizedUncleared` risk.
5. Only an exact real returned-eUSD position with authenticated finalized refs
   to both step 1 and the paired remote release/clearance may then be promoted to reusable
   eUSD inventory for `ETH_TO_MOB`.

The two promotions are provenance-preserving inventory conversion, not minting.
They cannot occur for a false assertion lacking a matching real source inflow.
When the source position and destination settlement reside on different chains,
`PROMOTE_SETTLED_SOURCE_INFLOW` consumes both the local source-inflow record and
an authenticated causal reference to the remote finalized release receipt. The
promotion cannot be justified by choosing a convenient product interleaving or
by an unauthenticated coordinator report.

## 7. Exact reserve and coalition arithmetic

### 7.1 Typed native-asset and common-risk values

Native USDC and eUSD amounts are never added directly. The immutable
`valuation_and_cap_manifest` supplies, for each asset and policy epoch:

```text
native_amount(position)
risk_value(position)       # conservative common integer risk unit
bond_risk_value(position)  # after asset, liquidity, freeze, and volatility haircut
C_loss_asset[domain, asset]
C_loss_risk[domain]
```

Every accepted action preserves both the per-asset vector and common-risk cap:

```text
I[domain, asset] =
    Sum(native_amount(p) for unique public capacity/source lots p exposed to domain)

RiskI[domain] =
    Sum(risk_value(p) for the same unique positions)

I[d, a]    <= C_loss_asset[d, a]
RiskI[d]   <= C_loss_risk[d]
```

Unspent public lots include `Available`, `ReservedIntent`, `EncumberedSource`,
and declared Unsafe/Stranded positions until the policy's explicit
loss-resolution event removes their exposure. A lot
appears once **within each domain sum** and appears separately in every domain
to which the immutable manifest exposes it.

For MobileCoin eUSD, `I` is deliberately an aggregate public-capacity assertion,
not a public enumeration of real UTXOs. The owner/WARDEN/ACCOUNT receipts and
input-lease-tag registry make overstatement or double selection
detectable at the defined protocol boundaries; the model must not claim that
ordinary ring consensus alone proves aggregate custody before final spend. The
per-asset/common-risk caps still bound accepted outflow under the declared
capitalization premise, while the strong `ReserveInputProof`/lease rules reject
fake, reused, or mismatched input evidence rather than converting it into a
strict-liability baseline.

### 7.2 Coalition capacity

A `QuorumUnion` records role-specific identity sets and is capable only if each
mandatory role independently meets its exact roster and threshold:

```text
ETH_TO_MOB: OWNER and FROST_GATE and WARDEN and ACCOUNT
MOB_TO_ETH: ETH_MULTISIG and WARDEN and ACCOUNT
```

Role overlap does not collapse a threshold. The capacity model enumerates every
minimal capable quorum-union for every simultaneously live direction,
generation, and policy; it does not trust only the signers chosen for the
current request. Each role manifest has a canonical ordered roster of distinct
identity IDs and distinct public keys, with one immutable
`(role, identity_id, public_key)` binding per slot. A duplicated key cannot fill
two slots in one role. If policy permits one identity/key in two different
roles, each role still requires a separately verified signature under
`RoleArtifactDigest(role, role_manifest_id, D)`; raw signature reuse does not
count twice.

Every role whose individual receipts carry equivocation liability satisfies the
accountable-intersection activation rule:

```text
for role in {WARDEN, ACCOUNT}:
    2 * threshold[role, manifest] > roster_size[role, manifest]

for any concurrently valid manifests m1 != m2 and any valid quorums Q1, Q2:
    |Q1(role, m1) intersection Q2(role, m2)| >= 1
```

Every guaranteed intersection identity has a bond locked through both manifests'
maximum windows. Preferably, rotation makes old/new authorization validity
non-overlapping after all predecessor reservations terminate; if overlap is
permitted, the cross-manifest intersection inequality is mandatory. Generation,
policy, roster, and gate activation reject a low threshold or disjoint concurrent
rosters. Otherwise two conflicting quorums could leave an empty culprit set and
the claimed penalty would be fictitious.

Each public capacity lot has one stable `risk_position_id` across its available,
reserved, spent, and finalized-uncleared phases. Thus retries and phase changes
do not duplicate or erase value. Here `w` is a complete capable adversarial
attack trace, potentially containing several false releases plus all outflow
during detection and pause propagation—not a single chosen request:

```text
L[f, w, asset] = native value of unique risk positions fault-class witness w
              can cause to leave before
              every affected chain reaches its committed local pause boundary,
              including CapacityReserved, FinalizedUncleared, and the maximum
              additional outflow during detection and pause propagation

RiskL[f, w] = common-risk value of that same unique set
```

The bound is computed from the policy's committed detection bound, remote-proof
delivery bound or fairness envelope, each chain's local inclusion/finality bound,
local allocation headroom, and reservation/finalization throughput. It does
not set propagation time to zero merely because the bond registry has frozen a
bond. Define:

```text
PropagationExposure[f, w, chain] =
    MaxUniqueRiskValue(w can newly reserve or finalize after the
                       first provable fault and before PAUSE_POLICY_EPOCH is
                       final on chain)

RiskL[f, w] = UniqueRiskValue(existing live/uncleared positions caused by w
                              union all PropagationExposure positions)
```

Allocation manifests and bond admission must cover this maximum reachable set.
If a deployment supplies no finite remote-proof delivery/fairness bound, it may
still be modeled for safety by the entire remaining local allocation; it may not
claim a tighter propagation reserve. Eventual remote pause is then a liveness
assumption, not a proved safety transition.

For false-source accountability, the objectively slashable approval identities
are exactly:

```text
LiableFalseSource(r) =
    ValidBondBoundWARDENSigners(r) union ValidBondBoundACCOUNTSigners(r)

LiableEquivocation(a1, a2) =
    (ValidBondBoundWARDENSigners(a1)
        intersection ValidBondBoundWARDENSigners(a2))
    union
    (ValidBondBoundACCOUNTSigners(a1)
        intersection ValidBondBoundACCOUNTSigners(a2))
```

Here `a1,a2` are two objectively incompatible approval bundles containing their
respective role receipts. The closed evidence subtype is:

```text
EquivocationEvidenceSubtype =
    DIGEST_CONFLICT
  | BACKING_SELECTION_EQUIVOCATION
```

`BACKING_SELECTION_EQUIVOCATION` means two approvals for the same stable
claim/liability semantics bind incompatible capacity-lot, key-image, lease-tag,
ring, or reservation selections. Because every such selection is committed into
the pre-reservation object and ultimately `D`, it is an evidence subtype of the
single `EQUIVOCATION` fault class, not a third prose-only `FaultClass`. Both
subtypes use the same per-role intersection culprit formula.

Identity and bond overlap is deduplicated. Hidden aggregate MLSAG/FROST
contributors and unbonded Ethereum signers do not inflate collectible value; they become
countable only under a future version that publishes and objectively verifies
their own liability receipts.

```text
FaultClass = FALSE_SOURCE | EQUIVOCATION

Culprits[FALSE_SOURCE, w] =
    UniqueUnion(LiableFalseSource(r) for every proved-false release r in w)

Culprits[EQUIVOCATION, w] =
    UniqueUnion(LiableEquivocation(a1, a2) for every proved incompatible
                approval pair (a1, a2) in w)

B_exact[f, w] =
    Sum(bond_risk_value(b) for unique currently collectible positions b of
        Culprits[f, w], locked through the maximum
        reserved/finalized/proof/adjudication/safety window)

for every covered f and every complete capable w:
    B_exact[f, w] >= 2 * RiskL[f, w]

B_min[f, authorization_window] =
    Min(B_exact[f, w] for every complete capable adversarial witness w admitted anywhere
        in that window, including every concurrently valid cross-manifest pair)

RiskL_max[f, authorization_window] =
    Max(RiskL[f, w] for the same fault-class witness set)

B_min[f, authorization_window] >= 2 * RiskL_max[f, authorization_window]
```

The per-witness inequality is the primary requirement. The independent
minimum-versus-maximum inequality is a stronger sufficient admission envelope;
this draft requires it for simple deterministic allocation checks even though
its minimum-bond and maximum-loss extrema may arise from different traces.

The minimum is over the **exact culprit formula**, not a capable quorum's union.
For `FALSE_SOURCE`, all valid WARDEN and ACCOUNT approvers on every proved-false
`D` in the trace are collectible. For either `EQUIVOCATION` evidence subtype,
only the per-role intersections across the incompatible approval bundles are
collectible; with 3-of-5 a guaranteed intersection may contain only one signer
in a role. Using the union would overstate penalty capacity.

In the canonical same-source path, claim-lock, reservation, and finalization
injectivity prevent both incompatible artifacts from causing two losses, so pure
equivocation has `RiskL_max[EQUIVOCATION] = 0` unless a separately modeled
cross-manifest/fork/cross-chain path makes both outflows reachable. The full
contractual slash still applies as deterrence, but it is not relabeled loss
coverage. If such a dual-outflow path is enabled, its exact reachable loss and
minimum intersection bonds enter the equation above.

Liability admission, capitalization, source-inflow acceptance, intent
reservation, finalization, allocation activation, generation activation, bond
exit, and policy reopening must preserve these bounds, including
`PropagationExposure`. The factor two remains configured policy, not an economic
theorem.

### 7.3 Per-chain allocations instead of magical cross-chain atomicity

Ethereum and MobileCoin cannot synchronously read and update one shared capacity
counter. Each active `capacity_allocation_manifest` therefore fixes immutable
local allocations in the common risk unit:

```text
Allocation[chain, direction, generation, asset]
AllocationRisk[chain, direction, generation]
manifest_epoch
activation_not_before
retirement_not_before
predecessor_manifest_or_absent
deployment_profile
```

For every failure domain and minimal capable quorum-union, a globally valid
allocation manifest satisfies:

```text
Sum(local domain allocations across both chains/directions/generations)
    <= C_loss_risk[domain]

Sum(local native allocation[domain, asset] across all segments)
    <= C_loss_asset[domain, asset]

AllocationRiskMax[f, window] =
    Max(Sum(unique AllocationRisk segments exercisable by witness w)
        for every capable witness w of fault class f in window)

B_min[f, window] >= 2 * AllocationRiskMax[f, window]
```

Each destination chain then enforces synchronously and locally:

```text
LocalAllocationUsage[segment] =
    UniqueRiskValue(
        CapacityReserved(segment)
        union FinalizedUncleared(segment)
    )

LocalAllocationUsage[segment] <= AllocationRisk[segment]
```

The same stable risk position moves between these two sets and is counted once;
it never disappears at finalization.

Every `reservation_id` and final release digest commits the active allocation
manifest and exact local segment. A local chain cannot borrow unused capacity
from another segment without a new manifest.

`PROPOSE_CAPACITY_ALLOCATION` changes no live limit. Reallocation that reduces,
retires, or moves an old segment cannot activate until all reservations,
finalized-uncleared positions, and historical bond
windows charged to the old segment have safely closed. The old and new manifests
may coexist only when the selected deployment profile supplies a conservative
old/new-union check and their aggregate still satisfies every domain and
coalition bound; otherwise activation waits. Each chain records the same content hash plus an explicit
chain-specific activation checkpoint. Temporary stagger while one checkpoint is
final and the other is not does not create atomicity: the active profile charges
the conservative union of old and new allocations, and neither chain may borrow
the other segment's capacity.

The profile is immutable and closed:

```text
V1_GOVERNANCE_ASSUMPTION
V2_PROOF_CARRYING
```

Under `V1_GOVERNANCE_ASSUMPTION`, each chain verifies its local predecessor
windows, local segment arithmetic, and the exact governance-threshold signature
over the global manifest hash. Global validity, same-hash deployment,
conservative stagger union, remote bond-registry faithfulness, and eventual
activation/pause delivery are explicit deployment assumptions. The chain does
not call the product runner and the runner cannot make an invalid activation
valid.

Under `V2_PROOF_CARRYING`, each activation carries closed-variant
`CHECKPOINT`/`FINALITY_PROOF` causal evidence for the other chain's relevant
predecessor/activation state and the required bond state. The local verifier
checks that proof and the global formulas above before committing. Unsupported
remote proof systems reject instead of silently falling back to governance.

The composition runner tests both profiles. In v1 it reports safety only
conditional on the declared premises and can detect their later violation as
audit evidence; it is not enforcement. In v2 it verifies the same proof-carrying
guards as the protocol. For both profiles it rejects a different hash, early
activation, unsafe stagger borrowing, or a missing activation after its explicit
fairness premise. No profile uses product replay as an activation oracle.

### 7.4 Fault-state accounting

`FAULT_BOND_FREEZE` freezes the exact implicated bonds on the Ethereum bond
registry and earmarks their full slashable value as fault-resolution collateral;
it must not make value disappear merely to preserve `B >= 2L` after an attack.
It does not atomically mutate a MobileCoin policy state. The admission inequality
is an ex-ante condition on open capacity, including the maximum outflow possible
during detection and cross-chain pause propagation. After fault:

- each chain remains governed by its own state until its local
  `PAUSE_POLICY_EPOCH` commits, after which new local liability admission,
  reservation, and finalization are closed;
- all reserved and finalized-uncleared risk remains recorded, including a
  reserved intent whose signatures may have existed before local pause and which
  is awaiting objective
  non-executability cancellation afterward;
- each frozen bond maps to a unique non-spendable `FaultResolutionCollateral`
  position with the same pre-distribution risk value;
- no collateral distribution, proof-cost payment, bounty, insurance transfer,
  or release back to the operator occurs while any implicated reservation,
  or finalized-uncleared outcome remains unresolved;
- after all such outcomes resolve, `DISTRIBUTE_FAULT_COLLATERAL` verifies an
  independently authenticated loss assessment, reduces that proved loss and
  seized collateral by the same restitution amount, then pays proof cost and
  capped bounty only from surplus;
- remaining surplus enters the insurance reserve; and
- no position is erased to make a post-fault invariant pass.

For distribution, “resolved” is not a Boolean supplied by the penalty event.
Every implicated reservation must be terminally cancelled or finalized, and
every implicated risk position must be `Cleared` or `ResolvedAudit` and therefore
absent from `L_q`. A `loss_fixed` flag on `FinalizedUncleared` is insufficient.

## 8. Exact penalty payload and consequences

`PenaltyPayload` contains exactly these fields:

```text
PenaltyPayload = {
proof_id, verdict_id, fault_class, authorization_window_id,
equivocation_evidence_subtype_or_absent,
complete_witness_commitment,
fault_proof_kind, fault_proof_commitment,
auto_verifiable_fault, penalty_phase,
target_release_ids, incompatible_digest_pair_or_absent,
warden_signers_by_digest, account_signers_by_digest,
expected_culprit_identities,
unique_bound_bond_position_ids,
bond_pre_amounts, exact_slash_amounts, bond_post_amounts,
challenge_bond_id_or_absent,
loss_proof_kind, loss_proof_commitment, loss_assessor_id_or_absent,
loss_by_asset, loss_risk_value, loss_fixed,
B_exact_risk_value, RiskL_witness_risk_value,
restitution_entries, proof_cost_entries, bounty_entries,
insurance_surplus_entries,
fault_resolution_collateral_ids,
implicated_reservation_ids, implicated_risk_position_ids,
implicated_finalized_uncleared_ids, all_implicated_outcomes_resolved,
affected_policy_ids, affected_policy_epochs,
local_pause_states_before, local_pause_states_after,
fault_causal_refs_by_chain, role_attestation_refs_by_chain,
exact_expelled_identities,
rotation_required, prohibited_old_gate_manifest,
fresh_gate_scope
}
```

The closed `fault_proof_kind` enum is
`FALSE_ETHEREUM_SOURCE_ASSERTION`,
`FALSE_MOBILECOIN_SOURCE_ASSERTION_V2`, `SIGNED_EQUIVOCATION`,
`BACKING_SELECTION_EQUIVOCATION`,
`CONTRACTUAL_MOBILECOIN_V1_FAULT`, or `INVALID_CHALLENGE`. The closed
`penalty_phase` enum is `FREEZE_OPERATOR`, `DISTRIBUTE_OPERATOR`, or
`APPLY_CHALLENGER`.

`SIGNED_EQUIVOCATION` requires
`equivocation_evidence_subtype = DIGEST_CONFLICT`;
`BACKING_SELECTION_EQUIVOCATION` requires the identically named subtype. Both
map to `fault_class = EQUIVOCATION` and use the intersection culprit formula.
Every non-equivocation proof requires `ABSENT_EQUIVOCATION_SUBTYPE`.

This replacement chooses a concrete operator penalty: an accepted operator-fault
verdict slashes **100% of every unique historically bound bond position of every
exact culprit**, including an `ExitRequested` position. Therefore, for each such
position `b`:

```text
exact_slash_amount[b] = bond_pre_amount[b]
bond_post_amount[b]   = 0
```

Freeze first makes that full amount non-spendable; distribution occurs only
under the later conditions below. Let `H` be its total frozen common-risk value,
`R_loss` the independently proved realized-loss risk value, `P_claim` the
authenticated proof-cost claim, and let `proof_cost_cap`, `bounty_rate_num`,
`bounty_rate_den`, and `bounty_cap` be immutable manifest constants. Distribution
is exactly:

```text
R = min(R_loss, H)                                      # restitution first
P = min(P_claim, proof_cost_cap, H - R)                 # then proof cost
Y = min(bounty_cap,
        floor(bounty_rate_num * (H - R - P) / bounty_rate_den),
        H - R - P)                                      # then bounty
S = H - R - P - Y                                      # insurance surplus
H = R + P + Y + S
```

Restitution entries are ordered by `(asset_id, liability_id, recipient)` and use
the immutable verdict-time conversion table; insufficient collateral is divided
pro rata with integer remainders assigned by that canonical order. The sum of
all native debit entries must equal the exact frozen native bond amounts, so
rounding cannot create or erase value. A proved operator fault with zero proved
loss still applies the full slash: `R = 0`, and only proof cost, capped bounty,
and insurance receive value. For `INVALID_CHALLENGE`, only the identified
challenge bond is fully debited to the insurance reserve; all operator fields,
pause/rotation effects, and operator collateral IDs are sentinels.

For `OperatorFault`, `FAULT_BOND_FREEZE` recomputes the culprit formula, freezes
every implicated active or exiting unique bond, and earmarks 100% of each
culprit's historically bound slashable bond exactly once. It records the exact
identities that every affected local policy manifest must exclude and the
required fresh-gate scope. It does not mutate either chain's policy epoch, guess
the final loss, or pay a bounty. Each chain subsequently commits its own
`PAUSE_POLICY_EPOCH` and rotation events with the typed causal proof or exact
role attestation required by section 4.5.

`AutoVerifiableFault` and objectively proved `RealizedLoss` are separate
capabilities. The former establishes culpability and permits bond freeze and the
policy-declared fault slash; it does not establish that a destination payment
occurred. In particular:

- for `ETH_TO_MOB`, contradictory WARDEN/ACCOUNT receipts plus the canonical
  Ethereum `DepositRecord` can prove a false Ethereum-source assertion and its
  culprits, but eUSD loss requires a finalized MobileCoin
  `BridgeReleaseReceipt`/checkpoint or the identified contractual adjudicator;
- for `MOB_TO_ETH/V2`, the authenticated MobileCoin
  `BridgeReturnReceipt` membership/non-membership result can establish source
  falsity, while the local finalized Ethereum escrow call establishes USDC
  payout; the loss assessment binds both;
- for `MOB_TO_ETH/V1`, absence of an authenticated MobileCoin receipt map leaves
  source falsity and any resulting loss under the explicitly named contractual
  adjudication rule; and
- equivocation can be automatically proved from two incompatible signed digests
  while objectively proved realized loss remains zero.

An automatic fault proof may therefore produce a nonzero contractual slash with
zero restitution. It may not synthesize a customer loss. `loss_proof_kind` is a
closed enum (`FINALIZED_MOBILE_RELEASE_RECEIPT`,
`FINALIZED_ETHEREUM_ESCROW_CALL`, `PAIRED_V2_CROSS_CHAIN_RECEIPTS`,
`CONTRACTUAL_ADJUDICATION`, or `PROVED_ZERO_LOSS`) and its commitment binds the
exact release, reservation, asset vector, finality/checkpoint, and assessor when
applicable.

`DISTRIBUTE_FAULT_COLLATERAL` is enabled only when every implicated reservation
is terminally cancelled or finalized and every implicated risk position is
`Cleared` or `ResolvedAudit`, hence removed from `L_q`. No implicated
`FinalizedUncleared` state may remain, regardless of a `loss_fixed` field. The
transition recomputes `all_implicated_outcomes_resolved`; it never trusts the
payload Boolean. The distribution recomputes the loss vector from the declared
`loss_proof_kind` and commitment, then applies the exact slash/distribution
amounts, restitution priority, proof costs, capped bounty, and insurance surplus.
Early distribution, invented or overstated loss, underpayment, an omitted
culprit bond, an extra innocent bond, or bounty paid ahead of restitution
rejects.

For `ChallengerFault`, only the exact authenticated challenge bond is slashed.
No operator bond, pause, expulsion, capacity closure, or gate rotation may be
created by that verdict alone.

## 9. Composition invariants

The final product model and runner must map each name below to a non-vacuous
check in both implementations or to an explicitly relational composition test:

```text
AtomicCapacityCommit
AcceptanceBindsExactlyOneEvent
EventLogChainComplete
EventLogAtMostOnce
EventIdImmutable
EventLogOrderSound
CausalReferenceSound
UnknownEventFailClosed
DerivedFieldsSound
DigestConstructionAcyclic
DirectionSpecificExecutionDigestSound
ProjectionParity
ObjectiveTruthAbsentFromInterface
SourceAdapterSoundness
CapacityLotConservation
LiabilityLifecycleSound
LiabilityReservationInjective
SourceNullifierLiabilityInjective
ConsensusReservationPrecedesExecution
ReservationDigestBound
ApprovalReceiptReuseSound
RoleArtifactDomainSound
LiveInputLeaseInjective
ReserveInputProofSound
ReserveAccountingBackendSound
ThresholdOwnershipPrerequisiteSound
PreIntentKeyImageAggregationSound
ThresholdOwnershipEqualityProofSound
ReserveChallengeDomainSound
MobileRangeProofVerificationSound
FinalizationMatchesReservation
RetryLeaseSound
PolicyHomogeneousRingSound
PolicyOutputProvenanceSound
AmountCommitmentWitnessSound
GrossLotChargeSound
SigningNonceDiscipline
SourceNullifierReservationSound
ReleaseLifecycleSound
CancellationProofSound
RiskExposureLifecycleComplete
RiskClearanceSound
SourceInflowPromotionSound
SourceInflowPromotionExactOnce
EncumberedSourceSound
AssetArithmeticTyped
FailureDomainBindingSound
ReserveExposureBound
CrossGenerationExposureComplete
CoalitionCapacityBound
AccountableQuorumIntersection
FaultClassBondCoverage
LocalAllocationBound
GlobalAllocationBound
AllocationActivationDelay
CrossChainAllocationManifestAgreement
StaggeredAllocationConservative
AllocationProfileSound
UniqueSlashableBondAccounting
HistoricalBondBinding
CapitalizationSound
NoIneligibleBacking
GenerationLifecycleSound
OperatorPenaltyExact
ChallengerPenaltyExact
RestitutionPriority
PausedPolicyClosed
ChainLocalPauseSound
FaultPropagationBound
FaultPreservesResidualExposure
FaultCollateralConserved
FaultDistributionDeferred
LossAssessmentSound
ExpelledSignerExcluded
FreshGateRequired
```

In particular, `CausalReferenceSound` requires every consumed remote effect to
be present, exact, finalized under its referenced verifier, and earlier in the
causal order. `SourceAdapterSoundness` authenticates actual escrow inflow but is
never a hidden release guard. `SourceNullifierReservationSound` enforces the
single `Free -> Reserved -> Consumed` path and permits `Reserved -> Free` only
under safe non-executability proof. `StaggeredAllocationConservative` charges the
old/new union during non-atomic activation. `FaultPropagationBound` includes the
maximum pre-local-pause outflow. `LossAssessmentSound` derives restitution only
from the declared finalized loss proof or an explicitly contractual adjudication,
including a valid zero-loss result. `ReserveExposureBound` applies both native
per-asset and common-risk `I` caps to every inventory-affecting transition,
including source-inflow recording; source provenance cannot bypass arithmetic.
`SourceNullifierLiabilityInjective` enforces one enduring liability binding per
source nullifier. `ChainLocalPauseSound` forbids a remote verdict/freeze from
mutating another chain before its own accepted pause event. `PausedPolicyClosed`
also rejects a post-pause `FINALIZE_RELEASE`; an earlier-created off-chain
signature grants no exception to local consensus ordering and is not a committed
authorization state. `CapacityLotConservation` permits only
deterministic split transitions whose child native/risk sums equal their
unique parents and whose states partition each lot exactly once.
`LiabilityLifecycleSound` permits liability `CapacityReserved -> Settled` and
claim binding `Bound -> Settled` only inside the exact atomic final destination
commit; no administrative or proof-only event may settle either record.
`LiabilityReservationInjective` permits one live reservation per liability and
one liability per reservation. `LiveInputLeaseInjective` requires all live tag
sets to be pairwise disjoint and disjoint from the activation-backfilled spent
tag index, including deterministic same-block candidate conflicts.
`ReserveInputProofSound` accepts only the two exact, domain-distinct,
non-spend-capable artifacts binding one public statement in section 4.1.
`ReserveAccountingBackendSound` rejects ownership/FROST-only claims and requires
exactly one recognized ZK-circuit or SGX-attested accounting backend to establish
lot provenance, private amount/output classification, binding to the public
range-proof commitments, change, and gross
depletion. `ThresholdOwnershipPrerequisiteSound` requires a valid per-output VSS
package or approved MPC mask-share derivation before a policy output is eligible;
missing historical mask shares block release.
`PreIntentKeyImageAggregationSound` requires fresh-domain, ordinal/set-bound
key-image/DLEQ shares and an aggregate transcript before canonical key images,
lease tags, `IntentBindingCore`, reservation ID, or `D` are derived; the exact
transcript commitments are ancestors of all later proof rounds.
`ThresholdOwnershipEqualityProofSound`
checks canonical point/scalar encodings, non-identity points, key-image DLEQ
shares, two independent `x_i`/`z_i` share families, z-relation proofs, exact
ring/input ordinals, and aggregate verification without reconstruction.
`ReserveChallengeDomainSound` requires the reserve-only top-level challenge and
fresh reserve nonce state, never the final-spend challenge/domain.
`MobileRangeProofVerificationSound` applies the ordinary block-version-selected
MobileCoin range-proof verifier to the exact public bytes independently of the
private accounting backend. `FinalizationMatchesReservation` requires a
prior-block live reservation and exact full transaction/call, capacity-lot,
key-image/tag, full ring/proof wire fields, pseudo-output/range-proof,
pre-intent key-image transcript, derived-summary, network, liability, nullifier,
allocation, and epoch match.
`RetryLeaseSound` requires objective cancellation, a later block, and the
same permanent salted ring-set binding when any cancelled key image is reused.
`ApprovalReceiptReuseSound` requires Open and Reserve to reference the same
ordered WARDEN/ACCOUNT receipts whose distinct role digests bind the same final
`D`; no second approval round or alternate signer set is admitted.
`RoleArtifactDomainSound` requires the closed role wrapper, exact role manifest,
unique identity-role-key binding, duplicate-free within-role keys, and separate
signature verification for every mandatory role; a raw receipt or gate artifact
cannot be replayed into another role.
`PolicyHomogeneousRingSound` enforces the vNext `spend_policy_id` ring rules and
real/change lot binding. `AmountCommitmentWitnessSound` requires the second
MLSAG amount-commitment witness equality to each exact pseudo-output rather than
accepting FROST ownership alone. `GrossLotChargeSound` charges recipient value,
fee, and every non-same-lot output. `SigningNonceDiscipline` requires durable
fresh nonce and abort/blame transitions under distinct proof/signature domains.
`FaultDistributionDeferred` requires terminal reservation outcomes and all
implicated risk to be `Cleared`/`ResolvedAudit`, not `FinalizedUncleared`.
`DigestConstructionAcyclic` enforces the dependency order and domain separation
in section 3.2; zeroing a self-dependent field is not an allowed substitute.
`DirectionSpecificExecutionDigestSound` reconstructs the exact MobileCoin
vNext wire prefix and block-version inputs or exact Ethereum EIP-712 value,
checks MobileCoin genesis/chain domains, and compares the returned base `D` and
derived descendants; field commitments never replace verifier input bytes.
`PolicyOutputProvenanceSound` enforces the closed output-creation rules in
section 4.1, including absent tags on ordinary/unsolicited transfers, exact
consensus-derived typed-return provenance, valid roster-bound witness packages,
and same-lot change conservation.
`AccountableQuorumIntersection` enforces the same-manifest threshold and
cross-manifest validity rules in section 7.2 before any liable role becomes
active. `FaultClassBondCoverage` uses the minimum exact-culprit collectible bond
over all capable witnesses, separately for false-source union liability and
equivocation intersection liability; a capable quorum union is not a substitute.

`GlobalAllocationBound` and `CrossChainAllocationManifestAgreement` are
conditional product properties. They are protocol-enforced only where both
chains authenticate the required remote allocation state; otherwise they are
checked against the explicitly declared deployment/governance premise. A model
run that assumes that premise may establish conditional composition safety, but
must not label it a native on-chain guarantee.
`AllocationProfileSound` forbids product-runner admission and requires exactly
the v1 governance premise or v2 proof-carrying guard selected in section 7.3.

The composition runner statically inventories every core/environment action and
classifies it as projection-affecting or projection-preserving. Every affecting
action must synchronously commit exactly one recognized event. Replaying the
committed local hash chain must produce byte-equal capacity projection state at
every prefix of that chain. Product parity is checked at every causally closed
cut across the two local chains, not only at one terminal interleaving. The
runner enumerates every relevant linear extension of each cut; it may collapse
two orders only after proving their events commute on disjoint typed state.
Forged, missing, future, wrong-chain, wrong-hash, or insufficiently finalized
causal references reject. Every non-affecting action must preserve the relevant
local projection and every causally closed product projection. Exact TLA+,
Python, config, interface, contract, and runner hashes are published together.

## 10. Exact falsifier inventory

### 10.1 Amended staged capacity selectors

Each one-defect run changes only the clause in its `Only mutation` cell. Its
fixture satisfies every other invariant before the attempted event. The runner
evaluates the named oracle at the stated boundary and halts immediately. The
default allowed-secondary set is `NONE`; the finite exception map after the
composition table is part of the contract. A non-listed simultaneous failure, a
failure before the stated boundary, or failure by absence of an enabled attempt
invalidates the test configuration.

These **nine** names retain the earlier acceptance inventory:

| # | Selector | Only mutation | Minimal prestate and attempted event | Earliest primary oracle |
|---:|---|---|---|---|
| S01 | `RESERVE_CAP_BYPASS` | skip native/common failure-domain reserve guard only | active epoch; local segment has headroom; next valid reserve exceeds `I` cap | `ReserveExposureBound` at reserve acceptance |
| S02 | `OMIT_PENDING_EXPOSURE` | omit one `CapacityReserved` risk position from `L_q` only | one valid committed reservation, no finalization | `RiskExposureLifecycleComplete` after reserve commit |
| S03 | `UNDERCOUNT_CROSS_DIRECTION` | exclude opposite-direction live risk from one capable coalition | one live reserve in each direction under same coalition | `CoalitionCapacityBound` after second reserve |
| S04 | `UNDERCOUNT_CROSS_GENERATION` | exclude predecessor-generation live risk only | predecessor and successor active with one reserve each | `CrossGenerationExposureComplete` after successor reserve |
| S05 | `DOUBLE_COUNT_OVERLAP_BOND` | count one physical bond twice through WARDEN/ACCOUNT identity overlap | one overlapping bonded identity and one live reserve | `UniqueSlashableBondAccounting` during admission recomputation |
| S06 | `UNFUNDED_SUCCESSOR` | permit successor activation with no eligible capacity lot | authorities/manifests ready; capitalization absent | `CapitalizationSound` at generation activation |
| S07 | `FUND_BEFORE_OWNER_AUTHORITY_READY` | admit capitalization before owner authority event | empty successor generation; capitalization attempted first | `CapitalizationSound` at capitalization acceptance |
| S08 | `INELIGIBLE_BACKING` | allow one Unsafe/ineligible lot into a reserve | otherwise valid open liability and sufficient caps | `NoIneligibleBacking` at reserve acceptance |
| S09 | `EARLY_BOND_EXIT` | release one bond one checkpoint before its maximum bound window | exact live historical window; exit requested | `HistoricalBondBinding` at bond release |

### 10.2 New interface/composition falsifiers

These **110** selectors cover the interface boundary under the same one-mutation,
earliest-oracle, and default-`NONE` secondary contract above:

| # | Selector | Only mutation | Minimal prestate and attempted event | Earliest primary oracle |
|---:|---|---|---|---|
| C01 | `COMMIT_WITHOUT_CAPACITY_ACCEPT` | let core commit after capacity rejects | valid open liability; reserve exceeds cap | `AtomicCapacityCommit` at attempted commit |
| C02 | `ACCEPTANCE_REPLAY` | reuse one acceptance ID/receipt for a second proposal | accepted event A; distinct event B at same local prestate | `AcceptanceBindsExactlyOneEvent` before B commit |
| C03 | `DELETE_LOAD_BEARING_EVENT` | delete one committed source/capital event while retaining descendants | two-event local causal chain | `EventLogChainComplete` on replay |
| C04 | `DUPLICATE_COMMITTED_EVENT` | append exact event bytes twice | one accepted event | `EventLogAtMostOnce` at second append |
| C05 | `MUTATE_REUSED_EVENT_ID` | reuse event ID with one payload byte changed | historical event and rebroadcast slot | `EventIdImmutable` before append |
| C06 | `REORDER_SAME_CHAIN_COMMITTED_EVENT` | swap a local cause and consumer | source inflow then promotion | `EventLogOrderSound` on reordered replay |
| C07 | `FORGE_DERIVED_FIELD` | alter only recomputable liability ID | otherwise canonical `OPEN_LIABILITY` | `DerivedFieldsSound` at admission |
| C08 | `UNKNOWN_EVENT_FAIL_OPEN` | decode unknown kind as no-op success | active empty generation | `UnknownEventFailClosed` at decoding |
| C09 | `FINALIZE_FROM_WRONG_RELEASE_STATE` | skip only release-state predecessor check | all reservation maps/lots live, but release-state tag is non-`CapacityReserved` | `ReleaseLifecycleSound` at finalization |
| C10 | `UNSAFE_CANCEL` | accept coordinator timeout/mempool absence as proof | one live reservation before expiry | `CancellationProofSound` at cancel validation |
| C11 | `OMIT_FINALIZED_UNCLEARED` | move finalized risk directly out of `L_q` | one valid finalization | `RiskExposureLifecycleComplete` after commit |
| C12 | `EARLY_RISK_CLEAR` | skip one committed risk deadline | one `FinalizedUncleared` position | `RiskClearanceSound` at clear attempt |
| C13 | `OVERBOOK_CAPACITY_LOT` | create/reserve children whose native sum exceeds parent | one Available lot; otherwise valid reserve | `CapacityLotConservation` at reserve commit |
| C14 | `RESERVATION_LIABILITY_INDEX_ALIAS` | write wrong reverse live-reservation index only | one valid reservation pair | `LiabilityReservationInjective` after reserve commit |
| C15 | `PROMOTE_SOURCE_BEFORE_SETTLEMENT` | omit settled-liability guard only | finalized source inflow; liability still CapacityReserved | `SourceInflowPromotionSound` at promotion |
| C16 | `PROMOTE_NONMATCHING_SOURCE` | substitute source asset/nullifier from another settled pair | two finalized source positions; one settled liability | `SourceInflowPromotionSound` at promotion |
| C17 | `DOUBLE_PROMOTE_SOURCE` | permit second promotion of same source position | one already promoted source lot | `SourceInflowPromotionExactOnce` at second attempt |
| C18 | `OMIT_SOURCE_INFLOW_EVENT` | mutate source escrow state without its recognized event | one valid local deposit/return transition | `ProjectionParity` at local prefix |
| C19 | `CUSTOMER_INFLOW_AS_FREE_CAPITAL` | create `Available` instead of `EncumberedSource` | one valid source inflow under caps | `EncumberedSourceSound` after commit |
| C20 | `MIX_NATIVE_ASSET_SUM` | add USDC native units to eUSD native units | one lot of each asset | `AssetArithmeticTyped` during cap calculation |
| C21 | `OMIT_FAILURE_DOMAIN` | remove one manifest-derived domain from one lot | lot exposed to two domains | `FailureDomainBindingSound` at admission |
| C22 | `COUNT_UNSLASHABLE_BOND` | include hidden/unbonded signer value in one `B_w` | capable witness with one unbonded signer | `UniqueSlashableBondAccounting` during admission |
| C23 | `UNDERPAY_OPERATOR_SLASH` | debit one culprit bond below 100% | proved operator fault; risk already Cleared | `OperatorPenaltyExact` at distribution |
| C24 | `OMIT_CULPRIT_SLASH` | exclude one exact culprit bond | proved false assertion with two culprits | `OperatorPenaltyExact` at freeze |
| C25 | `BOUNTY_BEFORE_RESTITUTION` | allocate one unit to bounty before proved victim loss | Cleared loss and held collateral | `RestitutionPriority` at distribution |
| C26 | `NEW_RESERVATION_WHILE_PAUSED` | ignore local paused-epoch guard only | local pause committed; Open liability | `PausedPolicyClosed` at reserve attempt |
| C27 | `EXPELLED_SIGNER_REUSE` | count one expelled signer in fresh roster | rotation required; exact expulsion record | `ExpelledSignerExcluded` at gate registration |
| C28 | `REOPEN_WITHOUT_FRESH_GATE` | reuse prohibited old gate manifest | paused/rotation-required epoch | `FreshGateRequired` at reopen |
| C29 | `FAULT_ERASES_RESERVATION` | delete one live reservation/risk entry during freeze | proved fault plus live reservation | `FaultPreservesResidualExposure` after freeze |
| C30 | `FAULT_COLLATERAL_ERASURE` | create Held collateral below frozen bond value | one culprit bond | `FaultCollateralConserved` at freeze |
| C31 | `FINALIZE_FROM_OFFCHAIN_SIGNATURE_ONLY` | skip consensus-reservation existence guard because a coordinator reports signatures | Open liability; no committed reservation; final event attempted | `ConsensusReservationPrecedesExecution` before finalization |
| C32 | `RESERVATION_DIGEST_MISMATCH` | alter one final digest field while retaining reservation ID | one live reservation and final attempt | `ReservationDigestBound` before artifact validation |
| C33 | `LOCAL_ALLOCATION_BYPASS` | skip only local segment-usage guard | global/domain caps have headroom; local segment full | `LocalAllocationBound` at reserve |
| C34 | `OVERALLOCATE_GLOBAL_MANIFEST` | increase one global segment while every local segment is internally valid | v2 proof profile or v1 premise fixture | `GlobalAllocationBound` at profile validation |
| C35 | `EARLY_REALLOCATION` | retire/reduce old segment with one live risk position | valid successor manifest | `AllocationActivationDelay` at activation |
| C36 | `MISMATCHED_ALLOCATION_HASH` | activate distinct hashes on the two chains | locally valid segments and closed predecessors | `CrossChainAllocationManifestAgreement` at causal cut |
| C37 | `DISTRIBUTE_BEFORE_RISK_RESOLVED` | distribute while one implicated risk is `FinalizedUncleared` | correct loss proof and collateral; no other defect | `FaultDistributionDeferred` at distribution |
| C38 | `FORGED_SOURCE_ADAPTER` | accept wrong escrow/event locator as local inflow | amount/caps otherwise valid | `SourceAdapterSoundness` at inflow commit |
| C39 | `SECOND_LIVE_RESERVATION_SAME_SOURCE` | clone a second live reservation only in source-nullifier map | one valid live reservation | `SourceNullifierReservationSound` on poststate check |
| C40 | `ACCEPTANCE_EVENT_HASH_MISMATCH` | bind acceptance to hash A but commit bytes B | one proposal and available capacity | `AcceptanceBindsExactlyOneEvent` before commit |
| C41 | `UNSAFE_STAGGER_BORROW` | borrow remote/new-segment headroom during stagger | old/new hashes valid; one chain not activated | `StaggeredAllocationConservative` at reserve |
| C42 | `CANCEL_CONSUMED_NULLIFIER` | change consumed nullifier back to Free only | one Settled release and Consumed nullifier | `SourceNullifierReservationSound` at cancel |
| C43 | `DRAIN_WITH_OUTSTANDING_LIABILITY` | ignore one Open liability in drain guard | closed generation with no other live state | `GenerationLifecycleSound` at drain |
| C44 | `SOURCE_INFLOW_CAP_BYPASS` | skip `I` cap only for source-inflow event | valid adapter; next encumbered lot exceeds cap | `ReserveExposureBound` at inflow commit |
| C45 | `CROSS_CHAIN_CAUSAL_REF_FORGERY` | substitute wrong remote event hash under otherwise valid evidence | promotion requiring one remote receipt | `CausalReferenceSound` at causal validation |
| C46 | `OMIT_DELAY_EXPOSURE` | set propagation exposure to zero only | delayed remote pause; remaining local allocation nonzero | `FaultPropagationBound` during admission |
| C47 | `INVENT_REALIZED_LOSS` | claim positive loss under a proved-zero-loss commitment | all risk Cleared | `LossAssessmentSound` at distribution |
| C48 | `SLASH_EXTRA_INNOCENT_OPERATOR` | include one non-culprit bond | exact culprit set and Cleared result | `OperatorPenaltyExact` at freeze |
| C49 | `CHALLENGER_FAULT_PAUSES_OPERATOR` | mutate operator pause on invalid-challenge verdict | challenge bond present; no operator fault | `ChallengerPenaltyExact` at verdict commit |
| C50 | `INSTANT_REMOTE_PAUSE_ASSUMPTION` | mutate MobileCoin pause state at Ethereum freeze commit | active epochs on both chains | `ChainLocalPauseSound` at causal cut |
| C51 | `UNDERSTATE_PROVED_LOSS` | record loss one unit below authenticated proof | all implicated risk Cleared | `LossAssessmentSound` at distribution |
| C52 | `SECOND_LIABILITY_SAME_SOURCE` | acquire second claim lock for same stable nullifier | one Bound claim; otherwise valid assertion | `SourceNullifierLiabilityInjective` at open |
| C53 | `FINALIZE_WHILE_PAUSED` | ignore active-epoch recheck only | pre-pause live reservation; pause committed first | `PausedPolicyClosed` at finalization |
| C54 | `CHALLENGER_FAULT_ROTATES_OPERATOR` | mutate gate/rotation state on invalid-challenge verdict | challenge bond present; no operator fault | `ChallengerPenaltyExact` at verdict commit |
| C55 | `DOUBLE_RESERVE_SAME_LEASE_TAG` | accept a second live reservation containing one live tag | distinct liabilities/lots; first reserve committed | `LiveInputLeaseInjective` at second reserve |
| C56 | `FORGED_RESERVE_INPUT_PROOF` | accept an invalid ownership/accounting bundle under the correct public shape | fresh tag, eligible lot, valid receipts | `ReserveInputProofSound` at reserve |
| C57 | `FINALIZE_WITH_DIFFERENT_KEY_IMAGE` | substitute one final key image/tag-vector member | prior-block live reservation; all other fields exact | `FinalizationMatchesReservation` at finalization |
| C58 | `MISSING_SPENT_TAG_BACKFILL` | omit one historical key image from activation backfill | history contains that spent key image | `LiveInputLeaseInjective` at upgrade activation |
| C59 | `RESERVE_AND_SPEND_SAME_BLOCK` | omit in-block conflict between reserve and a permitted competing policy-aware spend of the same key image | tag free in parent state | `LiveInputLeaseInjective` in candidate validation |
| C60 | `FINALIZE_WITH_SAME_BLOCK_RESERVATION` | accept reservation and its final spend in one block | no parent-state reservation | `FinalizationMatchesReservation` in candidate validation |
| C61 | `CANCEL_AND_RETRY_SAME_BLOCK` | accept cancel and tag reuse in one block | live prior-block reservation | `RetryLeaseSound` in candidate validation |
| C62 | `CANCEL_AND_SPEND_SAME_BLOCK` | accept cancel and a policy-aware bridge spend of its key image in one block | live prior-block reservation | `LiveInputLeaseInjective` in candidate validation |
| C63 | `CANCEL_AND_FINALIZE_SAME_BLOCK` | accept cancel and reserved final spend in one block | live prior-block reservation | `FinalizationMatchesReservation` in candidate validation |
| C64 | `RETRY_WITH_DIFFERENT_RING_COMMITMENT` | reuse cancelled tag with a new ring opening/order | safely cancelled historical lease | `RetryLeaseSound` at retry reserve |
| C65 | `PROMOTE_UNFINALIZED_SOURCE_INFLOW` | accept promotion without finalized local inflow reference | settled remote release; local inflow only provisional | `SourceInflowPromotionSound` at promotion |
| C66 | `PROMOTE_WITHOUT_FINALIZED_REMOTE_RELEASE` | accept promotion without finalized paired remote release/clearance | local inflow finalized; liability not remotely final | `SourceInflowPromotionSound` at promotion |
| C67 | `PRODUCT_RUNNER_AS_ACTIVATION_ORACLE` | accept activation solely because off-chain product runner returns success | neither v1 attestation nor v2 proof present | `AllocationProfileSound` at activation |
| C68 | `V2_ACTIVATION_WITHOUT_REMOTE_PROOF` | omit one mandatory proof-carrying remote state reference | v2 profile and locally valid segment | `AllocationProfileSound` at activation |
| C69 | `CAUSAL_EVIDENCE_KIND_BODY_MISMATCH` | label CHECKPOINT body as FINALITY_PROOF | otherwise valid remote event reference | `CausalReferenceSound` at decoding/verification |
| C70 | `EOA_NONCE_AS_CANCEL_PROOF` | substitute consumed EOA nonce for escrow-contract nonce | live Ethereum reservation | `CancellationProofSound` at cancel |
| C71 | `EPOCH_INVALIDATION_WITHOUT_FINAL_RECHECK` | accept epoch-invalidated proof while final path ignores epoch/live-reservation state | live reservation and paused epoch | `CancellationProofSound` at cancel |
| C72 | `CIRCULAR_RESERVATION_DIGEST` | include reservation ID/signature bytes in an ancestor digest | otherwise canonical reserve intent | `DigestConstructionAcyclic` during derivation |
| C73 | `NONINTERSECTING_ROLE_THRESHOLD` | activate one liable role with `2k <= n` | one proposed WARDEN or ACCOUNT manifest | `AccountableQuorumIntersection` at activation |
| C74 | `CONCURRENT_DISJOINT_LIABLE_ROSTERS` | allow two concurrently valid manifests with disjoint valid quorums | old/new rotations otherwise ready | `AccountableQuorumIntersection` at activation |
| C75 | `FROST_WITHOUT_AMOUNT_WITNESS` | accept ownership FROST while omitting input/pseudo-output amount witness | valid ring owner; mismatched pseudo-output | `AmountCommitmentWitnessSound` at reserve-proof verification |
| C76 | `OMIT_FEE_FROM_LOT_CHARGE` | subtract protocol fee from gross depletion | valid proof/transaction with nonzero fee | `GrossLotChargeSound` at reserve |
| C77 | `CHANGE_TO_DIFFERENT_CAPACITY_LOT` | classify output bound to another lot as same-lot change | valid input and nonzero change | `GrossLotChargeSound` at reserve-proof verification |
| C78 | `MIXED_SPEND_POLICY_RING` | admit two non-absent policy IDs in a bridge ring | otherwise valid bridge ring/proof | `PolicyHomogeneousRingSound` at reserve-proof verification |
| C79 | `STANDARD_RING_CONTAINS_POLICY_TXOUT` | admit policy-tagged member in a standard ring | otherwise valid ordinary MobileCoin spend | `PolicyHomogeneousRingSound` at transaction validation |
| C80 | `REUSE_SIGNING_NONCE` | reuse one NonceConsumed/NonceAbortedBurned nonce in a later signing round | durable prior nonce record | `SigningNonceDiscipline` before nonce message |
| C81 | `RETRY_AFTER_RING_SIZE_UPGRADE_WITHOUT_MIGRATION` | reuse cancelled tag under a newly required ring size without grandfather/migration rule | safely cancelled pinned old-size ring | `RetryLeaseSound` at retry reserve |
| C82 | `USE_UNION_BONDS_FOR_EQUIVOCATION` | compute equivocation coverage from both signing quorums' union instead of per-role intersections | 3-of-5 liable roles with minimum one-signer intersections | `FaultClassBondCoverage` during admission |
| C83 | `OMIT_CROSS_MANIFEST_WITNESS_FROM_B_MIN` | exclude one concurrently valid old/new quorum pair from the minimum | overlapping-validity manifests with bonded intersection | `FaultClassBondCoverage` at activation/admission |
| C84 | `EVENT_HASH_IN_ACCEPTANCE_ID` | include current `event_hash` or receipt bytes in `acceptance_id` only | otherwise canonical proposal with one accepted transition | `DigestConstructionAcyclic` during acceptance derivation |
| C85 | `EVENT_LOG_IN_POSTSTATE_HASH` | include the current event/receipt or resulting log/header root in one semantic poststate hash only | otherwise canonical proposal and semantic poststate | `DigestConstructionAcyclic` during poststate-hash derivation |
| C86 | `SETTLE_LIABILITY_WITHOUT_FINALIZATION` | change liability `CapacityReserved -> Settled` without the exact atomic `FINALIZE_RELEASE` effects | one live reservation, reserved nullifier/lot, and no final spend | `LiabilityLifecycleSound` at attempted commit |
| C87 | `OPEN_RESERVE_RECEIPT_MISMATCH` | substitute one WARDEN or ACCOUNT receipt/ref at Reserve after Open stored a different valid ordered set | one Open liability with exact stored final-D receipts and otherwise admissible candidates | `ApprovalReceiptReuseSound` before reserve mutation |
| C88 | `OMIT_RANGE_PROOF_FROM_MOBILE_DIGEST` | omit exactly one selected range-proof byte/vector element from the vNext signing-digest call | canonical MobileCoin final prefix, pseudo outputs, and valid block-version proof representation | `DirectionSpecificExecutionDigestSound` during `D_MOB` derivation |
| C89 | `MUTATE_RANGE_PROOF_AFTER_APPROVAL` | replace one exact range-proof byte after role receipts were issued while retaining its old reservation metadata | Open liability with valid receipts over original `D_MOB` | `DirectionSpecificExecutionDigestSound` before reserve/final artifact acceptance |
| C90 | `SELF_REFERENTIAL_TX_SUMMARY_COMMITMENT` | insert a commitment to `DerivedTxSummary` into its own pre-reservation prefix/IntentBinding ancestor | otherwise canonical MobileCoin candidate | `DigestConstructionAcyclic` during intent derivation |
| C91 | `UNAUTHORIZED_POLICY_TXOUT_CREATION` | let an ordinary/caller-selected output carry a non-absent policy or bridge-lot commitment | ordinary MobileCoin transaction, including an unsolicited escrow recipient | `PolicyOutputProvenanceSound` at output creation validation |
| C92 | `WRONG_MOBILE_NETWORK_REPLAY` | accept a candidate and artifacts bound to a different MobileCoin genesis/domain | two networks with identical remaining fixture bytes and one valid foreign-network artifact bundle | `DirectionSpecificExecutionDigestSound` before Open/final acceptance |
| C93 | `CROSS_ROLE_RECEIPT_REPLAY` | use one valid WARDEN signature byte string to satisfy an ACCOUNT or FROST role with an overlapping identity/key | manifests permit the overlap but require both roles | `RoleArtifactDomainSound` during role-artifact verification |
| C94 | `DUPLICATE_ROLE_PUBLIC_KEY_SLOT` | admit one public key in two ordered slots of the same liable-role roster | otherwise valid threshold manifest and unique identity labels | `RoleArtifactDomainSound` at manifest activation |
| C95 | `OWNERSHIP_PROOF_AS_ACCOUNTING_PROOF` | accept threshold MLSAG/FROST ownership/equality evidence while omitting or faking the selected ZK/SGX accounting artifact | valid hidden-owner and row-1 equality witness but wrong lot/change classification and gross depletion | `ReserveAccountingBackendSound` at reserve-proof verification |
| C96 | `CALLER_CHOSEN_BRIDGE_RETURN_POLICY` | trust one caller-supplied policy/generation/lot field instead of the consensus-derived typed-return value | valid MobileCoin `BridgeReturn` to the canonical escrow with one mismatched caller field | `PolicyOutputProvenanceSound` at output/source-inflow creation |
| C97 | `COMMITMENT_STUB_AS_MOBILE_TXPREFIX` | derive `D_MOB` from ring/field commitments instead of the exact final wire `TxPrefix` | two candidate prefixes differ in one full ring member or membership-proof byte while the defective stub is unchanged | `DirectionSpecificExecutionDigestSound` during `D_MOB` derivation |
| C98 | `MISSING_THRESHOLD_MASK_SHARE_PACKAGE` | admit a selected real policy output without threshold-available authenticated mask shares or a completed approved MPC derivation | provenance-valid output/package commitment but too few usable share records; public capacity otherwise sufficient | `ThresholdOwnershipPrerequisiteSound` before reserve proof |
| C99 | `FORGED_KEY_IMAGE_DLEQ_SHARE` | replace one participant's pre-intent key-image/DLEQ share with a point unrelated to its committed `x_i` | one valid zero-ID input/ring/package context, roster, and all other shares | `PreIntentKeyImageAggregationSound` during pre-intent share verification |
| C100 | `INVALID_Z_SHARE_RELATION` | set one `z_i` share or relation proof inconsistent with `b_pseudo_i - b_input_i` | one valid input with both committed mask-share families | `ThresholdOwnershipEqualityProofSound` during row-1 share verification |
| C101 | `OWNERSHIP_PROOF_SET_SWAP` | substitute a different ring/package set after pre-intent nonce commitments but before key-image/DLEQ aggregation | two valid same-shaped zero-ID sets and one committed pre-intent round | `PreIntentKeyImageAggregationSound` during transcript/aggregate verification |
| C102 | `CROSS_INPUT_SHARE_SWAP` | swap one valid D-bound z-relation share between two input ordinals | two valid inputs under one reservation | `ThresholdOwnershipEqualityProofSound` during ordinal-bound share verification |
| C103 | `RESERVE_FINAL_NONCE_REUSE` | reuse one reserve-round nonce commitment/share in the final MLSAG/FROST round | durable reserve nonce already consumed or burned | `SigningNonceDiscipline` before the first final-domain nonce message |
| C104 | `RESERVE_CHALLENGE_AS_SPEND_DOMAIN` | initialize the reserve proof with `mc_ring_mlsag_challenge` or another spend/gate domain | otherwise valid reserve statement and participant shares | `ReserveChallengeDomainSound` before challenge derivation |
| C105 | `IDENTITY_RESERVE_PROOF_POINT` | accept one identity point where the reserve proof requires a non-identity canonical point | otherwise valid ownership/equality transcript | `ThresholdOwnershipEqualityProofSound` at point decoding/validation |
| C106 | `NONCANONICAL_RESERVE_PROOF_SCALAR` | accept one noncanonical scalar/point encoding that reduces to a valid value | otherwise valid ownership/equality transcript | `ThresholdOwnershipEqualityProofSound` at canonical decoding |
| C107 | `PROOF_COMMITMENT_IN_STATEMENT_CORE` | include an ownership/accounting proof commitment or bundle commitment in its own statement digest | otherwise canonical reserve input bundle | `DigestConstructionAcyclic` during statement derivation |
| C108 | `SKIP_PUBLIC_MOBILE_RANGE_PROOF_VERIFY` | skip ordinary MobileCoin range-proof verification because the private accounting backend accepted | exact digest-bound but cryptographically invalid public range-proof bytes | `MobileRangeProofVerificationSound` before reserve acceptance |
| C109 | `CAPACITY_HASH_EVENT_RECEIPT_MISMATCH` | omit or alter exactly one capacity pre/post hash in the 31-field event envelope while retaining the acceptance receipt's correct hash | otherwise canonical accepted transition with both semantic projections | `AcceptanceBindsExactlyOneEvent` before commit |
| C110 | `KEY_IMAGE_AGGREGATED_AFTER_INTENT_DIGEST` | derive `IntentBindingCore`/reservation/`D` from placeholders and substitute canonical key images or their transcript afterward | exact zero-ID rings and valid threshold packages with no pre-intent aggregate yet | `PreIntentKeyImageAggregationSound` during intent derivation |

Allowed later secondaries are exactly:

```text
C57: { ReservationDigestBound }
C63: { ReleaseLifecycleSound }
C75: { ReserveInputProofSound }
C76: { CapacityLotConservation, ReserveInputProofSound }
C77: { CapacityLotConservation, ReserveInputProofSound }
C78: { ReserveInputProofSound }
C82: { CoalitionCapacityBound }
C83: { CoalitionCapacityBound }
C84: { AcceptanceBindsExactlyOneEvent }
C85: { EventLogChainComplete }
C88: { ReservationDigestBound }
C89: { ReservationDigestBound }
C90: { DirectionSpecificExecutionDigestSound }
C92: { ReservationDigestBound }
C94: { AccountableQuorumIntersection, UniqueSlashableBondAccounting }
C95: { ReserveInputProofSound, GrossLotChargeSound }
C97: { ReservationDigestBound, FinalizationMatchesReservation }
C98: { ReserveInputProofSound }
C99: { ThresholdOwnershipEqualityProofSound, ReserveInputProofSound }
C100: { ReserveInputProofSound }
C101: { ThresholdOwnershipEqualityProofSound, ReserveInputProofSound }
C102: { ReserveInputProofSound }
C103: { ReserveChallengeDomainSound }
C104: { ReserveInputProofSound }
C105: { ReserveInputProofSound }
C106: { ReserveInputProofSound }
C109: { DerivedFieldsSound }
C110: { DigestConstructionAcyclic, ThresholdOwnershipEqualityProofSound }
all other selectors: { }
```

These are allowed only after the listed earliest primary has been observed. A
secondary at the same or earlier evaluation boundary still invalidates the run.

The replacement interface therefore owns **119 exact one-defect tests**: nine
amended staged selectors plus one hundred ten composition selectors. This count is
separate from the acceptance contract's core cryptographic/claim selectors.

## 11. Required interface scenarios

The runner must execute these **ten** positive/negative scenario profiles in
both models with identical finite constants:

| # | Scenario | Required outcome |
|---:|---|---|
| 1 | `FULL_BIDIRECTIONAL_ROUND_TRIP_V2` | with authenticated remote release receipts: finalized USDC inflow -> settled eUSD release -> promoted USDC -> finalized eUSD return -> settled USDC release -> promoted eUSD; both liabilities settle and both nullifiers remain unique |
| 2 | `FALSE_SOURCE_NO_PHANTOM_CAPITAL` | a fully authorized false assertion can release within bounds but creates no reusable source inventory without an actual matching inflow |
| 3 | `SAFE_CANCEL_AND_RETRY` | objective non-executability changes liability `CapacityReserved -> Open`, lot `ReservedIntent -> Available`, source nullifier `Reserved -> Free`, and lease `Live -> Free`; a later-block retry retains the claim lock, reuses the same ring binding if it reuses a tag, and only one release finalizes |
| 4 | `UNSAFE_CANCEL_REJECTED` | coordinator timeout or mempool absence cannot free reservation, reserved risk, source nullifier, input lease, or bond coverage |
| 5 | `SERIAL_DRAIN_BLOCKED` | finalized-uncleared outflow remains in `L_q`, so the same bonds cannot reserve the next unit beyond the bound |
| 6 | `FAULT_WITH_LIVE_RESERVATION` | the Ethereum fault event freezes bonds but does not pretend to pause MobileCoin; a final spend may land before its separately committed local pause but never after it, reserved records/risk survive until safe cancellation or settlement, distribution waits for Cleared/ResolvedAudit risk and exact loss proof, and proved zero-loss equivocation creates no restitution |
| 7 | `MULTI_ASSET_CORRELATED_BOUNDARY` | USDC/eUSD native vectors and common-risk values reach exact cross-direction/domain boundary; the next unit is deterministically rejected without globally deduplicating a shared-domain position |
| 8 | `GENERATION_ROLLOVER_WITH_LIABILITIES` | successor authority/capital activates in order; predecessor cannot drain or deactivate until inventory bindings, Open/CapacityReserved liabilities, live reservations/leases, and uncleared risk are zero |
| 9 | `DELAYED_CROSS_CHAIN_REALLOCATION` | both chains enforce old local allocations while risk is live; after closure each activates the same manifest at its committed local checkpoint, and any temporary stagger counts the conservative old/new union without cross-segment borrowing |
| 10 | `CROSS_CHAIN_FAULT_PROPAGATION_DELAY` | after an Ethereum bond freeze, MobileCoin may continue admitting only within the precharged maximum propagation exposure until its own causally justified pause commits; no instant remote mutation is observed, and exceeding the bound rejects |

Scenario constraints may select only environmental dimensions and finite policy
profiles. They must not select a desired terminal state. Rejection scenarios
must record the exact attempted event and rejection reason in the harness while
leaving both committed projections unchanged; absence of an action alone is not
reported as an observed rejection.

The two automatic promotions in scenario 1 are a v2 claim because they consume
authenticated remote `BridgeReleaseReceipt` proofs. A v1 deployment lacking that
receipt map may perform only the explicitly contractual/adjudicated promotion
path and must not report automatic cross-chain promotion.

## 12. Acceptance conditions

This interface may replace the active draft only after:

1. the amended acceptance contract adopts the same schemas, event names,
   culprit rules, arithmetic, selector targets, and round-trip scenario;
2. independently authored TLA+ and Python models implement all 28 event kinds,
   119 one-defect tests, and ten scenarios;
3. SANY, broad TLC safety, independent reachability, required/forbidden
   witnesses, profile partitions, twin-state truth noninterference, and exact
   per-chain-prefix and causally closed-cut projection parity, plus relevant
   linear-extension exploration or a commuting-events proof, all complete;
4. every accepted event and every safe rejection has matching results in both
   engines;
5. no stale pre-interface count or hash is reused; and
6. the final runner publishes one exact hash manifest and exits zero.

Until all six conditions hold, the authoritative result remains **UNVERIFIED**.
