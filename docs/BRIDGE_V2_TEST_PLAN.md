# Bridge escrow v3 amended acceptance contract

> STATUS: PROSPECTIVE / NOT RUN.
>
> This document is a replacement acceptance contract, not a verification
> result. No model state count, scenario result, defect result, parity result,
> implementation result, security claim, or deployment approval may be
> inferred from it. The superseded v2 hashes remain invalid under HANDOFF
> section 20. New hashes may be published only after this contract, both model
> manifests, and the runner pass the contract self-test described below.

This draft incorporates HANDOFF section 20; conversation messages 67, 68, and
69; and the subsequent schema decisions concerning source-nullifier
lifecycle, delayed collateral distribution, chain-local fault propagation,
per-chain composition logs, and loss assessment.

> **M4 custody-profile correction (2026-08-08):** threshold spend custody
> requires the one-time spend scalar `x` to remain shared; it does not require
> `b_input`, `b_pseudo`, or `z=b_pseudo-b_input` to remain shared. The launch
> baseline is `CoreCustodyKnownZ`; optional `PrivateThresholdZ` is stronger
> privacy compartmentalization and has a separate range-proof witness gate.
> Any later clause that demands share-native input/pseudo masks or forbids an
> authorized row-1 authority from knowing `z` applies only when the optional
> private-Z profile is selected. It is not a baseline custody kill test. The
> property/test tables require a later mechanical refreeze around these two
> typed profiles before the complete contract can run. Consequently, every
> exact event/property/scenario/selector counts stated elsewhere in this draft
> is provisional and is **not frozen** until that profile refreeze is complete.

## 0. Normative language and acceptance boundary

The words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, and
MAY are normative. An implementation or model fails this contract when any
MUST or SHALL statement is false, any required scenario is absent or fails,
any required one-defect selector does not violate its one named property, or
the two independently implemented bounded models disagree.

The acceptance boundary comprises:

1. one TLA+ transition system and configuration family;
2. one independently authored executable reachability model;
3. one runner that validates this document and the two machine-readable model
   manifests before running either engine;
4. the exact CORE, STAGED, and COMPOSITION property, scenario, and defect
   tables in sections 14 through 16;
5. canonical schema and policy-manifest hashes emitted by the runner; and
6. reproducible run logs containing tool versions, commands, configuration
   hashes, state counts, scenario witnesses, and named defect violations.

The CORE layer is the protocol state machine. The STAGED layer independently
replays the chain-local capacity, inventory, penalty, and lifecycle events
emitted by CORE. The COMPOSITION layer combines the Ethereum and MobileCoin
logs as a causally constrained partial order. It MUST NOT invent a single
atomic cross-chain counter, sequencer, event list, or hash chain.

## 1. Product outcome and plain-language interpretation

The bridge has two customer-visible legs:

1. a finalized USDC deposit into the Ethereum escrow authorizes release of
   eUSD, the MobileCoin stablecoin, from MobileCoin reserve inventory; and
2. a finalized return of eUSD to the MobileCoin escrow authorizes release of
   USDC from Ethereum reserve inventory.

The MobileCoin destination uses protocol-level multisignature: a policy-bound
MLSAG ownership artifact, a current FROST authorization gate, and individually
attributable approval receipts are consensus requirements of a new transaction
format. The Ethereum destination uses its native contract multisignature plus
the same attributable approval policy.

FROST alone does not identify its actual share contributors. Therefore the
accepted design deliberately requires both:

- the aggregate threshold authorization needed to control reserve value; and
- ordinary individually authenticated, bond-bound WARDEN and ACCOUNT
  approvals that bind the identical canonical base settlement digest under
  distinct role domains.

The receipts prove explicit approval, not that each named identity contributed
a FROST response share. This distinction is part of the claim.

The protocol cannot prevent an authorized quorum from lying about a remote
chain it cannot itself verify. A fully authorized false source assertion MUST
remain reachable in the baseline model. The safety claim is instead that the
release is bounded, attributable, and punishable when an objective supported
proof class exists.

## 2. Success conditions

This contract succeeds only if all of the following are demonstrated in the
finite checked domains:

1. All 100 named properties pass in both applicable engines and at every
   causally closed composition cut.
2. All 56 named scenarios produce their specified witness or specified
   rejection result as explicit runner instances.
3. Each of the 176 defect selectors, enabled alone, violates exactly its one
   named target property and the runner rejects selectors with multiple
   targets.
4. Baseline execution contains both an honest source assertion and a fully
   authorized false source assertion without any defect selector.
5. Source objective truth is absent from liability admission, reservation,
   artifact validation, and destination-release guards.
6. A destination-consensus ReserveIntent exists before an executable
   destination spend can be accepted, and finalization atomically consumes the
   reservation, source nullifier, and destination backing.
7. The complete automatic V2
   USDC-deposit to eUSD-release to eUSD-return to USDC-release round trip
   preserves source inventory, liabilities, backing, fees, reservations,
   nullifiers, and uncleared-risk accounting. The V1 round trip is separately
   labeled contractual/manual and makes no automatic MobileCoin-truth claim.
8. MobileCoin v2 supports both authenticated inclusion and authenticated-map
   nonmembership for false-source evidence. MobileCoin v1 does not claim
   automatic false-source adjudication.
9. A proven operator fault immediately freezes the implicated Ethereum bond
   positions, while pause, expulsion, and rotation occur through separate
   chain-local events with typed causal references.
10. Collateral is not distributed until every implicated pending and
    FinalizedUncleared risk has an objectively determined disposition and any
    realized loss has admissible amount evidence.
11. Per-chain allocation manifests enforce local capacity. Their conservative
    cross-chain sum is an audited deployment/governance assumption, not a
    fictional synchronous oracle.
12. CORE and STAGED agree after every chain-local event prefix, and CORE,
    STAGED, and COMPOSITION agree at every causally closed pair of chain
    prefixes.
13. MobileCoin and Ethereum implementation byte vectors reproduce the exact
    direction-specific base D, including every verifier-consumed wire byte and
    network domain; WARDEN, ACCOUNT, and FROST bind that D only through their
    distinct role/scheme messages.
14. Consensus permits non-ABSENT MobileCoin policy outputs only through the
    closed authorized creation paths and rejects caller-labelled or
    unknown-provenance outputs before they can enter a CapacityLot or ring.
15. The two-artifact ReserveInputProof construction passes the kill test for
    its exact manifest-bound custody_profile. In both profiles, the pre-intent
    key-image/DLEQ and post-D reserve-proof state machines are monotone,
    context-bound, separately nonced, and abort-burned, and no ownership
    coordinator, individual participant, or sub-threshold ownership set
    reconstructs the root or one-time spend scalar. Under
    CoreCustodyKnownZ, only the registered signed row-1 authority may receive
    complete z = b_pseudo - b_input; complete input/pseudo mask sharing is not
    a custody prerequisite. Under PrivateThresholdZ, no individual or
    sub-threshold ownership set reconstructs b_input, b_pseudo, or z, and the
    selected private-Z range-proof witness mode also passes. The selected
    accounting backend proves the remaining relations and discloses its
    separate witness only within its exact bound launch trust profile.

## 3. Failure conditions

The contract fails if any of these occurs:

- a release transition reads ObjectiveSourceHistory or a predicate derived
  only from it;
- no ordinary baseline trace contains a fully authorized false-source release;
- one source event has two live reservations or more than one final settlement;
- cancellation frees backing or capacity while an exact signed destination
  artifact can still execute;
- one CapacityLot slice is simultaneously reserved by two liabilities;
- a final destination spend precedes or bypasses destination-consensus
  reservation state;
- MobileCoin artifacts sign a wrapper hash of TxPrefix instead of the exact
  version-gated MLSAG signing digest, omit verifier-consumed range-proof bytes,
  accept an external TxSummary, or omit the MobileCoin network/genesis domain;
- a WARDEN, ACCOUNT, or FROST signature is replayable in another role/scheme
  instead of binding the same base D through its exact role domain;
- an ordinary or unsolicited MobileCoin transaction can create an eligible
  non-ABSENT spend_policy_id output without typed authorized provenance;
- under either custody profile, the ownership/equality ceremony gives any
  coordinator, individual signer, or sub-threshold ownership set enough shares
  to reconstruct the root or one-time spend scalar; under
  CoreCustodyKnownZ, complete z is delivered to anyone other than the exact
  registered signed row-1 authority; under PrivateThresholdZ, any individual
  or sub-threshold ownership set reconstructs b_input, b_pseudo, or z; or the
  accounting/range-proof prover receives witness material outside its exact
  selected trust profile;
- a key image or pre-intent transcript is substituted after IntentBindingCore
  or D exists, a reserve nonce is committed before D, a nonce survives abort,
  or any ownership message crosses a phase, set, signer, or input ordinal;
- a two-row ownership proof is treated as proof of CapacityLot identity,
  output classification, gross depletion, public range-proof validity, or change
  provenance, or MobileCoin activates without a supported accounting-proof
  backend;
- a finalized release leaves correlated exposure before its committed risk
  window clears;
- heterogeneous assets are added without a bound valuation and haircut
  manifest;
- an authenticated inclusion tree is treated as a proof of nonexistence;
- culprits, bonds, loss, restitution, bounty, pause, expulsion, or rotation are
  inferred rather than replayed from immutable records;
- a fault on one chain atomically mutates the other chain;
- capacity assumes the remote chain pauses instantly or excludes the
  detection-and-propagation exposure;
- fault evidence is silently treated as proof of realized loss or amount;
- global chronological ordering or a global cross-chain event hash is assumed;
- partial-order reduction commutes causally related or footprint-overlapping
  events;
- a selector has zero or more than one target property;
- a required property, scenario, or selector exists in prose but is absent
  from either model manifest; or
- any reported result predates the runner's contract/manifest parity self-test.

## 4. Threat model, scope, and nonclaims

The bounded model includes both bridge directions, protocol versions V1 and
V2, two or more policy epochs, overlapping but role-separated rosters, two or
more custody generations, multiple assets and reserve positions, pending and
FinalizedUncleared releases, false source assertions, false fraud claims,
equivocation, safe cancellation, operator-fault propagation, and static
cross-chain allocations.

The adversary may coordinate any identities for which the chosen trace carries
valid artifacts. The adversary may withhold, reorder, or duplicate off-chain
messages; submit a fully signed false remote-chain assertion; exploit a stale
artifact; attempt to reuse backing, nullifiers, reservations, event IDs, or
bonds; and delay remote pause propagation for the entire policy bound.

The contract does not prove:

- MLSAG, FROST, DKG, Ed25519, Keccak, authenticated-map, checkpoint, or
  finality cryptography;
- nonce secrecy, share erasure, side-channel resistance, or wallet security;
- Ethereum or MobileCoin consensus correctness;
- remote-pause delivery without a light client;
- privacy, ring-member indistinguishability, traffic-analysis resistance, or
  amount unlinkability;
- availability under policy-pool UTXO fragmentation or the operational cost of
  policy-homogeneous decoy selection;
- availability when a threshold refuses to sign or loses its shares;
- key recovery or recovery of already stranded reserve outputs;
- legal collection under the MobileCoin-v1 contractual path;
- that any provisional roster, threshold, cap, haircut, timing window, or
  valuation is economically optimal; or
- unbounded safety outside the finite domains stated by the final configs.

Cryptographic validity is represented by deterministic verification over
typed finite tokens. The implementation test programme must replace those
tokens with real cryptographic vectors and negative tests. In particular,
ReserveInputProof nonce safety, blame attribution, domain separation,
non-spend-capability, and the network-upgrade/grandfathering behavior of legacy
UNTAGGED TxOuts require implementation tests; this state model does not prove
them.

## 5. Glossary and truth separation

SourceAssertion is the immutable statement signed by the bridge approvers
about a remote source event. ClaimedLiability is the obligation created from
that assertion. Neither object is objective source-chain inventory.

Its canonical bytes include bridge_id, direction, exact source_chain_id,
exact destination_chain_id, the MobileCoin network genesis ID whenever either
side is MobileCoin, source contract/policy and event locator, source asset and
amount, destination asset and amount, recipient, asserted checkpoint/finality
context, and schema version. SourceAssertion and its commitment reject an
ABSENT, aliased, or wrong-network chain identifier. The source nullifier below
uses the exact source-chain identifier; the final authorization digest also
binds the exact destination-chain identifier, preventing the same assertion or
approval from being replayed on another MobileCoin network/fork.

ObjectiveSourceHistory is independent environment history used only as ghost
state by the specification. It may determine GroundTruthFault in invariants
and witnesses, but implementation actions MUST NOT read it.

SourceInventoryEvent is the immutable chain-local
RECORD_ESCROW_SOURCE_INFLOW emitted atomically with the actual escrow deposit
or typed return inclusion; it creates Encumbered state but asserts no finality.
SourceAdapterRecord is later observable authenticated evidence, such as an
Ethereum escrow-state proof or MobileCoin checkpoint/authenticated-map proof,
used to promote the finalized local inflow after the paired remote
FinalCommit. Neither is created merely because signers asserted that a deposit
or return exists.

Destination backing is reserve value already held on the chain where a release
will execute. A source position is value held on the opposite/source escrow.
Only finalized reference to the local inflow plus authenticated paired remote
FinalCommit may convert that source position from Encumbered into reusable
Available inventory.

FinalizedUncleared means the destination transfer has finalized but remains
inside the coalition's risk window. It continues to consume allocation and
bond capacity until detection, proof, challenge, and propagation obligations
are safely resolved.

### 5.1 Ghost-state discipline

GroundTruthFault is derived, never assigned:

    GroundTruthFault(release) =
        release is destination-finalized
        and its SourceAssertion does not match ObjectiveSourceHistory
            at the asserted checkpoint.

ObjectiveSourceHistory evolves only through independent environment actions.
For any two well-typed states with identical observable projections but
different ObjectiveSourceHistory, request construction, artifact construction,
liability admission, ReserveIntent acceptance, and destination finalization
MUST have identical enabledness and identical sets of observable successors.
The runner checks this TruthNoninterference hyperproperty with paired states
and statically checks that objective-truth identifiers occur only in an
allowlist of ghost definitions, audit predicates, and scenario assertions.

Observable proofs used by SourceAdapterSoundness or post-release adjudication
do not violate this rule. Their authenticated bytes and public commitments are
ordinary inputs. The model assumes the relevant proof systems bind those
commitments; it does not permit a transition to consult ghost truth directly.

### 5.2 Claimed liability is not source inventory

Admitting a signed SourceAssertion may create ClaimedLiability(Open). It MUST
NOT create Available or Encumbered source inventory, charge a CapacityLot, or
create a reservation. A SourceInventoryEvent may independently create
Encumbered source inventory and
pair it with the liability when identifiers and values match. A false release
with no sound SourceInventoryEvent therefore creates no magical inventory even
though all destination authorization gates can accept it.

## 6. Canonical identities and immutable records

Every record has a canonical schema version, domain separator, chain ID where
applicable, content hash, and immutable record ID derived from its complete
canonical encoding. Canonical encoding is injective over the finite model
domain.

### 6.1 Stable source nullifier

For the one-source-event to one-settlement abstraction:

    source_nullifier = H(
        BRIDGE_SOURCE_EVENT_V1,
        bridge_id,
        direction,
        canonical_source_chain_id,
        source_contract_or_policy,
        canonical_source_event_locator
    )

It MUST NOT contain protocol version, policy epoch, reservation ID, release ID,
destination transaction, retry number, fee-bump number, signer set, or
destination generation. Batching and partial settlement are outside this
contract and require a new amount-conserving nullifier scheme.

### 6.2 Required record families

The frozen schema MUST contain complete forms of:

- SourceAssertion;
- ClaimedLiability;
- SourceAdapterRecord;
- SourceInventoryEvent;
- AllocationManifest;
- ValuationManifest;
- RoleManifest and BondManifest;
- DestinationTransactionCommitment, public CapacityLot, and MobileCoin
  InputLeaseTag;
- ThresholdWitnessPackage and its VSS/roster commitments;
- ThresholdOwnershipEqualityProof, ReserveAccountingProof, and the selected
  ReserveAccountingBackendManifest;
- WardenCertificate and AccountabilityCertificate;
- MlsagArtifact and FrostArtifact for ETH_TO_MOB;
- EthereumMultisigArtifact for MOB_TO_ETH;
- ReserveIntent and CapacityDecision;
- FinalCommit;
- ObjectiveCancelProof;
- FraudClaim, Evidence, Rejection, Verdict, and LossAssessment;
- FaultBondFreeze;
- ChainPause, registered fresh gate/role manifest, and Resume;
- OperatorConsequence;
- CollateralDistribution; and
- per-chain CapacityEvent and typed CausalEventRef.

No safety-relevant field may be hidden in prose or reconstructed from mutable
configuration.

### 6.3 Acyclic intent, reservation, and authorization commitments

The commitment construction is deliberately acyclic and uses this exact
order. Before any chain mutation, the coordinator deterministically derives a
candidate liability_id from bridge, direction, stable claimed-source
nullifier, source/destination assets and amounts, and the canonical destination
obligation. It then constructs the actual pre-reservation destination object
and its commitment. Only after that commitment exists may the MobileCoin
threshold ownership ceremony publish and aggregate canonical key-image/DLEQ
shares under dedicated fresh pre-intent nonces and the exact
PreIntentKeyImageContext; this still precedes D. Reserve-proof nonce
commitments and responses do not yet exist. The exact order is:

    source_chain_id, destination_chain_id = ExactChainIds(
        direction,
        ethereum_chain_id,
        mobile_network_genesis_id
    )

    source_assertion_commitment = H(
        "BRIDGE_SOURCE_ASSERTION_V2",
        CanonicalEncode(SourceAssertion)
    )

    MobilePreReservationTxPrefix = exact canonical vNext wire TxPrefix with:
        inputs: ordered full TxIn values, including every ordered ring TxOut,
                membership proof, and input_rules value,
        outputs: ordered full TxOut values, including masked amount,
                 target/public keys, fog hint, memo, spend_policy_id,
                 bridge_lot_commitment_or_absent, and
                 threshold_witness_package_commitment_or_absent,
        fee, tombstone_block, fee_token_id,
        bridge_extension: [
            network_genesis_id, bridge_id, direction, policy_id, policy_epoch,
            generation_id, liability_id, source_nullifier,
            capacity_allocation_manifest_id,
            reservation_id = ZERO_RESERVATION_ID
        ].

    EthereumPreReservationExecute = exact EIP-712 Execute value with:
        reservation_id = ZERO_RESERVATION_ID,
        policy_id, policy_epoch, generation_id, liability_id,
        source_nullifier, token, amount, recipient, fee_or_call_value,
        escrow_contract_nonce, deadline, capacity_allocation_manifest_id,
        calldata_hash.

The exact MobileCoin pseudo outputs and block-version-selected
legacy_range_proof_bytes/range_proofs also already exist. Their commitment
vectors are recomputed from those actual bytes. Define:

    destination_pre_reservation_object_commitment =
      destination_chain == MOBILECOIN
        ? H(
              "BRIDGE_MOBILE_PRERESERVATION_TXPREFIX_V2",
              network_genesis_id,
              block_version,
              CanonicalEncode(MobilePreReservationTxPrefix),
              pseudo_output_commitments,
              range_proof_commitments
          )
        : H(
              "BRIDGE_ETH_PRERESERVATION_EXECUTE_V2",
              CanonicalEncode(EthereumPreReservationExecute)
          )

    PreIntentKeyImageContext = [
        network_genesis_id,
        block_version,
        destination_pre_reservation_object_commitment,
        owner_manifest_id,
        ownership_equality_profile,
        ownership_share_provisioning_profile,
        ownership_share_package_ids,
        ordered_input_ordinals,
        ring_set_commitments
    ]

    (canonical_key_images,
     pre_intent_key_image_transcript_commitments) =
      destination_chain == MOBILECOIN
        ? ThresholdAggregateKeyImagesAndDleqShares(
              "BRIDGE_PREINTENT_KEY_IMAGE_DLEQ_V2",
              CanonicalEncode(PreIntentKeyImageContext),
              fresh durable pre-intent nonce records
          )
        : (typed ABSENT_KEY_IMAGE_VECTOR,
           typed ABSENT_KEY_IMAGE_TRANSCRIPT_VECTOR)

    input_lease_tags = Map(
        canonical_key_images,
        ki -> H(
            "MC_INPUT_LEASE_TAG_V1",
            network_genesis_id,
            canonical_key_image_bytes(ki)
        )
    )

    IntentBindingCore = [
        bridge_id,
        destination_chain,
        direction,
        source_chain_id,
        destination_chain_id,
        mobile_network_genesis_id_or_absent,
        mobile_block_version_or_absent,
        ethereum_chain_id_or_absent,
        policy_id,
        policy_epoch,
        generation_id,
        liability_id,
        source_nullifier,
        source_assertion_commitment,
        destination_asset_and_amount,
        recipient,
        fee_or_value,
        committed_tombstone_or_expiry,
        destination_pre_reservation_object_commitment,
        capacity_lot_ids,
        canonical_key_images,
        input_lease_tags,
        pre_intent_key_image_transcript_commitments,
        spend_policy_id,
        bridge_lot_commitments,
        ring_set_commitments,
        pseudo_output_commitments,
        range_proof_commitments,
        ownership_equality_profile,
        ownership_share_provisioning_profile,
        ownership_share_package_ids,
        accounting_backend_profile,
        accounting_backend_manifest_id,
        output_classification_commitments,
        gross_lot_depletion_commitment,
        manifest_bundle_id,
        capacity_allocation_manifest_id
    ]

    unsigned_intent_commitment = H(
        "BRIDGE_UNSIGNED_INTENT_V2",
        CanonicalEncode(IntentBindingCore)
    )

    reservation_id = H(
        "BRIDGE_RESERVATION_V2",
        bridge_id,
        destination_chain,
        direction,
        policy_id,
        policy_epoch,
        generation_id,
        liability_id,
        source_nullifier,
        unsigned_intent_commitment,
        committed_tombstone_or_expiry,
        manifest_bundle_id,
        capacity_allocation_manifest_id
    )

    FinalTxPrefix = ReplaceTypedReservationId(
        MobilePreReservationTxPrefix,
        ZERO_RESERVATION_ID,
        reservation_id
    )

    FinalEthereumExecute = ReplaceTypedReservationId(
        EthereumPreReservationExecute,
        ZERO_RESERVATION_ID,
        reservation_id
    )

    final_destination_object_commitment =
      destination_chain == MOBILECOIN
        ? H(
              "BRIDGE_MOBILE_FINAL_TXPREFIX_V2",
              CanonicalEncode(FinalTxPrefix)
          )
        : H(
              "BRIDGE_ETH_FINAL_EXECUTE_V2",
              CanonicalEncode(FinalEthereumExecute)
          )

    final_tx_prefix_commitment =
        destination_chain == MOBILECOIN
          ? final_destination_object_commitment
          : typed ABSENT_MOBILECOIN_FINAL_PREFIX_COMMITMENT

    (D_MOB, DerivedTxSummary, DerivedExtendedMessageDigest) =
      destination_chain == MOBILECOIN
        ? compute_mlsag_signing_digest_vNext(
              network_genesis_id,
              block_version,
              FinalTxPrefix,
              exact pseudo_output_commitments,
              exact legacy_range_proof_bytes_or_empty,
              exact ordered_range_proofs_or_empty
          )
        : typed ABSENT_MOBILECOIN_DIGEST_TUPLE

    derived_tx_summary_hash =
      destination_chain == MOBILECOIN
        ? H(
              "BRIDGE_DERIVED_MOBILE_TX_SUMMARY_V2",
              CanonicalEncode(DerivedTxSummary)
          )
        : typed ABSENT_DERIVED_MOBILE_TX_SUMMARY_HASH

    derived_extended_message_digest =
      destination_chain == MOBILECOIN
        ? exact bytes of DerivedExtendedMessageDigest
        : typed ABSENT_DERIVED_EXTENDED_MESSAGE_DIGEST

    D_ETH =
      destination_chain == ETHEREUM
        ? EIP712Hash(
              domain = [
                  destination_chain_id,
                  escrow_contract,
                  bridge_id,
                  protocol_version
              ],
              Execute = FinalEthereumExecute
          )
        : typed ABSENT_ETHEREUM_DIGEST

    D = destination_chain == MOBILECOIN ? D_MOB : D_ETH

    RoleArtifactDigest(role, role_manifest_id, D) = H(
        "BRIDGE_ROLE_ARTIFACT_V2",
        role,
        role_manifest_id,
        D
    )

    M_WARDEN = RoleArtifactDigest(WARDEN, warden_manifest_id, D)
    M_ACCOUNT = RoleArtifactDigest(ACCOUNT, account_role_manifest_id, D)

    M_GATE =
      destination_chain == MOBILECOIN
        ? H(
              "MOBILECOIN_BRIDGE_FROST_GATE_V2",
              gate_manifest_id,
              D
          )
        : typed ABSENT_FROST_GATE_MESSAGE

    RoleApprovalReceipt = [
        role,
        role_manifest_id,
        identity_id,
        role_public_key_id,
        base_destination_digest = D,
        role_artifact_digest =
            RoleArtifactDigest(role, role_manifest_id, D),
        signature_bytes
    ]

    role in {WARDEN, ACCOUNT}

The canonical common statement is constructed only after D and contains
exactly these ancestor/public fields:

    ReserveInputStatementCore = [
        network_genesis_id,
        block_version,
        reservation_id,
        canonical_digest = D,
        spend_policy_id,
        destination_pre_reservation_object_commitment,
        final_tx_prefix_commitment,
        ring_set_commitments,
        pseudo_output_commitments,
        range_proof_commitments,
        derived_tx_summary_hash,
        derived_extended_message_digest,
        output_classification_commitments,
        ordered_canonical_key_images,
        ordered_input_lease_tags,
        pre_intent_key_image_transcript_commitments,
        ordered_capacity_lot_ids,
        gross_lot_depletion_commitment,
        protocol_fee_commitment,
        native_amount_and_risk_commitment,
        ownership_equality_profile,
        ownership_share_provisioning_profile,
        ownership_share_package_ids,
        accounting_backend_profile,
        accounting_backend_manifest_id,
        zk_circuit_id_or_absent,
        zk_verifying_key_id_or_absent,
        enclave_measurement_or_absent,
        enclave_attestation_chain_commitment_or_absent,
        enclave_freshness_checkpoint_or_absent
    ]

ReserveInputStatementCore has no proof bytes, proof hashes/commitments, bundle
commitment, signature, receipt, or transaction ID field. Those descendants are
not encoded as zero placeholders inside the statement; they are structurally
absent from its closed schema. Define:

    ThresholdOwnershipEqualityProofDigest = H(
        "BRIDGE_THRESHOLD_MLSAG_OWNERSHIP_EQUALITY_V2",
        D,
        CanonicalEncode(ReserveInputStatementCore)
    )

    ReserveAccountingProofDigest = H(
        "BRIDGE_RESERVE_ACCOUNTING_V2",
        accounting_backend_profile,
        accounting_backend_manifest_id,
        D,
        CanonicalEncode(ReserveInputStatementCore)
    )

    ReserveInputProofDigest = H(
        "BRIDGE_NONSPEND_RESERVE_INPUT_BUNDLE_V2",
        D,
        ThresholdOwnershipEqualityProofDigest,
        ReserveAccountingProofDigest
    )

    ReserveOwnershipChallengeTranscript = NewTranscript(
        "BRIDGE_THRESHOLD_MLSAG_OWNERSHIP_EQUALITY_CHALLENGE_V2",
        network_genesis_id,
        block_version,
        reservation_id,
        ReserveInputProofDigest,
        canonical ring and point encodings
    )

    ownership_equality_proof_commitment = H(
        "BRIDGE_RESERVE_OWNERSHIP_PROOF_BYTES_V2",
        exact ownership proof bytes
    )

    accounting_proof_or_attestation_commitment = H(
        "BRIDGE_RESERVE_ACCOUNTING_PROOF_BYTES_V2",
        exact accounting artifact bytes
    )

    bundle_commitment = H(
        "BRIDGE_RESERVE_INPUT_BUNDLE_BYTES_V2",
        CanonicalEncode(ReserveInputStatementCore),
        ownership_equality_proof_commitment,
        accounting_proof_or_attestation_commitment
    )

The ownership proof uses the distinct structural challenge transcript above.
Merely hashing a different message is insufficient: the ordinary RingMLSAG
verifier MUST reject this proof type before interpreting responses, and the
reserve-proof verifier MUST reject an ordinary spend signature.

MobilePreReservationTxPrefix is the actual proposed wire prefix, not
CanonicalEncode(IntentBindingCore). No compact commitment may replace a full
ring member, membership proof, output, or other byte consumed by the
destination verifier. Each supplied byte string must open its commitment, and
the legacy single-range-proof versus multiple-range-proofs representation must
satisfy the exact MobileCoin block-version empty/nonempty rule.

IntentBindingCore and unsigned_intent_commitment exclude reservation_id, the
final destination object, derived TxSummary/extended-message results, and every
signature/proof or descendant commitment. The typed zero reservation ID is
replaced exactly once. DerivedTxSummary is constructed internally by
compute_mlsag_signing_digest_vNext from FinalTxPrefix and pseudo outputs and,
when required by block version, is bound into D_MOB. Its stored hash and the
derived extended-message digest are recomputed descendants only and feed no
ancestor. MobileCoin also checks network_genesis_id against local immutable
genesis state, and vNext binds it in the signing-digest domain.

`compute_mlsag_signing_digest_vNext` is a required network-upgrade function,
not an assertion about the current API. At reviewed MobileCoin commit
05cb699f8f4cc1bc21186392545820c5b38408db, the existing
`transaction/core/src/ring_ct/signing_digest.rs::compute_mlsag_signing_digest`
takes block_version, TxPrefix, pseudo outputs, legacy range-proof bytes, and
the range-proof vector; it derives TxSummary internally and returns the MLSAG
digest, TxSummary, and extended-message digest. vNext must preserve those exact
version rules while adding the immutable network/genesis domain and consuming
the new actual bridge fields through the upgraded wire prefix/digest.

After D exists, the distinct reserve-only nonce-commitment and response rounds,
accounting proof generation, and WARDEN/ACCOUNT role receipts may proceed.
OPEN_LIABILITY recomputes the
candidate identifiers and direction-specific D, validates and stores the exact
D-bound receipt references and candidate intent/resource commitments, and
acquires the claim lock. RESERVE_RELEASE_INTENT revalidates identical
D/receipts/proofs and still-available resources. Only after that prior-block
reservation exists may the separate MLSAG/FROST or Ethereum execution
ceremony authorize settlement.

WARDEN and ACCOUNT sign M_WARDEN and M_ACCOUNT; MobileCoin FROST signs M_GATE;
native MLSAG verifies D_MOB; and the Ethereum escrow verifies D_ETH. Every
artifact binds the identical base D under a distinct role/scheme domain. No
signature, proof byte/hash/commitment, bundle commitment, receipt ID,
transaction ID, derived summary, or extended-message result feeds an ancestor.
Changing any exact pre-signing prefix, pseudo-output, range-proof, network, or
IntentBindingCore byte changes the applicable descendants or makes its
commitment opening fail. The runner and both model manifests MUST declare and
byte-compare this exact DAG and both direction-specific digest algorithms.

## 7. Concrete authorization and role separation

No release guard may infer authorization from quorum availability. It validates
the actual immutable artifacts carried by the transaction or referenced
on-chain record.

ETH_TO_MOB requires:

- one valid policy-bound MLSAG ownership artifact for every consumed
  MobileCoin input;
- one valid current-epoch FROST gate artifact;
- one current-epoch WARDEN certificate;
- one current-epoch ACCOUNT certificate; and
- one live MobileCoin ReserveIntent referenced by the spend.

MOB_TO_ETH requires:

- one valid current-epoch Ethereum escrow multisig authorization;
- one current-epoch WARDEN certificate;
- one current-epoch ACCOUNT certificate; and
- one live Ethereum ReserveIntent referenced by the call.

Owner, FROST gate, Ethereum multisig, WARDEN, and ACCOUNT rosters are distinct
role mappings with independent thresholds. The same identity may occupy more
than one role only through a unique immutable
(identity_id, role, role_public_key) binding. Cross-role key overlap is allowed
only if the immutable policy explicitly permits it; it still requires a fresh
signature over each distinct role digest. A public key and identity may each
occupy at most one slot within any one role manifest. WARDEN receipts verify only M_WARDEN,
ACCOUNT receipts verify only M_ACCOUNT, and the FROST gate verifies only
M_GATE. A valid receipt, key, or signature from one role cannot satisfy any
other role even when rosters overlap. MLSAG and Ethereum execution
authorization remain in their native scheme domains over D_MOB and D_ETH.

Signer participation is an ordered fixed-width slot vector with explicit
length and the exact immutable role-key binding. Duplicate identities,
duplicate keys, padding, wrong-role identities, wrong keys, wrong epochs,
cross-role replay, and base-digest mismatch are representable and rejected.

The WARDEN and ACCOUNT artifacts are individually attributable. Each approving
identity is bound to exactly one historical bond position in the cited
BondManifest. Role overlap never duplicates that identity or bond in capacity,
culprit, freeze, slash, or distribution arithmetic.

## 8. Destination-consensus reservation and lifecycle

### 8.1 Required ordering

The logical order is:

    SourceAssertion plus canonical destination obligation
      -> construct exact zero-reservation-ID destination wire material,
         including MobileCoin full TxPrefix, pseudo-outputs, and range proofs
      -> derive candidate liability_id, IntentBindingCore, unsigned commitment,
         reservation_id, final nonzero-ID execution bytes, and
         direction-specific D; MobileCoin derives TxSummary internally
      -> WARDEN/ACCOUNT receipts and both ReserveInputProof artifacts
      -> OPEN_LIABILITY: ClaimedLiability(Open) plus claim lock
      -> RESERVE_RELEASE_INTENT: CapacityReserved
      -> destination FinalCommit: Settled plus FinalizedUncleared risk
      -> risk Cleared after the committed window.

MobileCoin adds a ReserveIntentTx family and a typed reservation index separate
from the typed source-nullifier index. Ethereum adds equivalent reserveRelease
contract state. Each destination locally and atomically checks:

- the liability is Open and owns the exclusive stable-source-nullifier claim
  lock;
- sufficient selected public CapacityLots are Available; for MobileCoin these
  lots do not identify real UTXOs;
- the source nullifier is Free;
- every MobileCoin InputLeaseTag is canonical, duplicate-free, and
  Free;
- every MobileCoin ThresholdOwnershipEqualityProof and the selected
  ReserveAccountingProof backend/manifest verify against the exact wire
  material and D;
- intent_commitment, reservation ID, and D are canonical and acyclic;
- WARDEN and ACCOUNT certificates and historical bonds are valid;
- the cited local AllocationManifest is active;
- per-asset reserve and local allocation limits pass; and
- the relevant chain is not locally paused.

Acceptance atomically records:

- ReserveIntent(Live);
- CapacityDecision(Accepted);
- ClaimedLiability(CapacityReserved);
- CapacityLots Available to ReservedIntent(reservation_id);
- MobileCoin InputLeaseTags Free to Live(reservation_id, ring_binding);
- source nullifier Free to Reserved(reservation_id); and
- release risk Proposed to CapacityReserved(reservation_id).

No destination spend/call is consensus- or contract-executable without the
live exact reservation ID. The model does not claim to prevent parties from
creating signature bytes early; it proves that those bytes cannot authorize a
state transition before reservation exists.

Off-chain signatures and mempool observation are not committed protocol state.
There is no AuthorizedPending or AcceptedPending event/state. A final
EscrowSpendTx/execute call validates all executable artifacts and uses the
reservation atomically in FinalCommit.

### 8.2 Atomic final commit

FinalCommit validates the exact destination authorization artifacts and live
reservation, then atomically:

- consumes the reservation;
- moves the source nullifier Reserved(reservation_id) to Consumed(release_id);
- moves CapacityLots ReservedIntent to Spent and creates exact accounting
  change lots;
- validates MobileCoin key-image-to-tag derivation and moves tags Live to
  Consumed;
- records the destination payout and fees;
- moves the liability CapacityReserved to Settled;
- moves release risk CapacityReserved to FinalizedUncleared; and
- retains the full risk value in local allocation and coalition L_q.

A partially applied final commit is forbidden.

### 8.3 Source-nullifier lifecycle

The current-state index is:

    Free -> Reserved(reservation_id) -> Consumed(release_id)

Safe cancellation may return Reserved(reservation_id) to Free, but the
append-only history retains the reservation and cancellation records. At most
one live reservation may own a source nullifier. A canceled event may later be
reauthorized under a new deterministic reservation only when the replacement
rule makes the new canonical intent distinct and no prior final consumption
exists.

### 8.4 Backing and liability lifecycle

Liability states are:

    Open -> CapacityReserved -> Settled
             |
             +-> Open by safe cancellation

The distinct claimed-liability binding is:

    Unbound -> Bound(liability_id) -> Settled(liability_id, release_id)

OPEN_LIABILITY performs Unbound to Bound. Safe cancellation leaves Bound
unchanged; final settlement moves it to Settled.

Backing states are:

    Available -> ReservedIntent(reservation_id) -> Spent(release_id)
                      |
                      +-> Available by safe cancellation

Release-risk states are:

    CapacityReserved(reservation_id)
        -> FinalizedUncleared(release_id)
        -> Cleared(release_id)
        -> ResolvedAudit(release_id)

    CapacityReserved(reservation_id)
        -> Cancelled(reservation_id) by safe cancellation

Safe cancellation moves CapacityReserved back to the same Open liability,
CapacityLot ReservedIntent back to Available, and moves release risk
CapacityReserved to Cancelled only after the proof in section 8.6. The Open
liability retains the exclusive source-claim lock for retry; no cancellation
or abandonment transition returns the binding to Unbound. OPEN_LIABILITY
acquires that lock atomically and admits at most one live Open,
CapacityReserved, or Settled liability per stable nullifier. ReserveIntent is
the first transition that selects and locks backing, so there is no standalone
Backed or Committed state and no backing-lock gap. One CapacityLot slice may
be selected by at most one live reservation. Spent and release-risk history is
immutable. Change is a new position and cannot silently reuse the spent ID.

### 8.5 MobileCoin capacity lots and private input selection

Consensus reserves public CapacityLot accounting value, not a real MobileCoin
TxOut or ring index. A CapacityLot has one asset, native amount, conservative
risk value, generation, custody/failure domain, provenance, and lifecycle
state. An Ethereum lot may refine to an exact escrow balance lot. A MobileCoin
lot refines only to aggregate policy-pool capacity. Its public reservation
MUST NOT reveal which member of an MLSAG ring is real.

The authorized ownership participants may know the complete selected rings
and their input ordinals; ring-set secrecy from those signers is not a claim.
The consensus-visible reservation still contains no real-input index, and no
individual or sub-threshold ownership set receives the complete root or
one-time spend witness. Under CoreCustodyKnownZ, the exact registered signed
row-1 authority may receive complete z; under PrivateThresholdZ, no individual
or sub-threshold ownership set receives complete b_input, b_pseudo, or z.

The baseline TxOut upgrade adds an immutable cleartext spend_policy_id. Legacy
and ordinary outputs are UNTAGGED. A standard transaction ring contains only
UNTAGGED members. A bridge EscrowSpendTx ring contains only members carrying
the one exact bridge spend_policy_id cited by its manifest. Mixed rings,
operator-supplied labels, and treating a legacy output as policy-bound are
consensus-invalid. This policy-homogeneous ring design is Josh's selected
option A: it preserves the hidden real index inside the eligible policy pool
but partitions the anonymity set. A zero-knowledge inventory/global-decoy
variant is future work and not part of this baseline.

The tag is trustworthy only because consensus also restricts **output
creation**. An ordinary/standard transaction may create only an
ABSENT/UNTAGGED TxOut. A non-ABSENT spend_policy_id may be created only by one
of these closed authorization paths:

- CAPITALIZE_EXTERNAL_EUSD after exact owner/policy/generation authorization;
- CAPITALIZE_PREDECESSOR_TRANSFER consuming cited eligible predecessor lots;
- a typed MobileCoin BridgeReturn/RECORD_ESCROW_SOURCE_INFLOW output whose
  canonical escrow recipient, policy ID, bridge-lot commitment, and provenance
  are derived from its authorized return intent, begins EncumberedSource, and
  exposes no caller-chosen label; or
- exact same-CapacityLot bridge change created atomically by an authorized
  FINALIZE_RELEASE.

Each such output carries an immutable bridge_lot_commitment whose asset,
generation, owner authority, CapacityLot ID, policy ID, provenance event, and
amount commitment validate against that creating transition. Promotion of a
typed BridgeReturn changes its accounting eligibility but does not
retroactively alter its immutable policy/lot fields. An unsolicited or
non-typed transfer, self-labelled output, unknown-provenance output, malformed
output, or wrong-lot output is rejected from the policy pool and is ineligible
as a CapacityLot or ring member. This prevents an unaffiliated transaction
from poisoning the policy anonymity pool or manufacturing apparent eligible
decoys.

Before reservation, the custody group publishes each true input's canonical
ordinary MLSAG key image and the network-global lease tag:

    input_lease_tag = H(
        "MC_INPUT_LEASE_TAG_V1",
        mobilecoin_network_genesis_id,
        canonical_key_image
    )

The domain and network genesis ID are stable. The tag contains no bridge,
epoch, generation, protocol version, retry, salt, ring ordering, or reservation
ID. Publishing the ordinary key image does not identify the real member of its
public MLSAG ring. The distinct typed lease state is:

    Free -> Live(reservation_id, ring_binding) -> Consumed

Before an output can be eligible private backing under either profile, the
historical owner manifest must identify a verifiable PedPoP/DKG root-spend
group, its threshold and verification shares, and the pinned one-time-offset
suite. At input selection, the authorized cohort derives
delta = Hs(aR) + Hs_subaddress(a || i), verifies P = B + delta*G before any
nonce reservation, and applies delta to selected-set root shares without
constructing the complete one-time scalar x. A missing, malformed,
wrong-roster, below-threshold, unrecoverable, or public-key-inconsistent root
share/offset record makes that TxOut ineligible and cannot be repaired by an
operator label.

CoreCustodyKnownZ imposes no per-output amount-blinding VSS prerequisite. Its
registered signed row-1 authority may derive or receive complete b_input,
b_pseudo, and z within the exact manifest-bound disclosure profile.
PrivateThresholdZ adds a separate eligibility gate: every authorized
policy-output creation path—external capitalization, predecessor transfer,
typed BridgeReturn, and same-lot change—must establish authenticated
input/pseudo mask shares or an approved equivalent MPC witness without
reconstructing b_input, b_pseudo, or z at an ownership participant. Because
MobileCoin MaskedAmountV2 derives its amount blinding through a nonlinear KDF
of a shared-secret term such as aR, applying that KDF independently to
Shamir/FROST key shares is invalid. The private-Z profile must use distributed
generation, an independently reviewed MPC/VSS derivation and resharing
protocol, or another pinned vNext witness rule, and must cover typed returns,
roster refresh/rotation, participant loss, backup/recovery, and
historical-manifest verification. Until one such path and its private-Z
range-proof witness mode are pinned, PrivateThresholdZ outputs are ineligible;
that omission does not invalidate CoreCustodyKnownZ outputs.

Once valid root-spend shares and a verified one-time offset exist—and, for
PrivateThresholdZ, valid mask shares or the pinned equivalent also exist—the
ownership/equality workflow uses a pre-intent key-image/DLEQ phase followed,
after D exists, by a fresh two-round/two-row reserve-proof ceremony per input:

1. Before D is known, each selected historical-owner participant uses a fresh
   durable pre-intent nonce record and publishes an authenticated key-image
   share with its consistency/DLEQ proof under
   `BRIDGE_PREINTENT_KEY_IMAGE_DLEQ_V2`. The exact PreIntentKeyImageContext
   binds the zero-reservation-ID destination object, owner manifest, ownership
   and provisioning profiles/package IDs, ordered input ordinals, and ring-set
   commitments. Valid shares aggregate to the canonical key image; the exact
   ordered transcript commitments and key image then enter IntentBindingCore.
2. The protocol derives the lease tags, unsigned intent, reservation ID, final
   destination object, and D from that immutable aggregate. Only now does each
   selected ownership participant begin a different reserve-only nonce round
   and publish fresh row-0 commitments alpha_0*G and alpha_0*Hp(P_l). Under
   CoreCustodyKnownZ, the registered row-1 authority publishes alpha_1*G;
   under PrivateThresholdZ, each selected participant publishes a row-1 nonce
   commitment share. Every commitment binds the committed pre-intent aggregate,
   reservation ID, D, input ordinal, profile, signer set, and reserve challenge
   domain.
3. After the aggregate reserve challenge is fixed, each selected participant
   returns a verifiable row-0 response share for its offset root-spend share.
   Under CoreCustodyKnownZ, the registered signed row-1 authority returns the
   row-1 response for complete z = b_pseudo - b_input. Under
   PrivateThresholdZ, each selected participant instead returns a verifiable
   row-1 z response share. Only the identical profile/package/ring/signer/input
   context may aggregate these values into ThresholdOwnershipEqualityProof.

The phase states are exact and monotone, mirroring a DKG-style state machine:

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
          -> Row1RelationProvided
          -> AggregateVerified
          -> Consumed

        ReserveNonceCommitted | OwnershipRowShared | Row1RelationProvided
          -> ReserveAbortedBurned(blame_or_abort_receipt)

    SigningNonceState:
        NonceUnused -> NonceCommitted -> NonceConsumed
                                   -> NonceAbortedBurned(blame_or_abort_receipt)

Each durable nonce record is uniquely keyed by participant, key epoch,
artifact domain, exact context digest, input ordinal, share family, and round.
Neither retry nor abort may return it to NonceUnused.

Each message commits to its previous phase, participant and input ordinal,
exact ring/package set, owner manifest, and phase domain. Pre-intent messages
cannot carry reservation_id or D. Reserve messages additionally carry the
committed pre-intent aggregate, reservation_id, D, and reserve challenge
domain. Out-of-order, duplicate, cross-set, cross-input, cross-phase, or
post-abort messages deterministically reject.

The reserve ceremony and later final-spend MLSAG ceremony are separate and use
independent nonce material. Nonces are also independent across inputs, retries,
roles, and transcript domains, with a durable consumed-nonce ledger. A bad
key-image share/DLEQ, bad signed row-1 response or private-Z response share,
signer-set or cross-input share swap, malformed/identity key image, nonce reuse,
or response generated before D rejects and reveals no secret. “Two rounds”
describes only the post-D
reserve proof; it excludes both prerequisite share provisioning and the
separate pre-intent key-image/DLEQ state machine.

ReserveIntent carries a ReserveInputProof with **two distinct proof
families**. It MUST NOT represent them as one MLSAG proof.

First, every proposed input carries a domain-separated, non-spend-capable
ThresholdOwnershipEqualityProof. Its intended algebra is a two-row
MLSAG-style proof with a threshold-distributed row 0 over the complete canonical
ring and
ThresholdOwnershipEqualityProofDigest:

- row 0 proves knowledge of the real one-time private key x and binds the
  ordinary key image and network-global lease tag;
- row 1 proves knowledge of z = b_pseudo - b_input and the exact relation
  C_pseudo - C_input = zG for the same hidden ring member;
- both rows bind the exact ring ordering, pseudo-output, base D, permanent
  ring binding, spend_policy_id, and historical owner manifest; and
- the transcript/domain is incompatible with an MLSAG destination spend.

This is not stock single-row FROST: row 0 requires the MobileCoin dual-generator
key-image relation, and row 1 must prove the commitment-difference relation.
The custody profile controls only who may hold the row-1 witness. Under
CoreCustodyKnownZ, one exact manifest-registered authority may hold complete z
and produce a signed, transcript-bound row-1 commitment and response; no other
participant gains that opening. Under PrivateThresholdZ, row 1 is additionally
threshold-distributed and no individual participant learns complete b_input,
b_pseudo, or z. A Serai-style complete opening held by the registered Core
authority is therefore not a baseline custody failure; the same disclosure to
an unregistered participant, or to any individual in PrivateThresholdZ, is.

Second, one transaction-wide ReserveAccountingProof binds the identical
hidden selected inputs and exact actual transaction to all facts that the two
MLSAG rows do **not** prove: CapacityLot identity/provenance, asset and token,
input/output amount relations, output classification, gross depletion, fee,
binding to the exact independently verified public range-proof bytes/result,
and exact same-lot change. Its backend is a
closed activation-manifest choice:

    accounting_backend_profile in {
        ZK_ACCOUNTING_CIRCUIT_V1,
        SGX_ATTESTED_ACCOUNTING_V1
    }

There is no NONE, MLSAG_ONLY, coordinator assertion, or opaque Boolean
backend. ZK_ACCOUNTING_CIRCUIT_V1 requires a pinned circuit/verifying key and
declared prover/witness boundary. SGX_ATTESTED_ACCOUNTING_V1 requires
pinned measurements, attestation roots/freshness and anti-rollback rules,
and deterministic consensus verification. Its manifest declares the exact
accounting-witness disclosure boundary; any additional threshold/MPC handling
must itself be pinned rather than inferred. Either backend must bind its exact
manifest ID, public statement, D, and the
ThresholdOwnershipEqualityProof statements. Ordinary MobileCoin verification
checks the exact range proofs and public commitment-balance equations directly;
the accounting backend need not claim knowledge of a range-proof opening unless
the finally selected circuit explicitly requires and proves one.
A valid Bulletproof/range proof establishes its ordinary RingCT range claim; it
does not by itself establish CapacityLot identity, output classification, or
same-lot provenance.
Activation fails closed if the selected backend or its verifier is absent,
unknown, stale, unverifiable, or cannot prove every required accounting
relation.

The exact proof, share-package, and distributed-witness schemas are:

    ReserveInputProof = [
        bundle_domain,
        statement_core = ReserveInputStatementCore,
        ownership_equality_proof_bytes,
        ownership_equality_proof_commitment,
        accounting_proof_or_attestation_bytes,
        accounting_proof_or_attestation_commitment,
        bundle_commitment
    ]

    ThresholdWitnessPackage = [
        package_id,
        policy_id,
        generation_id,
        owner_manifest_id,
        custody_profile,
        tx_out_public_key,
        masked_amount_commitment,
        provisioning_profile,
        ordered_participant_ids,
        root_spend_group_key,
        root_spend_share_commitments,
        one_time_offset_suite_and_binding,
        private_mask_share_commitments_or_absent,
        core_row1_authority_id_or_absent,
        encrypted_authenticated_share_commitments,
        private_vss_or_mpc_correctness_proof_commitment_or_absent,
        activation_checkpoint,
        retirement_checkpoint_or_absent
    ]

    ThresholdOwnershipParticipantWitnessShare[
        participant_id,
        input_ordinal
    ] = [
        offset_root_spend_share_i,
        b_input_share_i_or_absent,
        b_pseudo_share_i_or_absent,
        z_share_i_or_absent,
        local_nonce_state,
        private_vss_or_mpc_openings_or_absent
    ]

    CoreKnownZRow1AuthorityWitness[
        authority_id,
        input_ordinal
    ] = [
        z,
        input_and_pseudo_openings_or_absent,
        local_nonce_state,
        signed_profile_and_transcript_binding
    ]

    ThresholdOwnershipPublicProof = [
        pre-intent canonical-key-image/DLEQ transcript refs and aggregate binding,
        profile-typed row-1 commitment/response and relation proof,
        exact input-ordinal/ring-set binding,
        aggregated two-row MLSAG ownership/equality proof
    ]

    ReserveAccountingPrivateWitness = [
        bridge_lot_commitment_openings,
        input/output amount and change openings,
        output classification and gross-depletion witness
    ]

    custody_profile in {
        CORE_CUSTODY_KNOWN_Z_V1,
        PRIVATE_THRESHOLD_Z_V1
    }

    ownership_equality_profile = [
        proof_suite = PROFILE_TYPED_MLSAG_OWNERSHIP_EQUALITY_V1,
        custody_profile,
        core_row1_authority_id_or_absent,
        private_z_range_proof_witness_mode_or_absent
    ]

    bundle_domain = BRIDGE_NONSPEND_RESERVE_INPUT_BUNDLE_V2

    ownership_share_provisioning_profile in {
        ROOT_PEDPOP_PLUS_ONETIME_OFFSET_V1,
        ROOT_PLUS_TXOUT_VSS_MASK_SHARES_V1,
        ROOT_PLUS_APPROVED_MPC_MASK_DERIVATION_V1
    }

    accounting_backend_profile in {
        ZK_ACCOUNTING_CIRCUIT_V1,
        SGX_ATTESTED_ACCOUNTING_V1
    }

No complete root or one-time spend witness is reconstructed in either profile.
Each ownership participant retains only its authenticated offset root-spend
share plus fresh nonce state. In CoreCustodyKnownZ, only the registered signed
row-1 authority additionally retains the complete mask-difference witness. In
PrivateThresholdZ, participants retain only authenticated b_input_i,
b_pseudo_i, and z_i shares, and no complete mask witness is reconstructed. The
consensus verifier receives the public rings, ReserveInputStatementCore, and
proof bundle, never the real-input index, full spend secret, reconstructed
masks, or lot/opening witnesses. A ZK or SGX accounting prover may receive
ReserveAccountingPrivateWitness only according to its exact declared trust
profile; that is a separate disclosure boundary and not a property supplied by
threshold MLSAG.

Public consensus state receives the ordinary key image, lease tag, exact
pre-intent key-image transcript commitments, both proof
statement/verification results, ring and pseudo-output commitments,
CapacityLots, and unsigned-intent commitment; it receives no real-index field,
private amount, or blinding.

No ownership coordinator, signer, host, or sub-threshold ownership set may
receive or reconstruct the root or one-time spend scalar. The row-0 family MUST
use a threshold-distributed ceremony under the exact historical owner manifest
with independent nonces, transcript-bound shares, and explicit abort/retry
rules. CoreCustodyKnownZ permits complete z only at its exact registered signed
row-1 authority. PrivateThresholdZ additionally forbids any individual or
sub-threshold set from reconstructing b_input, b_pseudo, or z and MUST bind its
pinned private-Z range-proof witness mode. The accounting backend's different
disclosure boundary is accepted only if its exact launch profile is selected,
reviewed, and bound into IntentBindingCore/D. The concrete profile-specific
protocols and security reductions remain unresolved; failure to pin the
selected profile is a release-blocking kill test, while an unselected
PrivateThresholdZ profile does not block CoreCustodyKnownZ.

The first accepted proof also establishes a permanent
KeyImageRingBinding:

    key_image -> salted canonical ring-member-set commitment.

The opening is retained by the authorized custody protocol and enclave. Any
retry must prove the same opening and canonical ring-member set; neither a new
salt nor a new set is accepted for that key image.

ReserveIntent atomically reserves sufficient unique CapacityLot slices and a
duplicate-free exact vector of canonical key images and valid Free tags. The
live tag set is pairwise disjoint across reservations and disjoint from the
network-global stable tags of every spent key image across all epochs,
generations, retries, versions, and bridges on that network. Activation
requires a complete deterministic backfill of all historical ledger key images
into the spent-tag index; an absent or unaudited backfill entry is not treated
as Free.

The public CapacityLot charge equals gross reserve depletion, not merely the
customer amount:

    gross depletion =
        released value
        + fees
        + every output leaving the same CapacityLot/policy domain.

Exact change returns to the same CapacityLot. Every real input and every change
output has the same asset, generation, owner authority, CapacityLot identity,
and spend_policy_id committed by the reservation. The selected accounting
backend proves the confidential input/output/opening relations; consensus
recomputes the public aggregate charge, verifier result, and conservative risk
conversion. A public commitment or operator label alone cannot establish
eligibility or conservation.

FinalCommit validates the exact reserved unsigned transaction,
ThresholdOwnershipEqualityProof vector, ReserveAccountingProof, and artifact bundle,
then requires exact vector equality between final key images and
reserved tags in canonical input order. It verifies tag derivation, ordinary
ledger key-image spentness, and one-time consumption before moving each tag to
Consumed. It cannot substitute a ring, pseudo-output, CapacityLot amount,
tombstone, key image, or tag.

ReserveIntent must be finalized in a strictly earlier MobileCoin block than
FinalCommit. Whole-block validation rejects any unordered or conflicting
combination involving the same liability, reservation, key image, tag, or
source nullifier, including reserve/spend, reserve/cancel, cancel/retry,
cancel/final, and double-reserve/final conflicts. Transaction ordering within
one proposed block cannot make one of these combinations valid.

Safe cancellation alone returns a Live tag to Free while retaining immutable
history. A retry may re-lease it only after consensus recorded Cancelled and
in a later block, and must open the permanent binding to the same canonical
ring-member set. Proof randomness may refresh but the binding salt/opening may
not. Any later privacy-preserving equivalent requires a new contract revision.

The defect model MUST make two reservations secretly select the same UTXO by
disabling proof or lease injectivity. Both reservations remain fully charged in
CapacityLot and L_q accounting. At most one final can pass ordinary key-image
spentness; the other remains charged until exact safe cancellation. Forged
ThresholdOwnershipEqualityProof or ReserveAccountingProof, duplicate live tag, or final key-image substitution is
objective private-backing fault evidence. The applicable attributable culprits
and penalty path are the immutable WARDEN/ACCOUNT approvals for the offending
reservation or the exact per-role intersections for incompatible same-tag
approvals; realized loss may be zero.

InputLeaseTag is separate from SourceNullifier. The former prevents
private reserve-input collision within MobileCoin; the latter prevents two
destination settlements for one remote source event.

### 8.6 Safe cancellation

Cancellation fails closed unless an ObjectiveCancelProof proves the exact
signed destination artifact is no longer executable.

For MobileCoin the proof binds the exact transaction commitment and tombstone,
shows finalized chain height beyond that tombstone, AND proves finalized
non-inclusion/non-execution of that exact action and every committed allowed
replacement. Tombstone expiry without exact finalized nonexecution is
insufficient.

For Ethereum the proof binds the exact contract, nonce, calldata commitment,
expiry, and authorization epoch, and proves from finalized contract state that
the nonce or active epoch is permanently invalid for that action and that no
successful execution occurred.

Coordinator assertion, timeout alone, missing gossip, local database absence,
or a claim that a signer aborted is insufficient. Cancellation only reverses
the live reservation, ReservedIntent backing, CapacityReserved liability,
Reserved source nullifier, Live input leases, and CapacityReserved risk to
their exact cancel states. It never erases history or clears an already
finalized position.

## 9. Source inventory and the complete customer cycle

Local inclusion and later promotion are separate. One chain-local
RECORD_ESCROW_SOURCE_INFLOW event atomically accompanies the accepted bridge
deposit method or typed MobileCoin return inclusion and creates an Encumbered
source position. It asserts no finality. If the local block is reorganized,
both the escrow inclusion and this event roll back together; there is no
second keeper-generated finalization event.

PROMOTE_SETTLED_SOURCE_INFLOW later consumes:

- a finalized reference to that exact local inflow event; and
- a finalized authenticated causal reference to the paired remote
  FinalCommit, or the explicit V1 contractual/manual result.

Its SourceAdapter verification checks canonical chains, checkpoint/root,
finality rule, proof type, membership or nonmembership path, contract/policy,
event locator, asset, amount, liability, release, and recipient. A forged
checkpoint signature, root, causal reference, proof, or normalized inflow
binding is rejected.

Only this promotion moves the Encumbered position to Available. It occurs
after destination FinalCommit but need not wait for the later risk Cleared
state; FinalizedUncleared remains in L_q independently. If there is no exact
local inflow event or paired final settlement evidence, no source inventory is
promoted.

The full automatic honest scenario is explicitly V2 and MUST execute these
concrete steps:

1. A USDC transfer and local Ethereum RECORD_ESCROW_SOURCE_INFLOW atomically
   create Encumbered USDC; the honest trace later establishes its finality.
2. An ETH_TO_MOB ClaimedLiability is backed by Available eUSD, reserved on
   MobileCoin, and finalized; the eUSD leaves MobileCoin reserve.
3. A finalized reference to the local USDC inflow plus authenticated proof of
   the paired MobileCoin FinalCommit promotes it to Available Ethereum reserve
   inventory.
4. The customer return and local MobileCoin RECORD_ESCROW_SOURCE_INFLOW
   atomically create Encumbered eUSD.
5. A MOB_TO_ETH ClaimedLiability is backed by the Available USDC created in
   step 3, reserved on Ethereum, and finalized; USDC leaves Ethereum reserve.
6. A finalized reference to the local eUSD inflow plus authenticated proof of
   the paired Ethereum FinalCommit promotes it to Available MobileCoin reserve
   inventory.
7. Both liabilities become Settled at FinalCommit while their separate risk
   positions pass through FinalizedUncleared to Cleared; each source nullifier
   has exactly one reserve and one consume transition; all principal, change,
   and fees conserve per asset; no deposit or return is counted twice.

Preseeded reserve capital may supply the first eUSD backing, but it is not a
substitute for steps 1, 3, 4, and 6.

The V1 reverse leg has no automatically verifiable MobileCoin receipt. Its
full-cycle source promotion and loss adjudication therefore require the
explicit contractual/manual adapter configured by policy. That separate
scenario is evidence of accounting-path behavior, not a protocol proof of
remote truth or automatic enforceability.

## 10. Capacity, allocations, and correlated exposure

### 10.1 Local synchronous admission

Capacity is not a post-hoc replay decision. Each chain implements:

    propose -> local CapacityDecision/ReserveIntent -> atomic FinalCommit

The destination rejects over-cap ReserveIntent before any executable final
state transition. A later auditor replay is a parity check, not the admission
oracle.

Each chain separately tracks:

- current inventory stock by asset: Available plus ReservedIntent backing;
- current live risk by asset: CapacityReserved plus FinalizedUncleared;
- immutable conservation history by asset: deposits/returns, payouts, fees,
  change, and Spent records.

Historical Spent or released volume remains in conservation history but leaves
current inventory/allocation exposure after its FinalizedUncleared risk
clears. This prevents a lifetime-volume cap. The system MUST NOT directly add
USDC units to eUSD units.

For every public CapacityLot, both native units and recomputed conservative
risk units satisfy:

    initial eligible value
      + promoted source inflow
      - finalized outflow
      - resolved incident loss
    =
    free value
      + sum of unique live reservation charges.

Free value is nonnegative. FinalizedUncleared outflow remains in L_q and
accountability state but is not simultaneously counted as free inventory.
Each reservation charges exactly one liability and each selected lot slice
once.

### 10.2 Valuation manifest

A content-addressed ValuationManifest defines conservative conversion and
haircut functions from each asset into one common risk unit for bond capacity.
It includes source, timestamp/epoch, rounding direction, stale-data behavior,
and update rules. All rounding is against the bridge. A launch assumption that
one USDC equals one eUSD is policy input, not cryptographic fact.

### 10.3 Static allocation manifests

Every destination chain enforces its own immutable AllocationManifest keyed by
chain, direction, generation, asset, coalition/bond epoch, and validity
interval. D binds its manifest ID.

Without verified cross-chain state, no chain enforces a global atomic counter.
Instead deployment governance MUST establish and audit:

    sum of every simultaneously exercisable live allocation for coalition q
        across both chains, directions, and overlapping generations
    plus committed detection-and-propagation headroom
        <= B_min[f, authorization_window] / 2

and:

    every per-asset local allocation
        <= eligible local reserve for that asset
        <= the applicable correlated failure-domain cap C_loss.

B_min[f, authorization_window] is the minimum collectible haircut-adjusted
bond value of the exact proof-defined culprit set for fault class f, minimized
over every executable approval set or incompatible approval-set pair under
every manifest concurrently valid in that authorization window. It is not the
bond value of an entire capable quorum unless that exact quorum is what the
deterministic verdict can slash.

The closed top-level fault-class enum is exactly FALSE_SOURCE or EQUIVOCATION.
BACKING_SELECTION_EQUIVOCATION is a typed EQUIVOCATION evidence subtype, not a third fault
class. For FALSE_SOURCE, the culprit set is the unique union of the WARDEN and
ACCOUNT approvers bound to D. For EQUIVOCATION, including its
BACKING_SELECTION_EQUIVOCATION subtype, it is the union of the per-role intersections
across D1 and D2, which may contain only two times k minus n identities for one
same-roster role. Capacity uses the
minimum B_min over every applicable economically relevant fault class. The same
identity or bond is counted once even if it appears in multiple roles, chains,
directions, or generations.

Name this condition StaticGlobalAllocationPremiseV1. It is a v1
deployment/governance premise checked by the product auditor and model, not an
on-chain activation oracle and not an atomic cross-chain runtime counter. If
the premise is false, the product configuration is nonconforming even though
each chain can still locally accept its own manifest. Passing this contract is
conditional on the premise for every modeled manifest set.

Reallocation takes effect only after every old-manifest ReserveIntent and
FinalizedUncleared position is cleared, every old bond remains locked through
its complete window, and both chain-local manifest updates carry typed causal
references to the audited governance decision.

### 10.4 FinalizedUncleared and propagation exposure

For each coalition q:

    L_q =
        risk value of all live CapacityReserved release-risk positions
        + risk value of all FinalizedUncleared positions
        + conservative maximum additional value exercisable during
          detection and cross-chain pause propagation.

Finalization does not reduce L_q. A position clears only after its committed
detection, proof, challenge, and propagation window has ended and its incident
status is resolved.

An Ethereum bond freeze cannot atomically pause MobileCoin, and a MobileCoin
event cannot atomically mutate Ethereum. Therefore the exposure bound MUST be
safe even when the remote chain continues accepting locally valid reservations
for the complete configured propagation delay. Remote pause completion is a
liveness/fairness/operational assumption unless a verified light client makes
it a chain-local safety check.

## 11. Evidence, adjudication, loss, and penalties

### 11.1 Capability matrix

The fault-class column domain is the closed enum FALSE_SOURCE | EQUIVOCATION.
EQUIVOCATION evidence_kind is the closed subtype enum
DIGEST_CONFLICT | BACKING_SELECTION_EQUIVOCATION; both subtypes use the same deterministic
intersection culprit formula and B_min domain.

| Direction/version | FALSE_SOURCE evidence | EQUIVOCATION evidence | Automatic operator verdict |
|---|---|---|---|
| ETH_TO_MOB V1 | Ethereum escrow DepositRecord state plus signed approvals | two incompatible signed digests | yes |
| ETH_TO_MOB V2 | Ethereum escrow DepositRecord state plus signed approvals | two incompatible signed digests | yes |
| MOB_TO_ETH V1 | contractual/manual only for source falsity | two incompatible signed digests | no for false source; yes for syntactic equivocation |
| MOB_TO_ETH V2 inclusion mismatch | validator-authenticated MobileCoin receipt-map inclusion proof plus local Ethereum payout | two incompatible signed digests | yes |
| MOB_TO_ETH V2 nonexistent return | validator-authenticated sparse/authenticated-map nonmembership proof keyed by stable source nullifier plus local Ethereum payout | two incompatible signed digests | yes |

A plain Merkle inclusion tree cannot prove nonexistence. MobileCoin v2 MUST
commit an authenticated dictionary keyed by stable source nullifier. Inclusion
supports wrong-field mismatches. Authenticated nonmembership supports a
fabricated/nonexistent return. MobileCoin v1 explicitly lacks automatic
false-source adjudication.

### 11.2 Admission and deterministic verdict

Claims first pass parse/admission. Malformed, unauthenticated, unsupported,
unstable-checkpoint, wrong-domain, or replayed incident claims are recorded as
RejectMalformed or RejectUnsupported with no operator effect.

Every admitted supported proof yields exactly one deterministic verdict:

- OperatorFault(exact_culprits), or
- ChallengerFault(authenticated_challenger).

FALSE_SOURCE culprits are the unique union of valid, individually
authenticated, bond-bound WARDEN and ACCOUNT approvers whose respective
M_WARDEN or M_ACCOUNT receipts bind D.

EQUIVOCATION culprits, for both DIGEST_CONFLICT and BACKING_SELECTION_EQUIVOCATION
evidence subtypes, are exactly:

    (WARDEN_approvers(D1) intersect WARDEN_approvers(D2))
    union
    (ACCOUNT_approvers(D1) intersect ACCOUNT_approvers(D2)).

Role overlap never duplicates the identity or bond. No nonsigner, nonmember,
or signer of only one incompatible artifact is a culprit.

### 11.3 Fault proof and realized-loss proof are different

Objective evidence that approvers signed a false Ethereum source assertion can
justify an operator verdict and FaultBondFreeze from the signed receipts plus
Ethereum DepositRecord state. It does not by itself prove that the MobileCoin
payout landed or establish the realized loss amount.

LossAssessment requires separate objective payout evidence and deterministic
amount arithmetic:

- ETH_TO_MOB uses an objective MobileCoin release receipt/checkpoint when
  available, otherwise the amount remains unresolved or follows an explicitly
  contractual path;
- MOB_TO_ETH V2 combines the MobileCoin source proof with the local finalized
  Ethereum payout record;
- MOB_TO_ETH V1 uses the declared contractual adjudicator; and
- equivocation may have zero realized loss.

No restitution amount may be invented from the asserted amount alone. The
fault verdict, bond freeze, loss assessment, and collateral distribution are
separate immutable records with typed references.

### 11.4 Chain-local consequence protocol

On an OperatorFault verdict, the bond chain atomically emits
FaultBondFreeze containing proof/verdict ID, exact culprits, unique historical
bond positions and face amounts, affected bond/policy epoch, and incident ID.
Each implicated bond is frozen once, cannot exit, and contributes no new
capacity. This freeze is immediate relative to the verdict on that chain.

Pause, expulsion/rotation, and reopen are separate chain-local events:

1. PAUSE_POLICY_EPOCH(chain) references the finalized FAULT_BOND_FREEZE or an
   admissible typed cross-chain proof/attestation of it.
2. REGISTER_FRESH_GATE_EPOCH(chain) records the new role/gate manifests and
   excludes every exact culprit in the affected roles.
3. REOPEN_POLICY_EPOCH(chain) requires local pause, fresh required manifests,
   funded and threshold-capable replacement rosters, and no reuse of
   expelled/slashed identities.

No event on one chain directly changes remote chain state. While a chain is
paused it rejects new liability admission, ReserveIntent, and FinalCommit, but
may observe source events, accept fraud claims, finalize cancellation proofs,
and complete containment/rotation actions. Historical artifacts, bonds, and
already-finalized records remain verifiable.

Local temporal ordering is exact. A FinalCommit finalized before the local
PAUSE_POLICY_EPOCH remains effective and charged in L_q. Any FinalCommit
ordered after the local PAUSE_POLICY_EPOCH under the retired epoch is invalid,
even if its
ReserveIntent and signatures predate the pause. Pause does not delete or
release that pending reservation. It remains charged until the old epoch is
permanently invalidated and an ObjectiveCancelProof proves the exact action did
not land, or until a valid pre-pause final outcome is observed. Resume always
uses fresh required manifests; it never revives an old-epoch pending action.

### 11.5 Delayed collateral distribution

FaultBondFreeze is immediate; collateral distribution is deliberately later.
RiskResolved(incident) requires:

- every implicated live reservation is either objectively canceled or
  destination-finalized;
- every implicated FinalizedUncleared position has completed its committed
  detection/proof/challenge/propagation window;
- every implicated destination outcome has loss_fixed equal to an admitted
  objective LossAssessment, a completed contractual adjudication, or an
  admitted proof of zero realized loss; and
- no further payout can arise from an implicated executable artifact.

An unresolved contractual loss keeps collateral frozen and disables both risk
Cleared and CollateralDistribution. Once RiskResolved holds, a separate
ClearRisk event moves every implicated risk to Cleared and removes it from
L_q. Distribution is enabled only after those risks are Cleared and terminal,
never while any implicated position remains in L_q.

Only then does CollateralDistribution slash 100 percent of each unique frozen
culprit bond exactly once. Let H be total frozen common-risk value, R_loss the
fixed admissibly assessed unreimbursed loss, P_claim the authenticated proof-
cost claim, and proof_cost_cap, bounty_rate_num, bounty_rate_den, and bounty_cap
immutable manifest constants:

    R = min(R_loss, H)
    P = min(P_claim, proof_cost_cap, H - R)
    Y = min(
        bounty_cap,
        floor(bounty_rate_num * (H - R - P) / bounty_rate_den),
        H - R - P
    )
    S = H - R - P - Y
    H = R + P + Y + S

Payment order is restitution R, proof cost P, capped bounty Y, then insurance
surplus S. Restitution entries are canonically ordered by asset, liability, and
recipient. If collateral is insufficient, restitution is pro rata and integer
remainders follow that same order. Native debits exactly equal every frozen
native bond amount; rounding creates no value. All values, recipients, bond
positions, constants, and rounding are in the immutable record. No
distribution occurs before RiskResolved.

For ChallengerFault, 100 percent of the challenge bond is transferred to the
bridge insurance reserve exactly once. It freezes or slashes no operator bond,
causes no bridge pause or expulsion, and creates no operator rotation.

## 12. Per-chain event protocol and composition semantics

Ethereum and MobileCoin each maintain an append-only typed CapacityEvent
sequence. The envelope has exactly 31 top-level fields in this order:

    CapacityEvent = [
        schema_version,
        bridge_id,
        event_id,
        proposal_id,
        acceptance_id,
        event_chain_id,
        chain_sequence_no,
        prev_chain_event_hash,
        causal_event_refs,
        event_hash,
        kind,
        producer,
        producer_action,
        chain_logical_time,
        direction,
        protocol_version,
        policy_id,
        policy_epoch,
        generation_id,
        release_id,
        liability_id,
        reservation_id,
        source_nullifier,
        canonical_digest,
        risk_window_id,
        manifest_bundle_id,
        core_state_hash_before,
        core_state_hash_after,
        capacity_state_hash_before,
        capacity_state_hash_after,
        payload
    ]

Inapplicable fields contain typed ABSENT sentinels; they are never omitted or
inferred from mutable state. Payload is exactly one known closed-union variant.
For release-path events, canonical_digest is the direction-specific base D;
role artifacts in payload carry their exact M_WARDEN, M_ACCOUNT, or M_GATE
message/manifest binding and never replace base D with a role wrapper.

The event/receipt commitment graph is acyclic. These derivations and their
order are normative:

    event_id = H(
        "BRIDGE_CAPACITY_EVENT_V2",
        bridge_id,
        event_chain_id,
        producer_action,
        canonical primary object ID,
        transition ordinal
    )

    CanonicalProposalBody = CanonicalEncode(
        every eventual envelope field except proposal_id, acceptance_id,
        event_hash, core_state_hash_before, core_state_hash_after,
        capacity_state_hash_before, capacity_state_hash_after;
        with event_id already derived and every payload-derived field verified
    )

    proposal_id = H(
        "BRIDGE_CAPACITY_PROPOSAL_V2",
        CanonicalProposalBody
    )

    core_state_hash_before = H(
        "BRIDGE_CORE_SEMANTIC_PROJECTION_V2",
        canonical core semantic maps before the provisional transition
    )

    core_state_hash_after = H(
        "BRIDGE_CORE_SEMANTIC_PROJECTION_V2",
        canonical core semantic maps after the provisional transition
    )

    capacity_state_hash_before = H(
        "BRIDGE_CAPACITY_SEMANTIC_PROJECTION_V2",
        canonical capacity semantic maps before the provisional transition
    )

    capacity_state_hash_after = H(
        "BRIDGE_CAPACITY_SEMANTIC_PROJECTION_V2",
        canonical capacity semantic maps after the provisional transition
    )

    acceptance_id = H(
        "BRIDGE_CAPACITY_ACCEPTANCE_V2",
        proposal_id,
        event_id,
        event_chain_id,
        chain_sequence_no,
        prev_chain_event_hash,
        H(causal_event_refs),
        core_state_hash_before,
        core_state_hash_after,
        capacity_state_hash_before,
        capacity_state_hash_after
    )

    EventEnvelope = CanonicalEncode(
        schema_version,
        bridge_id,
        event_id,
        proposal_id,
        acceptance_id,
        event_chain_id,
        chain_sequence_no,
        prev_chain_event_hash,
        causal_event_refs,
        event_hash = ZERO_EVENT_HASH,
        kind,
        producer,
        producer_action,
        chain_logical_time,
        direction,
        protocol_version,
        policy_id,
        policy_epoch,
        generation_id,
        release_id,
        liability_id,
        reservation_id,
        source_nullifier,
        canonical_digest,
        risk_window_id,
        manifest_bundle_id,
        core_state_hash_before,
        core_state_hash_after,
        capacity_state_hash_before,
        capacity_state_hash_after,
        payload
    )

    event_hash = H(
        "BRIDGE_CAPACITY_EVENT_BYTES_V2",
        event_chain_id,
        EventEnvelope
    )

    AcceptanceReceipt = [
        acceptance_id,
        event_chain_id,
        event_hash,
        chain_sequence_no,
        prev_chain_event_hash,
        causal_event_refs_hash = H(causal_event_refs),
        core_state_hash_before,
        capacity_state_hash_before,
        core_state_hash_after,
        capacity_state_hash_after
    ]

    AcceptanceReceiptBytes = CanonicalEncode(
        AcceptanceReceipt including event_hash
    )

The semantic projections exclude append-only event logs,
proposal/acceptance-receipt stores, consensus block/header roots, and the
currently staged event and receipt. They include every safety-relevant core or
capacity semantic map. After event_hash is computed, consensus stores the
event with its populated event_hash and appends the corresponding acceptance
receipt. acceptance_id excludes event_hash and all receipt bytes. The receipt
is the only subsequently constructed object that contains event_hash, and
nothing hashed by the event contains that receipt.

ZERO_EVENT_HASH is the unique fixed-width all-zero value of the EventHash type
and is used only in the event_hash slot while computing EventEnvelope. No
other field is zeroed, omitted, or replaced by an ABSENT sentinel for that
hash. The populated event bytes, which contain the computed event_hash, are
stored but never recursively rehashed as EventEnvelope.
EventEnvelope reconstitutes all 31 scalar/aggregate fields in the exact
CapacityEvent order above; CanonicalProposalBody is not encoded as a nested
blob inside it.

For a given chain, chain_sequence_no is contiguous, event_id is
content-immutable, and prev_chain_event_hash commits to the prior event on
that chain. There is
no GlobalCapacityEvent, global sequence number, global previous hash, or
total-order service.

Each chain has a distinct typed genesis sentinel. An identical rebroadcast
returns the historical local result without appending. Reusing event_id,
proposal_id, or acceptance_id with different canonical bytes rejects.

A CausalEventRef has exactly:

    event_chain_id,
    event_hash,
    chain_sequence_no,
    evidence_kind,
    evidence_body,
    verifier_manifest_id.

evidence_kind is one of SAME_CHAIN, CHECKPOINT, FINALITY_PROOF, or
ROLE_ATTESTATION. Each kind has a closed typed evidence_body and exact verifier.
The referenced event must exist in the finalized origin prefix, its type must
be permitted for the consuming event, and all identifiers and hashes must
match. An opaque Boolean attestation is forbidden. A local event cannot cite a
future or nonfinalized origin event.

Product semantics is the partial order generated by:

- each chain's local sequence edges; and
- valid typed cross-chain causal-reference edges.

A composition cut is a pair of Ethereum and MobileCoin prefix lengths closed
under every causal edge. CORE, STAGED, and COMPOSITION parity is checked at
every reachable causally closed cut, not at arbitrary non-prefix subsets and
not only at the final state.

Partial-order reduction may commute two adjacent events only when:

- neither causally reaches the other;
- their complete read/write/resource footprints are disjoint;
- they do not share a nullifier, liability, backing position, reservation,
  allocation, bond, incident, epoch, source position, or manifest; and
- the resulting projected state and enabled action set are identical in both
  orders.

Deletion, duplication, mutation, same-chain reordering, forged references,
missing required references, and commuting dependent events are explicit
defects.

## 13. Generation and activation constraints

A custody generation follows:

    Defined -> AuthorityReady -> Capitalized -> Active
            -> DepositsClosed -> Drained -> Deactivated.

External reserve allocation or a fully authorized predecessor transfer
capitalizes a generation. A customer source deposit does not capitalize the
opposite-chain destination reserve. No output may be funded before its exact
ownership authority is ready. No generation becomes Active before its gate,
multisig, WARDEN, ACCOUNT, bond, allocation, and valuation manifests are
ready, and no MobileCoin generation activates without one pinned, supported,
fail-closed ReserveAccountingProof backend/verifier manifest and a verified
eligible-output PedPoP root-share/one-time-offset provisioning and refresh
pipeline. A PrivateThresholdZ generation additionally requires its verified
mask-share/MPC provisioning, refresh, and range-proof witness pipeline;
CoreCustodyKnownZ does not.

Unsafe, stranded, frozen, spent, reserved-for-another-liability, or
FinalizedUncleared value is ineligible to back a new liability. Overlapping
generations that share a failure domain, coalition, bond, software, storage,
or operator are summed for C_loss and L_q until the predecessor is fully
drained and deactivated.

### 13.1 Committed event-kind manifest

The interface has exactly 28 committed event kinds. Event IDs below are
machine-readable contract keys and MUST match both model manifests.

| Event ID | Event kind | Required state effect |
|---|---|---|
| E01 | OWNER_AUTHORITY_READY | Record exact owner key, roster, threshold, ceremony, and generation binding. |
| E02 | GATE_ROLE_AUTHORITY_READY | Record exact gate, Ethereum, WARDEN, ACCOUNT, and policy manifests. |
| E03 | LOCK_BOND_MANIFEST | Lock unique identity bond positions under the historical manifest and maximum possible window. |
| E04 | CAPITALIZE_EXTERNAL_EUSD | Create eligible eUSD CapacityLots and exact policy/bridge-lot-tagged custody outputs plus verified owner-roster PedPoP root-share/offset records and any mask-share/MPC records required by the selected custody_profile, from a logged external allocation only after owner authority exists. |
| E05 | CAPITALIZE_PREDECESSOR_TRANSFER | Consume cited predecessor lots and create exact policy/bridge-lot-tagged successor lots plus verified successor root-share/offset and profile-required mask witness records without duplication through a fully authorized settlement. |
| E06 | RECORD_ESCROW_SOURCE_INFLOW | Atomically accompany a local bridge deposit or recipient/policy-derived typed MobileCoin BridgeReturn inclusion, create one Encumbered source position with exact immutable lot provenance and the MobileCoin root-share/offset and optional private-Z witness records required by its custody_profile, assert no finality, and roll back with that inclusion on reorg; unsolicited/self-labelled transfers remain ineligible. |
| E07 | OPEN_LIABILITY | Verify the one exact bond-bound WARDEN and ACCOUNT quorum over M_WARDEN and M_ACCOUNT binding the already-derived final base D; store the immutable SourceAssertion/obligation, exact candidate intent/resource commitments, and receipt references; record ClaimedLiability(Open) and acquire its unique stable-nullifier claim lock without reserving capacity or consulting objective truth. |
| E08 | RESERVE_RELEASE_INTENT | On the destination chain, verify receipts, CapacityLots, MobileCoin ThresholdOwnershipEqualityProofs plus the selected ReserveAccountingProof backend where applicable, and local policy/capacity; atomically reserve lots, key-image/tags, and source nullifier, move Open to CapacityReserved, and create CapacityReserved risk. |
| E09 | FINALIZE_RELEASE | Validate a prior-block exact reservation and MLSAG/FROST or Ethereum artifacts, then atomically settle liability, spend lots, consume nullifier/tags, create only exact same-lot policy-tagged change with verified successor root-share/offset compatibility and profile-required mask witness records, and create FinalizedUncleared risk. |
| E10 | CANCEL_PENDING_RELEASE | With exact objective nonexecutability proof, return liability/lot/nullifier/lease to Open/Available/Free/Free, move risk CapacityReserved to Cancelled, and preserve claim lock, ring binding, and history. |
| E11 | PROMOTE_SETTLED_SOURCE_INFLOW | With finalized reference to E06 and the paired remote FinalCommit evidence or declared V1 contractual result, move one matching Encumbered source position to Available exactly once. |
| E12 | CLEAR_FINALIZED_RISK | After exact committed clearance and loss_fixed result, move FinalizedUncleared to Cleared and only then remove it from L_q. |
| E13 | ACTIVATE_GENERATION | Activate only after owner, capital, role/gate, bond, valuation, allocation, spent-tag backfill, eligible-input PedPoP root-share/offset pipeline plus any PrivateThresholdZ mask/MPC pipeline required by the selected custody_profile, selected ReserveAccountingProof backend/verifier, and cap prerequisites. |
| E14 | CLOSE_GENERATION_DEPOSITS | Stop new liability and reservation admission for the generation. |
| E15 | DRAIN_GENERATION | Require zero live inventory bindings, open/reserved liabilities, reservations, and uncleared risk. |
| E16 | DEACTIVATE_GENERATION | Deactivate a drained generation without erasing history. |
| E17 | DECLARE_UNSAFE | Mark exact lots ineligible while retaining bindings and gross exposure. |
| E18 | DECLARE_STRANDED | Mark exact lots unavailable/ineligible while retaining loss and obligation history. |
| E19 | REQUEST_BOND_EXIT | Start exit without reducing historical or reserved coverage. |
| E20 | COMPLETE_BOND_EXIT | Release a bond only after all exact bound windows and liabilities discharge. |
| E21 | PROPOSE_CAPACITY_ALLOCATION | Record a future immutable per-chain/direction/generation allocation and valuation manifest without changing active capacity. |
| E22 | ACTIVATE_CAPACITY_ALLOCATION | Each chain activates locally after predecessor-window and segment checks; global validity is authenticated proof or explicit StaticGlobalAllocationPremiseV1, never an atomic oracle. |
| E23 | PAUSE_POLICY_EPOCH | Locally close new liability/reservation and later old-epoch finalization after an authenticated causal proof or exact role attestation; retain pending risk. |
| E24 | FAULT_BOND_FREEZE | On the Ethereum bond registry, freeze exact implicated unique bonds and create held fault collateral without remote pause or distribution. |
| E25 | DISTRIBUTE_FAULT_COLLATERAL | Only after all implicated risk is Cleared and loss_fixed, debit each held bond once and distribute restitution, capped proof cost, rate-and-cap bounty, and insurance surplus in exact order. |
| E26 | APPLY_CHALLENGER_FAULT | Apply only the exact challenge-bond transfer with no operator or bridge-control consequence. |
| E27 | REGISTER_FRESH_GATE_EPOCH | Record a distinct fresh gate/role manifest produced by the authorized rotation path and exclude expelled identities. |
| E28 | REOPEN_POLICY_EPOCH | Reopen one local chain only after fresh registration and all local activation/allocation/cap prerequisites pass. |

## 14. Required property manifest

The Property ID and Property name columns are machine-readable primary keys.
The runner MUST parse these tables rather than maintain a hand-copied count.
Safety means an invariant; Hyper means paired-state noninterference; Reach
means a required reachability witness; Refinement means equality of a defined
projection; and AssumptionCheck means the model must expose and validate a
deployment assumption without pretending a chain enforces it.

### 14.1 CORE properties

| Property ID | Property name | Kind | Required predicate or witness |
|---|---|---|---|
| P01 | TypeOK | Safety | Every variable and record remains in its declared finite type. |
| P02 | ObjectiveHistoryIndependent | Safety | ObjectiveSourceHistory changes only through environment actions and is never assigned by protocol actions. |
| P03 | TruthNoninterference | Hyper | Equal observable states with different objective histories have equal release-path enabledness and projected successors. |
| P04 | FalseSourceReleaseReachable | Reach | A fully authorized destination release whose assertion conflicts with objective history is reachable without a defect selector. |
| P05 | ClaimedLiabilitySeparatedFromSourceInventory | Safety | A SourceAssertion or ClaimedLiability alone never creates or increases source inventory. |
| P06 | SourceInventoryAuthenticity | Safety | Every Encumbered source position is atomically created by one immutable local RECORD_ESCROW_SOURCE_INFLOW with equal normalized fields and rolls back with it. |
| P07 | SourceInventoryConservation | Safety | Encumbered source value becomes Available only once with finalized reference to its local inflow and authenticated paired remote FinalCommit, with exact per-asset principal and fees. |
| P08 | StableSourceNullifier | Safety | All attempts for one canonical source event derive one version- and epoch-independent nullifier. |
| P09 | NullifierBijection | Safety | Every final settlement consumes exactly one reserved source nullifier and every consumed nullifier identifies exactly one final settlement. |
| P10 | CanonicalDigestInjective | Safety | Distinct canonical settlement records have distinct modeled D atoms. |
| P11 | AllocationManifestBound | Safety | Every ReserveIntent and artifact cites the one active exact AllocationManifest bound into D. |
| P12 | ReserveIntentPrecedesExecutableSpend | Safety | No destination FinalCommit is enabled unless its exact destination-consensus reservation is already live. |
| P13 | ReserveIntentConsensusSound | Safety | A live ReserveIntent was created only by the destination's atomic local validation and reservation transition. |
| P14 | CapacityDecisionBound | Safety | CapacityDecision, deterministic reservation ID, D, liability, backing, nullifier, allocation, and expiry identify one another exactly. |
| P15 | NoPolicyBypass | Safety | Every final release carries every direction-applicable concrete artifact; no legacy or alternate spend path bypasses policy. |
| P16 | MlsagArtifactSound | Safety | Every MobileCoin input has a valid policy-bound MLSAG artifact over the exact recomputed D_MOB bytes and the actual ordered full wire inputs/rings. |
| P17 | FrostArtifactSound | Safety | Every ETH_TO_MOB finalization has a valid current-gate FROST artifact over M_GATE, which binds the exact returned D_MOB bytes and exact gate manifest/key. |
| P18 | EthereumMultisigArtifactSound | Safety | Every MOB_TO_ETH finalization has a valid current-epoch Ethereum multisig artifact over exact D_ETH bytes and exact escrow call. |
| P19 | WardenCertificateSound | Safety | Every final release and ReserveIntent has the required distinct current WARDEN receipts over M_WARDEN binding base D. |
| P20 | AccountabilityCertificateSound | Safety | Every final release and ReserveIntent has the required distinct current ACCOUNT receipts over M_ACCOUNT binding base D, each bound to a historical bond. |
| P21 | SignerSlotsDistinct | Safety | Occupied slots are authenticated, unpadded, in range, identity-distinct and public-key-distinct within each role artifact, and resolve one immutable (identity, role, key) binding. |
| P22 | RoleThresholdsIndependent | Safety | Each role threshold and RoleArtifactDigest is evaluated only against that role's exact manifest and immutable (identity, role, key) slots; permitted cross-role identity/key overlap still requires a fresh role-domain signature, and no WARDEN, ACCOUNT, gate, owner, or Ethereum artifact can satisfy another role. |
| P23 | ReleaseDigestBound | Safety | WARDEN, ACCOUNT, and FROST artifacts bind the byte-identical direction-specific base D under exact distinct role/scheme domains; MLSAG or Ethereum execution natively binds that same D; actual transaction/call fields, reservation records, and release records agree. |
| P24 | ReleaseEpochSound | Safety | Every artifact and manifest used for new authorization is current for its exact role and chain. |
| P25 | HistoricalBondBinding | Safety | Attribution and capacity use the immutable bond positions active when D was approved, locked through the full risk window. |
| P26 | LiabilityLifecycleSound | Safety | Every liability follows Open to CapacityReserved to Settled, or exact safe cancel to the same Open/claim-lock state; there is no Backed or AuthorizedPending state. |
| P27 | DestinationPositionPartition | Safety | Every backing follows Available to ReservedIntent to Spent, or exact safe cancel to Available; Spent and risk histories are immutable. |
| P28 | ClaimLockAndLotSelectionInjective | Safety | OPEN_LIABILITY gives one live liability the exclusive stable-nullifier claim lock, and one CapacityLot slice is selected by at most one ReserveIntent. |
| P29 | ReservationExclusive | Safety | One live reservation owns one CapacityReserved liability, ReservedIntent backing, source nullifier, deterministic ID, and capacity decision bijectively. |
| P30 | AtomicFinalCommit | Safety | Reservation consumption, nullifier consumption, backing spend/change, payout, and FinalizedUncleared creation occur in one destination transition. |
| P31 | FinalizedUnclearedRetained | Safety | A separate release-risk position moves CapacityReserved to FinalizedUncleared to Cleared/ResolvedAudit and remains in local allocation and L_q until Cleared. |
| P32 | SafeCancellation | Safety | Cancellation requires exact finalized destination nonexecution, including MobileCoin tombstone AND exact noninclusion, and returns liability/lot/nullifier/lease/risk to Open/Available/Free/Free/Cancelled without erasing history, claim lock, or ring binding. |
| P33 | ReallocationQuiescence | Safety | An old allocation cannot be replaced while its reservations, uncleared finals, or bond window remain live. |
| P34 | FullCycleConservation | Safety | The complete USDC/eUSD round trip conserves principal, fees, source positions, destination backing, liabilities, reservations, and nullifiers per asset. |
| P35 | PerAssetReserveExposureBound | Safety | Current stock and live-risk vectors obey per-asset limits; immutable Spent/released history conserves value but does not create a lifetime-volume cap after risk Cleared. |
| P36 | LocalAllocationBound | Safety | Each destination rejects any reservation exceeding its own active chain/direction/generation/asset allocation. |
| P37 | CorrelatedBondCapacityBound | AssumptionCheck | The audited sum of all simultaneously exercisable allocations plus propagation headroom is at most the minimum applicable B_min[f, authorization_window] divided by two for every coalition and fault class. |
| P38 | ValuationManifestSound | Safety | Every common-risk-unit comparison uses the exact active conservative valuation/haircut manifest and required rounding. |
| P39 | UniqueBondAccounting | Safety | One identity's historical bond is counted, frozen, slashed, and distributed at most once despite role or generation overlap. |
| P40 | UniqueValueAccounting | Safety | Every physical/risk position has one stable ID and is counted at most once in each declared aggregate/projection; legitimate simultaneous lifecycle, allocation, and L_q projections do not duplicate it within an aggregate. |
| P41 | UnmatchedReleaseHasAccountability | Safety | Every final release not matched by objective source history exposes the exact threshold-valid WARDEN and ACCOUNT approval identities and bonds. |
| P42 | UnmatchedReleaseHasAutomaticProof | Safety | Every unmatched release in an AutoVerifiable matrix cell has one supported objective proof; non-AutoVerifiable cells make no such claim. |
| P43 | ClaimEvidenceImmutable | Safety | Admitted claims, evidence bytes, checkpoints, incident IDs, and content hashes never change after admission. |
| P44 | RejectionSound | Safety | Malformed, unauthenticated, unsupported, unstable, wrong-domain, and replayed claims are recorded rejected with no verdict or operator effect. |
| P45 | VerdictDeterministic | Safety | Equal admitted evidence under equal manifests produces exactly one equal verdict and culprit set. |
| P46 | VerdictSound | Safety | OperatorFault requires a supported objective offense; ChallengerFault requires an admitted proof that deterministically fails against its authenticated challenger. |
| P47 | CulpritSetExact | Safety | FALSE_SOURCE uses unique WARDEN union ACCOUNT approvers; EQUIVOCATION uses the union of the two per-role intersections, with no extra identity. |
| P48 | SlashRequiresVerdict | Safety | No operator bond is frozen or slashed without an admitted OperatorFault verdict naming its owner as a culprit. |
| P49 | SlashExactOnce | Safety | Each culprit bond and challenge bond is slashed at most once for the content-addressed incident/distribution identity. |
| P50 | PenaltyDistributionExact | Safety | After eligibility, 100 percent of unique culprit bonds is partitioned exactly into restitution, capped proof cost, rate-and-cap bounty, then insurance surplus with native/risk conservation and canonical rounding. |
| P51 | NoRejectedClaimEffect | Safety | A rejected claim cannot freeze a bond, pause a chain, expel a role, rotate an epoch, assess loss, or distribute collateral. |
| P52 | NoUnsupportedAutomaticSlash | Safety | A MobileCoin-v1 false-source claim cannot create an automatic OperatorFault or operator slash. |
| P53 | ChallengerFaultDoesNotPause | Safety | ChallengerFault transfers only the challenge bond to insurance and has no operator or bridge-control consequence. |
| P54 | FaultBondFreezeImmediate | Safety | An OperatorFault verdict's same-chain transition freezes every and only implicated unique bond before any later consequence or distribution. |
| P55 | PauseCausalitySound | Safety | Every chain-local pause cites a finalized permitted FaultBondFreeze proof/attestation and never arises by remote state mutation. |
| P56 | PausedEpochAdmissionClosed | Safety | A locally paused chain admits no new liability or ReserveIntent and rejects later old-epoch FinalCommit without deleting pending records; pre-pause finals remain effective. |
| P57 | ExpelledSignerNotReused | Safety | Expelled or slashed identities cannot satisfy a new role artifact, manifest, reservation, or finalization. |
| P58 | FreshGateBeforeResumption | Safety | Resume requires fresh required gate/role manifests, eligible funded rosters, and completed local rotation after the cited incident. |
| P59 | SourceNullifierLifecycleSound | Safety | Current nullifier state follows Free to Reserved to Consumed or safe-cancel back to Free while append-only history remains complete. |
| P60 | NoConcurrentSourceReservation | Safety | A stable source nullifier has at most one live reservation on all retry and generation paths. |
| P61 | CollateralDistributionAfterRiskResolution | Safety | No operator collateral moves before all implicated pending, uncleared, challenge, propagation, and executability risks resolve. |
| P62 | LossAssessmentSound | Safety | Every realized-loss amount equals deterministic arithmetic over admitted objective payout evidence; an offense may have zero or unresolved loss. |
| P63 | FaultAndLossEvidenceSeparated | Safety | Fault verdict/freeze neither fabricates payout evidence nor authorizes restitution; loss and distribution cite their own admissible records. |
| P77 | CapacityLotConservation | Safety | Per lot, initial eligible plus promoted inflow minus finalized outflow and resolved incident loss equals free plus unique live reservation charges in native and recomputed risk units; free is nonnegative and uncleared risk is not free. |
| P78 | LiabilityReservationInjective | Safety | Each live liability has at most one live reservation, and each reservation charges exactly one liability and each CapacityLot slice once. |
| P79 | LiveInputLeaseInjective | Safety | Distinct live reservations have disjoint network-global stable lease tags, and live tags are disjoint from all spent-key-image-derived tags across bridges, epochs, generations, retries, and versions. |
| P80 | ThresholdOwnershipEqualityProofSound | Safety | Every accepted MobileCoin tag/ring/pseudo-output has a valid monotone PreIntentKeyImageContext-bound key-image/DLEQ aggregation committed into IntentBindingCore and ReserveInputStatementCore, followed only after D by a separately nonced two-round/two-row ownership/equality proof under the identical historical-owner profile/package/ring/signer/input set, with valid threshold row-0 response shares and valid profile-typed row-1 authority evidence or response shares, structural reserve-challenge DST, and no public real-index field or spend-verifier replay. |
| P81 | FinalizationMatchesReservation | Safety | Final MobileCoin execution matches reservation ID, unsigned transaction commitment, lots/amount, tombstone, and exact canonical key-image/tag vector and consumes each once. |
| P82 | RetryLeaseSound | Safety | A tag is re-leased only in a later block after consensus Cancelled and proves the identical permanent key-image/ring-set opening; only proof randomness refreshes. |
| P83 | NetworkGlobalLeaseTagStable | Safety | InputLeaseTag is exactly H("MC_INPUT_LEASE_TAG_V1", MobileCoin network genesis ID, canonical ordinary key image) with no bridge, epoch, generation, version, retry, salt, or ring field. |
| P84 | PermanentKeyImageRingBinding | Safety | The first accepted proof fixes one salted canonical ring-set commitment per key image and every retry opens the same binding. |
| P85 | HistoricalSpentTagBackfillComplete | Safety | Reservation activation requires an exact complete spent-tag index derived from every historical ledger key image; missing history fails closed. |
| P86 | PriorBlockReserveRequired | Safety | A MobileCoin FinalCommit can use only an exact reservation finalized in a strictly earlier block. |
| P87 | WholeBlockLeaseConflictFree | Safety | Whole-block validation rejects reserve/spend, reserve/cancel, cancel/retry, cancel/final, and double-reserve/final conflicts regardless transaction order. |
| P88 | DigestConstructionAcyclic | Safety | Candidate liability, actual zero-ID destination object, PreIntentKeyImageContext-bound key-image/DLEQ aggregation, and IntentBindingCore precede unsigned commitment, reservation ID, final wire execution, direction-specific D, ThresholdOwnershipEqualityProofDigest, ReserveAccountingProofDigest, and ReserveInputProofDigest; all descendant proof/hash/bundle fields are structurally absent from every ancestor closed schema, MobileCoin TxSummary is internally derived, WARDEN/ACCOUNT/proofs precede OPEN/RESERVE, and execution artifacts require the prior-block reservation. |
| P89 | AccountableQuorumIntersection | Safety | Every WARDEN pair and every ACCOUNT pair of concurrently valid quorums intersects, including across overlapping manifests; same-manifest thresholds satisfy two times k greater than n. |
| P90 | ThresholdOwnershipEqualityValueBinding | Safety | Every accepted ThresholdOwnershipEqualityProof establishes row-0 ordinary key-image ownership and row-1 knowledge of z = b_pseudo - b_input with C_pseudo - C_input = zG for the same hidden ring member and exact pseudo-output/base D without becoming spend-capable. |
| P91 | CapacityLotGrossDepletionConservation | Safety | The selected ReserveAccountingProof establishes that reserved lot charge equals release plus fees plus all non-lot outputs; exact change returns to the same lot and native/risk arithmetic conserves. |
| P92 | PolicyHomogeneousBridgeRing | Safety | spend_policy_id is immutable; standard rings are all UNTAGGED; bridge rings are all the one exact policy ID; no legacy, mixed, or operator-labeled member passes. |
| P93 | BridgeChangeLotPreservation | Safety | Every real bridge input and change output preserves the reservation's asset, generation, owner authority, CapacityLot identity, and spend_policy_id. |
| P94 | FaultClassBondCoverage | Safety | B_min[f, authorization_window] is the minimum unique collectible bond value of the exact deterministic culprit set over every executable same- or cross-manifest approval witness; capacity never substitutes a larger union/quorum sum or omits a concurrent witness pair. |
| P96 | DirectionSpecificExecutionDigestExact | Safety | MobileCoin D is exactly the first return value of the version-gated vNext compute_mlsag_signing_digest over local network genesis ID, block version, actual nonzero-reservation-ID wire TxPrefix, exact pseudo outputs, and exact legacy-or-vector range-proof fields, with TxSummary internally derived; Ethereum D is exactly the declared escrow EIP-712 digest; all exact chain/network domains are bound and no stored commitment substitutes for verifier-consumed bytes. |
| P97 | PolicyTagCreationAuthorized | Safety | Standard transactions create only ABSENT/UNTAGGED outputs, while every non-ABSENT spend_policy_id output is created only by authorized capitalization, authorized predecessor transfer, a recipient/policy-derived typed BridgeReturn beginning EncumberedSource, or exact same-lot bridge change, and has valid immutable bridge-lot provenance. |
| P98 | ReserveAccountingProofSound | Safety | Every accepted MobileCoin reservation has one valid selected-backend ReserveAccountingProof binding D, ownership statements, hidden selected inputs, CapacityLot provenance, assets/tokens, exact input/output relations, classifications, fee, exact independently verified public range-proof bytes/result, gross depletion, and same-lot change; absent, ownership-only, unknown, stale, or mismatched backends fail closed. |
| P99 | ReserveProofThresholdCustody | Safety | Under either manifest-bound custody_profile, no ownership coordinator, individual participant, or sub-threshold ownership set learns or reconstructs the root or one-time spend scalar; reserve/final ceremonies and all inputs use independent nonce state, and transcript/participant/input/profile bindings prevent share swaps and nonce extraction. CoreCustodyKnownZ permits complete z only at the exact registered signed row-1 authority. PrivateThresholdZ additionally prevents any individual or sub-threshold ownership set from reconstructing b_input, b_pseudo, or z and satisfies its selected private-Z range-proof witness boundary. Accounting-witness disclosure is checked separately against P98's selected profile. |
| P100 | EligibleInputWitnessSharesReady | Safety | Every eligible policy TxOut under either profile resolves to a verifiable historical-roster PedPoP/DKG root-spend record and pinned one-time-offset suite; before nonce reservation, derived delta validates P = B + delta*G and selected-set offset shares are usable without constructing x. PrivateThresholdZ additionally requires authenticated mask-share or approved MPC witness records for every authorized creation path, exact refresh/loss/recovery state, and a pinned nonlinear MaskedAmountV2 derivation that never applies the KDF independently to FROST shares. Missing private-mask provisioning does not invalidate CoreCustodyKnownZ. |

### 14.2 STAGED properties

| Property ID | Property name | Kind | Required predicate or witness |
|---|---|---|---|
| P64 | SourceAdapterSoundness | Safety | Every accepted adapter/inventory event has valid checkpoint/root authentication and exact proof-to-normalized-field binding. |
| P65 | PerChainEventExactlyOnce | Safety | Each required core mutation emits exactly one corresponding event in its own chain log; no duplicate event ID is applied. |
| P66 | PerChainEventHashChainSound | Safety | Event IDs are content-immutable and each chain's contiguous sequence and previous hash are exact. |
| P67 | CoreStagedProjectionParity | Refinement | Replaying either chain's event prefix yields the exact defined CORE projection for that same chain prefix. |
| P68 | UnknownEventFailsClosed | Safety | An unknown schema version or event type halts/rejects replay and never applies a guessed transition. |
| P69 | CapitalizationSound | Safety | Generation capital comes only from explicit external allocation or a fully authorized predecessor transfer after ownership authority is ready. |
| P70 | NoIneligibleBacking | Safety | Unsafe, Stranded, Spent, already ReservedIntent, Encumbered, or uncleared value never supplies Available CapacityLot backing for a new liability. |
| P71 | GenerationLifecycleSound | Safety | Generation transitions, admission opening/closure, drain, overlap, and deactivation obey the defined lifecycle and aggregate caps. |
| P72 | PropagationExposureBound | Safety | L_q includes conservative detection and cross-chain propagation outflow even while a remote chain has not paused. |
| P73 | ChainLocalConsequenceIsolation | Safety | A transition mutates only its local chain/bond state; remote pause, expulsion, rotation, and resume require separate causally referenced events. |

### 14.3 COMPOSITION properties

| Property ID | Property name | Kind | Required predicate or witness |
|---|---|---|---|
| P74 | CausalReferenceSound | Safety | Every cross-chain reference resolves to the exact finalized origin event/hash/checkpoint and is of a permitted causal type. |
| P75 | CrossChainPartialOrderSound | Safety | Composition honors all local and causal edges; reduction commutes only causally unrelated events with disjoint complete footprints. |
| P76 | ChainPrefixCausalCutParity | Refinement | CORE, STAGED, and COMPOSITION projections agree at every reachable causally closed Ethereum/MobileCoin prefix pair. |
| P95 | CapacityEventDigestAcyclic | Safety | Derived event ID, CanonicalProposalBody, proposal ID, both core and both capacity semantic projection hashes, acceptance ID including H(causal_event_refs), zero-self-field EventEnvelope, event hash, and receipt follow the exact dependency DAG; projections exclude log/receipt/block-root/staged-object effects, chain genesis sentinels differ, and rebroadcast/reuse semantics are exact. |

## 15. Required scenario manifest

Each row names one parameter-free runner instance. The runner MUST execute the
named instance exactly; it may not satisfy a row by choosing one of several
directions or versions at runtime. A witness includes the complete action
trace and final projection. A rejection scenario includes the precise
rejection code and proof that no forbidden state changed.

### 15.1 CORE scenarios

| Scenario ID | Runner instance | Required fixed trace and result |
|---|---|---|
| S01 | core_honest_eth_to_mob_v1 | Finalized Ethereum USDC DepositRecord, authentic source inflow, backed liability, MobileCoin ReserveIntent, complete MLSAG/FROST/WARDEN/ACCOUNT artifacts, final eUSD release, uncleared window, and settlement all succeed under V1. |
| S02 | core_honest_eth_to_mob_v2 | The same fixed ETH_TO_MOB flow executes under V2 with the V2 manifests and exact destination transaction. |
| S03 | core_honest_mob_to_eth_v1 | Finalized MobileCoin eUSD return under the V1 adapter policy, backed liability, Ethereum ReserveIntent, ETH/WARDEN/ACCOUNT artifacts, final USDC payout, uncleared window, and settlement all succeed. |
| S04 | core_honest_mob_to_eth_v2 | A MobileCoin v2 authenticated-map inclusion proof for the eUSD return leads through Ethereum reservation and final USDC payout. |
| S05 | core_full_usdc_eusd_round_trip_v2 | Execute all seven V2 inventory-cycle steps in section 9, including atomic local inflow records and later finalized local-plus-remote promotion evidence, using the exact USDC released from the first leg and returned eUSD position; finish with conservation and no preseeded source substitute. |
| S06 | core_false_source_eth_to_mob_v1 | A threshold-valid false Ethereum DepositRecord assertion releases eUSD, remains within capacity, exposes exact approvers, and admits automatic false-source proof. |
| S07 | core_false_source_eth_to_mob_v2 | The corresponding V2 false Ethereum source assertion is accepted on the release path and automatically adjudicable afterward. |
| S08 | core_false_source_mob_to_eth_v1 | A threshold-valid nonexistent MobileCoin-v1 return releases USDC within the V1 reverse cap, remains attributable, and is rejected by the automatic false-source adjudicator as Unsupported. |
| S09 | core_false_source_mob_to_eth_v2_inclusion | A MobileCoin-v2 authenticated inclusion proves that the signed return amount or recipient mismatches the committed receipt, yielding exact OperatorFault culprits. |
| S10 | core_false_source_mob_to_eth_v2_nonmembership | An authenticated dictionary nonmembership proof for the stable source nullifier proves a fabricated return and yields exact OperatorFault culprits. |
| S11 | core_equivocation_mob_to_eth_v2 | Two incompatible MOB_TO_ETH V2 digests with overlapping per-role approvals produce exactly the union of WARDEN and ACCOUNT intersections; realized loss is explicitly zero. |
| S12 | core_false_accusation_eth_to_mob_v1 | An authenticated challenger submits a supported but false Ethereum-source proof; verdict is ChallengerFault, only its challenge bond moves, and neither chain pauses. |
| S13 | core_claim_rejection_matrix | Fixed malformed, unauthenticated, unsupported, unstable-checkpoint, wrong-domain, and duplicate-incident claims each receive their specified rejection code with no verdict or consequence. |
| S14 | core_source_nullifier_exactly_once | One honest ETH_TO_MOB V2 source event experiences retry attempts but exactly one live reservation and one final nullifier consumption. |
| S15 | core_role_overlap_independence | One fixed identity belongs to WARDEN and ACCOUNT in ETH_TO_MOB V2 under the configured cross-role key-overlap policy; M_WARDEN and M_ACCOUNT thresholds require fresh distinct-domain signatures, either receipt fails in the other role, and the identity's bond/value is counted once. |
| S16 | core_mobilecoin_reserve_intent_order | A fixed ETH_TO_MOB V2 MobileCoin final spend is rejected before ReserveIntentTx, then accepted after the exact live reservation. |
| S17 | core_ethereum_reserve_intent_order | A fixed MOB_TO_ETH V2 Ethereum payout call is rejected before reserveRelease state, then accepted after the exact live reservation. |
| S18 | core_mobilecoin_safe_cancel | A MobileCoin reservation remains live before tombstone finality and also when only tombstone expiry is known; only exact finalized tombstone plus exact-action noninclusion/nonexecution safely returns it to Open/Available/Free while history and claim lock remain. |
| S19 | core_ethereum_safe_cancel | An Ethereum reservation remains live before nonce invalidation; after exact finalized invalidation/nonexecution proof it safely cancels without freeing any executable artifact. |
| S20 | core_eth_fault_freeze_without_loss | False ETH source evidence and signed approvals produce OperatorFault and immediate bond freeze even though no MobileCoin payout inclusion evidence exists; realized loss remains Unresolved and collateral is not distributed. |
| S21 | core_later_loss_assessment_and_distribution | A later objective MobileCoin payout receipt fixes the realized loss for S20; after every risk resolves, distribution pays exact restitution, capped proof cost, rate-and-cap bounty, and insurance surplus in order. |
| S22 | core_full_usdc_eusd_round_trip_v1_contractual | Execute the same accounting round trip under V1 using the explicitly configured contractual/manual MobileCoin-return adapter; label the result non-automatic and make no protocol proof claim for remote MobileCoin truth. |
| S37 | core_mobilecoin_reservation_privacy_twins | Two states differing only in the private real ring index generate equal public real-index-free projections and enabledness while carrying canonical public key images/tags and valid non-spend-capable ReserveInputProofs. |
| S38 | core_mobilecoin_same_tag_double_reserve | A first reservation of one network-global correct key-image/tag succeeds and a concurrent second reservation of that tag is rejected before finalization across a different bridge epoch/generation attempt. |
| S39 | core_mobilecoin_private_collision_defect_witness | With only FORGED_RESERVE_INPUT_PROOF enabled, two reservations secretly select the same UTXO under distinct claimed inputs and remain fully charged; one final succeeds, the other rejects, stays charged, and only tombstone plus exact noninclusion cancels it. |
| S40 | core_mobilecoin_spent_tag_backfill | Activation rejects an incomplete historical key-image/tag backfill; after exact rebuild, a reservation using any historically spent key image/tag rejects before charging capacity. |
| S41 | core_mobilecoin_prior_block_reserve | ReserveIntent and FinalCommit in one block reject as a block; after reservation finalizes in block h, the exact final succeeds no earlier than block h plus one. |
| S42 | core_mobilecoin_whole_block_conflict_matrix | Fixed reserve/spend, reserve/cancel, cancel/retry, cancel/final, and double-reserve/final same-block pairs each reject independent of transaction permutation. |
| S43 | core_mobilecoin_retry_ring_binding | After safe cancellation in block h, a later retry with a different ring set or salt rejects, while a later retry opening the identical permanent binding succeeds with refreshed proof randomness. |
| S44 | core_mobilecoin_final_vector_match | A multi-input final with exact ordered key-image/tag vector succeeds; permutation, omission, substitution, or extra element each rejects atomically. |
| S45 | core_accountable_quorum_intersection | A valid manifest with intersecting WARDEN and ACCOUNT quorums attributes incompatible approvals; the NONINTERSECTING_ACCOUNTABLE_QUORUM selector admits disjoint WARDEN quorums and is rejected by the manifest/property oracle before activation. |
| S46 | core_reserve_input_proof_value_binding | A valid structurally distinct two-row ThresholdOwnershipEqualityProof binds x/key image and z = b_pseudo - b_input to the same hidden member and exact C_pseudo - C_input relation; wrong pseudo-output, row substitution, and spend-domain transcript variants reject. |
| S47 | core_capacity_lot_gross_depletion | One MobileCoin release with principal, fee, external output, and exact change uses the selected ReserveAccountingProof to charge gross depletion and return change to the same lot with native/risk conservation. |
| S48 | core_policy_homogeneous_ring_matrix | A standard all-UNTAGGED ring and bridge all-matching-policy ring pass; mixed, wrong-policy, legacy-labeled, and change-policy variants each reject without revealing real index. |
| S49 | core_equivocation_intersection_bond_boundary | Two fixed intersecting WARDEN/ACCOUNT quorum pairs authorize incompatible digests; capacity uses only unique bonds in the exact per-role intersections, reaches the B_min divided-by-two boundary, and rejects one more risk unit. |
| S50 | core_cross_manifest_bond_minimum | Old and new WARDEN/ACCOUNT manifests are concurrently valid; enumeration includes every old/new quorum pair, selects the pair with minimum exact culprit bonds for B_min, and rejects capacity sized only from either manifest in isolation. |
| S52 | core_policy_tag_creation_matrix | An ordinary caller-created policy-tagged output and an unsolicited self-labelled return reject from the policy pool; authorized external capitalization, predecessor transfer, typed BridgeReturn beginning EncumberedSource, and exact same-lot bridge change each create only the expected immutable policy/lot provenance, and the typed return becomes eligible only after valid promotion. |
| S53 | core_threshold_reserve_proof_custody | Run the selected custody_profile under one fixed historical k-of-n owner manifest. In both profiles, PedPoP root shares plus the validated one-time offset produce the row-0 proof while every individual and k-minus-one knowledge projection lacks the root and one-time spend scalars. In CoreCustodyKnownZ, the exact registered signed row-1 authority may know z and every other recipient is rejected. In PrivateThresholdZ, every individual and k-minus-one projection additionally lacks b_input, b_pseudo, and z and the pinned private-Z range-proof witness mode passes. The selected accounting prover remains within its separate declared profile. |
| S54 | core_reserve_accounting_backend_kill_matrix | Under the one fixed SelectedAccountingProofBackend config, an exact accounting proof plus independently verified public range proofs pass; absent, ownership-only, unknown/stale/wrong-manifest backend and single mutations of CapacityLot, token, output class, fee, gross depletion, range-proof bytes/result, or change provenance reject before reservation state changes. |
| S55 | core_eligible_input_witness_share_lifecycle | Every authorized creation path resolves to the exact historical-roster PedPoP root-spend record and one-time-offset suite; wrong roster, invalid P = B + delta*G, below-threshold root refresh, participant loss without permitted recovery, and unverified root rotation leave the output ineligible in both profiles. Under PrivateThresholdZ only, external capitalization, predecessor transfer, typed BridgeReturn, and same-lot change also establish the exact mask-share/MPC records; missing delivery, nonlinear-KDF-per-share, or invalid mask refresh leaves the output ineligible. The same absent mask record remains eligible under CoreCustodyKnownZ when its registered row-1 authority path is valid. |
| S56 | core_threshold_ownership_ceremony_kill_matrix | Execute the exact monotone PreIntentKeyImageContext-bound pre-D key-image/DLEQ state machine, commit its ordered aggregate transcript into the intent/statement, derive D, then execute a freshly nonced row-0 reserve-commitment/response round plus the profile-typed row-1 path: one signed KnownZ authority response in CoreCustodyKnownZ or threshold z responses in PrivateThresholdZ. Bad key-image share/DLEQ, late key-image substitution, context/profile/set substitution, bad signed row-1 response or private-Z share, signer-set swap, cross-input swap, cross-phase/out-of-order message, reserve/final nonce reuse, malformed or identity key image, response-before-D, and reserve-proof-to-spend-verifier replay each reject at its earliest specified check. |

### 15.2 STAGED scenarios

| Scenario ID | Runner instance | Required fixed trace and result |
|---|---|---|
| S23 | staged_finalized_uncleared_serial_drain | A first finalized release remains in L_q; a second reservation by the same attributable coalition is rejected when their combined risk would exceed capacity. |
| S24 | staged_static_allocation_premise_boundary | Locally valid Ethereum and MobileCoin manifests whose global sum exceeds the minimum applicable B_min divided by two remain locally readable but make StaticGlobalAllocationPremiseV1 false and the product configuration nonconforming; no runtime activation oracle is invented. |
| S25 | staged_allocation_reconfiguration_quiescence | Reallocation is rejected with one live old reservation, rejected with one old FinalizedUncleared position, and accepted only after both clear while old bonds remain locked. |
| S26 | staged_chain_local_fault_rotate_resume | Ethereum FaultBondFreeze occurs first; separate causally referenced Ethereum and MobileCoin pauses, expulsions, rotations, and fresh-manifest resumes occur without remote atomic mutation. |
| S27 | staged_false_claim_creates_no_inventory | A fully authorized false ETH_TO_MOB release has a liability and payout but no authentic SourceInventoryEvent, so no USDC inventory becomes Available. |
| S28 | staged_nullifier_cancel_then_reauthorize | One source nullifier is Reserved, objectively canceled to Free with history retained and claim lock preserved, reserved by the allowed replacement intent, and consumed once. |
| S29 | staged_immediate_freeze_delayed_distribution | OperatorFault freezes all exact bonds immediately; a live remote reservation prevents risk Cleared and distribution; cancellation/final disposition, fixed loss, and window closure later permit the exact distribution. |
| S30 | staged_reject_forged_source_checkpoint | Promotion evidence with a forged local or remote checkpoint/root is rejected; the local position remains Encumbered and no Available inventory is created. |
| S31 | staged_reject_forged_source_inflow | Authentic checkpoints paired to a mutated inflow amount/asset/recipient fail proof-to-record normalization and leave the local position Encumbered. |
| S32 | staged_propagation_window_exposure | After Ethereum bond freeze and before MobileCoin pause, MobileCoin executes the exact maximum locally allocated outflow; L_q already includes it and rejects one unit more without assuming instant remote pause. |

### 15.3 COMPOSITION scenarios

| Scenario ID | Runner instance | Required fixed trace and result |
|---|---|---|
| S33 | composition_chain_log_tamper_matrix | Fixed deletion, duplication, payload mutation, and same-chain reordering variants are each detected by event/parity/hash checks. |
| S34 | composition_all_causally_closed_cuts | Enumerate every reachable causally closed Ethereum/MobileCoin prefix pair for the full honest cycle and verify three-way projection parity at each cut. |
| S35 | composition_independent_interleaving | Two fixed events with disjoint complete footprints and no causal path execute in both orders with identical projected state and enabled actions. |
| S36 | composition_fault_propagation_dag | Ethereum freeze, local pause, typed cross-chain attestation, MobileCoin pause, per-chain rotations, and resumes form the exact causal DAG; missing and forged edges are rejected and no global sequence is used. |
| S51 | composition_event_receipt_hash_dag | Construct one accepted event through derived event ID, CanonicalProposalBody, proposal ID, four log/receipt/block-root/staged-object-excluded semantic projections, acceptance ID with H(causal_event_refs), zero-self-field 31-field envelope, event hash, and receipt; identical rebroadcast is idempotent, altered-ID reuse rejects, and Ethereum/MobileCoin genesis sentinels produce distinct first-event chains. |

## 16. One-defect falsifier manifest

Each selector is a Boolean model constant whose baseline value is FALSE.
Exactly one selector is TRUE in a defect run. The Target field contains exactly
one Property ID. The mutation is one precise semantic change, not a bundle.
Minimal prestate fixes the shortest state class in which the mutation can bite.
Earliest oracle is the first named check that MUST report the target. Other
violations are permitted only when listed in Allowed secondary; an unlisted
violation, missing target, different earliest target, or clean run fails the
selector. The runner MUST reject selector names or rows that are duplicated,
missing, or mapped to zero/multiple targets.

### 16.1 CORE selectors

| Selector ID | Unique selector name | Exact mutated clause | Minimal prestate | Target | Earliest oracle | Allowed secondary |
|---|---|---|---|---|---|---|
| D01 | TRUTH_IN_RELEASE_GUARD | Add GroundTruthFault equals false to ReserveIntent admission. | Observable twin states differing only in source truth. | P03 | TruthNoninterference | {P04} |
| D02 | FALSE_RELEASE_WITHOUT_ACCOUNTABILITY | Finalize an unmatched release without stored WARDEN/ACCOUNT identities. | One threshold-signed false SourceAssertion and live reservation. | P41 | UnmatchedReleaseHasAccountability | {P19,P20} |
| D03 | MISSING_AUTOPROOF_ETH | Mark ETH_TO_MOB false-source release AutoVerifiable but create no supported proof. | One finalized false ETH assertion release. | P42 | UnmatchedReleaseHasAutomaticProof | {} |
| D04 | MISSING_AUTOPROOF_MOB_V2 | Mark MOB_TO_ETH V2 false-source release AutoVerifiable but create no map proof. | One finalized false MobileCoin V2 assertion release. | P42 | UnmatchedReleaseHasAutomaticProof | {} |
| D05 | MOB_NONMEMBERSHIP_AS_PLAIN_INCLUSION | Accept absence from an inclusion-only Merkle tree as nonmembership. | One fabricated V2 return and inclusion-root checkpoint. | P42 | UnmatchedReleaseHasAutomaticProof | {P64} |
| D06 | OMIT_MLSAG | Allow ETH_TO_MOB finalization with the MLSAG field absent. | One otherwise complete MobileCoin reservation. | P15 | NoPolicyBypass | {P16} |
| D07 | INVALID_MLSAG | Treat one invalid MLSAG token as valid. | One reserved MobileCoin release with all other artifacts. | P16 | MlsagArtifactSound | {} |
| D08 | UNDER_THRESHOLD_OWNER | Accept fewer than K_OWN valid owner participants. | One reserved MobileCoin release with K_OWN minus one. | P16 | MlsagArtifactSound | {} |
| D09 | OMIT_FROST | Allow ETH_TO_MOB finalization with no FROST artifact. | One otherwise complete MobileCoin reservation. | P15 | NoPolicyBypass | {P17} |
| D10 | INVALID_FROST | Treat an invalid FROST aggregate token as valid. | One reserved MobileCoin release with all other artifacts. | P17 | FrostArtifactSound | {} |
| D11 | UNDER_THRESHOLD_FROST | Accept fewer than K_FROST valid gate participants. | One reserved MobileCoin release with K_FROST minus one. | P17 | FrostArtifactSound | {} |
| D12 | OMIT_ETH_MULTISIG | Allow MOB_TO_ETH finalization with no Ethereum multisig artifact. | One otherwise complete Ethereum reservation. | P15 | NoPolicyBypass | {P18} |
| D13 | INVALID_ETH_MULTISIG | Treat an invalid Ethereum multisig artifact as valid. | One reserved Ethereum release with all other artifacts. | P18 | EthereumMultisigArtifactSound | {} |
| D14 | UNDER_THRESHOLD_ETH | Accept fewer than K_ETH valid Ethereum signers. | One reserved Ethereum release with K_ETH minus one. | P18 | EthereumMultisigArtifactSound | {} |
| D15 | OMIT_WARDEN_CERT | Reserve/finalize with WARDEN certificate absent. | One otherwise complete release request. | P15 | NoPolicyBypass | {P19,P41} |
| D16 | UNDER_THRESHOLD_WARDEN | Accept fewer than K_WARDEN distinct approvals. | One intent with K_WARDEN minus one valid approvals. | P19 | WardenCertificateSound | {P41} |
| D17 | OMIT_ACCOUNTABILITY_CERT | Reserve/finalize with ACCOUNT certificate absent. | One otherwise complete release request. | P15 | NoPolicyBypass | {P20,P41} |
| D18 | UNDER_THRESHOLD_ACCOUNT | Accept fewer than K_ACCOUNT distinct approvals. | One intent with K_ACCOUNT minus one valid approvals. | P20 | AccountabilityCertificateSound | {P41} |
| D19 | WRONG_ROLE_SIGNER | Count a valid signer from another role toward the selected threshold. | Overlapping manifests with one wrong-role identity. | P22 | RoleThresholdsIndependent | {P19,P20} |
| D20 | DUPLICATE_OWNER_SLOTS | Count the same owner identity in two occupied slots. | K_OWN requires the duplicated slot to pass. | P21 | SignerSlotsDistinct | {P16} |
| D21 | DUPLICATE_FROST_SLOTS | Count the same FROST identity twice. | K_FROST requires the duplicated slot to pass. | P21 | SignerSlotsDistinct | {P17} |
| D22 | DUPLICATE_ETH_SLOTS | Count the same Ethereum identity twice. | K_ETH requires the duplicated slot to pass. | P21 | SignerSlotsDistinct | {P18} |
| D23 | DUPLICATE_WARDEN_SLOTS | Count the same WARDEN identity twice. | K_WARDEN requires the duplicated slot to pass. | P21 | SignerSlotsDistinct | {P19} |
| D24 | DUPLICATE_ACCOUNT_SLOTS | Count the same ACCOUNT identity twice. | K_ACCOUNT requires the duplicated slot to pass. | P21 | SignerSlotsDistinct | {P20} |
| D25 | STALE_FROST_EPOCH | Accept a valid FROST artifact from the retired epoch. | Fresh epoch active; old FROST artifact available. | P24 | ReleaseEpochSound | {P17,P58} |
| D26 | STALE_ETH_EPOCH | Accept a valid Ethereum multisig artifact from the retired epoch. | Fresh Ethereum epoch active; old artifact available. | P24 | ReleaseEpochSound | {P18,P58} |
| D27 | STALE_WARDEN_EPOCH | Accept a valid WARDEN certificate from the retired epoch. | Fresh WARDEN epoch active; old certificate available. | P24 | ReleaseEpochSound | {P19,P57} |
| D28 | STALE_ACCOUNT_EPOCH | Accept a valid ACCOUNT certificate from the retired epoch. | Fresh ACCOUNT epoch active; old certificate available. | P24 | ReleaseEpochSound | {P20,P57} |
| D29 | MLSAG_DIGEST_MISMATCH | Validate MLSAG over D1 while finalizing D2. | One live reservation and mismatched valid token. | P23 | ReleaseDigestBound | {P16} |
| D30 | FROST_DIGEST_MISMATCH | Validate FROST over M_GATE(gate_manifest,D1) while finalizing base D2. | One live reservation and mismatched valid token. | P23 | ReleaseDigestBound | {P17} |
| D31 | ETH_MULTISIG_DIGEST_MISMATCH | Validate Ethereum multisig over D1 while finalizing D2. | One live reservation and mismatched valid token. | P23 | ReleaseDigestBound | {P18} |
| D32 | WARDEN_DIGEST_MISMATCH | Validate M_WARDEN receipts binding D1 for a reservation whose base digest is D2. | One proposed reservation with mismatched certificate. | P23 | ReleaseDigestBound | {P19} |
| D33 | ACCOUNT_DIGEST_MISMATCH | Validate M_ACCOUNT receipts binding D1 for a reservation whose base digest is D2. | One proposed reservation with mismatched certificate. | P23 | ReleaseDigestBound | {P20} |
| D34 | WRONG_BOND_MANIFEST | Resolve approver bonds from a mutable/current manifest instead of D's historical manifest. | One old-epoch approved intent after manifest rotation. | P25 | HistoricalBondBinding | {P39} |
| D35 | UNBONDED_ACCOUNT_SIGNER | Count an ACCOUNT signer with no bound historical bond. | Threshold depends on the unbonded identity. | P20 | AccountabilityCertificateSound | {P25,P41} |
| D36 | RELEASE_WITHOUT_RESERVE | Enable FinalCommit with no live reservation record. | Fully signed destination action and Free nullifier. | P12 | ReserveIntentPrecedesExecutableSpend | {P13,P14,P29,P30} |
| D37 | OMIT_NULLIFIER_CONSUMPTION | FinalCommit leaves source nullifier Reserved. | One live reservation ready to finalize. | P09 | NullifierBijection | {P30,P59} |
| D38 | POISON_NULLIFIER | Permit an action to set a Free nullifier directly to Consumed without release. | One unused source event. | P09 | NullifierBijection | {P59} |
| D39 | REUSE_SOURCE_EVENT | Permit a second final settlement for an already Consumed source nullifier. | One Settled liability and retry request. | P09 | NullifierBijection | {P59,P60} |
| D40 | VERSIONED_NULLIFIER | Include protocol version in nullifier derivation. | Same source event represented under V1 and V2. | P08 | StableSourceNullifier | {P09,P60} |
| D41 | ARBITRARY_OPERATOR_VERDICT | Let adjudication choose OperatorFault independent of evidence. | One admitted honest proof. | P45 | VerdictDeterministic | {P46,P48} |
| D42 | INNOCENT_CULPRIT | Add one nonapprover to computed FALSE_SOURCE culprits. | One valid false-source proof and one innocent bonded identity. | P47 | CulpritSetExact | {P48,P50} |
| D43 | SLASH_WITHOUT_VERDICT | Freeze one operator bond with no OperatorFault verdict. | One locked operator bond and no claim. | P48 | SlashRequiresVerdict | {} |
| D44 | DOUBLE_APPLY_PROOF | Apply the same incident distribution twice. | One completed collateral distribution. | P49 | SlashExactOnce | {P39,P50} |
| D45 | REJECTED_CLAIM_EFFECT | A rejected claim emits FAULT_BOND_FREEZE. | One malformed authenticated claim. | P51 | NoRejectedClaimEffect | {P44,P48} |
| D46 | UNSUPPORTED_AUTO_SLASH | Automatically convict operators for MobileCoin-v1 false-source evidence. | One V1 reverse false-source claim. | P52 | NoUnsupportedAutomaticSlash | {P46} |
| D47 | CHALLENGER_FAULT_PAUSES_OPERATOR | ChallengerFault emits PAUSE_POLICY_EPOCH. | One admitted false challenge. | P53 | ChallengerFaultDoesNotPause | {P55,P56} |
| D48 | WRONG_CHALLENGER_SLASH | ChallengerFault debits an operator bond instead of only the challenge bond. | One admitted false challenge and locked operator bond. | P46 | VerdictSound | {P48,P53} |
| D49 | RESERVE_CAP_BYPASS | ReserveIntent ignores the per-asset local cap. | Local usage equals allocation; one-unit proposal. | P35 | PerAssetReserveExposureBound | {P36,P77} |
| D50 | OMIT_LIVE_RESERVATION_EXPOSURE | Exclude one live CapacityReserved release-risk charge from current risk. | One accepted reservation before finalization. | P35 | PerAssetReserveExposureBound | {P37,P72,P77} |
| D51 | UNDERCOUNT_CROSS_DIRECTION | Omit the reverse-direction allocation from coalition q's governance sum. | Same bonds authorize one live allocation per direction. | P37 | CorrelatedBondCapacityBound | {P72} |
| D52 | UNDERCOUNT_CROSS_GENERATION | Omit an overlapping predecessor generation from coalition q's sum. | Two live generations share one failure domain and bond quorum. | P37 | CorrelatedBondCapacityBound | {P71,P72} |
| D53 | DOUBLE_COUNT_OVERLAP_BOND | Count one identity's bond once per role. | One identity occupies WARDEN and ACCOUNT. | P39 | UniqueBondAccounting | {P37,P50} |
| D54 | UNFUNDED_SUCCESSOR | Activate a successor generation with zero eligible destination capital. | Authority-ready successor with no capitalization event. | P69 | CapitalizationSound | {P71} |
| D55 | FUND_BEFORE_OWNER_AUTHORITY_READY | Capitalize a generation before owner authority is ready. | Defined generation and external capital allocation. | P69 | CapitalizationSound | {P71} |
| D56 | INELIGIBLE_BACKING | Let an Unsafe CapacityLot satisfy ReserveIntent. | One Unsafe lot and one open liability. | P70 | NoIneligibleBacking | {P35,P77} |
| D57 | EARLY_BOND_EXIT | Release a historical bond before its last bound risk window clears. | ExitRequested bond with one FinalizedUncleared release. | P25 | HistoricalBondBinding | {P37,P39} |
| D58 | EXECUTABLE_BEFORE_RESERVE_INTENT | Accept a spend/call against a proposed but uncommitted reservation. | Complete artifacts and proposal only. | P12 | ReserveIntentPrecedesExecutableSpend | {P13,P30} |
| D59 | RESERVATION_ID_NOT_IN_DIGEST | Remove reservation_id from D. | Two reservations share all other intent fields. | P14 | CapacityDecisionBound | {P23,P88} |
| D60 | CAPACITY_DECISION_AFTER_FINAL_COMMIT | Commit destination payout before capacity acceptance. | Open liability, available lot, complete artifacts. | P30 | AtomicFinalCommit | {P12,P13,P67} |
| D61 | LOCAL_ALLOCATION_BYPASS | Borrow unused allocation from the remote chain during local admission. | Local allocation full and remote allocation free. | P36 | LocalAllocationBound | {P37,P73} |
| D62 | ALLOCATION_MANIFEST_MISMATCH | Reserve under manifest M1 while D cites M2. | Two active-looking manifest atoms with different hashes. | P11 | AllocationManifestBound | {P23,P36} |
| D63 | REALLOCATE_WITH_LIVE_RESERVATION | Activate successor allocation while one old reservation is live. | Old allocation with one ReservedIntent. | P33 | ReallocationQuiescence | {P37} |
| D64 | REALLOCATE_WITH_UNCLEARED_FINAL | Activate successor allocation while one old risk is FinalizedUncleared. | Old allocation with finalized uncleared payout. | P33 | ReallocationQuiescence | {P31,P37} |
| D65 | DOUBLE_CLAIM_LOCK_ONE_NULLIFIER | OPEN_LIABILITY binds a second live liability to one stable source nullifier. | One Open liability owns the claim lock. | P28 | ClaimLockAndLotSelectionInjective | {P60,P78} |
| D66 | OPEN_TO_FINAL_WITHOUT_RESERVE | Allow liability Open to move directly to Settled. | Open liability, Available lots, complete artifacts. | P26 | LiabilityLifecycleSound | {P12,P27,P30} |
| D67 | FINAL_COMMIT_NONATOMIC | Spend CapacityLots but leave liability/nullifier/risk unchanged. | One live exact reservation ready to finalize. | P30 | AtomicFinalCommit | {P09,P26,P27,P31} |
| D68 | CLEAR_FINALIZED_OUTFLOW_EARLY | Move risk to Cleared before its committed window and loss_fixed result. | One FinalizedUncleared risk before deadline. | P31 | FinalizedUnclearedRetained | {P61,P72} |
| D69 | CANCEL_WITHOUT_NONEXECUTION | Accept coordinator timeout as ObjectiveCancelProof. | One live executable reservation. | P32 | SafeCancellation | {P59,P79} |
| D70 | CANCEL_WRONG_TOMBSTONE | Prove nonexecution for a tombstone not bound to the reserved action. | One MobileCoin reservation and unrelated expired tx. | P32 | SafeCancellation | {} |
| D71 | MAGIC_SOURCE_INVENTORY_FROM_CLAIM | OPEN_LIABILITY creates Available source inventory. | One signed SourceAssertion and no local inflow. | P05 | ClaimedLiabilitySeparatedFromSourceInventory | {P07,P40} |
| D72 | OMIT_USDC_SOURCE_INFLOW | Full V2 cycle promotes/uses USDC with no local RECORD_ESCROW_SOURCE_INFLOW. | First eUSD FinalCommit and no USDC source position. | P34 | FullCycleConservation | {P06,P07} |
| D73 | OMIT_EUSD_RETURN_INFLOW | Full V2 cycle promotes/uses eUSD with no local return inflow. | Second USDC FinalCommit and no eUSD source position. | P34 | FullCycleConservation | {P06,P07} |
| D74 | PROMOTE_SOURCE_BEFORE_DESTINATION_FINAL | Move Encumbered source value to Available before paired remote FinalCommit. | One local inflow and CapacityReserved remote liability. | P07 | SourceInventoryConservation | {P34} |
| D75 | CROSS_ASSET_ADD_WITHOUT_VALUATION | Add native USDC and eUSD units directly for B_min comparison. | One live reservation in each asset. | P38 | ValuationManifestSound | {P37} |
| D76 | DUPLICATE_VALUE_POSITION_IN_AGGREGATE | Count one CapacityLot slice twice in the same free or L_q aggregate. | One ReservedIntent lot with lifecycle and risk projections. | P40 | UniqueValueAccounting | {P35,P37,P77} |
| D77 | UNDER_SLASH_CULPRIT | Slash less than 100 percent of one exact culprit bond. | Risk Cleared, fixed loss, two frozen culprit bonds. | P50 | PenaltyDistributionExact | {P49} |
| D78 | OMIT_CULPRIT_BOND | Exclude one frozen exact culprit bond from distribution. | Risk Cleared and two unique frozen bonds. | P50 | PenaltyDistributionExact | {P39} |
| D79 | BOUNTY_BEFORE_RESTITUTION | Pay bounty from S before satisfying fixed unreimbursed loss. | Cleared risk with S greater than zero and L greater than zero. | P50 | PenaltyDistributionExact | {} |
| D80 | OPEN_LIABILITY_WHILE_PAUSED | Permit OPEN_LIABILITY after local pause. | One locally Paused epoch and valid receipts. | P56 | PausedEpochAdmissionClosed | {} |
| D81 | FINALIZE_WHILE_PAUSED | Permit old-epoch FinalCommit ordered after local pause. | Pre-pause live reservation and locally Paused epoch. | P56 | PausedEpochAdmissionClosed | {P24} |
| D82 | REUSE_EXPELLED_SIGNER | Count an expelled identity in a fresh WARDEN manifest/artifact. | One fault, freeze, pause, and fresh-manifest proposal. | P57 | ExpelledSignerNotReused | {P58} |
| D83 | REOPEN_WITH_STALE_GATE | Reopen using the pre-fault gate key/manifest. | Paused epoch after OperatorFault. | P58 | FreshGateBeforeResumption | {P24,P57} |

### 16.2 STAGED selectors

| Selector ID | Unique selector name | Exact mutated clause | Minimal prestate | Target | Earliest oracle | Allowed secondary |
|---|---|---|---|---|---|---|
| D84 | DELETE_CHAIN_EVENT | Drop one committed event from STAGED replay input. | Two-event local prefix whose second depends on first. | P67 | CoreStagedProjectionParity | {P66} |
| D85 | DUPLICATE_CHAIN_EVENT | Apply one immutable event ID twice. | One applicable committed event. | P65 | PerChainEventExactlyOnce | {P67} |
| D86 | MUTATE_CHAIN_EVENT | Change payload bytes while preserving event_id. | One committed capacity-affecting event. | P66 | PerChainEventHashChainSound | {P67} |
| D87 | REORDER_SAME_CHAIN_EVENT | Swap two causally ordered same-chain sequence entries. | Two adjacent dependent local events. | P66 | PerChainEventHashChainSound | {P67,P75} |
| D88 | UNKNOWN_CHAIN_EVENT_ACCEPTED | Treat an unknown kind as a no-op success. | One valid prefix and one unknown event envelope. | P68 | UnknownEventFailsClosed | {P67} |
| D89 | CORE_STAGED_DECISION_MISMATCH | Flip STAGED local capacity acceptance relative to CORE. | One boundary-value ReserveIntent proposal. | P67 | CoreStagedProjectionParity | {} |
| D90 | OMIT_OPEN_LIABILITY_EVENT | CORE opens liability but emitter omits E07. | One valid source assertion approval set. | P67 | CoreStagedProjectionParity | {P65} |
| D91 | OMIT_RESERVE_INTENT_EVENT | CORE reserves but emitter omits E08. | One Open liability and available CapacityLots. | P67 | CoreStagedProjectionParity | {P65} |
| D92 | OMIT_FINAL_COMMIT_EVENT | CORE finalizes but emitter omits E09. | One live exact reservation. | P67 | CoreStagedProjectionParity | {P65} |
| D93 | OMIT_FAULT_FREEZE_EVENT | CORE freezes bonds but emitter omits E24. | One OperatorFault verdict and locked culprit bonds. | P67 | CoreStagedProjectionParity | {P54,P65} |
| D94 | FORGET_RESERVED_SOURCE_NULLIFIER | STAGED ReserveIntent charges capacity but leaves nullifier Free. | One accepted reservation event. | P59 | SourceNullifierLifecycleSound | {P60,P67} |
| D95 | TWO_LIVE_RESERVATIONS_ONE_SOURCE | Permit two reservations to own one source nullifier. | One live reservation and second intent for same source. | P60 | NoConcurrentSourceReservation | {P29,P59,P78} |
| D96 | CANCEL_ERASES_NULLIFIER_HISTORY | Remove the prior Reserved/Canceled history on safe cancel. | One safely canceled reservation. | P59 | SourceNullifierLifecycleSound | {} |
| D97 | DELAY_FAULT_BOND_FREEZE | Record OperatorFault without same-chain bond freeze. | Admitted operator-fault proof and locked bonds. | P54 | FaultBondFreezeImmediate | {P48,P67} |
| D98 | EARLY_COLLATERAL_DISTRIBUTION | Distribute while one implicated risk remains FinalizedUncleared. | Frozen culprit bonds, fixed partial loss, uncleared risk. | P61 | CollateralDistributionAfterRiskResolution | {P31,P50} |
| D99 | FORGED_SOURCE_CHECKPOINT | Accept promotion evidence with invalid checkpoint/root authentication. | One Encumbered local inflow and paired remote release assertion. | P64 | SourceAdapterSoundness | {P06,P07} |
| D100 | FORGED_SOURCE_INFLOW | Bind valid checkpoint evidence to mutated inflow asset/amount/recipient. | One Encumbered local inflow and mismatched normalized record. | P64 | SourceAdapterSoundness | {P06,P07} |

### 16.3 COMPOSITION selectors

| Selector ID | Unique selector name | Exact mutated clause | Minimal prestate | Target | Earliest oracle | Allowed secondary |
|---|---|---|---|---|---|---|
| D101 | FORGED_CAUSAL_REFERENCE | Accept a causal edge whose origin hash does not match finalized origin bytes. | One finalized origin event and one dependent remote proposal. | P74 | CausalReferenceSound | {P76} |
| D102 | MISSING_REQUIRED_CAUSAL_REFERENCE | Commit a promotion/pause without its required remote edge. | One remote finalized prerequisite and local consumer proposal. | P74 | CausalReferenceSound | {P07,P55,P76} |
| D103 | POR_COMMUTES_CAUSALLY_RELATED_EVENTS | Declare two events commuting despite a causal path. | One cross-chain origin and its direct consumer. | P75 | CrossChainPartialOrderSound | {P76} |
| D104 | POR_COMMUTES_OVERLAPPING_FOOTPRINTS | Commute events sharing one liability or bond without a causal edge. | Two concurrent proposals with one shared typed resource. | P75 | CrossChainPartialOrderSound | {P76} |
| D105 | NON_PREFIX_CAUSAL_CUT | Compare projections at a cut missing an included event's causal predecessor. | Two local prefixes linked by one remote edge. | P76 | ChainPrefixCausalCutParity | {P74} |
| D106 | INSTANT_REMOTE_STATE_MUTATION | FAULT_BOND_FREEZE directly sets MobileCoin pause/rotation state. | Active chains and one Ethereum OperatorFault verdict. | P73 | ChainLocalConsequenceIsolation | {P55,P74} |
| D150 | CIRCULAR_STATE_EVENT_RECEIPT_HASH | Include the staged event/receipt/log bytes in a core or capacity poststate projection, or include event_hash in acceptance_id. | One accepted proposal ready to construct four projections, envelope, and receipt. | P95 | CapacityEventDigestAcyclic | {P66,P67} |
| D151 | EVENT_HASH_SELF_NOT_ZERO_SENTINEL | Hash the populated event_hash field instead of its typed zero sentinel. | One otherwise canonical complete CapacityEvent envelope. | P95 | CapacityEventDigestAcyclic | {P66} |

### 16.4 Additional CORE selectors

| Selector ID | Unique selector name | Exact mutated clause | Minimal prestate | Target | Earliest oracle | Allowed secondary |
|---|---|---|---|---|---|---|
| D108 | INVENTED_REALIZED_LOSS | Set loss_fixed from asserted amount with no payout evidence. | OperatorFault freeze and no objective destination receipt. | P62 | LossAssessmentSound | {P63} |
| D109 | WRONG_REALIZED_LOSS_AMOUNT | Compute loss_fixed from payout evidence using a different amount/asset. | One objective payout receipt and valuation manifest. | P62 | LossAssessmentSound | {P50,P63} |
| D110 | CONFLATE_FAULT_WITH_LOSS_PROOF | OperatorFault verdict automatically sets loss_fixed. | Valid false-source offense proof and absent payout proof. | P63 | FaultAndLossEvidenceSeparated | {P62} |
| D111 | RESTITUTION_WITHOUT_LOSS_EVIDENCE | Enable restitution directly from FaultBondFreeze. | Frozen bonds and unresolved destination outcome. | P63 | FaultAndLossEvidenceSeparated | {P50,P61} |
| D112 | EQUIVOCATION_ASSUMES_NONZERO_LOSS | Assign asserted release amount as loss to zero-payout equivocation. | Two incompatible approvals and no destination final. | P62 | LossAssessmentSound | {P50} |
| D113 | SLASH_INNOCENT_EXTRA_IDENTITY | Debit one bond owner not named by the exact verdict. | Valid verdict, exact frozen culprits, one extra locked bond. | P48 | SlashRequiresVerdict | {P47,P50} |
| D114 | CHALLENGER_FAULT_ROTATES_OPERATORS | ChallengerFault emits REGISTER_FRESH_GATE_EPOCH excluding operators. | One admitted false challenge. | P53 | ChallengerFaultDoesNotPause | {P57,P58} |
| D115 | TOMBSTONE_WITHOUT_FINAL_NONINCLUSION | Cancel after finalized tombstone height but omit exact-action noninclusion. | Live MobileCoin reservation beyond tombstone. | P32 | SafeCancellation | {P59,P79} |
| D116 | SECOND_LIVE_LIABILITY_SAME_SOURCE | Treat Bound claim-lock state as available during OPEN_LIABILITY. | One Open liability and second approved assertion for same nullifier. | P28 | ClaimLockAndLotSelectionInjective | {P60,P78} |
| D117 | OVERBOOK_CAPACITY_LOT | Accept reservation charges whose sum makes a CapacityLot free value negative. | One lot with free value exactly below proposed gross charge. | P77 | CapacityLotConservation | {P35,P36,P91} |
| D118 | DOUBLE_RESERVE_SAME_LEASE_TAG | Omit live-tag uniqueness check for the second reservation. | One live tag lease and a second Open liability using it. | P79 | LiveInputLeaseInjective | {P78,P87} |
| D119 | FORGED_RESERVE_INPUT_PROOF | Accept a ThresholdOwnershipEqualityProof whose ownership/equation token fails verification. | One Open liability, Available lot, and forged proof/tag. | P80 | ThresholdOwnershipEqualityProofSound | {P79,P90} |
| D120 | FINALIZE_WITH_DIFFERENT_KEY_IMAGE | Replace one final key image while retaining reservation and other artifacts. | One prior-block multi-input reservation ready to finalize. | P81 | FinalizationMatchesReservation | {P79} |
| D121 | BRIDGE_SCOPED_LEASE_TAG | Include bridge_id in LeaseTag derivation. | Same key image proposed by two bridge IDs on one network. | P83 | NetworkGlobalLeaseTagStable | {P79} |
| D122 | RETRY_DIFFERENT_RING_SET | Accept retry opening a new salted ring-set commitment for the same key image. | Safely canceled lease with permanent binding. | P84 | PermanentKeyImageRingBinding | {P82} |
| D123 | ACTIVATE_WITH_INCOMPLETE_KI_BACKFILL | Mark spent-tag index ready while one historical ledger key image is absent. | Authority-ready generation and incomplete migration set. | P85 | HistoricalSpentTagBackfillComplete | {P71,P79} |
| D124 | SAME_BLOCK_RESERVE_FINAL | Let FinalCommit consume a ReserveIntent created earlier in the same block order. | One Open liability and both transactions in one candidate block. | P86 | PriorBlockReserveRequired | {P87} |
| D125 | SAME_BLOCK_RESERVE_CANCEL | Sequentially accept ReserveIntent then cancellation in one block. | One Open liability and valid future cancellation proof inputs. | P87 | WholeBlockLeaseConflictFree | {} |
| D126 | SAME_BLOCK_CANCEL_RETRY | Sequentially cancel and re-lease the same tag in one block. | One live safely cancelable reservation and retry. | P87 | WholeBlockLeaseConflictFree | {P82} |
| D127 | SAME_BLOCK_CANCEL_FINAL | Sequentially cancel then finalize the canceled reservation in one block. | One live reservation, cancel proof, and final artifacts. | P87 | WholeBlockLeaseConflictFree | {P32,P81} |
| D128 | SAME_BLOCK_DOUBLE_RESERVE_FINAL | Resolve two same-tag reservations/final by transaction order in one block. | Two conflicting reserve/final candidates for one tag. | P87 | WholeBlockLeaseConflictFree | {P79,P86} |
| D129 | FINAL_KEY_IMAGE_VECTOR_PERMUTED | Accept final key-image/tag vector in a different order from reservation. | One prior-block two-input reservation. | P81 | FinalizationMatchesReservation | {} |
| D130 | RETRY_BEFORE_CONSENSUS_CANCEL | Re-lease a live tag before Cancelled is committed. | One live reservation and same-ring retry. | P82 | RetryLeaseSound | {P79,P87} |
| D131 | RESERVATION_CHARGES_TWO_LIABILITIES | Bind one reservation ID to two Open liabilities. | Two Open liabilities with distinct claim locks. | P78 | LiabilityReservationInjective | {P14,P29} |
| D132 | PUBLIC_REAL_RING_INDEX | Add real_input_index to ReserveIntent public payload. | One valid MobileCoin reservation with ring size above one. | P80 | ThresholdOwnershipEqualityProofSound | {} |
| D133 | PROMOTE_UNFINALIZED_LOCAL_INFLOW | Promote Encumbered inflow without finalized reference to its local inclusion. | One local inflow and finalized paired remote release. | P07 | SourceInventoryConservation | {P34,P64} |
| D134 | PROMOTE_WITHOUT_REMOTE_FINAL_RECEIPT | Promote source inflow from liability assertion without paired remote FinalCommit evidence. | One finalized local inflow and remote Settled assertion only. | P07 | SourceInventoryConservation | {P34,P64} |
| D136 | CANCEL_RELEASES_CLAIM_LOCK | Safe cancellation changes Bound claim lock to Unbound. | One CapacityReserved liability with valid cancel proof. | P28 | ClaimLockAndLotSelectionInjective | {P60,P78} |
| D137 | MEMPOOL_SIGNATURE_CREATES_AUTH_STATE | Add committed AuthorizedPending state when signatures appear off chain. | One live reservation and observed partial signatures. | P26 | LiabilityLifecycleSound | {P65,P67} |
| D138 | CIRCULAR_RESERVATION_DIGEST | Put reservation_id or a descendant receipt/proof hash, commitment, bundle commitment, or bytes inside IntentBindingCore before deriving reservation_id. | One candidate liability and complete pre-signing resources. | P88 | DigestConstructionAcyclic | {P10,P14,P23} |
| D139 | NONINTERSECTING_ACCOUNTABLE_QUORUM | Activate WARDEN threshold with two times k at most n, permitting two disjoint valid quorums. | One proposed manifest and two incompatible digests. | P89 | AccountableQuorumIntersection | {P47} |
| D140 | RESERVE_PROOF_OMITS_COMMITMENT_DIFFERENCE | Verify ownership/tag but omit MLSAG commitment-difference-row equality. | One ring input and mismatched pseudo-output. | P90 | ThresholdOwnershipEqualityValueBinding | {P80,P91} |
| D141 | UNDERCHARGE_GROSS_DEPLETION | Charge only customer principal and omit fee/non-lot output. | One reservation with principal, fee, and external output. | P91 | CapacityLotGrossDepletionConservation | {P35,P77} |
| D142 | CHANGE_TO_DIFFERENT_CAPACITY_LOT | Credit change to a different lot/generation than its real inputs. | One valid release with nonzero change and two lots. | P93 | BridgeChangeLotPreservation | {P40,P91} |
| D143 | MIXED_POLICY_BRIDGE_RING | Accept bridge ring containing one UNTAGGED or wrong-policy TxOut. | One bridge ring with matching real input and mixed decoy. | P92 | PolicyHomogeneousBridgeRing | {P15,P80} |
| D144 | OPERATOR_LABELS_LEGACY_TXOUT | Treat an operator-provided policy label as immutable TxOut spend_policy_id. | One legacy UNTAGGED output and bridge reservation. | P92 | PolicyHomogeneousBridgeRing | {P15,P80} |
| D145 | STANDARD_RING_INCLUDES_POLICY_TXOUT | Accept a standard transaction ring containing one bridge-policy TxOut. | One ordinary spend and one policy-tagged decoy. | P92 | PolicyHomogeneousBridgeRing | {} |
| D146 | USE_UNION_BONDS_FOR_EQUIVOCATION | Size equivocation capacity from the union of both capable quorums instead of exact per-role intersections. | Two incompatible approval sets with minimal quorum overlap. | P94 | FaultClassBondCoverage | {P37,P39} |
| D147 | OMIT_CROSS_MANIFEST_WITNESS_FROM_B_MIN | Exclude one concurrently valid old/new quorum pair from the B_min minimization domain. | Overlapping-validity manifests whose cross-pair culprit bonds are the minimum. | P94 | FaultClassBondCoverage | {P37,P89} |
| D148 | PROOF_COST_BEFORE_RESTITUTION | Deduct authenticated proof cost before satisfying fixed restitution. | Cleared risk with H below R_loss plus P_claim. | P50 | PenaltyDistributionExact | {} |
| D149 | OMIT_PROOF_COST_CAP | Pay P_claim above proof_cost_cap. | Cleared zero-loss incident with oversized authenticated P_claim. | P50 | PenaltyDistributionExact | {} |
| D152 | OMIT_RANGE_PROOF_BYTES_FROM_D_MOB | Compute D_MOB from FinalTxPrefix and pseudo outputs but omit the exact version-selected range_proof_bytes/range_proofs. | One canonical MobileCoin vNext unsigned execution with a valid one-byte-different range-proof variant. | P96 | DirectionSpecificExecutionDigestExact | {P16,P23,P88} |
| D153 | UNAUTHORIZED_POLICY_TAG_OUTPUT | Let an ordinary transaction create and register a caller-selected non-ABSENT spend_policy_id output as eligible policy-pool value. | One ordinary output creator, active bridge policy, and no authorized creation event. | P97 | PolicyTagCreationAuthorized | {P69,P70,P92} |
| D154 | EXTERNAL_TX_SUMMARY_INPUT | Put a caller-supplied TxSummary or tx_summary_commitment in IntentBindingCore and use it instead of the summary internally derived by compute_mlsag_signing_digest_vNext. | One exact MobileCoin prefix/pseudo-output set and a different caller-supplied summary. | P88 | DigestConstructionAcyclic | {P96} |
| D155 | WRONG_MOBILECOIN_NETWORK_DIGEST | Reuse D_MOB and its role artifacts after replacing the destination MobileCoin network/genesis ID with another network using the same wire format and keys. | Two MobileCoin network domains with otherwise byte-identical candidate execution material. | P96 | DirectionSpecificExecutionDigestExact | {P23} |
| D156 | DUPLICATE_ROLE_PUBLIC_KEY_SLOTS | Let two different identity slots in one WARDEN manifest use the same public key and count both toward threshold. | One WARDEN quorum that passes only when the duplicated key is counted twice. | P21 | SignerSlotsDistinct | {P19} |
| D157 | CROSS_ROLE_RECEIPT_REPLAY | Accept a valid WARDEN receipt/signature as an ACCOUNT receipt without recomputing the role-domain message. | One identity present in both role manifests and only a valid M_WARDEN signature. | P22 | RoleThresholdsIndependent | {P20} |
| D158 | OMIT_ROLE_SLOT_BINDING | Validate a role receipt by raw public-key membership without matching its immutable (identity, role, key) slot. | One key alias and two identity/role bindings where only the wrong tuple signed. | P22 | RoleThresholdsIndependent | {P19,P20,P21} |
| D159 | MLSAG_ONLY_ACCOUNTING_PROOF | Treat a valid ThresholdOwnershipEqualityProof as proof of CapacityLot identity, output classification, gross depletion, public range-proof validity, and change provenance without a ReserveAccountingProof. | One ownership-valid ring/pseudo-output and intentionally mismatched lot/output accounting. | P98 | ReserveAccountingProofSound | {P91,P93} |
| D160 | ACCOUNTING_PROOF_BACKEND_NONE | Activate MobileCoin reservation policy with accounting_backend_profile NONE and accept an opaque accounting Boolean. | Authority-ready generation with no pinned accounting verifier. | P98 | ReserveAccountingProofSound | {P71} |
| D161 | MASK_DISCLOSURE_OUTSIDE_CUSTODY_PROFILE | Under CoreCustodyKnownZ, give complete z to anyone other than the exact registered signed row-1 authority; under PrivateThresholdZ, give any individual ownership participant complete b_input, b_pseudo, or z. | One k-of-n ownership ceremony under one exact selected custody_profile with a recipient knowledge record that violates that profile. | P99 | ReserveProofThresholdCustody | {P80} |
| D162 | ACCOUNTING_WITNESS_EXCEEDS_PROFILE | Deliver the complete accounting witness to a host/prover not authorized by the selected backend trust profile. | One valid accounting witness and a manifest whose disclosure set excludes that recipient. | P98 | ReserveAccountingProofSound | {P99} |
| D163 | PRIVATE_Z_OUTPUT_WITHOUT_MASK_PROVISIONING | Under PrivateThresholdZ, mark one policy TxOut eligible although its required mask-share/MPC delivery record or private-Z range-proof witness mode is absent. Under CoreCustodyKnownZ, do not inject this defect merely because amount-blinding VSS is absent. | One otherwise valid typed BridgeReturn under an active PrivateThresholdZ owner manifest. | P100 | EligibleInputWitnessSharesReady | {P70,P71,P98} |
| D164 | PRIVATE_Z_NONLINEAR_KDF_PER_FROST_SHARE | Under PrivateThresholdZ, derive alleged blinding shares by applying MaskedAmountV2's nonlinear KDF independently to each FROST/Shamir key share. | One PrivateThresholdZ output whose blinding derives from shared-secret term aR and has no approved distributed/MPC derivation. | P100 | EligibleInputWitnessSharesReady | {P99} |
| D165 | ROTATE_WITHOUT_PROFILE_REQUIRED_RESHARE | Treat an old output as controllable after a refreshed owner roster without verified root-spend refresh/recovery in either profile, or without required mask-share refresh/recovery under PrivateThresholdZ. | One eligible old output, one selected custody_profile, and an owner-roster refresh missing a share transfer required by that profile. | P100 | EligibleInputWitnessSharesReady | {P71,P99} |
| D166 | ACCEPT_BAD_KEY_IMAGE_SHARE_DLEQ | Skip consistency/DLEQ verification for one invalid share in the pre-intent key-image state machine. | One exact zero-ID input/ring/package context and threshold pre-intent set containing one inconsistent share. | P80 | ThresholdOwnershipEqualityProofSound | {P79} |
| D167 | ACCEPT_BAD_PROFILE_TYPED_ROW1_RESPONSE | Under CoreCustodyKnownZ, accept an invalid or unsigned row-1 response from the registered authority; under PrivateThresholdZ, count one invalid z response share toward the threshold aggregate. | One valid committed pre-intent aggregate and reserve nonce round with one malformed post-D row-1 response under the selected profile. | P90 | ThresholdOwnershipEqualityValueBinding | {P80} |
| D168 | OWNERSHIP_SIGNER_SET_SWAP | Substitute a different historical-owner signer/package/ring set after the PreIntentKeyImageContext-bound aggregate, or aggregate reserve responses from a set different from that transcript. | Two threshold-capable same-shaped input sets and one committed pre-intent aggregate. | P80 | ThresholdOwnershipEqualityProofSound | {P99} |
| D169 | REUSE_RESERVE_NONCE_IN_FINAL | Reuse one participant's alpha_0 or alpha_1 nonce between ReserveInputProof and final MLSAG ceremonies. | One completed reserve proof and later final-spend ceremony for the same input. | P99 | ReserveProofThresholdCustody | {P16,P80} |
| D170 | CROSS_INPUT_RESPONSE_SHARE_SWAP | Accept a response share bound to input A in the aggregate proof for input B. | One two-input reservation with both post-D response vectors. | P80 | ThresholdOwnershipEqualityProofSound | {P90,P99} |
| D171 | IDENTITY_KEY_IMAGE_ACCEPTED | Accept the Ristretto identity element as an aggregated canonical key image. | One otherwise complete pre-intent aggregate with identity key image. | P80 | ThresholdOwnershipEqualityProofSound | {P79} |
| D172 | MALFORMED_KEY_IMAGE_ACCEPTED | Accept noncanonical or nondecompressing aggregate key-image bytes. | One otherwise complete pre-intent aggregate with malformed encoding. | P80 | ThresholdOwnershipEqualityProofSound | {P79} |
| D173 | RESERVE_PROOF_ACCEPTED_BY_SPEND_VERIFIER | Dispatch a valid reserve-domain ownership/equality proof to the ordinary RingMLSAG spend verifier as an executable signature. | One live reservation with valid reserve proof and no final MLSAG artifact. | P80 | ThresholdOwnershipEqualityProofSound | {P15,P16} |
| D174 | OWNERSHIP_RESPONSE_BEFORE_D | Permit reserve nonce commitments or ownership/z responses to be generated before final D and its reserve-challenge transcript are fixed. | One valid committed pre-intent aggregate and incomplete final destination digest. | P80 | ThresholdOwnershipEqualityProofSound | {P88,P99} |
| D175 | COMMITMENT_STUB_AS_MOBILE_TXPREFIX | Derive D_MOB from IntentBindingCore/ring-field commitments instead of the exact final wire TxPrefix consumed by the MLSAG verifier. | Two candidate prefixes differ in one full ring-member or membership-proof byte while the defective stub is unchanged. | P96 | DirectionSpecificExecutionDigestExact | {P23,P88} |
| D176 | MUTATE_RANGE_PROOF_AFTER_APPROVAL | Replace one exact range-proof byte after role receipts are issued while retaining the old reservation metadata and D-bound artifacts. | One Open liability with valid receipts over the original D_MOB and altered pre-reserve proof bytes. | P96 | DirectionSpecificExecutionDigestExact | {P16,P23} |

### 16.5 Additional STAGED selectors

| Selector ID | Unique selector name | Exact mutated clause | Minimal prestate | Target | Earliest oracle | Allowed secondary |
|---|---|---|---|---|---|---|
| D107 | OMIT_PROPAGATION_EXPOSURE | Set fault-delay headroom to zero while remote allocation remains executable. | Ethereum freeze, MobileCoin not yet paused, one remote allocation. | P72 | PropagationExposureBound | {P37} |
| D135 | GLOBAL_PREMISE_AS_RUNTIME_ORACLE | Make one chain synchronously read and mutate the remote allocation counter. | Active v1 allocations on both chains. | P37 | CorrelatedBondCapacityBound | {P73,P75} |

## 17. Mechanical contract manifest and runner protocol

### 17.1 Exact counts

The following are the last pre-profile-refreeze row counts. They are retained
only as a reconciliation baseline and are not a current frozen acceptance
assertion. The custody-profile refreeze MUST replace or explicitly reaffirm
this table before the runner is permitted to enforce exact counts:

| Manifest class | CORE | STAGED | COMPOSITION | Total |
|---|---:|---:|---:|---:|
| Committed event kinds | 28 | 0 | 0 | 28 |
| Properties | 86 | 10 | 4 | 100 |
| Scenario instances | 41 | 10 | 5 | 56 |
| One-defect selectors | 149 | 19 | 8 | 176 |

CapacityEvent also has exactly 31 top-level envelope fields; this field count is
not the event-kind count.

CORE property IDs are P01 through P63, P77 through P94, and P96 through P100.
STAGED property IDs are P64 through P73. COMPOSITION property IDs are P74
through P76 and P95.

CORE scenario IDs are S01 through S22, S37 through S50, and S52 through S56. STAGED
scenario IDs are S23 through S32. COMPOSITION scenario IDs are S33 through
S36 and S51.

CORE selector IDs are D01 through D83, D108 through D134, and D136 through
D149, plus D152 through D176. STAGED selector IDs are D84 through D100, D107,
and D135. COMPOSITION selector IDs are D101 through D106 and D150 through
D151.

### 17.2 Contract-parser self-test

After the custody-profile tables and counts are refrozen, and before syntax
checking or exploration, the runner MUST:

1. Parse this file's E, P, S, and D rows from their explicitly labeled layer
   tables.
2. Verify IDs are unique, names are unique, IDs cover the refrozen declared
   ranges, and the four refrozen count totals match section 17.1.
3. Verify every selector has exactly one Target cell matching one parsed
   Property ID. Commas, slash alternatives, Boolean conjunctions, and the word
   or are invalid in Target.
4. Verify every selector has nonempty mutation, minimal-prestate, and
   earliest-oracle cells, and every Allowed secondary entry names a parsed
   property.
5. Ask both engines to emit their machine-readable manifests and byte-compare
   their event IDs/kinds, property IDs/names/kinds, scenario IDs/instances,
   selector IDs/names/targets, allowed secondary sets, finite constants,
   constraints, capability matrix, state enums, 31 envelope fields, payload
   variants, digest dependency DAG, and chain-local event-footprint maps
   against the parsed contract.
6. Parse every generated TLA+ config rather than searching comments; verify
   baseline has all selectors FALSE and each defect config has exactly its
   named selector TRUE.
7. Structurally validate the exact state enums and transition manifest. Reject
   deprecated liability/backing members or transitions such as Backed,
   standalone Committed backing, AuthorizedPending, AcceptedPending, and
   COMMIT_ESCROW_DEPOSIT; reject a global event sequence/hash, a
   bridge/epoch/generation-scoped lease tag, or a public real ring index. This
   is an AST/manifest check with an explicit context allowlist, not a raw token
   grep: generic prose and unrelated valid enums may contain words such as
   committed.
8. Statically scan release-path actions and helpers for objective-truth
   identifiers outside the allowlist.
9. Verify the acyclic construction order: eligible ThresholdWitnessPackage
   records; candidate liability and actual zero-ID destination object;
   monotone PreIntentKeyImageContext-bound key-image/DLEQ aggregation under
   dedicated pre-intent nonces; ordered transcript commitments in
   IntentBindingCore; unsigned
   commitment, reservation ID, exact final wire execution and
   direction-specific D; role messages, all three reserve-proof digests with
   every descendant field structurally absent from ancestor closed schemas;
   a newly nonced post-D reserve commitment round, proof responses/receipts,
   OPEN,
   RESERVE, and only then execution artifacts after a prior-block reservation.
   Verify MobileCoin TxSummary is internally derived and that proof/bundle
   hashes never feed an ancestor.
10. Exit nonzero before running either engine on any disagreement.

The runner self-test is part of the acceptance evidence. A manually reported
count or a model-local manifest is not a substitute.

### 17.3 Required run order

After the custody-profile manifest is refrozen and the self-test passes:

1. Run the TLA+ semantic checker and the independent model's type/schema
   validator.
2. Run the paired-state TruthNoninterference check and required false-source
   reachability witness before broad exploration.
3. Run all refrozen named scenario instances and store the complete
   witness/rejection trace for each profile instance.
4. Run all refrozen selectors one at a time. Require the named Target as the
   earliest oracle and permit only its declared secondary set.
5. Run bounded exhaustive CORE and STAGED exploration independently. Their
   final state counts and normalized state hashes MUST agree for the declared
   common projection.
6. Partition the broad state space into declared disjoint profiles. Each engine
   reports every profile count; profile counts sum exactly to the broad total.
7. Run COMPOSITION on every reachable causally closed chain-prefix cut.
   Validate any partial-order reduction by comparing it with full linear-
   extension enumeration in a smaller exhaustive configuration.
8. Emit exact tool versions, commands, wall times, peak resources, config
   constants, hashes of this contract and both model manifests, state counts,
   profile sums, scenario outcomes, selector outcomes, and any counterexample.

Any interrupted, truncated, stale-hash, pre-self-test, or partially executed
run remains NOT RUN for acceptance purposes.

## 18. Implementation-level tests required after model acceptance

Passing the bounded models is necessary but insufficient. The implementation
programme MUST separately test:

- canonical byte serialization and the acyclic zero-reservation-ID
  intent/reservation/final-wire pipeline for both destinations;
- golden MobileCoin byte vectors against
  `transaction/core/src/ring_ct/signing_digest.rs::compute_mlsag_signing_digest`
  (reviewed code anchor 05cb699f8f4cc1bc21186392545820c5b38408db):
  for every retained block-version branch and vNext, the exact actual wire
  TxPrefix, pseudo outputs, range_proof_bytes/range_proofs, internally derived
  TxSummary, returned MLSAGSigningDigest, and ExtendedMessageDigest must match;
  one-byte mutations of a full ring/member proof, reservation ID, policy/lot
  field, MobileCoin network/genesis ID, pseudo-output, and each range-proof
  form must invalidate all D-bound artifacts; an externally supplied TxSummary
  is impossible or rejected;
- independent Ethereum EIP-712 golden vectors for every domain/Execute field,
  including chain ID, escrow contract, reservation ID, nonce, and calldata;
- MobileCoin ReserveIntentTx consensus validation and typed reservation,
  source-nullifier, lease-tag, spent-tag, and ring-binding indexes;
- whole-block conflict detection independent of transaction ordering;
- historical key-image backfill completeness and activation rollback;
- immutable TxOut spend_policy_id enforcement, policy-homogeneous bridge
  rings, all-UNTAGGED standard rings, legacy grandfathering/migration, and the
  closed output-creation matrix: unauthorized/self-labelled policy outputs
  reject, while authorized capitalization, predecessor transfer, typed
  BridgeReturn, and exact same-lot change produce valid immutable lot
  provenance;
- eligible-input custody provisioning for all four policy-output creation paths:
  under both profiles, historical PedPoP/DKG root-spend commitments/deliveries,
  the pinned one-time-offset derivation, P = B + delta*G validation before nonce
  reservation, roster refresh, participant loss, backup, and recovery; under
  PrivateThresholdZ only, mask-share VSS/MPC commitments/deliveries, typed
  external returns, MaskedAmountV2 nonlinear-KDF distributed derivation, and
  the selected private-Z range-proof witness mode; an output missing a
  prerequisite of its selected profile remains ineligible;
- two-artifact ReserveInputProof correctness, non-spend-capability, nonce discipline,
  transcript domain separation, malformed proof rejection, blame behavior, and
  accounting-prover boundary, including a profile-typed kill test proving no
  ownership coordinator/individual/sub-threshold set can reconstruct the root
  or one-time spend scalar; CoreCustodyKnownZ permits complete z only at its
  exact registered signed row-1 authority, while PrivateThresholdZ also proves
  no individual/sub-threshold reconstruction of either blinding or z;
- concrete pre-intent plus two-round/two-row
  ThresholdOwnershipEqualityProof vectors for threshold row-0 knowledge of the
  offset spend witness and profile-typed row-1 knowledge of
  z = b_pseudo - b_input: exact PreIntentKeyImageContext, monotone pre-intent
  nonce/DLEQ-share/aggregate states and ordered transcript commitments;
  only after D, fresh alpha_0*G and alpha_0*Hp(P_l) ownership commitments plus
  either the Core authority's alpha_1*G and signed response or distributed
  PrivateThresholdZ row-1 commitments/shares, followed by response verification;
  row/input/signer-set linkage, abort/retry and rogue-share tests; bad or
  identity key images, response-before-D, cross-input/signer swaps,
  reserve/final nonce reuse, and reserve-proof-to-RingMLSAG replay MUST fail;
  stock single-row FROST MUST fail this boundary; a full opening/mask delivered
  outside the exact Core authority or to any individual under PrivateThresholdZ
  also MUST fail;
- the selected ReserveAccountingProof backend and activation verifier, with
  independent mutations of CapacityLot identity/provenance, token, hidden
  input/output amount relations, output class, fee, exact public range-proof
  bytes/validity result, gross depletion, and change; absent, ownership-only, wrong verifier,
  stale SGX measurement/attestation, and accounting-witness disclosure outside
  the selected backend profile MUST all fail closed;
- MLSAG commitment-difference row/pseudo-output binding, FROST gate, WARDEN,
  ACCOUNT, and Ethereum multisig cross-artifact vectors, including distinct
  RoleArtifactDigest(WARDEN)/RoleArtifactDigest(ACCOUNT)/M_GATE domains,
  duplicate identity/key rejection,
  policy-permitted cross-role key overlap with fresh role-domain signatures,
  immutable role-slot binding, and cross-role receipt replay;
- MobileCoin v2 authenticated-dictionary membership and nonmembership,
  validator checkpoint verification, and exact release-receipt proofs;
- MobileCoin tombstone plus finalized exact-action noninclusion and Ethereum
  contract nonce/epoch cancellation proofs;
- per-chain event-envelope serialization, hash chaining, causal proof
  verification, and replay;
- contract arithmetic for local allocations, valuation/haircuts, bond freeze,
  fixed loss, restitution, bounty, and insurance residual; and
- network-upgrade activation, mixed old/new nodes, reorg rollback, pruning,
  storage growth, gas/fee behavior, and failure recovery.

UTXO fragmentation, signing latency, proof-generation latency, and policy-pool
decoy availability are liveness/performance measurements and release gates,
not safety conclusions of this finite model.

## 19. Unresolved decisions

The following inputs remain unresolved and MUST be chosen, justified, and
content-addressed before a final run. This draft deliberately does not invent
values:

1. Exact finite model bounds and production WARDEN, ACCOUNT, owner, FROST, and
   Ethereum roster sizes and thresholds, including cross-manifest quorum
   intersection and expulsion headroom.
2. Per-chain, per-direction, per-generation, per-asset allocation values,
   C_loss values, propagation headroom, and the V1 reverse exposure cap.
3. Valuation/haircut sources, conservative rounding, staleness rule, update
   delay, oracle trust, and 1:1 USD launch assumption if selected.
4. Exact ReserveIntentTx and Ethereum reserveRelease encodings, storage,
   fees/gas, pruning, replacement policy, and transaction/block limits.
5. CapacityLot creation, splitting, merge/change, custody-domain provenance,
   gross-depletion rules, and reconciliation with confidential amounts.
6. The full profile-typed eligible-input and two-artifact ReserveInputProof
   protocols. For both profiles: how every authorized output resolves to a
   verifiable historical PedPoP/DKG root-spend package; how delta is derived,
   P = B + delta*G is checked before nonce reservation, and selected-set shares
   are offset without constructing x; refresh/rotation/loss/backup/recovery;
   and the separate pre-intent key-image/DLEQ and post-D two-round/two-row
   security reductions, independent nonce protocols, monotone phase
   transitions, abort/retry, and blame semantics. For CoreCustodyKnownZ: the
   exact registered signed row-1 authority, its allowed mask disclosure, and
   its transcript-bound nonce/response evidence. For PrivateThresholdZ: how
   every authorized output path, especially an external typed return,
   establishes authenticated amount/pseudo-mask shares or approved MPC
   witnesses; how MaskedAmountV2's nonlinear KDF and stock-v4 range-proof
   witness boundary are handled; and proof that no individual or sub-threshold
   set reconstructs b_input, b_pseudo, or z. Also unresolved are the launch
   selection and manifest for ZK_ACCOUNTING_CIRCUIT_V1 versus
   SGX_ATTESTED_ACCOUNTING_V1, enclave/attestation and deterministic verifier
   boundaries, and the exact accounting-witness recipients. If a prerequisite
   of the selected profile cannot be demonstrated, that profile's outputs stay
   ineligible; failure to implement optional PrivateThresholdZ does not block
   CoreCustodyKnownZ.
7. Operational custody and recovery of permanent KeyImageRingBinding openings,
   and whether losing an opening permanently strands an otherwise spendable
   input.
8. Historical key-image/tag backfill algorithm, audit root, activation rule,
   network/genesis identifier, and reorg/update behavior.
9. TxOut spend_policy_id wire format, policy registry, legacy-output
   grandfathering/migration, policy-pool decoy selection, and acceptable
   fragmentation/anonymity loss.
10. MobileCoin v2 authenticated-dictionary key spaces, root placement,
    checkpoint signer/finality trust, inclusion/nonmembership formats, and
    EVM-verifiable release receipts.
11. Exact MobileCoin tombstone/noninclusion and Ethereum nonce/active-epoch
    finality rules, including what proof permanently disables every execution
    entry point.
12. Detection, challenge, evidence, cross-chain propagation, and
    FinalizedUncleared clearance windows, plus the fairness assumption for
    eventual remote pause without a light client.
13. Payout/loss evidence for ETH_TO_MOB, contractual adjudicator and
    collectability for MOB_TO_ETH V1, and deterministic zero-loss rules.
14. Challenge-bond size, policy bounty cap, proof-cost treatment, restitution
    recipients, insurance address, and legal enforceability; culprit bonds are
    otherwise specified as 100 percent slash.
15. StaticGlobalAllocationPremiseV1 governance signers, common manifest-hash
    agreement, audit cadence, change protocol, and emergency reduction path.
16. Source-position pairing, fees, unsolicited transfers, change, batching,
    partial settlement, and refund behavior beyond the one-event/one-settlement
    abstraction.
17. Generation capitalization sources, rollover cadence, predecessor transfer,
    drain conditions, overlapping failure domains, and bond windows.
18. Role-manifest rotation across chains, precise identities expelled per role,
    fresh-DKG operational procedure, and resumption availability thresholds.
19. Source adapter manifests and finality assumptions for Ethereum and
    MobileCoin, including reorg behavior and the V1 manual/contractual trust
    boundary.

## 20. Publication rule

After all unresolved decisions required for the bounded configuration are
frozen, the reconciled contract and interface receive new content hashes.
Only a complete runner output bound to those hashes may change the status from
PROSPECTIVE / NOT RUN. Until then this document is design input and an
acceptance specification, not evidence that the bridge or MobileCoin upgrade
works.
