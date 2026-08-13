----------------------------- MODULE BridgeCapacityV2 -----------------------------
(*******************************************************************************
Staged reserve-capacity and generation-lifecycle model for Bridge Escrow V2.

Normative inputs:
  * BRIDGE_V2_TEST_PLAN.md at SHA-256
    7ea7209ea086e37d4ae1f575eabcc2bde52b7e1c8405bbd0a01b25d8cd3428b8
  * BRIDGE_V2_CAPACITY_INTERFACE.md at SHA-256
    7181a297d8366cb816d440ed66eaf6aefba35573f3d5662a712b02ac5c7ea1a6

Assume/guarantee boundary:
  * the core model has already checked ordered signer slots, signatures,
    digests, nullifiers, source assertions, and claim/verdict causality;
  * this module accepts only the canonical CapacityEvent envelope below;
  * the two imported predecessor-transfer references in Init denote finalized,
    fully authorized settlements whose predecessor positions lie outside this
    bounded stage;
  * eUSD and USDC positions each have value one in an explicit fixed launch
    valuation map (one normalized capacity unit per asset unit).  No raw,
    heterogeneous amounts are silently added;
  * Tick changes only the environmental clock.  Every transition changing
    capital, inventory eligibility, pending exposure, a capacity position,
    a bond position, or a generation phase appends exactly one CapacityEvent.

Customer USDC deposits are deliberately absent from CapitalSourceKinds that
can create reserve positions.  They cannot emit CAPITALIZE_EXTERNAL_EUSD.
*******************************************************************************)

EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANT Bug, UsePOR

BugKinds == {
  "NONE",
  "RESERVE_CAP_BYPASS",
  "OMIT_PENDING_EXPOSURE",
  "UNDERCOUNT_CROSS_DIRECTION",
  "UNDERCOUNT_CROSS_GENERATION",
  "DOUBLE_COUNT_OVERLAP_BOND",
  "UNFUNDED_SUCCESSOR",
  "FUND_BEFORE_OWNER_AUTHORITY_READY",
  "INELIGIBLE_BACKING",
  "EARLY_BOND_EXIT"
}

ASSUME Bug \in BugKinds
ASSUME UsePOR \in BOOLEAN

-------------------------------------------------------------------------------
(* Finite shared schema domains.  Sentinels are explicit and type-specific.   *)

Directions == {"ETH_TO_MOB", "MOB_TO_ETH"}
NoDirection == "NO_DIRECTION"
DirectionValues == Directions \cup {NoDirection}

Assets == {"EUSD", "USDC"}
NoAsset == "NO_ASSET"
AssetValues == Assets \cup {NoAsset}

Generations == {"G0", "G1"}
NoGeneration == "NO_GENERATION"
GenerationValues == Generations \cup {NoGeneration}

GenerationPhases == {
  "Absent", "OwnerReady", "Capitalized", "Active",
  "DepositsClosed", "Drained", "Deactivated"
}
NoPhase == "NO_PHASE"
PhaseValues == GenerationPhases \cup {NoPhase}

EventKinds == {
  "OWNER_AUTHORITY_READY",
  "GATE_AUTHORITY_READY",
  "CAPITALIZE_EXTERNAL_EUSD",
  "CAPITALIZE_PREDECESSOR_TRANSFER",
  "ACTIVATE_GENERATION",
  "ADMIT_LIABILITY",
  "AUTHORIZE_PENDING_RELEASE",
  "FINALIZE_RELEASE",
  "CANCEL_PENDING_RELEASE",
  "CLOSE_GENERATION_DEPOSITS",
  "DECLARE_UNSAFE",
  "DECLARE_STRANDED",
  "DRAIN_GENERATION",
  "DEACTIVATE_GENERATION",
  "LOCK_BOND_MANIFEST",
  "REQUEST_BOND_EXIT",
  "COMPLETE_BOND_EXIT",
  "APPLY_OPERATOR_FAULT"
}

EventIds == {
  "EV_LOCK_BONDS",
  "EV_OWNER_G0", "EV_GATE_G0", "EV_CAP_G0_E", "EV_CAP_G0_U",
  "EV_ACTIVATE_G0",
  "EV_OWNER_G1", "EV_GATE_G1", "EV_CAP_G1", "EV_ACTIVATE_G1",
  "EV_ADMIT_E0", "EV_ADMIT_U0", "EV_ADMIT_E1",
  "EV_AUTH_RE0", "EV_AUTH_RU0", "EV_AUTH_RE1",
  "EV_FINAL_RE0", "EV_FINAL_RU0", "EV_FINAL_RE1",
  "EV_CANCEL_RE0", "EV_CANCEL_RU0", "EV_CANCEL_RE1",
  "EV_CLOSE_G0", "EV_CLOSE_G1",
  "EV_UNSAFE_E0", "EV_UNSAFE_U0", "EV_UNSAFE_E1", "EV_UNSAFE_E1B",
  "EV_STRANDED_E0", "EV_STRANDED_U0", "EV_STRANDED_E1",
  "EV_STRANDED_E1B",
  "EV_DRAIN_G0", "EV_DRAIN_G1",
  "EV_DEACTIVATE_G0", "EV_DEACTIVATE_G1",
  "EV_REQUEST_EXIT", "EV_COMPLETE_EXIT",
  "EV_FAULT_G0", "EV_FAULT_G1"
}

ReleaseIds == {"R_E0", "R_U0", "R_E1"}
NoRelease == "NO_RELEASE"
ReleaseValues == ReleaseIds \cup {NoRelease}

SourceKeys == {
  "SK_PRE_G0_E", "SK_PRE_G0_U", "SK_PRE_G1",
  "SK_EXTERNAL_G1", "SK_L_E0", "SK_L_U0", "SK_L_E1",
  "SK_R_E0", "SK_R_U0", "SK_R_E1", "SK_NONE"
}
NoSourceKey == "SK_NONE"

ValuePositionIds == {"VP_E0", "VP_U0", "VP_E1", "VP_E1B"}
CapacityPositionIds == {"CP_E0", "CP_U0", "CP_E1"}
FailureDomains == {"D_SHARED", "D_G0", "D_G1"}
Coalitions == {"Q_SHARED"}

Identities == {"op1", "op2"}
BondPositionIds == {"BP_OP1", "BP_OP2"}

OwnerManifestIds == {"OM_G0", "OM_G1", "NO_OWNER_MANIFEST"}
NoOwnerManifest == "NO_OWNER_MANIFEST"
GateManifestIds == {"GM_G0", "GM_G1", "NO_GATE_MANIFEST"}
NoGateManifest == "NO_GATE_MANIFEST"
RoleManifestIds == {
  "RM_ETH_G0", "RM_WARDEN_G0", "RM_ACCOUNT_G0",
  "RM_ETH_G1", "RM_WARDEN_G1", "RM_ACCOUNT_G1"
}
BondManifestIds == {"BM_SHARED", "NO_BOND_MANIFEST"}
NoBondManifest == "NO_BOND_MANIFEST"

CapitalSourceKinds == {
  "NONE", "EXTERNAL_EUSD", "AUTHORIZED_PREDECESSOR_TRANSFER"
}
NoCapitalSourceKind == "NONE"
CapitalSourceRefs == {
  "CSR_NONE", "CSR_EXTERNAL_G1", "CSR_PRE_G0_E", "CSR_PRE_G0_U",
  "CSR_PRE_G1"
}
NoCapitalSourceRef == "CSR_NONE"

MaxTime == 3
Times == 0..MaxTime
Amounts == 0..4

CapacityEventType ==
  [event_id: EventIds,
   kind: EventKinds,
   logical_time: Times,
   generation: GenerationValues,
   direction: DirectionValues,
   asset: AssetValues,
   amount: Amounts,
   release_id: ReleaseValues,
   source_key: SourceKeys,
   value_position_ids: SUBSET ValuePositionIds,
   capacity_position_ids: SUBSET CapacityPositionIds,
   failure_domains: SUBSET FailureDomains,
   approval_quorum: SUBSET Identities,
   owner_manifest: OwnerManifestIds,
   gate_manifest: GateManifestIds,
   role_manifests: SUBSET RoleManifestIds,
   bond_manifest: BondManifestIds,
   capital_source_kind: CapitalSourceKinds,
   capital_source_ref: CapitalSourceRefs,
   phase_before: PhaseValues,
   phase_after: PhaseValues]

CapacityEventFields == {
  "event_id", "kind", "logical_time", "generation", "direction", "asset",
  "amount", "release_id", "source_key", "value_position_ids",
  "capacity_position_ids", "failure_domains", "approval_quorum",
  "owner_manifest", "gate_manifest", "role_manifests", "bond_manifest",
  "capital_source_kind", "capital_source_ref", "phase_before", "phase_after"
}

CapacityEventTypeOK(e) ==
  /\ DOMAIN e = CapacityEventFields
  /\ e.event_id \in EventIds
  /\ e.kind \in EventKinds
  /\ e.logical_time \in Times
  /\ e.generation \in GenerationValues
  /\ e.direction \in DirectionValues
  /\ e.asset \in AssetValues
  /\ e.amount \in Amounts
  /\ e.release_id \in ReleaseValues
  /\ e.source_key \in SourceKeys
  /\ e.value_position_ids \subseteq ValuePositionIds
  /\ e.capacity_position_ids \subseteq CapacityPositionIds
  /\ e.failure_domains \subseteq FailureDomains
  /\ e.approval_quorum \subseteq Identities
  /\ e.owner_manifest \in OwnerManifestIds
  /\ e.gate_manifest \in GateManifestIds
  /\ e.role_manifests \subseteq RoleManifestIds
  /\ e.bond_manifest \in BondManifestIds
  /\ e.capital_source_kind \in CapitalSourceKinds
  /\ e.capital_source_ref \in CapitalSourceRefs
  /\ e.phase_before \in PhaseValues
  /\ e.phase_after \in PhaseValues

MkEvent(id, kind, time, generation, direction, asset, amount, release,
        sourceKey, valuePositions, capacityPositions, domains, quorum,
        ownerManifest, gateManifest, roleManifests, bondManifest,
        capitalSourceKind, capitalSourceRef, phaseBefore, phaseAfter) ==
  [event_id |-> id,
   kind |-> kind,
   logical_time |-> time,
   generation |-> generation,
   direction |-> direction,
   asset |-> asset,
   amount |-> amount,
   release_id |-> release,
   source_key |-> sourceKey,
   value_position_ids |-> valuePositions,
   capacity_position_ids |-> capacityPositions,
   failure_domains |-> domains,
   approval_quorum |-> quorum,
   owner_manifest |-> ownerManifest,
   gate_manifest |-> gateManifest,
   role_manifests |-> roleManifests,
   bond_manifest |-> bondManifest,
   capital_source_kind |-> capitalSourceKind,
   capital_source_ref |-> capitalSourceRef,
   phase_before |-> phaseBefore,
   phase_after |-> phaseAfter]

-------------------------------------------------------------------------------
(* Immutable registered metadata.                                            *)

ExpectedOwnerManifest(g) == IF g = "G0" THEN "OM_G0" ELSE "OM_G1"
ExpectedGateManifest(g) == IF g = "G0" THEN "GM_G0" ELSE "GM_G1"
ExpectedRoleManifests(g) ==
  IF g = "G0"
  THEN {"RM_ETH_G0", "RM_WARDEN_G0", "RM_ACCOUNT_G0"}
  ELSE {"RM_ETH_G1", "RM_WARDEN_G1", "RM_ACCOUNT_G1"}
ExpectedBondManifest(g) == "BM_SHARED"
ExpectedApprovalQuorum(g) == Identities

PositionGeneration(p) ==
  IF p \in {"VP_E0", "VP_U0"} THEN "G0" ELSE "G1"

PositionAsset(p) ==
  IF p \in {"VP_E0", "VP_E1", "VP_E1B"} THEN "EUSD" ELSE "USDC"

PositionDomains(p) ==
  IF PositionGeneration(p) = "G0"
  THEN {"D_SHARED", "D_G0"}
  ELSE {"D_SHARED", "D_G1"}

CapacityGeneration(c) ==
  IF c \in {"CP_E0", "CP_U0"} THEN "G0" ELSE "G1"

CapacityDirection(c) ==
  IF c \in {"CP_E0", "CP_E1"} THEN "ETH_TO_MOB" ELSE "MOB_TO_ETH"

CapacityCoalition(c) == "Q_SHARED"

CoalitionIdentities(q) == Identities
BondPositionIdentity(b) == IF b = "BP_OP1" THEN "op1" ELSE "op2"
BondHaircuttedValue(b) == 1

(* Explicit fixed launch valuation: one unit of either stablecoin is one     *)
(* normalized capacity unit.  Position IDs, not assets or roles, deduplicate. *)
NormalizedPositionValue(p) == 1
NormalizedCapacityValue(c) == 1

CLoss(d) == IF d = "D_SHARED" THEN 3 ELSE 2
RequiredCapital(g) == 1
BondFactor == 2
LiabilityWindow == 2

Liabilities == {"L_E0", "L_U0", "L_E1"}
LiabilityGeneration(l) ==
  IF l \in {"L_E0", "L_U0"} THEN "G0" ELSE "G1"
LiabilityDirection(l) ==
  IF l \in {"L_E0", "L_E1"} THEN "ETH_TO_MOB" ELSE "MOB_TO_ETH"
LiabilityPosition(l) ==
  CASE l = "L_E0" -> "VP_E0"
    [] l = "L_U0" -> "VP_U0"
    [] OTHER -> "VP_E1"
LiabilityCapacityPosition(l) ==
  CASE l = "L_E0" -> "CP_E0"
    [] l = "L_U0" -> "CP_U0"
    [] OTHER -> "CP_E1"
LiabilityEventId(l) ==
  CASE l = "L_E0" -> "EV_ADMIT_E0"
    [] l = "L_U0" -> "EV_ADMIT_U0"
    [] OTHER -> "EV_ADMIT_E1"
LiabilitySourceKey(l) ==
  CASE l = "L_E0" -> "SK_L_E0"
    [] l = "L_U0" -> "SK_L_U0"
    [] OTHER -> "SK_L_E1"

ReleaseGeneration(r) ==
  IF r \in {"R_E0", "R_U0"} THEN "G0" ELSE "G1"
ReleaseDirection(r) ==
  IF r \in {"R_E0", "R_E1"} THEN "ETH_TO_MOB" ELSE "MOB_TO_ETH"
ReleasePosition(r) ==
  CASE r = "R_E0" -> "VP_E0"
    [] r = "R_U0" -> "VP_U0"
    [] OTHER -> "VP_E1"
ReleaseCapacityPosition(r) ==
  CASE r = "R_E0" -> "CP_E0"
    [] r = "R_U0" -> "CP_U0"
    [] OTHER -> "CP_E1"
ReleaseSourceKey(r) ==
  CASE r = "R_E0" -> "SK_R_E0"
    [] r = "R_U0" -> "SK_R_U0"
    [] OTHER -> "SK_R_E1"
AuthorizeEventId(r) ==
  CASE r = "R_E0" -> "EV_AUTH_RE0"
    [] r = "R_U0" -> "EV_AUTH_RU0"
    [] OTHER -> "EV_AUTH_RE1"
FinalizeEventId(r) ==
  CASE r = "R_E0" -> "EV_FINAL_RE0"
    [] r = "R_U0" -> "EV_FINAL_RU0"
    [] OTHER -> "EV_FINAL_RE1"
CancelEventId(r) ==
  CASE r = "R_E0" -> "EV_CANCEL_RE0"
    [] r = "R_U0" -> "EV_CANCEL_RU0"
    [] OTHER -> "EV_CANCEL_RE1"

UnsafeEventId(p) ==
  CASE p = "VP_E0" -> "EV_UNSAFE_E0"
    [] p = "VP_U0" -> "EV_UNSAFE_U0"
    [] p = "VP_E1" -> "EV_UNSAFE_E1"
    [] OTHER -> "EV_UNSAFE_E1B"
StrandedEventId(p) ==
  CASE p = "VP_E0" -> "EV_STRANDED_E0"
    [] p = "VP_U0" -> "EV_STRANDED_U0"
    [] p = "VP_E1" -> "EV_STRANDED_E1"
    [] OTHER -> "EV_STRANDED_E1B"

TransferInputs(ref) == IF ref = "CSR_PRE_G1" THEN {"VP_E0"} ELSE {}
AuthorizedPredecessorRefs == {"CSR_PRE_G0_E", "CSR_PRE_G0_U", "CSR_PRE_G1"}

-------------------------------------------------------------------------------
VARIABLES eventLog, now

vars == <<eventLog, now>>

EventSet(log) == {log[i] : i \in DOMAIN log}
CurrentEvents == EventSet(eventLog)
UsedEventIds(es) == {e.event_id : e \in es}
HasKind(es, kind) == \E e \in es : e.kind = kind
HasGenerationKind(es, g, kind) ==
  \E e \in es : e.generation = g /\ e.kind = kind

EventsBefore(i) == {eventLog[j] : j \in 1..(i - 1)}

(* Sound partial-order reduction: capacity events that are independent in    *)
(* this finite interface are explored in one canonical rank order.  Equal     *)
(* ranks retain the non-commuting alternatives (gate/capital, declarations).  *)
EventRank(e) ==
  CASE e.event_id \in {
         "EV_LOCK_BONDS", "EV_OWNER_G0", "EV_GATE_G0", "EV_CAP_G0_E",
         "EV_CAP_G0_U", "EV_ACTIVATE_G0"} -> 0
    [] e.kind = "OWNER_AUTHORITY_READY" -> 1
    [] e.kind \in {"GATE_AUTHORITY_READY", "CAPITALIZE_EXTERNAL_EUSD",
                   "CAPITALIZE_PREDECESSOR_TRANSFER"} -> 2
    [] e.kind = "ACTIVATE_GENERATION" -> 3
    [] e.kind \in {"DECLARE_UNSAFE", "DECLARE_STRANDED"} -> 4
    [] e.kind = "ADMIT_LIABILITY" -> 5
    [] e.kind = "AUTHORIZE_PENDING_RELEASE" -> 6
    [] e.kind = "APPLY_OPERATOR_FAULT" -> 7
    [] e.kind = "CLOSE_GENERATION_DEPOSITS" -> 8
    [] e.kind \in {"FINALIZE_RELEASE", "CANCEL_PENDING_RELEASE"} -> 9
    [] e.kind = "REQUEST_BOND_EXIT" -> 10
    [] e.kind = "COMPLETE_BOND_EXIT" -> 11
    [] e.kind = "DRAIN_GENERATION" -> 12
    [] OTHER -> 13

LastEventRank == EventRank(eventLog[Len(eventLog)])

ChangesI(e) ==
  e.kind \in {"CAPITALIZE_EXTERNAL_EUSD", "CAPITALIZE_PREDECESSOR_TRANSFER",
              "AUTHORIZE_PENDING_RELEASE", "FINALIZE_RELEASE",
              "CANCEL_PENDING_RELEASE", "DECLARE_UNSAFE", "DECLARE_STRANDED"}

ChangesL(e) ==
  e.kind \in {"ADMIT_LIABILITY", "AUTHORIZE_PENDING_RELEASE",
              "FINALIZE_RELEASE", "CANCEL_PENDING_RELEASE"}

ChangesB(e) == e.kind \in {"LOCK_BOND_MANIFEST", "COMPLETE_BOND_EXIT"}

ReadsBond(e) ==
  e.kind \in {"GATE_AUTHORITY_READY", "ACTIVATE_GENERATION",
              "ADMIT_LIABILITY", "AUTHORIZE_PENDING_RELEASE",
              "FINALIZE_RELEASE", "CANCEL_PENDING_RELEASE",
              "REQUEST_BOND_EXIT", "APPLY_OPERATOR_FAULT"}

ChangesPhase(e) ==
  e.kind \in {"OWNER_AUTHORITY_READY", "CAPITALIZE_EXTERNAL_EUSD",
              "CAPITALIZE_PREDECESSOR_TRANSFER", "ACTIVATE_GENERATION",
              "CLOSE_GENERATION_DEPOSITS", "DRAIN_GENERATION",
              "DEACTIVATE_GENERATION"}

SettlementTerminal(e) ==
  e.kind \in {"FINALIZE_RELEASE", "CANCEL_PENDING_RELEASE"}

Declaration(e) == e.kind \in {"DECLARE_UNSAFE", "DECLARE_STRANDED"}

(* Two adjacent events commute only when their read/write footprints cannot  *)
(* affect one another's enabledness, bytes, or projected successor.  Shared   *)
(* cap/coalition/bond/phase footprints are deliberately conservative.         *)
EventsIndependent(a, b) ==
  /\ a.event_id # b.event_id
  /\ a.value_position_ids \cap b.value_position_ids = {}
  /\ a.capacity_position_ids \cap b.capacity_position_ids = {}
  /\ (a.release_id = NoRelease \/ b.release_id = NoRelease
        \/ a.release_id # b.release_id)
  /\ ~(a.generation = b.generation /\ a.generation \in Generations
       /\ (ChangesPhase(a) \/ ChangesPhase(b)))
  /\ (~(ChangesI(a) /\ ChangesI(b)
         /\ a.failure_domains \cap b.failure_domains # {})
       \/ (Declaration(a) /\ Declaration(b))
       \/ (SettlementTerminal(a) /\ SettlementTerminal(b)))
  /\ (~(ChangesL(a) /\ ChangesL(b))
       \/ (SettlementTerminal(a) /\ SettlementTerminal(b)))
  /\ ~(ChangesB(a) /\ ReadsBond(b))
  /\ ~(ChangesB(b) /\ ReadsBond(a))

CanonicalAppendAllowed(e) ==
  /\ Len(eventLog) > 0
  /\ LET previous == eventLog[Len(eventLog)]
     IN ~UsePOR
        \/ ~EventsIndependent(previous, e)
        \/ EventRank(previous) <= EventRank(e)

OwnerAuthorityReadyFrom(es, g) ==
  \E e \in es :
    /\ e.kind = "OWNER_AUTHORITY_READY"
    /\ e.generation = g
    /\ e.owner_manifest = ExpectedOwnerManifest(g)
    /\ e.approval_quorum = ExpectedApprovalQuorum(g)

BondManifestLockedFrom(es, manifest) ==
  \E e \in es :
    /\ e.kind = "LOCK_BOND_MANIFEST"
    /\ e.bond_manifest = manifest
    /\ e.approval_quorum = Identities

GateAuthorityReadyFrom(es, g) ==
  \E e \in es :
    /\ e.kind = "GATE_AUTHORITY_READY"
    /\ e.generation = g
    /\ e.owner_manifest = ExpectedOwnerManifest(g)
    /\ e.gate_manifest = ExpectedGateManifest(g)
    /\ e.role_manifests = ExpectedRoleManifests(g)
    /\ e.bond_manifest = ExpectedBondManifest(g)

CapitalEventsFrom(es) ==
  {e \in es :
    e.kind \in {"CAPITALIZE_EXTERNAL_EUSD",
                "CAPITALIZE_PREDECESSOR_TRANSFER"}}

CreatedPositionsFrom(es) ==
  UNION {e.value_position_ids : e \in CapitalEventsFrom(es)}

TransferSpentPositionsFrom(es) ==
  UNION {TransferInputs(e.capital_source_ref) :
    e \in {x \in es : x.kind = "CAPITALIZE_PREDECESSOR_TRANSFER"}}

FinalizedReleaseIdsFrom(es) ==
  {e.release_id : e \in {x \in es : x.kind = "FINALIZE_RELEASE"}}
CanceledReleaseIdsFrom(es) ==
  {e.release_id : e \in {x \in es : x.kind = "CANCEL_PENDING_RELEASE"}}

PendingAuthEventsFrom(es) ==
  {e \in es :
    /\ e.kind = "AUTHORIZE_PENDING_RELEASE"
    /\ e.release_id \notin FinalizedReleaseIdsFrom(es)
    /\ e.release_id \notin CanceledReleaseIdsFrom(es)}

PendingReleaseIdsFrom(es) ==
  {e.release_id : e \in PendingAuthEventsFrom(es)}

ReservedPositionsFrom(es) ==
  UNION {e.value_position_ids : e \in PendingAuthEventsFrom(es)}

FinalizedSpentPositionsFrom(es) ==
  UNION {e.value_position_ids :
    e \in {x \in es : x.kind = "FINALIZE_RELEASE"}}

SpentPositionsFrom(es) ==
  TransferSpentPositionsFrom(es) \cup FinalizedSpentPositionsFrom(es)

UnsafePositionsFrom(es) ==
  UNION {e.value_position_ids :
    e \in {x \in es : x.kind = "DECLARE_UNSAFE"}}

StrandedPositionsFrom(es) ==
  UNION {e.value_position_ids :
    e \in {x \in es : x.kind = "DECLARE_STRANDED"}}

CommittedPositionsFrom(es) ==
  UNION {e.value_position_ids :
    e \in {x \in es : x.kind = "ADMIT_LIABILITY"}}

AvailablePositionsFrom(es) ==
  CreatedPositionsFrom(es)
    \ (ReservedPositionsFrom(es) \cup SpentPositionsFrom(es)
       \cup UnsafePositionsFrom(es) \cup StrandedPositionsFrom(es)
       \cup CommittedPositionsFrom(es))

LiveInventoryFrom(es, g) ==
  {p \in CreatedPositionsFrom(es) : PositionGeneration(p) = g}
    \ SpentPositionsFrom(es)

LiabilityEventsFrom(es) == {e \in es : e.kind = "ADMIT_LIABILITY"}
LiabilityBackingPositionsFrom(es) ==
  CommittedPositionsFrom(es)

OutstandingLiabilitiesFrom(es, g) ==
  {e \in LiabilityEventsFrom(es) : e.generation = g}

LiveCapacityPositionsFrom(es) ==
  (UNION {e.capacity_position_ids : e \in LiabilityEventsFrom(es)})
    \cup
  (UNION {e.capacity_position_ids : e \in PendingAuthEventsFrom(es)})

CapitalValueFrom(es, g) ==
  Cardinality({p \in CreatedPositionsFrom(es) : PositionGeneration(p) = g})

GenerationPhaseFrom(es, g) ==
  IF HasGenerationKind(es, g, "DEACTIVATE_GENERATION") THEN "Deactivated"
  ELSE IF HasGenerationKind(es, g, "DRAIN_GENERATION") THEN "Drained"
  ELSE IF HasGenerationKind(es, g, "CLOSE_GENERATION_DEPOSITS")
       THEN "DepositsClosed"
  ELSE IF HasGenerationKind(es, g, "ACTIVATE_GENERATION") THEN "Active"
  ELSE IF CapitalValueFrom(es, g) > 0 THEN "Capitalized"
  ELSE IF OwnerAuthorityReadyFrom(es, g) THEN "OwnerReady"
  ELSE "Absent"

CurrentPhase(g) == GenerationPhaseFrom(CurrentEvents, g)

PausedGenerationsFrom(es) ==
  {e.generation : e \in {x \in es : x.kind = "APPLY_OPERATOR_FAULT"}}

ExitedIdentitiesFrom(es) ==
  UNION {e.approval_quorum :
    e \in {x \in es : x.kind = "COMPLETE_BOND_EXIT"}}

LockedBondPositionsFrom(es, q) ==
  IF BondManifestLockedFrom(es, "BM_SHARED")
  THEN {b \in BondPositionIds :
          /\ BondPositionIdentity(b) \in CoalitionIdentities(q)
          /\ BondPositionIdentity(b) \notin ExitedIdentitiesFrom(es)}
  ELSE {}

ActiveBondIdentitiesFrom(es, q) ==
  {BondPositionIdentity(b) : b \in LockedBondPositionsFrom(es, q)}

ExactBondQuorumActiveFrom(es, g) ==
  /\ BondManifestLockedFrom(es, ExpectedBondManifest(g))
  /\ ExpectedApprovalQuorum(g) \subseteq
       ActiveBondIdentitiesFrom(es, "Q_SHARED")

B(q, es) == Cardinality(LockedBondPositionsFrom(es, q))

L(q, es) ==
  Cardinality({c \in LiveCapacityPositionsFrom(es) : CapacityCoalition(c) = q})

LDirection(q, direction, es) ==
  Cardinality({c \in LiveCapacityPositionsFrom(es) :
    CapacityCoalition(c) = q /\ CapacityDirection(c) = direction})

LGeneration(q, g, es) ==
  Cardinality({c \in LiveCapacityPositionsFrom(es) :
    CapacityCoalition(c) = q /\ CapacityGeneration(c) = g})

ExposedPositionsFrom(es) ==
  AvailablePositionsFrom(es) \cup CommittedPositionsFrom(es)
    \cup ReservedPositionsFrom(es)

I(d, es) ==
  Cardinality({p \in ExposedPositionsFrom(es) : d \in PositionDomains(p)})

ReserveBoundsHold(es) == \A d \in FailureDomains : I(d, es) <= CLoss(d)
BondBoundsHold(es) == \A q \in Coalitions : B(q, es) >= BondFactor * L(q, es)

ExactGenerationManifests(e) ==
  /\ e.owner_manifest = ExpectedOwnerManifest(e.generation)
  /\ e.gate_manifest = ExpectedGateManifest(e.generation)
  /\ e.role_manifests = ExpectedRoleManifests(e.generation)
  /\ e.bond_manifest = ExpectedBondManifest(e.generation)
  /\ e.approval_quorum = ExpectedApprovalQuorum(e.generation)

ImportedInitialEventIds == {
  "EV_LOCK_BONDS", "EV_OWNER_G0", "EV_GATE_G0", "EV_CAP_G0_E",
  "EV_CAP_G0_U", "EV_ACTIVATE_G0"
}

MatchingPendingAuthorization(es, e) ==
  \E a \in PendingAuthEventsFrom(es) :
    /\ a.release_id = e.release_id
    /\ a.generation = e.generation
    /\ a.direction = e.direction
    /\ a.asset = e.asset
    /\ a.value_position_ids = e.value_position_ids
    /\ a.capacity_position_ids = e.capacity_position_ids
    /\ a.bond_manifest = e.bond_manifest

(* Pure precommit decision exported to the composition adapter.  The core    *)
(* proposes canonical bytes; this predicate accepts/reserves them before the  *)
(* core settlement commit.  Replaying an already committed event is not the   *)
(* security boundary.                                                         *)
CapacityAccepts(es, e) ==
  CASE e.kind = "OWNER_AUTHORITY_READY" ->
         /\ e.generation = "G1"
         /\ GenerationPhaseFrom(es, "G1") = "Absent"
         /\ e.owner_manifest = ExpectedOwnerManifest("G1")
         /\ e.approval_quorum = ExpectedApprovalQuorum("G1")
    [] e.kind = "GATE_AUTHORITY_READY" ->
         /\ e.generation = "G1"
         /\ OwnerAuthorityReadyFrom(es, "G1")
         /\ GenerationPhaseFrom(es, "G1") \in {"OwnerReady", "Capitalized"}
         /\ e.owner_manifest = ExpectedOwnerManifest("G1")
         /\ e.gate_manifest = ExpectedGateManifest("G1")
         /\ e.role_manifests = ExpectedRoleManifests("G1")
         /\ e.bond_manifest = ExpectedBondManifest("G1")
    [] e.kind \in {"CAPITALIZE_EXTERNAL_EUSD",
                   "CAPITALIZE_PREDECESSOR_TRANSFER"} ->
         /\ OwnerAuthorityReadyFrom(es, e.generation)
         /\ GenerationPhaseFrom(es, e.generation)
              \in {"OwnerReady", "Capitalized"}
         /\ e.value_position_ids \cap CreatedPositionsFrom(es) = {}
         /\ ReserveBoundsHold(es \cup {e})
         /\ IF e.kind = "CAPITALIZE_EXTERNAL_EUSD"
            THEN /\ e.asset = "EUSD"
                 /\ e.capital_source_kind = "EXTERNAL_EUSD"
                 /\ e.capital_source_ref = "CSR_EXTERNAL_G1"
            ELSE /\ e.capital_source_kind = "AUTHORIZED_PREDECESSOR_TRANSFER"
                 /\ e.capital_source_ref \in AuthorizedPredecessorRefs
                 /\ TransferInputs(e.capital_source_ref)
                      \subseteq AvailablePositionsFrom(es)
    [] e.kind = "ACTIVATE_GENERATION" ->
         /\ GenerationPhaseFrom(es, e.generation) = "Capitalized"
         /\ CapitalValueFrom(es, e.generation) >= RequiredCapital(e.generation)
         /\ OwnerAuthorityReadyFrom(es, e.generation)
         /\ GateAuthorityReadyFrom(es, e.generation)
         /\ ExactBondQuorumActiveFrom(es, e.generation)
         /\ ExactGenerationManifests(e)
         /\ ReserveBoundsHold(es)
         /\ BondBoundsHold(es)
    [] e.kind = "ADMIT_LIABILITY" ->
         /\ GenerationPhaseFrom(es, e.generation) = "Active"
         /\ e.generation \notin PausedGenerationsFrom(es)
         /\ e.value_position_ids # {}
         /\ e.value_position_ids \subseteq AvailablePositionsFrom(es)
         /\ ExactGenerationManifests(e)
         /\ ExactBondQuorumActiveFrom(es, e.generation)
         /\ BondBoundsHold(es \cup {e})
    [] e.kind = "AUTHORIZE_PENDING_RELEASE" ->
         /\ GenerationPhaseFrom(es, e.generation) = "Active"
         /\ e.generation \notin PausedGenerationsFrom(es)
         /\ e.value_position_ids # {}
         /\ e.value_position_ids \subseteq AvailablePositionsFrom(es)
         /\ ExactGenerationManifests(e)
         /\ ExactBondQuorumActiveFrom(es, e.generation)
         /\ ReserveBoundsHold(es \cup {e})
         /\ BondBoundsHold(es \cup {e})
    [] e.kind = "FINALIZE_RELEASE" -> MatchingPendingAuthorization(es, e)
    [] e.kind = "CANCEL_PENDING_RELEASE" -> FALSE
    [] e.kind = "CLOSE_GENERATION_DEPOSITS" ->
         GenerationPhaseFrom(es, e.generation) = "Active"
    [] e.kind \in {"DECLARE_UNSAFE", "DECLARE_STRANDED"} ->
         e.value_position_ids \subseteq AvailablePositionsFrom(es)
    [] e.kind = "DRAIN_GENERATION" ->
         /\ GenerationPhaseFrom(es, e.generation) = "DepositsClosed"
         /\ LiveInventoryFrom(es, e.generation) = {}
         /\ OutstandingLiabilitiesFrom(es, e.generation) = {}
         /\ ~\E a \in PendingAuthEventsFrom(es) :
              a.generation = e.generation
    [] e.kind = "DEACTIVATE_GENERATION" ->
         GenerationPhaseFrom(es, e.generation) = "Drained"
    [] e.kind = "REQUEST_BOND_EXIT" ->
         "EV_REQUEST_EXIT" \notin UsedEventIds(es)
    [] e.kind = "COMPLETE_BOND_EXIT" ->
         /\ "EV_REQUEST_EXIT" \in UsedEventIds(es)
         /\ L("Q_SHARED", es) = 0
         /\ \A a \in es : a.kind = "AUTHORIZE_PENDING_RELEASE" =>
              e.logical_time > a.logical_time + LiabilityWindow
    [] OTHER -> FALSE

-------------------------------------------------------------------------------
(* Canonical genesis/import trace.  The prior references are the explicit    *)
(* assume/guarantee boundary for positions outside this bounded stage.        *)

InitialLockEvent ==
  MkEvent("EV_LOCK_BONDS", "LOCK_BOND_MANIFEST", 0,
    NoGeneration, NoDirection, NoAsset, 0, NoRelease, NoSourceKey,
    {}, {}, {}, Identities, NoOwnerManifest, NoGateManifest, {},
    "BM_SHARED", NoCapitalSourceKind, NoCapitalSourceRef,
    NoPhase, NoPhase)

InitialOwnerEvent ==
  MkEvent("EV_OWNER_G0", "OWNER_AUTHORITY_READY", 0,
    "G0", NoDirection, NoAsset, 0, NoRelease, NoSourceKey,
    {}, {}, {}, Identities, "OM_G0", NoGateManifest, {},
    "BM_SHARED", NoCapitalSourceKind, NoCapitalSourceRef,
    "Absent", "OwnerReady")

InitialGateEvent ==
  MkEvent("EV_GATE_G0", "GATE_AUTHORITY_READY", 0,
    "G0", NoDirection, NoAsset, 0, NoRelease, NoSourceKey,
    {}, {}, {}, Identities, "OM_G0", "GM_G0", ExpectedRoleManifests("G0"),
    "BM_SHARED", NoCapitalSourceKind, NoCapitalSourceRef,
    "OwnerReady", "OwnerReady")

InitialCapitalEEvent ==
  MkEvent("EV_CAP_G0_E", "CAPITALIZE_PREDECESSOR_TRANSFER", 0,
    "G0", NoDirection, "EUSD", 1, NoRelease, "SK_PRE_G0_E",
    {"VP_E0"}, {}, PositionDomains("VP_E0"), Identities,
    "OM_G0", NoGateManifest, {}, "BM_SHARED",
    "AUTHORIZED_PREDECESSOR_TRANSFER", "CSR_PRE_G0_E",
    "OwnerReady", "Capitalized")

InitialCapitalUEvent ==
  MkEvent("EV_CAP_G0_U", "CAPITALIZE_PREDECESSOR_TRANSFER", 0,
    "G0", NoDirection, "USDC", 1, NoRelease, "SK_PRE_G0_U",
    {"VP_U0"}, {}, PositionDomains("VP_U0"), Identities,
    "OM_G0", NoGateManifest, {}, "BM_SHARED",
    "AUTHORIZED_PREDECESSOR_TRANSFER", "CSR_PRE_G0_U",
    "Capitalized", "Capitalized")

InitialActivateEvent ==
  MkEvent("EV_ACTIVATE_G0", "ACTIVATE_GENERATION", 0,
    "G0", NoDirection, NoAsset, 0, NoRelease, NoSourceKey,
    {}, {}, {}, Identities, "OM_G0", "GM_G0", ExpectedRoleManifests("G0"),
    "BM_SHARED", NoCapitalSourceKind, NoCapitalSourceRef,
    "Capitalized", "Active")

InitialEventLog ==
  <<InitialLockEvent, InitialOwnerEvent, InitialGateEvent,
    InitialCapitalEEvent, InitialCapitalUEvent, InitialActivateEvent>>

Init ==
  /\ eventLog = InitialEventLog
  /\ now = 0

-------------------------------------------------------------------------------
(* Event append primitive.                                                     *)

AppendCapacityEvent(e) ==
  /\ CapacityEventTypeOK(e)
  /\ e.event_id \notin UsedEventIds(CurrentEvents)
  /\ e.logical_time = now
  /\ CanonicalAppendAllowed(e)
  /\ eventLog' = Append(eventLog, e)
  /\ UNCHANGED now

Tick ==
  /\ now < MaxTime
  /\ now' = now + 1
  /\ UNCHANGED eventLog

CompleteOwnerAuthority ==
  /\ ~HasGenerationKind(CurrentEvents, "G1", "OWNER_AUTHORITY_READY")
  /\ CurrentPhase("G1") = "Absent"
  /\ LET e ==
       MkEvent("EV_OWNER_G1", "OWNER_AUTHORITY_READY", now,
         "G1", NoDirection, NoAsset, 0, NoRelease, NoSourceKey,
         {}, {}, {}, Identities, "OM_G1", NoGateManifest, {},
         "BM_SHARED", NoCapitalSourceKind, NoCapitalSourceRef,
         "Absent", "OwnerReady")
     IN AppendCapacityEvent(e)

CompleteGateAuthority ==
  /\ OwnerAuthorityReadyFrom(CurrentEvents, "G1")
  /\ ~HasGenerationKind(CurrentEvents, "G1", "GATE_AUTHORITY_READY")
  /\ CurrentPhase("G1") \in {"OwnerReady", "Capitalized"}
  /\ LET phase == CurrentPhase("G1")
         e ==
           MkEvent("EV_GATE_G1", "GATE_AUTHORITY_READY", now,
             "G1", NoDirection, NoAsset, 0, NoRelease, NoSourceKey,
             {}, {}, {}, Identities, "OM_G1", "GM_G1",
             ExpectedRoleManifests("G1"), "BM_SHARED",
             NoCapitalSourceKind, NoCapitalSourceRef, phase, phase)
     IN AppendCapacityEvent(e)

ExternalCapitalPositions ==
  IF Bug = "RESERVE_CAP_BYPASS" THEN {"VP_E1", "VP_E1B"}
  ELSE {"VP_E1"}

CapitalizeExternalEUSD ==
  /\ ~HasGenerationKind(CurrentEvents, "G1", "CAPITALIZE_EXTERNAL_EUSD")
  /\ ~HasGenerationKind(CurrentEvents, "G1", "CAPITALIZE_PREDECESSOR_TRANSFER")
  /\ IF Bug = "FUND_BEFORE_OWNER_AUTHORITY_READY"
     THEN CurrentPhase("G1") = "Absent"
     ELSE OwnerAuthorityReadyFrom(CurrentEvents, "G1")
          /\ CurrentPhase("G1") \in {"OwnerReady", "Capitalized"}
  /\ LET positions == ExternalCapitalPositions
         before == CurrentPhase("G1")
         e ==
           MkEvent("EV_CAP_G1", "CAPITALIZE_EXTERNAL_EUSD", now,
             "G1", NoDirection, "EUSD", Cardinality(positions),
             NoRelease, "SK_EXTERNAL_G1", positions, {},
             UNION {PositionDomains(p) : p \in positions}, Identities,
             "OM_G1", NoGateManifest, {}, "BM_SHARED", "EXTERNAL_EUSD",
             "CSR_EXTERNAL_G1", before, "Capitalized")
     IN
       /\ positions \cap CreatedPositionsFrom(CurrentEvents) = {}
       /\ (Bug = "RESERVE_CAP_BYPASS"
            \/ ReserveBoundsHold(CurrentEvents \cup {e}))
       /\ AppendCapacityEvent(e)

CapitalizePredecessorTransfer ==
  /\ OwnerAuthorityReadyFrom(CurrentEvents, "G1")
  /\ CurrentPhase("G1") \in {"OwnerReady", "Capitalized"}
  /\ ~HasGenerationKind(CurrentEvents, "G1", "CAPITALIZE_EXTERNAL_EUSD")
  /\ ~HasGenerationKind(CurrentEvents, "G1", "CAPITALIZE_PREDECESSOR_TRANSFER")
  /\ "VP_E0" \in AvailablePositionsFrom(CurrentEvents)
  /\ LET e ==
       MkEvent("EV_CAP_G1", "CAPITALIZE_PREDECESSOR_TRANSFER", now,
         "G1", NoDirection, "EUSD", 1, NoRelease, "SK_PRE_G1",
         {"VP_E1"}, {}, PositionDomains("VP_E1"), Identities,
         "OM_G1", NoGateManifest, {}, "BM_SHARED",
         "AUTHORIZED_PREDECESSOR_TRANSFER", "CSR_PRE_G1",
         CurrentPhase("G1"), "Capitalized")
     IN
       /\ ReserveBoundsHold(CurrentEvents \cup {e})
       /\ AppendCapacityEvent(e)

ActivateSuccessor ==
  /\ ~HasGenerationKind(CurrentEvents, "G1", "ACTIVATE_GENERATION")
  /\ OwnerAuthorityReadyFrom(CurrentEvents, "G1")
  /\ GateAuthorityReadyFrom(CurrentEvents, "G1")
  /\ ExactBondQuorumActiveFrom(CurrentEvents, "G1")
  /\ IF Bug = "UNFUNDED_SUCCESSOR"
     THEN CurrentPhase("G1") = "OwnerReady"
     ELSE CurrentPhase("G1") = "Capitalized"
          /\ CapitalValueFrom(CurrentEvents, "G1") >= RequiredCapital("G1")
  /\ LET e ==
       MkEvent("EV_ACTIVATE_G1", "ACTIVATE_GENERATION", now,
         "G1", NoDirection, NoAsset, 0, NoRelease, NoSourceKey,
         {}, {}, {}, Identities, "OM_G1", "GM_G1",
         ExpectedRoleManifests("G1"), "BM_SHARED",
         NoCapitalSourceKind, NoCapitalSourceRef,
         CurrentPhase("G1"), "Active")
     IN
       /\ ReserveBoundsHold(CurrentEvents)
       /\ BondBoundsHold(CurrentEvents)
       /\ AppendCapacityEvent(e)

AdmissionBondGuard(e) ==
  LET q == "Q_SHARED"
      direction == e.direction
      generation == e.generation
      prospective == CurrentEvents \cup {e}
  IN CASE Bug = "UNDERCOUNT_CROSS_DIRECTION" ->
            B(q, CurrentEvents) >= BondFactor * LDirection(q, direction, prospective)
       [] Bug = "UNDERCOUNT_CROSS_GENERATION" ->
            B(q, CurrentEvents) >= BondFactor * LGeneration(q, generation, prospective)
       [] Bug = "DOUBLE_COUNT_OVERLAP_BOND" ->
            2 * B(q, CurrentEvents) >= BondFactor * L(q, prospective)
       [] OTHER -> BondBoundsHold(prospective)

AdmitLiability ==
  \E l \in Liabilities :
    LET g == LiabilityGeneration(l)
        p == LiabilityPosition(l)
        c == LiabilityCapacityPosition(l)
        e ==
          MkEvent(LiabilityEventId(l), "ADMIT_LIABILITY", now,
            g, LiabilityDirection(l), PositionAsset(p), 1,
            NoRelease, LiabilitySourceKey(l), {p}, {c}, PositionDomains(p),
            Identities, ExpectedOwnerManifest(g), ExpectedGateManifest(g),
            ExpectedRoleManifests(g), "BM_SHARED",
            NoCapitalSourceKind, NoCapitalSourceRef, "Active", "Active")
    IN
      /\ LiabilityEventId(l) \notin UsedEventIds(CurrentEvents)
      /\ CurrentPhase(g) = "Active"
      /\ g \notin PausedGenerationsFrom(CurrentEvents)
      /\ OwnerAuthorityReadyFrom(CurrentEvents, g)
      /\ GateAuthorityReadyFrom(CurrentEvents, g)
      /\ ExactBondQuorumActiveFrom(CurrentEvents, g)
      /\ ExactGenerationManifests(e)
      /\ IF Bug = "INELIGIBLE_BACKING" /\ l = "L_E0"
         THEN p \in UnsafePositionsFrom(CurrentEvents)
         ELSE /\ p \in AvailablePositionsFrom(CurrentEvents)
              /\ p \notin LiabilityBackingPositionsFrom(CurrentEvents)
      /\ AdmissionBondGuard(e)
      /\ AppendCapacityEvent(e)

PendingBondGuard(e) ==
  IF Bug = "OMIT_PENDING_EXPOSURE"
  THEN BondBoundsHold(CurrentEvents)
  ELSE BondBoundsHold(CurrentEvents \cup {e})

AuthorizePendingRelease ==
  \E r \in ReleaseIds :
    LET g == ReleaseGeneration(r)
        p == ReleasePosition(r)
        c == ReleaseCapacityPosition(r)
        e ==
          MkEvent(AuthorizeEventId(r), "AUTHORIZE_PENDING_RELEASE", now,
            g, ReleaseDirection(r), PositionAsset(p), 1, r,
            ReleaseSourceKey(r), {p}, {c}, PositionDomains(p), Identities,
            ExpectedOwnerManifest(g), ExpectedGateManifest(g),
            ExpectedRoleManifests(g), "BM_SHARED",
            NoCapitalSourceKind, NoCapitalSourceRef, "Active", "Active")
    IN
      /\ AuthorizeEventId(r) \notin UsedEventIds(CurrentEvents)
      /\ CurrentPhase(g) = "Active"
      /\ g \notin PausedGenerationsFrom(CurrentEvents)
      /\ p \in AvailablePositionsFrom(CurrentEvents)
      /\ p \notin LiabilityBackingPositionsFrom(CurrentEvents)
      /\ OwnerAuthorityReadyFrom(CurrentEvents, g)
      /\ GateAuthorityReadyFrom(CurrentEvents, g)
      /\ ExactBondQuorumActiveFrom(CurrentEvents, g)
      /\ ExactGenerationManifests(e)
      /\ ReserveBoundsHold(CurrentEvents \cup {e})
      /\ PendingBondGuard(e)
      /\ AppendCapacityEvent(e)

PendingAuthFor(r) ==
  {e \in PendingAuthEventsFrom(CurrentEvents) : e.release_id = r}

FinalizePendingRelease ==
  \E r \in ReleaseIds :
    /\ PendingAuthFor(r) # {}
    /\ FinalizeEventId(r) \notin UsedEventIds(CurrentEvents)
    /\ LET a == CHOOSE x \in PendingAuthFor(r) : TRUE
           e ==
             MkEvent(FinalizeEventId(r), "FINALIZE_RELEASE", now,
               a.generation, a.direction, a.asset, a.amount, r,
               a.source_key, a.value_position_ids, a.capacity_position_ids,
               a.failure_domains, a.approval_quorum, a.owner_manifest,
               a.gate_manifest, a.role_manifests, a.bond_manifest,
               NoCapitalSourceKind, NoCapitalSourceRef,
               CurrentPhase(a.generation), CurrentPhase(a.generation))
       IN AppendCapacityEvent(e)

CancelPendingRelease ==
  (* The frozen 21-field envelope has no authenticated cancellation proof or *)
  (* objective non-executability commitment.  Fail closed until amended.     *)
  /\ FALSE
  /\ \E r \in ReleaseIds :
    /\ PendingAuthFor(r) # {}
    /\ CancelEventId(r) \notin UsedEventIds(CurrentEvents)
    /\ LET a == CHOOSE x \in PendingAuthFor(r) : TRUE
       IN
         /\ now > a.logical_time + LiabilityWindow
         /\ LET e ==
              MkEvent(CancelEventId(r), "CANCEL_PENDING_RELEASE", now,
                a.generation, a.direction, a.asset, a.amount, r,
                a.source_key, a.value_position_ids, a.capacity_position_ids,
                a.failure_domains, a.approval_quorum, a.owner_manifest,
                a.gate_manifest, a.role_manifests, a.bond_manifest,
                NoCapitalSourceKind, NoCapitalSourceRef,
                CurrentPhase(a.generation), CurrentPhase(a.generation))
            IN AppendCapacityEvent(e)

CloseGenerationDeposits ==
  \E g \in Generations :
    /\ CurrentPhase(g) = "Active"
    /\ LET id == IF g = "G0" THEN "EV_CLOSE_G0" ELSE "EV_CLOSE_G1"
           e ==
             MkEvent(id, "CLOSE_GENERATION_DEPOSITS", now,
               g, NoDirection, NoAsset, 0, NoRelease, NoSourceKey,
               {}, {}, {}, {}, ExpectedOwnerManifest(g),
               ExpectedGateManifest(g), ExpectedRoleManifests(g),
               ExpectedBondManifest(g), NoCapitalSourceKind,
               NoCapitalSourceRef, "Active", "DepositsClosed")
       IN AppendCapacityEvent(e)

DeclareUnsafe ==
  \E p \in AvailablePositionsFrom(CurrentEvents) :
    LET g == PositionGeneration(p)
        e ==
          MkEvent(UnsafeEventId(p), "DECLARE_UNSAFE", now,
            g, NoDirection, PositionAsset(p), 1, NoRelease, NoSourceKey,
            {p}, {}, PositionDomains(p), {}, ExpectedOwnerManifest(g),
            ExpectedGateManifest(g), ExpectedRoleManifests(g),
            ExpectedBondManifest(g), NoCapitalSourceKind,
            NoCapitalSourceRef, CurrentPhase(g), CurrentPhase(g))
    IN AppendCapacityEvent(e)

DeclareStranded ==
  \E p \in AvailablePositionsFrom(CurrentEvents) :
    LET g == PositionGeneration(p)
        e ==
          MkEvent(StrandedEventId(p), "DECLARE_STRANDED", now,
            g, NoDirection, PositionAsset(p), 1, NoRelease, NoSourceKey,
            {p}, {}, PositionDomains(p), {}, ExpectedOwnerManifest(g),
            ExpectedGateManifest(g), ExpectedRoleManifests(g),
            ExpectedBondManifest(g), NoCapitalSourceKind,
            NoCapitalSourceRef, CurrentPhase(g), CurrentPhase(g))
    IN AppendCapacityEvent(e)

DrainGeneration ==
  \E g \in Generations :
    /\ CurrentPhase(g) = "DepositsClosed"
    /\ LiveInventoryFrom(CurrentEvents, g) = {}
    /\ ~\E a \in PendingAuthEventsFrom(CurrentEvents) : a.generation = g
    /\ OutstandingLiabilitiesFrom(CurrentEvents, g) = {}
    /\ LET id == IF g = "G0" THEN "EV_DRAIN_G0" ELSE "EV_DRAIN_G1"
           e ==
             MkEvent(id, "DRAIN_GENERATION", now,
               g, NoDirection, NoAsset, 0, NoRelease, NoSourceKey,
               {}, {}, {}, {}, ExpectedOwnerManifest(g),
               ExpectedGateManifest(g), ExpectedRoleManifests(g),
               ExpectedBondManifest(g), NoCapitalSourceKind,
               NoCapitalSourceRef, "DepositsClosed", "Drained")
       IN AppendCapacityEvent(e)

DeactivateGeneration ==
  \E g \in Generations :
    /\ CurrentPhase(g) = "Drained"
    /\ LET id == IF g = "G0" THEN "EV_DEACTIVATE_G0"
                 ELSE "EV_DEACTIVATE_G1"
           e ==
             MkEvent(id, "DEACTIVATE_GENERATION", now,
               g, NoDirection, NoAsset, 0, NoRelease, NoSourceKey,
               {}, {}, {}, {}, ExpectedOwnerManifest(g),
               ExpectedGateManifest(g), ExpectedRoleManifests(g),
               ExpectedBondManifest(g), NoCapitalSourceKind,
               NoCapitalSourceRef, "Drained", "Deactivated")
       IN AppendCapacityEvent(e)

RequestBondExit ==
  /\ "EV_REQUEST_EXIT" \notin UsedEventIds(CurrentEvents)
  /\ LET e ==
       MkEvent("EV_REQUEST_EXIT", "REQUEST_BOND_EXIT", now,
         NoGeneration, NoDirection, NoAsset, 0, NoRelease, NoSourceKey,
         {}, {}, {}, {"op1"}, NoOwnerManifest, NoGateManifest, {},
         "BM_SHARED", NoCapitalSourceKind, NoCapitalSourceRef,
         NoPhase, NoPhase)
     IN AppendCapacityEvent(e)

CompleteBondExit ==
  /\ "EV_REQUEST_EXIT" \in UsedEventIds(CurrentEvents)
  /\ "EV_COMPLETE_EXIT" \notin UsedEventIds(CurrentEvents)
  /\ IF Bug = "EARLY_BOND_EXIT"
     THEN PendingAuthEventsFrom(CurrentEvents) # {}
     ELSE /\ L("Q_SHARED", CurrentEvents) = 0
          /\ \A a \in CurrentEvents :
               a.kind = "AUTHORIZE_PENDING_RELEASE" =>
                 now > a.logical_time + LiabilityWindow
  /\ LET e ==
       MkEvent("EV_COMPLETE_EXIT", "COMPLETE_BOND_EXIT", now,
         NoGeneration, NoDirection, NoAsset, 0, NoRelease, NoSourceKey,
         {}, {}, {}, {"op1"}, NoOwnerManifest, NoGateManifest, {},
         "BM_SHARED", NoCapitalSourceKind, NoCapitalSourceRef,
         NoPhase, NoPhase)
     IN AppendCapacityEvent(e)

ApplyOperatorFault ==
  (* The frozen envelope cannot replay proof/verdict, exact culprits, bond    *)
  (* amounts, restitution/bounty, or epoch pause/expulsion.  Fail closed.     *)
  /\ FALSE
  /\ \E g \in Generations :
    /\ g \notin PausedGenerationsFrom(CurrentEvents)
    /\ \E a \in PendingAuthEventsFrom(CurrentEvents) : a.generation = g
    /\ LET id == IF g = "G0" THEN "EV_FAULT_G0" ELSE "EV_FAULT_G1"
           a == CHOOSE x \in PendingAuthEventsFrom(CurrentEvents) :
                  x.generation = g
           e ==
             MkEvent(id, "APPLY_OPERATOR_FAULT", now,
               g, a.direction, a.asset, a.amount, a.release_id,
               a.source_key, a.value_position_ids, a.capacity_position_ids,
               a.failure_domains, a.approval_quorum, a.owner_manifest,
               a.gate_manifest, a.role_manifests, a.bond_manifest,
               NoCapitalSourceKind, NoCapitalSourceRef,
               CurrentPhase(g), CurrentPhase(g))
       IN AppendCapacityEvent(e)

Next ==
  \/ Tick
  \/ CompleteOwnerAuthority
  \/ CompleteGateAuthority
  \/ CapitalizeExternalEUSD
  \/ CapitalizePredecessorTransfer
  \/ ActivateSuccessor
  \/ AdmitLiability
  \/ AuthorizePendingRelease
  \/ FinalizePendingRelease
  \/ CancelPendingRelease
  \/ CloseGenerationDeposits
  \/ DeclareUnsafe
  \/ DeclareStranded
  \/ DrainGeneration
  \/ DeactivateGeneration
  \/ RequestBondExit
  \/ CompleteBondExit
  \/ ApplyOperatorFault

Spec == Init /\ [][Next]_vars

(* Bounded unreduced profile used to cross-check the POR.  It fixes no       *)
(* terminal conclusion and merely caps the number of imported interface       *)
(* events; every defect config runs with UsePOR = FALSE as a second check.     *)
NoPORBoundConstraint == Len(eventLog) <= 11

-------------------------------------------------------------------------------
(* Canonical envelope and arithmetic invariants.                              *)

TypeOK ==
  /\ Len(eventLog) <= Cardinality(EventIds)
  /\ DOMAIN eventLog = 1..Len(eventLog)
  /\ \A i \in DOMAIN eventLog : CapacityEventTypeOK(eventLog[i])
  /\ now \in Times

EventIdsUnique ==
  \A i, j \in DOMAIN eventLog :
    eventLog[i].event_id = eventLog[j].event_id => i = j

EventTimesMonotonic ==
  \A i \in 2..Len(eventLog) :
    eventLog[i - 1].logical_time <= eventLog[i].logical_time

IndependentEventOrderSound ==
  \A i \in 2..Len(eventLog) :
    /\ UsePOR
    /\ EventsIndependent(eventLog[i - 1], eventLog[i])
    => EventRank(eventLog[i - 1]) <= EventRank(eventLog[i])

HomogeneousValueMetadata(e) ==
  IF e.value_position_ids = {}
  THEN /\ e.amount = 0
       /\ e.asset = NoAsset
       /\ e.failure_domains = {}
  ELSE /\ e.amount = Cardinality(e.value_position_ids)
       /\ \A p \in e.value_position_ids :
            /\ PositionGeneration(p) = e.generation
            /\ PositionAsset(p) = e.asset
       /\ e.failure_domains =
            UNION {PositionDomains(p) : p \in e.value_position_ids}

HomogeneousCapacityMetadata(e) ==
  \A c \in e.capacity_position_ids :
    /\ CapacityGeneration(c) = e.generation
    /\ CapacityDirection(c) = e.direction

CanonicalEventInterfaceSound ==
  /\ EventIdsUnique
  /\ EventTimesMonotonic
  /\ IndependentEventOrderSound
  /\ \A e \in CurrentEvents :
    /\ HomogeneousValueMetadata(e)
    /\ HomogeneousCapacityMetadata(e)
    /\ (e.kind \in {"ADMIT_LIABILITY", "AUTHORIZE_PENDING_RELEASE",
                    "FINALIZE_RELEASE", "CANCEL_PENDING_RELEASE",
                    "APPLY_OPERATOR_FAULT"}
          => e.capacity_position_ids # {})
    /\ (e.kind \notin {"ADMIT_LIABILITY", "AUTHORIZE_PENDING_RELEASE",
                       "FINALIZE_RELEASE", "CANCEL_PENDING_RELEASE",
                       "APPLY_OPERATOR_FAULT"}
          => e.capacity_position_ids = {})
    /\ (e.kind \in {"AUTHORIZE_PENDING_RELEASE", "FINALIZE_RELEASE",
                    "CANCEL_PENDING_RELEASE", "APPLY_OPERATOR_FAULT"}
          => e.release_id \in ReleaseIds)
    /\ (e.kind \notin {"AUTHORIZE_PENDING_RELEASE", "FINALIZE_RELEASE",
                       "CANCEL_PENDING_RELEASE", "APPLY_OPERATOR_FAULT"}
          => e.release_id = NoRelease)
    /\ (e.kind = "CAPITALIZE_EXTERNAL_EUSD" =>
          /\ e.asset = "EUSD"
          /\ e.capital_source_kind = "EXTERNAL_EUSD"
          /\ e.capital_source_ref = "CSR_EXTERNAL_G1")
    /\ (e.kind = "CAPITALIZE_PREDECESSOR_TRANSFER" =>
          /\ e.capital_source_kind = "AUTHORIZED_PREDECESSOR_TRANSFER"
          /\ e.capital_source_ref \in AuthorizedPredecessorRefs)
    /\ (e.kind \notin {"CAPITALIZE_EXTERNAL_EUSD",
                       "CAPITALIZE_PREDECESSOR_TRANSFER"} =>
          /\ e.capital_source_kind = NoCapitalSourceKind
          /\ e.capital_source_ref = NoCapitalSourceRef)

PrecommitAcceptanceSound ==
  \A i \in DOMAIN eventLog :
    eventLog[i].event_id \notin ImportedInitialEventIds =>
      CapacityAccepts(EventsBefore(i), eventLog[i])

PositionPartitionSound ==
  LET available == AvailablePositionsFrom(CurrentEvents)
      reserved == ReservedPositionsFrom(CurrentEvents)
      committed == CommittedPositionsFrom(CurrentEvents)
      spent == SpentPositionsFrom(CurrentEvents)
      unsafe == UnsafePositionsFrom(CurrentEvents)
      stranded == StrandedPositionsFrom(CurrentEvents)
  IN /\ available \cup reserved \cup committed \cup spent \cup unsafe
           \cup stranded =
           CreatedPositionsFrom(CurrentEvents)
     /\ available \cap reserved = {}
     /\ available \cap committed = {}
     /\ available \cap spent = {}
     /\ available \cap unsafe = {}
     /\ available \cap stranded = {}
     /\ reserved \cap spent = {}
     /\ reserved \cap committed = {}
     /\ reserved \cap unsafe = {}
     /\ reserved \cap stranded = {}
     /\ committed \cap spent = {}
     /\ committed \cap unsafe = {}
     /\ committed \cap stranded = {}
     /\ spent \cap unsafe = {}
     /\ spent \cap stranded = {}
     /\ unsafe \cap stranded = {}

ReserveExposureBound ==
  \A d \in FailureDomains : I(d, CurrentEvents) <= CLoss(d)

CorrelatedBondCapacityBound ==
  \A q \in Coalitions :
    B(q, CurrentEvents) >= BondFactor * L(q, CurrentEvents)

NoIneligibleBacking ==
  \A i \in DOMAIN eventLog :
    LET e == eventLog[i]
        before == EventsBefore(i)
    IN e.kind = "ADMIT_LIABILITY" =>
      /\ e.value_position_ids # {}
      /\ e.value_position_ids \subseteq AvailablePositionsFrom(before)
      /\ e.value_position_ids \cap UnsafePositionsFrom(before) = {}
      /\ e.value_position_ids \cap StrandedPositionsFrom(before) = {}
      /\ e.value_position_ids \cap SpentPositionsFrom(before) = {}
      /\ e.value_position_ids \subseteq CreatedPositionsFrom(before)

CapitalEventSoundAt(i) ==
  LET e == eventLog[i]
      before == EventsBefore(i)
      g == e.generation
  IN
    /\ OwnerAuthorityReadyFrom(before, g)
    /\ e.owner_manifest = ExpectedOwnerManifest(g)
    /\ e.bond_manifest = ExpectedBondManifest(g)
    /\ e.value_position_ids \cap CreatedPositionsFrom(before) = {}
    /\ e.phase_before = GenerationPhaseFrom(before, g)
    /\ e.phase_before \in {"OwnerReady", "Capitalized"}
    /\ e.phase_after = "Capitalized"
    /\ CASE e.kind = "CAPITALIZE_EXTERNAL_EUSD" ->
            /\ e.asset = "EUSD"
            /\ e.capital_source_kind = "EXTERNAL_EUSD"
            /\ e.capital_source_ref = "CSR_EXTERNAL_G1"
            /\ e.source_key = "SK_EXTERNAL_G1"
       [] e.kind = "CAPITALIZE_PREDECESSOR_TRANSFER" ->
            /\ e.capital_source_kind = "AUTHORIZED_PREDECESSOR_TRANSFER"
            /\ e.capital_source_ref \in AuthorizedPredecessorRefs
            /\ TransferInputs(e.capital_source_ref)
                 \subseteq AvailablePositionsFrom(before)
            /\ e.approval_quorum = ExpectedApprovalQuorum(g)
       [] OTHER -> FALSE

ActivationCapitalSoundAt(i) ==
  LET e == eventLog[i]
      before == EventsBefore(i)
      g == e.generation
  IN e.kind = "ACTIVATE_GENERATION" =>
    /\ CapitalValueFrom(before, g) >= RequiredCapital(g)
    /\ OwnerAuthorityReadyFrom(before, g)
    /\ GateAuthorityReadyFrom(before, g)
    /\ ExactBondQuorumActiveFrom(before, g)
    /\ ExactGenerationManifests(e)

AdmissionCapitalSoundAt(i) ==
  LET e == eventLog[i]
      before == EventsBefore(i)
      g == e.generation
  IN e.kind \in {"ADMIT_LIABILITY", "AUTHORIZE_PENDING_RELEASE"} =>
    /\ CapitalValueFrom(before, g) >= RequiredCapital(g)
    /\ GenerationPhaseFrom(before, g) = "Active"
    /\ OwnerAuthorityReadyFrom(before, g)
    /\ GateAuthorityReadyFrom(before, g)
    /\ ExactBondQuorumActiveFrom(before, g)
    /\ ExactGenerationManifests(e)

CapitalizationSound ==
  /\ \A i \in DOMAIN eventLog :
       eventLog[i].kind \in {"CAPITALIZE_EXTERNAL_EUSD",
                             "CAPITALIZE_PREDECESSOR_TRANSFER"}
         => CapitalEventSoundAt(i)
  /\ \A i \in DOMAIN eventLog : ActivationCapitalSoundAt(i)
  /\ \A i \in DOMAIN eventLog : AdmissionCapitalSoundAt(i)

PhaseSoundAt(i) ==
  LET e == eventLog[i]
      before == EventsBefore(i)
      phase == IF e.generation \in Generations
               THEN GenerationPhaseFrom(before, e.generation)
               ELSE NoPhase
  IN CASE e.kind = "OWNER_AUTHORITY_READY" ->
            /\ e.phase_before = "Absent"
            /\ e.phase_after = "OwnerReady"
            /\ phase = "Absent"
       [] e.kind = "GATE_AUTHORITY_READY" ->
            /\ OwnerAuthorityReadyFrom(before, e.generation)
            /\ phase \in {"OwnerReady", "Capitalized"}
            /\ e.phase_before = phase
            /\ e.phase_after = phase
       [] e.kind \in {"CAPITALIZE_EXTERNAL_EUSD",
                      "CAPITALIZE_PREDECESSOR_TRANSFER"} ->
            CapitalEventSoundAt(i)
       [] e.kind = "ACTIVATE_GENERATION" ->
            /\ phase = "Capitalized"
            /\ e.phase_before = "Capitalized"
            /\ e.phase_after = "Active"
            /\ OwnerAuthorityReadyFrom(before, e.generation)
            /\ GateAuthorityReadyFrom(before, e.generation)
            /\ ExactGenerationManifests(e)
       [] e.kind \in {"ADMIT_LIABILITY", "AUTHORIZE_PENDING_RELEASE"} ->
            /\ phase = "Active"
            /\ e.phase_before = "Active"
            /\ e.phase_after = "Active"
            /\ e.generation \notin PausedGenerationsFrom(before)
            /\ ExactGenerationManifests(e)
       [] e.kind \in {"FINALIZE_RELEASE", "CANCEL_PENDING_RELEASE"} ->
            /\ phase \in {"Active", "DepositsClosed"}
            /\ e.phase_before = phase
            /\ e.phase_after = phase
            /\ \E a \in PendingAuthEventsFrom(before) :
                 a.release_id = e.release_id
       [] e.kind = "CLOSE_GENERATION_DEPOSITS" ->
            /\ phase = "Active"
            /\ e.phase_before = "Active"
            /\ e.phase_after = "DepositsClosed"
       [] e.kind \in {"DECLARE_UNSAFE", "DECLARE_STRANDED",
                      "APPLY_OPERATOR_FAULT"} ->
            /\ e.phase_before = phase
            /\ e.phase_after = phase
       [] e.kind = "DRAIN_GENERATION" ->
            /\ phase = "DepositsClosed"
            /\ e.phase_before = "DepositsClosed"
            /\ e.phase_after = "Drained"
            /\ LiveInventoryFrom(before, e.generation) = {}
            /\ ~\E a \in PendingAuthEventsFrom(before) :
                 a.generation = e.generation
            /\ OutstandingLiabilitiesFrom(before, e.generation) = {}
       [] e.kind = "DEACTIVATE_GENERATION" ->
            /\ phase = "Drained"
            /\ e.phase_before = "Drained"
            /\ e.phase_after = "Deactivated"
       [] e.kind \in {"LOCK_BOND_MANIFEST", "REQUEST_BOND_EXIT",
                      "COMPLETE_BOND_EXIT"} ->
            /\ e.generation = NoGeneration
            /\ e.phase_before = NoPhase
            /\ e.phase_after = NoPhase
       [] OTHER -> FALSE

GenerationLifecycleSound ==
  /\ \A i \in DOMAIN eventLog : PhaseSoundAt(i)
  /\ \A g \in Generations :
    /\ (CurrentPhase(g) = "Active" =>
          /\ OwnerAuthorityReadyFrom(CurrentEvents, g)
          /\ GateAuthorityReadyFrom(CurrentEvents, g)
          /\ CapitalValueFrom(CurrentEvents, g) >= RequiredCapital(g))
    /\ (CurrentPhase(g) = "Deactivated" =>
          /\ HasGenerationKind(CurrentEvents, g, "DRAIN_GENERATION")
          /\ LiveInventoryFrom(CurrentEvents, g) = {}
          /\ OutstandingLiabilitiesFrom(CurrentEvents, g) = {}
          /\ ~\E a \in PendingAuthEventsFrom(CurrentEvents) :
               a.generation = g)

HistoricalBondBinding ==
  /\ \A i \in DOMAIN eventLog :
    LET e == eventLog[i]
        before == EventsBefore(i)
    IN e.kind \in {"ADMIT_LIABILITY", "AUTHORIZE_PENDING_RELEASE"} =>
      /\ e.bond_manifest = "BM_SHARED"
      /\ e.approval_quorum = Identities
      /\ BondManifestLockedFrom(before, e.bond_manifest)
      /\ e.approval_quorum \subseteq
           {BondPositionIdentity(b) : b \in LockedBondPositionsFrom(before, "Q_SHARED")}
  /\ \A a \in CurrentEvents :
    a.kind = "AUTHORIZE_PENDING_RELEASE" =>
      \A x \in CurrentEvents :
        x.kind = "COMPLETE_BOND_EXIT"
          /\ x.approval_quorum \cap a.approval_quorum # {}
        => x.logical_time > a.logical_time + LiabilityWindow
  /\ \A a \in CurrentEvents :
    a.kind = "ADMIT_LIABILITY" =>
      \A x \in CurrentEvents :
        x.kind = "COMPLETE_BOND_EXIT"
          /\ x.approval_quorum \cap a.approval_quorum # {}
        => a.capacity_position_ids \cap LiveCapacityPositionsFrom(CurrentEvents) = {}

Safety ==
  /\ TypeOK
  /\ CanonicalEventInterfaceSound
  /\ PrecommitAcceptanceSound
  /\ PositionPartitionSound
  /\ ReserveExposureBound
  /\ CorrelatedBondCapacityBound
  /\ NoIneligibleBacking
  /\ CapitalizationSound
  /\ GenerationLifecycleSound
  /\ HistoricalBondBinding

(* Reachability targets for later named scenario configurations.              *)
CorrelatedCapacityBoundaryReached ==
  /\ I("D_SHARED", CurrentEvents) = CLoss("D_SHARED")
  /\ B("Q_SHARED", CurrentEvents) = BondFactor * L("Q_SHARED", CurrentEvents)

GenerationRolloverReached == CurrentPhase("G1") = "Deactivated"

SuccessorOwnerBeforeFundingReached ==
  /\ OwnerAuthorityReadyFrom(CurrentEvents, "G1")
  /\ CapitalValueFrom(CurrentEvents, "G1") = 0

SeparateGateReadinessReached ==
  /\ GateAuthorityReadyFrom(CurrentEvents, "G1")
  /\ CapitalValueFrom(CurrentEvents, "G1") = 0
  /\ CurrentPhase("G1") = "OwnerReady"

SuccessorActiveReached == CurrentPhase("G1") = "Active"

PendingExposureDeduplicatedReached ==
  /\ PendingAuthEventsFrom(CurrentEvents) # {}
  /\ ReservedPositionsFrom(CurrentEvents) \subseteq
       ExposedPositionsFrom(CurrentEvents)
  /\ Cardinality(AvailablePositionsFrom(CurrentEvents))
       + Cardinality(ReservedPositionsFrom(CurrentEvents))
       = Cardinality(ExposedPositionsFrom(CurrentEvents))

BondExitAfterWindowReached ==
  "EV_COMPLETE_EXIT" \in UsedEventIds(CurrentEvents)

NoCustomerUSDCReserveCapital ==
  ~\E e \in CurrentEvents :
    e.kind = "CAPITALIZE_EXTERNAL_EUSD" /\ e.asset = "USDC"

=============================================================================
