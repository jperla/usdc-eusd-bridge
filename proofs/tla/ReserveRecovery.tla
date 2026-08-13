------------------------------ MODULE ReserveRecovery ------------------------------
(*******************************************************************************)
(* Standalone recovery and successor-generation model for DESIGN.md section 7.1. *)
(*                                                                             *)
(* This module deliberately DOES NOT model claims, verdicts, slashing, or       *)
(* whether an incident declaration was justified. RaiseIncident is an arbitrary *)
(* environment input. Safety must hold after true, false, and repeated inputs.  *)
(*                                                                             *)
(* The model keeps four facts separate:                                         *)
(*   - operational ownership shares;                                            *)
(*   - adversarially retained historical shares;                                *)
(*   - immutable MobileCoin output metadata;                                    *)
(*   - accounting eligibility of each custody generation.                       *)
(*                                                                             *)
(* Bug injection uses one typed selector rather than independent booleans.       *)
(* A configuration therefore cannot accidentally enable zero or several bugs.   *)
(*******************************************************************************)

EXTENDS Integers, FiniteSets, TLC

CONSTANT Bug

BugKinds == {
    "NONE",
    "RESHARE_WITHOUT_THRESHOLD",
    "ERASE_SHARE_KNOWLEDGE",
    "CLEAR_HISTORICAL_EXPOSURE",
    "RESUME_BEFORE_GATE_DKG",
    "ACCEPT_OLD_GATE",
    "ROTATE_OWNER_IN_PLACE",
    "RECOVER_BEFORE_DELAY",
    "RECOVERY_DOES_NOT_CONSUME",
    "RECOVERY_EXTERNAL_RECIPIENT",
    "ACTIVATE_PARTIAL_MIGRATION",
    "COUNT_INELIGIBLE_BACKING",
    "ERASE_LEGACY_LIABILITY",
    "RESET_NULLIFIERS"
}

ASSUME Bug \in BugKinds

-------------------------------------------------------------------------------
(* A deliberately small, asymmetric instance. Symmetry would hide which old    *)
(* sharing epoch a retained threshold belongs to.                              *)

Custodians        == {"c1", "c2", "c3", "c4"}
InitialRoster     == Custodians
ReplacementRoster == {"c3", "c4"}
GateOperators     == {"g1", "g2", "g3"}
RecoveryOperators == {"r1", "r2"}
AllActors         == Custodians \cup GateOperators \cup RecoveryOperators

KOwn == 2
KGate == 2
KRecovery == 2

Modes  == {"LONG_LIVED", "RESHARE", "DELAYED", "STRAND"}
Scopes == {"GLOBAL", "SEGREGATED"}

LegacyPhases == {
    "Active", "Frozen", "GateDKG", "Ownership", "RecoveryDelay",
    "Migrating", "Ready", "Stranded", "Retired"
}
SuccessorPhases == {"Absent", "Ready", "Active"}
IncidentKinds == {
    "FALSE_1", "FALSE_2", "PARTIAL_LOSS", "CATASTROPHIC_LOSS",
    "THRESHOLD_COMPROMISE"
}

OwnerKeys  == {"K0", "KR", "KS"}
ShareEpochs == 0..1
GateEpochs  == 0..1
ShareTriples == Custodians \X OwnerKeys \X ShareEpochs

LegacyPool    == "legacy"
SuccessorPool == "successor"
Pools == {LegacyPool, SuccessorPool}

Units == {"u1", "u2"}
Old(u)   == <<LegacyPool, u, 0>>
Moved(u) == <<LegacyPool, u, 1>>
Fresh(u) == <<SuccessorPool, u, 0>>

OldOutputs   == {Old(u)   : u \in Units}
MovedOutputs == {Moved(u) : u \in Units}
FreshOutputs == {Fresh(u) : u \in Units}
AllOutputs   == OldOutputs \cup MovedOutputs \cup FreshOutputs

PoolOf(o) == o[1]
ValueOf(o) == IF o[2] = "u1" THEN 1 ELSE 2
BirthOwner(o) ==
    IF o \in OldOutputs THEN "K0"
    ELSE IF o \in MovedOutputs THEN "KR"
    ELSE "KS"
PolicyOf(o) ==
    IF o \in OldOutputs \cup MovedOutputs THEN "LEGACY_POLICY"
    ELSE "SUCCESSOR_POLICY"

InitialShares == {<<c, "K0", 0>> : c \in InitialRoster}
SharesFor(key, epoch, roster) == {<<c, key, epoch>> : c \in roster}

InitialLiabilities ==
    [p \in Pools |-> IF p = LegacyPool THEN 2 ELSE 0]
LiabilityIds == {"q1", "q2"}
IntentIds == {"intent1"}

RecoveryDelay == 1
MaxTime == 2

-------------------------------------------------------------------------------
(* Persistent state is grouped into seven records. This keeps action updates    *)
(* reviewable: every action must explicitly change or preserve each record.     *)

VARIABLES ctrl, shares, gates, outputs, recovery, accounting, audit

vars == <<ctrl, shares, gates, outputs, recovery, accounting, audit>>

ShareEventType ==
    [kind: {"reshare", "new-key"},
     oldKey: OwnerKeys,
     newKey: OwnerKeys,
     fromEpoch: ShareEpochs,
     toEpoch: ShareEpochs,
     contributors: SUBSET AllActors,
     availableSnapshot: SUBSET AllActors,
     newShares: SUBSET ShareTriples]

MigrationEventType ==
    [unit: Units,
     kind: {"OWNER", "RECOVERY"},
     old: AllOutputs,
     new: AllOutputs,
     time: 0..MaxTime,
     maturity: 0..MaxTime,
     signers: SUBSET AllActors,
     internal: BOOLEAN,
     consumedOld: BOOLEAN]

LiabilityEventType ==
    [id: LiabilityIds,
     pool: Pools,
     hadCapacity: BOOLEAN]

AuthorizationEventType ==
    [usedEpoch: GateEpochs,
     expectedEpoch: GateEpochs,
     stale: BOOLEAN]

-------------------------------------------------------------------------------
(* Derived authority and accounting predicates. None is a freely assigned      *)
(* "controllable" or "solvent" Boolean.                                       *)

RosterFor(key, epoch) ==
    IF key = "K0" /\ epoch = 0 THEN InitialRoster
    ELSE IF key = "K0" /\ epoch = 1 THEN ReplacementRoster
    ELSE IF key \in {"KR", "KS"} /\ epoch = 0 THEN ReplacementRoster
    ELSE {}

Holders(key, epoch) ==
    {c \in Custodians : <<c, key, epoch>> \in shares.issued}

CompromisedHolders(key, epoch) ==
    {c \in Custodians : <<c, key, epoch>> \in shares.compromised}

OperationalHolders(key, epoch) ==
    (Holders(key, epoch) \ ctrl.unavailable) \ CompromisedHolders(key, epoch)

CanOperate(key, epoch) ==
    Cardinality(OperationalHolders(key, epoch)) >= KOwn

OwnerEpoch(key) == IF key = "K0" THEN ctrl.currentShareEpoch ELSE 0

ThresholdKnown(known, key) ==
    \E e \in ShareEpochs :
        Cardinality({c \in Custodians : <<c, key, e>> \in known}) >= KOwn

UnsafeOutputs ==
    {o \in outputs.live : outputs.ownerKey[o] \in shares.exposed}

Controllable(o) ==
    CanOperate(outputs.ownerKey[o], OwnerEpoch(outputs.ownerKey[o]))

CandidateEligible(p) ==
    {o \in outputs.live :
        /\ PoolOf(o) = p
        /\ o \notin outputs.stranded
        /\ o \notin outputs.quarantined
        /\ o \notin UnsafeOutputs
        /\ Controllable(o)}

PoolActive(p) ==
    IF p = LegacyPool
    THEN ctrl.legacyPhase = "Active"
    ELSE ctrl.successorPhase = "Active"

ActiveEligible(p) == IF PoolActive(p) THEN CandidateEligible(p) ELSE {}

LowValueOutputs  == {o \in AllOutputs : ValueOf(o) = 1}
HighValueOutputs == {o \in AllOutputs : ValueOf(o) = 2}
BackingValue(os) ==
    Cardinality(os \cap LowValueOutputs)
      + 2 * Cardinality(os \cap HighValueOutputs)

TotalLiability ==
    accounting.liabilities[LegacyPool] + accounting.liabilities[SuccessorPool]

TotalActiveBacking ==
    BackingValue(ActiveEligible(LegacyPool))
      + BackingValue(ActiveEligible(SuccessorPool))

CorrectCapacity(p) ==
    IF ctrl.scope = "GLOBAL"
    THEN TotalActiveBacking >= TotalLiability + 1
    ELSE BackingValue(ActiveEligible(p)) >= accounting.liabilities[p] + 1

(* Deliberately wrong accounting used only by the injected bug. It treats all  *)
(* live outputs, including quarantined, stranded, unsafe, and inactive ones, as *)
(* available backing.                                                         *)
ReportedCapacity(p) ==
    IF ctrl.scope = "GLOBAL"
    THEN BackingValue(outputs.live) >= TotalLiability + 1
    ELSE BackingValue({o \in outputs.live : PoolOf(o) = p})
           >= accounting.liabilities[p] + 1

OtherPool(p) == IF p = LegacyPool THEN SuccessorPool ELSE LegacyPool

ProspectiveBacking(p) ==
    BackingValue(CandidateEligible(p))
      + BackingValue(ActiveEligible(OtherPool(p)))

ProspectiveSolvent(p) ==
    IF ctrl.scope = "GLOBAL"
    THEN ProspectiveBacking(p) >= TotalLiability
    ELSE BackingValue(CandidateEligible(p)) >= accounting.liabilities[p]

UsedLiabilityIds == {e.id : e \in audit.liabilityLog}

LoggedShares == UNION {e.newShares : e \in audit.shareLog}

ExpectedLiability(p) ==
    InitialLiabilities[p]
      + Cardinality({e \in audit.liabilityLog : e.pool = p})

LegacyLive == {o \in outputs.live : PoolOf(o) = LegacyPool}

LossSet(kind, epoch) ==
    CASE kind \in {"FALSE_1", "FALSE_2", "THRESHOLD_COMPROMISE"} -> {}
      [] kind = "PARTIAL_LOSS" -> IF epoch = 0 THEN {"c1"} ELSE {"c3"}
      [] kind = "CATASTROPHIC_LOSS" ->
           IF epoch = 0 THEN {"c1", "c2", "c3"} ELSE ReplacementRoster

CompromiseSet(kind, epoch) ==
    IF kind # "THRESHOLD_COMPROMISE" THEN {}
    ELSE IF epoch = 0 THEN {"c1", "c2"} ELSE ReplacementRoster

CompromiseTriples(kind, epoch) ==
    SharesFor("K0", epoch, CompromiseSet(kind, epoch))

-------------------------------------------------------------------------------
Init ==
    \E mode \in Modes, scope \in Scopes :
      /\ ctrl =
          [mode |-> mode,
           scope |-> scope,
           legacyPhase |-> "Active",
           successorPhase |-> "Absent",
           now |-> 0,
           raised |-> {},
           unavailable |-> {},
           currentShareEpoch |-> 0,
           currentLegacyKey |-> "K0"]
      /\ shares =
          [issued |-> InitialShares,
           compromised |-> {},
           compromiseHistory |-> {},
           exposed |-> {},
           exposureHistory |-> {}]
      /\ gates =
          [ready |-> {0},
           activeEpoch |-> 0,
           successorReady |-> FALSE]
      /\ outputs =
          [created |-> OldOutputs,
           live |-> OldOutputs,
           consumed |-> {},
           ownerKey |-> [o \in AllOutputs |-> BirthOwner(o)],
           stranded |-> {},
           quarantined |-> {}]
      /\ recovery =
          [armed |-> FALSE,
           maturity |-> 0,
           signers |-> {},
           kind |-> "NONE",
           migrated |-> {}]
      /\ accounting =
          [liabilities |-> InitialLiabilities,
           nullifiers |-> {},
           nullifierHistory |-> {}]
      /\ audit =
          [shareLog |-> {},
           migrationLog |-> {},
           liabilityLog |-> {},
           authorizationLog |-> {}]

-------------------------------------------------------------------------------
(* Incident declarations are arbitrary environment input. They do not inspect  *)
(* a verdict or objective-fault oracle, and they never reset in-flight state.   *)

RaiseIncident ==
    \E kind \in IncidentKinds \ ctrl.raised :
      /\ gates.activeEpoch = 0
      /\ (ctrl.successorPhase # "Active"
           \/ kind \in {"FALSE_1", "FALSE_2"})
      /\ LET lost == LossSet(kind, ctrl.currentShareEpoch)
             newlyCompromised ==
                 CompromiseTriples(kind, ctrl.currentShareEpoch)
             allCompromised == shares.compromised \cup newlyCompromised
             newlyExposed ==
                 IF ThresholdKnown(allCompromised, "K0") THEN {"K0"} ELSE {}
         IN
           /\ ctrl' =
               [ctrl EXCEPT
                  !.legacyPhase =
                      IF @ = "Active" THEN "Frozen" ELSE @,
                  !.raised = @ \cup {kind},
                  !.unavailable = @ \cup lost]
           /\ shares' =
               [shares EXCEPT
                  !.compromised = allCompromised,
                  !.compromiseHistory = @ \cup newlyCompromised,
                  !.exposed = @ \cup newlyExposed,
                  !.exposureHistory = @ \cup newlyExposed]
      /\ UNCHANGED <<gates, outputs, recovery, accounting, audit>>

StartGateDKG ==
    /\ ctrl.legacyPhase = "Frozen"
    /\ ctrl' = [ctrl EXCEPT !.legacyPhase = "GateDKG"]
    /\ UNCHANGED <<shares, gates, outputs, recovery, accounting, audit>>

CompleteGateDKG ==
    /\ ctrl.legacyPhase = "GateDKG"
    /\ Cardinality(GateOperators) >= KGate
    /\ ctrl' = [ctrl EXCEPT !.legacyPhase = "Ownership"]
    /\ gates' = [gates EXCEPT !.ready = @ \cup {1}]
    /\ UNCHANGED <<shares, outputs, recovery, accounting, audit>>

(* Injected direct resume. There is intentionally no abstract "gateReady"     *)
(* guard whose truth the action may choose: the invariant reads the DKG state.  *)
BypassGateDKG ==
    /\ Bug = "RESUME_BEFORE_GATE_DKG"
    /\ ctrl.legacyPhase = "Frozen"
    /\ CanOperate(ctrl.currentLegacyKey, OwnerEpoch(ctrl.currentLegacyKey))
    /\ ProspectiveSolvent(LegacyPool)
    /\ ctrl' = [ctrl EXCEPT !.legacyPhase = "Active"]
    /\ gates' = [gates EXCEPT !.activeEpoch = 1]
    /\ UNCHANGED <<shares, outputs, recovery, accounting, audit>>

-------------------------------------------------------------------------------
(* Ownership-mode actions.                                                    *)

KeepLongLivedOwner ==
    /\ ctrl.legacyPhase = "Ownership"
    /\ ctrl.mode = "LONG_LIVED"
    /\ CanOperate("K0", ctrl.currentShareEpoch)
    /\ ctrl' = [ctrl EXCEPT !.legacyPhase = "Ready"]
    /\ UNCHANGED <<shares, gates, outputs, recovery, accounting, audit>>

ReshareStableOwner ==
    /\ ctrl.legacyPhase = "Ownership"
    /\ ctrl.mode = "RESHARE"
    /\ \E contributors \in SUBSET OperationalHolders("K0", ctrl.currentShareEpoch) :
         /\ contributors # {}
         /\ (Cardinality(contributors) >= KOwn
              \/ Bug = "RESHARE_WITHOUT_THRESHOLD")
         /\ LET newShares == SharesFor("K0", 1, ReplacementRoster)
                event ==
                  [kind |-> "reshare",
                   oldKey |-> "K0", newKey |-> "K0",
                   fromEpoch |-> ctrl.currentShareEpoch, toEpoch |-> 1,
                   contributors |-> contributors,
                   availableSnapshot |-> AllActors \ ctrl.unavailable,
                   newShares |-> newShares]
            IN
              /\ ctrl' =
                  [ctrl EXCEPT
                     !.legacyPhase = "Ready",
                     !.currentShareEpoch = 1]
              /\ shares' =
                  [shares EXCEPT
                     !.issued =
                       IF Bug = "ERASE_SHARE_KNOWLEDGE"
                       THEN newShares
                       ELSE @ \cup newShares,
                     !.exposed =
                       IF Bug = "CLEAR_HISTORICAL_EXPOSURE"
                       THEN @ \ {"K0"}
                       ELSE @]
              /\ audit' =
                  [audit EXCEPT !.shareLog = @ \cup {event}]
    /\ UNCHANGED <<gates, outputs, recovery, accounting>>

ArmDelayedRecovery ==
    /\ ctrl.legacyPhase = "Ownership"
    /\ ctrl.mode = "DELAYED"
    /\ Cardinality(RecoveryOperators) >= KRecovery
    /\ ctrl' = [ctrl EXCEPT !.legacyPhase = "RecoveryDelay"]
    /\ recovery' =
        [recovery EXCEPT
           !.armed = TRUE,
           !.maturity = ctrl.now + RecoveryDelay,
           !.signers = RecoveryOperators]
    /\ UNCHANGED <<shares, gates, outputs, accounting, audit>>

Tick ==
    /\ ctrl.legacyPhase = "RecoveryDelay"
    /\ ctrl.now < MaxTime
    /\ ctrl' = [ctrl EXCEPT !.now = @ + 1]
    /\ UNCHANGED <<shares, gates, outputs, recovery, accounting, audit>>

BeginDelayedMigration ==
    /\ ctrl.legacyPhase = "RecoveryDelay"
    /\ recovery.armed
    /\ (ctrl.now >= recovery.maturity \/ Bug = "RECOVER_BEFORE_DELAY")
    /\ LET newShares == SharesFor("KR", 0, ReplacementRoster)
           event ==
             [kind |-> "new-key",
              oldKey |-> "K0", newKey |-> "KR",
              fromEpoch |-> ctrl.currentShareEpoch, toEpoch |-> 0,
              contributors |-> recovery.signers,
              availableSnapshot |-> AllActors \ ctrl.unavailable,
              newShares |-> newShares]
       IN
         /\ ctrl' = [ctrl EXCEPT !.legacyPhase = "Migrating"]
         /\ shares' = [shares EXCEPT !.issued = @ \cup newShares]
         /\ recovery' =
             [recovery EXCEPT !.kind = "RECOVERY", !.migrated = {}]
         /\ audit' = [audit EXCEPT !.shareLog = @ \cup {event}]
    /\ UNCHANGED <<gates, outputs, accounting>>

(* If an honest old threshold survives while K0 is exposed, it can use the     *)
(* fresh gate to migrate funds normally. This restores exclusivity by moving    *)
(* outputs; same-key resharing alone never clears the historical exposure.      *)
BeginOwnerMigration ==
    /\ ctrl.legacyPhase = "Ready"
    /\ ctrl.mode \in {"LONG_LIVED", "RESHARE"}
    /\ ctrl.currentLegacyKey = "K0"
    /\ "K0" \in shares.exposed
    /\ 1 \in gates.ready
    /\ CanOperate("K0", ctrl.currentShareEpoch)
    /\ LET newShares == SharesFor("KR", 0, ReplacementRoster)
           event ==
             [kind |-> "new-key",
              oldKey |-> "K0", newKey |-> "KR",
              fromEpoch |-> ctrl.currentShareEpoch, toEpoch |-> 0,
              contributors |-> OperationalHolders("K0", ctrl.currentShareEpoch),
              availableSnapshot |-> AllActors \ ctrl.unavailable,
              newShares |-> newShares]
       IN
         /\ ctrl' = [ctrl EXCEPT !.legacyPhase = "Migrating"]
         /\ shares' = [shares EXCEPT !.issued = @ \cup newShares]
         /\ recovery' = [recovery EXCEPT !.kind = "OWNER", !.migrated = {}]
         /\ audit' = [audit EXCEPT !.shareLog = @ \cup {event}]
    /\ UNCHANGED <<gates, outputs, accounting>>

MigrateOne ==
    /\ ctrl.legacyPhase = "Migrating"
    /\ recovery.kind \in {"OWNER", "RECOVERY"}
    /\ \E u \in Units \ recovery.migrated :
         /\ Old(u) \in outputs.live
         /\ (recovery.kind = "RECOVERY"
              \/ /\ 1 \in gates.ready
                 /\ CanOperate("K0", ctrl.currentShareEpoch))
         /\ LET consume ==
                  Bug # "RECOVERY_DOES_NOT_CONSUME"
                    \/ recovery.kind # "RECOVERY"
                internal ==
                  Bug # "RECOVERY_EXTERNAL_RECIPIENT"
                    \/ recovery.kind # "RECOVERY"
                event ==
                  [unit |-> u,
                   kind |-> recovery.kind,
                   old |-> Old(u), new |-> Moved(u),
                   time |-> ctrl.now,
                   maturity |->
                     IF recovery.kind = "RECOVERY" THEN recovery.maturity
                     ELSE ctrl.now,
                   signers |->
                     IF recovery.kind = "RECOVERY"
                     THEN recovery.signers
                     ELSE OperationalHolders("K0", ctrl.currentShareEpoch),
                   internal |-> internal,
                   consumedOld |-> consume]
            IN
              /\ outputs' =
                  [outputs EXCEPT
                     !.created = @ \cup {Moved(u)},
                     !.live =
                       (IF consume THEN @ \ {Old(u)} ELSE @) \cup {Moved(u)},
                     !.consumed =
                       IF consume THEN @ \cup {Old(u)} ELSE @]
              /\ recovery' =
                  [recovery EXCEPT !.migrated = @ \cup {u}]
              /\ audit' =
                  [audit EXCEPT !.migrationLog = @ \cup {event}]
    /\ UNCHANGED <<ctrl, shares, gates, accounting>>

FinishMigration ==
    /\ ctrl.legacyPhase = "Migrating"
    /\ recovery.migrated # {}
    /\ (recovery.migrated = Units \/ Bug = "ACTIVATE_PARTIAL_MIGRATION")
    /\ ctrl' =
        [ctrl EXCEPT
           !.legacyPhase = "Ready",
           !.currentLegacyKey = "KR",
           !.currentShareEpoch = 0]
    /\ recovery' = [recovery EXCEPT !.kind = "NONE"]
    /\ UNCHANGED <<shares, gates, outputs, accounting, audit>>

DeclareStranded ==
    /\ ctrl.legacyPhase \in {"Ownership", "Ready"}
    /\ \/ ctrl.mode = "STRAND"
       \/ /\ ctrl.mode \in {"LONG_LIVED", "RESHARE"}
          /\ ~CanOperate(ctrl.currentLegacyKey,
                         OwnerEpoch(ctrl.currentLegacyKey))
    /\ ctrl' = [ctrl EXCEPT !.legacyPhase = "Stranded"]
    /\ outputs' =
        [outputs EXCEPT !.stranded = @ \cup LegacyLive]
    /\ UNCHANGED <<shares, gates, recovery, accounting, audit>>

RotateOwnerInPlace ==
    /\ Bug = "ROTATE_OWNER_IN_PLACE"
    /\ ctrl.legacyPhase = "Ownership"
    /\ \E o \in outputs.live \cap OldOutputs :
         outputs' =
           [outputs EXCEPT !.ownerKey = [@ EXCEPT ![o] = "KR"]]
    /\ UNCHANGED <<ctrl, shares, gates, recovery, accounting, audit>>

-------------------------------------------------------------------------------
(* Activation checks facts derived above. A successor is a new generation; the *)
(* legacy generation remains Stranded or Retired and its liability survives.   *)

ActivateLegacy ==
    /\ ctrl.legacyPhase = "Ready"
    /\ 1 \in gates.ready
    /\ CanOperate(ctrl.currentLegacyKey, OwnerEpoch(ctrl.currentLegacyKey))
    /\ ProspectiveSolvent(LegacyPool)
    /\ ctrl' = [ctrl EXCEPT !.legacyPhase = "Active"]
    /\ gates' = [gates EXCEPT !.activeEpoch = 1]
    /\ UNCHANGED <<shares, outputs, recovery, accounting, audit>>

PrepareSuccessor ==
    /\ ctrl.raised # {}
    /\ ctrl.successorPhase = "Absent"
    /\ LET newShares == SharesFor("KS", 0, ReplacementRoster)
           event ==
             [kind |-> "new-key",
              oldKey |-> "K0", newKey |-> "KS",
              fromEpoch |-> ctrl.currentShareEpoch, toEpoch |-> 0,
              contributors |-> ReplacementRoster,
              availableSnapshot |-> AllActors \ ctrl.unavailable,
              newShares |-> newShares]
       IN
         /\ ctrl' =
             [ctrl EXCEPT
                !.successorPhase = "Ready",
                !.legacyPhase =
                  IF @ = "Stranded" THEN "Stranded" ELSE "Retired"]
         /\ shares' = [shares EXCEPT !.issued = @ \cup newShares]
         /\ gates' = [gates EXCEPT !.successorReady = TRUE]
         /\ outputs' =
             [outputs EXCEPT
                !.created = @ \cup FreshOutputs,
                !.live = @ \cup FreshOutputs,
                !.quarantined = @ \cup LegacyLive]
         /\ accounting' =
             [accounting EXCEPT
                !.liabilities =
                  IF Bug = "ERASE_LEGACY_LIABILITY"
                  THEN [@ EXCEPT ![LegacyPool] = 0]
                  ELSE @,
                !.nullifiers =
                  IF Bug = "RESET_NULLIFIERS" THEN {} ELSE @]
         /\ audit' = [audit EXCEPT !.shareLog = @ \cup {event}]
    /\ UNCHANGED recovery

ActivateSuccessor ==
    /\ ctrl.successorPhase = "Ready"
    /\ gates.successorReady
    /\ CanOperate("KS", 0)
    /\ ProspectiveSolvent(SuccessorPool)
    /\ ctrl' = [ctrl EXCEPT !.successorPhase = "Active"]
    /\ UNCHANGED <<shares, gates, outputs, recovery, accounting, audit>>

-------------------------------------------------------------------------------
(* Small operational actions used to test accounting and history continuity.   *)

AcceptLiability ==
    \E p \in Pools, id \in LiabilityIds \ UsedLiabilityIds :
      /\ PoolActive(p)
      /\ (CorrectCapacity(p)
           \/ /\ Bug = "COUNT_INELIGIBLE_BACKING"
              /\ ReportedCapacity(p))
      /\ LET event ==
             [id |-> id, pool |-> p, hadCapacity |-> CorrectCapacity(p)]
         IN
           /\ accounting' =
               [accounting EXCEPT
                  !.liabilities =
                    [@ EXCEPT ![p] = @ + 1]]
           /\ audit' =
               [audit EXCEPT !.liabilityLog = @ \cup {event}]
    /\ UNCHANGED <<ctrl, shares, gates, outputs, recovery>>

ConsumeIntent ==
    \E i \in IntentIds \ accounting.nullifiers :
      /\ accounting' =
          [accounting EXCEPT
             !.nullifiers = @ \cup {i},
             !.nullifierHistory = @ \cup {i}]
      /\ UNCHANGED <<ctrl, shares, gates, outputs, recovery, audit>>

AcceptGateAuthorization ==
    /\ ctrl.legacyPhase = "Active"
    /\ ctrl.raised # {}
    /\ \E used \in gates.ready :
         /\ (used = gates.activeEpoch \/ Bug = "ACCEPT_OLD_GATE")
         /\ LET event ==
                [usedEpoch |-> used,
                 expectedEpoch |-> gates.activeEpoch,
                 stale |-> used # gates.activeEpoch]
            IN
              audit' =
                [audit EXCEPT !.authorizationLog = @ \cup {event}]
    /\ UNCHANGED <<ctrl, shares, gates, outputs, recovery, accounting>>

-------------------------------------------------------------------------------
Next ==
    \/ RaiseIncident
    \/ StartGateDKG
    \/ CompleteGateDKG
    \/ BypassGateDKG
    \/ KeepLongLivedOwner
    \/ ReshareStableOwner
    \/ ArmDelayedRecovery
    \/ Tick
    \/ BeginDelayedMigration
    \/ BeginOwnerMigration
    \/ MigrateOne
    \/ FinishMigration
    \/ DeclareStranded
    \/ RotateOwnerInPlace
    \/ ActivateLegacy
    \/ PrepareSuccessor
    \/ ActivateSuccessor
    \/ AcceptLiability
    \/ ConsumeIntent
    \/ AcceptGateAuthorization

Spec == Init /\ [][Next]_vars

-------------------------------------------------------------------------------
(* Invariants. Bug constants occur only in transition definitions, never here. *)

TypeOK ==
    /\ ctrl \in
        [mode: Modes,
         scope: Scopes,
         legacyPhase: LegacyPhases,
         successorPhase: SuccessorPhases,
         now: 0..MaxTime,
         raised: SUBSET IncidentKinds,
         unavailable: SUBSET Custodians,
         currentShareEpoch: ShareEpochs,
         currentLegacyKey: {"K0", "KR"}]
    /\ shares \in
        [issued: SUBSET ShareTriples,
         compromised: SUBSET ShareTriples,
         compromiseHistory: SUBSET ShareTriples,
         exposed: SUBSET OwnerKeys,
         exposureHistory: SUBSET OwnerKeys]
    /\ gates \in
        [ready: SUBSET GateEpochs,
         activeEpoch: GateEpochs,
         successorReady: BOOLEAN]
    /\ outputs \in
        [created: SUBSET AllOutputs,
         live: SUBSET AllOutputs,
         consumed: SUBSET AllOutputs,
         ownerKey: [AllOutputs -> OwnerKeys],
         stranded: SUBSET AllOutputs,
         quarantined: SUBSET AllOutputs]
    /\ recovery \in
        [armed: BOOLEAN,
         maturity: 0..MaxTime,
         signers: SUBSET AllActors,
         kind: {"NONE", "OWNER", "RECOVERY"},
         migrated: SUBSET Units]
    /\ accounting \in
        [liabilities: [Pools -> 0..4],
         nullifiers: SUBSET IntentIds,
         nullifierHistory: SUBSET IntentIds]
    /\ audit.shareLog \subseteq ShareEventType
    /\ audit.migrationLog \subseteq MigrationEventType
    /\ audit.liabilityLog \subseteq LiabilityEventType
    /\ audit.authorizationLog \subseteq AuthorizationEventType

OutputMetadataImmutable ==
    outputs.ownerKey = [o \in AllOutputs |-> BirthOwner(o)]

OutputVersionExclusive ==
    /\ outputs.live \cap outputs.consumed = {}
    /\ outputs.live \subseteq outputs.created
    /\ \A u \in Units :
         Cardinality(outputs.live \cap {Old(u), Moved(u)}) <= 1

ShareIssuanceAccounted ==
    shares.issued = InitialShares \cup LoggedShares

CompromiseKnowledgePreserved ==
    shares.compromiseHistory \subseteq shares.compromised

HistoricalExposurePreserved ==
    shares.exposureHistory \subseteq shares.exposed

ReshareSound ==
    \A e \in audit.shareLog :
      e.kind = "reshare" =>
        /\ Cardinality(e.contributors) >= KOwn
        /\ e.contributors
             \subseteq RosterFor(e.oldKey, e.fromEpoch)
                         \cap e.availableSnapshot
        /\ e.oldKey = e.newKey

RecoveryDelayHonored ==
    \A m \in audit.migrationLog :
      m.kind = "RECOVERY" => m.time >= m.maturity

RecoveryAuthorized ==
    \A m \in audit.migrationLog :
      m.kind = "RECOVERY" =>
        /\ m.signers \subseteq RecoveryOperators
        /\ Cardinality(m.signers) >= KRecovery

MigrationConsumesOld ==
    \A m \in audit.migrationLog :
      /\ m.consumedOld
      /\ m.old \in outputs.consumed
      /\ m.old \notin outputs.live
      /\ m.new \in outputs.live

MigrationConservative ==
    \A m \in audit.migrationLog :
      /\ m.old = Old(m.unit)
      /\ m.new = Moved(m.unit)
      /\ ValueOf(m.old) = ValueOf(m.new)
      /\ PolicyOf(m.old) = PolicyOf(m.new)
      /\ m.internal

ActiveGateReady ==
    /\ (ctrl.legacyPhase = "Active" /\ ctrl.raised # {}) =>
         /\ gates.activeEpoch = 1
         /\ 1 \in gates.ready
    /\ ctrl.successorPhase = "Active" => gates.successorReady

NoStaleAuthorization ==
    \A a \in audit.authorizationLog : ~a.stale

FreshKeyRequiresFullMigration ==
    ctrl.legacyPhase = "Active" /\ ctrl.currentLegacyKey = "KR" =>
      recovery.migrated = Units

ActiveOwnershipOperable ==
    /\ ctrl.legacyPhase = "Active" =>
         CanOperate(ctrl.currentLegacyKey, OwnerEpoch(ctrl.currentLegacyKey))
    /\ ctrl.successorPhase = "Active" => CanOperate("KS", 0)

StrandingSound ==
    ctrl.legacyPhase = "Stranded" => LegacyLive \subseteq outputs.stranded

NewLiabilitySound ==
    \A e \in audit.liabilityLog : e.hadCapacity

LiabilitiesAccounted ==
    \A p \in Pools : accounting.liabilities[p] = ExpectedLiability(p)

NullifierHistoryPreserved ==
    accounting.nullifierHistory \subseteq accounting.nullifiers

ActiveSolvency ==
    /\ ctrl.legacyPhase = "Active" =>
         IF ctrl.scope = "GLOBAL"
         THEN TotalActiveBacking >= TotalLiability
         ELSE BackingValue(ActiveEligible(LegacyPool))
                >= accounting.liabilities[LegacyPool]
    /\ ctrl.successorPhase = "Active" =>
         IF ctrl.scope = "GLOBAL"
         THEN TotalActiveBacking >= TotalLiability
         ELSE BackingValue(ActiveEligible(SuccessorPool))
                >= accounting.liabilities[SuccessorPool]

SuccessorIsolation ==
    ctrl.successorPhase = "Active" =>
      /\ gates.successorReady
      /\ FreshOutputs \subseteq outputs.created
      /\ FreshOutputs \subseteq outputs.live
      /\ ctrl.legacyPhase \in {"Stranded", "Retired"}
      /\ LegacyLive \subseteq outputs.quarantined

Safety ==
    /\ TypeOK
    /\ OutputMetadataImmutable
    /\ OutputVersionExclusive
    /\ ShareIssuanceAccounted
    /\ CompromiseKnowledgePreserved
    /\ HistoricalExposurePreserved
    /\ ReshareSound
    /\ RecoveryDelayHonored
    /\ RecoveryAuthorized
    /\ MigrationConsumesOld
    /\ MigrationConservative
    /\ ActiveGateReady
    /\ NoStaleAuthorization
    /\ FreshKeyRequiresFullMigration
    /\ ActiveOwnershipOperable
    /\ StrandingSound
    /\ NewLiabilitySound
    /\ LiabilitiesAccounted
    /\ NullifierHistoryPreserved
    /\ ActiveSolvency
    /\ SuccessorIsolation

=============================================================================
