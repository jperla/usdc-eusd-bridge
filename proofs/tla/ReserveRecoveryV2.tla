----------------------------- MODULE ReserveRecoveryV2 -----------------------------
(*******************************************************************************
Standalone authority-recovery model for DESIGN.md section 7.1.

Scope is deliberately bounded to one incident and one ownership/gate rotation.
RaiseIncident is an arbitrary environment input; this module does not decide
whether an incident, verdict, or slash was justified.

The model separates:
  * lost share packages from actor availability;
  * exact adversary-known share triples from actor identity;
  * composable RESHARE / RECOVERY / SUCCESSOR capabilities;
  * immutable output policy from recovery-time control state; and
  * authorization artifacts from facts merely asserted by an audit Boolean.

Bug is one typed selector.  Every bug changes real state or an authorization
artifact and must violate a named invariant.
*******************************************************************************)

EXTENDS Integers, FiniteSets, TLC

CONSTANT Bug

BugKinds == {
  "NONE",
  "RESHARE_WITHOUT_THRESHOLD",
  "RESHARE_WITH_NONHOLDER",
  "RESHARE_WITH_MIXED_EPOCH",
  "ERASE_ISSUED_SHARES",
  "ERASE_LOST_SHARES",
  "ERASE_SHARE_KNOWLEDGE",
  "COMPLETE_GATE_WITHOUT_QUORUM",
  "REUSE_OLD_GATE_KEY",
  "RESUME_BEFORE_GATE_DKG",
  "OWNER_DKG_WITHOUT_QUORUM",
  "OWNER_DKG_WRONG_ROSTER",
  "OWNER_UNBOUND_REQUEST",
  "OWNER_UNLOGGED_AUTH",
  "RETROACTIVE_RECOVERY",
  "RECOVERY_BEFORE_OWNER_DKG",
  "RECOVERY_UNLOGGED_AUTH",
  "RECOVERY_WITHOUT_QUORUM",
  "RECOVERY_UNBOUND_REQUEST",
  "RECOVER_BEFORE_DELAY",
  "RECOVERY_DOES_NOT_CONSUME",
  "RECOVERY_EXTERNAL_RECIPIENT",
  "RECOVERY_WRONG_OWNER",
  "RECOVERY_WRONG_POLICY",
  "RECOVERY_WRONG_VALUE",
  "ROTATE_OWNER_IN_PLACE",
  "ACTIVATE_PARTIAL_MIGRATION",
  "ACTIVATE_UNSAFE_KEY",
  "SUCCESSOR_WITHOUT_DKG",
  "SUCCESSOR_REUSES_GATE",
  "FUND_BEFORE_OWNER_DKG",
  "UNFUNDED_SUCCESSOR",
  "COUNT_INELIGIBLE_BACKING",
  "ERASE_LEGACY_LIABILITY",
  "RESET_RESERVATIONS",
  "RESET_NULLIFIERS",
  "ACCEPT_OLD_GATE"
}

ASSUME Bug \in BugKinds

-------------------------------------------------------------------------------
(* Small asymmetric instance.  c3/c4 can receive a fresh key even after their *)
(* old K0 package was lost.                                                    *)

Custodians        == {"c1", "c2", "c3", "c4"}
InitialRoster     == Custodians
ReplacementRoster == {"c3", "c4"}
GateOperators     == {"g1", "g2", "g3"}
RecoveryOperators == {"r1", "r2"}
AllActors         == Custodians \cup GateOperators \cup RecoveryOperators

KOwn      == 2
KGate     == 2
KRecovery == 2

FeatureKinds == {"RESHARE", "RECOVERY", "SUCCESSOR"}
Scopes       == {"GLOBAL", "SEGREGATED"}
Incidents    == {
  "FALSE",
  "PARTIAL_LOSS",
  "CATASTROPHIC_LOSS",
  "THRESHOLD_COMPROMISE",
  "MIXED_EPOCH",
  "GATE_OUTAGE",
  "RECOVERY_OUTAGE"
}

LegacyPhases == {
  "Active", "Frozen", "GateDKG", "Ownership", "RecoveryDelay",
  "Migrating", "Ready", "Stranded"
}
SuccessorPhases == {"Absent", "OwnerReady", "Funded", "Ready", "Active"}

OwnerKeys  == {"K0", "KR", "KS", "KX"}
GateKeys   == {"G0", "G1", "GS", "NO_GATE"}
ShareEpochs == 0..1
ShareTriples == Custodians \X OwnerKeys \X ShareEpochs
ShareClaims == AllActors \X OwnerKeys \X ShareEpochs

RecoveryPolicyIds == {"NONE", "RECOVERY_V1"}
RecoveryDomains == {"EUSD_ETH_BRIDGE_V1", "OTHER_DOMAIN"}

LegacyPool    == "legacy"
SuccessorPool == "successor"
ExternalPool  == "external"
Pools == {LegacyPool, SuccessorPool}

Units == {"u1", "u2"}

Old(u)         == <<LegacyPool, u, "old">>
Moved(u)       == <<LegacyPool, u, "moved">>
WrongOwner(u)  == <<LegacyPool, u, "wrong-owner">>
WrongPolicy(u) == <<LegacyPool, u, "wrong-policy">>
WrongValue(u)  == <<LegacyPool, u, "wrong-value">>
External(u)    == <<ExternalPool, u, "external">>
Fresh(u)       == <<SuccessorPool, u, "fresh">>

OldOutputs         == {Old(u)         : u \in Units}
MovedOutputs       == {Moved(u)       : u \in Units}
WrongOwnerOutputs  == {WrongOwner(u)  : u \in Units}
WrongPolicyOutputs == {WrongPolicy(u) : u \in Units}
WrongValueOutputs  == {WrongValue(u)  : u \in Units}
ExternalOutputs    == {External(u)    : u \in Units}
FreshOutputs       == {Fresh(u)       : u \in Units}
ReplacementVersions ==
  MovedOutputs \cup WrongOwnerOutputs \cup WrongPolicyOutputs
    \cup WrongValueOutputs \cup ExternalOutputs
AllOutputs == OldOutputs \cup ReplacementVersions \cup FreshOutputs

PoolOf(o) == o[1]
BaseValue(u) == IF u = "u1" THEN 1 ELSE 2
ValueOf(o) ==
  IF o \in WrongValueOutputs THEN BaseValue(o[2]) + 1 ELSE BaseValue(o[2])
PolicyOf(o) ==
  IF o \in WrongPolicyOutputs \cup ExternalOutputs THEN "OTHER_POLICY"
  ELSE IF o \in FreshOutputs THEN "SUCCESSOR_POLICY"
  ELSE "LEGACY_POLICY"
BirthOwner(o) ==
  IF o \in OldOutputs THEN "K0"
  ELSE IF o \in FreshOutputs THEN "KS"
  ELSE IF o \in WrongOwnerOutputs \cup ExternalOutputs THEN "KX"
  ELSE "KR"

SharesFor(key, epoch, roster) == {<<c, key, epoch>> : c \in roster}
InitialShares == SharesFor("K0", 0, InitialRoster)

LiabilityIds == {"q1", "q2"}
IntentIds    == {"intent1"}
RecoveryDelay == 1
MaxTime == 2

-------------------------------------------------------------------------------
VARIABLES ctrl, actors, shares, gates, outputs, recovery, accounting, audit

vars == <<ctrl, actors, shares, gates, outputs, recovery, accounting, audit>>

GateEventType ==
  [pool: Pools,
   epoch: 0..1,
   key: GateKeys,
   policy: {"LEGACY_POLICY", "SUCCESSOR_POLICY"},
   signers: SUBSET AllActors,
   availableSnapshot: SUBSET AllActors]

OwnerEventType ==
  [key: OwnerKeys,
   epoch: ShareEpochs,
   roster: SUBSET Custodians,
   signers: SUBSET AllActors,
   availableSnapshot: SUBSET AllActors,
   newShares: SUBSET ShareTriples]

ReshareEventType ==
  [key: OwnerKeys,
   fromEpoch: ShareEpochs,
   toEpoch: ShareEpochs,
   contributorShares: SUBSET ShareClaims,
   issuedSnapshot: SUBSET ShareTriples,
   lostSnapshot: SUBSET ShareTriples,
   expelledSnapshot: SUBSET Custodians,
   offlineSnapshot: SUBSET AllActors,
   newShares: SUBSET ShareTriples]

RecoveryRequestType ==
  [incident: Incidents,
   domain: RecoveryDomains,
   recoveryPolicy: RecoveryPolicyIds,
   oldOutputs: SUBSET AllOutputs,
   newOutputs: SUBSET AllOutputs,
   newOwner: OwnerKeys,
   policy: {"LEGACY_POLICY", "SUCCESSOR_POLICY", "OTHER_POLICY"},
   gateKey: GateKeys,
   ownerDkg: OwnerEventType,
   gateDkg: GateEventType,
   armedAt: 0..MaxTime,
   maturity: 0..MaxTime]

RecoveryAuthType ==
  [request: RecoveryRequestType,
   signedRequest: RecoveryRequestType,
   signers: SUBSET AllActors,
   availableSnapshot: SUBSET AllActors]

OwnerAuthType ==
  [oldOutputs: SUBSET AllOutputs,
   newOutputs: SUBSET AllOutputs,
   oldKey: OwnerKeys,
   newKey: OwnerKeys,
   shareEpoch: ShareEpochs,
   signers: SUBSET AllActors,
   availableSnapshot: SUBSET AllActors,
   gateKey: GateKeys,
   ownerDkg: OwnerEventType,
   gateDkg: GateEventType]

MigrationEventType ==
  [unit: Units,
   kind: {"OWNER", "RECOVERY"},
   old: AllOutputs,
   new: AllOutputs,
   time: 0..MaxTime,
   recoveryAuth: SUBSET RecoveryAuthType,
   ownerAuth: SUBSET OwnerAuthType,
   consumedOld: BOOLEAN]

LiabilityEventType ==
  [id: LiabilityIds,
   pool: Pools,
   eligibleValue: 0..20,
   requiredBefore: 0..20]

CapitalEventType ==
  [pool: Pools,
   suppliedOutputs: SUBSET AllOutputs,
   amount: 0..20,
   external: BOOLEAN]

AuthorizationEventType ==
  [pool: Pools,
   usedKey: GateKeys,
   expectedKey: GateKeys]

InitialGateEvent ==
  [pool |-> LegacyPool,
   epoch |-> 0,
   key |-> "G0",
   policy |-> "LEGACY_POLICY",
   signers |-> GateOperators,
   availableSnapshot |-> AllActors]

PrematureKREvent ==
  [key |-> "KR",
   epoch |-> 0,
   roster |-> ReplacementRoster,
   signers |-> ReplacementRoster,
   availableSnapshot |-> AllActors,
   newShares |-> SharesFor("KR", 0, ReplacementRoster)]

-------------------------------------------------------------------------------
(* Derived authority.  No "exposed" or "controllable" Boolean exists.          *)

RosterFor(key, epoch) ==
  IF key = "K0" /\ epoch = 0 THEN InitialRoster
  ELSE IF key = "K0" /\ epoch = 1 THEN ReplacementRoster
  ELSE IF key \in {"KR", "KS"} /\ epoch = 0 THEN ReplacementRoster
  ELSE {}

Holders(key, epoch) ==
  {c \in Custodians : <<c, key, epoch>> \in shares.issued}

ClaimHolders(claims) ==
  {a \in AllActors : \E key \in OwnerKeys, epoch \in ShareEpochs :
    <<a, key, epoch>> \in claims}

UsableHolders(key, epoch) ==
  {c \in Holders(key, epoch) :
    /\ <<c, key, epoch>> \notin shares.lost
    /\ c \notin shares.expelled
    /\ c \notin actors.offline}

CanOperate(key, epoch) == Cardinality(UsableHolders(key, epoch)) >= KOwn

DurableHolders(key, epoch) ==
  {c \in Holders(key, epoch) :
    /\ <<c, key, epoch>> \notin shares.lost
    /\ c \notin shares.expelled}

CanEventuallyOperate(key, epoch) ==
  Cardinality(DurableHolders(key, epoch)) >= KOwn

AdversaryCan(key) ==
  \E e \in ShareEpochs :
    Cardinality(
      {c \in Custodians : <<c, key, e>> \in shares.adversaryKnown}
    ) >= KOwn

OwnerEpoch(key) == IF key = "K0" THEN ctrl.currentShareEpoch ELSE 0

UnsafeOutputs ==
  {o \in outputs.live : AdversaryCan(outputs.ownerKey[o])}

AvailableActors == (AllActors \ actors.offline) \ shares.expelled
AvailableGateOperators == GateOperators \cap AvailableActors
AvailableRecoveryOperators == RecoveryOperators \cap AvailableActors
AvailableReplacement == ReplacementRoster \cap AvailableActors

ExpectedGateKey(pool, epoch) ==
  IF pool = LegacyPool /\ epoch = 0 THEN "G0"
  ELSE IF pool = LegacyPool /\ epoch = 1 THEN "G1"
  ELSE "GS"

ExpectedGatePolicy(pool) ==
  IF pool = LegacyPool THEN "LEGACY_POLICY" ELSE "SUCCESSOR_POLICY"

GateRecorded(pool, epoch) ==
  \E e \in audit.gateLog : e.pool = pool /\ e.epoch = epoch

OwnerRecorded(key) == \E e \in audit.ownerLog : e.key = key

RecoveryBoundOnAllOld ==
  \A o \in OldOutputs : outputs.recoveryBranch[o] = "RECOVERY_V1"

ViableRecoveryCapability(o) ==
  /\ "RECOVERY" \in ctrl.features
  /\ outputs.recoveryBranch[o] = "RECOVERY_V1"
  /\ Cardinality(RecoveryOperators) >= KRecovery
  /\ Cardinality(ReplacementRoster \ shares.expelled) >= KOwn
  /\ Cardinality(GateOperators) >= KGate

LegacyLive == {o \in outputs.live : PoolOf(o) = LegacyPool}

DerivedStrandedOutputs ==
  {o \in LegacyLive :
    /\ ctrl.incident # "NONE"
    /\ o \notin UnsafeOutputs
    /\ ~CanEventuallyOperate(outputs.ownerKey[o], OwnerEpoch(outputs.ownerKey[o]))
    /\ ~ViableRecoveryCapability(o)}

Controllable(o) ==
  CanOperate(outputs.ownerKey[o], OwnerEpoch(outputs.ownerKey[o]))

CandidateEligible(p) ==
  {o \in outputs.live :
    /\ PoolOf(o) = p
    /\ o \notin outputs.quarantined
    /\ o \notin DerivedStrandedOutputs
    /\ o \notin UnsafeOutputs
    /\ Controllable(o)}

PoolActive(p) ==
  IF p = LegacyPool
  THEN ctrl.legacyPhase = "Active"
  ELSE ctrl.successorPhase = "Active"

ActiveEligible(p) == IF PoolActive(p) THEN CandidateEligible(p) ELSE {}

LowValueOutputs  == {o \in AllOutputs : ValueOf(o) = 1}
HighValueOutputs == {o \in AllOutputs : ValueOf(o) = 2}
HigherValueOutputs == {o \in AllOutputs : ValueOf(o) = 3}

BackingValue(os) ==
  Cardinality(os \cap LowValueOutputs)
    + 2 * Cardinality(os \cap HighValueOutputs)
    + 3 * Cardinality(os \cap HigherValueOutputs)

Obligation(p) == accounting.liabilities[p] + accounting.reserved[p]
TotalObligation == Obligation(LegacyPool) + Obligation(SuccessorPool)
TotalActiveBacking ==
  BackingValue(ActiveEligible(LegacyPool))
    + BackingValue(ActiveEligible(SuccessorPool))

CorrectCapacity(p) ==
  IF ctrl.scope = "GLOBAL"
  THEN TotalActiveBacking >= TotalObligation + 1
  ELSE BackingValue(ActiveEligible(p)) >= Obligation(p) + 1

ReportedCapacity(p) ==
  IF ctrl.scope = "GLOBAL"
  THEN BackingValue(outputs.live) >= TotalObligation + 1
  ELSE BackingValue({o \in outputs.live : PoolOf(o) = p}) >= Obligation(p) + 1

OtherPool(p) == IF p = LegacyPool THEN SuccessorPool ELSE LegacyPool

ProspectiveBacking(p) ==
  BackingValue(CandidateEligible(p))
    + BackingValue(ActiveEligible(OtherPool(p)))

ProspectiveSolvent(p) ==
  IF ctrl.scope = "GLOBAL"
  THEN ProspectiveBacking(p) >= TotalObligation
  ELSE BackingValue(CandidateEligible(p)) >= Obligation(p)

UsedLiabilityIds == {e.id : e \in audit.liabilityLog}
LoggedReshareShares == UNION {e.newShares : e \in audit.reshareLog}
LoggedOwnerShares   == UNION {e.newShares : e \in audit.ownerLog}
ExpectedLiability(p) ==
  (IF p = LegacyPool THEN 2 ELSE 0)
    + Cardinality({e \in audit.liabilityLog : e.pool = p})
(* TLA+ has no built-in finite sum over records.  With one bounded successor   *)
(* contribution, its expected amount is a simple conditional.                  *)
ExpectedCapitalValue(p) ==
  (IF p = LegacyPool THEN 3 ELSE 0)
    + (IF \E e \in audit.capitalLog : e.pool = p THEN 3 ELSE 0)

-------------------------------------------------------------------------------
Init ==
  \E features \in SUBSET FeatureKinds, scope \in Scopes :
    /\ ctrl =
      [features |-> features,
       scope |-> scope,
       legacyPhase |-> "Active",
       successorPhase |-> "Absent",
       now |-> 0,
       incident |-> "NONE",
       incidentShareEpoch |-> 0,
       currentShareEpoch |-> 0,
       currentLegacyKey |-> "K0"]
    /\ actors = [offline |-> {}]
    /\ shares =
      [issued |-> InitialShares,
       lost |-> {},
       lostHistory |-> {},
       adversaryKnown |-> {},
       adversaryHistory |-> {},
       expelled |-> {}]
    /\ gates =
      [active |-> [p \in Pools |-> IF p = LegacyPool THEN "G0" ELSE "NO_GATE"]]
    /\ outputs =
      [created |-> OldOutputs,
       live |-> OldOutputs,
       consumed |-> {},
       ownerKey |-> [o \in AllOutputs |-> BirthOwner(o)],
       recoveryBranch |->
         [o \in AllOutputs |->
           IF o \in OldOutputs /\ "RECOVERY" \in features
           THEN "RECOVERY_V1"
           ELSE "NONE"],
       quarantined |-> {}]
    /\ recovery =
      [kind |-> "NONE",
       migrated |-> {},
       authLog |-> {},
       ownerAuthLog |-> {}]
    /\ accounting =
      [liabilities |-> [p \in Pools |-> IF p = LegacyPool THEN 2 ELSE 0],
       reserved |-> [p \in Pools |-> IF p = LegacyPool THEN 1 ELSE 0],
       capital |-> [p \in Pools |-> IF p = LegacyPool THEN 3 ELSE 0],
       nullifiers |-> {},
       nullifierHistory |-> {}]
    /\ audit =
      [gateLog |-> {InitialGateEvent},
       ownerLog |-> {},
       reshareLog |-> {},
       migrationLog |-> {},
       liabilityLog |-> {},
       capitalLog |-> {},
       authorizationLog |-> {}]

-------------------------------------------------------------------------------
(* Proactive maintenance can occur before the single incident.                 *)

ProactiveReshare ==
  /\ "RESHARE" \in ctrl.features
  /\ ctrl.incident = "NONE"
  /\ ctrl.legacyPhase = "Active"
  /\ ctrl.currentShareEpoch = 0
  /\ \E contributors \in SUBSET UsableHolders("K0", 0) :
    /\ Cardinality(contributors) >= KOwn
    /\ LET contributorShares ==
             {<<c, "K0", 0>> : c \in contributors}
           newShares == SharesFor("K0", 1, ReplacementRoster)
           event ==
             [key |-> "K0",
              fromEpoch |-> 0,
              toEpoch |-> 1,
              contributorShares |-> contributorShares,
              issuedSnapshot |-> shares.issued,
              lostSnapshot |-> shares.lost,
              expelledSnapshot |-> shares.expelled,
              offlineSnapshot |-> actors.offline,
              newShares |-> newShares]
       IN
         /\ ctrl' = [ctrl EXCEPT !.currentShareEpoch = 1]
         /\ shares' =
           [shares EXCEPT
             !.issued =
               IF Bug = "ERASE_ISSUED_SHARES" THEN newShares ELSE @ \cup newShares]
         /\ audit' = [audit EXCEPT !.reshareLog = @ \cup {event}]
  /\ UNCHANGED <<actors, gates, outputs, recovery, accounting>>

IncidentLost(kind, epoch) ==
  CASE kind = "PARTIAL_LOSS" ->
         IF epoch = 0
         THEN {<<"c1", "K0", 0>>}
         ELSE {<<"c3", "K0", 1>>}
    [] kind = "CATASTROPHIC_LOSS" ->
         IF epoch = 0
         THEN {<<"c1", "K0", 0>>, <<"c2", "K0", 0>>,
               <<"c3", "K0", 0>>}
         ELSE SharesFor("K0", 1, ReplacementRoster)
    [] OTHER -> {}

IncidentKnown(kind, epoch) ==
  CASE kind = "THRESHOLD_COMPROMISE" ->
         IF epoch = 0
         THEN {<<"c1", "K0", 0>>, <<"c2", "K0", 0>>}
         ELSE SharesFor("K0", 1, ReplacementRoster)
    [] kind = "MIXED_EPOCH" ->
         {<<"c1", "K0", 0>>, <<"c3", "K0", 1>>}
    [] OTHER -> {}

IncidentExpelled(kind, epoch) ==
  IF kind = "THRESHOLD_COMPROMISE"
  THEN IF epoch = 0 THEN {"c1", "c2"} ELSE ReplacementRoster
  ELSE IF kind = "MIXED_EPOCH" THEN {"c1"}
  ELSE {}

IncidentOffline(kind) ==
  IF kind = "GATE_OUTAGE" THEN {"g1", "g2"}
  ELSE IF kind = "RECOVERY_OUTAGE" THEN {"r1"}
  ELSE {}

ExpectedLostHistory ==
  IF ctrl.incident = "NONE"
  THEN {}
  ELSE IncidentLost(ctrl.incident, ctrl.incidentShareEpoch)

ExpectedAdversaryHistory ==
  IF ctrl.incident = "NONE"
  THEN {}
  ELSE IncidentKnown(ctrl.incident, ctrl.incidentShareEpoch)

RaiseIncident ==
  \E kind \in Incidents :
    /\ ctrl.incident = "NONE"
    /\ ctrl.legacyPhase = "Active"
    /\ (kind = "MIXED_EPOCH" => ctrl.currentShareEpoch = 1)
    /\ LET lost == IncidentLost(kind, ctrl.currentShareEpoch)
           known == IncidentKnown(kind, ctrl.currentShareEpoch)
       IN
         /\ lost \subseteq shares.issued
         /\ known \subseteq shares.issued
         /\ ctrl' =
           [ctrl EXCEPT
             !.legacyPhase = "Frozen",
             !.incident = kind,
             !.incidentShareEpoch = ctrl.currentShareEpoch]
         /\ actors' =
           [actors EXCEPT !.offline = @ \cup IncidentOffline(kind)]
         /\ shares' =
           [shares EXCEPT
             !.lost = @ \cup lost,
             !.lostHistory = @ \cup lost,
             !.adversaryKnown = @ \cup known,
             !.adversaryHistory = @ \cup known,
             !.expelled =
               @ \cup IncidentExpelled(kind, ctrl.currentShareEpoch)]
  /\ UNCHANGED <<gates, outputs, recovery, accounting, audit>>

StartLegacyGateDKG ==
  /\ ctrl.legacyPhase = "Frozen"
  /\ ctrl' = [ctrl EXCEPT !.legacyPhase = "GateDKG"]
  /\ UNCHANGED <<actors, shares, gates, outputs, recovery, accounting, audit>>

CompleteLegacyGateDKG ==
  /\ ctrl.legacyPhase = "GateDKG"
  /\ \E signers \in SUBSET AvailableGateOperators :
    /\ IF Bug = "COMPLETE_GATE_WITHOUT_QUORUM"
       THEN Cardinality(signers) = 1
       ELSE Cardinality(signers) >= KGate
    /\ LET key == IF Bug = "REUSE_OLD_GATE_KEY" THEN "G0" ELSE "G1"
           event ==
             [pool |-> LegacyPool,
              epoch |-> 1,
              key |-> key,
              policy |-> "LEGACY_POLICY",
              signers |-> signers,
              availableSnapshot |-> AvailableActors]
       IN
         /\ ctrl' = [ctrl EXCEPT !.legacyPhase = "Ownership"]
         /\ audit' = [audit EXCEPT !.gateLog = @ \cup {event}]
  /\ UNCHANGED <<actors, shares, gates, outputs, recovery, accounting>>

KeepOwner ==
  /\ ctrl.legacyPhase = "Ownership"
  /\ CanOperate(ctrl.currentLegacyKey, OwnerEpoch(ctrl.currentLegacyKey))
  /\ ctrl' = [ctrl EXCEPT !.legacyPhase = "Ready"]
  /\ UNCHANGED <<actors, shares, gates, outputs, recovery, accounting, audit>>

IncidentReshare ==
  /\ ctrl.legacyPhase = "Ownership"
  /\ "RESHARE" \in ctrl.features
  /\ ctrl.currentLegacyKey = "K0"
  /\ ctrl.currentShareEpoch = 0
  /\ \E chosen \in SUBSET UsableHolders("K0", 0) :
    /\ chosen # {}
    /\ LET normalClaims == {<<c, "K0", 0>> : c \in chosen}
           contributorShares ==
             CASE Bug = "RESHARE_WITH_NONHOLDER" ->
                    {<<"g1", "K0", 0>>, <<"g2", "K0", 0>>}
               [] Bug = "RESHARE_WITH_MIXED_EPOCH" ->
                    {<<"c1", "K0", 0>>, <<"c3", "K0", 1>>}
               [] OTHER -> normalClaims
           newShares == SharesFor("K0", 1, ReplacementRoster)
           event ==
             [key |-> "K0",
              fromEpoch |-> 0,
              toEpoch |-> 1,
              contributorShares |-> contributorShares,
              issuedSnapshot |-> shares.issued,
              lostSnapshot |-> shares.lost,
              expelledSnapshot |-> shares.expelled,
              offlineSnapshot |-> actors.offline,
              newShares |-> newShares]
       IN
         /\ (Cardinality(ClaimHolders(contributorShares)) >= KOwn
              \/ Bug = "RESHARE_WITHOUT_THRESHOLD")
         /\ ctrl' =
           [ctrl EXCEPT
             !.legacyPhase = "Ready",
             !.currentShareEpoch = 1]
         /\ shares' =
           [shares EXCEPT
             !.issued =
               IF Bug = "ERASE_ISSUED_SHARES" THEN newShares ELSE @ \cup newShares,
             !.lost = IF Bug = "ERASE_LOST_SHARES" THEN {} ELSE @,
             !.lostHistory = IF Bug = "ERASE_LOST_SHARES" THEN {} ELSE @,
             !.adversaryKnown =
               IF Bug = "ERASE_SHARE_KNOWLEDGE" THEN {} ELSE @,
             !.adversaryHistory =
               IF Bug = "ERASE_SHARE_KNOWLEDGE" THEN {} ELSE @]
         /\ audit' = [audit EXCEPT !.reshareLog = @ \cup {event}]
  /\ UNCHANGED <<actors, gates, outputs, recovery, accounting>>

CompleteLegacyOwnerDKG ==
  /\ ctrl.legacyPhase \in {"Ownership", "Ready", "RecoveryDelay"}
  /\ ~OwnerRecorded("KR")
  /\ \E signers \in SUBSET AvailableReplacement :
    /\ IF Bug = "OWNER_DKG_WITHOUT_QUORUM"
       THEN Cardinality(signers) = 1
       ELSE Cardinality(signers) >= KOwn
    /\ LET roster ==
             IF Bug = "OWNER_DKG_WRONG_ROSTER"
             THEN InitialRoster
             ELSE ReplacementRoster
           newShares == SharesFor("KR", 0, roster)
           event ==
             [key |-> "KR",
              epoch |-> 0,
              roster |-> roster,
              signers |-> signers,
              availableSnapshot |-> AvailableActors,
              newShares |-> newShares]
       IN
         /\ shares' = [shares EXCEPT !.issued = @ \cup newShares]
         /\ audit' = [audit EXCEPT !.ownerLog = @ \cup {event}]
  /\ UNCHANGED <<ctrl, actors, gates, outputs, recovery, accounting>>

CanonicalRecoveryRequest(ownerEvent, gateEvent) ==
  [incident |-> ctrl.incident,
   domain |-> "EUSD_ETH_BRIDGE_V1",
   recoveryPolicy |-> "RECOVERY_V1",
   oldOutputs |-> OldOutputs,
   newOutputs |-> MovedOutputs,
   newOwner |-> "KR",
   policy |-> "LEGACY_POLICY",
   gateKey |-> "G1",
   ownerDkg |-> ownerEvent,
   gateDkg |-> gateEvent,
   armedAt |-> ctrl.now,
   maturity |-> ctrl.now + RecoveryDelay]

RetroactivelyEnableRecovery ==
  /\ Bug = "RETROACTIVE_RECOVERY"
  /\ ctrl.legacyPhase = "Ownership"
  /\ "RECOVERY" \notin ctrl.features
  /\ outputs' =
    [outputs EXCEPT
      !.recoveryBranch =
        [o \in AllOutputs |->
          IF o \in OldOutputs THEN "RECOVERY_V1" ELSE @[o]]]
  /\ UNCHANGED <<ctrl, actors, shares, gates, recovery, accounting, audit>>

AuthorizeRecovery ==
  /\ ctrl.legacyPhase = "Ownership"
  /\ ("RECOVERY" \in ctrl.features \/ Bug = "RETROACTIVE_RECOVERY")
  /\ RecoveryBoundOnAllOld
  /\ \E ownerEvent \in
         (IF Bug = "RECOVERY_BEFORE_OWNER_DKG"
          THEN {PrematureKREvent}
          ELSE {e \in audit.ownerLog : e.key = "KR"}),
       gateEvent \in audit.gateLog,
       signers \in SUBSET AvailableRecoveryOperators :
    /\ ownerEvent.key = "KR"
    /\ gateEvent.pool = LegacyPool
    /\ gateEvent.epoch = 1
    /\ gateEvent.key = "G1"
    /\ IF Bug = "RECOVERY_WITHOUT_QUORUM"
       THEN Cardinality(signers) = 1
       ELSE Cardinality(signers) >= KRecovery
    /\ LET request == CanonicalRecoveryRequest(ownerEvent, gateEvent)
           signed ==
             IF Bug = "RECOVERY_UNBOUND_REQUEST"
             THEN [request EXCEPT !.gateKey = "G0"]
             ELSE request
           auth ==
             [request |-> request,
              signedRequest |-> signed,
              signers |-> signers,
              availableSnapshot |-> AvailableActors]
       IN
         /\ ctrl' = [ctrl EXCEPT !.legacyPhase = "RecoveryDelay"]
         /\ recovery' = [recovery EXCEPT !.authLog = @ \cup {auth}]
  /\ UNCHANGED <<actors, shares, gates, outputs, accounting, audit>>

Tick ==
  /\ ctrl.legacyPhase = "RecoveryDelay"
  /\ ctrl.now < MaxTime
  /\ ctrl' = [ctrl EXCEPT !.now = @ + 1]
  /\ UNCHANGED <<actors, shares, gates, outputs, recovery, accounting, audit>>

BeginRecoveryMigration ==
  /\ ctrl.legacyPhase = "RecoveryDelay"
  /\ recovery.authLog # {}
  /\ OwnerRecorded("KR")
  /\ \E a \in recovery.authLog :
    /\ (ctrl.now >= a.request.maturity \/ Bug = "RECOVER_BEFORE_DELAY")
    /\ ctrl' = [ctrl EXCEPT !.legacyPhase = "Migrating"]
    /\ recovery' =
      [recovery EXCEPT
        !.kind = "RECOVERY",
        !.migrated = {}]
  /\ UNCHANGED <<actors, shares, gates, outputs, accounting, audit>>

BeginOwnerMigration ==
  /\ ctrl.legacyPhase \in {"Ownership", "Ready"}
  /\ ctrl.currentLegacyKey = "K0"
  /\ AdversaryCan("K0")
  /\ \E ownerEvent \in audit.ownerLog,
       gateEvent \in audit.gateLog,
       signers \in SUBSET UsableHolders("K0", ctrl.currentShareEpoch) :
    /\ ownerEvent.key = "KR"
    /\ gateEvent.pool = LegacyPool
    /\ gateEvent.epoch = 1
    /\ gateEvent.key = "G1"
    /\ Cardinality(signers) >= KOwn
    /\ LET auth ==
         [oldOutputs |-> OldOutputs,
          newOutputs |-> MovedOutputs,
          oldKey |-> IF Bug = "OWNER_UNBOUND_REQUEST" THEN "KR" ELSE "K0",
          newKey |-> "KR",
          shareEpoch |-> ctrl.currentShareEpoch,
          signers |-> signers,
          availableSnapshot |-> AvailableActors,
          gateKey |-> "G1",
          ownerDkg |-> ownerEvent,
          gateDkg |-> gateEvent]
       IN
         /\ ctrl' = [ctrl EXCEPT !.legacyPhase = "Migrating"]
         /\ recovery' =
           [recovery EXCEPT
             !.kind = "OWNER",
             !.migrated = {},
             !.ownerAuthLog = @ \cup {auth}]
  /\ UNCHANGED <<actors, shares, gates, outputs, accounting, audit>>

MigrationTarget(u) ==
  CASE Bug = "RECOVERY_EXTERNAL_RECIPIENT" -> External(u)
    [] Bug = "RECOVERY_WRONG_OWNER" -> WrongOwner(u)
    [] Bug = "RECOVERY_WRONG_POLICY" -> WrongPolicy(u)
    [] Bug = "RECOVERY_WRONG_VALUE" -> WrongValue(u)
    [] OTHER -> Moved(u)

MigrateOne ==
  /\ ctrl.legacyPhase = "Migrating"
  /\ recovery.kind \in {"OWNER", "RECOVERY"}
  /\ \E u \in Units \ recovery.migrated :
    /\ Old(u) \in outputs.live
    /\ (recovery.kind = "OWNER" => recovery.ownerAuthLog # {})
    /\ (recovery.kind = "RECOVERY" => recovery.authLog # {})
    /\ LET target ==
             IF recovery.kind = "RECOVERY" THEN MigrationTarget(u) ELSE Moved(u)
           consume ==
             Bug # "RECOVERY_DOES_NOT_CONSUME" \/ recovery.kind # "RECOVERY"
           rAuth ==
             IF recovery.kind = "RECOVERY"
             THEN IF Bug = "RECOVERY_UNLOGGED_AUTH"
                  THEN {[a EXCEPT !.signers = {}] : a \in recovery.authLog}
                  ELSE recovery.authLog
             ELSE {}
           oAuth ==
             IF recovery.kind = "OWNER"
             THEN IF Bug = "OWNER_UNLOGGED_AUTH"
                  THEN {[a EXCEPT !.availableSnapshot = AllActors] :
                          a \in recovery.ownerAuthLog}
                  ELSE recovery.ownerAuthLog
             ELSE {}
           event ==
             [unit |-> u,
              kind |-> recovery.kind,
              old |-> Old(u),
              new |-> target,
              time |-> ctrl.now,
              recoveryAuth |-> rAuth,
              ownerAuth |-> oAuth,
              consumedOld |-> consume]
       IN
         /\ outputs' =
           [outputs EXCEPT
             !.created = @ \cup {target},
             !.live =
               (IF consume THEN @ \ {Old(u)} ELSE @) \cup {target},
             !.consumed =
               IF consume THEN @ \cup {Old(u)} ELSE @,
             !.quarantined =
               IF consume THEN @ \ {Old(u)} ELSE @]
         /\ recovery' =
           [recovery EXCEPT !.migrated = @ \cup {u}]
         /\ audit' =
           [audit EXCEPT !.migrationLog = @ \cup {event}]
  /\ UNCHANGED <<ctrl, actors, shares, gates, accounting>>

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
  /\ UNCHANGED <<actors, shares, gates, outputs, accounting, audit>>

DeclareStranded ==
  /\ ctrl.incident # "NONE"
  /\ ctrl.legacyPhase \in
       {"Frozen", "GateDKG", "Ownership", "Ready", "RecoveryDelay"}
  /\ LegacyLive # {}
  /\ LegacyLive \subseteq DerivedStrandedOutputs
  /\ ctrl' = [ctrl EXCEPT !.legacyPhase = "Stranded"]
  /\ UNCHANGED <<actors, shares, gates, outputs, recovery, accounting, audit>>

RotateOwnerInPlace ==
  /\ Bug = "ROTATE_OWNER_IN_PLACE"
  /\ ctrl.legacyPhase = "Ownership"
  /\ \E o \in outputs.live \cap OldOutputs :
    outputs' = [outputs EXCEPT !.ownerKey = [@ EXCEPT ![o] = "KR"]]
  /\ UNCHANGED <<ctrl, actors, shares, gates, recovery, accounting, audit>>

ActivateLegacy ==
  /\ ctrl.legacyPhase = "Ready"
  /\ GateRecorded(LegacyPool, 1)
  /\ CanOperate(ctrl.currentLegacyKey, OwnerEpoch(ctrl.currentLegacyKey))
  /\ (~AdversaryCan(ctrl.currentLegacyKey) \/ Bug = "ACTIVATE_UNSAFE_KEY")
  /\ (ProspectiveSolvent(LegacyPool)
       \/ Bug \in {"ACTIVATE_PARTIAL_MIGRATION", "ACTIVATE_UNSAFE_KEY"})
  /\ ctrl' = [ctrl EXCEPT !.legacyPhase = "Active"]
  /\ gates' = [gates EXCEPT !.active = [@ EXCEPT ![LegacyPool] = "G1"]]
  /\ UNCHANGED <<actors, shares, outputs, recovery, accounting, audit>>

BypassLegacyGate ==
  /\ Bug = "RESUME_BEFORE_GATE_DKG"
  /\ ctrl.legacyPhase = "Frozen"
  /\ CanOperate(ctrl.currentLegacyKey, OwnerEpoch(ctrl.currentLegacyKey))
  /\ ctrl' = [ctrl EXCEPT !.legacyPhase = "Active"]
  /\ gates' = [gates EXCEPT !.active = [@ EXCEPT ![LegacyPool] = "G1"]]
  /\ UNCHANGED <<actors, shares, outputs, recovery, accounting, audit>>

-------------------------------------------------------------------------------
(* Successor continuity is an independent overlay: capital, owner DKG, gate   *)
(* DKG, and activation are separate transitions.                              *)

ContributeSuccessorCapital ==
  /\ "SUCCESSOR" \in ctrl.features
  /\ ctrl.incident # "NONE"
  /\ (ctrl.successorPhase = "OwnerReady"
       \/ /\ Bug = "FUND_BEFORE_OWNER_DKG"
          /\ ctrl.successorPhase = "Absent")
  /\ LET event ==
       [pool |-> SuccessorPool,
        suppliedOutputs |-> FreshOutputs,
        amount |-> 3,
        external |-> TRUE]
     IN
       /\ ctrl' = [ctrl EXCEPT !.successorPhase = "Funded"]
       /\ outputs' =
         [outputs EXCEPT
           !.created = @ \cup FreshOutputs,
           !.live = @ \cup FreshOutputs]
       /\ accounting' =
         [accounting EXCEPT
           !.capital =
             IF Bug = "UNFUNDED_SUCCESSOR"
             THEN @
             ELSE [@ EXCEPT ![SuccessorPool] = @ + 3],
           !.liabilities =
             IF Bug = "ERASE_LEGACY_LIABILITY"
             THEN [@ EXCEPT ![LegacyPool] = 0]
             ELSE @,
           !.reserved =
             IF Bug = "RESET_RESERVATIONS"
             THEN [@ EXCEPT ![LegacyPool] = 0]
             ELSE @,
           !.nullifiers =
             IF Bug = "RESET_NULLIFIERS" THEN {} ELSE @]
       /\ audit' =
         [audit EXCEPT
           !.capitalLog =
             IF Bug = "UNFUNDED_SUCCESSOR" THEN @ ELSE @ \cup {event}]
  /\ UNCHANGED <<actors, shares, gates, recovery>>

CompleteSuccessorOwnerDKG ==
  /\ "SUCCESSOR" \in ctrl.features
  /\ ctrl.incident # "NONE"
  /\ ctrl.successorPhase = "Absent"
  /\ \E signers \in SUBSET AvailableReplacement :
    /\ Cardinality(signers) >= KOwn
    /\ LET roster ==
             IF Bug = "OWNER_DKG_WRONG_ROSTER"
             THEN InitialRoster
             ELSE ReplacementRoster
           newShares == SharesFor("KS", 0, roster)
           event ==
             [key |-> "KS",
              epoch |-> 0,
              roster |-> roster,
              signers |-> signers,
              availableSnapshot |-> AvailableActors,
              newShares |-> newShares]
       IN
         /\ ctrl' = [ctrl EXCEPT !.successorPhase = "OwnerReady"]
         /\ shares' = [shares EXCEPT !.issued = @ \cup newShares]
         /\ audit' = [audit EXCEPT !.ownerLog = @ \cup {event}]
  /\ UNCHANGED <<actors, gates, outputs, recovery, accounting>>

CompleteSuccessorGateDKG ==
  /\ ctrl.successorPhase = "Funded"
  /\ \E signers \in SUBSET AvailableGateOperators :
    /\ Cardinality(signers) >= KGate
    /\ LET key == IF Bug = "SUCCESSOR_REUSES_GATE" THEN "G1" ELSE "GS"
           event ==
             [pool |-> SuccessorPool,
              epoch |-> 0,
              key |-> key,
              policy |-> "SUCCESSOR_POLICY",
              signers |-> signers,
              availableSnapshot |-> AvailableActors]
       IN
         /\ ctrl' = [ctrl EXCEPT !.successorPhase = "Ready"]
         /\ audit' = [audit EXCEPT !.gateLog = @ \cup {event}]
  /\ UNCHANGED <<actors, shares, gates, outputs, recovery, accounting>>

ActivateSuccessor ==
  /\ ctrl.successorPhase = "Ready"
  /\ OwnerRecorded("KS")
  /\ GateRecorded(SuccessorPool, 0)
  /\ CanOperate("KS", 0)
  /\ ProspectiveSolvent(SuccessorPool)
  /\ ctrl' = [ctrl EXCEPT !.successorPhase = "Active"]
  /\ gates' = [gates EXCEPT !.active = [@ EXCEPT ![SuccessorPool] = "GS"]]
  /\ outputs' =
    [outputs EXCEPT
      !.quarantined =
        IF ctrl.legacyPhase = "Active" THEN @ ELSE @ \cup LegacyLive]
  /\ UNCHANGED <<actors, shares, recovery, accounting, audit>>

BypassSuccessorDKG ==
  /\ Bug = "SUCCESSOR_WITHOUT_DKG"
  /\ ctrl.successorPhase = "Funded"
  /\ ctrl' = [ctrl EXCEPT !.successorPhase = "Active"]
  /\ gates' = [gates EXCEPT !.active = [@ EXCEPT ![SuccessorPool] = "GS"]]
  /\ outputs' =
    [outputs EXCEPT
      !.quarantined =
        IF ctrl.legacyPhase = "Active" THEN @ ELSE @ \cup LegacyLive]
  /\ UNCHANGED <<actors, shares, recovery, accounting, audit>>

-------------------------------------------------------------------------------
AcceptLiability ==
  \E p \in Pools, id \in LiabilityIds \ UsedLiabilityIds :
    /\ PoolActive(p)
    /\ (CorrectCapacity(p)
         \/ /\ Bug = "COUNT_INELIGIBLE_BACKING"
            /\ ReportedCapacity(p))
    /\ LET eligible ==
             IF ctrl.scope = "GLOBAL"
             THEN TotalActiveBacking
             ELSE BackingValue(ActiveEligible(p))
           required ==
             IF ctrl.scope = "GLOBAL"
             THEN TotalObligation
             ELSE Obligation(p)
           event ==
             [id |-> id,
              pool |-> p,
              eligibleValue |-> eligible,
              requiredBefore |-> required]
       IN
         /\ accounting' =
           [accounting EXCEPT
             !.liabilities = [@ EXCEPT ![p] = @ + 1]]
         /\ audit' =
           [audit EXCEPT !.liabilityLog = @ \cup {event}]
  /\ UNCHANGED <<ctrl, actors, shares, gates, outputs, recovery>>

ConsumeNullifier ==
  \E i \in IntentIds \ accounting.nullifiers :
    /\ accounting' =
      [accounting EXCEPT
        !.nullifiers = @ \cup {i},
        !.nullifierHistory = @ \cup {i}]
    /\ UNCHANGED <<ctrl, actors, shares, gates, outputs, recovery, audit>>

AcceptGateAuthorization ==
  /\ ctrl.legacyPhase = "Active"
  /\ ctrl.incident # "NONE"
  /\ LET used ==
         IF Bug = "ACCEPT_OLD_GATE" THEN "G0" ELSE gates.active[LegacyPool]
         event ==
         [pool |-> LegacyPool,
          usedKey |-> used,
          expectedKey |-> gates.active[LegacyPool]]
     IN
       audit' = [audit EXCEPT !.authorizationLog = @ \cup {event}]
  /\ UNCHANGED <<ctrl, actors, shares, gates, outputs, recovery, accounting>>

-------------------------------------------------------------------------------
Next ==
  \/ ProactiveReshare
  \/ RaiseIncident
  \/ StartLegacyGateDKG
  \/ CompleteLegacyGateDKG
  \/ KeepOwner
  \/ IncidentReshare
  \/ CompleteLegacyOwnerDKG
  \/ RetroactivelyEnableRecovery
  \/ AuthorizeRecovery
  \/ Tick
  \/ BeginRecoveryMigration
  \/ BeginOwnerMigration
  \/ MigrateOne
  \/ FinishMigration
  \/ DeclareStranded
  \/ RotateOwnerInPlace
  \/ ActivateLegacy
  \/ BypassLegacyGate
  \/ ContributeSuccessorCapital
  \/ CompleteSuccessorOwnerDKG
  \/ CompleteSuccessorGateDKG
  \/ ActivateSuccessor
  \/ BypassSuccessorDKG
  \/ AcceptLiability
  \/ ConsumeNullifier
  \/ AcceptGateAuthorization

Spec == Init /\ [][Next]_vars

(* Named scenario constraints select one environment/policy tuple without     *)
(* weakening the broad Scenario=ALL-style safety run above.  TLC configs use   *)
(* these as state constraints, so branches to other incidents are discarded.  *)

FalseKeepConstraint ==
  /\ ctrl.features = {}
  /\ ctrl.scope = "GLOBAL"
  /\ ctrl.incident \in {"NONE", "FALSE"}

PartialReshareConstraint ==
  /\ ctrl.features = {"RESHARE"}
  /\ ctrl.scope = "GLOBAL"
  /\ ctrl.incident \in {"NONE", "PARTIAL_LOSS"}
  /\ (ctrl.incident = "NONE" => ctrl.currentShareEpoch = 0)

(* The named scenario selects the operator's reshare response explicitly.     *)
(* It does not prune the resulting state or assert the desired epoch.          *)
PartialReshareResponsePolicy ==
  ctrl.incident = "PARTIAL_LOSS" => ~KeepOwner

CatastrophicReshareConstraint ==
  /\ ctrl.features = {"RESHARE"}
  /\ ctrl.scope = "GLOBAL"
  /\ ctrl.incident \in {"NONE", "CATASTROPHIC_LOSS"}

CatastrophicNoRecoveryConstraint ==
  /\ ctrl.features = {}
  /\ ctrl.scope = "GLOBAL"
  /\ ctrl.incident \in {"NONE", "CATASTROPHIC_LOSS"}

CatastrophicDelayedConstraint ==
  /\ ctrl.features = {"RECOVERY"}
  /\ ctrl.scope = "GLOBAL"
  /\ ctrl.incident \in {"NONE", "CATASTROPHIC_LOSS"}

ThresholdMigrationConstraint ==
  /\ ctrl.features = {}
  /\ ctrl.scope = "GLOBAL"
  /\ ctrl.incident \in {"NONE", "THRESHOLD_COMPROMISE"}

MixedEpochConstraint ==
  /\ ctrl.features = {"RESHARE"}
  /\ ctrl.scope = "GLOBAL"
  /\ ctrl.incident \in {"NONE", "MIXED_EPOCH"}

SuccessorGlobalConstraint ==
  /\ ctrl.features = {"SUCCESSOR"}
  /\ ctrl.scope = "GLOBAL"
  /\ ctrl.incident \in {"NONE", "CATASTROPHIC_LOSS"}

SuccessorSegregatedConstraint ==
  /\ ctrl.features = {"SUCCESSOR"}
  /\ ctrl.scope = "SEGREGATED"
  /\ ctrl.incident \in {"NONE", "CATASTROPHIC_LOSS"}

ProfileNoFeaturesGlobal ==
  ctrl.features = {} /\ ctrl.scope = "GLOBAL"

ProfileNoFeaturesSegregated ==
  ctrl.features = {} /\ ctrl.scope = "SEGREGATED"

ProfileReshareGlobal ==
  ctrl.features = {"RESHARE"} /\ ctrl.scope = "GLOBAL"

ProfileReshareSegregated ==
  ctrl.features = {"RESHARE"} /\ ctrl.scope = "SEGREGATED"

ProfileRecoveryGlobal ==
  ctrl.features = {"RECOVERY"} /\ ctrl.scope = "GLOBAL"

ProfileRecoverySegregated ==
  ctrl.features = {"RECOVERY"} /\ ctrl.scope = "SEGREGATED"

ProfileSuccessorGlobal ==
  ctrl.features = {"SUCCESSOR"} /\ ctrl.scope = "GLOBAL"

ProfileSuccessorSegregated ==
  ctrl.features = {"SUCCESSOR"} /\ ctrl.scope = "SEGREGATED"

ProfileRecoverySuccessorGlobal ==
  ctrl.features = {"RECOVERY", "SUCCESSOR"} /\ ctrl.scope = "GLOBAL"

ProfileRecoverySuccessorSegregated ==
  ctrl.features = {"RECOVERY", "SUCCESSOR"} /\ ctrl.scope = "SEGREGATED"

ProfileReshareRecoveryGlobal ==
  ctrl.features = {"RESHARE", "RECOVERY"} /\ ctrl.scope = "GLOBAL"

ProfileReshareRecoverySegregated ==
  ctrl.features = {"RESHARE", "RECOVERY"} /\ ctrl.scope = "SEGREGATED"

ProfileReshareSuccessorGlobal ==
  ctrl.features = {"RESHARE", "SUCCESSOR"} /\ ctrl.scope = "GLOBAL"

ProfileReshareSuccessorSegregated ==
  ctrl.features = {"RESHARE", "SUCCESSOR"} /\ ctrl.scope = "SEGREGATED"

ProfileAllGlobal ==
  ctrl.features = FeatureKinds /\ ctrl.scope = "GLOBAL"

ProfileAllSegregated ==
  ctrl.features = FeatureKinds /\ ctrl.scope = "SEGREGATED"

ScenarioFairSpec ==
  /\ Spec
  /\ WF_vars(ProactiveReshare)
  /\ WF_vars(RaiseIncident)
  /\ WF_vars(StartLegacyGateDKG)
  /\ WF_vars(CompleteLegacyGateDKG)
  /\ WF_vars(KeepOwner)
  /\ WF_vars(IncidentReshare)
  /\ WF_vars(CompleteLegacyOwnerDKG)
  /\ WF_vars(AuthorizeRecovery)
  /\ WF_vars(Tick)
  /\ WF_vars(BeginRecoveryMigration)
  /\ WF_vars(BeginOwnerMigration)
  /\ WF_vars(MigrateOne)
  /\ WF_vars(FinishMigration)
  /\ WF_vars(DeclareStranded)
  /\ WF_vars(ActivateLegacy)
  /\ WF_vars(ContributeSuccessorCapital)
  /\ WF_vars(CompleteSuccessorOwnerDKG)
  /\ WF_vars(CompleteSuccessorGateDKG)
  /\ WF_vars(ActivateSuccessor)
  /\ WF_vars(AcceptLiability)

EventuallyFalseKeep ==
  <> (ctrl.incident = "FALSE"
       /\ ctrl.legacyPhase = "Active"
       /\ ctrl.currentLegacyKey = "K0"
       /\ gates.active[LegacyPool] = "G1"
       /\ outputs.live = OldOutputs)

EventuallyPartialReshare ==
  <> (ctrl.incident = "PARTIAL_LOSS"
       /\ ctrl.legacyPhase = "Active"
       /\ ctrl.currentLegacyKey = "K0"
       /\ ctrl.currentShareEpoch = 1)

EventuallyCatastrophicStranded ==
  <> (ctrl.incident = "CATASTROPHIC_LOSS"
       /\ ctrl.legacyPhase = "Stranded")

EventuallyCatastrophicRecovered ==
  <> (ctrl.incident = "CATASTROPHIC_LOSS"
       /\ ctrl.legacyPhase = "Active"
       /\ ctrl.currentLegacyKey = "KR"
       /\ recovery.migrated = Units)

EventuallyThresholdMigrated ==
  <> (ctrl.incident = "THRESHOLD_COMPROMISE"
       /\ ctrl.legacyPhase = "Active"
       /\ ctrl.currentLegacyKey = "KR"
       /\ AdversaryCan("K0"))

EventuallyMixedEpochSafe ==
  <> (ctrl.incident = "MIXED_EPOCH"
       /\ ctrl.legacyPhase = "Active"
       /\ ctrl.currentShareEpoch = 1
       /\ ~AdversaryCan("K0"))

EventuallySuccessorActive ==
  <> (ctrl.incident = "CATASTROPHIC_LOSS"
       /\ ctrl.successorPhase = "Active"
       /\ gates.active[SuccessorPool] = "GS")

EventuallySuccessorLiabilityAccepted ==
  <> (ctrl.incident = "CATASTROPHIC_LOSS"
       /\ ctrl.successorPhase = "Active"
       /\ accounting.liabilities[SuccessorPool] >= 1)

NoCatastrophicReactivationWithoutRecovery ==
  ctrl.incident = "CATASTROPHIC_LOSS"
    /\ "RECOVERY" \notin ctrl.features
    /\ ~CanOperate("K0", ctrl.currentShareEpoch)
  => ctrl.legacyPhase # "Active"

GlobalSuccessorHasNoNewCapacity ==
  ctrl.incident = "CATASTROPHIC_LOSS"
    /\ ctrl.scope = "GLOBAL"
    /\ ctrl.successorPhase = "Active"
  => accounting.liabilities[SuccessorPool] = 0

SegregatedLegacyObligationsRemain ==
  ctrl.incident = "CATASTROPHIC_LOSS"
    /\ ctrl.scope = "SEGREGATED"
    /\ ctrl.successorPhase = "Active"
  => /\ accounting.liabilities[LegacyPool] = 2
     /\ accounting.reserved[LegacyPool] = 1

-------------------------------------------------------------------------------
(* Invariants contain no Bug tests.                                           *)

TypeOK ==
  /\ ctrl \in
    [features: SUBSET FeatureKinds,
     scope: Scopes,
     legacyPhase: LegacyPhases,
     successorPhase: SuccessorPhases,
     now: 0..MaxTime,
     incident: Incidents \cup {"NONE"},
     incidentShareEpoch: ShareEpochs,
     currentShareEpoch: ShareEpochs,
     currentLegacyKey: {"K0", "KR"}]
  /\ actors \in [offline: SUBSET AllActors]
  /\ shares \in
    [issued: SUBSET ShareTriples,
     lost: SUBSET ShareTriples,
     lostHistory: SUBSET ShareTriples,
     adversaryKnown: SUBSET ShareTriples,
     adversaryHistory: SUBSET ShareTriples,
     expelled: SUBSET Custodians]
  /\ gates \in [active: [Pools -> GateKeys]]
  /\ outputs \in
    [created: SUBSET AllOutputs,
     live: SUBSET AllOutputs,
     consumed: SUBSET AllOutputs,
     ownerKey: [AllOutputs -> OwnerKeys],
     recoveryBranch: [AllOutputs -> RecoveryPolicyIds],
     quarantined: SUBSET AllOutputs]
  /\ recovery \in
    [kind: {"NONE", "OWNER", "RECOVERY"},
     migrated: SUBSET Units,
     authLog: SUBSET RecoveryAuthType,
     ownerAuthLog: SUBSET OwnerAuthType]
  /\ accounting \in
    [liabilities: [Pools -> 0..4],
     reserved: [Pools -> 0..2],
     capital: [Pools -> 0..6],
     nullifiers: SUBSET IntentIds,
     nullifierHistory: SUBSET IntentIds]
  /\ audit \in
    [gateLog: SUBSET GateEventType,
     ownerLog: SUBSET OwnerEventType,
     reshareLog: SUBSET ReshareEventType,
     migrationLog: SUBSET MigrationEventType,
     liabilityLog: SUBSET LiabilityEventType,
     capitalLog: SUBSET CapitalEventType,
     authorizationLog: SUBSET AuthorizationEventType]

OutputMetadataImmutable ==
  outputs.ownerKey = [o \in AllOutputs |-> BirthOwner(o)]

RecoveryPolicyImmutable ==
  outputs.recoveryBranch =
    [o \in AllOutputs |->
      IF o \in OldOutputs /\ "RECOVERY" \in ctrl.features
      THEN "RECOVERY_V1"
      ELSE "NONE"]

OutputConservation ==
  /\ outputs.live \cap outputs.consumed = {}
  /\ outputs.created = outputs.live \cup outputs.consumed
  /\ outputs.quarantined \subseteq outputs.live
  /\ \A u \in Units :
    Cardinality(
      outputs.live \cap
        {Old(u), Moved(u), WrongOwner(u), WrongPolicy(u),
         WrongValue(u), External(u)}
    ) <= 1

ShareIssuanceAccounted ==
  shares.issued = InitialShares \cup LoggedReshareShares \cup LoggedOwnerShares

ShareHistoryMonotonic ==
  /\ shares.lostHistory = ExpectedLostHistory
  /\ shares.adversaryHistory = ExpectedAdversaryHistory
  /\ shares.lostHistory \subseteq shares.lost
  /\ shares.adversaryHistory \subseteq shares.adversaryKnown
  /\ shares.lost \subseteq shares.issued
  /\ shares.adversaryKnown \subseteq shares.issued

MixedEpochIsNotThreshold ==
  ctrl.incident = "MIXED_EPOCH" => ~AdversaryCan("K0")

ReshareSound ==
  \A e \in audit.reshareLog :
    /\ e.key = "K0"
    /\ e.toEpoch = e.fromEpoch + 1
    /\ Cardinality(ClaimHolders(e.contributorShares)) >= KOwn
    /\ e.contributorShares \subseteq
      {<<c, e.key, e.fromEpoch>> :
        c \in {d \in Custodians :
          /\ <<d, e.key, e.fromEpoch>> \in e.issuedSnapshot
          /\ <<d, e.key, e.fromEpoch>> \notin e.lostSnapshot
          /\ d \notin e.expelledSnapshot
          /\ d \notin e.offlineSnapshot}}
    /\ e.newShares = SharesFor(e.key, e.toEpoch, ReplacementRoster)

GateCeremonySound ==
  \A e \in audit.gateLog :
    /\ e.signers \subseteq GateOperators \cap e.availableSnapshot
    /\ Cardinality(e.signers) >= KGate
    /\ e.key = ExpectedGateKey(e.pool, e.epoch)
    /\ e.policy = ExpectedGatePolicy(e.pool)

FreshGateCeremonies ==
  /\ \A e \in audit.gateLog :
    e.pool = LegacyPool /\ e.epoch = 1 => e.key # "G0"
  /\ \A e \in audit.gateLog :
    e.pool = SuccessorPool => e.key \notin {"G0", "G1"}

OwnerCeremonySound ==
  \A e \in audit.ownerLog :
    /\ e.key \in {"KR", "KS"}
    /\ e.epoch = 0
    /\ e.roster = ReplacementRoster
    /\ e.signers \subseteq e.roster \cap e.availableSnapshot
    /\ Cardinality(e.signers) >= KOwn
    /\ e.newShares = SharesFor(e.key, e.epoch, e.roster)

RecoveryAuthorizationSound ==
  \A a \in recovery.authLog :
    /\ a.request = a.signedRequest
    /\ a.request.incident = ctrl.incident
    /\ a.request.incident # "NONE"
    /\ a.request.domain = "EUSD_ETH_BRIDGE_V1"
    /\ a.request.recoveryPolicy = "RECOVERY_V1"
    /\ a.request.oldOutputs = OldOutputs
    /\ a.request.newOutputs = MovedOutputs
    /\ a.request.newOwner = "KR"
    /\ a.request.policy = "LEGACY_POLICY"
    /\ a.request.gateKey = "G1"
    /\ a.request.ownerDkg \in audit.ownerLog
    /\ a.request.ownerDkg.key = a.request.newOwner
    /\ a.request.ownerDkg.roster = ReplacementRoster
    /\ a.request.gateDkg \in audit.gateLog
    /\ a.request.gateDkg.pool = LegacyPool
    /\ a.request.gateDkg.epoch = 1
    /\ a.request.gateDkg.key = a.request.gateKey
    /\ \A o \in a.request.oldOutputs :
         outputs.recoveryBranch[o] = a.request.recoveryPolicy
    /\ a.request.maturity = a.request.armedAt + RecoveryDelay
    /\ a.signers \subseteq RecoveryOperators \cap a.availableSnapshot
    /\ Cardinality(a.signers) >= KRecovery

RecoveryDelayHonored ==
  \A m \in audit.migrationLog :
    m.kind = "RECOVERY" =>
      \A a \in m.recoveryAuth : m.time >= a.request.maturity

RecoveryBranchConfinement ==
  \A m \in audit.migrationLog :
    m.kind = "RECOVERY" => outputs.recoveryBranch[m.old] = "RECOVERY_V1"

RecoveryMigrationBound ==
  \A m \in audit.migrationLog :
    m.kind = "RECOVERY" =>
      /\ m.recoveryAuth # {}
      /\ m.recoveryAuth = recovery.authLog
      /\ \A a \in m.recoveryAuth :
        /\ m.old \in a.request.oldOutputs
        /\ m.new \in a.request.newOutputs
        /\ outputs.ownerKey[m.new] = a.request.newOwner
        /\ PolicyOf(m.new) = a.request.policy
        /\ a.request.gateKey = "G1"

OwnerMigrationSound ==
  \A m \in audit.migrationLog :
    m.kind = "OWNER" =>
      /\ m.ownerAuth # {}
      /\ m.ownerAuth = recovery.ownerAuthLog
    /\ \A a \in m.ownerAuth :
        /\ a.oldOutputs = OldOutputs
        /\ a.newOutputs = MovedOutputs
        /\ a.oldKey = "K0"
        /\ a.newKey = "KR"
        /\ a.ownerDkg \in audit.ownerLog
        /\ a.ownerDkg.key = a.newKey
        /\ a.ownerDkg.roster = ReplacementRoster
        /\ a.gateDkg \in audit.gateLog
        /\ a.gateDkg.pool = LegacyPool
        /\ a.gateDkg.epoch = 1
        /\ a.gateDkg.key = a.gateKey
        /\ Cardinality(a.signers) >= KOwn
        /\ a.signers \subseteq
          {c \in Custodians :
            /\ <<c, a.oldKey, a.shareEpoch>> \in shares.issued
            /\ <<c, a.oldKey, a.shareEpoch>> \notin shares.lost
            /\ c \notin shares.expelled
            /\ c \in a.availableSnapshot}
        /\ a.gateKey = "G1"
        /\ m.old \in a.oldOutputs
        /\ m.new \in a.newOutputs
        /\ outputs.ownerKey[m.old] = a.oldKey
        /\ outputs.ownerKey[m.new] = a.newKey

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
    /\ PoolOf(m.new) = LegacyPool
    /\ outputs.ownerKey[m.new] = "KR"
    /\ ValueOf(m.old) = ValueOf(m.new)
    /\ PolicyOf(m.old) = PolicyOf(m.new)

FreshOwnerRequiresFullMigration ==
  ctrl.legacyPhase = "Active" /\ ctrl.currentLegacyKey = "KR" =>
    /\ recovery.migrated = Units
    /\ OldOutputs \subseteq outputs.consumed
    /\ MovedOutputs \subseteq outputs.live

ActiveGateSound ==
  /\ ctrl.legacyPhase = "Active" /\ ctrl.incident # "NONE" =>
    /\ gates.active[LegacyPool] = "G1"
    /\ \E e \in audit.gateLog :
      e.pool = LegacyPool /\ e.epoch = 1 /\ e.key = "G1"
  /\ ctrl.successorPhase = "Active" =>
    /\ gates.active[SuccessorPool] = "GS"
    /\ \E e \in audit.gateLog :
      e.pool = SuccessorPool /\ e.key = "GS"

ActiveOwnershipSound ==
  /\ ctrl.legacyPhase = "Active" =>
    /\ CanOperate(ctrl.currentLegacyKey, OwnerEpoch(ctrl.currentLegacyKey))
    /\ ~AdversaryCan(ctrl.currentLegacyKey)
  /\ ctrl.successorPhase = "Active" =>
    /\ OwnerRecorded("KS")
    /\ CanOperate("KS", 0)
    /\ ~AdversaryCan("KS")

StrandingSound ==
  ctrl.legacyPhase = "Stranded" =>
    /\ LegacyLive # {}
    /\ LegacyLive \subseteq DerivedStrandedOutputs

NoRecoveryWithoutBranch ==
  "RECOVERY" \notin ctrl.features => recovery.authLog = {}

LiabilityAdmissionSound ==
  \A e \in audit.liabilityLog :
    e.eligibleValue >= e.requiredBefore + 1

LiabilitiesAccounted ==
  \A p \in Pools : accounting.liabilities[p] = ExpectedLiability(p)

ReservationsAccounted ==
  /\ accounting.reserved[LegacyPool] = 1
  /\ accounting.reserved[SuccessorPool] = 0

CapitalizationSound ==
  /\ \A p \in Pools : accounting.capital[p] = ExpectedCapitalValue(p)
  /\ FreshOutputs \subseteq outputs.created =>
    /\ OwnerRecorded("KS")
    /\ \E e \in audit.capitalLog :
        /\ e.pool = SuccessorPool
        /\ e.suppliedOutputs = FreshOutputs
        /\ e.amount = 3
        /\ e.external

NullifierHistoryPreserved ==
  accounting.nullifierHistory \subseteq accounting.nullifiers

ActiveSolvency ==
  /\ ctrl.legacyPhase = "Active" =>
    IF ctrl.scope = "GLOBAL"
    THEN TotalActiveBacking >= TotalObligation
    ELSE BackingValue(ActiveEligible(LegacyPool)) >= Obligation(LegacyPool)
  /\ ctrl.successorPhase = "Active" =>
    IF ctrl.scope = "GLOBAL"
    THEN TotalActiveBacking >= TotalObligation
    ELSE BackingValue(ActiveEligible(SuccessorPool)) >= Obligation(SuccessorPool)

SuccessorSound ==
  ctrl.successorPhase = "Active" =>
    /\ "SUCCESSOR" \in ctrl.features
    /\ FreshOutputs \subseteq outputs.created
    /\ FreshOutputs \subseteq outputs.live
    /\ OwnerRecorded("KS")
    /\ GateRecorded(SuccessorPool, 0)
    /\ accounting.capital[SuccessorPool] = 3
    /\ (ctrl.legacyPhase # "Active" =>
          (OldOutputs \cap outputs.live) \subseteq outputs.quarantined)

NoStaleAuthorization ==
  \A a \in audit.authorizationLog : a.usedKey = a.expectedKey

Safety ==
  /\ TypeOK
  /\ OutputMetadataImmutable
  /\ RecoveryPolicyImmutable
  /\ OutputConservation
  /\ ShareIssuanceAccounted
  /\ ShareHistoryMonotonic
  /\ MixedEpochIsNotThreshold
  /\ ReshareSound
  /\ GateCeremonySound
  /\ FreshGateCeremonies
  /\ OwnerCeremonySound
  /\ RecoveryAuthorizationSound
  /\ RecoveryDelayHonored
  /\ RecoveryBranchConfinement
  /\ RecoveryMigrationBound
  /\ OwnerMigrationSound
  /\ MigrationConsumesOld
  /\ MigrationConservative
  /\ FreshOwnerRequiresFullMigration
  /\ ActiveGateSound
  /\ ActiveOwnershipSound
  /\ StrandingSound
  /\ NoRecoveryWithoutBranch
  /\ LiabilityAdmissionSound
  /\ LiabilitiesAccounted
  /\ ReservationsAccounted
  /\ CapitalizationSound
  /\ NullifierHistoryPreserved
  /\ ActiveSolvency
  /\ SuccessorSound
  /\ NoStaleAuthorization

=============================================================================
