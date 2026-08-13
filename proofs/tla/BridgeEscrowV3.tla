------------------------------ MODULE BridgeEscrowV3 ------------------------------
EXTENDS Integers, FiniteSets, TLC

(***************************************************************************
This is a deliberately small, finite abstraction of the amended bridge-v3
acceptance contract.  Cryptographic verification is an atomic predicate here;
the model concerns lifecycle composition, not cryptographic soundness.

The two directions are fixed so TLC can exercise the complete customer cycle:
  ETH_TO_MOB: a real USDC inflow releases pre-seeded eUSD; and
  MOB_TO_ETH: a typed eUSD return releases the promoted USDC inflow.

Objective source truth is ghost state.  OPEN, RESERVE, and FINALIZE never read
it.  Only the source-chain environment and fault adjudication read it.
***************************************************************************)

Fwd == "ETH_TO_MOB"
Rev == "MOB_TO_ETH"
Directions == {Fwd, Rev}

Eth == "ETHEREUM"
Mob == "MOBILECOIN"
Chains == {Eth, Mob}

PreseedEusd == "EUSD_PRESEED"
UsdcDeposit == "USDC_DEPOSIT_LOT"
EusdReturn == "EUSD_RETURN_LOT"
Lots == {PreseedEusd, UsdcDeposit, EusdReturn}

Attempts == 1..2
ReservationIds == Directions \X Attempts
NoRes == <<"NO_RESERVATION", 0>>
NoDir == "NO_DIRECTION"
NoChain == "NO_CHAIN"
NoHeight == -1
MaxHeight == 3

Operators == {"w1", "w2", "w3", "a1", "a2", "innocent"}

SourceStates == {"Absent", "Encumbered", "Available"}
LotStates == {"Absent", "Encumbered", "Available", "ReservedIntent", "Spent"}
LiabilityStates == {"Absent", "Open", "CapacityReserved", "Settled"}
ClaimStates == {"Unbound", "Bound", "Settled"}
ReservationStates == {"Absent", "Live", "Cancelled", "Finalized"}
NullifierStates == {"Free", "Reserved", "Consumed"}
LeaseStates == {"Free", "Live", "Consumed"}
RiskStates == {"None", "CapacityReserved", "FinalizedUncleared",
               "Cancelled", "Cleared"}
FaultStates == {"None", "Frozen", "Distributed"}
BondStates == {"Locked", "Frozen", "Distributed"}

DestChain(d) == IF d = Fwd THEN Mob ELSE Eth
SourceLot(d) == IF d = Fwd THEN UsdcDeposit ELSE EusdReturn
BackingLot(d) == IF d = Fwd THEN PreseedEusd ELSE UsdcDeposit
UsesMobileLease(d) == d = Fwd

WardenApprovers(d) == IF d = Fwd THEN {"w1", "w2"}
                       ELSE {"w2", "w3"}
AccountApprovers(d) == IF d = Fwd THEN {"w2", "a1"}
                        ELSE {"w2", "a2"}
ExactCulprits(d) == WardenApprovers(d) \cup AccountApprovers(d)

VARIABLES objectiveSource, st, honestStep

vars == <<objectiveSource, st, honestStep>>

InitWithObjective(obj) ==
    /\ objectiveSource = obj
    /\ st = [sourceState |-> [d \in Directions |-> "Absent"],
             sourceFinal |-> [d \in Directions |-> FALSE],
             sourceRecordHistory |-> {},
             liability |-> [d \in Directions |-> "Absent"],
             claim |-> [d \in Directions |-> "Unbound"],
             lotState |-> [l \in Lots |->
                              IF l = PreseedEusd THEN "Available" ELSE "Absent"],
             lotRes |-> [l \in Lots |-> NoRes],
             nullState |-> [d \in Directions |-> "Free"],
             nullRes |-> [d \in Directions |-> NoRes],
             nullFinal |-> [d \in Directions |-> NoDir],
             leaseState |-> "Free",
             leaseRes |-> NoRes,
             resState |-> [r \in ReservationIds |-> "Absent"],
             liveRes |-> [d \in Directions |-> NoRes],
             finalRes |-> [d \in Directions |-> NoRes],
             nextAttempt |-> [d \in Directions |-> 1],
             risk |-> [d \in Directions |-> "None"],
             riskMature |-> [d \in Directions |-> FALSE],
             exposure |-> [d \in Directions |-> FALSE],
             reserveHeight |-> [d \in Directions |-> NoHeight],
             finalHeight |-> [d \in Directions |-> NoHeight],
             blockHeight |-> [c \in Chains |-> 0],
             reservationHistory |-> {},
             cancelHistory |-> {},
             finalCount |-> [d \in Directions |-> 0],
             promotionCount |-> [d \in Directions |-> 0],
             clearHistory |-> [d \in Directions |-> FALSE],
             paused |-> [c \in Chains |-> FALSE],
             pauseCause |-> [c \in Chains |-> NoChain],
             faultState |-> [d \in Directions |-> "None"],
             held |-> [d \in Directions |-> {}],
             distribution |-> [d \in Directions |-> {}],
             bondState |-> [o \in Operators |-> "Locked"]]
    /\ honestStep = 0

Init == \E obj \in [Directions -> BOOLEAN] : InitWithObjective(obj)
HonestInit == InitWithObjective([d \in Directions |-> TRUE])

(***************************************************************************
Source-chain environment.  This is the only admission-side action allowed to
read objectiveSource.  A signed claim does not call this action implicitly.
***************************************************************************)
RecordSourceInflow(d) ==
    /\ d \in Directions
    /\ objectiveSource[d]
    /\ st.sourceState[d] = "Absent"
    /\ st.lotState[SourceLot(d)] = "Absent"
    /\ st' = [st EXCEPT
                 !.sourceState[d] = "Encumbered",
                 !.lotState[SourceLot(d)] = "Encumbered",
                 !.sourceRecordHistory = @ \cup {d}]
    /\ UNCHANGED objectiveSource

FinalizeLocalInflow(d) ==
    /\ d \in Directions
    /\ st.sourceState[d] = "Encumbered"
    /\ ~st.sourceFinal[d]
    /\ st' = [st EXCEPT !.sourceFinal[d] = TRUE]
    /\ UNCHANGED objectiveSource

(***************************************************************************
Claim admission deliberately does not inspect source truth or source inventory.
WARDEN and ACCOUNT receipt validity is abstracted by this action's existence.
***************************************************************************)
OpenLiability(d) ==
    /\ d \in Directions
    /\ ~st.paused[DestChain(d)]
    /\ st.liability[d] = "Absent"
    /\ st.claim[d] = "Unbound"
    /\ st' = [st EXCEPT
                 !.liability[d] = "Open",
                 !.claim[d] = "Bound"]
    /\ UNCHANGED objectiveSource

ReserveRelease(d) ==
    LET rid == <<d, st.nextAttempt[d]>>
        lot == BackingLot(d)
    IN  /\ d \in Directions
        /\ ~st.paused[DestChain(d)]
        /\ st.liability[d] = "Open"
        /\ st.claim[d] = "Bound"
        /\ st.liveRes[d] = NoRes
        /\ st.resState[rid] = "Absent"
        /\ st.lotState[lot] = "Available"
        /\ st.lotRes[lot] = NoRes
        /\ st.nullState[d] = "Free"
        /\ st.nullRes[d] = NoRes
        /\ (~UsesMobileLease(d) \/ st.leaseState = "Free")
        /\ st' = [st EXCEPT
                     !.liability[d] = "CapacityReserved",
                     !.lotState[lot] = "ReservedIntent",
                     !.lotRes[lot] = rid,
                     !.nullState[d] = "Reserved",
                     !.nullRes[d] = rid,
                     !.leaseState = IF UsesMobileLease(d) THEN "Live" ELSE @,
                     !.leaseRes = IF UsesMobileLease(d) THEN rid ELSE @,
                     !.resState[rid] = "Live",
                     !.liveRes[d] = rid,
                     !.risk[d] = "CapacityReserved",
                     !.riskMature[d] = FALSE,
                     !.exposure[d] = TRUE,
                     !.reserveHeight[d] = st.blockHeight[DestChain(d)],
                     !.reservationHistory = @ \cup {rid}]
        /\ UNCHANGED objectiveSource

AdvanceBlock(c) ==
    /\ c \in Chains
    /\ st.blockHeight[c] < MaxHeight
    /\ \E d \in Directions :
          /\ DestChain(d) = c
          /\ st.liveRes[d] # NoRes
    /\ st' = [st EXCEPT !.blockHeight[c] = @ + 1]
    /\ UNCHANGED objectiveSource

FinalizeRelease(d, requirePriorBlock, retainExposure) ==
    LET rid == st.liveRes[d]
        lot == BackingLot(d)
        h == st.blockHeight[DestChain(d)]
    IN  /\ d \in Directions
        /\ ~st.paused[DestChain(d)]
        /\ st.liability[d] = "CapacityReserved"
        /\ rid \in ReservationIds
        /\ st.resState[rid] = "Live"
        /\ st.lotState[lot] = "ReservedIntent"
        /\ st.lotRes[lot] = rid
        /\ st.nullState[d] = "Reserved"
        /\ st.nullRes[d] = rid
        /\ (IF requirePriorBlock
            THEN st.reserveHeight[d] < h
            ELSE st.reserveHeight[d] <= h)
        /\ st.finalCount[d] = 0
        /\ st' = [st EXCEPT
                     !.liability[d] = "Settled",
                     !.claim[d] = "Settled",
                     !.lotState[lot] = "Spent",
                     !.nullState[d] = "Consumed",
                     !.nullFinal[d] = d,
                     !.leaseState = IF UsesMobileLease(d) THEN "Consumed" ELSE @,
                     !.resState[rid] = "Finalized",
                     !.liveRes[d] = NoRes,
                     !.finalRes[d] = rid,
                     !.risk[d] = "FinalizedUncleared",
                     !.exposure[d] = retainExposure,
                     !.finalHeight[d] = h,
                     !.finalCount[d] = @ + 1]
        /\ UNCHANGED objectiveSource

CancelRelease(d, releaseLease) ==
    LET rid == st.liveRes[d]
        lot == BackingLot(d)
    IN  /\ d \in Directions
        /\ st.liability[d] = "CapacityReserved"
        /\ rid \in ReservationIds
        /\ st.resState[rid] = "Live"
        /\ st.lotState[lot] = "ReservedIntent"
        /\ st.nullState[d] = "Reserved"
        /\ st.reserveHeight[d] < st.blockHeight[DestChain(d)]
        /\ st' = [st EXCEPT
                     !.liability[d] = "Open",
                     !.lotState[lot] = "Available",
                     !.lotRes[lot] = NoRes,
                     !.nullState[d] = "Free",
                     !.nullRes[d] = NoRes,
                     !.leaseState =
                         IF UsesMobileLease(d) /\ releaseLease THEN "Free" ELSE @,
                     !.leaseRes =
                         IF UsesMobileLease(d) /\ releaseLease THEN NoRes ELSE @,
                     !.resState[rid] = "Cancelled",
                     !.liveRes[d] = NoRes,
                     !.risk[d] = "Cancelled",
                     !.exposure[d] = FALSE,
                     !.cancelHistory = @ \cup {rid},
                     !.nextAttempt[d] =
                         IF @ < 2 THEN @ + 1 ELSE @]
        /\ UNCHANGED objectiveSource

PromoteSettledSource(d) ==
    /\ d \in Directions
    /\ st.sourceState[d] = "Encumbered"
    /\ st.sourceFinal[d]
    /\ st.liability[d] = "Settled"
    /\ st.finalCount[d] = 1
    /\ st.promotionCount[d] = 0
    /\ st' = [st EXCEPT
                 !.sourceState[d] = "Available",
                 !.lotState[SourceLot(d)] = "Available",
                 !.promotionCount[d] = @ + 1]
    /\ UNCHANGED objectiveSource

MatureRisk(d) ==
    /\ d \in Directions
    /\ st.risk[d] = "FinalizedUncleared"
    /\ ~st.riskMature[d]
    /\ st' = [st EXCEPT !.riskMature[d] = TRUE]
    /\ UNCHANGED objectiveSource

ClearRisk(d, requireMaturity) ==
    /\ d \in Directions
    /\ st.risk[d] = "FinalizedUncleared"
    /\ (~requireMaturity \/ st.riskMature[d])
    /\ st' = [st EXCEPT
                 !.risk[d] = "Cleared",
                 !.exposure[d] = FALSE,
                 !.clearHistory[d] = TRUE]
    /\ UNCHANGED objectiveSource

(***************************************************************************
Fault handling is chain-local and set-valued.  The shared identity w2 appears
in both role quorums but is frozen and distributed once because culprit sets
are mathematical sets, not concatenated signer lists.
***************************************************************************)
FreezeFault(d, exactOnly) ==
    LET culprits == IF exactOnly THEN ExactCulprits(d)
                    ELSE ExactCulprits(d) \cup {"innocent"}
    IN  /\ d \in Directions
        /\ st.liability[d] = "Settled"
        /\ ~objectiveSource[d]
        /\ st.faultState[d] = "None"
        /\ \A e \in Directions : st.faultState[e] = "None"
        /\ st' = [st EXCEPT
                     !.faultState[d] = "Frozen",
                     !.held[d] = culprits,
                     !.bondState = [o \in Operators |->
                         IF o \in culprits THEN "Frozen" ELSE st.bondState[o]]]
        /\ UNCHANGED objectiveSource

PauseChain(c, localOnly) ==
    /\ c \in Chains
    /\ ~st.paused[c]
    /\ \E d \in Directions : st.faultState[d] \in {"Frozen", "Distributed"}
    /\ st' = IF localOnly
             THEN [st EXCEPT
                      !.paused[c] = TRUE,
                      !.pauseCause[c] = c]
             ELSE [st EXCEPT
                      !.paused = [x \in Chains |-> TRUE],
                      !.pauseCause = [x \in Chains |-> c]]
    /\ UNCHANGED objectiveSource

DistributeFaultCollateral(d) ==
    /\ d \in Directions
    /\ st.faultState[d] = "Frozen"
    /\ st.risk[d] = "Cleared"
    /\ st' = [st EXCEPT
                 !.faultState[d] = "Distributed",
                 !.distribution[d] = st.held[d],
                 !.bondState = [o \in Operators |->
                     IF o \in st.held[d] THEN "Distributed"
                     ELSE st.bondState[o]]]
    /\ UNCHANGED objectiveSource

(***************************************************************************
Deliberate single-defect actions used by separate TLC configurations.
They are absent from the baseline Next relation.
***************************************************************************)
ReplayPromotion(d) ==
    /\ d \in Directions
    /\ st.promotionCount[d] = 1
    /\ st.promotionCount[d] < 2
    /\ st' = [st EXCEPT !.promotionCount[d] = @ + 1]
    /\ UNCHANGED objectiveSource

ReplayFinal(d) ==
    /\ d \in Directions
    /\ st.liability[d] = "Settled"
    /\ st.finalCount[d] = 1
    /\ st' = [st EXCEPT !.finalCount[d] = @ + 1]
    /\ UNCHANGED objectiveSource

BaselineAction ==
    \/ \E d \in Directions : RecordSourceInflow(d)
    \/ \E d \in Directions : FinalizeLocalInflow(d)
    \/ \E d \in Directions : OpenLiability(d)
    \/ \E d \in Directions : ReserveRelease(d)
    \/ \E c \in Chains : AdvanceBlock(c)
    \/ \E d \in Directions : FinalizeRelease(d, TRUE, TRUE)
    \/ \E d \in Directions : CancelRelease(d, TRUE)
    \/ \E d \in Directions : PromoteSettledSource(d)
    \/ \E d \in Directions : MatureRisk(d)
    \/ \E d \in Directions : ClearRisk(d, TRUE)
    \/ \E d \in Directions : FreezeFault(d, TRUE)
    \/ \E c \in Chains : PauseChain(c, TRUE)
    \/ \E d \in Directions : DistributeFaultCollateral(d)

Next == BaselineAction /\ UNCHANGED honestStep

NextEarlyFinalize ==
    (BaselineAction \/ \E d \in Directions : FinalizeRelease(d, FALSE, TRUE))
    /\ UNCHANGED honestStep
NextUnsafeCancel ==
    (BaselineAction \/ CancelRelease(Fwd, FALSE)) /\ UNCHANGED honestStep
NextDropFinalExposure ==
    (BaselineAction \/ \E d \in Directions : FinalizeRelease(d, TRUE, FALSE))
    /\ UNCHANGED honestStep
NextEarlyClear ==
    (BaselineAction \/ \E d \in Directions : ClearRisk(d, FALSE))
    /\ UNCHANGED honestStep
NextExtraCulprit ==
    (BaselineAction \/ \E d \in Directions : FreezeFault(d, FALSE))
    /\ UNCHANGED honestStep
NextGlobalPause ==
    (BaselineAction \/ \E c \in Chains : PauseChain(c, FALSE))
    /\ UNCHANGED honestStep
NextReplayPromotion ==
    (BaselineAction \/ \E d \in Directions : ReplayPromotion(d))
    /\ UNCHANGED honestStep
NextReplayFinal ==
    (BaselineAction \/ \E d \in Directions : ReplayFinal(d))
    /\ UNCHANGED honestStep

Spec == Init /\ [][Next]_vars
SpecEarlyFinalize == Init /\ [][NextEarlyFinalize]_vars
SpecUnsafeCancel == Init /\ [][NextUnsafeCancel]_vars
SpecDropFinalExposure == Init /\ [][NextDropFinalExposure]_vars
SpecEarlyClear == Init /\ [][NextEarlyClear]_vars
SpecExtraCulprit == Init /\ [][NextExtraCulprit]_vars
SpecGlobalPause == Init /\ [][NextGlobalPause]_vars
SpecReplayPromotion == Init /\ [][NextReplayPromotion]_vars
SpecReplayFinal == Init /\ [][NextReplayFinal]_vars

(***************************************************************************
Deterministic honest V2 round-trip harness.  It uses exactly the same actions
as the baseline, including a separate block advance before each finalization.
***************************************************************************)
HonestNext ==
    CASE honestStep = 0 -> RecordSourceInflow(Fwd) /\ honestStep' = 1
      [] honestStep = 1 -> FinalizeLocalInflow(Fwd) /\ honestStep' = 2
      [] honestStep = 2 -> OpenLiability(Fwd) /\ honestStep' = 3
      [] honestStep = 3 -> ReserveRelease(Fwd) /\ honestStep' = 4
      [] honestStep = 4 -> AdvanceBlock(Mob) /\ honestStep' = 5
      [] honestStep = 5 -> FinalizeRelease(Fwd, TRUE, TRUE) /\ honestStep' = 6
      [] honestStep = 6 -> PromoteSettledSource(Fwd) /\ honestStep' = 7
      [] honestStep = 7 -> RecordSourceInflow(Rev) /\ honestStep' = 8
      [] honestStep = 8 -> FinalizeLocalInflow(Rev) /\ honestStep' = 9
      [] honestStep = 9 -> OpenLiability(Rev) /\ honestStep' = 10
      [] honestStep = 10 -> ReserveRelease(Rev) /\ honestStep' = 11
      [] honestStep = 11 -> AdvanceBlock(Eth) /\ honestStep' = 12
      [] honestStep = 12 -> FinalizeRelease(Rev, TRUE, TRUE) /\ honestStep' = 13
      [] honestStep = 13 -> PromoteSettledSource(Rev) /\ honestStep' = 14
      [] honestStep = 14 -> MatureRisk(Fwd) /\ honestStep' = 15
      [] honestStep = 15 -> ClearRisk(Fwd, TRUE) /\ honestStep' = 16
      [] honestStep = 16 -> MatureRisk(Rev) /\ honestStep' = 17
      [] honestStep = 17 -> ClearRisk(Rev, TRUE) /\ honestStep' = 18
      [] OTHER -> UNCHANGED vars

HonestSpec == HonestInit /\ [][HonestNext]_vars

(***************************************************************************
Safety invariants.
***************************************************************************)
TypeOK ==
    /\ objectiveSource \in [Directions -> BOOLEAN]
    /\ st.sourceState \in [Directions -> SourceStates]
    /\ st.sourceFinal \in [Directions -> BOOLEAN]
    /\ st.sourceRecordHistory \subseteq Directions
    /\ st.liability \in [Directions -> LiabilityStates]
    /\ st.claim \in [Directions -> ClaimStates]
    /\ st.lotState \in [Lots -> LotStates]
    /\ st.lotRes \in [Lots -> ReservationIds \cup {NoRes}]
    /\ st.nullState \in [Directions -> NullifierStates]
    /\ st.nullRes \in [Directions -> ReservationIds \cup {NoRes}]
    /\ st.nullFinal \in [Directions -> Directions \cup {NoDir}]
    /\ st.leaseState \in LeaseStates
    /\ st.leaseRes \in ReservationIds \cup {NoRes}
    /\ st.resState \in [ReservationIds -> ReservationStates]
    /\ st.liveRes \in [Directions -> ReservationIds \cup {NoRes}]
    /\ st.finalRes \in [Directions -> ReservationIds \cup {NoRes}]
    /\ st.nextAttempt \in [Directions -> Attempts]
    /\ st.risk \in [Directions -> RiskStates]
    /\ st.riskMature \in [Directions -> BOOLEAN]
    /\ st.exposure \in [Directions -> BOOLEAN]
    /\ st.reserveHeight \in [Directions -> NoHeight..MaxHeight]
    /\ st.finalHeight \in [Directions -> NoHeight..MaxHeight]
    /\ st.blockHeight \in [Chains -> 0..MaxHeight]
    /\ st.reservationHistory \subseteq ReservationIds
    /\ st.cancelHistory \subseteq ReservationIds
    /\ st.finalCount \in [Directions -> 0..2]
    /\ st.promotionCount \in [Directions -> 0..2]
    /\ st.clearHistory \in [Directions -> BOOLEAN]
    /\ st.paused \in [Chains -> BOOLEAN]
    /\ st.pauseCause \in [Chains -> Chains \cup {NoChain}]
    /\ st.faultState \in [Directions -> FaultStates]
    /\ st.held \in [Directions -> SUBSET Operators]
    /\ st.distribution \in [Directions -> SUBSET Operators]
    /\ st.bondState \in [Operators -> BondStates]
    /\ honestStep \in 0..18

ClaimLifecycleSound ==
    \A d \in Directions :
      /\ (st.liability[d] = "Absent" <=> st.claim[d] = "Unbound")
      /\ (st.liability[d] \in {"Open", "CapacityReserved"}
          => st.claim[d] = "Bound")
      /\ (st.liability[d] = "Settled" => st.claim[d] = "Settled")

SourceLotProjection ==
    /\ \A d \in Directions :
         st.sourceState[d] # "Absent" => d \in st.sourceRecordHistory
    /\ \A d \in Directions :
         /\ (st.sourceState[d] = "Absent" <=>
               st.lotState[SourceLot(d)] = "Absent")
         /\ (st.sourceState[d] = "Encumbered" <=>
               st.lotState[SourceLot(d)] = "Encumbered")
         /\ (st.sourceState[d] = "Available" <=>
               st.lotState[SourceLot(d)] \in
                 {"Available", "ReservedIntent", "Spent"})

ReservationAtomic ==
    /\ \A d \in Directions :
       st.liability[d] = "CapacityReserved" =>
         LET rid == st.liveRes[d]
             lot == BackingLot(d)
         IN  /\ rid \in ReservationIds
             /\ st.resState[rid] = "Live"
             /\ st.lotState[lot] = "ReservedIntent"
             /\ st.lotRes[lot] = rid
             /\ st.nullState[d] = "Reserved"
             /\ st.nullRes[d] = rid
             /\ st.risk[d] = "CapacityReserved"
             /\ st.exposure[d]
             /\ (UsesMobileLease(d) =>
                   /\ st.leaseState = "Live"
                   /\ st.leaseRes = rid)
    /\ \A d \in Directions :
         st.liveRes[d] # NoRes => st.liability[d] = "CapacityReserved"
    /\ \A d1, d2 \in Directions :
         d1 # d2 /\ st.liveRes[d1] # NoRes /\ st.liveRes[d2] # NoRes
         => st.liveRes[d1] # st.liveRes[d2]

PriorBlockReservation ==
    \A d \in Directions :
      st.finalCount[d] > 0 =>
        /\ st.finalRes[d] \in ReservationIds
        /\ st.reserveHeight[d] < st.finalHeight[d]

AtomicFinalCommit ==
    \A d \in Directions :
      st.liability[d] = "Settled" =>
        LET rid == st.finalRes[d]
            lot == BackingLot(d)
        IN  /\ rid \in ReservationIds
            /\ st.resState[rid] = "Finalized"
            /\ st.liveRes[d] = NoRes
            /\ st.lotState[lot] = "Spent"
            /\ st.lotRes[lot] = rid
            /\ st.nullState[d] = "Consumed"
            /\ st.nullRes[d] = rid
            /\ st.nullFinal[d] = d
            /\ st.finalCount[d] = 1
            /\ st.risk[d] \in {"FinalizedUncleared", "Cleared"}
            /\ (UsesMobileLease(d) =>
                  /\ st.leaseState = "Consumed"
                  /\ st.leaseRes = rid)

SafeCancellation ==
    \A d \in Directions :
      st.risk[d] = "Cancelled" =>
        /\ st.liability[d] = "Open"
        /\ st.claim[d] = "Bound"
        /\ st.liveRes[d] = NoRes
        /\ st.lotState[BackingLot(d)] = "Available"
        /\ st.lotRes[BackingLot(d)] = NoRes
        /\ st.nullState[d] = "Free"
        /\ st.nullRes[d] = NoRes
        /\ (UsesMobileLease(d) =>
              /\ st.leaseState = "Free"
              /\ st.leaseRes = NoRes)

HistoryAndReplaySound ==
    /\ \A r \in ReservationIds :
         (st.resState[r] # "Absent") <=> (r \in st.reservationHistory)
    /\ st.cancelHistory \subseteq st.reservationHistory
    /\ \A d \in Directions : st.finalCount[d] <= 1
    /\ \A d \in Directions : st.promotionCount[d] <= 1

FinalizedUnclearedRetained ==
    \A d \in Directions :
      /\ (st.exposure[d] <=>
            st.risk[d] \in {"CapacityReserved", "FinalizedUncleared"})
      /\ (st.clearHistory[d] =>
            /\ st.riskMature[d]
            /\ st.risk[d] = "Cleared")
      /\ (st.finalCount[d] = 1 /\ ~st.clearHistory[d]
          => st.risk[d] = "FinalizedUncleared")

ChainLocalPauseSound ==
    \A c \in Chains : st.paused[c] => st.pauseCause[c] = c

ExactCulpritPenalty ==
    /\ \A d \in Directions :
         st.faultState[d] \in {"Frozen", "Distributed"}
         => st.held[d] = ExactCulprits(d)
    /\ \A d \in Directions :
         st.faultState[d] = "Distributed" =>
           /\ st.risk[d] = "Cleared"
           /\ st.distribution[d] = ExactCulprits(d)
           /\ \A o \in ExactCulprits(d) : st.bondState[o] = "Distributed"
    /\ \A d \in Directions : Cardinality(st.held[d]) =
         IF st.faultState[d] = "None" THEN 0 ELSE 3

HonestRoundTripDone ==
    /\ honestStep = 18
    /\ \A d \in Directions :
         /\ st.liability[d] = "Settled"
         /\ st.claim[d] = "Settled"
         /\ st.nullState[d] = "Consumed"
         /\ st.finalCount[d] = 1
         /\ st.promotionCount[d] = 1
         /\ st.risk[d] = "Cleared"
         /\ ~st.exposure[d]
    /\ st.lotState[PreseedEusd] = "Spent"
    /\ st.sourceState[Fwd] = "Available"
    /\ st.sourceState[Rev] = "Available"
    /\ st.lotState[UsdcDeposit] = "Spent"
    /\ st.lotState[EusdReturn] = "Available"
    /\ st.leaseState = "Consumed"

FullCycleConservation == honestStep = 18 => HonestRoundTripDone

BaselineSafety ==
    /\ TypeOK
    /\ ClaimLifecycleSound
    /\ SourceLotProjection
    /\ ReservationAtomic
    /\ PriorBlockReservation
    /\ AtomicFinalCommit
    /\ SafeCancellation
    /\ HistoryAndReplaySound
    /\ FinalizedUnclearedRetained
    /\ ChainLocalPauseSound
    /\ ExactCulpritPenalty

HonestCycleSafety ==
    /\ BaselineSafety
    /\ FullCycleConservation

NoHonestRoundTrip == ~HonestRoundTripDone
FalseSourceReleaseSeen ==
    \E d \in Directions : st.finalCount[d] = 1 /\ ~objectiveSource[d]
NoFalseSourceRelease == ~FalseSourceReleaseSeen

=============================================================================
