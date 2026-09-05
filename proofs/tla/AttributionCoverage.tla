--------------------- MODULE AttributionCoverage ---------------------------
(***************************************************************************)
(* Bounded structural analysis of attribution slots and real principals.   *)
(* The artifact sees slot names; the model explores hidden key/share       *)
(* ownership assignments. Cryptography, audit and funding are not actions  *)
(* here. Successful artifact validation is a PREMISE, not a result.        *)
(*                                                                         *)
(* Distinct keys do not establish distinct entities. A linked proof of     *)
(* knowledge of an identity secret and share also does not establish that  *)
(* ONE principal holds both: separate parties can jointly produce the      *)
(* responses. Consequently EndorserHoldsShare is a CO-LOCATION ASSUMPTION, *)
(* not an implementation theorem established by ceremony::endorse_seat.    *)
(* The implementation tests establish that either secret alone cannot      *)
(* produce the proof, a different and useful property.                     *)
(*                                                                         *)
(* NoRetainedCopies separately assumes nobody retained additional shares. *)
(* A stronger ceremony/process may justify these ownership premises; the  *)
(* public endorsement alone does not discharge them.                       *)
(* Quorums also assumes independent share material: a share cannot reveal   *)
(* another seat's share. SpecCorrelatedShares explicitly drops this        *)
(* premise for the owner cohort, as with p(x) = b*(1+x).                    *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS OwnerSeats, GateSeats, Principals, CohortKeys, NoOne,
          OwnerT, GateT, CompromiseT,
          AttributionPerSeat,
          MaxKeysPerPrincipal,
          NoRetainedCopies,
          EndorserHoldsShare

Seats == OwnerSeats \cup GateSeats
AttributedKeys == IF AttributionPerSeat THEN Seats ELSE CohortKeys

ASSUME OwnerSeats \cap GateSeats = {}
ASSUME NoOne \notin Principals
ASSUME OwnerT >= 1 /\ GateT >= 1 /\ CompromiseT >= 1
ASSUME Cardinality(OwnerSeats) >= OwnerT /\ Cardinality(GateSeats) >= GateT
ASSUME MaxKeysPerPrincipal >= 1
ASSUME Cardinality(Principals) * MaxKeysPerPrincipal >= Cardinality(AttributedKeys)

KeysHeldBy(f, p) == Cardinality({k \in DOMAIN f : f[k] = p})

VARIABLES seatHolder, nameHolder, retainer, spend
vars == <<seatHolder, nameHolder, retainer, spend>>
NoSpend == [seats |-> {}, by |-> {}]

NameHolders ==
    {f \in [AttributedKeys -> Principals] :
        \A p \in Principals : KeysHeldBy(f, p) <= MaxKeysPerPrincipal}

\* This equality is the premise needed for the guarantee, not a conclusion
\* from a linked sigma proof. If identity and share owners collaborate on a
\* proof while retaining separate secrets, use EndorserHoldsShare = FALSE.
SeatHolders(nh) ==
    IF AttributionPerSeat /\ EndorserHoldsShare
      THEN {[s \in Seats |-> nh[s]]}
      ELSE [Seats -> Principals]

Retainers ==
    IF NoRetainedCopies
      THEN {[owners |-> NoOne, gates |-> NoOne]}
      ELSE [owners: Principals \cup {NoOne}, gates: Principals \cup {NoOne}]

TypeOK ==
    /\ nameHolder \in [AttributedKeys -> Principals]
    /\ seatHolder \in [Seats -> Principals]
    /\ retainer \in [owners: Principals \cup {NoOne}, gates: Principals \cup {NoOne}]
    /\ spend \in [seats: SUBSET Seats, by: SUBSET Principals]

Init ==
    /\ nameHolder \in NameHolders
    /\ seatHolder \in SeatHolders(nameHolder)
    /\ retainer \in Retainers
    /\ spend = NoSpend

RetainerFor(s) == IF s \in OwnerSeats THEN retainer.owners ELSE retainer.gates
Holders(s) ==
    {seatHolder[s]} \cup (IF RetainerFor(s) = NoOne THEN {} ELSE {RetainerFor(s)})

Quorums ==
    {os \cup gs :
        os \in {x \in SUBSET OwnerSeats : Cardinality(x) >= OwnerT},
        gs \in {y \in SUBSET GateSeats : Cardinality(y) >= GateT}}

SpendUsing(quorums) ==
    /\ spend = NoSpend
    /\ \E q \in quorums :
         \E c \in SUBSET Principals :
           /\ \A s \in q : Holders(s) \cap c # {}
           \* Prune irrelevant members; padding cannot violate a lower bound.
           /\ \A p \in c : \E s \in q : p \in Holders(s)
           /\ spend' = [seats |-> q, by |-> c]
    /\ UNCHANGED <<seatHolder, nameHolder, retainer>>

Spend == SpendUsing(Quorums)
Next == Spend \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

\* One owner's share can recover the owner polynomial when its coefficients
\* have a known relation. Distinct named holders and no retained copies do
\* not prevent this. The gate cohort retains its ordinary threshold here.
CorrelatedQuorums ==
    {os \cup gs :
        os \in {x \in SUBSET OwnerSeats : Cardinality(x) >= 1},
        gs \in {y \in SUBSET GateSeats : Cardinality(y) >= GateT}}
CorrelatedNext == SpendUsing(CorrelatedQuorums) \/ UNCHANGED vars
SpecCorrelatedShares == Init /\ [][CorrelatedNext]_vars

\* A statement about real coalition size, conditional on ownership premises.
INV_SpendNeedsThresholdPrincipals ==
    spend.seats # {} => Cardinality(spend.by) >= CompromiseT

\* Counts attribution SLOTS, neither key values nor real entities.
INV_AttributedKeysMeetThreshold ==
    Cardinality(AttributedKeys) >= CompromiseT

\* Specific adversarial stand-in. The runner refutes this predicate at
\* MaxKeysPerPrincipal = 2, CompromiseT = 2, where the actual guarantee holds.
\* No finite configuration matrix excludes all constants-only stand-ins.
FAKE_ConstantsOnlyGuarantee ==
    /\ AttributionPerSeat
    /\ NoRetainedCopies
    /\ EndorserHoldsShare
    /\ MaxKeysPerPrincipal * CompromiseT <= OwnerT + GateT

COV_CanSpend == spend.seats = {}
COV_TightCoalition ==
    ~(spend.seats # {} /\ Cardinality(spend.by) = CompromiseT)

\* One way to violate the guarantee, not its converse: retained copies and
\* two keys behind one controller can weaken it without collapsing a cohort.
COV_ForgeryShape ==
    ~(/\ \E p \in Principals : \A s \in OwnerSeats : seatHolder[s] = p
      /\ spend.seats # {})
=============================================================================
