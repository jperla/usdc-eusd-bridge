--------------------- MODULE AccessStructure ---------------------
(***************************************************************************)
(* Who can authorize a release, as a function of role overlap.              *)
(*                                                                          *)
(* CompositeGate answers "does a pause bind?". This answers the prior       *)
(* question: how many distinct principals must be compromised to satisfy    *)
(* BOTH thresholds? An earlier attempt bolted a cardinality constraint onto *)
(* CompositeGate and claimed to have machine-checked the overlap theorem.   *)
(* It had not: a counting constraint is not the same as principals holding  *)
(* both role shares, which is the load-bearing assumption.                  *)
(*                                                                          *)
(*     Authorized(S)  iff  |S cap Owners| >= K  AND  |S cap Gates| >= Ga    *)
(*                                                                          *)
(* under the assumption that compromising principal p yields control of     *)
(* BOTH of p's role shares. The claim under test, with r = |Owners cap      *)
(* Gates|:                                                                  *)
(*                                                                          *)
(*     T = max(K, Ga, K + Ga - r)                                           *)
(*                                                                          *)
(* is the minimum size of an authorizing coalition, and it is TIGHT.        *)
(* Full overlap gives T = max(K,Ga); disjoint roles give T = K + Ga.        *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Principals,     \* every distinct control/failure domain
    Owners,         \* principals holding an owner share
    Gates,          \* principals holding a gate share
    K, Ga           \* the two thresholds

VARIABLES coalition   \* the compromised set

vars == <<coalition>>

TypeOK == coalition \subseteq Principals

\* Enumerate every coalition. TLC explores all of them as initial states.
Init == coalition \in SUBSET Principals
Next == UNCHANGED coalition

Spec == Init /\ [][Next]_vars

-------------------------------------------------------------------------
Authorized(S) ==
    /\ Cardinality(S \cap Owners) >= K
    /\ Cardinality(S \cap Gates) >= Ga

Overlap == Cardinality(Owners \cap Gates)

Max3(a, b, c) ==
    LET m == IF a > b THEN a ELSE b IN IF m > c THEN m ELSE c

\* The claimed minimum coalition size.
T == Max3(K, Ga, K + Ga - Overlap)

-------------------------------------------------------------------------
(*                              INVARIANTS                                *)

\* THE THEOREM. No coalition smaller than T can authorize.
INV_MinCoalitionIsT ==
    Authorized(coalition) => Cardinality(coalition) >= T

-------------------------------------------------------------------------
(*                       COVERAGE ASSERTIONS                              *)

\* ...and T is ACHIEVABLE, so the bound is tight rather than merely an upper
\* limit. Written to FAIL: TLC violating it exhibits an authorizing coalition
\* of exactly size T.
COV_TIsAchievable == ~(Authorized(coalition) /\ Cardinality(coalition) = T)

\* Some coalition authorizes at all, or the invariant is vacuous.
COV_SomethingAuthorizes == ~Authorized(coalition)
=========================================================================
