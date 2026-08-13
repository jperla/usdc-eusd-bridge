-------------------------- MODULE SubsetRetry -------------------------
(***************************************************************************)
(* A BOUNDED SUBSET-EXHAUSTION LEMMA. Not a liveness proof.                 *)
(*                                                                          *)
(* Renamed after review. `Spec == Init /\ [][Next]_vars` carries no WF/SF   *)
(* fairness and permits infinite stuttering, and INV_BoundedAttempts is a   *)
(* safety implication over a counter, not <>done. Attempt() also resolves   *)
(* success and failure atomically, so delivery, crash, coordinator          *)
(* scheduling and late messages are all absent. What follows is a           *)
(* combinatorial bound under those assumptions, and nothing more.           *)
(*                                                                          *)
(* The exact bound is C(n,k) - C(n-f,k) + 1. For an 8-of-11 roster that is  *)
(* 121, 157 or 165 attempts for one, two or three permanent withholders --  *)
(* a finite sequence of that many timeouts is operationally a stall. Exact  *)
(* failed-subset non-retry is a valid fallback invariant, not the           *)
(* load-bearing scheduler. ROAST is the design target.                      *)
(*                                                                          *)
(* This question is forced by two earlier results. NonceSlot.tla shows that *)
(* every abort after commitment exposure must BURN the slot -- that is a    *)
(* safety requirement, not a preference. And standard FROST is not robust:  *)
(* a participant selected into a signing package can withhold its share and *)
(* force an abort. Together those mean an operator can make the bridge      *)
(* spend slots without producing signatures.                                *)
(*                                                                          *)
(* Slots themselves are not scarce -- a signer can always derive a fresh    *)
(* nonce. What is scarce is ATTEMPTS: each costs a round trip and a         *)
(* timeout. So the property that matters is whether the number of attempts  *)
(* needed to complete one release is BOUNDED.                               *)
(*                                                                          *)
(* On attribution, corrected in review. Over authenticated channels the     *)
(* coordinator DOES know which selected identities failed to answer. What a *)
(* timeout cannot establish is WHY -- malice, crash, censorship, partition  *)
(* or delay. Three separate notions: local identification of a             *)
(* nonresponder (available); transferable evidence of nonperformance        *)
(* (needs a stated delivery/synchrony assumption); proof of intent (not     *)
(* available). The subset bound below is therefore a fallback invariant,    *)
(* not a claim that responsibility is unknowable.                           *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Participants,       \* the roster
    Faulty,             \* those who withhold (unknown to the coordinator)
    K,                  \* threshold
    MaxAttempts,        \* bound, to keep the model finite

    GuardExcludeOnTimeout   \* a timed-out subset is not retried unchanged

VARIABLES
    attempts,       \* how many signing attempts have been made
    tried,          \* subsets already attempted and failed
    done,           \* a release completed
    suspected       \* participants excluded from future subsets

vars == <<attempts, tried, done, suspected>>

Subsets == {S \in SUBSET Participants : Cardinality(S) = K}

TypeOK ==
    /\ attempts \in 0..MaxAttempts
    /\ tried \subseteq Subsets
    /\ done \in BOOLEAN
    /\ suspected \subseteq Participants

Init ==
    /\ attempts = 0
    /\ tried = {}
    /\ done = FALSE
    /\ suspected = {}

(* The coordinator selects a k-subset and runs a ceremony. If every member  *)
(* answers, the release completes. If any member withholds, the attempt     *)
(* aborts and the slot burns. This model deliberately excludes SUBSETS      *)
(* rather than participants -- a conservative fallback that does not rely   *)
(* on any timeout policy. It is not a claim that the nonresponder is        *)
(* unidentifiable; see the header.                                          *)
Attempt(S) ==
    /\ ~done
    /\ attempts < MaxAttempts
    /\ S \cap suspected = {}
    /\ GuardExcludeOnTimeout => S \notin tried
    /\ attempts' = attempts + 1
    /\ IF S \cap Faulty = {}
         THEN /\ done' = TRUE
              /\ UNCHANGED <<tried, suspected>>
         ELSE /\ done' = FALSE
              /\ tried' = tried \cup {S}
              /\ UNCHANGED suspected

Next == \E S \in Subsets : Attempt(S)

Spec == Init /\ [][Next]_vars

-------------------------------------------------------------------------
(*                              INVARIANTS                                *)

(* Every k-subset drawn entirely from honest participants. If one of these  *)
(* exists, a release is possible at all.                                    *)
GoodSubsets == {S \in Subsets : S \cap Faulty = {}}

\* PROGRESS IS POSSIBLE AT ALL. Requires enough honest participants to fill
\* a subset -- i.e. |Participants| - |Faulty| >= K. This is a fact about the
\* roster, not about the protocol.
INV_ProgressPossible == GoodSubsets # {}

\* THE BOUND. With subset exclusion, the coordinator can exhaust the failing
\* subsets and must reach a good one; the attempt count is bounded by the
\* number of subsets touching a faulty member, plus one. Without exclusion it
\* may retry the same failing subset indefinitely, and the model reaches
\* MaxAttempts without completing.
INV_BoundedAttempts ==
    (attempts >= MaxAttempts) => done

-------------------------------------------------------------------------
(*                       COVERAGE ASSERTIONS                              *)
(* Written to FAIL. A pass means that state is unreachable and any clean    *)
(* result is worthless.                                                     *)

COV_CanComplete == ~done
COV_CanFail     == tried = {}

=========================================================================
