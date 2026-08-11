--------------------- MODULE AuditObservability ---------------------
(***************************************************************************)
(* Which auditor can tell that an unauthorized bridge spend happened?       *)
(*                                                                          *)
(* REBUILT. The first version was a tautology: one state variable, a        *)
(* Distinguishes operator returning a boolean over capability CONSTANTS,    *)
(* and an invariant reducing to TRUE => TRUE. TLC confirmed only that the   *)
(* runner printed the table I had written by hand.                          *)
(*                                                                          *)
(* This version is a real two-world (self-composed) hyperproperty. Two      *)
(* worlds are explored simultaneously and nondeterministically. V is        *)
(* DERIVED from each world's contents rather than assigned. TLC searches    *)
(* for a pair of worlds with EQUAL observations and DIFFERENT V -- which is *)
(* exactly a proof that the observer cannot distinguish them.               *)
(*                                                                          *)
(*     INV_Observational ==                                                 *)
(*         Obs(O, h0) = Obs(O, h1)  =>  V(h0) = V(h1)                       *)
(*                                                                          *)
(* Violated  => that observer class is INSUFFICIENT (TLC exhibits the pair) *)
(* Clean     => no such pair exists in the model; the class suffices        *)
(*                                                                          *)
(* CORRECTION, and it matters beyond this model. An earlier version said    *)
(* that sorting makes an F-derived key image and an unrelated one identical *)
(* on chain. That is WRONG. Finalized blocks expose concrete key-image      *)
(* VALUES; independent sorting erases transaction GROUPING, not bytes. The  *)
(* two key images are distinct values that a public observer cannot LABEL,  *)
(* which is a computational unlinkability (DDH) property, not a consequence *)
(* of sorting.                                                              *)
(*                                                                          *)
(* So the chain projection below IMPORTS that unlinkability as an           *)
(* assumption by omitting the link. It does not derive it. Saying otherwise *)
(* was assuming the thing and presenting the assumption as a result.        *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Predicate,      \* "wasFOutputSpent" | "wasAuthorizedRelease"
    HasAF,          \* holds the F-output view private scalar
    HasCatalog,     \* complete, proof-valid (F output -> canonical key image)
    HasDeposits,    \* independent finalized Ethereum deposit view
    HasIntent,      \* append-only preauthorized exact intent
    HasLogs         \* operator records, which a colluding quorum may withhold

VARIABLES
    finalized,      \* the block containing the key image is final in both worlds
    \* --- world 0 ---
    fSpend0,        \* the finalized key image consumed an F output
    auth0,          \* a matching deposit and authorization exist for it
    traffic0,       \* ordinary unrelated activity, nondeterministic
    \* --- world 1 ---
    fSpend1, auth1, traffic1

vars == <<finalized, fSpend0, auth0, traffic0, fSpend1, auth1, traffic1>>

TypeOK ==
    /\ finalized \in BOOLEAN
    /\ fSpend0 \in BOOLEAN /\ auth0 \in BOOLEAN /\ traffic0 \in 0..2
    /\ fSpend1 \in BOOLEAN /\ auth1 \in BOOLEAN /\ traffic1 \in 0..2

(* Both worlds are free. TLC will look for the adversarial pair itself.     *)
Init ==
    /\ finalized = FALSE
    /\ fSpend0 \in BOOLEAN /\ auth0 \in BOOLEAN /\ traffic0 \in 0..2
    /\ fSpend1 \in BOOLEAN /\ auth1 \in BOOLEAN /\ traffic1 \in 0..2

Finalize == /\ ~finalized /\ finalized' = TRUE
            /\ UNCHANGED <<fSpend0, auth0, traffic0, fSpend1, auth1, traffic1>>

Next == Finalize

Spec == Init /\ [][Next]_vars

-------------------------------------------------------------------------
(*                      THE VIOLATION PREDICATE, DERIVED                   *)

\* "was a known F output spent?" -- the narrow question.
\* "was this an authorized release?" -- the one the bridge actually needs.
V(fs, au) ==
    IF Predicate = "wasFOutputSpent" THEN fs ELSE (fs /\ ~au)

-------------------------------------------------------------------------
(*                        THE OBSERVATION PROJECTION                       *)

\* Chain-only: ordinary traffic, and nothing that reveals what a key image
\* consumed. fSpend is deliberately ABSENT. That omission IMPORTS the
\* computational unlinkability assumption stated in the header -- it is not
\* derived from sorting, and an earlier version of this comment wrongly said
\* it was a verified fact rather than an imported abstraction.
\*
\* a_F adds F-output inventory and amounts. It does NOT add fSpend, because
\* computing a key image needs the spend-private scalar, which a_F is not.
\* So it contributes nothing to this projection -- which is the finding.
\*
\* ASSUMED ORACLE PROJECTION. A complete catalogue is modelled as exposing
\* fSpend directly, so the catalogue/source-spend row below is a CONDITIONAL
\* PROJECTION SELF-CHECK rather than a derived sufficiency result. What is
\* genuinely derived here are the INSUFFICIENCY counterexamples.
\*
\* Deposits plus intent reveal whether a matching authorization existed: auth.
\*
\* Logs would reveal both, when they exist at all.
Obs(fs, au, tr) ==
    << tr,
       IF HasCatalog \/ HasLogs THEN fs ELSE 0,
       IF (HasDeposits /\ HasIntent) \/ HasLogs THEN au ELSE 0 >>

-------------------------------------------------------------------------
(*                             THE PROPERTY                                *)

INV_Observational ==
    finalized =>
        (Obs(fSpend0, auth0, traffic0) = Obs(fSpend1, auth1, traffic1)
            => V(fSpend0, auth0) = V(fSpend1, auth1))

-------------------------------------------------------------------------
(*                       COVERAGE ASSERTIONS                              *)
(* Written to FAIL. These check that the interesting CONFIGURATIONS are    *)
(* reachable, not merely that some state is.                               *)

\* the two worlds genuinely differ in the thing being audited
COV_VDiffers == ~(finalized /\ V(fSpend0, auth0) # V(fSpend1, auth1))
\* an F output really was spent covertly in one world
COV_CovertSpend == ~(finalized /\ fSpend0 /\ ~auth0)
\* the worlds are publicly identical while differing underneath
COV_EqualTraffic == ~(finalized /\ traffic0 = traffic1 /\ fSpend0 # fSpend1)
\* a spend that WAS authorized, so V is not trivially equal to fSpend
COV_AuthorizedSpend == ~(finalized /\ fSpend0 /\ auth0)

=========================================================================
