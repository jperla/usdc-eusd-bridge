--------------------- MODULE CompositeGate ---------------------
(***************************************************************************)
(* Can a Phase-A pause be enforced against a colluding owner threshold      *)
(* WITHOUT a MobileCoin consensus change?                                   *)
(*                                                                          *)
(* Two separate results converged on this question. The freeze analysis     *)
(* found that an instruction to pause binds only honest signers, because    *)
(* consensus cannot distinguish threshold signing and carries no mandatory  *)
(* certificate. CatalogIntegrity found that its own Spend action assumes an *)
(* administrative admission gate that consensus does not enforce -- the     *)
(* same gap from the other side.                                            *)
(*                                                                          *)
(* The candidate: a composite spend root                                    *)
(*                                                                          *)
(*     B = B_owner + B_gate                                                 *)
(*                                                                          *)
(* with access (k-of-n owners) AND (g-of-m independent gates).              *)
(*                                                                          *)
(* What makes this different from every other "add an approver" scheme is   *)
(* WHERE the gate's contribution lands. The MLSAG key image is I = x*Hp(P), *)
(* and under a composite root the one-time scalar x carries both shares. So *)
(* an indispensable gate share is not a signature that a coordinator may    *)
(* choose to collect -- it is an input to a value consensus already checks. *)
(* Omitting it does not produce an unauthorized spend; it produces no valid *)
(* spend at all.                                                            *)
(*                                                                          *)
(* This model exists to show that the DISTINCTION is load-bearing: a        *)
(* detached signature or an advisory coordinator policy is bypassable by    *)
(* exactly the party the gate is meant to constrain.                        *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Owners, Gates,
    K,              \* owner threshold
    G,              \* gate threshold
    GateMode,       \* "indispensable" | "offChainOnly"
    GatesIndependent, \* are the gates outside the owners' control?
    SharedPool        \* do BOTH roles come from the same party set?

VARIABLES
    ownerShares,      \* owners who contributed a share
    gateShares,       \* gates who contributed a share
    paused,           \* the auditor has raised an alarm and paused
    finalized,        \* a spend finalized on MobileCoin
    gateQuorumAtPause, \* the GATE quorum was already reached when paused
    finalizedAfterPause, \* the spend finalized STRICTLY AFTER the pause
    ownerQuorumAtPause  \* the OWNER quorum was already complete when paused

vars == <<ownerShares, gateShares, paused, finalized, gateQuorumAtPause,
          finalizedAfterPause, ownerQuorumAtPause>>

TypeOK ==
    /\ ownerShares \subseteq Owners
    /\ gateShares \subseteq Gates
    /\ paused \in BOOLEAN
    /\ finalized \in BOOLEAN
    /\ gateQuorumAtPause \in BOOLEAN
    /\ finalizedAfterPause \in BOOLEAN
    /\ ownerQuorumAtPause \in BOOLEAN

Init ==
    /\ ownerShares = {}
    /\ gateShares = {}
    /\ paused = FALSE
    /\ finalized = FALSE
    /\ gateQuorumAtPause = FALSE
    /\ finalizedAfterPause = FALSE
    /\ ownerQuorumAtPause = FALSE

(* The owner threshold is assumed COMPROMISED: they contribute whenever     *)
(* they like, including after a pause. That is the whole threat model.      *)
OwnerContribute(o) ==
    /\ o \notin ownerShares
    /\ ownerShares' = ownerShares \cup {o}
    /\ UNCHANGED <<ownerQuorumAtPause, gateShares, paused, finalized, gateQuorumAtPause, finalizedAfterPause>>

(* An independent gate refuses once paused. A gate under owner control does *)
(* not -- which is why independence is a named assumption and not a detail. *)
GateContribute(g) ==
    /\ g \notin gateShares
    \* SHARED POOL: a gate share is held by a party that is also an owner, so
    \* it is available exactly when that party has already acted as an owner.
    \* This is Josh's "3 independent parties" if both roles are drawn from them.
    /\ SharedPool => Cardinality(ownerShares) > Cardinality(gateShares)
    /\ (GatesIndependent /\ paused) => FALSE
    /\ gateShares' = gateShares \cup {g}
    /\ UNCHANGED <<ownerQuorumAtPause, ownerShares, paused, finalized, gateQuorumAtPause, finalizedAfterPause>>

\* Record whether the spend was ALREADY fully authorized at the moment of the
\* pause. A pause cannot recall an authorization that already exists -- which
\* is precisely the P_irrevocable term in the freeze bound, arriving here from
\* the access structure rather than from the Ethereum side.
ConsensusAccepts ==
    /\ Cardinality(ownerShares) >= K
    /\ GateMode = "indispensable" => Cardinality(gateShares) >= G

Pause == /\ ~paused /\ paused' = TRUE
         \* What a pause can withhold is FUTURE gate contributions -- not owner
         \* shares, since the owners are compromised, and not a gate release
         \* that already happened. So the irrevocable quantity is exactly the
         \* set of spends whose GATE QUORUM predates the pause. This is the
         \* P_irrevocable term of the freeze bound, arriving from the access
         \* structure rather than from the Ethereum side.
         /\ gateQuorumAtPause' = (Cardinality(gateShares) >= G)
         /\ ownerQuorumAtPause' = (Cardinality(ownerShares) >= K)
         /\ UNCHANGED <<ownerShares, gateShares, finalized, finalizedAfterPause>>

(* What consensus actually requires to accept the spend.                    *)
(*                                                                          *)
(*  indispensable : the gate share enters the key image / row-0 response,   *)
(*                  so the signature does not verify without it             *)
(*  offChainOnly  : anything consensus does not check -- a detached          *)
(*                  signature or an advisory coordinator policy. These were  *)
(*                  separate values with IDENTICAL transition systems, which *)
(*                  made the model look like it distinguished them when it   *)
(*                  only compared a string against "indispensable". Collapsed*)
(*                  so the model does not appear to derive a distinction it  *)
(*                  never modelled.                                          *)
Finalize ==
    /\ ~finalized
    /\ ConsensusAccepts
    /\ finalized' = TRUE
    /\ finalizedAfterPause' = paused        \* records the ORDERING, not just the fact
    /\ UNCHANGED <<ownerQuorumAtPause, ownerShares, gateShares, paused, gateQuorumAtPause>>

Next ==
    \/ \E o \in Owners : OwnerContribute(o)
    \/ \E g \in Gates : GateContribute(g)
    \/ Pause
    \/ Finalize

Spec == Init /\ [][Next]_vars

-------------------------------------------------------------------------
(*                              INVARIANTS                                *)

\* THE PROPERTY THE DESIGN NEEDS. Once the auditor pauses, a compromised
\* owner threshold cannot finalize a spend.
\* THE PROPERTY. A spend whose gate quorum was NOT already reached when the
\* pause fired can never finalize afterwards.
\* Corrected: `finalized` is monotone, so (paused /\ finalized) cannot
\* distinguish Pause -> Finalize from Finalize -> Pause. The second ordering
\* is a spend that completed BEFORE the pause and is not a violation at all,
\* but it became one when Pause snapshotted gateQuorumAtPause = FALSE. Track
\* the ordering itself.
INV_PauseStopsUnauthorized ==
    finalizedAfterPause => gateQuorumAtPause

\* The gate actually gates: no finalized spend without g gate contributions.
INV_GateWasRequired == finalized => Cardinality(gateShares) >= G

-------------------------------------------------------------------------
(*                       COVERAGE ASSERTIONS                              *)

COV_CanPause     == ~paused
COV_CanFinalize  == ~finalized
\* Owners really can reach their own threshold unaided -- otherwise the
\* model proves nothing about a compromised threshold.
COV_OwnersReachK == Cardinality(ownerShares) < K
\* A pause must be reachable BEFORE finalization, or the property is only
\* holding because the dangerous ordering never occurs.
COV_PauseFirst   == ~(paused /\ ~finalized /\ ~gateQuorumAtPause
                        /\ Cardinality(ownerShares) >= K)
\* The crucial ALLOWED case, corrected. The old predicate recorded only
\* post-pause finalization plus a pre-pause gate quorum, so the owner quorum
\* could have completed BEFORE the pause and the advertised sequence never
\* occurred. This additionally requires that the owner quorum was NOT complete
\* when the pause fired -- i.e. remaining owner work really happened after it.
COV_AllowedLate  == ~(finalizedAfterPause /\ gateQuorumAtPause
                        /\ ~ownerQuorumAtPause)

-------------------------------------------------------------------------
(*        MOVED: the overlap theorem now lives in AccessStructure.tla       *)
(* What follows was a CARDINALITY constraint dressed as the overlap result. *)
(* A counting condition is not the same as principals holding both role     *)
(* shares, which is the load-bearing assumption, so this could not prove    *)
(* the theorem it claimed. AccessStructure.tla models principals and roles  *)
(* directly and checks T = max(K, G, K+G-r) tight across six configurations.*)
(* These are retained only as a coarse sanity check.                        *)
(*                     THE SHARED-POOL SANITY CHECK                        *)
(* Claimed in review and not previously checked: if the same parties hold   *)
(* BOTH roles, a coalition spends iff it reaches max(K,G) -- so the access  *)
(* structure is EXACTLY a max(K,G)-of-n multisig and the two-cohort split   *)
(* provides no benefit at all. This tests that claim rather than asserting  *)
(* it, which is how it was first stated.                                    *)

MaxKG == IF K > G THEN K ELSE G

\* Nothing finalizes below max(K,G) owner contributions.
INV_CollapsesToMax ==
    SharedPool => (finalized => Cardinality(ownerShares) >= MaxKG)

\* ...and max(K,G) is actually SUFFICIENT, so the bound is tight rather than
\* merely an upper limit. Written to FAIL: TLC violating it proves finalizing
\* at exactly max(K,G) is reachable.
COV_ReachesMax ==
    ~(SharedPool /\ finalized /\ Cardinality(ownerShares) = MaxKG)
=========================================================================
