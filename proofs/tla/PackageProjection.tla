-------------------- MODULE PackageProjection --------------------
(***************************************************************************)
(* What durable state must AUTHENTICATE, as opposed to what the response    *)
(* actually depends on.                                                     *)
(*                                                                          *)
(* This migrates the one obligation Ceremony.tla was still carrying, into   *)
(* the slot-centric frame. NonceSlot.tla assumes its `pkg` already denotes  *)
(* the complete security context and stores that exact value, so it cannot  *)
(* express the failure where the ENCODING durable state authenticates is a  *)
(* lossy projection of the thing the response depends on.                   *)
(*                                                                          *)
(* The obligation, from review:                                             *)
(*                                                                          *)
(*     StoredBinding(P) = StoredBinding(Q)                                  *)
(*         =>  ResponseSecurityContext(P) = ResponseSecurityContext(Q)      *)
(*                                                                          *)
(* Modelled operationally rather than as a bare implication, because the    *)
(* consequence is what matters: a slot binds under one package, the process *)
(* restarts, a peer offers a package that AGREES ON THE STORED DIGEST but   *)
(* differs in a response-affecting field, and the signer recomputes. That   *)
(* is a second response on one nonce, which RESULTS 2 and 3 show leaks.     *)
(*                                                                          *)
(* Note this is not covered by the M2b spike. Its reservation digest binds  *)
(* the statement and included set; the complete round-one map enters only   *)
(* the later binding-factor transcript during signing. That shows package   *)
(* changes AFFECT the response -- which is why reuse is dangerous -- not    *)
(* that durable state AUTHENTICATES the exact package.                      *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Statements,     \* the canonical authorization statement
    Subsets,        \* the included signer set
    PeerPkgs,       \* the complete ordered round-one package from peers

    GuardFullProjection   \* the stored encoding covers EVERY response-affecting field

VARIABLES
    isBound,        \* has the slot been bound yet
    bound,          \* the stored binding digest (meaningful when isBound)
    boundCtx,       \* the full context actually bound (ghost, for the property)
    responded,      \* set of full contexts a response was emitted for
    crashed,
    everRestarted,  \* a restart has actually happened
    volatile        \* in-memory context; LOST on crash, rebuilt from durable state

vars == <<isBound, bound, boundCtx, responded, crashed, everRestarted, volatile>>

Ctxs == Statements \X Subsets \X PeerPkgs
\* A same-type collapse value. Using 0 here mixes integers with model values
\* inside a tuple, which TLC rejects on comparison.
Collapsed == CHOOSE p \in PeerPkgs : TRUE

\* THE RESPONSE SECURITY CONTEXT: everything the emitted share depends on.
\* All three components are response-affecting -- the statement through the
\* challenge, the subset through the interpolation factor, and the peer
\* package through the binding factor.
Context(c) == c

\* THE STORED BINDING: what durable state actually authenticates. When the
\* projection is lossy it drops the peer package, which is precisely the
\* field an implementer is most likely to omit because it arrives last and
\* is the bulkiest.
StoredBinding(c) ==
    IF GuardFullProjection THEN <<c[1], c[2], c[3]>>
                           ELSE <<c[1], c[2], Collapsed>>

TypeOK ==
    /\ isBound \in BOOLEAN
    /\ bound \in {StoredBinding(c) : c \in Ctxs}
    /\ boundCtx \in Ctxs
    /\ responded \subseteq Ctxs
    /\ crashed \in BOOLEAN
    /\ everRestarted \in BOOLEAN
    /\ volatile \in BOOLEAN

InitCtx == CHOOSE c \in Ctxs : TRUE

Init ==
    /\ isBound = FALSE
    /\ bound = StoredBinding(InitCtx)
    /\ boundCtx = InitCtx
    /\ responded = {}
    /\ crashed = FALSE
    /\ everRestarted = FALSE
    /\ volatile = FALSE

(* Bind the slot: durably store the projection of this context. *)
Bind(c) ==
    /\ ~crashed                      \* a crashed process does nothing
    /\ ~isBound
    /\ isBound' = TRUE
    /\ bound' = StoredBinding(c)
    /\ boundCtx' = c
    /\ volatile' = TRUE              \* in-memory context now held
    /\ UNCHANGED <<responded, crashed, everRestarted>>

\* A crash loses VOLATILE state. Durable state survives -- that asymmetry is
\* the whole point, and the earlier version had no volatile state at all, so
\* Crash/Restart merely toggled a flag while every action stayed enabled.
Crash == /\ ~crashed /\ crashed' = TRUE
         /\ volatile' = FALSE
         /\ UNCHANGED <<isBound, bound, boundCtx, responded, everRestarted>>

Restart == /\ crashed /\ crashed' = FALSE
           /\ everRestarted' = TRUE
           /\ UNCHANGED <<isBound, bound, boundCtx, responded, volatile>>

(* Emit a response for context c. Durable state can only check the STORED   *)
(* binding -- it cannot check fields it never authenticated.                *)
Respond(c) ==
    /\ ~crashed
    /\ isBound
    \* Durable state can only check the STORED binding. After a restart the
    \* volatile context is gone, so this is the ONLY check available.
    /\ StoredBinding(c) = bound
    /\ responded' = responded \cup {Context(c)}
    /\ UNCHANGED <<isBound, bound, boundCtx, crashed, everRestarted, volatile>>

Next == \/ \E c \in Ctxs : Bind(c)
        \/ \E c \in Ctxs : Respond(c)
        \/ Crash \/ Restart

Spec == Init /\ [][Next]_vars

-------------------------------------------------------------------------
\* THE OBLIGATION. One slot, one response security context -- no matter what
\* a peer offers after a restart.
INV_OneContextResponded == Cardinality(responded) <= 1

\* The implication form, stated directly: anything accepted against the
\* stored binding must have the same context as what was bound.
INV_BindingDeterminesContext ==
    \A c \in responded : isBound => Context(c) = Context(boundCtx)

-------------------------------------------------------------------------
COV_CanBind    == ~isBound
COV_CanRespond == responded = {}
COV_CanCrash   == ~crashed
\* A restart followed by a response must be reachable, or the property is
\* only holding because the dangerous sequence never occurs.
\* Corrected: the old form was satisfied by Bind -> Respond with no crash at
\* all. This requires an ACTUAL restart to have happened, with the volatile
\* context lost, before a response is emitted.
COV_RespondAfterRestart == ~(responded # {} /\ everRestarted /\ ~volatile)
=========================================================================
