--------------------------- MODULE NonceSlot ---------------------------
(***************************************************************************)
(* The one-time nonce SLOT, and what a rolled-back store does to it.        *)
(*                                                                          *)
(* Ceremony.tla proved a narrower thing than was claimed for it: given a    *)
(* perfect, non-rollback durable map, one session cannot be authorised      *)
(* against two different input tuples. Review made two corrections that     *)
(* this module exists to address.                                           *)
(*                                                                          *)
(*   1. The unique resource is the signer's own nonce SLOT -- not the       *)
(*      transcript. The transcript is what a slot may be bound to, once.    *)
(*      Keying on transcript fields inverts that: if a coordinator reuses   *)
(*      our commitments but changes another participant's round-one         *)
(*      package, the "keys" differ while the private nonce is the same.     *)
(*      That is precisely the dangerous case.                               *)
(*                                                                          *)
(*   2. A store ROLLED BACK from a snapshot is the real hazard, and fsync   *)
(*      does not address it. Prevention needs an external monotonic anchor  *)
(*      that does not rewind with the store -- or restoration must be       *)
(*      treated as key compromise.                                          *)
(*                                                                          *)
(* CONSEQUENCE, corrected. An earlier version said two bindings leak and    *)
(* three recover. That is too strong for the generic case: two responses    *)
(* extract only when the SAME effective nonce answers different challenges; *)
(* with changing binding factors two generic responses leave one scalar     *)
(* degree of freedom, and three recover. See spec/frost_nonce_reuse_witness *)
(* and threshold_algebra.py RESULTS 2 and 3. One-binding-per-slot remains   *)
(* the right conservative rule; its algebraic consequence is narrower than  *)
(* was claimed.                                                             *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Transcripts,            \* canonical authorization statements
    Packages,               \* complete ordered round-one packages
    MaxGen,                 \* bound on the generation counter

    GuardBurnOnAbort,       \* an abort after commitments are public BURNS the slot
    GuardAntiRollback,      \* an external anchor detects a rewound store
    GuardRetransmitOnly     \* after a crash, resend persisted bytes; never recompute

VARIABLES
    state,          \* slot phase
    durTranscript,  \* durable: the statement this slot is bound to
    durPackage,     \* durable: the full round-one digest
    durResponse,    \* durable: the exact response bytes already persisted
    durGen,         \* durable: generation counter (REWINDS on rollback)
    extGen,         \* external anchor (does NOT rewind)
    emitted,        \* what the world has seen: <<transcript, package>> pairs
    r1Public,       \* our round-one commitment is public for this slot
    reReserved,     \* a Reserve SUCCEEDED after commitments were already public
    everBound,      \* every <<transcript, package>> ever BOUND, not merely sent
    burnedPublic,   \* a slot with public commitments was burned
    workAfterBurn,  \* a Bind/Respond/Send FIRED after such a burn
    snapTaken, snapState, snapTranscript, snapPackage, snapResponse, snapGen

vars == <<state, durTranscript, durPackage, durResponse, durGen, extGen,
          emitted, r1Public, reReserved, everBound, burnedPublic, workAfterBurn, snapTaken,
          snapState, snapTranscript, snapPackage, snapResponse, snapGen>>

None == 0
States == {"AVAILABLE", "RESERVED", "R1_EXPOSED", "BOUND", "CONSUMED",
           "SENT", "BURNED"}

TypeOK ==
    /\ state \in States
    /\ durTranscript \in Transcripts \cup {None}
    /\ durPackage \in Packages \cup {None}
    /\ durResponse \in Packages \cup {None}
    /\ durGen \in 0..MaxGen
    /\ extGen \in 0..MaxGen
    /\ emitted \subseteq (Transcripts \X Packages)
    /\ r1Public \in BOOLEAN
    /\ reReserved \in BOOLEAN
    /\ everBound \subseteq (Transcripts \X Packages)
    /\ burnedPublic \in BOOLEAN
    /\ workAfterBurn \in BOOLEAN
    /\ snapTaken \in BOOLEAN
    /\ snapState \in States
    /\ snapGen \in 0..MaxGen

Init ==
    /\ state = "AVAILABLE"
    /\ durTranscript = None
    /\ durPackage = None
    /\ durResponse = None
    /\ durGen = 0
    /\ extGen = 0
    /\ emitted = {}
    /\ r1Public = FALSE
    /\ reReserved = FALSE
    /\ everBound = {}
    /\ burnedPublic = FALSE
    /\ workAfterBurn = FALSE
    /\ snapTaken = FALSE
    /\ snapState = "AVAILABLE"
    /\ snapTranscript = None
    /\ snapPackage = None
    /\ snapResponse = None
    /\ snapGen = 0

(* Claim the slot for a statement. The anti-rollback guard refuses when the *)
(* durable generation is behind the external anchor -- i.e. the store has   *)
(* been rewound underneath us.                                             *)
Reserve(t) ==
    /\ state = "AVAILABLE"
    /\ extGen < MaxGen
    /\ GuardAntiRollback => durGen = extGen
    /\ state' = "RESERVED"
    /\ durTranscript' = t
    /\ extGen' = extGen + 1
    /\ durGen' = extGen + 1
    \* The hazard is a reservation SUCCEEDING after our commitments are public.
    /\ reReserved' = (reReserved \/ r1Public)
    /\ UNCHANGED <<workAfterBurn, everBound, burnedPublic, durPackage, durResponse, emitted, r1Public, snapTaken,
                   snapState, snapTranscript, snapPackage, snapResponse, snapGen>>

(* Publish our round-one commitment. After this the private nonce is        *)
(* committed to in public and the slot can never be safely reused.          *)
(*                                                                          *)
(* MODEL CHECKING FOUND THIS, in two rounds.                                *)
(*                                                                          *)
(* First: gating the anchor on Reserve alone is not sufficient. A rollback  *)
(* restoring a MID-CEREMONY state never needs to reserve again -- it        *)
(* resumes and binds a different package on the same private nonce.         *)
(*                                                                          *)
(* Then: checking it at exposure too is STILL not sufficient. An external   *)
(* counter can only detect a rewind if it advanced during the interval that *)
(* was rolled back. A snapshot taken after exposure, restored before        *)
(* binding, leaves durGen = extGen and passes every check.                  *)
(*                                                                          *)
(* The rule, as corrected in review: anchor every nonce-security state      *)
(* transition BEFORE ITS EXTERNALLY OBSERVABLE CONSEQUENCE -- not literally *)
(* every durable write. A purely idempotent delivery-status update may be   *)
(* left unanchored. Reserve, expose, bind, respond and ABORT all qualify.   *)
(* A single check at the start is not a defence.                            *)
(*                                                                          *)
(* And counter equality alone is not a sufficient production construction:  *)
(* it cannot reject a torn record holding a current generation beside stale *)
(* phase bytes. This model updates the record and the counter in ONE        *)
(* indivisible action and so assumes that problem away. The real thing      *)
(* needs an immutable WAL record plus an external digest compare-and-swap.  *)
ExposeR1 ==
    /\ state = "RESERVED"
    /\ GuardAntiRollback => durGen = extGen
    /\ extGen < MaxGen
    /\ extGen' = extGen + 1
    /\ durGen' = extGen + 1
    /\ state' = "R1_EXPOSED"
    /\ r1Public' = TRUE
    /\ UNCHANGED <<workAfterBurn, everBound, burnedPublic, reReserved, durTranscript, durPackage, durResponse,
                   emitted, snapTaken, snapState, snapTranscript, snapPackage,
                   snapResponse, snapGen>>

(* Bind to the complete ordered round-one package from every participant. *)
Bind(pkg) ==
    /\ state = "R1_EXPOSED"
    /\ GuardAntiRollback => durGen = extGen
    /\ extGen < MaxGen
    /\ extGen' = extGen + 1
    /\ durGen' = extGen + 1
    /\ state' = "BOUND"
    /\ durPackage' = pkg
    /\ workAfterBurn' = (workAfterBurn \/ burnedPublic)
    /\ everBound' = everBound \cup {<<durTranscript, pkg>>}
    /\ UNCHANGED <<durTranscript, durResponse, emitted, burnedPublic,
                   r1Public, reReserved, snapTaken, snapState, snapTranscript, snapPackage,
                   snapResponse, snapGen>>

(* Compute and durably persist the response BEFORE anything is sent. *)
Respond ==
    /\ state = "BOUND"
    /\ GuardAntiRollback => durGen = extGen
    /\ extGen < MaxGen
    /\ extGen' = extGen + 1
    /\ durGen' = extGen + 1
    /\ workAfterBurn' = (workAfterBurn \/ burnedPublic)
    /\ state' = "CONSUMED"
    /\ durResponse' = durPackage
    /\ UNCHANGED <<everBound, burnedPublic, durTranscript, durPackage, emitted,
                   r1Public, reReserved, snapTaken, snapState, snapTranscript, snapPackage,
                   snapResponse, snapGen>>

Send ==
    /\ state = "CONSUMED"
    /\ workAfterBurn' = (workAfterBurn \/ burnedPublic)
    /\ state' = "SENT"
    /\ emitted' = emitted \cup {<<durTranscript, durPackage>>}
    /\ UNCHANGED <<everBound, burnedPublic, durTranscript, durPackage, durResponse, durGen, extGen,
                   r1Public, reReserved, snapTaken, snapState, snapTranscript, snapPackage,
                   snapResponse, snapGen>>

(* A byte-identical retry resends what was persisted. It never recomputes. *)
Retransmit ==
    /\ state = "SENT"
    /\ GuardRetransmitOnly
    /\ emitted' = emitted \cup {<<durTranscript, durPackage>>}
    /\ UNCHANGED <<workAfterBurn, everBound, burnedPublic, state, durTranscript, durPackage, durResponse, durGen,
                   extGen, r1Public, reReserved, snapTaken, snapState, snapTranscript,
                   snapPackage, snapResponse, snapGen>>

(* Abort. Once commitments are public the slot must be BURNED, never        *)
(* returned to the pool.                                                    *)
(* Aborting is itself a nonce-security state transition, so it must be      *)
(* anchored like any other. Review found the counterexample: with every     *)
(* guard on,                                                                *)
(*   Reserve -> ExposeR1 -> Bind -> Snapshot -> Abort(BURNED) -> Rollback   *)
(* restores a live BOUND slot, because durGen = extGen held across the      *)
(* unanchored Abort and the rollback check therefore accepted it. The model *)
(* was failing to enforce its own rule that a public nonce is burned for    *)
(* good, and the existing invariants missed it because they tracked only a  *)
(* later Reserve and the SENT set.                                          *)
Abort ==
    /\ state \in {"RESERVED", "R1_EXPOSED", "BOUND"}
    /\ GuardAntiRollback => durGen = extGen
    /\ extGen < MaxGen
    /\ extGen' = extGen + 1
    /\ durGen' = extGen + 1
    /\ state' = IF GuardBurnOnAbort /\ r1Public THEN "BURNED" ELSE "AVAILABLE"
    /\ burnedPublic' = (burnedPublic \/ (GuardBurnOnAbort /\ r1Public))
    \* The BURNED record RETAINS the prior binding rather than erasing it --
    \* DESIGN-FINAL says "Aborted owns the evidence", and a burn record that
    \* forgets what it burned cannot support that. A real WAL entry would
    \* chain to the prior binding digest.
    /\ durTranscript' = durTranscript
    /\ durPackage' = durPackage
    /\ UNCHANGED <<workAfterBurn, durResponse, emitted, r1Public, reReserved, everBound, snapTaken,
                   snapState, snapTranscript, snapPackage, snapResponse, snapGen>>

Snapshot ==
    /\ ~snapTaken
    /\ snapTaken' = TRUE
    /\ snapState' = state
    /\ snapTranscript' = durTranscript
    /\ snapPackage' = durPackage
    /\ snapResponse' = durResponse
    /\ snapGen' = durGen
    /\ UNCHANGED <<workAfterBurn, everBound, burnedPublic, state, durTranscript, durPackage, durResponse, durGen,
                   extGen, emitted, r1Public, reReserved>>

(* The dangerous event. The durable store rewinds. What the world already   *)
(* saw does not, and neither does the external anchor.                      *)
Rollback ==
    /\ snapTaken
    /\ state' = snapState
    /\ durTranscript' = snapTranscript
    /\ durPackage' = snapPackage
    /\ durResponse' = snapResponse
    /\ durGen' = snapGen
    /\ UNCHANGED <<workAfterBurn, everBound, burnedPublic, extGen, emitted, r1Public, reReserved, snapTaken, snapState,
                   snapTranscript, snapPackage, snapResponse, snapGen>>

Next ==
    \/ \E t \in Transcripts : Reserve(t)
    \/ ExposeR1
    \/ \E p \in Packages : Bind(p)
    \/ Respond
    \/ Send
    \/ Retransmit
    \/ Abort
    \/ Snapshot
    \/ Rollback

Spec == Init /\ [][Next]_vars

-------------------------------------------------------------------------
(*                              INVARIANTS                                *)

\* THE SAFETY PROPERTY. RESULTS 2 and 3 show that two distinct bindings on
\* one slot leak information about the share, and three recover it. So one
\* slot must never be bound to two different (transcript, package) pairs.
\* NOTE the narrow scope, which review corrected: `emitted` changes only at
\* Send, so this proves at most one SENT context -- not at most one context
\* bound or response computed. INV_OneContextBound below is the real property.
INV_OneContextSent == Cardinality(emitted) <= 1

\* THE STRONG PROPERTY. At most one context is ever BOUND to this slot, which
\* is what RESULTS 2 and 3 actually require: a second binding leaks even if
\* its response never reaches the wire.
INV_OneContextBound == Cardinality(everBound) <= 1

\* A slot whose public commitments were burned never does further work.
\* Deliberately an ACTION, not a label: a rollback really does restore the
\* label BOUND, and no anchor can prevent that. What the anchor prevents is
\* the next transition firing. This is the fourth invariant in this project
\* that had to be rewritten from a label to an action.
INV_NoWorkAfterBurn == ~workAfterBurn

\* A slot whose commitments became public must never be RE-RESERVED.
\* Deliberately NOT a condition on the state label. A rollback really does
\* restore the label -- to AVAILABLE, or to RESERVED mid-ceremony -- and no
\* external anchor can prevent that. What the anchor prevents is the next
\* RESERVATION SUCCEEDING against a rewound store. Two earlier versions of this
\* invariant tested labels and failed the baseline for that reason; the hazard
\* is an action, so it is tracked as one.
INV_NoReuseAfterExposure == ~reReserved

\* Nothing is emitted that was not first persisted.
INV_PersistedBeforeSend ==
    (state = "SENT") => durResponse # None

-------------------------------------------------------------------------
(*                       COVERAGE ASSERTIONS                              *)
(* These are written to FAIL. Each asserts that some interesting state is  *)
(* unreachable; TLC violating it proves the state IS reachable. A spec     *)
(* with a contradictory action reports "no violation" on every real        *)
(* invariant while being completely dead -- which happened here, and was   *)
(* invisible until these were added.                                       *)

COV_CanExpose  == state # "R1_EXPOSED"
COV_CanSend    == state # "SENT"
COV_CanRollback == ~(snapTaken /\ state = "RESERVED" /\ r1Public)

\* HAZARD COVERAGE for the exact sequence review found:
\*   Reserve -> Expose -> Bind -> Snapshot -> Abort(BURNED) -> Rollback(BOUND)
\* Without this the Abort repair could silently become vacuous later, since
\* COV_CanRollback exercises a different endpoint entirely.
COV_BurnThenRollback == ~(burnedPublic /\ state = "BOUND")

=========================================================================
