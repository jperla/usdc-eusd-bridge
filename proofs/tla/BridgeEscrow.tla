-------------------------------- MODULE BridgeEscrow --------------------------------
(***************************************************************************)
(* Consensus state machine for the USDC <-> eUSD bridge escrow.            *)
(*                                                                         *)
(* Models the two-gate escrow release, the source-event nullifier, epoch    *)
(* rotation on fault, and the blame adjudicator.  See DESIGN.md section 2.  *)
(*                                                                         *)
(* WHAT THIS SPEC IS FOR                                                   *)
(*                                                                         *)
(* The design's load-bearing safety claims are reachability properties, not *)
(* cryptographic ones.  This spec is where they get checked:                *)
(*                                                                         *)
(*   NoBypass         an escrow output cannot be spent without ALL gates    *)
(*   NoDoubleRelease  one source event funds at most one release           *)
(*   NoDoubleSpend    an output is consumed at most once                    *)
(*   RotationSound    rotation does not strand outputs                      *)
(*   BlameExclusive   adjudication never blames both or neither             *)
(*   ContainmentOK    only operator fault pauses the bridge                 *)
(*   NoSlashUnproven  nobody is slashed without an admitted verdict         *)
(*   Solvency         releases never exceed finalized deposits              *)
(*                                                                         *)
(* The cryptography is deliberately abstracted.  We do not model MLSAG,     *)
(* FROST, or signatures -- we model *whether the required authorization     *)
(* artifact was produced by a party able to produce it*.  A separate        *)
(* Tamarin model covers the protocol, and Verus/Kani cover the nonce state  *)
(* machine.  Mixing those layers here would make the state space useless.   *)
(*                                                                         *)
(* BUG SWITCHES -- READ THIS                                               *)
(*                                                                         *)
(* A specification that cannot reproduce a known bug is not validating      *)
(* anything.  Four constants inject defects we argued about during design.  *)
(* Each MUST cause a specific invariant to fail.  If flipping a switch      *)
(* leaves every invariant passing, the spec is too weak -- fix the spec,    *)
(* not the switch.  See README.md for the expected failure per switch.      *)
(***************************************************************************)

EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Operators,          \* operator identities (wardens; also FROST participants)
    SourceEvents,       \* Ethereum deposit event ids
    EscrowOutputs,      \* escrow-policy outputs (ring-private, policy-bound)
    PlainOutputs,       \* ordinary outputs, present to exercise the legacy path
    K_W,                \* warden certificate threshold
    K_F,                \* FROST gate threshold
    K_OWN,              \* MLSAG ownership threshold
    MaxEpoch,           \* bound the epoch counter so TLC terminates
    NoOutput            \* model value: "no output funded this event"

\* Deliberate defects.  All FALSE = the design as specified in DESIGN.md section 2.
CONSTANTS
    BUG_OptionalCertificate,  \* certificate becomes spend-time optional
    BUG_NoNullifier,          \* source events are not consumed
    BUG_RotateOwnership,      \* rotation replaces K_own, not just the gate
    BUG_LegacyPathOpen,       \* escrow outputs remain spendable via the ordinary path
    BUG_NoEpochCheck          \* consensus does not require the authorization's epoch
                              \* to be current -- lets an expelled coalition replay
                              \* an authorization under the gate key they still hold

ASSUME
    /\ K_W \in 1..Cardinality(Operators)
    /\ K_F \in 1..Cardinality(Operators)
    /\ K_OWN \in 1..Cardinality(Operators)
    /\ MaxEpoch \in Nat \ {0}
    /\ NoOutput \notin EscrowOutputs
    /\ EscrowOutputs \cap PlainOutputs = {}

AllOutputs == EscrowOutputs \cup PlainOutputs

VARIABLES
    epoch,          \* current policy epoch; the gate key is identified by it
    unspent,        \* set of outputs not yet consumed
    keyImages,      \* consumed output identifiers (stand-in for key images)
    nullifiers,     \* consumed source-event nullifiers  (consensus state)
    releases,       \* set of [event, output, certified] -- certification is
                    \* TRACKED, not inferred; see NoBypass
    paused,         \* bridge halted
    expelled,       \* operators removed from the roster
    slashed,        \* operators whose bond was confiscated
    verdicts,       \* set of records: [claim, kind] with kind in {"op","chal"}
    finalized,      \* source events with a finalized Ethereum DepositRecord
    gateHolders     \* epoch -> operators holding THAT epoch's gate key.  Expelled
                    \* operators stay in the holder sets of epochs they were part
                    \* of: rotation cannot retract key material already issued.

vars == << epoch, unspent, keyImages, nullifiers, releases, paused,
           expelled, slashed, verdicts, finalized, gateHolders >>

------------------------------------------------------------------------------
(* Roster and authorization capability.                                     *)

Active == Operators \ expelled

(* An artifact can be produced iff enough non-expelled operators remain.
   For the gate this is per-epoch: expelled operators knew gate key e, not e+1,
   which is exactly why rotation contains a compromised quorum. *)
CanCertify   == Cardinality(Active) >= K_W

(* Gate capability is per-epoch, and deliberately NOT restricted to Active.
   An expelled coalition still holds the gate key of the epoch it was expelled
   from -- rotation issues a new key, it cannot retract the old one.  Modelling
   the gate as Cardinality(Active) >= K_F (an earlier draft) made stale-epoch
   replay inexpressible, which meant the spec could not verify the containment
   property that justifies the two-key design. *)
CanGateAt(e) == Cardinality(gateHolders[e]) >= K_F

(* Ownership is the stable key.  Expelled operators RETAIN their K_own shares
   -- expulsion removes a name, not key material -- so ownership capability is
   about whether enough *honest* operators remain to reach the threshold.  When
   BUG_RotateOwnership is set, rotation mints a fresh ownership key that cannot
   generate the old outputs' key images at all (onetime_keys.rs:169-184), so
   pre-rotation outputs become permanently unspendable. *)
CanOwn == /\ Cardinality(Active) >= K_OWN
          /\ ~(BUG_RotateOwnership /\ epoch > 0)

------------------------------------------------------------------------------
Init ==
    /\ epoch      = 0
    /\ gateHolders = [e \in 0..MaxEpoch |-> IF e = 0 THEN Operators ELSE {}]
    /\ unspent    = AllOutputs
    /\ keyImages  = {}
    /\ nullifiers = {}
    /\ releases   = {}
    /\ paused     = FALSE
    /\ expelled   = {}
    /\ slashed    = {}
    /\ verdicts   = {}
    /\ finalized  = {}

------------------------------------------------------------------------------
(* A deposit is observed and, after the configured depth, finalized.  Only a
   finalized DepositRecord may be cited; see DESIGN.md section 4 on
   reorg-induced false slashing. *)

FinalizeDeposit ==
    /\ ~paused
    /\ \E e \in SourceEvents \ finalized :
         finalized' = finalized \cup {e}
    /\ UNCHANGED << epoch, unspent, keyImages, nullifiers, releases, paused,
                    expelled, slashed, verdicts, gateHolders >>

------------------------------------------------------------------------------
(* THE ESCROW RELEASE.  All four artifacts are required.                    *)

EscrowRelease ==
    /\ ~paused
    /\ \E o \in unspent \cap EscrowOutputs, e \in finalized, ae \in 0..epoch :
         /\ CanOwn                                  \* gate 1: MLSAG(K_own)
         /\ CanGateAt(ae)                           \* gate 2: FROST(K_gate[ae])
         \* Consensus must require the authorization's epoch to be CURRENT.
         \* Without this, holders of a retired gate key can still authorize.
         /\ (ae = epoch \/ BUG_NoEpochCheck)
         /\ (CanCertify \/ BUG_OptionalCertificate) \* gate 3: warden certificate
         /\ (BUG_NoNullifier \/ e \notin nullifiers) \* gate 4: nullifier unconsumed
         /\ unspent'    = unspent \ {o}
         /\ keyImages'  = keyImages \cup {o}
         /\ nullifiers' = IF BUG_NoNullifier THEN nullifiers ELSE nullifiers \cup {e}
         \* Record what was ACTUALLY true, not what was required -- an
         \* uncertified or stale-epoch release must stay visible to the
         \* invariants.  Inferring either one hides the defect.
         /\ releases'   = releases \cup
                            {[event |-> e, output |-> o,
                              certified |-> CanCertify, stale |-> ae # epoch]}
    /\ UNCHANGED << epoch, paused, expelled, slashed, verdicts, finalized,
                    gateHolders >>

------------------------------------------------------------------------------
(* THE LEGACY PATH.  An ordinary MobileCoin spend: ownership only, no gate,
   no certificate.  Escrow outputs must be unreachable through it -- that is
   the whole content of "the gates are unavoidable" (DESIGN.md section 3).    *)

LegacySpend ==
    /\ ~paused
    /\ \E o \in unspent :
         /\ \/ o \in PlainOutputs
            \/ (o \in EscrowOutputs /\ BUG_LegacyPathOpen)
         /\ CanOwn
         /\ unspent'   = unspent \ {o}
         /\ keyImages' = keyImages \cup {o}
    /\ UNCHANGED << epoch, nullifiers, releases, paused, expelled, slashed,
                    verdicts, finalized, gateHolders >>

------------------------------------------------------------------------------
(* THE ADJUDICATOR.  Modelled on Serai's BlameMachine (pedpop/src/lib.rs:535)
   with the bridge's asymmetric containment.

   Admission comes first and is NOT a verdict: malformed or unsupported claims
   revert without punishing anyone.  Serai's blame is total only after the
   accusation is authenticated; feeding it unadmitted input is undefined
   behaviour (pedpop/src/lib.rs:611-643).                                     *)

ClaimIds == SourceEvents          \* one canonical proof_id per incident

Resolved(c) == \E v \in verdicts : v.claim = c

\* NOTE: an earlier draft had a RejectInadmissible action whose body was
\* UNCHANGED vars.  TLC confirmed it was dead code -- the state count was
\* identical (9582) with and without it -- because a step that changes nothing
\* is already permitted by stuttering.  "Inadmissible claims are rejected
\* without punishment" is therefore NOT verified here; it is simply not
\* modelled.  Making it observable needs a rejection counter.

\* Admitted, and the operator really is at fault: slash, expel, pause, rotate.
BlameOperator ==
    /\ ~paused
    /\ epoch < MaxEpoch
    /\ \E c \in ClaimIds, culprits \in SUBSET Active :
         /\ ~Resolved(c)
         /\ c \in finalized
         /\ culprits # {}
         /\ verdicts'  = verdicts \cup {[claim |-> c, kind |-> "op"]}
         /\ slashed'   = slashed \cup culprits
         /\ expelled'  = expelled \cup culprits
         /\ paused'    = TRUE
         /\ epoch'     = epoch + 1        \* fresh DKG for K_gate[epoch+1]
         \* The new gate key goes only to the surviving roster.  The culprits
         \* keep the OLD epoch's key -- that is the point of rotation, and the
         \* reason the epoch-currency check above is load-bearing.
         /\ gateHolders' = [gateHolders EXCEPT ![epoch + 1] = Active \ culprits]
    /\ UNCHANGED << unspent, keyImages, nullifiers, releases, finalized >>

\* Admitted, but the accusation was false: slash the challenger, DO NOT pause.
\* Serai aborts on any fault; a bridge copying that hands griefers a halt.
BlameChallenger ==
    /\ ~paused
    /\ \E c \in ClaimIds, chal \in Active :
         /\ ~Resolved(c)
         /\ c \in finalized
         /\ verdicts' = verdicts \cup {[claim |-> c, kind |-> "chal"]}
         /\ slashed'  = slashed \cup {chal}
    /\ UNCHANGED << epoch, unspent, keyImages, nullifiers, releases, paused,
                    expelled, finalized, gateHolders >>

\* Governor action resumes after an operator fault, once the gate is rotated.
Resume ==
    /\ paused
    /\ paused' = FALSE
    /\ UNCHANGED << epoch, unspent, keyImages, nullifiers, releases,
                    expelled, slashed, verdicts, finalized, gateHolders >>

------------------------------------------------------------------------------
Next ==
    \/ FinalizeDeposit
    \/ EscrowRelease
    \/ LegacySpend
    \/ BlameOperator
    \/ BlameChallenger
    \/ Resume

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------------
(*                              I N V A R I A N T S                         *)
------------------------------------------------------------------------------

TypeOK ==
    /\ epoch \in 0..MaxEpoch
    /\ unspent \subseteq AllOutputs
    /\ keyImages \subseteq AllOutputs
    /\ nullifiers \subseteq SourceEvents
    /\ finalized \subseteq SourceEvents
    /\ releases \subseteq [event: SourceEvents, output: EscrowOutputs,
                            certified: BOOLEAN, stale: BOOLEAN]
    /\ gateHolders \in [0..MaxEpoch -> SUBSET Operators]
    /\ paused \in BOOLEAN
    /\ expelled \subseteq Operators
    /\ slashed \subseteq Operators

(* NoBypass.  Every consumed escrow output was released WITH a certificate.
   Certification is TRACKED per release, not inferred from the citing event --
   an earlier draft inferred it, and the check.py run proved that version could
   not detect BUG_OptionalCertificate at all. *)
ReleasedOutputs == { r.output : r \in releases }
CertifiedOutputs == { r.output : r \in {x \in releases : x.certified} }

NoBypass == (keyImages \cap EscrowOutputs) \subseteq CertifiedOutputs

(* NoDoubleRelease.  No source event funds two releases. *)
NoDoubleRelease ==
    \A e \in SourceEvents :
        Cardinality({r \in releases : r.event = e}) <= 1

(* NoDoubleSpend.  An output is never both unspent and consumed.

   Honest note: this is UNREACHABLE in the current model -- `unspent` only ever
   shrinks and nothing returns an output to it, so the property holds by
   construction.  It is not vacuous: adding a ReplaySpend action makes TLC
   violate it, so it works as a regression guard.  But it currently supplies no
   evidence about the design. *)
NoDoubleSpend == unspent \cap keyImages = {}

(* NoStaleAuthorization.  No release was authorized under a retired gate key.
   This is the containment property that justifies the two-key split: rotation
   must actually stop an expelled coalition from authorizing, and it can only do
   so if consensus checks that the authorization's epoch is current. *)
NoStaleAuthorization == \A r \in releases : ~r.stale

(* RotationSound.  If enough operators remain to meet the OWNERSHIP threshold,
   ownership must remain exercisable.  Rotating the gate key must not strand
   pre-rotation outputs -- the property that forced the two-key split.

   Deliberately independent of the certificate and gate thresholds.  An earlier
   draft conjoined all three, which made the invariant VACUOUS after any
   expulsion (the expulsion alone dropped the roster below K_W), so it could not
   detect BUG_RotateOwnership.  Found by check.py. *)
RotationSound == (Cardinality(Active) >= K_OWN) => CanOwn

(* BlameExclusive.  No claim resolves to both operator and challenger fault. *)
BlameExclusive ==
    \A c \in ClaimIds :
        ~( /\ [claim |-> c, kind |-> "op"]   \in verdicts
           /\ [claim |-> c, kind |-> "chal"] \in verdicts )

(* ContainmentOK.  The bridge is paused only after an operator-fault verdict.
   A proven-false accusation must not halt it. *)
ContainmentOK ==
    paused => \E v \in verdicts : v.kind = "op"

(* NoSlashUnproven.  Nobody is slashed without some admitted verdict. *)
NoSlashUnproven ==
    slashed # {} => verdicts # {}

(* Solvency.  Never release more than has been finalized. *)
Solvency == Cardinality(releases) <= Cardinality(finalized)

(* Only finalized events may be cited -- the reorg guard. *)
CitesOnlyFinalized == \A r \in releases : r.event \in finalized

------------------------------------------------------------------------------
Safety ==
    /\ TypeOK
    /\ NoBypass
    /\ NoDoubleRelease
    /\ NoDoubleSpend
    /\ RotationSound
    /\ BlameExclusive
    /\ ContainmentOK
    /\ NoSlashUnproven
    /\ Solvency
    /\ CitesOnlyFinalized

=============================================================================
