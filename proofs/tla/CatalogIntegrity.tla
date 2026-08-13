--------------------- MODULE CatalogIntegrity ---------------------
(***************************************************************************)
(* The key-image catalogue that AuditObservability ASSUMES.                 *)
(*                                                                          *)
(* AuditObservability shows a complete, proof-valid catalogue is what lets  *)
(* an auditor see that a known F output was spent. It assumes completeness  *)
(* and proof-validity rather than deriving them. This derives them.         *)
(*                                                                          *)
(* The causal chain, from review:                                           *)
(*                                                                          *)
(*   F output known                                                         *)
(*     -> valid canonical key-image proof (Chaum-Pedersen / DLEQ)           *)
(*     -> immutable catalogue entry anchored                                *)
(*     -> output admitted as spend-eligible                                 *)
(*     -> exact spend authorization                                         *)
(*     -> finalization                                                      *)
(*                                                                          *)
(* The ordering is the whole point. A CP proof establishes the P <-> I      *)
(* relation; it establishes NO publication time, no completeness, and no    *)
(* non-equivocation. An entry created after the spend proves nothing about  *)
(* that spend, so the anchor must precede spend-eligibility -- not merely   *)
(* exist.                                                                   *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Outputs,        \* F outputs
    KeyImages,      \* canonical key images

    GuardProofBeforeAnchor,   \* only a proof-valid entry may be anchored
    GuardAnchorBeforeSpend,   \* an output is spend-eligible only once anchored
    GuardUniqueMapping,       \* one P <-> one I, both directions
    GuardNoOverwrite          \* an anchored entry is immutable

VARIABLES
    provenKI,   \* output -> the key image PROVEN canonical for it, or NoKI
    entry,      \* output -> key image, or NoKI  (the catalogue)
    anchored,   \* outputs whose entry is immutably committed
    spendable,  \* outputs admitted as spend-eligible
    spent,      \* outputs actually spent
    equivocated \* an anchored entry was changed

vars == <<provenKI, entry, anchored, spendable, spent, equivocated>>

NoKI == 0

TypeOK ==
    /\ provenKI \in [Outputs -> KeyImages \cup {NoKI}]
    /\ entry \in [Outputs -> KeyImages \cup {NoKI}]
    /\ anchored \subseteq Outputs
    /\ spendable \subseteq Outputs
    /\ spent \subseteq Outputs
    /\ equivocated \in BOOLEAN

Init ==
    /\ provenKI = [o \in Outputs |-> NoKI]
    /\ entry = [o \in Outputs |-> NoKI]
    /\ anchored = {}
    /\ spendable = {}
    /\ spent = {}
    /\ equivocated = FALSE

(* A valid Chaum-Pedersen proof of the canonical P <-> I relation. *)
(* Review: the old Prove(o) recorded only `o`, with no key image and no proof
   relation, so Record(o,i) could then choose ANY i. The model never proved an
   (output, key-image) pair and could not establish that the recorded i was the
   one proven for o. It now binds the pair. *)
Prove(o, i) ==
    /\ provenKI[o] = NoKI
    /\ provenKI' = [provenKI EXCEPT ![o] = i]
    /\ UNCHANGED <<entry, anchored, spendable, spent, equivocated>>

(* Write the catalogue entry. Without the proof guard this can record an    *)
(* unproven relation; without the uniqueness guard it can collide.          *)
Record(o, i) ==
    \* must record the key image actually proven for this output
    /\ GuardProofBeforeAnchor => provenKI[o] = i
    \* These two were conflated: the uniqueness check also forbade ANY
    \* rewrite, so it subsumed no-overwrite and that mutation broke nothing.
    \* They are different failures. Uniqueness is a CROSS-OUTPUT collision;
    \* overwrite is a TEMPORAL rewrite of an already-anchored entry. A
    \* correction before anchoring is legitimate and must stay reachable.
    /\ GuardUniqueMapping =>
          \A p \in Outputs : p # o => entry[p] # i     \* I -> one P
    /\ GuardNoOverwrite => o \notin anchored           \* anchored is immutable
    /\ equivocated' = (equivocated \/ (o \in anchored /\ entry[o] # i))
    /\ entry' = [entry EXCEPT ![o] = i]
    /\ UNCHANGED <<provenKI, anchored, spendable, spent>>

(* Anchor the entry immutably -- the independently witnessed receipt. *)
Anchor(o) ==
    /\ entry[o] # NoKI
    /\ o \notin anchored
    /\ anchored' = anchored \cup {o}
    /\ UNCHANGED <<provenKI, entry, spendable, spent, equivocated>>

(* Admit the output for spending. This is the ordering that matters. *)
Admit(o) ==
    /\ o \notin spendable
    /\ GuardAnchorBeforeSpend => o \in anchored
    /\ spendable' = spendable \cup {o}
    /\ UNCHANGED <<provenKI, entry, anchored, spent, equivocated>>

Spend(o) ==
    /\ o \in spendable
    /\ o \notin spent
    /\ spent' = spent \cup {o}
    /\ UNCHANGED <<provenKI, entry, anchored, spendable, equivocated>>

Next ==
    \/ \E o \in Outputs, i \in KeyImages : Prove(o, i)
    \/ \E o \in Outputs, i \in KeyImages : Record(o, i)
    \/ \E o \in Outputs : Anchor(o)
    \/ \E o \in Outputs : Admit(o)
    \/ \E o \in Outputs : Spend(o)

Spec == Init /\ [][Next]_vars

-------------------------------------------------------------------------
(*                              INVARIANTS                                *)

\* GuardAnchorBeforeSpend. THE ordering property: an entry created after the
\* spend proves nothing about that spend.
INV_SpentWasAnchoredFirst == \A o \in spent : o \in anchored

\* GuardProofBeforeAnchor. Every anchored entry rests on a valid proof.
\* Stronger than before: the anchored entry must equal the PROVEN key image
\* for that output, not merely coexist with some proof.
INV_AnchoredIsProven == \A o \in anchored : entry[o] = provenKI[o]

\* GuardUniqueMapping, both directions. P -> two I would let one output be
\* accounted twice; I -> two P would let one spend be attributed to the wrong
\* output.
INV_InjectiveMapping ==
    \A a, b \in Outputs :
        (a # b /\ entry[a] # NoKI /\ entry[b] # NoKI) => entry[a] # entry[b]

\* GuardNoOverwrite. An anchored entry is never rewritten.
INV_NoEquivocation == ~equivocated

\* COMPLETENESS: every spendable output has a catalogue entry. Without this
\* the auditor's inventory has holes, and a spend of a missing output is
\* invisible exactly as in the chain-only case.
INV_SpendableIsCatalogued == \A o \in spendable : entry[o] # NoKI

-------------------------------------------------------------------------
(*                       COVERAGE ASSERTIONS                              *)

COV_CanProve   == \A o \in Outputs : provenKI[o] = NoKI
COV_CanAnchor  == anchored = {}
COV_CanSpend   == spent = {}
\* The good ordered state: proven, anchored, admitted and spent, in order.
COV_FullChain  == \A o \in Outputs :
                    ~(o \in spent /\ o \in anchored /\ provenKI[o] # NoKI)
\* Review: the old form's shortest trace was the FIRST write, not a
\* correction. A genuine correction needs a second write to the same output
\* with a DIFFERENT key image, before anchoring -- which requires tracking the
\* write count, so this is stated as a known gap rather than mislabelled.
\* KNOWN UNPROVED: pre-anchor correction reachability.
=========================================================================
