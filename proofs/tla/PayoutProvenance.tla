------------------------- MODULE PayoutProvenance -------------------------
(***************************************************************************)
(* Every value the payout depends on must be a function of the             *)
(* authenticated output -- not of anything the relayer chose.              *)
(*                                                                         *)
(* WHY THIS MODEL EXISTS. ClaimAcceptance.tla scoped itself out of exactly  *)
(* this question and said so:                                              *)
(*                                                                         *)
(*   "The memo codec is NOT modelled, so 'the output names a beneficiary'  *)
(*    is an ASSUMPTION rather than a result."                              *)
(*                                                                         *)
(* The assumption was never discharged, and the implementation shipped      *)
(* without meeting it: amount, token id and beneficiary were all supplied   *)
(* by whoever relayed the proof, while the output's digest bound only their *)
(* ENCRYPTED forms. One authenticated output could then be redeemed for any *)
(* value, to anyone. The proof named its own boundary and the code walked   *)
(* across it, which is the failure this module is meant to stop recurring.  *)
(*                                                                         *)
(* WHAT IS MODELLED. Not cryptography -- whether Blake2b, HKDF and the      *)
(* Pedersen opening agree with MobileCoin is a differential-testing         *)
(* question and lives in contracts/test. What is modelled is PROVENANCE:    *)
(* for each field the payout reads, is its value pinned by the              *)
(* authenticated output, or free for the submitter to choose?              *)
(*                                                                         *)
(* The relayer here is not assumed dishonest. It is assumed FREE: it        *)
(* supplies whatever it likes for any field the contract does not derive.   *)
(* That is simply what "the contract does not check it" means.              *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Outputs,        \* authenticated outputs: really signed, really included
    Values,         \* candidate payout amounts
    Tokens,         \* candidate token ids
    Payees,         \* candidate payees

    (* Provenance switches, one per field on the payout path. TRUE means the
       contract DERIVES the field from the authenticated output; FALSE means
       it accepts whatever the submitter supplies. Flipping any one of these
       to FALSE must break INV_PayoutPinnedByOutput -- that is the whole
       coverage argument, and run_payout_provenance.py checks it. *)
    DeriveAmount,
    DeriveTokenId,
    DerivePayee

VARIABLES
    paid,           \* [out, value, token, payee] tuples actually paid out
    redeemed,       \* outputs whose replay slot has been consumed
    trueVal,        \* out -> the value that output actually opens to
    trueTok,        \* out -> the token id it actually opens to
    truePayee       \* out -> the payee its memo actually names

vars == <<paid, redeemed, trueVal, trueTok, truePayee>>

(* Each output HAS one true opening, fixed for all time and different outputs
   may differ. Chosen nondeterministically at Init and never written again, so
   TLC explores every assignment rather than one.
   
   An earlier version defined these with `CHOOSE x \in S : TRUE`, which is
   deterministic: every output got the SAME true value, and an invariant
   saying "the payout matches the output" held trivially because there was
   only one value to match. That is the shape of tautology this whole file
   exists to avoid. *)
Init ==
    /\ paid = {}
    /\ redeemed = {}
    /\ trueVal \in [Outputs -> Values]
    /\ trueTok \in [Outputs -> Tokens]
    /\ truePayee \in [Outputs -> Payees]

(* What the contract ends up using for a field: the output's own value when
   the field is derived, and anything at all when it is not. *)
UsableValues(o) == IF DeriveAmount  THEN {trueVal[o]}   ELSE Values
UsableTokens(o) == IF DeriveTokenId THEN {trueTok[o]}   ELSE Tokens
UsablePayees(o) == IF DerivePayee   THEN {truePayee[o]} ELSE Payees

(* A redemption. The relayer picks any output it can authenticate, and any
   value, token and payee the contract will let it pick. The replay set still
   binds one redemption per output -- that guard is independent of provenance
   and is modelled in ClaimAcceptance; it is kept here so the two cannot be
   confused for one another. *)
Redeem ==
    \E o \in Outputs :
      \E v \in UsableValues(o), k \in UsableTokens(o), p \in UsablePayees(o) :
        /\ o \notin redeemed
        /\ redeemed' = redeemed \cup {o}
        /\ paid' = paid \cup {<<o, v, k, p>>}
        /\ UNCHANGED <<trueVal, trueTok, truePayee>>

Next == Redeem \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

(*-------------------------------- the property ---------------------------*)

(* THE POINT. Every payout carries the value, token and payee the output
   itself opens to. With any field left to the submitter, this fails: the same
   authenticated output yields a payout the output does not name.

   Each conjunct is state-dependent -- it compares what was paid against what
   the output opens to -- so none of them can hold by construction. *)
INV_PayoutPinnedByOutput ==
    \A t \in paid :
        /\ t[2] = trueVal[t[1]]
        /\ t[3] = trueTok[t[1]]
        /\ t[4] = truePayee[t[1]]

(* Stated separately because it is the consequence that costs money. One
   authenticated output must not be able to produce two different payouts.
   Replay alone does not give this: the replay set stops a second REDEMPTION,
   but with a free field the FIRST redemption was already the submitter's
   choice out of many, and TLC will exhibit two runs that differ. *)
INV_OneOutputOneOutcome ==
    \A t1, t2 \in paid : t1[1] = t2[1] => t1 = t2

(*------------------------------- coverage --------------------------------*)

(* Negative coverage: a model that can never pay anything satisfies every
   invariant above. This must be violated in a run that reaches a payout, so
   a spec too dead to move is visible instead of passing quietly. *)
COV_CanPay == paid = {}

=============================================================================
