------------------------ MODULE ClaimAcceptance ------------------------
(***************************************************************************)
(* Who gets paid, how often, and in what order.                             *)
(*                                                                          *)
(* REBUILT after review. The previous version was a toy counterexample      *)
(* dressed up as three production claims:                                   *)
(*   - the beneficiary was a constant that IGNORED the output, so every     *)
(*     output named the same address and per-output binding went untested;  *)
(*   - "global nullifier" meant only "not partitioned by epoch";            *)
(*   - CEI had no transfer-success, transfer-failure or revert action, so   *)
(*     the rollback claim was unmodelled and INV_NoPayoutDuringFlight was   *)
(*     vacuous in the baseline.                                             *)
(*                                                                          *)
(* This version uses per-call state, a real per-output beneficiary map, and *)
(* a claim identity stable across epoch AND mode:                           *)
(*                                                                          *)
(*   IDLE --validate+consume--> PENDING --> SUCCESS                         *)
(*                                  |-----> FAILURE (revert restores state) *)
(*                                  |-----> reentry attempt, rejected       *)
(*                                                                          *)
(* SCOPE. The memo codec is NOT modelled, so "the output names a            *)
(* beneficiary" is an assumption rather than a result: finalized bytes      *)
(* establish an Ethereum beneficiary only after schema, decryption, domain  *)
(* and canonical-address checks succeed. Contract upgrade is modelled as a  *)
(* mode change over ONE registry, not as two independent deployments.       *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Outputs, Beneficiaries, Relayers, Epochs, Modes,

    GuardBeneficiaryFromOutput,   \* pay the output's beneficiary, not the submitter
    GuardStableClaimId,           \* claim identity excludes epoch and mode
    GuardConsumeBeforeCall,       \* consume, then call
    GuardRevertOnFailure          \* a failed transfer restores state

\* Each output names a DISTINCT beneficiary. The previous version used a
\* constant that ignored the output entirely, so every output named the same
\* address and per-output binding was never tested. Injectivity is asserted
\* here rather than supplied by the config, which cannot express it.
BeneficiaryOf ==
    CHOOSE f \in [Outputs -> Beneficiaries] :
        \A a, b \in Outputs : a # b => f[a] # f[b]

VARIABLES consumed, payouts, payCount, pending, epoch, mode, stranded

vars == <<consumed, payouts, payCount, pending, epoch, mode, stranded>>

\* The replay key. Stable means it excludes epoch and mode, so one source
\* event maps to one key everywhere; partitioned, each namespace gets its own.
ClaimKeyAt(o, e, m) ==
    IF GuardStableClaimId THEN <<o, 0, 0>> ELSE <<o, e, m>>

\* Ambient form, for validating a NEW submission against current state.
ClaimKey(o) == ClaimKeyAt(o, epoch, mode)

NoClaim == [out |-> 0, payee |-> 0, ep |-> 0, md |-> 0, key |-> 0]
Claims  == [out: Outputs, payee: Beneficiaries \cup Relayers, ep: Epochs,
            md: Modes, key: {ClaimKeyAt(o, e, m) :
                              o \in Outputs, e \in Epochs, m \in Modes}]

TypeOK ==
    /\ consumed \subseteq (Outputs \X (Epochs \cup {0}) \X (Modes \cup {0}))
    /\ payouts \subseteq (Outputs \X (Beneficiaries \cup Relayers))
    /\ payCount \in [Outputs -> 0..2]
    /\ pending \in Claims \cup {NoClaim}
    /\ epoch \in Epochs
    /\ mode \in Modes
    /\ stranded \subseteq Outputs

Init ==
    /\ consumed = {}
    /\ payouts = {}
    /\ payCount = [o \in Outputs |-> 0]
    /\ pending = NoClaim
    /\ epoch = CHOOSE e \in Epochs : TRUE
    /\ mode = CHOOSE m \in Modes : TRUE
    /\ stranded = {}

Payee(o, r) == IF GuardBeneficiaryFromOutput THEN BeneficiaryOf[o] ELSE r

ValidateAndCall(o, r) ==
    /\ pending = NoClaim
    /\ ClaimKey(o) \notin consumed
    /\ payCount[o] < 2
    \* Capture the EXACT key. Review's trace: validate under (e1,m1), rotate to
    \* e2, then fail -- the failure removed <<o1,e2,m1>>, which was never
    \* inserted, while <<o1,e1,m1>> stayed consumed with nothing paid.
    /\ pending' = [out |-> o, payee |-> Payee(o, r), ep |-> epoch, md |-> mode,
                   key |-> ClaimKey(o)]
    /\ consumed' = IF GuardConsumeBeforeCall
                     THEN consumed \cup {ClaimKey(o)} ELSE consumed
    /\ UNCHANGED <<payouts, payCount, epoch, mode, stranded>>

(* A re-entrant call arrives DURING the external transfer, for the claim    *)
(* being transferred -- that is what re-entrancy is. Review caught the       *)
(* earlier version letting it select any output, which paid out for         *)
(* unrelated claims that had never been validated.                          *)
ReenterAttempt(r) ==
    /\ pending # NoClaim
    /\ pending.key \notin consumed             \* only open if CEI guard is off
    /\ payCount[pending.out] < 2
    /\ payouts' = payouts \cup {<<pending.out, Payee(pending.out, r)>>}
    /\ payCount' = [payCount EXCEPT ![pending.out] = @ + 1]
    /\ UNCHANGED <<consumed, pending, epoch, mode, stranded>>

ReturnSuccess ==
    /\ pending # NoClaim
    /\ payCount[pending.out] < 2
    /\ payouts' = payouts \cup {<<pending.out, pending.payee>>}
    /\ payCount' = [payCount EXCEPT ![pending.out] = @ + 1]
    /\ consumed' = consumed \cup {pending.key}
    /\ pending' = NoClaim
    /\ UNCHANGED <<epoch, mode, stranded>>

ReturnFailure ==
    /\ pending # NoClaim
    /\ consumed' = IF GuardRevertOnFailure
                     THEN consumed \ {pending.key} ELSE consumed
    \* Without the revert, the claim stays consumed although nothing was paid:
    \* the user's funds are unreachable for good.
    /\ stranded' = IF GuardRevertOnFailure THEN stranded
                    ELSE stranded \cup {pending.out}
    /\ pending' = NoClaim
    /\ UNCHANGED <<payouts, payCount, epoch, mode>>

\* Disabled during a pending synchronous call: an EVM transaction does not
\* observe an admin rotation mid-call. Modelling it as reachable produced a
\* namespace-drift artifact that had nothing to do with the guards under test.
Rotate(e)  == /\ pending = NoClaim
              /\ e # epoch /\ epoch' = e
              /\ UNCHANGED <<consumed, payouts, payCount, pending, mode, stranded>>
Upgrade(m) == /\ pending = NoClaim
              /\ m # mode /\ mode' = m
              /\ UNCHANGED <<consumed, payouts, payCount, pending, epoch, stranded>>

Next ==
    \/ \E o \in Outputs, r \in Relayers : ValidateAndCall(o, r)
    \/ \E r \in Relayers : ReenterAttempt(r)
    \/ ReturnSuccess \/ ReturnFailure
    \/ \E e \in Epochs : Rotate(e)
    \/ \E m \in Modes : Upgrade(m)

Spec == Init /\ [][Next]_vars

-------------------------------------------------------------------------
\* Every payout goes to the beneficiary named by THAT output. With distinct
\* beneficiaries per output this tests the binding rather than a constant.
INV_PaidOnlyNamedBeneficiary ==
    \A p \in payouts : p[2] = BeneficiaryOf[p[1]]

\* One source event, one payout -- across every epoch and mode.
INV_AtMostOnePayout == \A o \in Outputs : payCount[o] <= 1

\* A pending external call implies that exact claim is already consumed.
INV_PendingImpliesConsumed ==
    pending # NoClaim => pending.key \in consumed

\* KNOWN UNPROVED. This looks like the revert guard's property and is not.
\* `stranded` is set by the SAME guard branch that breaks rollback, so the
\* guard both introduces the bug and raises the flag that detects it. Counter-
\* mutating the real behaviour -- leave `consumed` untouched on failure while
\* keeping the `stranded` update "good" -- passes every invariant. A derived
\* property needs an independent failure-history record and a retry trace.
INV_NoStrandedClaims == stranded = {}

-------------------------------------------------------------------------
COV_CanPay       == payouts = {}
COV_CanPend      == pending = NoClaim
COV_CanRotate    == epoch = (CHOOSE e \in Epochs : TRUE)
COV_CanUpgrade   == mode = (CHOOSE m \in Modes : TRUE)
\* The good state review asked for: consumed AND a call in flight.
COV_ConsumedPend == ~(pending # NoClaim /\ pending.key \in consumed)
\* KNOWN UNPROVED. This does NOT cover ReturnFailure: its shortest violation
\* is Init -> ValidateAndCall, where the key is consumed and payCount is 0
\* with the call merely pending. No failure has occurred, and breaking the
\* rollback assignment leaves it firing regardless.
COV_CanRevert    == \A o \in Outputs : ClaimKey(o) \notin consumed \/ payCount[o] > 0
COV_CanStrand    == stranded = {}   \* reachable only with the revert guard off
=========================================================================
