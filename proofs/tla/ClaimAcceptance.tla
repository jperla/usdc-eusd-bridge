------------------------ MODULE ClaimAcceptance ------------------------
(***************************************************************************)
(* Bounded claim lifecycle: validate/consume, external call, success or     *)
(* revert, retry, and changes of epoch/mode over one replay registry.       *)
(*                                                                         *)
(* SCOPE: authenticated outputs and decoded beneficiaries are assumptions. *)
(* This does not prove the codec, token implementation, implementation     *)
(* refinement, gas sufficiency, or separate contract deployments.          *)
(*                                                                         *)
(* lastFailure records actual before/after state. The old stranded flag   *)
(* read the same guard as the faulty transition, so a broken rollback      *)
(* could escape it. The new observer does not read that guard.             *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS Outputs, Beneficiaries, Relayers, Epochs, Modes,
          GuardBeneficiaryFromOutput, GuardStableClaimId,
          GuardConsumeBeforeCall, GuardRevertOnFailure

ASSUME Outputs # {} /\ Beneficiaries # {} /\ Relayers # {}
ASSUME Epochs # {} /\ Modes # {}

VARIABLES consumed, payouts, payCount, pending, epoch, mode, beneficiaryOf,
          lastFailure, failedKeys, retryPaid

vars == <<consumed, payouts, payCount, pending, epoch, mode, beneficiaryOf,
          lastFailure, failedKeys, retryPaid>>

ClaimKeyAt(o, e, m) ==
    IF GuardStableClaimId THEN <<o, 0, 0>> ELSE <<o, e, m>>
ClaimKey(o) == ClaimKeyAt(o, epoch, mode)
Keys == {ClaimKeyAt(o, e, m) : o \in Outputs, e \in Epochs, m \in Modes}
Payouts == SUBSET (Outputs \X (Beneficiaries \cup Relayers))
Counts == [Outputs -> 0..2]
Snapshot(c, p, n) == [consumed |-> c, payouts |-> p, counts |-> n]
Snapshots == [consumed: SUBSET Keys, payouts: Payouts, counts: Counts]
EmptySnapshot == Snapshot({}, {}, [o \in Outputs |-> 0])
NoClaim == [out |-> 0, payee |-> 0, key |-> 0, before |-> EmptySnapshot]
Claims == [out: Outputs, payee: Beneficiaries \cup Relayers,
           key: Keys, before: Snapshots]

TypeOK ==
    /\ consumed \subseteq Keys
    /\ payouts \in Payouts
    /\ payCount \in Counts
    /\ pending \in Claims \cup {NoClaim}
    /\ epoch \in Epochs /\ mode \in Modes
    /\ beneficiaryOf \in [Outputs -> Beneficiaries]
    /\ lastFailure \in [before: Snapshots, after: Snapshots]
    /\ failedKeys \subseteq Keys
    /\ retryPaid \in BOOLEAN

Init ==
    /\ consumed = {} /\ payouts = {}
    /\ payCount = [o \in Outputs |-> 0]
    /\ pending = NoClaim
    /\ epoch = CHOOSE e \in Epochs : TRUE
    /\ mode = CHOOSE m \in Modes : TRUE
    \* Includes different beneficiaries AND multiple outputs to one payee.
    /\ beneficiaryOf \in [Outputs -> Beneficiaries]
    /\ lastFailure = [before |-> EmptySnapshot, after |-> EmptySnapshot]
    /\ failedKeys = {} /\ retryPaid = FALSE

Payee(o, r) == IF GuardBeneficiaryFromOutput THEN beneficiaryOf[o] ELSE r

ValidateAndCall(o, r) ==
    /\ pending = NoClaim
    /\ ClaimKey(o) \notin consumed
    /\ payCount[o] < 2
    /\ pending' = [out |-> o, payee |-> Payee(o, r), key |-> ClaimKey(o),
                    before |-> Snapshot(consumed, payouts, payCount)]
    /\ consumed' = IF GuardConsumeBeforeCall
                     THEN consumed \cup {ClaimKey(o)} ELSE consumed
    /\ UNCHANGED <<payouts, payCount, epoch, mode, beneficiaryOf,
                    lastFailure, failedKeys, retryPaid>>

ReenterAttempt(r) ==
    /\ pending # NoClaim
    /\ pending.key \notin consumed
    /\ payCount[pending.out] < 2
    /\ payouts' = payouts \cup {<<pending.out, Payee(pending.out, r)>>}
    /\ payCount' = [payCount EXCEPT ![pending.out] = @ + 1]
    /\ UNCHANGED <<consumed, pending, epoch, mode, beneficiaryOf,
                    lastFailure, failedKeys, retryPaid>>

ReturnSuccess ==
    /\ pending # NoClaim
    /\ payCount[pending.out] < 2
    /\ payouts' = payouts \cup {<<pending.out, pending.payee>>}
    /\ payCount' = [payCount EXCEPT ![pending.out] = @ + 1]
    /\ consumed' = consumed \cup {pending.key}
    /\ retryPaid' = (retryPaid \/ pending.key \in failedKeys)
    /\ pending' = NoClaim
    /\ UNCHANGED <<epoch, mode, beneficiaryOf, lastFailure, failedKeys>>

ReturnFailure ==
    /\ pending # NoClaim
    \* An EVM revert undoes the whole call, including any nested transfer.
    /\ consumed' = IF GuardRevertOnFailure THEN pending.before.consumed ELSE consumed
    /\ payouts' = IF GuardRevertOnFailure THEN pending.before.payouts ELSE payouts
    /\ payCount' = IF GuardRevertOnFailure THEN pending.before.counts ELSE payCount
    \* Observe the state actually produced, independently of the guard.
    /\ lastFailure' = [before |-> pending.before,
                        after |-> Snapshot(consumed', payouts', payCount')]
    \* Only the most recent failure is needed for a retry witness. Retaining
    \* every failed namespace multiplies states without strengthening safety.
    /\ failedKeys' = {pending.key}
    /\ pending' = NoClaim
    /\ UNCHANGED <<epoch, mode, beneficiaryOf, retryPaid>>

\* Admin actions occur between synchronous external calls in this model.
Rotate(e) ==
    /\ pending = NoClaim /\ e # epoch /\ epoch' = e
    /\ UNCHANGED <<consumed, payouts, payCount, pending, mode, beneficiaryOf,
                    lastFailure, failedKeys, retryPaid>>
Upgrade(m) ==
    /\ pending = NoClaim /\ m # mode /\ mode' = m
    /\ UNCHANGED <<consumed, payouts, payCount, pending, epoch, beneficiaryOf,
                    lastFailure, failedKeys, retryPaid>>

Next ==
    \/ \E o \in Outputs, r \in Relayers : ValidateAndCall(o, r)
    \/ \E r \in Relayers : ReenterAttempt(r)
    \/ ReturnSuccess \/ ReturnFailure
    \/ \E e \in Epochs : Rotate(e)
    \/ \E m \in Modes : Upgrade(m)
Spec == Init /\ [][Next]_vars

INV_PaidOnlyNamedBeneficiary ==
    \A p \in payouts : p[2] = beneficiaryOf[p[1]]
INV_AtMostOnePayout == \A o \in Outputs : payCount[o] <= 1
INV_PendingImpliesConsumed == pending # NoClaim => pending.key \in consumed
INV_FailureRestoresState == lastFailure.after = lastFailure.before
\* Retained name for existing configs; the oracle is now observed state.
INV_NoStrandedClaims == INV_FailureRestoresState

COV_CanPay == payouts = {}
COV_CanPend == pending = NoClaim
COV_CanRotate == epoch = (CHOOSE e \in Epochs : TRUE)
COV_CanUpgrade == mode = (CHOOSE m \in Modes : TRUE)
COV_ConsumedPend == ~(pending # NoClaim /\ pending.key \in consumed)
\* Only ReturnFailure can change failedKeys; a pending call is insufficient.
COV_CanRevert == failedKeys = {}
\* A successful retry of the EXACT failed replay key, not an unrelated pay.
COV_RetryPays == ~retryPaid
COV_SameBeneficiaryOutputsPay ==
    ~(\E a, b \in Outputs : a # b /\ beneficiaryOf[a] = beneficiaryOf[b]
        /\ payCount[a] = 1 /\ payCount[b] = 1)
=========================================================================
