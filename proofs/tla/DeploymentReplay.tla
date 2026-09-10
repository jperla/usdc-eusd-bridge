------------------------- MODULE DeploymentReplay -------------------------
(***************************************************************************)
(* Authenticated return destinations versus editable relay metadata.      *)
(* A deployment is (chain, escrow, namespace). Verifier upgrades that keep *)
(* this tuple keep the SAME escrow replay registry; a new escrow does not. *)
(* The authenticated destination is chosen independently at Init. Hashing *)
(* the tuple is modeled as injective; memo encryption, membership, quorum  *)
(* verification and hash collision resistance are premises, not results.  *)
(*                                                                         *)
(* Production v2 uses type 0x8002 and authenticates this tuple in the memo. *)
(* The relayer-tag branch represents the old editable metadata design.     *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS Outputs, Chains, Escrows, Namespaces,
          GuardAuthenticatedDomain, GuardRejectLegacy,
          GuardChain, GuardEscrow, GuardNamespace, GuardReplay

Deployments == Chains \X Escrows \X Namespaces
Versions == {"legacy", "bound"}
ASSUME Outputs # {} /\ Chains # {} /\ Escrows # {} /\ Namespaces # {}

VARIABLES destination, memoVersion, consumed, paid, payCount
vars == <<destination, memoVersion, consumed, paid, payCount>>

ExpectedDomain(d) ==
    <<IF GuardChain THEN d[1] ELSE CHOOSE c \in Chains : TRUE,
      IF GuardEscrow THEN d[2] ELSE CHOOSE e \in Escrows : TRUE,
      IF GuardNamespace THEN d[3] ELSE CHOOSE n \in Namespaces : TRUE>>

\* A legacy memo carries no authenticated destination. Permitting it here
\* allows relay metadata to fill that gap; the baseline rejects it first.
PresentedDomain(o, tag) ==
    IF GuardAuthenticatedDomain /\ memoVersion[o] = "bound"
      THEN destination[o] ELSE tag

\* Namespace-changing verifier upgrades still use the existing escrow's
\* registry. A new chain or escrow has independent state.
ReplayKey(d, o) == <<d[1], d[2], o>>
Keys == Chains \X Escrows \X Outputs

TypeOK ==
    /\ destination \in [Outputs -> Deployments]
    /\ memoVersion \in [Outputs -> Versions]
    /\ consumed \subseteq Keys
    /\ paid \subseteq (Outputs \X Deployments)
    /\ payCount \in [Outputs -> 0..2]

Init ==
    /\ destination \in [Outputs -> Deployments]
    /\ memoVersion \in [Outputs -> Versions]
    /\ consumed = {} /\ paid = {}
    /\ payCount = [o \in Outputs |-> 0]

Redeem(o, d, tag) ==
    /\ payCount[o] < 2
    /\ GuardRejectLegacy => memoVersion[o] = "bound"
    /\ PresentedDomain(o, tag) = ExpectedDomain(d)
    /\ GuardReplay => ReplayKey(d, o) \notin consumed
    /\ consumed' = consumed \cup {ReplayKey(d, o)}
    /\ paid' = paid \cup {<<o, d>>}
    /\ payCount' = [payCount EXCEPT ![o] = @ + 1]
    /\ UNCHANGED <<destination, memoVersion>>

Next == \E o \in Outputs, d \in Deployments, tag \in Deployments : Redeem(o, d, tag)
Spec == Init /\ [][Next]_vars

INV_OnlyIntendedDeployment == \A p \in paid : p[2] = destination[p[1]]
INV_OnlyBoundMemos == \A p \in paid : memoVersion[p[1]] = "bound"
INV_AtMostOnePayout == \A o \in Outputs : payCount[o] <= 1

COV_CanPay == paid = {}
COV_DistinctDestinationsPay ==
    ~(\E a, b \in Outputs : a # b /\ destination[a] # destination[b]
        /\ payCount[a] = 1 /\ payCount[b] = 1)
\* Wrong relay metadata cannot override a correct authenticated destination.
\* The editable tag is deliberately irrelevant to the baseline decision.
COV_RelayTagIrrelevant ==
    ~(\E o \in Outputs, d, tag \in Deployments :
        tag # destination[o] /\ ENABLED Redeem(o, d, tag))
=============================================================================
