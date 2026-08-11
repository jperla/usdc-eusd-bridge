---------------------------- MODULE BridgeA ----------------------------
(***************************************************************************)
(* Escrow bridge (phase A) — the design in DESIGN-FINAL.md.                 *)
(*                                                                          *)
(* USDC deposited on Ethereum causes eUSD to be RELEASED from a bridge      *)
(* float wallet F. eUSD returned to a public-view-key address R causes USDC *)
(* to be released on Ethereum. eUSD is moved, never created or destroyed.   *)
(*                                                                          *)
(* METHODOLOGY NOTE, and the reason this spec is structured the way it is.  *)
(* An earlier spec in this project proved its safety properties by putting  *)
(* validity into the release guard, which made the interesting failure      *)
(* unreachable. Every property here is therefore paired with a CONSTANT     *)
(* guard flag, and a bug configuration that switches exactly that guard off *)
(* and MUST produce a violation of exactly that invariant. A guard whose    *)
(* removal changes nothing is a guard that was never doing any work, and    *)
(* an invariant that survives its own guard being removed was vacuous.      *)
(*                                                                          *)
(* Deliberately reachable: AllowCorruptRelease models a colluding quorum    *)
(* releasing eUSD with no deposit behind it. The design does not prevent    *)
(* this and must not appear to. INV_AllReleasesBacked is EXPECTED TO FAIL   *)
(* under that configuration; INV_TheftBounded states what survives.         *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Deposits,               \* deposit identifiers on Ethereum
    Returns,                \* eUSD returns to R
    Operators,              \* the signer roster
    K,                      \* signing threshold
    FloatInit,              \* eUSD initially held in F
    MaxBlock,               \* bound on MobileCoin block index

    (* Each guard corresponds to one implementation requirement.           *)
    GuardReplayDeposit,     \* a deposit may fund at most one release
    GuardReplayReturn,      \* a return may redeem at most once (dedupe on output pubkey)
    GuardRecipient,         \* target_key check: the output is really payable to R
    GuardCapacity,          \* never release more eUSD than F holds
    GuardOneWay,            \* value never moves F -> R
    GuardReleaseSource,     \* releases never spend R-owned outputs
    GuardThreshold,         \* no release without K signers
    GuardRootTiming,        \* proof must be rooted in a block AFTER the output's

    AllowCorruptRelease     \* model a colluding quorum releasing with no deposit

VARIABLES
    deposited,      \* deposits whose USDC is locked
    releaseCount,   \* deposit -> number of releases funded by it
    redeemCount,    \* return  -> number of USDC releases it caused
    arrived,        \* returns that genuinely landed at R
    arrivedAt,      \* return  -> block index it landed in
    fBal,           \* eUSD in F (the float; funds releases)
    rBal,           \* eUSD in R (returns; public view key)
    usdcOut,        \* USDC released by the contract
    unbacked,       \* releases with no deposit behind them
    spentROutput,   \* a release spent an R-owned output (privacy break)
    sweptFtoR,      \* value moved F -> R (breaks the one-way rule)
    weakQuorum,     \* a release happened below threshold
    blk             \* current MobileCoin block index

vars == <<deposited, releaseCount, redeemCount, arrived, arrivedAt, fBal, rBal,
          usdcOut, unbacked, spentROutput, sweptFtoR, weakQuorum, blk>>

TypeOK ==
    /\ deposited \subseteq Deposits
    /\ releaseCount \in [Deposits -> 0..3]
    /\ redeemCount \in [Returns -> 0..3]
    /\ arrived \subseteq Returns
    /\ arrivedAt \in [Returns -> 0..MaxBlock]
    /\ fBal \in -3..(FloatInit + 4)
    /\ rBal \in -3..(FloatInit + 4)
    /\ usdcOut \in 0..4
    /\ unbacked \in 0..4
    /\ spentROutput \in BOOLEAN
    /\ sweptFtoR \in BOOLEAN
    /\ weakQuorum \in BOOLEAN
    /\ blk \in 0..MaxBlock

Init ==
    /\ deposited = {}
    /\ releaseCount = [d \in Deposits |-> 0]
    /\ redeemCount = [r \in Returns |-> 0]
    /\ arrived = {}
    /\ arrivedAt = [r \in Returns |-> 0]
    /\ fBal = FloatInit
    /\ rBal = 0
    /\ usdcOut = 0
    /\ unbacked = 0
    /\ spentROutput = FALSE
    /\ sweptFtoR = FALSE
    /\ weakQuorum = FALSE
    /\ blk = 0

(* A user deposits USDC into the Ethereum contract. *)
Deposit(d) ==
    /\ d \notin deposited
    /\ deposited' = deposited \cup {d}
    /\ UNCHANGED <<releaseCount, redeemCount, arrived, arrivedAt, fBal, rBal,
                   usdcOut, unbacked, spentROutput, sweptFtoR, weakQuorum, blk>>

(* Operators release eUSD against a deposit.  `src` is which wallet funds   *)
(* it; releasing from R is what GuardReleaseSource forbids.                 *)
Release(d, S, src) ==
    /\ d \in deposited
    /\ GuardReplayDeposit => releaseCount[d] = 0
    /\ GuardThreshold => Cardinality(S) >= K
    /\ GuardReleaseSource => src = "F"
    /\ IF src = "F" THEN (GuardCapacity => fBal > 0) ELSE (GuardCapacity => rBal > 0)
    /\ releaseCount' = [releaseCount EXCEPT ![d] = @ + 1]
    /\ IF src = "F"
         THEN /\ fBal' = fBal - 1
              /\ UNCHANGED <<rBal, spentROutput>>
         ELSE /\ rBal' = rBal - 1
              /\ spentROutput' = TRUE
              /\ UNCHANGED fBal
    /\ weakQuorum' = (weakQuorum \/ Cardinality(S) < K)
    /\ UNCHANGED <<deposited, redeemCount, arrived, arrivedAt, usdcOut,
                   unbacked, sweptFtoR, blk>>

(* A colluding quorum releases eUSD with no deposit behind it.  The design  *)
(* cannot prevent this; the model must be able to reach it.                 *)
(* Review: this previously drained only fBal, so INV_NoReleaseFromR survived
   collusion TAUTOLOGICALLY even though the design's shared-root threat says a
   compromised owner threshold can spend F AND R. It now spends either. *)
CorruptRelease(S, src) ==
    /\ AllowCorruptRelease
    /\ Cardinality(S) >= K
    /\ IF src = "F" THEN fBal > 0 ELSE rBal > 0
    /\ IF src = "F"
         THEN /\ fBal' = fBal - 1
              /\ UNCHANGED <<rBal, spentROutput>>
         ELSE /\ rBal' = rBal - 1
              /\ spentROutput' = TRUE
              /\ UNCHANGED fBal
    /\ unbacked' = unbacked + 1
    /\ UNCHANGED <<deposited, releaseCount, redeemCount, arrived, arrivedAt,
                   usdcOut, sweptFtoR, weakQuorum, blk>>

(* A user sends eUSD back to R. *)
Return(r) ==
    /\ r \notin arrived
    /\ arrived' = arrived \cup {r}
    /\ arrivedAt' = [arrivedAt EXCEPT ![r] = blk]
    /\ rBal' = rBal + 1
    /\ UNCHANGED <<deposited, releaseCount, redeemCount, fBal, usdcOut,
                   unbacked, spentROutput, sweptFtoR, weakQuorum, blk>>

(* Ethereum verifies a return and releases USDC.                            *)
(* GuardRecipient is the target_key check; without it a claimed return that *)
(* never arrived can be redeemed.  GuardRootTiming is the block N+1 rule.   *)
Redeem(r) ==
    /\ GuardRecipient => r \in arrived
    /\ GuardReplayReturn => redeemCount[r] = 0
    /\ GuardRootTiming => blk > arrivedAt[r]
    /\ usdcOut < Cardinality(deposited)      \* the contract cannot pay what it lacks
    /\ redeemCount' = [redeemCount EXCEPT ![r] = @ + 1]
    /\ usdcOut' = usdcOut + 1
    /\ UNCHANGED <<deposited, releaseCount, arrived, arrivedAt, fBal, rBal,
                   unbacked, spentROutput, sweptFtoR, weakQuorum, blk>>

(* Sweeping R into F is the intended, one-way direction. *)
SweepRtoF ==
    /\ rBal > 0
    /\ rBal' = rBal - 1
    /\ fBal' = fBal + 1
    /\ UNCHANGED <<deposited, releaseCount, redeemCount, arrived, arrivedAt,
                   usdcOut, unbacked, spentROutput, sweptFtoR, weakQuorum, blk>>

(* The forbidden direction: moving float into the public-view-key address   *)
(* would make those outputs publicly identifiable.                          *)
SweepFtoR ==
    /\ ~GuardOneWay
    /\ fBal > 0
    /\ fBal' = fBal - 1
    /\ rBal' = rBal + 1
    /\ sweptFtoR' = TRUE
    /\ UNCHANGED <<deposited, releaseCount, redeemCount, arrived, arrivedAt,
                   usdcOut, unbacked, spentROutput, weakQuorum, blk>>

Tick ==
    /\ blk < MaxBlock
    /\ blk' = blk + 1
    /\ UNCHANGED <<deposited, releaseCount, redeemCount, arrived, arrivedAt,
                   fBal, rBal, usdcOut, unbacked, spentROutput, sweptFtoR,
                   weakQuorum>>

Next ==
    \/ \E d \in Deposits : Deposit(d)
    \/ \E d \in Deposits, S \in SUBSET Operators, src \in {"F", "R"} : Release(d, S, src)
    \/ \E S \in SUBSET Operators, src \in {"F", "R"} : CorruptRelease(S, src)
    \/ \E r \in Returns : Return(r)
    \/ \E r \in Returns : Redeem(r)
    \/ SweepRtoF
    \/ SweepFtoR
    \/ Tick

Spec == Init /\ [][Next]_vars

-------------------------------------------------------------------------
(*                              INVARIANTS                                *)
(* Each is paired with the guard whose removal must break it.             *)

\* GuardReplayDeposit: one deposit funds at most one release.
INV_NoDoubleRelease == \A d \in Deposits : releaseCount[d] <= 1

\* GuardReplayReturn: one return redeems at most once.
INV_NoDoubleRedeem == \A r \in Returns : redeemCount[r] <= 1

\* GuardRecipient: USDC is released only for eUSD that genuinely arrived at R.
INV_RedeemRequiresArrival == \A r \in Returns : redeemCount[r] > 0 => r \in arrived

\* GuardCapacity: balances never go negative — no releasing eUSD we do not hold.
INV_BalancesNonNegative == fBal >= 0 /\ rBal >= 0

\* GuardOneWay: value never moves float -> public address.
INV_OneWaySweep == ~sweptFtoR

\* GuardReleaseSource: a release never spends an R-owned (publicly labelled)
\* output.  This is the structural core of the §2 privacy argument: R-owned
\* outputs are identifiable, so one appearing in a release ring identifies
\* the real input.
INV_NoReleaseFromR == ~spentROutput

\* GuardThreshold: no release below K signers.
INV_ThresholdRespected == ~weakQuorum

\* GuardRootTiming: an output created in block N is not in block N's root.
INV_RootTiming == \A r \in Returns : redeemCount[r] > 0 => blk > arrivedAt[r]

\* Structural, guard-independent: the contract never pays out more USDC than
\* was deposited.  Should hold even with a colluding quorum.
INV_ContractSolvent == usdcOut <= Cardinality(deposited)

\* The bound that survives collusion.  NOTE: this is NOT the initial float.
\* Returns swept from R replenish F, so a colluding quorum can release again
\* against the replenished balance.  TLC found this: `unbacked <= FloatInit`
\* is FALSE.  The real ceiling is all eUSD that ever came under bridge
\* control, which GROWS WITH VOLUME -- so "loss is bounded by the escrow"
\* means the balance at the moment of collusion, not the amount funded.
INV_TheftBounded == unbacked <= FloatInit + Cardinality(arrived)

-------------------------------------------------------------------------
(*                       COVERAGE ASSERTIONS                              *)
(* Written to FAIL. TLC violating one proves that state is reachable. A    *)
(* spec with a contradictory action reports "no violation" on every real   *)
(* invariant while being completely dead -- that happened in NonceSlot.tla *)
(* and was invisible until assertions like these were added. A CLEAN run   *)
(* is not evidence unless the model can be shown to move.                  *)

COV_CanRelease  == \A d \in Deposits : releaseCount[d] = 0
COV_CanRedeem   == \A r \in Returns : redeemCount[r] = 0
COV_CanSweep    == rBal = 0 \/ fBal <= FloatInit
COV_BlocksMove  == blk = 0

\* HONEST LIMIT.  Expected to FAIL whenever AllowCorruptRelease is TRUE.
\* The design does not prevent a colluding quorum from releasing unbacked
\* eUSD; it bounds and detects it.  This invariant exists to make that
\* limit explicit rather than to be satisfied.
INV_AllReleasesBacked == unbacked = 0

=========================================================================
