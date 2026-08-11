--------------------- MODULE FreezeBound ---------------------
(***************************************************************************)
(* The freeze bound, with amounts.                                          *)
(*                                                                          *)
(* DESIGN-FINAL 5b states: if the contract enforces rate `rho` and          *)
(* `Delta_eff` finitely bounds finalized detection through effective pause, *)
(* incremental USDC outflow is at most                                      *)
(*                                                                          *)
(*     min(remaining contract balance, P_irrevocable + rho * Delta_eff)     *)
(*                                                                          *)
(* otherwise the hard bound is the remaining balance or an explicit         *)
(* allocation. That formula requires FOUR assumptions, and until now none   *)
(* of them was checked -- CompositeGate derives a related STRUCTURAL        *)
(* condition (which spends are irrevocable) but has no amounts, no rate and *)
(* no liability, so it cannot speak to this bound at all.                   *)
(*                                                                          *)
(* Each assumption is a guard here, and each mutation must break the bound. *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS
    Balance,        \* USDC in the escrow contract
    Rho,            \* contract-enforced release rate, per tick
    Delta,          \* ticks from detection to EFFECTIVE pause
    Irrevocable,    \* already-authorized outflow that a pause cannot recall
    MaxTick,

    GuardRateLimit,       \* the contract enforces rho per tick
    GuardFiniteDelta,     \* the pause takes effect within Delta ticks
    GuardPauseAllPaths,   \* every payout path checks the pause at execution
    GuardIndependentPauser \* the pauser is not the compromised quorum

VARIABLES
    tick,
    tickOutflow,    \* released THIS tick -- a rate is per-tick, not per-release
    irrevLeft,      \* already-authorized amount a pause cannot recall
    outflow,        \* cumulative USDC released
    detected,       \* the auditor has raised the alarm
    detectedAt,
    paused,         \* the pause is EFFECTIVE
    postDetection   \* outflow since detection

vars == <<tick, tickOutflow, irrevLeft, outflow, detected, detectedAt, paused, postDetection>>

TypeOK ==
    /\ tick \in 0..MaxTick
    /\ tickOutflow \in 0..Balance
    /\ irrevLeft \in 0..Irrevocable
    /\ outflow \in 0..Balance
    /\ detected \in BOOLEAN
    /\ detectedAt \in 0..MaxTick
    /\ paused \in BOOLEAN
    /\ postDetection \in 0..Balance

Init ==
    /\ tick = 0 /\ tickOutflow = 0 /\ irrevLeft = Irrevocable
    /\ outflow = 0 /\ detected = FALSE
    /\ detectedAt = 0 /\ paused = FALSE /\ postDetection = 0

\* How much may leave in one tick.
PerTick == IF GuardRateLimit THEN Rho ELSE Balance

(* A rate is PER TICK, not per release. The first version capped each single
   release at rho while allowing unboundedly many within one tick, so the
   baseline violated its own bound. *)
Release(amt) ==
    /\ amt > 0
    /\ tickOutflow + amt <= PerTick
    /\ outflow + amt <= Balance
    \* An effective pause stops payouts only if EVERY path checks it.
    /\ GuardPauseAllPaths => ~paused
    /\ outflow' = outflow + amt
    /\ tickOutflow' = tickOutflow + amt
    /\ postDetection' = IF detected THEN postDetection + amt ELSE postDetection
    /\ UNCHANGED <<irrevLeft, tick, detected, detectedAt, paused>>

(* Already-authorized outflow. A pause cannot recall it, so it escapes the
   rate limit and the pause check alike -- this is P_irrevocable itself. *)
ReleaseIrrevocable ==
    /\ irrevLeft > 0
    /\ outflow + 1 <= Balance
    /\ irrevLeft' = irrevLeft - 1
    /\ outflow' = outflow + 1
    /\ postDetection' = IF detected THEN postDetection + 1 ELSE postDetection
    /\ UNCHANGED <<tick, tickOutflow, detected, detectedAt, paused>>

Detect ==
    /\ ~detected /\ detected' = TRUE /\ detectedAt' = tick
    /\ UNCHANGED <<tick, tickOutflow, irrevLeft, outflow, paused, postDetection>>

(* The pause becomes effective. With a finite Delta it must land within that *)
(* window; without one it may never land. And a pauser that is the           *)
(* compromised quorum simply does not pause.                                 *)
Pause ==
    /\ detected /\ ~paused
    /\ GuardIndependentPauser
    \* Strictly before the deadline, so releases occur on exactly Delta ticks.
    /\ GuardFiniteDelta => tick < detectedAt + Delta
    /\ paused' = TRUE
    /\ UNCHANGED <<tick, tickOutflow, irrevLeft, outflow, detected, detectedAt, postDetection>>

(* Time advances. With a finite Delta the pause MUST have landed by the      *)
(* deadline, so the clock cannot run past it unpaused.                       *)
Tick ==
    /\ tick < MaxTick
    /\ GuardFiniteDelta /\ detected /\ GuardIndependentPauser =>
          (tick + 1 < detectedAt + Delta \/ paused)
    /\ tick' = tick + 1
    /\ tickOutflow' = 0              \* the rate window resets
    /\ UNCHANGED <<irrevLeft, outflow, detected, detectedAt, paused, postDetection>>

Next == (\E a \in 1..Balance : Release(a)) \/ ReleaseIrrevocable
        \/ Detect \/ Pause \/ Tick

Spec == Init /\ [][Next]_vars

-------------------------------------------------------------------------
\* THE BOUND. Post-detection outflow is at most what was already irrevocably
\* authorized, plus the rate times the detection-to-pause window.
INV_FreezeBound == postDetection <= Irrevocable + Rho * Delta

\* The unconditional fallback, which holds no matter what: the contract
\* cannot pay out more than it holds.
INV_BalanceBound == outflow <= Balance

-------------------------------------------------------------------------
COV_CanDetect  == ~detected
COV_CanPause   == ~paused
COV_CanRelease == outflow = 0
\* Releases must be reachable AFTER detection, or the bound is vacuous.
COV_PostDetectionFlow == postDetection = 0
=========================================================================
