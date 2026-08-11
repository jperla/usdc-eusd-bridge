#!/usr/bin/env python3
"""The freeze bound with amounts, and the four assumptions it rests on."""
import sys
from tlc_harness import CLEAN, ERROR, VIOLATED, HERE, expect, matrix, run

MODULE = "FreezeBound.tla"
GUARDS = ["GuardRateLimit", "GuardFiniteDelta", "GuardPauseAllPaths",
          "GuardIndependentPauser"]
INVARIANTS = ["INV_FreezeBound", "INV_BalanceBound"]
WHY = {
    "GuardRateLimit": "without a contract-enforced rate, one release drains the balance",
    "GuardFiniteDelta": "without a finite detection-to-pause window, the pause may never land",
    "GuardPauseAllPaths": "a payout path that does not check the pause keeps paying",
    "GuardIndependentPauser": "a pauser that IS the compromised quorum never pauses",
}


def write_cfg(name, off=None, invariants=None):
    lines = ["SPECIFICATION Spec", "CONSTANTS",
             "    Balance = 12", "    Rho = 2", "    Delta = 2",
             "    Irrevocable = 2", "    MaxTick = 4"]
    for g in GUARDS:
        lines.append(f"    {g} = {'FALSE' if g == off else 'TRUE'}")
    lines.append("INVARIANT TypeOK")
    for i in (invariants or INVARIANTS):
        lines.append(f"INVARIANT {i}")
    p = HERE / f"{name}.cfg"
    p.write_text("\n".join(lines) + "\n")
    return p


def main():
    fails = []
    print("=" * 78)
    print("BASELINE — all four assumptions hold")
    print("Balance=12, rho=2/tick, Delta=2, P_irrevocable=2")
    print("so the bound is 2 + 2*2 = 6, against a balance of 12")
    print("=" * 78)
    r = run(MODULE, write_cfg("FreezeBound"))
    print(f"  {r}")
    if r.status != CLEAN:
        fails.append(f"baseline: {r}")

    print()
    print("=" * 78)
    print("COVERAGE")
    print("=" * 78)
    for cov in ["COV_CanDetect", "COV_CanPause", "COV_CanRelease",
                "COV_PostDetectionFlow"]:
        c = expect(MODULE, write_cfg(f"_fb_cov_{cov}", invariants=[cov]), cov)
        alive = c.status == VIOLATED
        print(f"  {cov:<24} {'reachable' if alive else 'UNREACHABLE'}   {c}")
        if not alive:
            fails.append(f"{cov} unreachable")

    print()
    print("=" * 78)
    print("MUTATIONS — each assumption must be necessary for the bound")
    print("=" * 78)
    for g in GUARDS:
        res = matrix(MODULE, write_cfg, INVARIANTS, off=g)
        errs = sorted(k for k, v in res.items() if v.status == ERROR)
        if errs:
            print(f"  {g:<26} TOOL ERROR on {errs}")
            fails.append(f"{g}: tool error")
            continue
        broke = sorted(k for k, v in res.items() if v.status == VIOLATED)
        ok = "INV_FreezeBound" in broke
        print(f"  {g:<26} {'ok' if ok else 'FAIL'}  breaks {broke or 'nothing'}")
        print(f"  {'':<26} {WHY[g]}")
        if not ok:
            fails.append(f"{g}: did not break INV_FreezeBound")
        if "INV_BalanceBound" in broke:
            fails.append(f"{g} broke the unconditional balance bound")

    print()
    print("=" * 78)
    if fails:
        print(f"{len(fails)} FAILURE(S):")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("READING: all four assumptions are load-bearing. Drop any one and")
    print("post-detection outflow exceeds P_irrevocable + rho*Delta -- so the")
    print("conditional bound in DESIGN-FINAL 5b may not be quoted unless all")
    print("four hold. The unconditional balance bound survives every mutation,")
    print("which is why it is the correct fallback to state.")
    print()
    print("SCOPE: one contract, one currency, integer ticks. Does NOT model")
    print("MobileCoin-side outflow -- a pause bounds the USDC leg only, and")
    print("stolen eUSD can still be realized outside the bridge.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
