#!/usr/bin/env python3
"""Model-check BridgeA.tla, testing mutation specificity honestly.

Rewritten after review found two defects in the previous version:

  - it failed OPEN (a TLC error printed as "PASS 0 states"), and
  - it claimed each mutation broke "exactly" one invariant while only ever
    inspecting TLC's FIRST reported violation.

Both are fixed. Every invariant is now checked in its own TLC run, so the
report below states the FULL set each mutation breaks -- which is more than
one in at least one case, and that is reported rather than hidden.

The capacity mutation previously also changed FloatInit from 2 to 1, so it
varied two things at once. The baseline is now FloatInit=1 throughout, which
makes an overdraw reachable without a confounded comparison.
"""
import sys

from tlc_harness import CLEAN, ERROR, VIOLATED, HERE, expect, matrix, run

MODULE = "BridgeA.tla"

GUARDS = [
    "GuardReplayDeposit", "GuardReplayReturn", "GuardRecipient", "GuardCapacity",
    "GuardOneWay", "GuardReleaseSource", "GuardThreshold", "GuardRootTiming",
]

INVARIANTS = [
    "INV_NoDoubleRelease", "INV_NoDoubleRedeem", "INV_RedeemRequiresArrival",
    "INV_BalancesNonNegative", "INV_OneWaySweep", "INV_NoReleaseFromR",
    "INV_ThresholdRespected", "INV_RootTiming", "INV_ContractSolvent",
    "INV_TheftBounded",
]

# The invariant each guard exists to protect. A mutation must break this one;
# it may break others, and those are reported.
PROTECTS = {
    "GuardReplayDeposit": "INV_NoDoubleRelease",
    "GuardReplayReturn": "INV_NoDoubleRedeem",
    "GuardRecipient": "INV_RedeemRequiresArrival",
    "GuardCapacity": "INV_BalancesNonNegative",
    "GuardOneWay": "INV_OneWaySweep",
    "GuardReleaseSource": "INV_NoReleaseFromR",
    "GuardThreshold": "INV_ThresholdRespected",
    "GuardRootTiming": "INV_RootTiming",
}

FLOAT_INIT = 1   # one common value; overdraw reachable with 2 deposits


def write_cfg(name, off=None, corrupt=False, invariants=None):
    inv = invariants if invariants is not None else INVARIANTS
    lines = [
        "SPECIFICATION Spec",
        "CONSTANTS",
        "    Deposits = {d1, d2}",
        "    Returns  = {r1, r2}",
        "    Operators = {o1, o2, o3}",
        "    K = 2",
        f"    FloatInit = {FLOAT_INIT}",
        "    MaxBlock = 2",
    ]
    for g in GUARDS:
        lines.append(f"    {g} = {'FALSE' if g == off else 'TRUE'}")
    lines.append(f"    AllowCorruptRelease = {'TRUE' if corrupt else 'FALSE'}")
    lines.append("INVARIANT TypeOK")
    for i in inv:
        lines.append(f"INVARIANT {i}")
    p = HERE / f"{name}.cfg"
    p.write_text("\n".join(lines) + "\n")
    return p


def main():
    fails = []

    print("=" * 78)
    print("BASELINE — all guards on, no collusion")
    print("=" * 78)
    r = run(MODULE, write_cfg("BridgeA"))
    print(f"  {r}")
    if r.status != CLEAN:
        fails.append(f"baseline: {r}")

    print()
    print("=" * 78)
    print("COVERAGE — written to FAIL. A pass means that state is unreachable")
    print("and every CLEAN result above is worthless.")
    print("=" * 78)
    for cov in ["COV_CanRelease", "COV_CanRedeem", "COV_CanSweep", "COV_BlocksMove"]:
        c = expect(MODULE, write_cfg(f"_cov_{cov}", invariants=[cov]), cov)
        alive = c.status == VIOLATED
        print(f"  {cov:<18} {'reachable' if alive else 'UNREACHABLE'}   {c}")
        if not alive:
            fails.append(f"{cov}: unreachable — model is dead here")

    print()
    print("=" * 78)
    print("MUTATIONS — every invariant checked in its OWN run, so the full set")
    print("each mutation breaks is reported, not just the first one TLC hits.")
    print("=" * 78)
    for g in GUARDS:
        res = matrix(MODULE, write_cfg, INVARIANTS, off=g)
        broke = sorted(k for k, v in res.items() if v.status == VIOLATED)
        errs = sorted(k for k, v in res.items() if v.status == ERROR)
        want = PROTECTS[g]
        if errs:
            print(f"  {g:<22} TOOL ERROR on {errs}")
            fails.append(f"{g}: tool error on {errs}")
            continue
        ok = want in broke
        extra = [b for b in broke if b != want]
        note = "" if not extra else f"  (also: {', '.join(extra)})"
        print(f"  {g:<22} breaks {want:<26} {'ok' if ok else 'FAIL'}{note}")
        if not ok:
            fails.append(f"{g}: did NOT break {want}; broke {broke or 'nothing'}")

    print()
    print("=" * 78)
    print("HONEST LIMIT — a colluding quorum releases with no deposit behind it")
    print("=" * 78)
    res = matrix(MODULE, write_cfg, INVARIANTS + ["INV_AllReleasesBacked"],
                 corrupt=True)
    errs = sorted(k for k, v in res.items() if v.status == ERROR)
    if errs:
        print(f"  TOOL ERROR on {errs}")
        fails.append(f"collusion: tool error on {errs}")
    else:
        broke = sorted(k for k, v in res.items() if v.status == VIOLATED)
        survived = sorted(k for k, v in res.items() if v.status == CLEAN)
        if "INV_AllReleasesBacked" in broke:
            print("  INV_AllReleasesBacked  breaks, as designed — the bridge does")
            print("  not prevent a colluding quorum from releasing unbacked eUSD.")
        else:
            fails.append("collusion did not violate INV_AllReleasesBacked")
        # Both are EXPECTED to break: unbacked release is the acknowledged
        # limit, and NoReleaseFromR breaks because a compromised owner
        # threshold can spend R as well as F under the shared spend root.
        # Anything else breaking is a regression, not an observation.
        expected_broken = {"INV_AllReleasesBacked", "INV_NoReleaseFromR"}
        unexpected = [b for b in broke if b not in expected_broken]
        missing = [e for e in expected_broken if e not in broke]
        print(f"  also breaks (expected)      : "
              f"{sorted(expected_broken & set(broke) - {'INV_AllReleasesBacked'}) or 'none'}")
        print(f"  survives collusion          : {survived}")
        if unexpected:
            print(f"  UNEXPECTED breakage         : {unexpected}")
            fails.append(f"collusion broke unexpected invariants: {unexpected}")
        if missing:
            fails.append(f"collusion did NOT break expected: {missing}")

    print()
    print("=" * 78)
    if fails:
        print(f"{len(fails)} FAILURE(S):")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("Every guard breaks the invariant it protects. Where a mutation breaks")
    print("more than one, that is listed above rather than elided.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
