#!/usr/bin/env python3
"""Bounded subset-exhaustion lemma. NOT a liveness proof.

Follows from two earlier results: aborts after commitment exposure must burn
the slot (NonceSlot.tla), and standard FROST lets a selected participant force
an abort by withholding. So attempts, not slots, are the scarce resource.
"""
import sys
from tlc_harness import CLEAN, ERROR, VIOLATED, HERE, expect, run

MODULE = "SubsetRetry.tla"


def write_cfg(name, exclude=True, faulty="{p1}", n=4, k=2, maxatt=8,
              invariants=None):
    parts = ", ".join(f"p{i}" for i in range(1, n + 1))
    lines = [
        "SPECIFICATION Spec",
        "CONSTANTS",
        f"    Participants = {{{parts}}}",
        f"    Faulty = {faulty}",
        f"    K = {k}",
        f"    MaxAttempts = {maxatt}",
        f"    GuardExcludeOnTimeout = {'TRUE' if exclude else 'FALSE'}",
        "INVARIANT TypeOK",
    ]
    for i in (invariants or ["INV_BoundedAttempts"]):
        lines.append(f"INVARIANT {i}")
    p = HERE / f"{name}.cfg"
    p.write_text("\n".join(lines) + "\n")
    return p


def main():
    fails = []
    print("=" * 78)
    print("COVERAGE")
    print("=" * 78)
    for cov in ["COV_CanComplete", "COV_CanFail"]:
        c = expect(MODULE, write_cfg(f"_lcov_{cov}", invariants=[cov]), cov)
        alive = c.status == VIOLATED
        print(f"  {cov:<18} {'reachable' if alive else 'UNREACHABLE'}   {c}")
        if not alive:
            fails.append(f"{cov} unreachable")

    print()
    print("=" * 78)
    print("WITH subset exclusion — a failed subset is not retried unchanged")
    print("=" * 78)
    r = run(MODULE, write_cfg("SubsetRetry-exclude", exclude=True))
    print(f"  n=4 k=2, one withholder : {r}")
    if r.status != CLEAN:
        fails.append(f"exclusion should bound attempts, got {r}")
    else:
        print("  No execution that actually performs MaxAttempts attempts")
        print("  remains unfinished. Note the spec permits infinite stuttering,")
        print("  so this is NOT a claim that progress eventually happens.")

    print()
    print("=" * 78)
    print("WITHOUT subset exclusion — the same subset may be retried")
    print("=" * 78)
    r = expect(MODULE, write_cfg("SubsetRetry-noexclude", exclude=False),
               "INV_BoundedAttempts")
    if r.status == VIOLATED:
        print(f"  VIOLATED — the bound is reached without completing.")
        print(f"  ({r.states:,} states) A coordinator that retries a failing")
        print("  subset unchanged makes no progress, even though enough honest")
        print("  participants exist to complete. Retrying is not a strategy.")
    else:
        print(f"  FAIL — expected a violation, got {r}")
        fails.append(f"no-exclusion should reach the bound, got {r}")

    print()
    print("=" * 78)
    print("THE EXACT BOUND, actually checked rather than printed")
    print("C(n,k) - C(n-f,k) + 1 = C(4,2) - C(3,2) + 1 = 6 - 3 + 1 = 4")
    print("=" * 78)
    at = run(MODULE, write_cfg("SubsetRetry-bound4", exclude=True, maxatt=4))
    print(f"  MaxAttempts = 4 (the bound)      {at}")
    if at.status != CLEAN:
        fails.append(f"exact bound 4 should be clean, got {at}")
    below = expect(MODULE, write_cfg("SubsetRetry-bound3", exclude=True, maxatt=3),
                   "INV_BoundedAttempts")
    print(f"  MaxAttempts = 3 (one below)      "
          f"{'violated, as it must be' if below.status == VIOLATED else f'FAIL {below}'}")
    if below.status != VIOLATED:
        fails.append(f"bound-1 should violate, got {below}")
    print()
    print("  So 4 is TIGHT for this case: reachable and sufficient at 4,")
    print("  insufficient at 3. The 8-of-11 figures below are the same formula")
    print("  evaluated, NOT machine-checked -- n=11 is not run here.")

    print()
    print("=" * 78)
    print("TOO MANY WITHHOLDERS — n-f < k, progress is impossible")
    print("=" * 78)
    r = expect(MODULE, write_cfg("SubsetRetry-toomany", faulty="{p1, p2, p3}",
                                 invariants=["INV_ProgressPossible"]),
               "INV_ProgressPossible")
    if r.status == VIOLATED:
        print("  INV_ProgressPossible violated, correctly: with 3 of 4")
        print("  withholding and k=2, no honest subset exists. This is a")
        print("  roster fact, not a protocol failure — no retry policy helps.")
    else:
        print(f"  unexpected: {r}")
        fails.append(f"expected ProgressPossible violation, got {r}")

    print()
    print("=" * 78)
    if fails:
        print(f"{len(fails)} FAILURE(S):")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("SCOPE. This is a combinatorial bound, not temporal liveness: the spec")
    print("has no fairness and Attempt() resolves atomically. The exact bound is")
    print("C(n,k) - C(n-f,k) + 1, checked tight above for n=4,k=2,f=1. The")
    print("8-of-11 figures 121/157/165 are that formula EVALUATED, not")
    print("machine-checked. They are operationally a stall either way. Exact")
    print("failed-subset non-retry is a fallback, not the scheduler; ROAST is the")
    print("design target.")
    print()
    print("On attribution, corrected: over authenticated channels the coordinator")
    print("DOES know which identities did not answer. What a timeout cannot tell")
    print("it is WHY -- malice, crash, censorship, partition or delay. So local")
    print("identification is available; transferable evidence of nonperformance")
    print("needs a stated delivery/synchrony assumption; proof of intent is not")
    print("available at all.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
