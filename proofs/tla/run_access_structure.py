#!/usr/bin/env python3
"""Minimum compromising coalition as a function of owner/gate role overlap."""
import sys
from tlc_harness import CLEAN, ERROR, VIOLATED, HERE, expect, run

MODULE = "AccessStructure.tla"

# (label, principals, owners, gates, K, Ga, expected T)
SCENARIOS = [
    ("3 principals, BOTH roles (full overlap)", 3, [1,2,3], [1,2,3], 2, 2, 2),
    ("same, owners 2-of-3 gates 3-of-3",        3, [1,2,3], [1,2,3], 2, 3, 3),
    ("disjoint 2-of-3 AND 2-of-3",              6, [1,2,3], [4,5,6], 2, 2, 4),
    ("disjoint 2-of-3 AND 1-of-2",              5, [1,2,3], [4,5],   2, 1, 3),
    ("partial overlap of 1",                    5, [1,2,3], [3,4,5], 2, 2, 3),
    ("partial overlap of 2",                    4, [1,2,3], [2,3,4], 2, 2, 2),
    # Josh 2026-08-10: "six distinct entities is too much". Smaller profiles:
    ("2-of-3 owners AND 1 gate  (4 entities)",  4, [1,2,3], [4],     2, 1, 3),
    ("2-of-2 owners AND 1 gate  (3 entities)",  3, [1,2],   [3],     2, 1, 3),
    ("1-of-2 owners AND 1 gate  (3 entities)",  3, [1,2],   [3],     1, 1, 2),
]


def write_cfg(name, n, owners, gates, k, ga, invariants=None):
    ps = ", ".join(f"p{i}" for i in range(1, n + 1))
    os_ = ", ".join(f"p{i}" for i in owners)
    gs = ", ".join(f"p{i}" for i in gates)
    lines = ["SPECIFICATION Spec", "CONSTANTS",
             f"    Principals = {{{ps}}}", f"    Owners = {{{os_}}}",
             f"    Gates = {{{gs}}}", f"    K = {k}", f"    Ga = {ga}",
             "INVARIANT TypeOK"]
    for i in (invariants or ["INV_MinCoalitionIsT"]):
        lines.append(f"INVARIANT {i}")
    p = HERE / f"{name}.cfg"
    p.write_text("\n".join(lines) + "\n")
    return p


def main():
    fails = []
    print("=" * 78)
    print("MINIMUM COMPROMISING COALITION,  T = max(K, G, K+G-r)")
    print("r = |Owners ∩ Gates|.  Assumes compromising a principal yields BOTH")
    print("of its role shares -- which is the load-bearing assumption.")
    print("=" * 78)
    print(f"  {'configuration':<38} {'T':>3}  {'bound':<9} {'tight'}")
    for i, (label, n, ow, ga_set, k, ga, want_t) in enumerate(SCENARIOS):
        args = (n, ow, ga_set, k, ga)
        lo = run(MODULE, write_cfg(f"_as_lo_{i}", *args))
        tight = expect(MODULE, write_cfg(f"_as_t_{i}", *args,
                                         invariants=["COV_TIsAchievable"]),
                       "COV_TIsAchievable")
        live = expect(MODULE, write_cfg(f"_as_a_{i}", *args,
                                        invariants=["COV_SomethingAuthorizes"]),
                      "COV_SomethingAuthorizes")
        okb = lo.status == CLEAN
        okt = tight.status == VIOLATED
        okl = live.status == VIOLATED
        print(f"  {label:<38} {want_t:>3}  "
              f"{'holds' if okb else 'FAILS':<9} {'yes' if okt else 'NO'}")
        if not okb:
            fails.append(f"{label}: bound does not hold ({lo})")
        if not okt:
            fails.append(f"{label}: T not achievable, bound not tight")
        if not okl:
            fails.append(f"{label}: nothing authorizes; invariant vacuous")

    print()
    print("=" * 78)
    if fails:
        print(f"{len(fails)} FAILURE(S):")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("READING")
    print()
    print("Full overlap collapses to max(K,G): three principals holding both")
    print("roles need only 2 compromised at 2-of-3/2-of-3, and 3 at 2-of-3/3-of-3")
    print("-- identical to plain 3-of-3. The role split buys no entity-level")
    print("compromise threshold.")
    print()
    print("Disjoint 2-of-3 AND 2-of-3 needs FOUR distinct principals, which is")
    print("the smallest ordinary profile with both thresholds at least two.")
    print()
    print("Partial overlap degrades smoothly: each overlapping principal counts")
    print("toward both thresholds and lowers T by one, until overlap saturates")
    print("the smaller threshold.")
    print()
    print("SCOPE. This is entity-level compromise only. It assumes compromising")
    print("a principal yields BOTH its role shares -- true for one organization")
    print("holding two keys, NOT necessarily true for separately administered,")
    print("non-bypassable systems where one role's credentials can fall alone.")
    print("It says nothing about liveness, key loss, or who administers what.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
