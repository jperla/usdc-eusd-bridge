#!/usr/bin/env python3
"""Durable state must authenticate every response-affecting field.

Migrates Ceremony.tla's last obligation into the slot-centric frame, so that
model can be retired.
"""
import sys
from tlc_harness import CLEAN, ERROR, VIOLATED, HERE, expect, matrix, run

MODULE = "PackageProjection.tla"
GUARDS = ["GuardFullProjection"]
INVARIANTS = ["INV_OneContextResponded", "INV_BindingDeterminesContext"]


def write_cfg(name, off=None, invariants=None):
    lines = ["SPECIFICATION Spec", "CONSTANTS",
             "    Statements = {s1}", "    Subsets = {u1}",
             "    PeerPkgs = {q1, q2}"]
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
    print("BASELINE — the stored encoding covers every response-affecting field")
    print("=" * 78)
    r = run(MODULE, write_cfg("PackageProjection"))
    print(f"  {r}")
    if r.status != CLEAN:
        fails.append(f"baseline: {r}")

    print()
    print("=" * 78)
    print("COVERAGE")
    print("=" * 78)
    for cov in ["COV_CanBind", "COV_CanRespond", "COV_CanCrash",
                "COV_RespondAfterRestart"]:
        c = expect(MODULE, write_cfg(f"_pp_cov_{cov}", invariants=[cov]), cov)
        alive = c.status == VIOLATED
        print(f"  {cov:<26} {'reachable' if alive else 'UNREACHABLE'}   {c}")
        if not alive:
            fails.append(f"{cov} unreachable")

    print()
    print("=" * 78)
    print("MUTATION — the stored encoding OMITS the peer round-one package,")
    print("holding statement and included set fixed")
    print("=" * 78)
    res = matrix(MODULE, write_cfg, INVARIANTS, off="GuardFullProjection")
    errs = sorted(k for k, v in res.items() if v.status == ERROR)
    broke = sorted(k for k, v in res.items() if v.status == VIOLATED)
    if errs:
        print(f"  TOOL ERROR on {errs}")
        fails.append(f"tool error: {errs}")
    else:
        print(f"  breaks {broke or 'nothing'}")
        for want in INVARIANTS:
            if want not in broke:
                fails.append(f"lossy projection did not break {want}")

    print()
    print("=" * 78)
    if fails:
        print(f"{len(fails)} FAILURE(S):")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("READING: a lossy encoding lets two packages that differ in a")
    print("response-affecting field share one stored binding. After a restart")
    print("the signer cannot tell them apart, because durable state never")
    print("authenticated the field that differs -- so it recomputes, and that")
    print("is a second response on one nonce.")
    print()
    print("The peer package is the field most likely to be dropped: it arrives")
    print("last, it is the bulkiest, and it is the one M2b's reservation digest")
    print("does NOT bind -- the complete round-one map enters only the later")
    print("binding-factor transcript during signing.")
    print()
    print("Ceremony.tla can now be retired; this is the obligation it carried.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
