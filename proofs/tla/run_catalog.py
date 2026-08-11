#!/usr/bin/env python3
"""Derive what AuditObservability assumes: a complete, proof-valid catalogue."""
import sys
from tlc_harness import CLEAN, ERROR, VIOLATED, HERE, expect, matrix, run

MODULE = "CatalogIntegrity.tla"
# GuardNoOverwrite is handled separately below: it is SUBSUMED once Prove
# binds the (output, key image) pair.
GUARDS = ["GuardProofBeforeAnchor", "GuardAnchorBeforeSpend",
          "GuardUniqueMapping"]
ALL_GUARDS = GUARDS + ["GuardNoOverwrite"]
INVARIANTS = ["INV_SpentWasAnchoredFirst", "INV_AnchoredIsProven",
              "INV_InjectiveMapping", "INV_NoEquivocation",
              "INV_SpendableIsCatalogued"]
PROTECTS = {
    "GuardProofBeforeAnchor": "INV_AnchoredIsProven",
    "GuardAnchorBeforeSpend": "INV_SpentWasAnchoredFirst",
    "GuardUniqueMapping": "INV_InjectiveMapping",
}

# GuardNoOverwrite is SUBSUMED once Prove binds the (output, key image) pair:
# there is then exactly one valid key image per output, so a differing rewrite
# is already impossible. It is load-bearing only in the absence of
# proof-binding, which is what this pairing checks.
SUBSUMED = ("GuardNoOverwrite", "GuardProofBeforeAnchor", "INV_NoEquivocation")
WHY = {
    "GuardProofBeforeAnchor": "an entry with no valid CP proof asserts a relation nobody checked",
    "GuardAnchorBeforeSpend": "an entry created AFTER the spend proves nothing about that spend",
    "GuardUniqueMapping": "P->two I double-counts an output; I->two P misattributes a spend",
    "GuardNoOverwrite": "a rewritable entry lets the catalogue equivocate after the fact",
}


def write_cfg(name, off=None, invariants=None):
    lines = ["SPECIFICATION Spec", "CONSTANTS",
             "    Outputs = {p1, p2}", "    KeyImages = {i1, i2}"]
    for g in ALL_GUARDS:
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
    print("BASELINE — full catalogue discipline")
    print("=" * 78)
    r = run(MODULE, write_cfg("CatalogIntegrity"))
    print(f"  {r}")
    if r.status != CLEAN:
        fails.append(f"baseline: {r}")

    print()
    print("=" * 78)
    print("COVERAGE")
    print("=" * 78)
    for cov in ["COV_CanProve", "COV_CanAnchor", "COV_CanSpend", "COV_FullChain"]:
        c = expect(MODULE, write_cfg(f"_cat_cov_{cov}", invariants=[cov]), cov)
        alive = c.status == VIOLATED
        print(f"  {cov:<18} {'reachable' if alive else 'UNREACHABLE'}   {c}")
        if not alive:
            fails.append(f"{cov} unreachable")

    print()
    print("=" * 78)
    print("MUTATIONS")
    print("=" * 78)
    for g in GUARDS:
        res = matrix(MODULE, write_cfg, INVARIANTS, off=g)
        errs = sorted(k for k, v in res.items() if v.status == ERROR)
        if errs:
            print(f"  {g:<26} TOOL ERROR on {errs}")
            fails.append(f"{g}: tool error")
            continue
        broke = sorted(k for k, v in res.items() if v.status == VIOLATED)
        want = PROTECTS[g]
        ok = want in broke
        print(f"  {g:<26} {'ok' if ok else 'FAIL'}  breaks {broke or 'nothing'}")
        print(f"  {'':<26} {WHY[g]}")
        if not ok:
            fails.append(f"{g}: expected {want}, broke {broke}")

    print("=" * 78)
    print("SUBSUMED GUARD — load-bearing only without the stronger one")
    print("=" * 78)
    g, needs, inv = SUBSUMED
    r1 = run(MODULE, write_cfg("_sub_alone", off=g, invariants=[inv]))
    # Fail-closed: an ERROR must NOT print as 'breaks nothing', and a
    # VIOLATED here contradicts the section's own premise of subsumption.
    if r1.status == ERROR:
        print(f"  {g} off alone            -> TOOL ERROR {r1}")
        fails.append(f"subsumption r1: {r1}")
    elif r1.status == VIOLATED:
        print(f"  {g} off alone            -> breaks {r1.invariant} (NOT subsumed)")
        fails.append(f"{g} breaks {r1.invariant} alone; it is not subsumed")
    else:
        print(f"  {g} off alone            -> breaks nothing (subsumed)")
    cfgp = HERE / "_sub_both.cfg"
    lines = ["SPECIFICATION Spec", "CONSTANTS",
             "    Outputs = {p1, p2}", "    KeyImages = {i1, i2}"]
    for gg in ALL_GUARDS:
        lines.append(f"    {gg} = {'FALSE' if gg in (g, needs) else 'TRUE'}")
    lines.append("INVARIANT TypeOK")
    lines.append(f"INVARIANT {inv}")
    cfgp.write_text("\n".join(lines) + "\n")
    r2 = expect(MODULE, cfgp, inv)
    print(f"  {g} + {needs} off -> "
          f"{'breaks ' + inv if r2.status == VIOLATED else 'FAIL ' + str(r2)}")
    if r2.status != VIOLATED:
        fails.append(f"{g} not load-bearing even without {needs}")
    print()
    print("  Once Prove binds the (output, key image) pair there is exactly one")
    print("  valid key image per output, so a differing rewrite is already")
    print("  impossible and no-overwrite adds nothing. It matters only where")
    print("  proof-binding is absent. Reporting it as an independent")
    print("  load-bearing guard would credit it with the proof guard's work --")
    print("  the same conflation found earlier between uniqueness and")
    print("  overwrite, arriving from the other direction.")

    print()
    print("=" * 78)
    print("KNOWN UNPROVED, excluded from the evidence above:")
    print("  - pre-anchor correction reachability (the old COV_PreAnchorFix")
    print("    covered the FIRST write, not a correction)")
    print("  - inventory completeness: 'every F output is known' is assumed;")
    print("    there is no external finalized F-output inventory here")
    print("  - authorization, finalization, receipts and alarms: named in the")
    print("    header but absent from Next")
    print("  - MOST IMPORTANTLY: Spend requires this model's own `spendable`")
    print("    admission, and a colluding owner threshold is NOT forced through")
    print("    that gate by current consensus. The model verifies a mandatory")
    print("    mediator that does not exist -- see CompositeGate for what would")
    print("    be needed to create one.")
    print()
    print("READING: the ordering guard is the one that is easy to get wrong and")
    print("hard to notice. A catalogue entry that exists is not evidence; an")
    print("entry ANCHORED BEFORE the output became spend-eligible is. A CP proof")
    print("establishes the P<->I relation and says nothing about publication")
    print("time, completeness, or non-equivocation -- those are the other three.")
    print()
    print("SCOPE: derives ordering, injectivity, and that an anchored entry")
    print("equals the key image PROVEN for that output -- Prove now binds the")
    print("pair, so Record can no longer choose an arbitrary key image. Does")
    print("NOT model the proof system itself or the anchor's own failure modes.")

    print()
    print("=" * 78)
    # MUST come after EVERY section that appends to `fails`. It previously sat
    # before the subsumption block, so failures appended there printed FAIL
    # while the runner still exited 0.
    if fails:
        print(f"{len(fails)} FAILURE(S):")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("ALL CHECKS PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
