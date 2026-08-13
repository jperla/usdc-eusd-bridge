#!/usr/bin/env python3
"""Which auditor class can see an unauthorized bridge spend?

A real two-world hyperproperty, rebuilt after the first version was found to
be a tautology. TLC searches for a pair of worlds with equal observations and
different V. Finding one PROVES the class insufficient; finding none over the
model proves it sufficient.
"""
import sys
from tlc_harness import CLEAN, ERROR, VIOLATED, HERE, expect, run

MODULE = "AuditObservability.tla"
CAPS = ["HasAF", "HasCatalog", "HasDeposits", "HasIntent", "HasLogs"]

# (label, predicate, capabilities, expected_sufficient)
CLASSES = [
    ("chain-only", "wasFOutputSpent", set(), False),
    ("+ a_F (inventory only)", "wasFOutputSpent", {"HasAF"}, False),
    # CONDITIONAL PROJECTION SELF-CHECK, not a derived result: Obs exposes
    # fs directly under HasCatalog. Retained because the CONTRAST with the
    # authorized-release row below is the useful finding.
    ("+ complete catalogue [self-check]", "wasFOutputSpent",
     {"HasAF", "HasCatalog"}, True),
    ("+ complete catalogue", "wasAuthorizedRelease", {"HasAF", "HasCatalog"}, False),
    ("+ deposits, no intent", "wasAuthorizedRelease",
     {"HasAF", "HasCatalog", "HasDeposits"}, False),
    ("operator logs, withheld", "wasAuthorizedRelease", set(), False),
]

# ASSUMED, NOT DERIVED -- excluded from the evidence above. Obs hands these
# observers ground truth directly, so their sufficiency is true by
# construction rather than searched for. `auth` is a free boolean, not derived
# from a deposit record, exact pre-intent, executed transaction, receipt or
# finalization; and publication does not make a colluding operator's log
# truthful or complete.
KNOWN_ASSUMED = [
    ("catalogue + deposits + intent", "wasAuthorizedRelease",
     {"HasAF", "HasCatalog", "HasDeposits", "HasIntent"}),
    ("operator logs, published", "wasAuthorizedRelease", {"HasLogs"}),
]


def write_cfg(name, predicate, caps=(), invariants=None):
    lines = ["SPECIFICATION Spec", "CONSTANTS", f'    Predicate = "{predicate}"']
    for c in CAPS:
        lines.append(f"    {c} = {'TRUE' if c in caps else 'FALSE'}")
    lines.append("INVARIANT TypeOK")
    for i in (invariants or ["INV_Observational"]):
        lines.append(f"INVARIANT {i}")
    p = HERE / f"{name}.cfg"
    p.write_text("\n".join(lines) + "\n")
    return p


def main():
    fails = []
    print("=" * 78)
    print("COVERAGE — the interesting CONFIGURATIONS must be reachable, not")
    print("merely some state. A pass here means the search never saw the pair.")
    print("=" * 78)
    for cov in ["COV_VDiffers", "COV_CovertSpend", "COV_EqualTraffic",
                "COV_AuthorizedSpend"]:
        c = expect(MODULE, write_cfg(f"_ao_cov_{cov}", "wasAuthorizedRelease",
                                     set(CAPS), invariants=[cov]), cov)
        alive = c.status == VIOLATED
        print(f"  {cov:<22} {'reachable' if alive else 'UNREACHABLE'}   {c}")
        if not alive:
            fails.append(f"{cov} unreachable")

    print()
    print("=" * 78)
    print("OBSERVER LATTICE — TLC searches for two worlds with EQUAL")
    print("observations and DIFFERENT V. Finding one proves insufficiency.")
    print("=" * 78)
    print(f"  {'observer':<32} {'predicate':<22} result")
    for i, (label, pred, caps, want_ok) in enumerate(CLASSES):
        cfg = write_cfg(f"_ao_{i}", pred, caps)
        r = (run(MODULE, cfg) if want_ok
             else expect(MODULE, cfg, "INV_Observational"))
        if r.status == ERROR:
            print(f"  {label:<32} {pred:<22} TOOL ERROR {r}")
            fails.append(f"{label}: {r}")
            continue
        ok = r.status == CLEAN
        print(f"  {label:<32} {pred:<22} "
              f"{'SUFFICIENT' if ok else 'cannot distinguish'}")
        if ok != want_ok:
            fails.append(f"{label}/{pred}: expected "
                         f"{'sufficient' if want_ok else 'insufficient'}")

    print()
    print("=" * 78)
    print("ASSUMED, NOT DERIVED — excluded from the results above")
    print("=" * 78)
    for label, pred, caps in KNOWN_ASSUMED:
        print(f"  {label:<32} {pred}")
    print()
    print("  Obs hands these observers ground truth directly, so a clean run")
    print("  reports an encoding rather than a search result. Deriving them")
    print("  needs auth built from an exact deposit, pre-registered intent, the")
    print("  executed transaction and finalization -- and adversarial logs")
    print("  treated as observations rather than truth oracles.")

    print()
    print("=" * 78)
    if fails:
        print(f"{len(fails)} FAILURE(S):")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("READING")
    print()
    print("What is DERIVED here is the insufficiency results, which are")
    print("genuine counterexample searches. The sufficiency rows above are not.")
    print()
    print("Chain-only and a_F both fail, and the reason a_F adds nothing is the")
    print("point: it identifies F-owned outputs and unmasks amounts, but a key")
    print("image needs the spend-private scalar, so it buys inventory")
    print("visibility and zero spend visibility.")
    print()
    print("The catalogue splits by PREDICATE, which is the result worth having.")
    print("It answers 'was a known F output spent?' and does NOT answer 'was")
    print("this an authorized release?' -- TLC exhibits two worlds where the")
    print("same F output was spent, the catalogue sees both identically, and")
    print("one had a matching deposit while the other did not.")
    print()
    print("Operator logs are not in the lattice at all. Publication does not")
    print("make a colluding operator's log truthful or complete, so neither")
    print("their presence nor their absence is evidence.")
    print()
    print("SCOPE. Observability only -- says nothing about whether an alarm can")
    print("be ACTED on, and CompositeGate shows that in Phase A it largely")
    print("cannot. The chain projection IMPORTS computational unlinkability by")
    print("omitting the key-image link; it does not derive it from sorting, and")
    print("an earlier version of this file wrongly said it did. Finalized")
    print("blocks expose concrete key-image values; sorting erases grouping,")
    print("not bytes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
