#!/usr/bin/env python3
"""Bounded coalition analysis, conditional on explicit ownership assumptions."""
import sys
import tempfile
from pathlib import Path
from tlc_harness import CLEAN, VIOLATED, HERE, expect

MODULE = "AttributionCoverage.tla"
CONFIGS = tempfile.TemporaryDirectory(prefix="attribution-configs-")
GUARANTEE = "INV_SpendNeedsThresholdPrincipals"
BAR = "INV_AttributedKeysMeetThreshold"
SHAPE = "COV_ForgeryShape"
FAKE = "FAKE_ConstantsOnlyGuarantee"
BOOLEANS = ["AttributionPerSeat", "NoRetainedCopies", "EndorserHoldsShare"]
PROPERTIES = [GUARANTEE, BAR, SHAPE]

# Expected violations, with each property tested in its own exhaustive run.
ROWS = [
    ("per-cohort attribution", dict(off="AttributionPerSeat"), {GUARANTEE, BAR, SHAPE}),
    ("identity/share owners may differ", dict(off="EndorserHoldsShare"), {GUARANTEE, SHAPE}),
    ("up to four keys per principal", dict(max_keys=4), {GUARANTEE, SHAPE}),
    ("retained share copies", dict(off="NoRetainedCopies"), {GUARANTEE}),
    ("up to two keys per principal", dict(max_keys=2), {GUARANTEE}),
]


def write_cfg(name, off=None, compromise=3, owner_t=2, max_keys=1, invariants=None,
              specification="Spec"):
    lines = [
        f"SPECIFICATION {specification}", "CONSTANTS",
        "    OwnerSeats = {o1, o2, o3}", "    GateSeats = {g1}",
        # One spare principal permits a dealer who holds no attributed seat.
        "    Principals = {p1, p2, p3, p4, p5}",
        "    CohortKeys = {kOwners, kGates}", "    NoOne = noone",
        f"    OwnerT = {owner_t}", "    GateT = 1",
        f"    CompromiseT = {compromise}", f"    MaxKeysPerPrincipal = {max_keys}",
    ]
    lines += [f"    {s} = {'FALSE' if s == off else 'TRUE'}" for s in BOOLEANS]
    lines += [f"INVARIANT {i}" for i in (invariants or [GUARANTEE, BAR])]
    p = Path(CONFIGS.name) / f"{name}.cfg"
    p.write_text("\n".join(lines) + "\n")
    return p


def main():
    fails = []

    def check(name, inv, wanted, **kw):
        r = expect(MODULE, write_cfg(name, invariants=[inv], **kw), inv)
        print(f"  {name} / {inv}: {r}")
        if r.status != wanted:
            fails.append(f"{name} / {inv}: expected {wanted}, got {r}")
        return r

    print("BASELINE: per-seat attribution plus THREE ownership assumptions")
    for inv in ["TypeOK", GUARANTEE, BAR]:
        check(f"_ac_base_{inv}", inv, CLEAN)
    print("COVERAGE: spending exists, and the claimed lower bound is tight")
    for inv in ["COV_CanSpend", "COV_TightCoalition"]:
        check(f"_ac_cov_{inv}", inv, VIOLATED)
    check("_ac_cov_COV_ForgeryShape", SHAPE, CLEAN)

    print("MUTATION MATRIX: type safety and each property checked separately")
    for index, (label, kw, violations) in enumerate(ROWS):
        print(f"  {label}")
        check(f"_ac_row{index}_TypeOK", "TypeOK", CLEAN, **kw)
        for inv in PROPERTIES:
            check(f"_ac_row{index}_{inv}", inv,
                  VIOLATED if inv in violations else CLEAN, **kw)

    print("SENSITIVITY AND SURVIVAL: reject inflated claims and a specific fake oracle")
    check("_ac_overclaim_guarantee", GUARANTEE, VIOLATED, compromise=4)
    check("_ac_overclaim_bar", BAR, CLEAN, compromise=4)
    check("_ac_undecided_threshold", GUARANTEE, VIOLATED, owner_t=1)
    check("_ac_survive_real", GUARANTEE, CLEAN, max_keys=2, compromise=2)
    check("_ac_survive_fake", FAKE, VIOLATED, max_keys=2, compromise=2)
    check("_ac_survive_fake_base", FAKE, CLEAN)

    # The two-principal residual claim must itself be tight, rather than merely
    # surviving because no modeled coalition spends below an unrelated bound.
    check("_ac_survive_tight", "COV_TightCoalition", VIOLATED,
          max_keys=2, compromise=2)

    print("CORRELATED SHARES: named holders do not establish share independence")
    for inv, wanted in [("TypeOK", CLEAN), (GUARANTEE, VIOLATED),
                         (BAR, CLEAN), (SHAPE, CLEAN)]:
        check(f"_ac_correlated_{inv}", inv, wanted,
              specification="SpecCorrelatedShares")
    check("_ac_correlated_bound", GUARANTEE, CLEAN, compromise=2,
          specification="SpecCorrelatedShares")
    check("_ac_correlated_tight", "COV_TightCoalition", VIOLATED, compromise=2,
          specification="SpecCorrelatedShares")

    if fails:
        print("FAIL\n  " + "\n  ".join(fails))
        return 1
    print("PASS: conditional bounds, mutation specificity and tightness checked.")
    print("Per-seat attribution raises the bar from two slots to four.")
    print("The three-principal bound additionally assumes separate key owners,")
    print("identity/share ownership by the same principal, and no retained copies.")
    print("Linked knowledge proofs require contributions from both secrets;")
    print("they do NOT prove that one principal holds both. Separate parties can")
    print("jointly produce a verifying proof while retaining separate secrets.")
    print("Thus EndorserHoldsShare remains a premise, not a theorem of the Rust")
    print("endorsement API. This model contains no proof-verification algorithm.")
    print("The quorum bound also assumes independent share material. Correlated")
    print("owner shares reduce the modeled bound to one owner plus one gate,")
    print("even with all three ownership assumptions true and four slots filled.")
    print("Scope: five principals, three owner seats, one gate seat. These are")
    print("finite structural checks, not a proof of implementation or operations.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
