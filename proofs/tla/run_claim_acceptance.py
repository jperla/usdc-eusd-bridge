#!/usr/bin/env python3
"""Bounded beneficiary, replay, call-order, rollback and retry evidence."""
import sys
import tempfile
from pathlib import Path
from tlc_harness import CLEAN, ERROR, VIOLATED, HERE, expect, matrix, run

MODULE = "ClaimAcceptance.tla"
CONFIGS = tempfile.TemporaryDirectory(prefix="claim-configs-")
GUARDS = ["GuardBeneficiaryFromOutput", "GuardStableClaimId",
          "GuardConsumeBeforeCall", "GuardRevertOnFailure"]
INVARIANTS = ["INV_PaidOnlyNamedBeneficiary", "INV_AtMostOnePayout",
              "INV_PendingImpliesConsumed", "INV_FailureRestoresState"]

# Each mutation must break exactly this set; checking only the first reported
# invariant cannot establish independence of the other protections.
BREAKS = {
    "GuardBeneficiaryFromOutput": {"INV_PaidOnlyNamedBeneficiary"},
    "GuardStableClaimId": {"INV_AtMostOnePayout"},
    "GuardConsumeBeforeCall": {"INV_AtMostOnePayout", "INV_PendingImpliesConsumed"},
    "GuardRevertOnFailure": {"INV_FailureRestoresState"},
}


def write_cfg(name, off=None, invariants=None):
    lines = [
        "SPECIFICATION Spec", "CONSTANTS",
        "    Outputs = {o1, o2}", "    Beneficiaries = {alice, bob}",
        "    Relayers = {mallory}", "    Epochs = {e1, e2}",
        "    Modes = {m1, m2}",
    ]
    lines += [f"    {g} = {'FALSE' if g == off else 'TRUE'}" for g in GUARDS]
    lines += ["INVARIANT TypeOK"]
    lines += [f"INVARIANT {i}" for i in (invariants or INVARIANTS)]
    p = Path(CONFIGS.name) / f"{name}.cfg"
    p.write_text("\n".join(lines) + "\n")
    return p


def main():
    fails = []
    r = run(MODULE, write_cfg("ClaimAcceptance"))
    print(f"BASELINE: {r}")
    if r.status != CLEAN:
        fails.append(f"baseline: {r}")

    print("COVERAGE: each named state must be reachable")
    for cov in ["COV_CanPay", "COV_CanPend", "COV_CanRotate", "COV_CanUpgrade",
                "COV_ConsumedPend", "COV_CanRevert", "COV_RetryPays",
                "COV_SameBeneficiaryOutputsPay"]:
        c = expect(MODULE, write_cfg(f"_cacov_{cov}", invariants=[cov]), cov)
        print(f"  {cov}: {c}")
        if c.status != VIOLATED:
            fails.append(f"{cov}: expected a reachability witness, got {c}")

    print("MUTATION MATRIX: each invariant checked separately")
    for guard in GUARDS:
        res = matrix(MODULE, write_cfg, INVARIANTS, off=guard)
        errors = {k: v.detail for k, v in res.items() if v.status == ERROR}
        broke = {k for k, v in res.items() if v.status == VIOLATED}
        print(f"  {guard}: breaks {sorted(broke)}")
        if errors or broke != BREAKS[guard]:
            fails.append(f"{guard}: expected {BREAKS[guard]}, got {broke}; {errors}")

    # A failure still happens when rollback is broken; the old coverage probe
    # merely witnessed validation. But the exact failed key cannot be retried.
    for cov, wanted in [("COV_CanRevert", VIOLATED), ("COV_RetryPays", CLEAN)]:
        c = expect(MODULE, write_cfg(f"_cacov_broken_{cov}",
                   off="GuardRevertOnFailure", invariants=[cov]), cov)
        print(f"  broken rollback / {cov}: {c}")
        if c.status != wanted:
            fails.append(f"broken rollback / {cov}: wanted {wanted}, got {c}")

    # Counter-mutation: leave ALL guards true and corrupt only the state
    # assignment. The observer must detect actual failure, not a switch value.
    source = (HERE / MODULE).read_text()
    original = "consumed' = IF GuardRevertOnFailure THEN pending.before.consumed ELSE consumed"
    if source.count(original) != 1:
        fails.append("rollback source-mutation target changed; update this test explicitly")
    else:
        with tempfile.TemporaryDirectory(prefix="claim-rollback-") as raw:
            work = Path(raw)
            mutant = work / "ClaimAcceptanceBrokenRollback.tla"
            mutant.write_text(source.replace("MODULE ClaimAcceptance ",
                                             "MODULE ClaimAcceptanceBrokenRollback ")
                              .replace(original, "consumed' = consumed"))
            cfg = write_cfg("_cacov_source_broken", invariants=["INV_FailureRestoresState"])
            c = expect(str(mutant), cfg, "INV_FailureRestoresState")
            print(f"  source mutation with all guards TRUE: {c}")
            if c.status != VIOLATED:
                print(c.raw)
                fails.append(f"independent failure observer missed broken assignment: {c}")

    if fails:
        print("FAIL\n  " + "\n  ".join(fails))
        return 1
    print("PASS: four guards checked, actual revert observed, failed key retried.")
    print("Scope: finite two-output/two-epoch/two-mode model over one registry.")
    print("Rollback restores observed pre-call state, including nested effects.")
    print("A retry SUCCESS is reachable; eventual success is NOT proved (no")
    print("fairness or assumption that the external token eventually succeeds).")
    print("Authenticated outputs and immutable beneficiary decoding are premises;")
    print("these checks do not establish cryptography or implementation refinement.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
