#!/usr/bin/env python3
"""Finite provenance checks; authenticated output openings are model premises."""
import sys
import tempfile
from pathlib import Path
from tlc_harness import CLEAN, VIOLATED, HERE, expect, matrix, run

MODULE = "PayoutProvenance.tla"
CONFIGS = tempfile.TemporaryDirectory(prefix="payout-configs-")
FIELDS = ["DeriveAmount", "DeriveTokenId", "DerivePayee"]
PINNED = ["INV_AmountPinned", "INV_TokenPinned", "INV_PayeePinned"]
INVARIANTS = PINNED + ["INV_PayoutPinnedByOutput", "INV_OneOutputOneOutcome",
                        "INV_RelayerChoiceIndependent"]


def write_cfg(name, off=None, invariants=None):
    lines = [
        "SPECIFICATION Spec", "CONSTANTS",
        "    Outputs = {o1, o2}", "    Values = {v1, v2}",
        "    Tokens = {eusd, other}", "    Payees = {alice, mallory}",
    ]
    lines += [f"    {f} = {'FALSE' if f == off else 'TRUE'}" for f in FIELDS]
    lines += ["INVARIANT TypeOK"]
    lines += [f"INVARIANT {i}" for i in (invariants or INVARIANTS)]
    p = Path(CONFIGS.name) / f"{name}.cfg"
    p.write_text("\n".join(lines) + "\n")
    return p


def main():
    fails = []
    r = run(MODULE, write_cfg("PayoutProvenance"))
    print(f"BASELINE: {r}")
    if r.status != CLEAN:
        fails.append(f"baseline: {r}")
    for cov in ["COV_CanPay", "COV_DifferentOutputsPay"]:
        r = expect(MODULE, write_cfg(f"PayoutProvenance-{cov}",
                                     invariants=[cov]), cov)
        print(f"COVERAGE {cov}: {r}")
        if r.status != VIOLATED:
            fails.append(f"{cov}: expected a reachable witness, got {r}")

    print("MUTATION MATRIX: all invariants checked independently")
    for field, pinned in zip(FIELDS, PINNED):
        results = matrix(MODULE, write_cfg, INVARIANTS, off=field)
        want = {pinned, "INV_PayoutPinnedByOutput", "INV_RelayerChoiceIndependent"}
        got = {i for i, r in results.items() if r.status == VIOLATED}
        errors = {i: r.detail for i, r in results.items()
                  if r.status not in (CLEAN, VIOLATED)}
        print(f"  {field} off: breaks {sorted(got)}")
        if got != want or errors:
            fails.append(f"{field}: expected {want}, got {got}; {errors}")

    if fails:
        print("FAIL\n  " + "\n  ".join(fails))
        return 1
    print("PASS: each field constrains only its own value and payout choices.")
    print("Replay uniqueness survives all three mutations: it is a within-run")
    print("property and cannot prove the relayer has no choice of FIRST payout.")
    print("Scope: two outputs and two candidates per field. Derivation is an")
    print("abstract premise, not a proof that Solidity authenticates/unmasks them.")
    print("Cryptographic correctness and implementation refinement remain separate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
