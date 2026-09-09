#!/usr/bin/env python3
"""Finite recovery model, with counterexample and reachability controls."""
import sys
import tempfile
from pathlib import Path
from tlc_harness import CLEAN, VIOLATED, expect, run

MODULE = "JournalReconcile.tla"


def main():
    failures = []
    with tempfile.TemporaryDirectory(prefix="journal-reconcile-") as raw:
        work = Path(raw)
        def check(name, invariant, off=(), expected=CLEAN):
            cfg = work / f"{name}.cfg"
            cfg.write_text("SPECIFICATION Spec\nCONSTANTS\n" + "\n".join(
                f"{g} = {'FALSE' if g in off else 'TRUE'}"
                for g in ["GuardPredecessor", "GuardSequence", "GuardPoison"])
                + f"\nINVARIANT TypeOK\nINVARIANT {invariant}\n")
            result = expect(MODULE, cfg, invariant) if expected == VIOLATED else run(MODULE, cfg)
            print(f"{name}: {result}")
            if result.status != expected:
                failures.append(name)
        check("continuation", "INV_ExactContinuation")
        check("poison", "INV_NoPoisonRecovery")
        check("reachable", "COV_CanRecover", expected=VIOLATED)
        check("wrong-predecessor", "INV_ExactContinuation", ("GuardPredecessor",), VIOLATED)
        check("poison-bypass", "INV_NoPoisonRecovery", ("GuardPoison",), VIOLATED)
        # In an abstract full history, predecessor equality also implies the
        # length. Real code checks both hash and sequence independently.
        check("redundant-sequence", "INV_ExactContinuation", ("GuardSequence",))
        check("unchecked-history", "INV_ExactContinuation",
              ("GuardPredecessor", "GuardSequence"), VIOLATED)
    if failures:
        print("FAIL: " + ", ".join(failures))
        return 1
    print("PASS: histories over two records, lengths 0..3; independent design model, not implementation refinement.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
