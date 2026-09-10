#!/usr/bin/env python3
"""Crash, lost acknowledgement, rollback and commitment-publication model."""
import sys
import tempfile
from pathlib import Path
from tlc_harness import CLEAN, VIOLATED, HERE, expect, run

MODULE = "DurablePublication.tla"
GUARDS = ["GuardDuplicate", "GuardAnchor", "GuardBeforePublish"]


def main():
    failures = []
    with tempfile.TemporaryDirectory(prefix="durable-publication-") as raw:
        work = Path(raw)
        def check(name, invariants, off=None, module=MODULE, status=CLEAN):
            cfg = work / f"{name}.cfg"
            cfg.write_text("SPECIFICATION Spec\nCONSTANTS\n" + "\n".join(
                f"{g} = {'FALSE' if g == off else 'TRUE'}" for g in GUARDS)
                + "\nINVARIANT TypeOK\n" + "\n".join(f"INVARIANT {i}" for i in invariants) + "\n")
            result = expect(module, cfg, invariants[0]) if status == VIOLATED else run(module, cfg)
            print(f"{name}: {result}")
            if result.status != status:
                failures.append(f"{name}: {result}")
        check("baseline", ["INV_OnePublication", "INV_AnchoredBeforePublication"])
        for cov in ["COV_Publish", "COV_RecoverThenPublish", "COV_LostAckThenPublish"]:
            check(cov, [cov], status=VIOLATED)
        for guard, inv in [("GuardDuplicate", "INV_OnePublication"),
                           ("GuardAnchor", "INV_OnePublication"),
                           ("GuardBeforePublish", "INV_AnchoredBeforePublication")]:
            check(guard, [inv], off=guard, status=VIOLATED)
        source = (HERE / MODULE).read_text()
        target = 'IF pc = "reserveAck" THEN "bind" ELSE "ready"'
        if source.count(target) != 1:
            failures.append("source mutation target changed")
        else:
            # All guards remain true, but publication becomes reachable as
            # soon as reserve is anchored, before any context binding exists.
            mutant = work / "PublishAfterReserve.tla"
            mutant.write_text(source.replace("MODULE DurablePublication ", "MODULE PublishAfterReserve ")
                              .replace(target, '"ready"'))
            check("source-publish-after-reserve", ["INV_AnchoredBeforePublication"],
                  module=str(mutant), status=VIOLATED)
    if failures:
        print("FAIL\n" + "\n".join(failures))
        return 1
    print("PASS: one session/seat, four durable writes, two possible publications.")
    print("Models reserve/bind acknowledgement loss, crash, recovery and rollback.")
    print("Durable writes, hash security and an independent honest anchor are premises.")
    print("Independent finite design evidence; no hardware or Rust refinement claim.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
