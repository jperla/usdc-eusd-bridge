#!/usr/bin/env python3
"""Caller-bound packet acceptance, with reachable rounds and source mutations."""
import sys
import tempfile
from pathlib import Path
from tlc_harness import CLEAN, VIOLATED, HERE, expect, run

FIELDS = ["Identity", "Signature", "Seat", "Phase", "Session", "Transcript", "Domain", "Canonical", "Length"]
MODULE = "PacketAcceptance.tla"


def main():
    failures = []
    with tempfile.TemporaryDirectory(prefix="packet-acceptance-") as raw:
        work = Path(raw)
        def check(name, invariants, off=None, module=MODULE, status=CLEAN):
            cfg = work / f"{name}.cfg"
            cfg.write_text("SPECIFICATION Spec\nCONSTANTS\n" + "\n".join(
                f"Guard{field} = {'FALSE' if field == off else 'TRUE'}" for field in FIELDS)
                + "\nINVARIANT TypeOK\n" + "\n".join(f"INVARIANT {i}" for i in invariants) + "\n")
            result = expect(module, cfg, invariants[0]) if status == VIOLATED else run(module, cfg)
            print(f"{name}: {result}")
            if result.status != status:
                failures.append(f"{name}: {result}")
        check("baseline", [f"INV_{f}" for f in FIELDS])
        for cov in ["COV_RoundOne", "COV_RoundTwo", "COV_RoundOneIgnoresTranscript"]:
            check(cov, [cov], status=VIOLATED)
        for field in FIELDS:
            check(f"missing-{field}", [f"INV_{field}"], off=field, status=VIOLATED)
        source = (HERE / MODULE).read_text()
        old = 'packet.session = "current"'
        # Replace only the acceptance predicate, leaving its invariant intact.
        target = '/\\ GuardSession => ' + old
        if source.count(target) != 1:
            failures.append("source mutation target changed")
        else:
            mutant = work / "PacketSelfSelectedContext.tla"
            mutant.write_text(source.replace("MODULE PacketAcceptance ", "MODULE PacketSelfSelectedContext ")
                              .replace(target, '/\\ GuardSession => packet.session = packet.session'))
            check("source-self-selected-context", ["INV_Session"], module=str(mutant), status=VIOLATED)
        # The model's safety invariants alone accept a reject-everything codec;
        # prove our positive-path probes distinguish that vacuous model.
        mutant = work / "PacketRejectEverything.tla"
        mutant.write_text(source.replace("MODULE PacketAcceptance ", "MODULE PacketRejectEverything ")
                          .replace('Accept ==\n', 'Accept ==\n    /\\ FALSE\n'))
        check("reject-all-safety", [f"INV_{f}" for f in FIELDS], module=str(mutant))
        check("reject-all-unreachable", ["COV_RoundOne", "COV_RoundTwo"], module=str(mutant))
    if failures:
        print("FAIL\n" + "\n".join(failures))
        return 1
    print("PASS: two keys/seats/phases/sessions/transcripts and malformed packet classes.")
    print("Assumes signature security, context collision resistance and correct caller enrollment.")
    print("Independent finite design evidence, not a cryptographic or Rust refinement proof.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
