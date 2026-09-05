#!/usr/bin/env python3
"""Does the harness every other runner depends on actually fail CLOSED?

WHY THIS FILE EXISTS. `tlc_harness.run()` decides, for all thirteen runners,
whether a TLC invocation counted as CLEAN, VIOLATED or ERROR. Nothing checked
that decision, and review found it wrong twice in the same way: the CLEAN path
consulted TLC's exit code and the two VIOLATED paths did not, so output that
carried a violation marker and then crashed (`rc=17`) was reported as VIOLATED.
Every mutation row in every runner treats VIOLATED as the DESIRED result -- it
is how a runner says "the guard caught it" -- so a crashed run counted as a
caught mutation, in the direction that manufactures confidence.

The cases below cannot be provoked from a real TLC on demand, which is why
`classify()` was split out as a pure function over (output, exit code). No JVM,
no jar, no model: this runner is fast and runs first alphabetically.

WHAT IT DOES NOT ESTABLISH. That `TRACE_VIOLATION_RC` and `CONST_FALSE_RC` are
the codes this jar emits -- those were measured separately, and the other
runners' own passes are the standing evidence, since a wrong code turns every
real violation into an ERROR and fails the suite loudly. Only the classification
logic is covered here, and only for `tlc_harness`: `run_bridge_v3_tla.py` parses
TLC itself, and its fix is checked by `bridge_v3_cases()` at the end.
"""
import sys

from tlc_harness import CLEAN, VIOLATED, ERROR, classify

STATES = "12,345 states generated"
COMPLETED = "Model checking completed. No error has been found."
TRACE = "The behavior up to this point is:"
CRASH = ("Error: TLC threw an unexpected exception.\n"
         "java.lang.RuntimeException: StatePoolWriter")

# (label, TLC output, exit code, expected status, why this case is here)
CASES = [
    ("clean run",
     f"{COMPLETED}\n{STATES}", 0, CLEAN,
     "the ordinary pass"),

    ("clean marker, nonzero rc",
     f"{COMPLETED}\n{STATES}", 1, ERROR,
     "the FIRST fail-open review found: a completion line is not a completion"),

    ("clean marker, zero states",
     f"{COMPLETED}\n0 states generated", 0, ERROR,
     "a model that generated nothing checked nothing"),

    ("zero progress, positive final summary",
     f"0 states generated\n{COMPLETED}\n{STATES}", 0, CLEAN,
     "progress counts do not replace the final summary"),

    ("positive progress, zero final summary",
     f"{STATES}\n{COMPLETED}\n0 states generated", 0, ERROR,
     "earlier progress must not conceal an empty final count"),

    ("violation with a trace",
     f"Error: Invariant INV_Foo is violated.\n{TRACE}\n{STATES}", 12, VIOLATED,
     "the ordinary catch"),

    ("violation, then a crash",
     f"Error: Invariant INV_Foo is violated.\n{TRACE}\n{STATES}\n{CRASH}",
     17, ERROR,
     "THE REPORTED DEFECT. A marker plus a later crash used to read as "
     "VIOLATED, which every mutation row reads as success"),

    ("violation by the initial state",
     "Error: Invariant INV_Foo is violated by the initial state:\n"
     "State 1: <Initial predicate>\n1 states generated", 12, VIOLATED,
     "no trace is printed for an initial-state violation and it is still real"),

    ("initial-state violation, then a crash",
     "Error: Invariant INV_Foo is violated by the initial state:\n"
     f"1 states generated\n{CRASH}", 17, ERROR,
     "the same defect on the trace-less branch"),

    ("violation marker with no trace at all",
     f"Error: Invariant INV_Foo is violated.\n{STATES}", 12, ERROR,
     "output truncated before the counterexample: nothing to read"),

    ("state-independent invariant, identically FALSE",
     "Error: The invariant of INV_Bar is equal to FALSE\n1 states generated",
     151, VIOLATED,
     "a degenerate violation, and still a violation"),

    ("identically FALSE, then a crash",
     f"Error: The invariant of INV_Bar is equal to FALSE\n{CRASH}", 1, ERROR,
     "THE SECOND REPORTED DEFECT, and the worse one: this branch never "
     "required a trace, so nothing else on it could have caught the crash"),

    ("violation exit code, no marker",
     f"{STATES}", 12, ERROR,
     "TLC says it violated something and did not say what: unusable"),

    # ---- the four a SECOND review pass found still accepted ----

    ("clean marker, rc=0, and an exception",
     f"{COMPLETED}\n{STATES}\n{CRASH}", 0, ERROR,
     "SECOND PASS: only the fallback scanned for exceptions, and the fallback "
     "is reached last, so a crash after the completion line was invisible"),

    ("violation with a trace, rc=12, and an exception",
     f"Error: Invariant INV_Foo is violated.\n{TRACE}\n{STATES}\n{CRASH}",
     12, ERROR,
     "SECOND PASS: the exit code was right and TLC still died afterwards"),

    ("identically FALSE, rc=151, and an exception",
     f"Error: The invariant of INV_Bar is equal to FALSE\n1 states generated\n{CRASH}",
     151, ERROR,
     "SECOND PASS: same, on the branch with no trace requirement to fall back on"),

    ("trace header, rc=12, zero states",
     f"Error: Invariant INV_Foo is violated.\n{TRACE}\n0 states generated",
     12, ERROR,
     "SECOND PASS: a header with nothing generated is a truncated run, not a "
     "counterexample"),

    ("identically FALSE under the TRACED violation code",
     "Error: The invariant of INV_Bar is equal to FALSE\n1 states generated",
     12, ERROR,
     "SECOND PASS: the two formats have their own exit codes; accepting the "
     "union meant a message and a code that cannot co-occur were still taken"),

    ("traced violation under the CONSTANT-FALSE code",
     f"Error: Invariant INV_Foo is violated.\n{TRACE}\n{STATES}", 151, ERROR,
     "SECOND PASS: the mirror image of the case above"),

    ("nothing at all",
     "", 0, ERROR,
     "TLC never ran; the pre-fix harness printed PASS 0 states here"),

    ("parse failure",
     "Error: Parsing or semantic analysis failed.", 255, ERROR,
     "a broken model is not a clean model"),
]


def bridge_v3_cases():
    """`run_bridge_v3_tla.py` parses TLC in its own code, and had the same
    fail-open: any nonzero exit code counted as the expected violation, and
    nothing looked past the marker. Review supplied marker + counts + a later
    crash + rc=17 and it was accepted. Driven here with synthetic completed
    processes, since the real thing takes minutes and cannot be made to crash on
    demand."""
    import subprocess
    import run_bridge_v3_tla as v3

    counts = ("1000 states generated, 500 distinct states found\n"
              "The depth of the complete state graph search is 7.")
    case = v3.EXPECTED_VIOLATIONS[0]
    marker = f"Error: Invariant {case.invariant} is violated."

    def proc(out, rc):
        return subprocess.CompletedProcess(args=["tlc"], returncode=rc, stdout=out)

    def refuses(fn, *args):
        # The runner prints the whole TLC output to stderr when it refuses,
        # which is right in production and noise here.
        import contextlib
        import io
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                fn(*args)
        except AssertionError:
            return True
        return False

    checks = [
        ("v3 violation, rc=12", not refuses(v3.assert_named_violation, case,
                                            proc(f"{marker}\n{counts}", 12)),
         "the ordinary catch must still be accepted"),
        ("v3 violation, rc=17 + crash", refuses(v3.assert_named_violation, case,
                                                proc(f"{marker}\n{counts}\n{CRASH}", 17)),
         "THE REPORTED DEFECT in this runner"),
        ("v3 violation, rc=12 + crash", refuses(v3.assert_named_violation, case,
                                                proc(f"{marker}\n{counts}\n{CRASH}", 12)),
         "right code, TLC still died afterwards"),
        # Separates the two guards: this one carries no exception text at all,
        # so only the pinned exit code can refuse it. Without it, reverting the
        # code check to "any nonzero" is caught by the crash scan instead and
        # the pinning looks unnecessary.
        ("v3 violation, rc=17, no crash text", refuses(v3.assert_named_violation, case,
                                                       proc(f"{marker}\n{counts}", 17)),
         "a violation TLC did not exit as a violation for"),
        ("v3 clean + crash", refuses(v3.assert_clean_pass, "baseline",
                                     proc(f"{COMPLETED}\n{counts}\n{CRASH}", 0)),
         "same on the clean path"),
        ("v3 clean, rc=0", not refuses(v3.assert_clean_pass, "baseline",
                                       proc(f"{COMPLETED}\n{counts}", 0)),
         "the ordinary pass must still be accepted"),
    ]
    out = []
    for label, ok, why in checks:
        print(f"  {label:<44} {'':<7} {'ok' if ok else 'WRONG'}")
        if not ok:
            out.append(f"{label}: {why}")
    return out


def isolated_execution_cases():
    """Configs, models and execution errors remain isolated without a JVM."""
    import subprocess
    import tempfile
    from pathlib import Path
    from unittest.mock import patch
    import tlc_harness as harness

    failures = []
    with tempfile.TemporaryDirectory(prefix="harness-selftest-") as raw:
        fixture = Path(raw)
        java = fixture / "java"
        jar = fixture / "tla2tools.jar"
        model = fixture / "Model.tla"
        config = fixture / "input.cfg"
        for path, value in [(java, "stub"), (jar, "stub"),
                            (model, "model snapshot"), (config, "config snapshot")]:
            path.write_text(value)
        workdirs = []

        def complete(command, **kwargs):
            work = Path(kwargs["cwd"])
            workdirs.append(work)
            if work == fixture or work == harness.HERE:
                failures.append("TLC did not receive a private working directory")
            if (work / model.name).read_text() != model.read_text():
                failures.append("TLC model snapshot differs from requested source")
            if (work / config.name).read_text() != config.read_text():
                failures.append("TLC config snapshot differs from requested config")
            if command[command.index("-config") + 1] != config.name:
                failures.append("TLC config is not relative to its private model directory")
            return subprocess.CompletedProcess(command, 0,
                stdout=f"{COMPLETED}\n{STATES}", stderr="")

        with patch.object(harness, "JAVA", str(java)), patch.object(harness, "JAR", jar):
            with patch.object(harness.subprocess, "run", side_effect=complete):
                result = harness.run(str(model), config)
            if result.status != CLEAN:
                failures.append(f"isolated successful invocation: {result}")
            if any(work.exists() for work in workdirs):
                failures.append("TLC work directory was not removed after completion")
            with patch.object(harness.subprocess, "run", side_effect=OSError("cannot execute")):
                result = harness.run(str(model), config)
            if result.status != ERROR:
                failures.append("an execution OSError did not fail closed")

        with patch.dict("os.environ", {"JAVA_BIN": str(java)}, clear=True):
            if harness.java_binary() != str(java):
                failures.append("JAVA_BIN override was ignored")
        with patch.dict("os.environ", {"JAVA_HOME": str(fixture)}, clear=True):
            if harness.java_binary() != str(fixture / "bin" / "java"):
                failures.append("JAVA_HOME override was ignored")

    print(f"  {'isolated execution, cleanup and tool selection':<52} "
          f"{'WRONG' if failures else 'ok'}")
    return failures


def main():
    fails = []
    print("=" * 78)
    print("HARNESS SELFTEST -- classify(output, exit code), no JVM needed")
    print("=" * 78)
    for label, out, rc, want, why in CASES:
        r = classify(out, rc)
        ok = r.status == want
        print(f"  {label:<44} rc={rc:<4} {r.status:<8} "
              f"{'ok' if ok else 'WRONG, wanted ' + want}")
        if not ok:
            fails.append(f"{label}: wanted {want}, got {r.status} ({r.detail}) "
                         f"-- {why}")

    counts = classify(f"7 states generated\n{COMPLETED}\n{STATES}", 0)
    if counts.states != 12345:
        fails.append(f"reported progress count instead of final count: {counts.states}")

    # `expect()` is the other place a wrong answer would be invisible: a run
    # that violates some OTHER invariant must not count as a hit for the one the
    # caller asked about. Driven through a stub, since the point is the
    # attribution rule and not TLC.
    print()
    import tlc_harness
    real_run = tlc_harness.run
    try:
        tlc_harness.run = lambda module, cfg: tlc_harness.Result(
            VIOLATED, invariant="INV_Other", states=7)
        r = tlc_harness.expect("M", "c.cfg", "INV_Wanted")
        ok = r.status == ERROR
        print(f"  {'expect(): a violation naming another invariant':<44} "
              f"{'':<7} {r.status:<8} {'ok' if ok else 'WRONG, wanted ERROR'}")
        if not ok:
            fails.append("expect() counted a different invariant as a hit")

        tlc_harness.run = lambda module, cfg: tlc_harness.Result(
            VIOLATED, invariant="INV_Wanted", states=7)
        r = tlc_harness.expect("M", "c.cfg", "INV_Wanted")
        ok = r.status == VIOLATED
        print(f"  {'expect(): the requested invariant':<44} "
              f"{'':<7} {r.status:<8} {'ok' if ok else 'WRONG, wanted VIOLATED'}")
        if not ok:
            fails.append("expect() rejected the invariant it asked for")
    finally:
        tlc_harness.run = real_run

    print()
    fails.extend(bridge_v3_cases())
    fails.extend(isolated_execution_cases())

    print()
    if fails:
        print("FAIL")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("PASS -- the harness reports success only when TLC finished and said so.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
