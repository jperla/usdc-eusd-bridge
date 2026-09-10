"""Shared TLC harness that fails CLOSED, and tests mutation specificity honestly.

Four defects, all found by review, all fixed here:

  1. FAIL-OPEN ON CLEAN. `run()` ignored TLC's exit code and treated "no
     invariant regex in the output" as success. A TLC environment failure
     therefore printed as `PASS 0 states`. A verification harness that reports
     success when the tool never ran is worse than no harness.

  2. FIRST-VIOLATION-ONLY. TLC stops at the first invariant it finds violated,
     so checking a list of invariants in one run cannot establish that a
     mutation breaks *exactly* one of them. The earlier claim "each mutation
     violates exactly its own invariant" was not supported by the evidence
     produced. `matrix()` below checks each invariant in its own run.

  3. FAIL-OPEN ON VIOLATED -- the same defect as (1) on the other branch, and it
     survived the fix for (1) because only the CLEAN path was made to consult the
     return code. Both VIOLATED paths returned as soon as they matched a marker
     in the output, so output carrying a violation marker AND a later TLC
     crash (`rc=17`) was reported as VIOLATED. That matters more than it looks:
     every mutation row in every runner here treats VIOLATED as the DESIRED
     result, so a truncated or crashed run counted as a caught mutation. The
     return code is now checked on all three paths, against codes measured from
     this tree's `tla2tools.jar` rather than assumed, and `classify()` is a pure
     function so `run_harness_selftest.py` can exercise exactly this case
     without a JVM.

     A SECOND review pass found that first fix incomplete in three ways, all
     closed here and all now in the self-test: the two violation formats each
     accepted the OTHER's exit code; no accept path scanned for a crash that
     arrived AFTER the marker it was reading (only the fallback did, and the
     fallback is reached last); and a bare trace header with zero states
     generated -- a truncated run -- counted as a violation. The same pass found
     that `run_bridge_v3_tla.py` parses TLC itself and had the original defect
     in its own code; it now shares `fatal()` and pins the exit code.

  5. SHARED SCRATCH DIRECTORY. Every run passed `-cleanup` with a common cwd, so
     two TLC processes in the same checkout -- two sessions, or a runner and a
     mutation sweep -- deleted each other's state directory mid-run and both
     died with `StatePoolWriter` exceptions. That is precisely the output shape
     defect (3) misclassified. Each run now gets its own `-metadir`, removed
     when it finishes, so concurrent runs cannot collide.

Every result is one of three explicit outcomes -- CLEAN, VIOLATED, or ERROR --
and ERROR is never silently treated as a pass.
"""
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def java_binary():
    """Honor explicit tool selection; avoid the macOS no-runtime java stub."""
    if os.environ.get("JAVA_BIN"):
        return shutil.which(os.environ["JAVA_BIN"]) or os.environ["JAVA_BIN"]
    if os.environ.get("JAVA_HOME"):
        return str(Path(os.environ["JAVA_HOME"]) / "bin" / "java")
    for candidate in ("/opt/homebrew/opt/openjdk/bin/java",
                      "/opt/homebrew/opt/openjdk@21/bin/java"):
        if Path(candidate).is_file():
            return candidate
    return shutil.which("java") or "java"


JAVA = java_binary()
JAR = Path(os.environ.get("TLA2TOOLS_JAR", str(HERE / "tla2tools.jar"))).resolve()

CLEAN, VIOLATED, ERROR = "CLEAN", "VIOLATED", "ERROR"

# TLC's exit codes, MEASURED against the jar in this directory rather than read
# off a wiki -- the whole point of this whitelist is that it is not a guess:
#
#     0    model checking completed with nothing violated
#     12   a safety violation, both the trace form and the "violated by the
#          initial state" form
#     151  a state-independent invariant that is identically FALSE
#
# Anything else accompanying a violation marker means TLC also failed, and a
# harness that reports the desired outcome from a failed run is the defect this
# constant exists to close. Deliberately a whitelist: a new TLC version that
# starts reporting violations under some other code makes the runners fail
# loudly, which is the correct direction to be wrong in.
#
# The two are matched to their OWN message format, not unioned. A later review
# pass pointed out that accepting `{12, 151}` on both branches means a
# constant-false message under a safety-violation code -- which cannot happen
# unless something is wrong -- was still accepted.
CLEAN_RC = 0
TRACE_VIOLATION_RC = 12
CONST_FALSE_RC = 151

# Markers TLC only prints when the RUN failed, wherever they appear in the
# output. Scanned on every accept path, not only the fallback: the fallback is
# reached last, so a crash AFTER a violation or a completion line used to be
# invisible. Kept narrow and specific so a counterexample trace cannot trip it.
FATAL_MARKERS = (
    "TLC threw an unexpected exception",
    "Exception in thread",
    "java.lang.",
    "java.io.",
    "OutOfMemoryError",
    "Error: Failed to",
    "Parsing or semantic analysis failed",
)


def fatal(out):
    """The first failure marker in `out`, or None. Shared with runners that do
    their own parsing -- `run_bridge_v3_tla.py` had the same fail-open."""
    for m in FATAL_MARKERS:
        if m in out:
            return m
    return None


class Result:
    def __init__(self, status, invariant=None, states=0, detail="", raw=""):
        self.status = status
        self.invariant = invariant
        self.states = states
        self.detail = detail
        self.raw = raw

    @property
    def ok(self):
        return self.status in (CLEAN, VIOLATED)

    def __repr__(self):
        if self.status == VIOLATED:
            return f"VIOLATED({self.invariant}, {self.states} states)"
        if self.status == CLEAN:
            return f"CLEAN({self.states} states)"
        return f"ERROR({self.detail})"


def classify(out, rc):
    """Turn one TLC run's output and exit code into a Result.

    Pure, and separate from `run()` on purpose: the interesting cases -- a
    violation marker followed by a crash, a violation code with no marker -- are
    cheap to construct as strings and impossible to provoke on demand from a
    real TLC. `run_harness_selftest.py` drives this function directly, so the
    fail-closed behaviour is a checked claim rather than a comment.

    The rule, on every path: the MARKER says what TLC found, the RETURN CODE
    says whether TLC finished finding it. Both must agree.
    """
    # Long runs print progress counts before the final summary. Taking the
    # first match reports timing-dependent partial counts as completed work.
    state_counts = re.findall(r"([\d,]+) states generated", out)
    states = int(state_counts[-1].replace(",", "")) if state_counts else 0

    m_viol = re.search(r"Invariant (\w+) is violated", out)
    # A state-independent invariant that is identically false gets a different
    # message and no counterexample trace. That is still a violation -- of a
    # degenerate kind -- and must not be reported as a tool error.
    m_const = re.search(r"The invariant of (\w+) is equal to FALSE", out)

    def bad(detail):
        return Result(ERROR, states=states, raw=out, detail=detail)

    def rc_mismatch(what, want):
        """A marker TLC only prints when it means it, under a code it does not."""
        return bad(f"{what} but rc={rc}, expected {want}: TLC did not finish "
                   f"cleanly, so this run establishes nothing")

    # Checked BEFORE any accept path. A crash after the interesting line is the
    # whole defect this function was rewritten for, and it can follow a
    # violation marker, a constant-false marker or a completion line alike.
    crash = fatal(out)

    if m_const and not m_viol:
        if rc != CONST_FALSE_RC:
            return rc_mismatch(f"{m_const.group(1)} reported identically FALSE",
                               CONST_FALSE_RC)
        if crash:
            return bad(f"{m_const.group(1)} reported identically FALSE, then "
                       f"TLC failed: {crash}")
        return Result(VIOLATED, invariant=m_const.group(1), states=states,
                      detail="state-independent invariant, identically false",
                      raw=out)

    completed = "Model checking completed" in out
    # TLC prints this immediately before a counterexample trace.
    has_trace = "The behavior up to this point" in out

    # An INITIAL-STATE violation prints "violated by the initial state:" and no
    # "behavior up to this point" trace, because there is no behavior yet. That
    # is still a genuine violation. The fail-closed check was right to refuse a
    # silent pass but too strict about the format.
    init_viol = "violated by the initial state" in out

    if m_viol:
        if not (has_trace or init_viol):
            return bad("violation reported without a trace")
        if rc != TRACE_VIOLATION_RC:
            return rc_mismatch(f"{m_viol.group(1)} reported violated",
                               TRACE_VIOLATION_RC)
        # A trace HEADER with nothing generated is a truncated run. Measured,
        # not assumed: TLC prints no "states generated" line at all for an
        # initial-state violation, so the count is only required where TLC
        # actually reports one.
        if has_trace and not init_viol and states <= 0:
            return bad("violation reported with a trace header and 0 states "
                       "generated: the run was truncated")
        if crash:
            return bad(f"{m_viol.group(1)} reported violated, then TLC "
                       f"failed: {crash}")
        return Result(VIOLATED, invariant=m_viol.group(1), states=states, raw=out)

    if completed and rc == CLEAN_RC:
        if states <= 0:
            return bad("completed but generated 0 states")
        if crash:
            return bad(f"model checking reported complete, then TLC failed: {crash}")
        return Result(CLEAN, states=states, raw=out)

    # Anything else is a tool failure, and is reported as one. Note this also
    # catches a violation EXIT CODE with no violation marker, which would mean
    # the output was truncated before the thing that matters got printed.
    first_err = ""
    for line in out.splitlines():
        if line.startswith("Error:") or "Exception" in line or "cannot" in line.lower():
            first_err = line.strip()[:160]
            break
    return Result(ERROR,
                  detail=first_err or f"rc={rc}, no completion marker",
                  states=states, raw=out)


def run(module, cfg_path):
    """Run TLC once. Returns a Result. Never reports success on tool failure."""
    if not Path(JAVA).exists():
        return Result(ERROR, detail=f"no java at {JAVA}")
    if not JAR.exists():
        return Result(ERROR, detail=f"no tla2tools.jar at {JAR}")
    # Its OWN scratch directory, not the shared one `-cleanup` used to wipe.
    # Two TLC processes in this checkout -- a runner and a mutation sweep, or
    # two sessions -- used to delete each other's state pool and die with
    # exceptions that the pre-fix classifier read as violations.
    meta = tempfile.mkdtemp(prefix="tlc-")
    try:
        # TLC resolves configs relative to the model directory even when an
        # absolute path is supplied. Snapshot both into one private workdir;
        # this also isolates generated configs and source-level mutants.
        source = Path(module)
        if not source.is_absolute():
            source = HERE / source
        config = Path(cfg_path)
        if not config.is_absolute():
            config = HERE / config
        shutil.copy2(source, Path(meta) / source.name)
        shutil.copy2(config, Path(meta) / config.name)
        p = subprocess.run(
            # -deadlock: terminal states are legitimate here (every deposit
            # released, every return redeemed, blocks exhausted). We assert
            # safety, not deadlock-freedom. The previous harness masked TLC's
            # deadlock report entirely by treating "no invariant match" as a
            # pass; now it would be a loud ERROR, so it is disabled explicitly.
            [JAVA, "-XX:+UseParallelGC", "-cp", str(JAR), "tlc2.TLC",
             "-config", config.name,
             "-workers", os.environ.get("TLC_WORKERS", "1"),
             "-seed", "1", "-fp", "0",
             "-metadir", str(Path(meta) / "states"), "-deadlock", source.name],
            cwd=meta, capture_output=True, text=True, timeout=1800,
        )
    except subprocess.TimeoutExpired:
        return Result(ERROR, detail="TLC timed out")
    except OSError as exc:
        return Result(ERROR, detail=f"could not execute TLC: {exc}")
    finally:
        shutil.rmtree(meta, ignore_errors=True)
    return classify(p.stdout + p.stderr, p.returncode)


def expect(module, cfg_path, wanted):
    """Run and require that any violation names EXACTLY `wanted`.

    Every generated config also checks TypeOK, so a run that violates TypeOK
    (or any other invariant) would otherwise be counted as a hit for whatever
    invariant the caller asked about. That attribution bug made an unexpected
    violation indistinguishable from the intended one. A mismatch is an ERROR.
    """
    r = run(module, cfg_path)
    if r.status == VIOLATED and r.invariant != wanted:
        return Result(ERROR, invariant=r.invariant, states=r.states,
                      detail=f"expected {wanted}, TLC reported {r.invariant}",
                      raw=r.raw)
    return r


def matrix(module, write_cfg, invariants, **cfg_kwargs):
    """Check each invariant in its OWN run, requiring exact attribution.

    TLC halts at the first violation, so a single run over a list of invariants
    cannot establish which others would also have broken. Returns
    {invariant: Result}. An ERROR propagates -- it is never a pass -- and a
    violation naming a DIFFERENT invariant than the one requested is an ERROR,
    not a hit.
    """
    out = {}
    for inv in invariants:
        cfg = write_cfg(f"_matrix_{inv}", invariants=[inv], **cfg_kwargs)
        out[inv] = expect(module, cfg, inv)
    return out


def fmt_matrix(results):
    broke = sorted(k for k, v in results.items() if v.status == VIOLATED)
    errs = sorted(k for k, v in results.items() if v.status == ERROR)
    return broke, errs
