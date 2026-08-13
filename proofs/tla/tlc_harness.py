"""Shared TLC harness that fails CLOSED, and tests mutation specificity honestly.

Two defects in the previous runners, both found by review:

  1. FAIL-OPEN. `run()` ignored TLC's exit code and treated "no invariant regex
     in the output" as success. A TLC environment failure therefore printed as
     `PASS 0 states`. A verification harness that reports success when the tool
     never ran is worse than no harness.

  2. FIRST-VIOLATION-ONLY. TLC stops at the first invariant it finds violated,
     so checking a list of invariants in one run cannot establish that a
     mutation breaks *exactly* one of them. The earlier claim "each mutation
     violates exactly its own invariant" was not supported by the evidence
     produced. `matrix()` below checks each invariant in its own run.

Every result is now one of three explicit outcomes -- CLEAN, VIOLATED, or
ERROR -- and ERROR is never silently treated as a pass.
"""
import re
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
JAVA = "/opt/homebrew/opt/openjdk@21/bin/java"
JAR = HERE / "tla2tools.jar"

CLEAN, VIOLATED, ERROR = "CLEAN", "VIOLATED", "ERROR"


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


def run(module, cfg_path):
    """Run TLC once. Returns a Result. Never reports success on tool failure."""
    if not Path(JAVA).exists():
        return Result(ERROR, detail=f"no java at {JAVA}")
    if not JAR.exists():
        return Result(ERROR, detail=f"no tla2tools.jar at {JAR}")
    try:
        p = subprocess.run(
            # -deadlock: terminal states are legitimate here (every deposit
            # released, every return redeemed, blocks exhausted). We assert
            # safety, not deadlock-freedom. The previous harness masked TLC's
            # deadlock report entirely by treating "no invariant match" as a
            # pass; now it would be a loud ERROR, so it is disabled explicitly.
            [JAVA, "-XX:+UseParallelGC", "-cp", str(JAR), "tlc2.TLC",
             "-config", Path(cfg_path).name, "-workers", "auto", "-cleanup",
             "-deadlock", module],
            cwd=HERE, capture_output=True, text=True, timeout=1800,
        )
    except subprocess.TimeoutExpired:
        return Result(ERROR, detail="TLC timed out")
    out = p.stdout + p.stderr

    m_states = re.search(r"([\d,]+) states generated", out)
    states = int(m_states.group(1).replace(",", "")) if m_states else 0

    m_viol = re.search(r"Invariant (\w+) is violated", out)
    # A state-independent invariant that is identically false gets a different
    # message and no counterexample trace. That is still a violation -- of a
    # degenerate kind -- and must not be reported as a tool error.
    m_const = re.search(r"The invariant of (\w+) is equal to FALSE", out)
    if m_const and not m_viol:
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
            return Result(ERROR, detail="violation reported without a trace",
                          raw=out)
        return Result(VIOLATED, invariant=m_viol.group(1), states=states, raw=out)

    if completed and p.returncode == 0:
        if states <= 0:
            return Result(ERROR, detail="completed but generated 0 states", raw=out)
        return Result(CLEAN, states=states, raw=out)

    # Anything else is a tool failure, and is reported as one.
    first_err = ""
    for line in out.splitlines():
        if line.startswith("Error:") or "Exception" in line or "cannot" in line.lower():
            first_err = line.strip()[:160]
            break
    return Result(ERROR,
                  detail=first_err or f"rc={p.returncode}, no completion marker",
                  states=states, raw=out)


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
