#!/usr/bin/env python3
"""Reproducible focused TLC suite for BridgeEscrowV3.

This suite checks the reduced lifecycle model only.  It does not confer the
reserved full-contract BOUNDED MODEL PASS label.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


HERE = Path(__file__).resolve().parent
MODEL = HERE / "BridgeEscrowV3.tla"
BASELINE_CFG = HERE / "BridgeEscrowV3.cfg"
HONEST_CFG = HERE / "BridgeEscrowV3_honest.cfg"
JAR = Path(os.environ.get("TLA2TOOLS_JAR", "/Users/jperla/josh/spec/tla2tools.jar"))
JAVA = os.environ.get("JAVA_BIN", "/opt/homebrew/opt/openjdk@21/bin/java")

BASELINE_INVARIANTS = (
    "TypeOK",
    "ClaimLifecycleSound",
    "SourceLotProjection",
    "ReservationAtomic",
    "PriorBlockReservation",
    "AtomicFinalCommit",
    "SafeCancellation",
    "HistoryAndReplaySound",
    "FinalizedUnclearedRetained",
    "ChainLocalPauseSound",
    "ExactCulpritPenalty",
)


@dataclass(frozen=True)
class ExpectedViolation:
    name: str
    specification: str
    invariant: str
    include_baseline_safety: bool = False


EXPECTED_VIOLATIONS = (
    ExpectedViolation("false_source_witness", "Spec", "NoFalseSourceRelease"),
    ExpectedViolation(
        "honest_roundtrip_witness",
        "HonestSpec",
        "NoHonestRoundTrip",
        include_baseline_safety=True,
    ),
    ExpectedViolation("early_finalize", "SpecEarlyFinalize", "PriorBlockReservation"),
    ExpectedViolation("unsafe_cancel", "SpecUnsafeCancel", "SafeCancellation"),
    ExpectedViolation(
        "drop_final_exposure",
        "SpecDropFinalExposure",
        "FinalizedUnclearedRetained",
    ),
    ExpectedViolation("early_clear", "SpecEarlyClear", "FinalizedUnclearedRetained"),
    ExpectedViolation("extra_culprit", "SpecExtraCulprit", "ExactCulpritPenalty"),
    ExpectedViolation("global_pause", "SpecGlobalPause", "ChainLocalPauseSound"),
    ExpectedViolation("replay_promotion", "SpecReplayPromotion", "HistoryAndReplaySound"),
    ExpectedViolation("replay_final", "SpecReplayFinal", "HistoryAndReplaySound"),
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def tlc_command(config: Path) -> list[str]:
    return [
        JAVA,
        "-XX:+UseParallelGC",
        "-cp",
        str(JAR),
        "tlc2.TLC",
        "-cleanup",
        "-workers",
        "1",
        "-seed",
        "1",
        "-fp",
        "0",
        "-config",
        config.name,
        "BridgeEscrowV3",
    ]


def parse_counts(output: str) -> tuple[int, int, int]:
    states = re.search(r"(\d+) states generated, (\d+) distinct states found", output)
    depth = re.search(r"depth of the complete state graph search is (\d+)", output)
    if not states or not depth:
        raise AssertionError("TLC output did not contain complete state/depth counts")
    return int(states.group(1)), int(states.group(2)), int(depth.group(1))


def write_config(path: Path, case: ExpectedViolation) -> None:
    invariants = ["TypeOK"]
    if case.include_baseline_safety:
        invariants = list(BASELINE_INVARIANTS) + ["FullCycleConservation"]
    if case.invariant not in invariants:
        invariants.append(case.invariant)
    lines = [
        f"SPECIFICATION {case.specification}",
        "",
        "CHECK_DEADLOCK FALSE",
        "",
    ]
    lines.extend(f"INVARIANT {name}" for name in invariants)
    path.write_text("\n".join(lines) + "\n")


def assert_clean_pass(label: str, result: subprocess.CompletedProcess[str]) -> tuple[int, int, int]:
    if result.returncode != 0 or "Model checking completed. No error has been found." not in result.stdout:
        print(result.stdout, file=sys.stderr)
        raise AssertionError(f"{label} did not pass cleanly (exit {result.returncode})")
    return parse_counts(result.stdout)


def assert_named_violation(case: ExpectedViolation, result: subprocess.CompletedProcess[str]) -> tuple[int, int, int]:
    expected = f"Invariant {case.invariant} is violated."
    if result.returncode == 0 or expected not in result.stdout:
        print(result.stdout, file=sys.stderr)
        raise AssertionError(
            f"{case.name} did not produce the named oracle {case.invariant} "
            f"(exit {result.returncode})"
        )
    return parse_counts(result.stdout)


def main() -> None:
    for required in (MODEL, BASELINE_CFG, HONEST_CFG, JAR, Path(JAVA)):
        if not required.is_file():
            raise SystemExit(f"missing required file: {required}")

    sany = run(
        [JAVA, "-cp", str(JAR), "tla2sany.SANY", MODEL.name],
        HERE,
    )
    if sany.returncode != 0 or "Semantic processing of module BridgeEscrowV3" not in sany.stdout:
        print(sany.stdout, file=sys.stderr)
        raise SystemExit("SANY FAIL")

    print("SANY PASS")
    print(f"model_sha256={sha256(MODEL)}")
    print(f"baseline_cfg_sha256={sha256(BASELINE_CFG)}")
    print(f"honest_cfg_sha256={sha256(HONEST_CFG)}")
    print(f"tla2tools_sha256={sha256(JAR)}")

    with tempfile.TemporaryDirectory(prefix="bridge-v3-tlc-") as raw:
        work = Path(raw)
        shutil.copy2(MODEL, work / MODEL.name)
        shutil.copy2(BASELINE_CFG, work / BASELINE_CFG.name)
        shutil.copy2(HONEST_CFG, work / HONEST_CFG.name)

        baseline = run(tlc_command(work / BASELINE_CFG.name), work)
        counts = assert_clean_pass("baseline", baseline)
        print(f"baseline PASS generated={counts[0]} distinct={counts[1]} depth={counts[2]}")

        honest = run(tlc_command(work / HONEST_CFG.name), work)
        counts = assert_clean_pass("honest_cycle", honest)
        print(f"honest_cycle PASS generated={counts[0]} distinct={counts[1]} depth={counts[2]}")

        for case in EXPECTED_VIOLATIONS:
            config = work / f"{case.name}.cfg"
            write_config(config, case)
            result = run(tlc_command(config), work)
            counts = assert_named_violation(case, result)
            print(
                f"{case.name} WITNESS oracle={case.invariant} "
                f"generated={counts[0]} distinct={counts[1]} depth={counts[2]}"
            )

    print(
        "FOCUSED TLA SUITE PASS: baseline=1 honest_cycle=1 "
        f"named_witnesses={len(EXPECTED_VIOLATIONS)}"
    )


if __name__ == "__main__":
    main()
