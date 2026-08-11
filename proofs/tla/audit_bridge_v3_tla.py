#!/usr/bin/env python3
"""Static companion audit for the focused BridgeEscrowV3 TLC suite.

This does not parse TLA+ and must never be substituted for SANY/TLC.
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
TLA = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "BridgeEscrowV3.tla"
CFG = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / "BridgeEscrowV3.cfg"
HONEST_CFG = (
    Path(sys.argv[3])
    if len(sys.argv) > 3
    else HERE / "BridgeEscrowV3_honest.cfg"
)
RUNNER = HERE / "run_bridge_v3_tla.py"

EXPECTED_TLA_SHA256 = "afc87b6fa2982f7daf17f44b057113dbae64da0f0af67ccdf6cd3d9e2be7569b"
EXPECTED_CFG_SHA256 = "63dcf13c1443af55e94a9a953e67b84b25783988cac69cbe40494b921e08ef8c"
EXPECTED_HONEST_CFG_SHA256 = "32dbbb1e3dd4cf205ec955d99f2e20013d777c8201c5b40756edb6613344be50"
EXPECTED_RUNNER_SHA256 = "61a0e64427c8fe474e1e9f96b9cdd9da911218494e541bf5036a20056042a5b3"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def definition_names(text: str) -> set[str]:
    return set(
        re.findall(
            r"^([A-Za-z][A-Za-z0-9_]*)\s*(?:\([^\n]*\))?\s*==",
            text,
            re.MULTILINE,
        )
    )


def definition_body(text: str, name: str) -> str:
    start = re.search(
        rf"^{re.escape(name)}\s*(?:\([^\n]*\))?\s*==",
        text,
        re.MULTILINE,
    )
    if not start:
        raise AssertionError(f"missing definition {name}")
    following = re.search(
        r"^[A-Za-z][A-Za-z0-9_]*\s*(?:\([^\n]*\))?\s*==",
        text[start.end():],
        re.MULTILINE,
    )
    end = start.end() + following.start() if following else len(text)
    return text[start.end():end]


def strip_comments_and_strings(text: str) -> str:
    result: list[str] = []
    depth = 0
    in_string = False
    i = 0
    while i < len(text):
        pair = text[i:i + 2]
        char = text[i]
        if depth:
            if pair == "(*":
                depth += 1
                i += 2
            elif pair == "*)":
                depth -= 1
                i += 2
            else:
                i += 1
            continue
        if not in_string and pair == "(*":
            depth = 1
            i += 2
            continue
        if char == '"':
            in_string = not in_string
            result.append(" ")
            i += 1
            continue
        result.append(" " if in_string else char)
        i += 1
    if depth:
        raise AssertionError("unterminated block comment")
    if in_string:
        raise AssertionError("unterminated string")
    return "".join(result)


def check_delimiters(text: str) -> None:
    clean = strip_comments_and_strings(text)
    stack: list[tuple[str, int]] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for offset, char in enumerate(clean):
        if char in "([{":
            stack.append((char, offset))
        elif char in pairs:
            if not stack or stack[-1][0] != pairs[char]:
                raise AssertionError(f"unmatched {char} at byte {offset}")
            stack.pop()
    if stack:
        raise AssertionError(f"unclosed delimiters: {stack[-5:]}")
    if clean.count("<<") != clean.count(">>"):
        raise AssertionError("tuple delimiter count mismatch")


def main() -> None:
    tla = TLA.read_text()
    cfg = CFG.read_text()
    honest_cfg = HONEST_CFG.read_text()
    assert digest(TLA) == EXPECTED_TLA_SHA256
    assert digest(CFG) == EXPECTED_CFG_SHA256
    assert digest(HONEST_CFG) == EXPECTED_HONEST_CFG_SHA256
    assert digest(RUNNER) == EXPECTED_RUNNER_SHA256
    assert tla.startswith("------------------------------ MODULE BridgeEscrowV3 ")
    assert tla.rstrip().endswith("=============================================================================")
    assert not any(line.rstrip() != line for line in tla.splitlines())
    check_delimiters(tla)

    definitions = definition_names(tla)
    expected_actions = {
        "RecordSourceInflow", "FinalizeLocalInflow", "OpenLiability",
        "ReserveRelease", "AdvanceBlock", "FinalizeRelease", "CancelRelease",
        "PromoteSettledSource", "MatureRisk", "ClearRisk", "FreezeFault",
        "PauseChain", "DistributeFaultCollateral",
    }
    expected_invariants = {
        "TypeOK", "ClaimLifecycleSound",
        "SourceLotProjection", "ReservationAtomic",
        "PriorBlockReservation", "AtomicFinalCommit", "SafeCancellation",
        "HistoryAndReplaySound", "FinalizedUnclearedRetained",
        "ChainLocalPauseSound", "ExactCulpritPenalty", "FullCycleConservation",
    }
    expected_specs = {
        "Spec", "SpecEarlyFinalize", "SpecUnsafeCancel",
        "SpecDropFinalExposure", "SpecEarlyClear", "SpecExtraCulprit",
        "SpecGlobalPause", "SpecReplayPromotion", "SpecReplayFinal", "HonestSpec",
    }
    missing = (expected_actions | expected_invariants | expected_specs) - definitions
    assert not missing, f"missing definitions: {sorted(missing)}"

    baseline = definition_body(tla, "BaselineAction")
    for action in expected_actions:
        assert re.search(rf"\b{re.escape(action)}\s*\(", baseline), action
    for mutant in (
        "ReplayPromotion", "ReplayFinal", "FALSE", "NextEarlyFinalize",
        "NextUnsafeCancel", "NextDropFinalExposure", "NextEarlyClear",
        "NextExtraCulprit", "NextGlobalPause",
    ):
        assert mutant not in baseline, f"mutant leaked into baseline: {mutant}"

    for release_path in ("OpenLiability", "ReserveRelease", "FinalizeRelease"):
        body = definition_body(tla, release_path)
        assert "objectiveSource[" not in body, f"truth read in {release_path}"
    assert "objectiveSource[d]" in definition_body(tla, "RecordSourceInflow")
    assert "~objectiveSource[d]" in definition_body(tla, "FreezeFault")

    steps = [int(value) for value in re.findall(r"honestStep = (\d+) ->", definition_body(tla, "HonestNext"))]
    assert steps == list(range(18)), steps
    assert "honestStep' = 18" in definition_body(tla, "HonestNext")

    cfg_spec_match = re.search(r"^SPECIFICATION\s+(\w+)\s*$", cfg, re.MULTILINE)
    assert cfg_spec_match and cfg_spec_match.group(1) in definitions
    cfg_invariants = re.findall(r"^INVARIANT\s+(\w+)\s*$", cfg, re.MULTILINE)
    assert cfg_invariants == [
        "TypeOK", "ClaimLifecycleSound",
        "SourceLotProjection", "ReservationAtomic",
        "PriorBlockReservation", "AtomicFinalCommit", "SafeCancellation",
        "HistoryAndReplaySound", "FinalizedUnclearedRetained",
        "ChainLocalPauseSound", "ExactCulpritPenalty",
    ]
    assert set(cfg_invariants) == expected_invariants - {"FullCycleConservation"}
    assert "CHECK_DEADLOCK FALSE" in cfg
    assert "CONSTANT" not in cfg

    honest_spec_match = re.search(
        r"^SPECIFICATION\s+(\w+)\s*$", honest_cfg, re.MULTILINE
    )
    assert honest_spec_match and honest_spec_match.group(1) == "HonestSpec"
    honest_invariants = re.findall(
        r"^INVARIANT\s+(\w+)\s*$", honest_cfg, re.MULTILINE
    )
    assert honest_invariants == cfg_invariants + ["FullCycleConservation"]
    assert set(honest_invariants) == expected_invariants
    assert "CHECK_DEADLOCK FALSE" in honest_cfg
    assert "CONSTANT" not in honest_cfg

    assert 'LiabilityStates == {"Absent", "Open", "CapacityReserved", "Settled"}' in tla
    assert 'SourceStates == {"Absent", "Encumbered", "Available"}' in tla
    for action in ("ReserveRelease", "FinalizeRelease", "CancelRelease"):
        assert "sourceState" not in definition_body(tla, action), action
    assert 'st.sourceState[Fwd] = "Available"' in definition_body(
        tla, "HonestRoundTripDone"
    )
    for deprecated in ("AuthorizedPending", "AcceptedPending", "COMMIT_ESCROW_DEPOSIT"):
        assert deprecated not in strip_comments_and_strings(tla)

    print("TLA STATIC COMPANION AUDIT PASS — NOT SANY/TLC")
    print(f"tla_sha256={digest(TLA)}")
    print(f"cfg_sha256={digest(CFG)}")
    print(f"honest_cfg_sha256={digest(HONEST_CFG)}")
    print(f"runner_sha256={digest(RUNNER)}")
    print(
        f"definitions={len(definitions)} actions=13 invariants=12 specs=10 "
        "baseline_invariants=11 honest_invariants=12 honest_steps=18"
    )
    print("release_path_objective_truth_reads=0")


if __name__ == "__main__":
    main()
