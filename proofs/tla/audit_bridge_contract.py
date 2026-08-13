#!/usr/bin/env python3
"""Independent mechanical audit for the prospective bridge-v3 contracts."""

from __future__ import annotations

import hashlib
import re
import sys
from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent
PLAN = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "BRIDGE_V2_TEST_PLAN.md"
CAP = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / "BRIDGE_V2_CAPACITY_INTERFACE.md"

EXPECTED_HASHES = {
    PLAN.name: "bbbd520350d133124ca77f2827f563cd64692b1495e4949cce65bdf28e2d0f14",
    CAP.name: "71114628df1b10a5eba70f787e160f86d22b2ea81a3398cd0f0825f5a05884dd",
}


def fail(message: str) -> None:
    raise AssertionError(message)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def section(text: str, start: str, end: str | None) -> str:
    start_at = text.index(start)
    end_at = text.index(end, start_at) if end else len(text)
    return text[start_at:end_at]


def table_rows(text: str, id_pattern: str) -> list[list[str]]:
    matcher = re.compile(rf"^\|\s*({id_pattern})\s*\|(.*)\|\s*$", re.MULTILINE)
    rows = []
    for match in matcher.finditer(text):
        cells = [match.group(1).strip()]
        cells.extend(cell.strip() for cell in match.group(2).split("|"))
        rows.append(cells)
    return rows


def assert_unique_and_exact(rows: list[list[str]], prefix: str, total: int) -> None:
    ids = [row[0] for row in rows]
    names = [row[1].strip("`") for row in rows]
    duplicate_ids = sorted(key for key, value in Counter(ids).items() if value > 1)
    duplicate_names = sorted(key for key, value in Counter(names).items() if value > 1)
    if duplicate_ids:
        fail(f"duplicate {prefix} IDs: {duplicate_ids}")
    if duplicate_names:
        fail(f"duplicate {prefix} names: {duplicate_names}")
    expected = {f"{prefix}{number:02d}" for number in range(1, total + 1)}
    actual = set(ids)
    if actual != expected:
        fail(f"{prefix} coverage mismatch: missing={sorted(expected-actual)}, extra={sorted(actual-expected)}")


def parse_named_fields(text: str, name: str) -> list[str]:
    pattern = re.compile(rf"^\s*{re.escape(name)}\s*=\s*[\[{{]\s*$", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        fail(f"missing schema {name}")
    lines = []
    for raw in text[match.end():].splitlines():
        if re.match(r"^\s*[\]}}]\s*$", raw):
            break
        value = raw.split("#", 1)[0].strip()
        if value:
            lines.append(value)
    joined = "\n".join(lines)
    fields = []
    for token in joined.split(","):
        token = token.strip()
        if not token:
            continue
        token = token.split("=", 1)[0].strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", token):
            fail(f"non-field token in {name}: {token!r}")
        fields.append(token)
    return fields


def main() -> None:
    plan = PLAN.read_text()
    cap = CAP.read_text()

    for path in (PLAN, CAP):
        actual = sha256(path)
        expected = EXPECTED_HASHES.get(path.name)
        if expected and actual != expected:
            fail(f"hash mismatch for {path}: expected {expected}, got {actual}")

    event_rows = table_rows(section(plan, "### 13.1 Committed event-kind manifest", "## 14."), r"E\d{2}")
    property_rows = table_rows(section(plan, "## 14. Required property manifest", "## 15."), r"P\d{2,3}")
    scenario_rows = table_rows(section(plan, "## 15. Required scenario manifest", "## 16."), r"S\d{2,3}")
    selector_rows = table_rows(section(plan, "## 16. One-defect falsifier manifest", "## 17."), r"D\d{2,3}")

    assert_unique_and_exact(event_rows, "E", 28)
    assert_unique_and_exact(property_rows, "P", 100)
    assert_unique_and_exact(scenario_rows, "S", 56)
    assert_unique_and_exact(selector_rows, "D", 176)

    property_names = {row[0]: row[1] for row in property_rows}
    if len(property_names) != 100:
        fail("property map cardinality mismatch")
    for row in selector_rows:
        if len(row) != 7:
            fail(f"selector {row[0]} has {len(row)} cells, expected 7")
        selector_id, _, mutation, prestate, target, oracle, secondary = row
        if not mutation or not prestate or not oracle:
            fail(f"selector {selector_id} has an empty required cell")
        if not re.fullmatch(r"P\d{2,3}", target):
            fail(f"selector {selector_id} has non-atomic target {target!r}")
        if property_names.get(target) != oracle:
            fail(f"selector {selector_id} target/oracle mismatch: {target}/{oracle}")
        if not re.fullmatch(r"\{(?:P\d{2,3}(?:,P\d{2,3})*)?\}", secondary):
            fail(f"selector {selector_id} malformed secondary set {secondary!r}")
        for prop_id in re.findall(r"P\d{2,3}", secondary):
            if prop_id not in property_names:
                fail(f"selector {selector_id} references missing secondary {prop_id}")

    expected_layers = {
        "properties": (86, 10, 4),
        "scenarios": (41, 10, 5),
        "selectors": (149, 19, 8),
    }
    layer_sections = {
        "properties": ("### 14.1 CORE", "### 14.2 STAGED", "### 14.3 COMPOSITION", "## 15."),
        "scenarios": ("### 15.1 CORE", "### 15.2 STAGED", "### 15.3 COMPOSITION", "## 16."),
        "selectors": ("### 16.1 CORE", "### 16.2 STAGED", "### 16.3 COMPOSITION", "### 16.4 Additional CORE", "### 16.5 Additional STAGED", "## 17."),
    }
    prefixes = {"properties": "P", "scenarios": "S", "selectors": "D"}
    for kind, headings in layer_sections.items():
        prefix = prefixes[kind]
        if kind != "selectors":
            core = table_rows(section(plan, headings[0], headings[1]), rf"{prefix}\d{{2,3}}")
            staged = table_rows(section(plan, headings[1], headings[2]), rf"{prefix}\d{{2,3}}")
            composition = table_rows(section(plan, headings[2], headings[3]), rf"{prefix}\d{{2,3}}")
        else:
            core = table_rows(section(plan, headings[0], headings[1]), r"D\d{2,3}")
            staged = table_rows(section(plan, headings[1], headings[2]), r"D\d{2,3}")
            composition = table_rows(section(plan, headings[2], headings[3]), r"D\d{2,3}")
            core += table_rows(section(plan, headings[3], headings[4]), r"D\d{2,3}")
            staged += table_rows(section(plan, headings[4], headings[5]), r"D\d{2,3}")
        actual = (len(core), len(staged), len(composition))
        if actual != expected_layers[kind]:
            fail(f"{kind} layer counts: expected {expected_layers[kind]}, got {actual}")

    cap_events_region = section(cap, "## 5. Canonical event vocabulary", "### 5.1")
    cap_event_rows = table_rows(cap_events_region, r"\d{1,2}")
    if [int(row[0]) for row in cap_event_rows] != list(range(1, 29)):
        fail("capacity event number coverage mismatch")
    cap_event_names = [row[1].strip("`") for row in cap_event_rows]
    if cap_event_names != [row[1] for row in event_rows]:
        fail("event vocabulary/order differs between documents")

    cap_selectors_region = section(cap, "## 10. Exact falsifier inventory", "## 11.")
    cap_staged = table_rows(section(cap_selectors_region, "### 10.1", "### 10.2"), r"S\d{2,3}")
    cap_composition = table_rows(section(cap_selectors_region, "### 10.2", None), r"C\d{2,3}")
    assert_unique_and_exact(cap_staged, "S", 9)
    assert_unique_and_exact(cap_composition, "C", 110)
    cap_selector_names = [row[1].strip("`") for row in cap_staged + cap_composition]
    duplicates = sorted(key for key, value in Counter(cap_selector_names).items() if value > 1)
    if duplicates:
        fail(f"duplicate selector names across capacity layers: {duplicates}")

    schema_names = (
        "CapacityEvent",
        "PreIntentKeyImageContext",
        "IntentBindingCore",
        "ReserveInputStatementCore",
        "ReserveInputProof",
        "ThresholdWitnessPackage",
        "AcceptanceReceipt",
    )
    expected_schema_counts = {
        "CapacityEvent": 31,
        "PreIntentKeyImageContext": 9,
        "IntentBindingCore": 37,
        "ReserveInputStatementCore": 30,
        "ReserveInputProof": 7,
        "ThresholdWitnessPackage": 14,
        "AcceptanceReceipt": 10,
    }
    for name in schema_names:
        plan_fields = parse_named_fields(plan, name)
        cap_fields = parse_named_fields(cap, name)
        if plan_fields != cap_fields:
            fail(f"{name} field sequence differs:\nplan={plan_fields}\ncap={cap_fields}")
        if len(plan_fields) != expected_schema_counts[name]:
            fail(f"{name} expected {expected_schema_counts[name]} fields, got {len(plan_fields)}")

    unresolved = section(plan, "## 19. Unresolved decisions", "## 20.")
    unresolved_ids = [int(value) for value in re.findall(r"^(\d+)\. ", unresolved, re.MULTILINE)]
    if unresolved_ids != list(range(1, 20)):
        fail(f"unresolved decision coverage mismatch: {unresolved_ids}")

    if "PROSPECTIVE / NOT RUN" not in plan or "UNVERIFIED" not in cap:
        fail("prospective/unverified status labels missing")

    print("AUDIT PASS")
    print(f"plan_sha256={sha256(PLAN)}")
    print(f"capacity_sha256={sha256(CAP)}")
    print("events=28 properties=100 scenarios=56 selectors=176")
    print("layers=P(86,10,4) S(41,10,5) D(149,19,8)")
    print("capacity_selectors=9+110 schemas=31/10/9/37/30/7/14")
    print("unresolved_decisions=19 status=PROSPECTIVE_UNVERIFIED")


if __name__ == "__main__":
    main()
