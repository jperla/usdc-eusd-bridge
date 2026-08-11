#!/usr/bin/env python3
"""Executable counterexample for unspent-only ring-member selection.

This is a structural inference result, not a quantitative MobileCoin privacy
claim. It applies to an adversary that observes complete rings and knows that
every member of every ring was unspent immediately before that transaction.
Current public MobileCoin BlockContents do not retain rings, so a chain-only
observer does not receive the observations used here.
"""

from __future__ import annotations

from argparse import ArgumentParser
from itertools import combinations


def candidates_unspent_only(rings: list[frozenset[str]], target: int) -> frozenset[str]:
    """Return candidates surviving all later unspent-only observations."""
    later_members = (
        frozenset().union(*rings[target + 1 :])
        if target + 1 < len(rings)
        else frozenset()
    )
    return rings[target] - later_members


def candidates_all_outputs(rings: list[frozenset[str]], target: int) -> frozenset[str]:
    """Later membership supplies no fact when spent outputs may be decoys."""
    return rings[target]


def build_elimination_trace(ring_size: int) -> list[frozenset[str]]:
    """Build a valid trace that eliminates every target decoy."""
    if ring_size < 2:
        raise ValueError("ring_size must be at least 2")

    first = frozenset(f"x{i}" for i in range(ring_size))
    rings = [first]
    for j in range(1, ring_size):
        later = {f"x{j}"}
        later.update(f"fresh_{j}_{k}" for k in range(ring_size - 1))
        rings.append(frozenset(later))
    return rings


def exhaustive_three_member_check() -> None:
    """Exhaustively confirm the inference against all small assignments."""
    rings = [
        frozenset({"a", "b", "c"}),
        frozenset({"b", "d", "e"}),
        frozenset({"c", "f", "g"}),
    ]
    feasible: list[tuple[str, str, str]] = []
    for r0 in rings[0]:
        for r1 in rings[1]:
            for r2 in rings[2]:
                reals = (r0, r1, r2)
                if len(set(reals)) != len(reals):
                    continue
                if any(
                    reals[t] in rings[u]
                    for t, u in combinations(range(len(rings)), 2)
                ):
                    continue
                feasible.append(reals)
    assert feasible
    assert {assignment[0] for assignment in feasible} == {"a"}
    assert candidates_unspent_only(rings, 0) == frozenset({"a"})


def selftest() -> None:
    exhaustive_three_member_check()
    rings = build_elimination_trace(11)
    assert len(rings) == 11
    assert all(len(ring) == 11 for ring in rings)
    assert candidates_unspent_only(rings, 0) == frozenset({"x0"})
    assert len(candidates_all_outputs(rings, 0)) == 11

    for k in range(11):
        prefix = rings[: k + 1]
        assert len(candidates_unspent_only(prefix, 0)) == 11 - k


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--ring-size", type=int, default=11)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    if args.selftest:
        selftest()
        print("PASS: exhaustive size-3 check and constructive size-11 checks")
        return

    rings = build_elimination_trace(args.ring_size)
    print(f"target ring size: {args.ring_size}")
    print(f"later observed rings: {len(rings) - 1}")
    print(
        "survivors under unspent-only eligibility: "
        f"{sorted(candidates_unspent_only(rings, 0))}"
    )
    print(
        "survivors when spent outputs may be decoys: "
        f"{len(candidates_all_outputs(rings, 0))}"
    )
    print(
        "scope: ring-observing adversary; current chain-only BlockContents "
        "redacts rings"
    )


if __name__ == "__main__":
    main()
