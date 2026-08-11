#!/usr/bin/env python3
"""Independent deterministic stress audit for sizing.py.corrected."""

from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
import math
import random
import sys
from pathlib import Path


MODULE_PATH = (
    Path(sys.argv[1])
    if len(sys.argv) > 1
    else Path(__file__).resolve().with_name("sizing.py")
)
spec = importlib.util.spec_from_loader(
    "sizing_corrected", SourceFileLoader("sizing_corrected", str(MODULE_PATH))
)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load sizing module")
sizing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sizing)


def close(a: float, b: float, tolerance: float = 1e-12) -> bool:
    return math.isclose(a, b, rel_tol=tolerance, abs_tol=tolerance)


def main() -> None:
    rng = random.Random(0x4D4F42434F494E)
    roster_cases = 0
    mixture_cases = 0
    arithmetic_cases = 0

    for _ in range(250):
        loss_hazard = rng.uniform(0.0, 0.3)
        compromise_hazard = rng.uniform(0.0, 0.3)
        years = rng.uniform(0.0, 25.0)
        state = sizing.competing_risk_probabilities(
            loss_hazard, compromise_hazard, years
        )
        assert all(0.0 <= value <= 1.0 for value in state.__dict__.values())
        assert close(state.lost + state.compromised + state.surviving, 1.0)

        for n in range(1, 18):
            previous_majority_union = -1.0
            for k in range(1, n + 1):
                outcome = sizing.roster_outcomes(n, k, state)
                assert 0.0 <= outcome.pure_liveness_loss <= 1.0 + 1e-12
                assert 0.0 <= outcome.ownership_threshold_compromised <= 1.0 + 1e-12
                assert close(
                    outcome.union_ownership_failure,
                    outcome.pure_liveness_loss
                    + outcome.ownership_threshold_compromised,
                )
                if 2 * k > n:
                    below = sizing.probability_survivors_below_threshold(
                        n, k, state
                    )
                    assert close(outcome.union_ownership_failure, below)
                    # Within the strict-majority domain, raising k cannot lower
                    # P(survivors < k).
                    assert (
                        outcome.union_ownership_failure + 1e-12
                        >= previous_majority_union
                    )
                    previous_majority_union = outcome.union_ownership_failure
                roster_cases += 1

        shock_state = sizing.competing_risk_probabilities(
            loss_hazard * 4.0, compromise_hazard, years
        )
        n = rng.randint(3, 17)
        k = n // 2 + 1
        base = sizing.roster_outcomes(n, k, state)
        shock = sizing.roster_outcomes(n, k, shock_state)
        for weight in (0.0, 0.01, 0.25, 0.5, 0.99, 1.0):
            mixed = sizing.mix_outcomes(base, shock, weight)
            for field in mixed.__dict__:
                value = getattr(mixed, field)
                expected = (1.0 - weight) * getattr(base, field) + weight * getattr(shock, field)
                assert close(value, expected)
            correlation = sizing.induced_loss_indicator_correlation(
                state.lost, shock_state.lost, weight
            )
            assert -1e-15 <= correlation <= 1.0 + 1e-12
            if weight in (0.0, 1.0):
                assert correlation == 0.0
            mixture_cases += 1

    for _ in range(10_000):
        u_f = rng.uniform(1e-9, 1.0)
        u_r = rng.uniform(1e-9, 1.0)
        pi_f = rng.uniform(1e-9, 10.0)
        pi_r = rng.uniform(1e-9, 10.0)
        lgd_f = rng.uniform(1e-9, 1.0)
        lgd_r = rng.uniform(1e-9, 1.0)
        ratio = sizing.cap_ratio(u_f, pi_f, lgd_f, u_r, pi_r, lgd_r)
        expected = (u_f * pi_f * lgd_f) / (u_r * pi_r * lgd_r)
        assert close(ratio, expected, tolerance=1e-11)

        p_q = rng.uniform(1e-9, 1.0)
        gamma = rng.uniform(0.0, 10.0)
        assert close(
            sizing.toy_bond_factor(p_q, gamma),
            max(1.0 / p_q, 1.0 + gamma),
            tolerance=1e-11,
        )

        c_loss = rng.uniform(1e-6, 1e12)
        volume = rng.uniform(0.0, 1e15)
        frequency = rng.uniform(0.0, 10.0)
        turns, proxy = sizing.closs_metrics(c_loss, volume, frequency)
        assert close(turns, volume / c_loss, tolerance=1e-11)
        assert close(proxy, c_loss * frequency, tolerance=1e-11)
        arithmetic_cases += 1

    print("SIZING STRESS AUDIT PASS")
    print(f"roster_cases={roster_cases}")
    print(f"mixture_cases={mixture_cases}")
    print(f"arithmetic_triplets={arithmetic_cases}")
    print("scope=bounded arithmetic identities and validation; no production calibration")


if __name__ == "__main__":
    main()
