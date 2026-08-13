#!/usr/bin/env python3
"""Conditional sizing sensitivities for DESIGN.md section 7.2.

This program is NOT a design-decision oracle.  Every numerical default is
ILLUSTRATIVE AND UNCALIBRATED.  The program can answer conditional questions
such as "which row is smallest inside an externally imposed search range?";
it cannot choose the risk appetite, failure hazards, recovery assumptions,
operator cost, or maximum roster size required to make a launch decision.

The four commands deliberately keep unlike quantities separate:

* ``roster`` evaluates an ownership layer under mutually exclusive competing
  loss/compromise hazards.  It reports disjoint pure-liveness-loss and
  ownership-threshold-compromise probabilities.  The latter is not bridge
  theft: an unauthorized release still requires the independent gate and
  accountability/warden authorizations.
* ``capratio`` equalizes an illustrative expected-loss density only after
  utilization, incident frequency, and loss given default (LGD) are supplied.
  It does not choose either absolute exposure cap.
* ``bond`` evaluates a deliberately simple monetary deterrence inequality.
  The factor two is a conservative policy floor, not an estimate that
  enforcement succeeds exactly half the time.
* ``closs`` treats C_loss as an externally selected concurrent-stock risk
  limit.  Annual volume divided by C_loss is a flow/stock (inventory-turns)
  ratio, not the number of key generations or DKG ceremonies.

The shared-shock option in ``roster`` is only a two-regime sensitivity.  Its
``shock_probability`` parameter is a mixture weight, NOT a correlation
coefficient.  The script reports the pairwise correlation induced between
participants' loss indicators; that correlation is generally non-monotone in
the mixture weight and is zero at both weights 0 and 1.  Production sizing
should additionally use explicit vendor/region/jurisdiction/software failure
domains and cross-role coalition analysis.
"""

import argparse
from dataclasses import dataclass
from math import comb, exp, inf, isclose, isfinite


DEFAULTS_WARNING = "ALL NUMERICAL DEFAULTS BELOW ARE ILLUSTRATIVE AND UNCALIBRATED."


@dataclass(frozen=True)
class StateProbabilities:
    """Mutually exclusive terminal probabilities for one participant."""

    lost: float
    compromised: float
    surviving: float


@dataclass(frozen=True)
class RosterOutcomes:
    """Disjoint ownership-layer failure outcomes.

    pure_liveness_loss:
        Fewer than k trusted surviving shares and fewer than k compromised
        shares.  The ownership layer is unavailable, but the adversary does
        not hold an ownership threshold.
    ownership_threshold_compromised:
        At least k compromised ownership shares.  This is ownership-artifact
        capability, not bridge theft; the independent gate and warden paths
        are intentionally absent from this toy model.
    union_ownership_failure:
        Union of the preceding disjoint outcomes.
    """

    pure_liveness_loss: float
    ownership_threshold_compromised: float
    union_ownership_failure: float


def _require_finite(name, value):
    if not isfinite(value):
        raise ValueError(f"{name} must be finite")


def _require_finite_nonnegative(name, value):
    _require_finite(name, value)
    if value < 0:
        raise ValueError(f"{name} must be non-negative")


def _require_probability(name, value):
    _require_finite(name, value)
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be in [0, 1]")


def competing_risk_probabilities(loss_hazard, compromise_hazard, years):
    """Convert two exponential hazards into exclusive terminal outcomes.

    If the first event wins, a participant is either lost or compromised;
    otherwise the participant survives the horizon.  Unlike independently
    exponentiating both hazards, these three probabilities always form one
    mutually exclusive distribution.
    """

    _require_finite_nonnegative("loss_hazard", loss_hazard)
    _require_finite_nonnegative("compromise_hazard", compromise_hazard)
    _require_finite_nonnegative("years", years)
    total_hazard = loss_hazard + compromise_hazard
    _require_finite("combined_hazard", total_hazard)
    if total_hazard == 0:
        return StateProbabilities(0.0, 0.0, 1.0)
    horizon_hazard = total_hazard * years
    _require_finite("combined_horizon_hazard", horizon_hazard)
    surviving = exp(-horizon_hazard)
    event_probability = 1.0 - surviving
    lost = loss_hazard / total_hazard * event_probability
    compromised = compromise_hazard / total_hazard * event_probability
    return StateProbabilities(lost, compromised, surviving)


def roster_outcomes(n, k, state):
    """Enumerate exact multinomial ownership-layer outcomes for a roster."""

    if not isinstance(n, int) or isinstance(n, bool):
        raise ValueError("n must be an integer")
    if not isinstance(k, int) or isinstance(k, bool):
        raise ValueError("k must be an integer")
    if not (1 <= k <= n):
        raise ValueError("require 1 <= k <= n")
    for name, value in (
        ("state.lost", state.lost),
        ("state.compromised", state.compromised),
        ("state.surviving", state.surviving),
    ):
        _require_probability(name, value)
    if not isclose(
        state.lost + state.compromised + state.surviving,
        1.0,
        rel_tol=0.0,
        abs_tol=1e-12,
    ):
        raise ValueError("state probabilities must sum to one")

    pure_liveness_loss = 0.0
    ownership_threshold_compromised = 0.0
    for n_lost in range(n + 1):
        for n_compromised in range(n + 1 - n_lost):
            n_surviving = n - n_lost - n_compromised
            weight = (
                comb(n, n_lost)
                * comb(n - n_lost, n_compromised)
                * state.lost**n_lost
                * state.compromised**n_compromised
                * state.surviving**n_surviving
            )
            if n_compromised >= k:
                ownership_threshold_compromised += weight
            elif n_surviving < k:
                pure_liveness_loss += weight

    union = pure_liveness_loss + ownership_threshold_compromised
    return RosterOutcomes(
        pure_liveness_loss,
        ownership_threshold_compromised,
        union,
    )


def probability_survivors_below_threshold(n, k, state):
    """Binomial P(n_surviving < k), used to check the majority identity."""

    # Reuse roster_outcomes for complete input validation without trusting a
    # separately constructed StateProbabilities object.
    roster_outcomes(n, k, state)
    return sum(
        comb(n, survivors)
        * state.surviving**survivors
        * (1.0 - state.surviving) ** (n - survivors)
        for survivors in range(k)
    )


def mix_outcomes(base, shock, shock_probability):
    """Mix roster-level outcomes across a shared latent regime."""

    _require_probability("shock_probability", shock_probability)
    w = shock_probability
    return RosterOutcomes(
        (1.0 - w) * base.pure_liveness_loss
        + w * shock.pure_liveness_loss,
        (1.0 - w) * base.ownership_threshold_compromised
        + w * shock.ownership_threshold_compromised,
        (1.0 - w) * base.union_ownership_failure
        + w * shock.union_ownership_failure,
    )


def induced_loss_indicator_correlation(p_loss_base, p_loss_shock, shock_probability):
    """Pairwise correlation induced by the two-regime mixture.

    Conditional on a regime, participants are independent.  The common latent
    regime creates covariance w(1-w)(p1-p0)^2.  At w=0 or w=1 the regime is no
    longer random and the induced correlation is zero.
    """

    _require_probability("p_loss_base", p_loss_base)
    _require_probability("p_loss_shock", p_loss_shock)
    _require_probability("shock_probability", shock_probability)
    w = shock_probability
    marginal = (1.0 - w) * p_loss_base + w * p_loss_shock
    variance = marginal * (1.0 - marginal)
    if variance == 0.0:
        return 0.0
    covariance = w * (1.0 - w) * (p_loss_shock - p_loss_base) ** 2
    return covariance / variance


def conditional_roster_outcomes(
    n,
    k,
    years,
    loss_hazard,
    compromise_hazard,
    shock_probability,
    shock_loss_multiplier,
):
    """Evaluate one roster in the illustrative two-regime model."""

    _require_finite("shock_loss_multiplier", shock_loss_multiplier)
    if shock_loss_multiplier < 1.0:
        raise ValueError("shock_loss_multiplier must be at least 1")
    base_state = competing_risk_probabilities(
        loss_hazard, compromise_hazard, years
    )
    shock_loss_hazard = loss_hazard * shock_loss_multiplier
    _require_finite("shock_loss_hazard", shock_loss_hazard)
    shock_state = competing_risk_probabilities(
        shock_loss_hazard,
        compromise_hazard,
        years,
    )
    base_outcomes = roster_outcomes(n, k, base_state)
    shock_outcomes = roster_outcomes(n, k, shock_state)
    return mix_outcomes(base_outcomes, shock_outcomes, shock_probability)


def scan_rosters(
    years,
    loss_hazard,
    compromise_hazard,
    shock_probability,
    shock_loss_multiplier=4.0,
    n_min=3,
    n_max=15,
):
    """Enumerate majority rosters inside an externally imposed range."""

    if (
        not isinstance(n_min, int)
        or isinstance(n_min, bool)
        or not isinstance(n_max, int)
        or isinstance(n_max, bool)
    ):
        raise ValueError("n_min and n_max must be integers")
    if n_min < 1 or n_max < n_min:
        raise ValueError("require 1 <= n_min <= n_max")
    rows = []
    for n in range(n_min, n_max + 1):
        for k in range(2, n + 1):
            if k / n <= 0.5:
                continue
            outcome = conditional_roster_outcomes(
                n,
                k,
                years,
                loss_hazard,
                compromise_hazard,
                shock_probability,
                shock_loss_multiplier,
            )
            rows.append(
                {
                    "n": n,
                    "k": k,
                    "headroom": n - k,
                    "pure_liveness_loss": outcome.pure_liveness_loss,
                    "ownership_threshold_compromised": (
                        outcome.ownership_threshold_compromised
                    ),
                    "union_ownership_failure": outcome.union_ownership_failure,
                }
            )
    if not rows:
        raise ValueError("search range contains no majority k-of-n roster")
    return rows


def pareto_rows(rows):
    """Return rows not dominated on the two disjoint failure probabilities."""

    result = []
    for row in rows:
        dominated = any(
            other["pure_liveness_loss"] <= row["pure_liveness_loss"]
            and other["ownership_threshold_compromised"]
            <= row["ownership_threshold_compromised"]
            and (
                other["pure_liveness_loss"] < row["pure_liveness_loss"]
                or other["ownership_threshold_compromised"]
                < row["ownership_threshold_compromised"]
            )
            for other in rows
        )
        if not dominated:
            result.append(row)
    return result


def cmd_roster(a):
    # Scan first so all CLI inputs fail closed before any sensitivity output is
    # emitted.
    rows = scan_rosters(
        a.years,
        a.loss_hazard,
        a.compromise_hazard,
        a.shock_probability,
        a.shock_loss_multiplier,
        a.n_min,
        a.n_max,
    )
    print("D1 — CONDITIONAL OWNERSHIP-ROSTER SENSITIVITY (NOT A DECISION)")
    print(DEFAULTS_WARNING)
    print()
    print(
        f"horizon={a.years:g}y; annual hazards: loss={a.loss_hazard:.3%}, "
        f"compromise={a.compromise_hazard:.3%}"
    )
    print(
        f"externally imposed search range: {a.n_min} <= n <= {a.n_max}; "
        "majority thresholds only"
    )
    print(
        f"shock_probability={a.shock_probability:.3f} (mixture weight, NOT rho); "
        f"shock loss-hazard multiplier={a.shock_loss_multiplier:g}x"
    )

    base = competing_risk_probabilities(
        a.loss_hazard, a.compromise_hazard, a.years
    )
    shock = competing_risk_probabilities(
        a.loss_hazard * a.shock_loss_multiplier,
        a.compromise_hazard,
        a.years,
    )
    w = a.shock_probability
    marginal_lost = (1.0 - w) * base.lost + w * shock.lost
    marginal_comp = (1.0 - w) * base.compromised + w * shock.compromised
    marginal_surv = (1.0 - w) * base.surviving + w * shock.surviving
    induced_corr = induced_loss_indicator_correlation(base.lost, shock.lost, w)
    print(
        "one-participant competing-risk probabilities after regime mixing: "
        f"lost={marginal_lost:.6f}, compromised={marginal_comp:.6f}, "
        f"surviving={marginal_surv:.6f}"
    )
    print(f"induced pairwise loss-indicator correlation={induced_corr:.6f}")
    print(
        "The induced correlation is generally non-monotone in "
        "shock_probability and returns to zero at shock_probability=1. "
        "The mixture also changes marginal hazards, so a tail change cannot "
        "be attributed to correlation alone."
    )
    print()

    minimum_union = min(rows, key=lambda row: row["union_ownership_failure"])
    frontier = pareto_rows(rows)
    print(
        "For majority k, {C>=k} is a subset of {S<k}; therefore "
        "P(union ownership failure) = P(S<k).  At fixed n this toy union "
        "objective is minimized (possibly tied) by the smallest majority k.  "
        "It cannot balance compromise security against liveness."
    )
    print(
        "The table reports the Pareto frontier of the two DISJOINT outcomes.  "
        "Choosing among it requires external constraints or explicit risk "
        "weights; the union column is shown only to expose the old objective."
    )
    print()
    print(
        f"{'n':>3} {'k':>3} {'k/n':>6} {'hdrm':>5} "
        f"{'P(pure live loss)':>18} {'P(own threshold)':>18} "
        f"{'P(union=P(S<k))':>18}"
    )
    for row in sorted(frontier, key=lambda r: r["union_ownership_failure"]):
        mark = (
            "  <-- minimum reported union under this toy objective"
            if row is minimum_union
            else ""
        )
        print(
            f"{row['n']:>3} {row['k']:>3} {row['k']/row['n']:>6.0%} "
            f"{row['headroom']:>5} "
            f"{row['pure_liveness_loss']:>18.3e} "
            f"{row['ownership_threshold_compromised']:>18.3e} "
            f"{row['union_ownership_failure']:>18.3e}{mark}"
        )
    print()
    print(
        "Minimum reported union under this toy objective and the imposed "
        f"n <= {a.n_max} bound: {minimum_union['k']}-of-{minimum_union['n']}."
    )
    extension_max = a.n_max + 2
    extended_rows = scan_rosters(
        a.years,
        a.loss_hazard,
        a.compromise_hazard,
        a.shock_probability,
        a.shock_loss_multiplier,
        a.n_min,
        extension_max,
    )
    extended_minimum_union = min(
        extended_rows, key=lambda row: row["union_ownership_failure"]
    )
    if (
        extended_minimum_union["union_ownership_failure"]
        < minimum_union["union_ownership_failure"]
    ):
        print(
            f"BOUNDARY WARNING: extending the search through n={extension_max} "
            "lowers the minimum reported union under this toy objective to "
            f"{extended_minimum_union['k']}-of-{extended_minimum_union['n']}. "
            "The imposed roster bound is load-bearing."
        )
    else:
        print(
            f"The n_max+2 probe through n={extension_max} did not lower the "
            "reported union.  That local result still does not derive a roster "
            "choice or supply the missing cost/security objective."
        )
    print()
    print(
        "Category warning: P(own threshold) means k ownership shares are "
        "compromised; it is NOT bridge-theft probability because this model "
        "omits the independent gate and warden/accountability coalitions."
    )
    print(
        "Lifecycle warning: same-key FROST refresh re-randomizes shares and can "
        "remove existing identifiers but cannot add one or change k; repair can "
        "issue a "
        "share at a new identifier.  The application must authenticate the "
        "ceremony and rebuild its PublicKeyPackage and roster.  Neither operation "
        "recovers below k nor revokes a retained historical threshold.  Fixed "
        "membership is a product choice if normal maintenance is excluded."
    )
    print(
        "Production procurement should test each explicit failure domain d: "
        "n-|loss_domain_d|-offline_tolerance >= k and "
        "|compromise_domain_d|+independent_compromise_tolerance < k."
    )


def cap_ratio(
    forward_utilization,
    forward_incident_frequency,
    forward_lgd,
    reverse_utilization,
    reverse_incident_frequency,
    reverse_lgd,
):
    """Return C_rev/C_fwd when illustrative expected losses are equalized."""

    for name, value in (
        ("forward_utilization", forward_utilization),
        ("reverse_utilization", reverse_utilization),
        ("forward_lgd", forward_lgd),
        ("reverse_lgd", reverse_lgd),
    ):
        _require_probability(name, value)
    for name, value in (
        ("forward_incident_frequency", forward_incident_frequency),
        ("reverse_incident_frequency", reverse_incident_frequency),
    ):
        _require_finite_nonnegative(name, value)
    numerator = (
        forward_utilization * forward_incident_frequency * forward_lgd
    )
    denominator = (
        reverse_utilization * reverse_incident_frequency * reverse_lgd
    )
    _require_finite("forward expected-loss density", numerator)
    _require_finite("reverse expected-loss density", denominator)
    if denominator == 0.0:
        raise ValueError("reverse expected-loss density must be positive")
    ratio = numerator / denominator
    _require_finite("cap ratio", ratio)
    return ratio


# --------------------------------------------------------------------------
# maintain: the question that matters once share maintenance is IN SCOPE.
# --------------------------------------------------------------------------
def replenished_ruin(n, k, loss_hazard, window_years, life_years):
    """Ruin probability when the roster is replenished after each loss.

    SCOPE DECISION 2026-08-08 (Josh): proactive share maintenance is in scope.
    That changes the question. Without maintenance the roster only shrinks and
    the horizon is the design life. With maintenance the roster returns to `n`,
    so what matters is whether too many holders are lost inside ONE response
    window before replacements can be seated.

    `window_years` is detection latency + scheduling + ceremony duration -- the
    interval during which losses accumulate UNREPLACED. A scheduled audit
    cadence feeds into it: if you only test liveness every 90 days, detection
    latency alone is up to 90 days.

    Ruin within a window means losing `n - k + 1` holders, because at `k - 1`
    survivors you can no longer run the repair ceremony either -- repair needs a
    live threshold. That is the cliff: maintenance is a fire extinguisher, not
    an insurance policy.

    Returns (p_window, p_life, cycles).
    """
    _require_finite_nonnegative("loss_hazard", loss_hazard)
    _require_finite_nonnegative("window_years", window_years)
    _require_finite_nonnegative("life_years", life_years)
    if not (1 <= k <= n):
        raise ValueError("require 1 <= k <= n")

    q = 1.0 - exp(-loss_hazard * window_years)
    tolerable = n - k
    p_window = sum(
        comb(n, j) * q**j * (1.0 - q) ** (n - j)
        for j in range(tolerable + 1, n + 1)
    )
    cycles = (life_years / window_years) if window_years > 0 else inf
    p_life = 1.0 - (1.0 - p_window) ** cycles if isfinite(cycles) else 1.0
    return p_window, p_life, cycles


def cmd_maintain(a):
    print("MAINTAINED OWNERSHIP ROSTER — share maintenance IN SCOPE")
    print(DEFAULTS_WARNING)
    print()
    print(f"per-holder loss hazard   {a.loss_hazard:.1%}/yr")
    print(f"response window          {a.window_days:.0f} days "
          f"(detection + scheduling + ceremony)")
    print(f"design life              {a.life_years:.0f} yr")
    print()
    print("Ruin = losing n-k+1 holders inside one window. At k-1 survivors the")
    print("repair ceremony itself becomes impossible, so that is the cliff.")
    print()
    window_years = a.window_days / 365.0
    print(f"{'n':>3} {'k':>3} {'tol':>4} {'P(ruin/window)':>16} "
          f"{'P(ruin over life)':>19}")
    rows = []
    for n in range(3, a.n_max + 1):
        for k in range(2, n + 1):
            if k / n <= 0.5:
                continue
            pw, pl, cyc = replenished_ruin(n, k, a.loss_hazard,
                                           window_years, a.life_years)
            rows.append((n, k, n - k, pw, pl))
    for n, k, tol, pw, pl in sorted(rows, key=lambda r: r[4])[:10]:
        flag = "  <-- meets target" if pl <= a.target else ""
        print(f"{n:>3} {k:>3} {tol:>4} {pw:>16.3e} {pl:>19.3e}{flag}")
    print()
    ok = [r for r in rows if r[4] <= a.target]
    if ok:
        smallest = min(ok, key=lambda r: (r[0], -r[1]))
        print(f"SMALLEST ROSTER meeting target {a.target:.0e} over "
              f"{a.life_years:.0f}yr: n={smallest[0]}, k={smallest[1]} "
              f"(tolerates {smallest[2]} losses per window)")
    else:
        print(f"No roster up to n={a.n_max} meets target {a.target:.0e}. "
              f"Shorten the response window.")
    print()
    print("SENSITIVITY TO THE RESPONSE WINDOW (the operational lever):")
    print(f"{'window':>10}  {'smallest n,k meeting target':>32}")
    for days in [7, 30, 90, 180, 365]:
        wy = days / 365.0
        cands = []
        for n in range(3, a.n_max + 1):
            for k in range(2, n + 1):
                if k / n <= 0.5:
                    continue
                _, pl, _ = replenished_ruin(n, k, a.loss_hazard, wy, a.life_years)
                if pl <= a.target:
                    cands.append((n, k))
        best = min(cands, key=lambda c: (c[0], -c[1])) if cands else None
        txt = f"n={best[0]}, k={best[1]}" if best else f"none up to n={a.n_max}"
        print(f"{days:>7} d  {txt:>32}")
    print()
    print("Reading: the roster requirement is FLAT across response windows from")
    print("a week to six months -- an earlier draft of this text claimed the window")
    print("was the dominant lever, which the data above contradicts. A quarterly")
    print("liveness audit is ample; the cliff only appears past roughly a year.")
    print()
    print("MORE IMPORTANT: this command models LOSS ONLY. Do not read the smallest")
    print("roster off it. Maintenance removes loss as the binding constraint, which")
    print("FREES k/n to be chosen for COMPROMISE resistance instead of traded")
    print("against loss. Cross-check with `roster`, which models both: n=5,k=3 meets")
    print("this liveness target and is ~300,000x worse on ownership compromise.")


def cmd_capratio(a):
    ratio = cap_ratio(
        a.forward_utilization,
        a.forward_incident_frequency,
        a.forward_lgd,
        a.reverse_utilization,
        a.reverse_incident_frequency,
        a.reverse_lgd,
    )
    print("D3 — CONDITIONAL CAP-RATIO SENSITIVITY (NOT AN ABSOLUTE CAP)")
    print(DEFAULTS_WARNING)
    print()
    print("Expected-loss density for leg x: u_x * pi_x * LGD_x")
    print("  u   = average utilization of that leg's exposure cap")
    print("  pi  = incident frequency per exposure-year")
    print("  LGD = fractional loss after severity, recovery, collection delay/cost")
    print()
    print(
        "forward: "
        f"u={a.forward_utilization:g}, pi={a.forward_incident_frequency:g}, "
        f"LGD={a.forward_lgd:g}"
    )
    print(
        "reverse: "
        f"u={a.reverse_utilization:g}, pi={a.reverse_incident_frequency:g}, "
        f"LGD={a.reverse_lgd:g}"
    )
    print()
    print(
        "C_reverse/C_forward = "
        "(u_f*pi_f*LGD_f)/(u_r*pi_r*LGD_r) "
        f"= {ratio:.3f} ({ratio:.1%})"
    )
    print()
    print(
        "This ratio only equalizes the supplied expected-loss scenarios.  It "
        "does not establish those assumptions, and it does not replace an "
        "absolute tail-loss cap or a survivable no-enforcement bound."
    )
    print(
        "The familiar 10% result occurs only in the illustrative special case "
        "u_f=u_r, pi_f=pi_r, LGD_f=5%, and LGD_r=50%.  Doubling reverse "
        "incident frequency changes it to 5%; using reverse utilization at "
        "40% of forward changes it to 25%."
    )


def toy_bond_factor(coalition_enforcement_probability, restitution_overhead):
    """Toy factor max(1/p_Q, 1+gamma); infinity when p_Q is zero."""

    _require_probability(
        "coalition_enforcement_probability", coalition_enforcement_probability
    )
    _require_finite_nonnegative("restitution_overhead", restitution_overhead)
    deterrence = (
        inf
        if coalition_enforcement_probability == 0.0
        else 1.0 / coalition_enforcement_probability
    )
    restitution = 1.0 + restitution_overhead
    _require_finite("1 + restitution_overhead", restitution)
    return max(deterrence, restitution)


def cmd_bond(a):
    model_factor = toy_bond_factor(
        a.coalition_enforcement_probability, a.restitution_overhead
    )
    policy_factor = max(2.0, model_factor)
    print("SECTION 4 — BOND-FACTOR SENSITIVITY")
    print(DEFAULTS_WARNING)
    print()
    print("Q(f,w) = exact culprit set for fault class f and complete witness w")
    print("p_Q(f,w) = procedural proof/admission/enforcement probability for Q")
    print("Toy model: p_Q*B_exact >= L; restitution B_exact >= (1+gamma)*L")
    print("Policy: B_exact(f,w) >= L(f,w) * max(2, 1/p_Q(f,w), 1+gamma)")
    print(
        f"p_Q={a.coalition_enforcement_probability:.1%}; "
        f"gamma={a.restitution_overhead:.1%}; "
        f"toy-model factor={model_factor:g}"
    )
    print(f"factor after retaining the B >= 2L policy floor={policy_factor:g}")
    print()
    print(
        "The 2L floor is sufficient in this toy model when p_Q >= 50% and "
        "gamma <= 100%; it does NOT mean p_Q is exactly 50%.  If p_Q < 50% "
        "(or gamma > 100%), factor two is insufficient."
    )
    print(
        "B_exact sums UNIQUE culprit bond positions after the versioned "
        "collectability/valuation haircut.  Here p_Q excludes the monetary "
        "collection fraction already represented by that haircut, preventing "
        "double discounting.  It covers only proof detection, admission, and "
        "execution before exit."
    )
    print(
        "FALSE_SOURCE Q is unique(WARDEN approvers union ACCOUNT approvers).  "
        "EQUIVOCATION Q is unique((WARDEN(D1) intersection WARDEN(D2)) union "
        "(ACCOUNT(D1) intersection ACCOUNT(D2))).  Each liable role requires "
        "2k>n and nonempty bonded quorum intersection across every concurrently "
        "valid manifest pair.  Hidden aggregate signers do not inflate B_exact."
    )
    print(
        "An admitted operator fault freezes and ultimately slashes 100% of each "
        "unique exact-culprit bond.  After every implicated risk outcome resolves, "
        "distribution is restitution, then capped proof cost, then capped bounty, "
        "then insurance surplus.  An invalid challenger loses only its challenge "
        "bond and cannot pause, expel, or rotate operators.  Unsupported v1 "
        "automatic proof has p_Q=0; contractual collection is a separate path."
    )


def closs_metrics(c_loss, volume, incident_frequency):
    """Validate flow/stock inputs and return turns and a full-cap-loss proxy."""

    _require_finite_nonnegative("c_loss", c_loss)
    _require_finite_nonnegative("volume", volume)
    _require_finite_nonnegative("incident_frequency", incident_frequency)
    if volume > 0.0 and c_loss <= 0.0:
        raise ValueError("c_loss must be positive when volume is positive")
    turns = 0.0 if c_loss == 0.0 else volume / c_loss
    full_cap_loss_proxy = c_loss * incident_frequency
    _require_finite("volume/c_loss", turns)
    _require_finite("c_loss*incident_frequency", full_cap_loss_proxy)
    return turns, full_cap_loss_proxy


def cmd_closs(a):
    turns, full_cap_loss_proxy = closs_metrics(
        a.c_loss, a.volume, a.incident_frequency
    )
    print("D5 — C_LOSS RISK-APPETITE INPUT")
    print(DEFAULTS_WARNING)
    print()
    print("C_loss is an externally chosen concurrent-stock/tail-loss limit.")
    print(f"C_loss={a.c_loss:,.2f}; annual flow volume={a.volume:,.2f}")
    print(
        f"volume/C_loss={turns:g} capacity-equivalent inventory turns per year"
    )
    print(
        "That quotient is a flow/stock ratio.  It is NOT a count of successor "
        "generations, key rotations, DKG ceremonies, or capitalization events; "
        "the same reserve inventory can be reused.  Generation cadence follows "
        "key lifecycle, incidents, maintenance, overlap rules, and available "
        "capital, while liquidity follows peak net flow and settlement latency."
    )
    print()
    print(
        f"C_loss*pi={full_cap_loss_proxy:,.2f} at illustrative "
        f"pi={a.incident_frequency:.2%}/y.  This is only a full-cap-loss proxy, "
        "not a derived expected annual loss."
    )
    print(
        "The exposure bound must aggregate all overlapping generations in each "
        "correlated failure domain.  Do not infer L(f,w) <= C_loss: complete-"
        "witness loss can span directions, generations, roles, and domains and "
        "therefore requires its own exact-culprit bond-capacity calculation."
    )
    print(
        "Maintain a per-asset vector I[d,asset] <= C_loss_asset[d,asset].  Never "
        "add raw USDC and eUSD units.  A common-risk aggregate is valid only "
        "through the exact active, versioned, immutable, conservative valuation/"
        "haircut manifest, including its rounding rules."
    )


def _expect_value_error(fn, *args):
    try:
        fn(*args)
    except ValueError:
        return
    raise AssertionError(f"expected ValueError from {fn.__name__}{args!r}")


def run_selftests():
    # Competing hazards are mutually exclusive and reproduce the audited values.
    state = competing_risk_probabilities(0.02, 0.01, 5.0)
    assert isclose(state.lost, 0.09286134904996148, abs_tol=1e-15)
    assert isclose(state.compromised, 0.04643067452498074, abs_tol=1e-15)
    assert isclose(state.surviving, 0.8607079764250578, abs_tol=1e-15)
    assert isclose(
        state.lost + state.compromised + state.surviving,
        1.0,
        abs_tol=1e-15,
    )

    # For every tested majority, the disjoint categories form their union and
    # that union is exactly P(n_surviving < k); it cannot balance the two axes.
    for n in range(3, 16):
        for k in range(n // 2 + 1, n + 1):
            outcome = roster_outcomes(n, k, state)
            assert isclose(
                outcome.union_ownership_failure,
                outcome.pure_liveness_loss
                + outcome.ownership_threshold_compromised,
                abs_tol=1e-15,
            )
            assert isclose(
                outcome.union_ownership_failure,
                probability_survivors_below_threshold(n, k, state),
                rel_tol=1e-12,
                abs_tol=1e-15,
            )

    shock_state = competing_risk_probabilities(0.08, 0.01, 5.0)
    mixed = mix_outcomes(
        roster_outcomes(15, 8, state),
        roster_outcomes(15, 8, shock_state),
        0.05,
    )
    mixed_liveness = (
        0.95 * probability_survivors_below_threshold(15, 8, state)
        + 0.05 * probability_survivors_below_threshold(15, 8, shock_state)
    )
    assert isclose(
        mixed.union_ownership_failure,
        mixed_liveness,
        rel_tol=1e-12,
        abs_tol=1e-15,
    )

    # The union objective selects the smallest majority for every fixed n.
    rows_15 = scan_rosters(5.0, 0.02, 0.01, 0.0, n_max=15)
    for n in range(3, 16):
        rows_n = [row for row in rows_15 if row["n"] == n]
        minimum_n = min(rows_n, key=lambda row: row["union_ownership_failure"])
        assert minimum_n["k"] == n // 2 + 1

    # The historical result is boundary-driven.  The general n_max+2 probe
    # catches both odd and even externally supplied ceilings, including 16/42.
    expected_minima = {
        15: (15, 8),
        16: (15, 8),
        17: (17, 9),
        41: (41, 21),
        42: (41, 21),
        43: (43, 22),
        44: (43, 22),
    }
    minima = {}
    for n_max, expected in expected_minima.items():
        rows = scan_rosters(5.0, 0.02, 0.01, 0.0, n_max=n_max)
        minimum = min(rows, key=lambda row: row["union_ownership_failure"])
        minima[n_max] = minimum
        assert (minimum["n"], minimum["k"]) == expected
    for bounded, extended in ((15, 17), (16, 18), (41, 43), (42, 44)):
        if extended not in minima:
            rows = scan_rosters(5.0, 0.02, 0.01, 0.0, n_max=extended)
            minima[extended] = min(
                rows, key=lambda row: row["union_ownership_failure"]
            )
        assert (
            minima[extended]["union_ownership_failure"]
            < minima[bounded]["union_ownership_failure"]
        )

    # A mixture weight is not rho: induced correlation vanishes at both ends.
    corr_0 = induced_loss_indicator_correlation(state.lost, shock_state.lost, 0.0)
    corr_mid = induced_loss_indicator_correlation(state.lost, shock_state.lost, 0.5)
    corr_1 = induced_loss_indicator_correlation(state.lost, shock_state.lost, 1.0)
    assert corr_0 == 0.0
    assert corr_mid > 0.0
    assert corr_1 == 0.0

    # The conditional 10% ratio and two counter-scenarios are arithmetic only.
    assert isclose(cap_ratio(1, 0.01, 0.05, 1, 0.01, 0.50), 0.10)
    assert isclose(cap_ratio(1, 0.01, 0.05, 1, 0.02, 0.50), 0.05)
    assert isclose(cap_ratio(1, 0.01, 0.05, 0.4, 0.01, 0.50), 0.25)

    # Factor two is sufficient over a range, not an equality claim about q.
    assert toy_bond_factor(0.5, 0.1) == 2.0
    assert toy_bond_factor(0.8, 0.1) == 1.25
    assert toy_bond_factor(0.0, 0.1) == inf
    assert closs_metrics(1_000_000, 50_000_000, 0.02) == (50.0, 20_000.0)
    assert closs_metrics(0.0, 0.0, 0.0) == (0.0, 0.0)

    # Reject NaN/infinity and out-of-domain values rather than emitting
    # plausible-looking but meaningless sensitivities.
    nan = float("nan")
    positive_infinity = float("inf")
    negative_infinity = float("-inf")
    _expect_value_error(competing_risk_probabilities, nan, 0.01, 5.0)
    _expect_value_error(competing_risk_probabilities, positive_infinity, 0.01, 5.0)
    _expect_value_error(competing_risk_probabilities, 0.02, 0.01, negative_infinity)
    _expect_value_error(competing_risk_probabilities, -0.01, 0.01, 5.0)
    _expect_value_error(competing_risk_probabilities, 1e308, 1e308, 1.0)
    _expect_value_error(competing_risk_probabilities, 1e308, 0.0, 1e308)
    _expect_value_error(
        roster_outcomes, 3, 2, StateProbabilities(nan, 0.0, 1.0)
    )
    _expect_value_error(
        induced_loss_indicator_correlation, 0.1, 0.2, positive_infinity
    )
    _expect_value_error(
        conditional_roster_outcomes, 3, 2, 5.0, 0.02, 0.01, 0.0, 0.99
    )
    _expect_value_error(
        conditional_roster_outcomes, 3, 2, 1.0, 1e308, 0.0, 0.0, 2.0
    )
    _expect_value_error(cap_ratio, 1.01, 0.01, 0.05, 1.0, 0.01, 0.5)
    _expect_value_error(cap_ratio, 1.0, 0.01, nan, 1.0, 0.01, 0.5)
    _expect_value_error(
        cap_ratio, 1.0, positive_infinity, 0.05, 1.0, 0.01, 0.5
    )
    _expect_value_error(cap_ratio, 1.0, 1e308, 1.0, 1.0, 1e-308, 1.0)
    _expect_value_error(cap_ratio, 1.0, 0.01, 0.05, 0.0, 0.01, 0.5)
    _expect_value_error(toy_bond_factor, nan, 0.1)
    _expect_value_error(toy_bond_factor, 0.8, positive_infinity)
    _expect_value_error(closs_metrics, 0.0, 1.0, 0.02)
    _expect_value_error(closs_metrics, positive_infinity, 1.0, 0.02)
    _expect_value_error(closs_metrics, 1.0, nan, 0.02)
    _expect_value_error(closs_metrics, 1e308, 1.0, 1e308)
    print(
        "SELFTEST PASS (competing risk, majority identity, Pareto axes, "
        "odd/even boundary probes, mixture, cap, bond, C_loss, validation)"
    )


def build_parser():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    roster = sub.add_parser("roster", help="conditional ownership-roster scan")
    roster.set_defaults(fn=cmd_roster)
    roster.add_argument("--years", type=float, default=5.0)
    roster.add_argument(
        "--loss-hazard",
        type=float,
        default=0.02,
        help="illustrative annual permanent-loss hazard (default: 0.02)",
    )
    roster.add_argument(
        "--compromise-hazard",
        type=float,
        default=0.01,
        help="illustrative annual compromise hazard (default: 0.01)",
    )
    roster.add_argument(
        "--shock-probability",
        type=float,
        default=0.0,
        help="two-regime mixture weight, not correlation (default: 0)",
    )
    roster.add_argument(
        "--shock-loss-multiplier",
        type=float,
        default=4.0,
        help="illustrative loss-hazard multiplier in shock regime (default: 4)",
    )
    roster.add_argument("--n-min", type=int, default=3)
    roster.add_argument(
        "--n-max",
        type=int,
        default=15,
        help="externally imposed enumeration ceiling (default: 15)",
    )

    maint = sub.add_parser("maintain",
                           help="roster sizing WITH share maintenance in scope")
    maint.set_defaults(fn=cmd_maintain)
    maint.add_argument("--loss-hazard", type=float, default=0.02)
    maint.add_argument("--window-days", type=float, default=90.0,
                       help="detection + scheduling + ceremony (default 90)")
    maint.add_argument("--life-years", type=float, default=5.0)
    maint.add_argument("--target", type=float, default=1e-4,
                       help="acceptable lifetime ruin probability")
    maint.add_argument("--n-max", type=int, default=15)

    cap = sub.add_parser("capratio", help="conditional forward/reverse cap ratio")
    cap.set_defaults(fn=cmd_capratio)
    cap.add_argument("--forward-utilization", type=float, default=1.0)
    cap.add_argument("--reverse-utilization", type=float, default=1.0)
    cap.add_argument("--forward-incident-frequency", type=float, default=0.01)
    cap.add_argument("--reverse-incident-frequency", type=float, default=0.01)
    cap.add_argument("--forward-lgd", type=float, default=0.05)
    cap.add_argument("--reverse-lgd", type=float, default=0.50)

    bond = sub.add_parser("bond", help="conditional toy bond factor")
    bond.set_defaults(fn=cmd_bond)
    bond.add_argument(
        "--coalition-enforcement-probability",
        "--enforcement-probability",
        dest="coalition_enforcement_probability",
        type=float,
        default=0.8,
        help="illustrative p_Q; excludes collectability already in haircut",
    )
    bond.add_argument("--restitution-overhead", type=float, default=0.1)

    closs = sub.add_parser("closs", help="C_loss flow/stock implications")
    closs.set_defaults(fn=cmd_closs)
    closs.add_argument("--c-loss", type=float, default=1_000_000)
    closs.add_argument("--volume", type=float, default=50_000_000)
    closs.add_argument("--incident-frequency", type=float, default=0.02)

    selftest = sub.add_parser("selftest", help="run deterministic arithmetic tests")
    selftest.set_defaults(fn=lambda _args: run_selftests())
    return parser


def main():
    args = build_parser().parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
