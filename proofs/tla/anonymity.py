#!/usr/bin/env python3
"""Conditional hypergeometric sensitivity calculation for one isolated ring.

This is exact arithmetic under a hypothetical oracle model, not an exact
MobileCoin anonymity measurement. The assumed observer knows the identities of
exactly ``n_spent`` previously eliminated outputs, uses a uniform prior over all
other members, observes one ring, and has no age, amount, provenance, timing,
reuse, multi-input, or future-ring information.

MobileCoin does *not* supply the assumed output-status oracle. A public key
image ``I = x*Hp(P)`` detects reuse of the same hidden input but does not reveal
which ring public key ``P = x*G`` generated it. Public policy-pool membership
does not change that discrete-log-equality hiding property. If a different side
channel supplies a partial or delayed known-spent set, this program quantifies
the resulting single-ring sensitivity.

See ``PRIVACY_SELECTOR_COUNTEREXAMPLE.md`` and
``privacy_selector_trace.py`` for a distinct longitudinal counterexample to
unspent-only selection under a ring-observing adversary.
"""
import argparse
from math import comb, log2


def effective_set_distribution(ring_size, pool_size, n_spent):
    """Exact conditional distribution of survivor-set size for one ring.

    The real input is unspent by construction. The other `ring_size - 1` members
    are drawn from the pool. The hypothetical oracle has already identified
    ``n_spent`` exact outputs as impossible real members. Returns
    ``{survivor_set_size: probability}`` by hypergeometric enumeration.
    """
    decoys = ring_size - 1
    # decoys are drawn from the pool excluding the real input
    population = pool_size - 1
    unspent_others = pool_size - n_spent - 1   # unspent, excluding the real input
    spent = n_spent

    if unspent_others < 0 or population < decoys:
        return {}

    dist = {}
    total = comb(population, decoys)
    if total == 0:
        return {}
    for k in range(0, decoys + 1):            # k = decoys that are unspent
        if k > unspent_others or (decoys - k) > spent:
            continue
        ways = comb(unspent_others, k) * comb(spent, decoys - k)
        if ways:
            dist[1 + k] = dist.get(1 + k, 0.0) + ways / total
    return dist


def entropy_bits(dist):
    """Expected conditional posterior entropy under the uniform-survivor model.

    Given an effective set of size m, a uniform guess succeeds with probability
    1/m, contributing log2(m) bits. Averaged over the distribution.
    """
    return sum(p * log2(m) for m, p in dist.items() if m > 0)


def success_probability(dist):
    """Conditional guess probability under the uniform-survivor model."""
    return sum(p * (1.0 / m) for m, p in dist.items() if m > 0)


def cmd_closure(a):
    print("KNOWN-SPENT-SET ORACLE — conditional single-ring sensitivity")
    print(f"ring size {a.ring_size}, pool size {a.pool_size}")
    print()
    print(f"{'spent':>7} {'util':>6} {'E[eff set]':>11} {'bits':>7} "
          f"{'P(guess)':>9}  {'worst case':>11}")
    nominal = log2(a.ring_size)
    for frac in [0.0, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99]:
        n_spent = int(a.pool_size * frac)
        d = effective_set_distribution(a.ring_size, a.pool_size, n_spent)
        if not d:
            continue
        exp_set = sum(m * p for m, p in d.items())
        worst = min(d)
        print(f"{n_spent:>7} {frac:>6.0%} {exp_set:>11.2f} "
              f"{entropy_bits(d):>7.2f} {success_probability(d):>9.1%}  {worst:>11}")
    print()
    print(f"nominal anonymity at ring size {a.ring_size}: {nominal:.2f} bits "
          f"(P(guess) = {1/a.ring_size:.1%})")
    print()
    print("Reading: these values apply only when an external oracle identifies the")
    print("exact eliminated outputs and the posterior is uniform over survivors.")
    print("Public MobileCoin key images do not provide that oracle.")


def cmd_sizing(a):
    """What pool size sustains a target anonymity at a target utilisation?"""
    print("CONDITIONAL SIZING UNDER THE KNOWN-SPENT-SET ORACLE")
    print(f"ring size {a.ring_size}, target >= {a.target_bits} bits at "
          f"{a.utilisation:.0%} utilisation")
    print()
    print(f"{'pool':>7} {'spent':>7} {'bits':>7} {'P(guess)':>9}  {'verdict':>8}")
    ok_at = None
    for pool in [20, 50, 100, 200, 500, 1000, 5000]:
        n_spent = int(pool * a.utilisation)
        d = effective_set_distribution(a.ring_size, pool, n_spent)
        if not d:
            continue
        b = entropy_bits(d)
        good = b >= a.target_bits
        if good and ok_at is None:
            ok_at = pool
        print(f"{pool:>7} {n_spent:>7} {b:>7.2f} {success_probability(d):>9.1%}"
              f"  {'OK' if good else 'fails':>8}")
    print()
    if ok_at:
        print(f"Smallest pool meeting {a.target_bits} bits at {a.utilisation:.0%} "
              f"utilisation: {ok_at}")
    else:
        print(f"No pool size tested reaches {a.target_bits} bits at "
              f"{a.utilisation:.0%} utilisation.")
    print()
    print("NOTE: at a fixed oracle-known fraction, increasing absolute pool size has")
    print("little effect in this conditional model. This is not an operational churn")
    print("recommendation; output creation/spending dynamics and observations are not")
    print("modeled here.")


def cmd_compare(a):
    """Compare hypothetical known-elimination fractions."""
    print("HYPOTHETICAL KNOWN-ELIMINATION FRACTIONS")
    print()
    print("Labels below are scenarios supplied to the oracle model, not established")
    print("MobileCoin observer capabilities or long-run bridge trajectories.")
    print()
    print(f"{'scenario':>34} {'util':>6} {'bits':>7} {'P(guess)':>9}")
    for label, pool, frac in [
        ("global pool, lightly spent", 1_000_000, 0.10),
        ("policy pool, new",                 500, 0.05),
        ("policy pool, half consumed",       500, 0.50),
        ("policy pool, mostly consumed",     500, 0.90),
        ("small policy pool, half",          100, 0.50),
        ("small policy pool, mostly",        100, 0.90),
    ]:
        d = effective_set_distribution(a.ring_size, pool, int(pool * frac))
        if not d:
            continue
        print(f"{label:>34} {frac:>6.0%} {entropy_bits(d):>7.2f} "
              f"{success_probability(d):>9.1%}")
    print()
    print("Do not interpret this table without specifying the side channel that reveals")
    print("the exact eliminated outputs and when that revelation occurs.")


def cmd_selftest(a):
    """Sanity checks on the exact computation."""
    ok = True
    # zero spent -> full ring, exactly log2(ring)
    d = effective_set_distribution(11, 1000, 0)
    b = entropy_bits(d)
    print(f"zero utilisation gives nominal bits: {b:.4f} vs {log2(11):.4f} "
          f"{'PASS' if abs(b - log2(11)) < 1e-9 else 'FAIL'}")
    ok &= abs(b - log2(11)) < 1e-9
    # distributions must sum to 1
    for pool, spent in [(100, 50), (500, 450), (50, 10)]:
        d = effective_set_distribution(11, pool, spent)
        s = sum(d.values())
        good = abs(s - 1.0) < 1e-9
        print(f"distribution sums to 1 (pool={pool}, spent={spent}): {s:.10f} "
              f"{'PASS' if good else 'FAIL'}")
        ok &= good
    # monotonicity: more spent must never increase entropy
    prev = None
    mono = True
    for spent in range(0, 90, 10):
        b = entropy_bits(effective_set_distribution(11, 100, spent))
        if prev is not None and b > prev + 1e-12:
            mono = False
        prev = b
    print(f"entropy monotonically decreasing in spent fraction: "
          f"{'PASS' if mono else 'FAIL'}")
    ok &= mono
    print()
    print("ARITHMETIC SELFTESTS PASS; ADVERSARY PREMISE NOT TESTED" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    q = sub.add_parser("closure", help="effective anonymity as the pool is consumed")
    q.set_defaults(fn=cmd_closure)
    q.add_argument("--ring-size", type=int, default=11)
    q.add_argument("--pool-size", type=int, default=500)

    q = sub.add_parser("sizing", help="pool size needed to sustain a target")
    q.set_defaults(fn=cmd_sizing)
    q.add_argument("--ring-size", type=int, default=11)
    q.add_argument("--target-bits", type=float, default=3.0)
    q.add_argument("--utilisation", type=float, default=0.5)

    q = sub.add_parser("compare", help="policy pool vs global pool")
    q.set_defaults(fn=cmd_compare)
    q.add_argument("--ring-size", type=int, default=11)

    sub.add_parser("selftest", help="sanity checks").set_defaults(fn=cmd_selftest)

    a = p.parse_args()
    raise SystemExit(a.fn(a) or 0)


if __name__ == "__main__":
    main()
