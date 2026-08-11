//! The freeze bound: `E = min(B, P + rho * delta_eff)`.

mod common;

use std::time::Duration;

use auditor::{effective_delay, exposure_bound, irrevocable_value, Amount, RateError,
              ReleaseRate};
use common::amt;

// A base point in USDC base units (6 decimals):
//   B         = 1,000,000 USDC
//   P         =   200,000 USDC
//   rho       =   100,000 USDC / 60s
//   delta_eff =        90s   ->  rho * delta_eff = 150,000 USDC
// so P + rho*delta_eff = 350,000 USDC, which is below B. The rate term is the
// one that binds; that is deliberate, see `each_of_the_four_inputs_is_load_bearing`.
const B: u128 = 1_000_000_000_000;
const P: u128 = 200_000_000_000;
const RHO_PER_WINDOW: u128 = 100_000_000_000;
const WINDOW: Duration = Duration::from_secs(60);
const DELTA: Duration = Duration::from_secs(90);
const BASE: u128 = 350_000_000_000;

fn rho() -> ReleaseRate {
    ReleaseRate::new(amt(RHO_PER_WINDOW), WINDOW).unwrap()
}

fn base() -> Amount {
    exposure_bound(amt(B), amt(P), rho(), DELTA)
}

#[test]
fn base_point_is_the_hand_computed_value() {
    assert_eq!(base(), amt(BASE));
}

/// Change one input, the bound changes -- for each of the four.
///
/// The perturbations are all in the direction that makes the changed input
/// bind, and that is not a weakening of the claim, it is what the claim can
/// mean for a `min`: raising `B` above the rate term cannot change the answer
/// and nothing is wrong with a bound for which that is true. What must not
/// happen is an input being ignorable, and a witness perturbation for each of
/// the four rules that out. The base point is chosen so that all four witnesses
/// exist simultaneously.
#[test]
fn each_of_the_four_inputs_is_load_bearing() {
    let cases: [(&str, Amount); 4] = [
        // B: drop it below the 350k rate term and it becomes the binding side.
        ("remaining_balance", exposure_bound(amt(300_000_000_000), amt(P), rho(), DELTA)),
        // P: 250k + 150k = 400k.
        ("p_irrevocable", exposure_bound(amt(B), amt(250_000_000_000), rho(), DELTA)),
        // rho: 200k/60s over 90s = 300k, + 200k = 500k.
        (
            "rho",
            exposure_bound(
                amt(B),
                amt(P),
                ReleaseRate::new(amt(200_000_000_000), WINDOW).unwrap(),
                DELTA,
            ),
        ),
        // delta_eff: 100k/60s over 180s = 300k, + 200k = 500k.
        ("delta_eff", exposure_bound(amt(B), amt(P), rho(), Duration::from_secs(180))),
    ];

    for (name, perturbed) in cases {
        assert_ne!(perturbed, base(), "changing {name} left the bound unchanged");
    }

    // The witnesses land where hand arithmetic says they should, so this is not
    // merely "something moved".
    assert_eq!(cases[0].1, amt(300_000_000_000));
    assert_eq!(cases[1].1, amt(400_000_000_000));
    assert_eq!(cases[2].1, amt(500_000_000_000));
    assert_eq!(cases[3].1, amt(500_000_000_000));
}

/// Both branches of the `min` really do bind, in both directions. Without
/// this, an implementation that dropped one term entirely could still pass the
/// load-bearing test above by accident.
#[test]
fn both_branches_of_the_min_bind() {
    // Rate term binding: raising B far past it changes nothing.
    assert_eq!(exposure_bound(amt(u128::MAX), amt(P), rho(), DELTA), amt(BASE));
    // Balance binding: raising P far past a small B changes nothing.
    let small = amt(1_000);
    assert_eq!(exposure_bound(small, amt(u128::MAX), rho(), DELTA), small);
    assert_eq!(
        exposure_bound(small, amt(P), rho(), Duration::from_secs(86_400)),
        small
    );
}

/// A bound that could shrink when an input worsened would be worse than no
/// bound: it would let a deteriorating situation read as an improving one.
#[test]
fn the_bound_is_monotone_in_every_input() {
    let balances = [0u128, 1_000, BASE, B, u128::MAX];
    let ps = [0u128, 1_000, P, B];
    let rates = [0u128, 1, RHO_PER_WINDOW, u128::MAX];
    let deltas = [0u64, 1, 90, 86_400];

    let f = |b: u128, p: u128, r: u128, d: u64| {
        exposure_bound(
            amt(b),
            amt(p),
            ReleaseRate::new(amt(r), WINDOW).unwrap(),
            Duration::from_secs(d),
        )
    };

    for w in balances.windows(2) {
        for &p in &ps {
            for &r in &rates {
                for &d in &deltas {
                    assert!(f(w[0], p, r, d) <= f(w[1], p, r, d), "B at p={p} r={r} d={d}");
                }
            }
        }
    }
    for &b in &balances {
        for w in ps.windows(2) {
            for &r in &rates {
                for &d in &deltas {
                    assert!(f(b, w[0], r, d) <= f(b, w[1], r, d), "P at b={b} r={r} d={d}");
                }
            }
        }
    }
    for &b in &balances {
        for &p in &ps {
            for w in rates.windows(2) {
                for &d in &deltas {
                    assert!(f(b, p, w[0], d) <= f(b, p, w[1], d), "rho at b={b} p={p} d={d}");
                }
            }
        }
    }
    for &b in &balances {
        for &p in &ps {
            for &r in &rates {
                for w in deltas.windows(2) {
                    assert!(f(b, p, r, w[0]) <= f(b, p, r, w[1]), "delta at b={b} p={p} r={r}");
                }
            }
        }
    }
}

// ----------------------------------------------------------------- rho * delta

/// Hand-computed vectors. The third is the one that separates ceiling from
/// truncating division: 7 per 60s over 10s is 7/6 of a unit, and a bound that
/// truncates to 1 is a bound that is wrong in the unsafe direction.
#[test]
fn rate_times_delay_known_values() {
    let cases: [(u128, u64, u64, u128); 5] = [
        // (per window, window secs, delta secs, expected)
        (100, 60, 60, 100),
        (100, 60, 90, 150),
        (7, 60, 10, 2),
        (100, 60, 0, 0),
        (0, 60, 86_400, 0),
    ];
    for (per, w, d, want) in cases {
        let r = ReleaseRate::new(amt(per), Duration::from_secs(w)).unwrap();
        assert_eq!(
            r.max_released_within(Duration::from_secs(d)),
            amt(want),
            "{per} per {w}s over {d}s"
        );
    }
}

/// Nanosecond granularity: any non-zero slice of time at a non-zero rate must
/// yield at least one base unit, because rounding an interval down to zero is
/// the same as asserting nothing can happen during it.
#[test]
fn a_sliver_of_time_is_not_free() {
    let r = ReleaseRate::new(amt(100), Duration::from_secs(60)).unwrap();
    assert_eq!(r.max_released_within(Duration::from_nanos(1)), amt(1));
}

/// The defining property of ceiling division, checked with multiplication
/// only -- no division appears in this oracle, so it does not restate the
/// implementation. A floor-dividing implementation fails the second clause.
#[test]
fn rate_times_delay_satisfies_the_ceiling_property() {
    let pers = [0u128, 1, 7, 100, 1_000_000, RHO_PER_WINDOW];
    let windows = [1u64, 7, 60, 3_600];
    let deltas = [0u64, 1, 5, 60, 90, 3_599, 86_400];

    for &per in &pers {
        for &w in &windows {
            let window = Duration::from_secs(w);
            let rate = ReleaseRate::new(amt(per), window).unwrap();
            for &d in &deltas {
                let delta = Duration::from_secs(d);
                let got = rate.max_released_within(delta).base_units();

                let numerator = per
                    .checked_mul(delta.as_nanos())
                    .expect("chosen to stay in range");
                let wn = window.as_nanos();

                assert!(
                    got.checked_mul(wn).expect("in range") >= numerator,
                    "{per}/{w}s over {d}s: {got} is below the true value"
                );
                if got > 0 {
                    assert!(
                        (got - 1).checked_mul(wn).expect("in range") < numerator,
                        "{per}/{w}s over {d}s: {got} overshoots by a whole unit"
                    );
                }
            }
        }
    }
}

/// An overflowing `rho * delta` must saturate upward. Wrapping here would turn
/// an absurd rate into a small, plausible-looking bound.
#[test]
fn an_overflowing_rate_term_saturates_upward_and_does_not_panic() {
    let r = ReleaseRate::new(Amount::MAX, Duration::from_nanos(1)).unwrap();
    assert_eq!(r.max_released_within(Duration::from_secs(1)), Amount::MAX);
    assert_eq!(exposure_bound(amt(B), amt(P), r, Duration::from_secs(1)), amt(B));
    // And with P also at the ceiling, so the addition saturates too.
    assert_eq!(exposure_bound(amt(B), Amount::MAX, r, Duration::MAX), amt(B));
}

#[test]
fn a_halted_rate_leaves_only_what_is_already_gone() {
    assert_eq!(
        exposure_bound(amt(B), amt(P), ReleaseRate::halted(), Duration::from_secs(86_400)),
        amt(P)
    );
    assert_eq!(exposure_bound(amt(B), amt(P), rho(), Duration::ZERO), amt(P));
}

/// A zero window is an infinite rate. Accepting it would make the bound
/// silently equal to the balance, which looks like a number.
#[test]
fn a_zero_rate_window_is_rejected() {
    assert_eq!(
        ReleaseRate::new(amt(1), Duration::ZERO),
        Err(RateError::ZeroWindow)
    );
}

#[test]
fn per_second_is_the_same_rate_as_per_60s_scaled() {
    let a = ReleaseRate::per_second(amt(1_000));
    let b = ReleaseRate::new(amt(60_000), Duration::from_secs(60)).unwrap();
    for d in [0u64, 1, 30, 90, 3_600] {
        let d = Duration::from_secs(d);
        assert_eq!(a.max_released_within(d), b.max_released_within(d));
    }
}

// -------------------------------------------------------------------------- P

#[test]
fn irrevocable_counts_only_what_is_past_the_horizon() {
    let now = 10_000u64;
    let items = vec![
        (amt(100), now - 3_600), // exactly at the horizon: counted
        (amt(200), now - 3_599), // one second short: not counted
        (amt(400), now - 7_200), // well past: counted
        (amt(800), now),         // just now: not counted
    ];
    assert_eq!(
        irrevocable_value(items.clone(), now, Duration::from_secs(3_600)),
        amt(500)
    );
    // A zero horizon treats everything already out as unrecoverable.
    assert_eq!(irrevocable_value(items.clone(), now, Duration::ZERO), amt(1_500));
    // A horizon nothing has reached yet.
    assert_eq!(irrevocable_value(items, now, Duration::from_secs(100_000)), Amount::ZERO);
}

#[test]
fn irrevocable_saturates_rather_than_wrapping() {
    let items = vec![(Amount::MAX, 0u64), (amt(1), 0u64)];
    assert_eq!(irrevocable_value(items, 10_000, Duration::ZERO), Amount::MAX);
}

// --------------------------------------------------------------- delta_eff

#[test]
fn effective_delay_is_the_sum_of_its_segments() {
    assert_eq!(
        effective_delay(
            Duration::from_secs(20),  // MobileCoin feed lag
            Duration::from_secs(30),  // auditor poll interval
            Duration::from_secs(5),   // reconcile + decide
            Duration::from_secs(60),  // freeze tx to inclusion
        ),
        Duration::from_secs(115)
    );
    assert_eq!(
        effective_delay(Duration::MAX, Duration::from_secs(1), Duration::ZERO, Duration::ZERO),
        Duration::MAX,
        "saturates rather than panicking on absurd input"
    );
}
