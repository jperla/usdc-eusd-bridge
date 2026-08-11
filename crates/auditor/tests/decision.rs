//! The decision layer: what the caller is handed and what it can do with it.

mod common;

use std::time::Duration;

use auditor::{
    audit, Amount, AuditPolicy, BoundParams, Discrepancy, FreezeDecision, FreezeReason,
    Ledger, ReleaseRate, ReleaseRecord,
};
use common::{amt, b32, deposit, lenient_policy, release};

const T0: u64 = 1_700_000_000;
const NOW: u64 = T0 + 10_000;

fn clean_ledger() -> Ledger {
    let mut l = Ledger::new();
    l.ingest_deposit(deposit(0, 100_000, b32(0xAA), T0)).unwrap();
    l.ingest_release(release(b32(1), Some(0), 100_000, b32(0xAA), T0 + 60))
        .unwrap();
    l
}

#[test]
fn a_clean_ledger_continues_and_still_reports_the_bound() {
    let d = audit(&clean_ledger(), &lenient_policy(), NOW);
    let FreezeDecision::Continue { stats } = d else {
        panic!("unexpected freeze: {d:?}");
    };
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.releases_examined, 1);
    assert_eq!(stats.deposits_examined, 1);
    assert_eq!(stats.stale_deposits, 0);
    // No findings, so P = 0 and the bound is the pure rate term: 1,000,000
    // USDC per 60s over 60s.
    assert_eq!(stats.bound, amt(1_000_000_000_000));
}

#[test]
fn an_unbacked_release_produces_a_freeze_carrying_the_evidence() {
    let mut l = clean_ledger();
    l.ingest_release(ReleaseRecord {
        block_index: 600,
        ..release(b32(2), Some(77), 250_000, b32(0xAA), T0 + 120)
    })
    .unwrap();

    let d = audit(&l, &lenient_policy(), NOW);
    assert!(d.is_freeze());
    assert_eq!(d.reason(), Some(FreezeReason::UnbackedRelease));

    let FreezeDecision::Freeze { evidence, .. } = &d else { unreachable!() };
    assert_eq!(evidence.observed_exposure, amt(250_000));
    assert_eq!(
        evidence.report.discrepancies,
        vec![Discrepancy::UnbackedRelease {
            release: b32(2),
            claimed: Some(77),
            amount: amt(250_000),
        }]
    );
    assert_eq!(evidence.observed_at, NOW);
    // The inputs are recorded so the number can be recomputed without
    // trusting this run.
    assert_eq!(evidence.params, lenient_policy().bound);
}

/// The freeze reason ranks the findings; the caller acts on one string, so it
/// must be the most alarming thing that happened, not the first one seen.
#[test]
fn the_reason_is_the_worst_finding_present() {
    let mut l = Ledger::new();
    l.ingest_deposit(deposit(0, 100_000, b32(0xAA), T0)).unwrap();
    // A destination mismatch (ranked low) at an early block, and an unbacked
    // release (ranked high) at a later one, so finding order and rank differ.
    l.ingest_release(ReleaseRecord {
        block_index: 500,
        ..release(b32(1), Some(0), 100_000, b32(0xBB), T0 + 60)
    })
    .unwrap();
    l.ingest_release(ReleaseRecord {
        block_index: 900,
        ..release(b32(2), None, 1_000, b32(0xCC), T0 + 120)
    })
    .unwrap();

    let d = audit(&l, &lenient_policy(), NOW);
    assert_eq!(d.reason(), Some(FreezeReason::UnbackedRelease));
    let FreezeDecision::Freeze { evidence, .. } = &d else { unreachable!() };
    assert_eq!(
        evidence.report.discrepancies[0].kind(),
        "destination-mismatch",
        "the low-ranked finding really did come first"
    );
}

/// Realised loss above the bound means `rho`, `delta_eff` or `P` is not
/// describing reality, which outranks any individual finding: the size of the
/// hole is no longer known either.
#[test]
fn loss_beyond_the_bound_is_reported_as_a_model_failure() {
    // Two unbacked releases of 500k each, both far inside the recall horizon
    // so P = 0, against a rate ceiling of 100k/hour over a 60s delay:
    // rho * delta_eff = ceil(100_000 * 60 / 3600) = 1_667.
    let strict = AuditPolicy {
        bound: BoundParams {
            remaining_balance: amt(10_000_000_000),
            rho: ReleaseRate::new(amt(100_000), Duration::from_secs(3_600)).unwrap(),
            delta_eff: Duration::from_secs(60),
            recall_horizon: Duration::from_secs(3_600),
        },
        ..lenient_policy()
    };

    let mut l = Ledger::new();
    l.ingest_release(ReleaseRecord {
        block_index: 500,
        ..release(b32(1), None, 500_000, b32(0xAA), NOW - 20)
    })
    .unwrap();
    l.ingest_release(ReleaseRecord {
        block_index: 600,
        ..release(b32(2), None, 500_000, b32(0xAA), NOW - 10)
    })
    .unwrap();

    let d = audit(&l, &strict, NOW);
    assert_eq!(d.reason(), Some(FreezeReason::ExposureBoundViolated));
    let FreezeDecision::Freeze { evidence, .. } = &d else { unreachable!() };
    assert_eq!(evidence.p_irrevocable, Amount::ZERO, "both releases are recent");
    assert_eq!(evidence.bound, amt(1_667));
    assert_eq!(evidence.observed_exposure, amt(1_000_000));

    // Same ledger, a rate ceiling that actually permits what happened --
    // 100M/hour over 60s is 1,666,667, above the 1,000,000 observed. The model
    // is no longer contradicted, so the reason falls back to the finding.
    let permissive = AuditPolicy {
        bound: BoundParams {
            rho: ReleaseRate::new(amt(100_000_000), Duration::from_secs(3_600)).unwrap(),
            ..strict.bound
        },
        ..strict
    };
    let d = audit(&l, &permissive, NOW);
    let FreezeDecision::Freeze { evidence, .. } = &d else { unreachable!() };
    assert_eq!(evidence.bound, amt(1_666_667));
    assert_eq!(d.reason(), Some(FreezeReason::UnbackedRelease));
}

/// Value out past the recall horizon lands in `P` and raises the bound; the
/// same value still inside the horizon does not. This is the only place the
/// horizon changes an answer, so it is the only place it can be checked.
#[test]
fn the_recall_horizon_moves_value_into_p() {
    let base = AuditPolicy {
        bound: BoundParams {
            remaining_balance: amt(10_000_000_000),
            rho: ReleaseRate::new(amt(100_000), Duration::from_secs(3_600)).unwrap(),
            delta_eff: Duration::from_secs(60),
            recall_horizon: Duration::from_secs(3_600),
        },
        ..lenient_policy()
    };

    let mut old = Ledger::new();
    old.ingest_release(release(b32(1), None, 500_000, b32(0xAA), NOW - 7_200))
        .unwrap();
    let FreezeDecision::Freeze { evidence, .. } = audit(&old, &base, NOW) else {
        panic!("expected a freeze");
    };
    assert_eq!(evidence.p_irrevocable, amt(500_000));
    assert_eq!(evidence.bound, amt(501_667));

    let mut recent = Ledger::new();
    recent
        .ingest_release(release(b32(1), None, 500_000, b32(0xAA), NOW - 60))
        .unwrap();
    let FreezeDecision::Freeze { evidence, .. } = audit(&recent, &base, NOW) else {
        panic!("expected a freeze");
    };
    assert_eq!(evidence.p_irrevocable, Amount::ZERO);
    assert_eq!(evidence.bound, amt(1_667));
}

// ------------------------------------------------------------------ anomalies

fn anomaly_ledger() -> Ledger {
    let mut l = Ledger::new();
    l.ingest_deposit(deposit(0, 100_000, b32(0xAA), T0)).unwrap();
    l.ingest_release(release(b32(1), Some(0), 100_000, b32(0xAA), T0 - 601))
        .unwrap();
    l
}

#[test]
fn an_anomaly_alone_freezes_under_the_default_policy() {
    let d = audit(&anomaly_ledger(), &lenient_policy(), NOW);
    assert_eq!(d.reason(), Some(FreezeReason::ReleasePrecedesDeposit));
    let FreezeDecision::Freeze { evidence, .. } = &d else { unreachable!() };
    assert_eq!(evidence.observed_exposure, Amount::ZERO, "no value at risk yet");
}

/// The opt-out exists, and turning it on really is the only difference between
/// the two runs above and below.
#[test]
fn an_anomaly_alone_can_be_configured_not_to_freeze() {
    let p = AuditPolicy { freeze_on_anomaly: false, ..lenient_policy() };
    let d = audit(&anomaly_ledger(), &p, NOW);
    assert!(!d.is_freeze(), "{d:?}");
    let FreezeDecision::Continue { stats } = d else { unreachable!() };
    assert_eq!(stats.matched, 0, "the release still did not match");
}

/// The opt-out must not suppress a real loss that happens to sit alongside an
/// anomaly.
#[test]
fn the_anomaly_opt_out_does_not_suppress_a_loss() {
    let mut l = anomaly_ledger();
    l.ingest_release(ReleaseRecord {
        block_index: 900,
        ..release(b32(2), Some(999), 5_000, b32(0xAA), T0 + 60)
    })
    .unwrap();

    let p = AuditPolicy { freeze_on_anomaly: false, ..lenient_policy() };
    assert_eq!(audit(&l, &p, NOW).reason(), Some(FreezeReason::UnbackedRelease));
}

/// A stuck user is a liveness problem with the opposite remedy: freezing over
/// it strands everyone else to no benefit.
#[test]
fn a_stale_deposit_alone_does_not_freeze() {
    let mut l = Ledger::new();
    l.ingest_deposit(deposit(0, 100_000, b32(0xAA), T0)).unwrap();
    let d = audit(&l, &lenient_policy(), T0 + 200_000);
    assert!(!d.is_freeze(), "{d:?}");
    let FreezeDecision::Continue { stats } = d else { unreachable!() };
    assert_eq!(stats.stale_deposits, 1);
}

// ------------------------------------------------------------- escrow calldata

/// `Escrow.freeze(string)` takes calldata, which costs gas and is paid at the
/// worst possible moment. The reason string names the finding and locates the
/// release; the case itself is `Evidence`, off-chain.
#[test]
fn the_escrow_reason_is_short_deterministic_and_names_the_finding() {
    let mut l = clean_ledger();
    l.ingest_release(ReleaseRecord {
        block_index: 600,
        ..release(b32(0xDEAD), Some(77), 250_000, b32(0xAA), T0 + 120)
    })
    .unwrap();

    let a = audit(&l, &lenient_policy(), NOW).escrow_reason().unwrap();
    let b = audit(&l, &lenient_policy(), NOW).escrow_reason().unwrap();
    assert_eq!(a, b, "the same facts must produce the same calldata");
    assert!(a.len() <= 200, "reason is {} bytes: {a}", a.len());
    assert!(a.is_ascii(), "calldata should not carry surprises: {a}");
    assert!(a.contains("unbacked-release"), "{a}");
    assert!(a.contains("000000000000dead"), "{a}");
    assert!(a.contains("exp=250000"), "{a}");
}

#[test]
fn a_continue_has_no_escrow_reason() {
    assert_eq!(audit(&clean_ledger(), &lenient_policy(), NOW).escrow_reason(), None);
}

/// The whole decision, including the case, has to survive being written to a
/// file and read by whoever unwinds this later.
#[test]
fn a_freeze_decision_round_trips_through_json() {
    let mut l = clean_ledger();
    l.ingest_release(ReleaseRecord {
        block_index: 600,
        ..release(b32(2), Some(77), 250_000, b32(0xAA), T0 + 120)
    })
    .unwrap();

    let d = audit(&l, &lenient_policy(), NOW);
    let json = serde_json::to_string(&d).unwrap();
    let back: FreezeDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
    assert_eq!(back.escrow_reason(), d.escrow_reason());
}

/// `FreezeReason`'s ordering is what `worst_of` relies on, so pin it.
#[test]
fn freeze_reasons_are_ranked_most_alarming_first() {
    let ranked = [
        FreezeReason::ExposureBoundViolated,
        FreezeReason::UnbackedRelease,
        FreezeReason::DoubleRelease,
        FreezeReason::OverRelease,
        FreezeReason::DestinationMismatch,
        FreezeReason::ReleasePrecedesDeposit,
    ];
    for w in ranked.windows(2) {
        assert!(w[0] < w[1], "{:?} should outrank {:?}", w[0], w[1]);
    }
}
