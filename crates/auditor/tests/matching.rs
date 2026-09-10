//! One-to-one matching: the four required detections, and the edges around
//! them where a matcher usually goes wrong.

mod common;

use std::time::Duration;

use auditor::{
    Amount, Bytes32, Discrepancy, IngestError, Ledger, MatchPolicy, ReleaseRecord, Severity,
};
use common::{amt, b32, deposit, release};

const T0: u64 = 1_700_000_000;
const NOW: u64 = T0 + 10_000;

fn policy() -> MatchPolicy {
    MatchPolicy {
        clock_skew_tolerance: Duration::from_secs(600),
        stale_deposit_after: Duration::from_secs(86_400),
    }
}

/// One deposit, one release, everything agreeing. If this ever reports a
/// finding, every other test in this file is measuring the wrong thing.
#[test]
fn matched_pair_is_clean() {
    let mut l = Ledger::new();
    l.ingest_deposit(deposit(0, 100_000, b32(0xAA), T0)).unwrap();
    l.ingest_release(release(b32(1), Some(0), 100_000, b32(0xAA), T0 + 60))
        .unwrap();

    let r = l.reconcile(&policy(), NOW);
    assert!(r.is_clean(), "{:?}", r.discrepancies);
    assert_eq!(r.matched, 1);
    assert_eq!(r.exposure(), Amount::ZERO);
    assert!(r.stale_deposits.is_empty());
}

// ------------------------------------------------- 1. release with no deposit

#[test]
fn release_claiming_a_nonexistent_deposit_is_unbacked() {
    let mut l = Ledger::new();
    l.ingest_deposit(deposit(0, 100_000, b32(0xAA), T0)).unwrap();
    l.ingest_release(release(b32(1), Some(7), 100_000, b32(0xAA), T0 + 60))
        .unwrap();

    let r = l.reconcile(&policy(), NOW);
    assert_eq!(
        r.discrepancies,
        vec![Discrepancy::UnbackedRelease {
            release: b32(1),
            claimed: Some(7),
            amount: amt(100_000),
        }]
    );
    assert_eq!(r.exposure(), amt(100_000));
    assert_eq!(r.matched, 0);
}

/// A release naming no deposit at all. Tolerating this -- treating a missing
/// memo as "unknown, skip" -- is how free minting stays invisible.
#[test]
fn release_naming_no_deposit_at_all_is_unbacked() {
    let mut l = Ledger::new();
    l.ingest_release(release(b32(1), None, 42_000, b32(0xAA), T0 + 60))
        .unwrap();

    let r = l.reconcile(&policy(), NOW);
    assert_eq!(
        r.discrepancies,
        vec![Discrepancy::UnbackedRelease {
            release: b32(1),
            claimed: None,
            amount: amt(42_000),
        }]
    );
    assert_eq!(r.exposure(), amt(42_000));
}

// ---------------------------------------- 2. two releases against one deposit

#[test]
fn two_releases_against_one_deposit() {
    let mut l = Ledger::new();
    l.ingest_deposit(deposit(0, 100_000, b32(0xAA), T0)).unwrap();
    l.ingest_release(release(b32(1), Some(0), 100_000, b32(0xAA), T0 + 60))
        .unwrap();
    l.ingest_release(ReleaseRecord {
        block_index: 600,
        ..release(b32(2), Some(0), 100_000, b32(0xAA), T0 + 120)
    })
    .unwrap();

    let r = l.reconcile(&policy(), NOW);
    assert_eq!(
        r.discrepancies,
        vec![Discrepancy::DoubleRelease {
            deposit: 0,
            first: b32(1),
            second: b32(2),
            amount: amt(100_000),
        }]
    );
    // The first release was legitimate; only the second is unbacked.
    assert_eq!(r.exposure(), amt(100_000));
    assert_eq!(r.matched, 1);
}

/// Which release is named "first" must come from the chains, not from the
/// order the feeds happened to deliver in -- otherwise two auditors reading
/// the same two chains publish contradictory evidence. The ids here are chosen
/// so that ordering by id gives the opposite answer to ordering by block, so a
/// matcher that leaned on id order would fail this.
#[test]
fn double_release_first_claimant_is_chain_order_not_arrival_order() {
    let early = ReleaseRecord {
        block_index: 500,
        ..release(b32(9), Some(0), 100_000, b32(0xAA), T0 + 60)
    };
    let late = ReleaseRecord {
        block_index: 900,
        ..release(b32(1), Some(0), 100_000, b32(0xAA), T0 + 120)
    };

    for (a, b) in [(early, late), (late, early)] {
        let mut l = Ledger::new();
        l.ingest_deposit(deposit(0, 100_000, b32(0xAA), T0)).unwrap();
        l.ingest_release(a).unwrap();
        l.ingest_release(b).unwrap();

        let r = l.reconcile(&policy(), NOW);
        assert_eq!(
            r.discrepancies,
            vec![Discrepancy::DoubleRelease {
                deposit: 0,
                first: b32(9),
                second: b32(1),
                amount: amt(100_000),
            }],
            "ingest order changed the evidence"
        );
    }
}

// ------------------------------------------- 3. release exceeding its deposit

#[test]
fn release_exceeding_its_deposit_exposes_only_the_excess() {
    let mut l = Ledger::new();
    l.ingest_deposit(deposit(0, 100_000, b32(0xAA), T0)).unwrap();
    l.ingest_release(release(b32(1), Some(0), 150_000, b32(0xAA), T0 + 60))
        .unwrap();

    let r = l.reconcile(&policy(), NOW);
    assert_eq!(
        r.discrepancies,
        vec![Discrepancy::OverRelease {
            deposit: 0,
            release: b32(1),
            deposited: amt(100_000),
            released: amt(150_000),
            excess: amt(50_000),
        }]
    );
    assert_eq!(r.exposure(), amt(50_000));
}

/// Releasing *less* than the deposit does not create exposure -- the bridge
/// owes the depositor, it has not lost anything. Reporting it as a
/// discrepancy would freeze the escrow over a rounding difference.
#[test]
fn release_below_its_deposit_is_not_a_discrepancy() {
    let mut l = Ledger::new();
    l.ingest_deposit(deposit(0, 100_000, b32(0xAA), T0)).unwrap();
    l.ingest_release(release(b32(1), Some(0), 90_000, b32(0xAA), T0 + 60))
        .unwrap();

    assert!(l.reconcile(&policy(), NOW).is_clean());
}

// ---------------------------------------------- 4. destination does not match

#[test]
fn release_to_the_wrong_destination() {
    let mut l = Ledger::new();
    l.ingest_deposit(deposit(0, 100_000, b32(0xAA), T0)).unwrap();
    l.ingest_release(release(b32(1), Some(0), 100_000, b32(0xBB), T0 + 60))
        .unwrap();

    let r = l.reconcile(&policy(), NOW);
    assert_eq!(
        r.discrepancies,
        vec![Discrepancy::DestinationMismatch {
            deposit: 0,
            release: b32(1),
            expected: b32(0xAA),
            actual: b32(0xBB),
            amount: amt(100_000),
        }]
    );
    assert_eq!(r.exposure(), amt(100_000));
}

// ------------------------------------------------------------- exposure maths

/// One release, two findings. Summing them would report 200k at risk from a
/// release that moved 150k -- a number that cannot be fed into a bound.
#[test]
fn exposure_per_release_is_the_max_of_its_findings_not_the_sum() {
    let mut l = Ledger::new();
    l.ingest_deposit(deposit(0, 100_000, b32(0xAA), T0)).unwrap();
    l.ingest_release(release(b32(1), Some(0), 150_000, b32(0xBB), T0 + 60))
        .unwrap();

    let r = l.reconcile(&policy(), NOW);
    assert_eq!(r.discrepancies.len(), 2, "{:?}", r.discrepancies);
    let sum = r
        .discrepancies
        .iter()
        .fold(Amount::ZERO, |a, d| a.saturating_add(d.exposure()));
    assert_eq!(sum, amt(200_000), "the two findings do total 200k");
    assert_eq!(r.exposure(), amt(150_000), "but the release only moved 150k");
}

/// A double release is already a freeze, but the evidence must still describe
/// everything that was wrong with it -- whoever unwinds this needs to know the
/// money also went somewhere unexpected.
#[test]
fn a_double_release_is_still_checked_for_amount_and_destination() {
    let mut l = Ledger::new();
    l.ingest_deposit(deposit(0, 100_000, b32(0xAA), T0)).unwrap();
    l.ingest_release(release(b32(1), Some(0), 100_000, b32(0xAA), T0 + 60))
        .unwrap();
    l.ingest_release(ReleaseRecord {
        block_index: 600,
        ..release(b32(2), Some(0), 300_000, b32(0xCC), T0 + 120)
    })
    .unwrap();

    let r = l.reconcile(&policy(), NOW);
    let kinds: Vec<&str> = r.discrepancies.iter().map(|d| d.kind()).collect();
    assert_eq!(kinds, vec!["double-release", "over-release", "destination-mismatch"]);
    assert_eq!(r.exposure(), amt(300_000));
}

// --------------------------------------------------------------- time ordering

#[test]
fn release_before_its_deposit_beyond_skew_is_an_anomaly_with_no_exposure() {
    let mut l = Ledger::new();
    l.ingest_deposit(deposit(0, 100_000, b32(0xAA), T0)).unwrap();
    l.ingest_release(release(b32(1), Some(0), 100_000, b32(0xAA), T0 - 601))
        .unwrap();

    let r = l.reconcile(&policy(), NOW);
    assert_eq!(
        r.discrepancies,
        vec![Discrepancy::ReleasePrecedesDeposit {
            deposit: 0,
            release: b32(1),
            deposit_ts: T0,
            release_ts: T0 - 601,
        }]
    );
    assert_eq!(r.worst_severity(), Some(Severity::Anomaly));
    // The deposit did arrive and the amount matches, so no value is at risk
    // from this record alone. The finding is about the authorisation path.
    assert_eq!(r.exposure(), Amount::ZERO);
}

/// The two chains' clocks are independent; the check must not fire on the
/// difference between them. 600s tolerance, release 600s early: exactly at the
/// boundary, and the boundary is inclusive of tolerated skew.
#[test]
fn release_before_its_deposit_within_skew_is_clean() {
    let mut l = Ledger::new();
    l.ingest_deposit(deposit(0, 100_000, b32(0xAA), T0)).unwrap();
    l.ingest_release(release(b32(1), Some(0), 100_000, b32(0xAA), T0 - 600))
        .unwrap();

    assert!(l.reconcile(&policy(), NOW).is_clean());
}

// -------------------------------------------------------------------- liveness

#[test]
fn unreleased_deposit_is_stale_not_a_discrepancy() {
    let mut l = Ledger::new();
    l.ingest_deposit(deposit(0, 100_000, b32(0xAA), T0)).unwrap();

    let p = MatchPolicy { stale_deposit_after: Duration::from_secs(3_600), ..policy() };
    let r = l.reconcile(&p, T0 + 7_200);
    assert!(r.is_clean(), "a stuck user is not a solvency event");
    assert_eq!(r.stale_deposits.len(), 1);
    assert_eq!(r.stale_deposits[0].deposit_id, 0);
    assert_eq!(r.stale_deposits[0].age_secs, 7_200);
    assert_eq!(r.exposure(), Amount::ZERO);
}

#[test]
fn recently_deposited_and_unreleased_is_not_yet_stale() {
    let mut l = Ledger::new();
    l.ingest_deposit(deposit(0, 100_000, b32(0xAA), T0)).unwrap();

    let p = MatchPolicy { stale_deposit_after: Duration::from_secs(3_600), ..policy() };
    let r = l.reconcile(&p, T0 + 60);
    assert!(r.stale_deposits.is_empty());
}

// --------------------------------------------------------------------- ingest

/// Last-write-wins on deposits would let anything that can inject one log
/// entry raise a deposit's amount until it backs a release that nothing backs,
/// and the audit would then pass.
#[test]
fn contradictory_deposit_under_one_id_is_refused() {
    let mut l = Ledger::new();
    l.ingest_deposit(deposit(0, 100_000, b32(0xAA), T0)).unwrap();
    assert_eq!(
        l.ingest_deposit(deposit(0, 999_999, b32(0xAA), T0)),
        Err(IngestError::ConflictingDeposit(0))
    );
    assert_eq!(l.deposit(0).unwrap().amount, amt(100_000), "original survived");
}

#[test]
fn contradictory_release_under_one_id_is_refused() {
    let mut l = Ledger::new();
    l.ingest_release(release(b32(1), Some(0), 100_000, b32(0xAA), T0))
        .unwrap();
    assert_eq!(
        l.ingest_release(release(b32(1), Some(0), 1, b32(0xAA), T0)),
        Err(IngestError::ConflictingRelease(b32(1)))
    );
}

/// Both feeds replay on reconnect. An identical redelivery is normal traffic
/// and must not turn into a double-release finding.
#[test]
fn identical_redelivery_is_idempotent() {
    let mut l = Ledger::new();
    let d = deposit(0, 100_000, b32(0xAA), T0);
    let r = release(b32(1), Some(0), 100_000, b32(0xAA), T0 + 60);
    for _ in 0..3 {
        l.ingest_deposit(d).unwrap();
        l.ingest_release(r).unwrap();
    }

    let rep = l.reconcile(&policy(), NOW);
    assert!(rep.is_clean(), "{:?}", rep.discrepancies);
    assert_eq!(rep.releases_examined, 1);
    assert_eq!(rep.deposits_examined, 1);
}

// ---------------------------------------------------------------------- serde

/// Amounts leave this process as JSON. A `u128` serialised as a JSON *number*
/// is silently rounded by any consumer that parses numbers as doubles, which
/// is most of them, and the rounding starts around 9 billion USDC -- inside
/// the range a bridge float can reach.
#[test]
fn amounts_survive_json_past_the_double_precision_cliff() {
    let big = Amount::from_base_units(u128::MAX);
    let json = serde_json::to_string(&big).unwrap();
    assert_eq!(json, format!("\"{}\"", u128::MAX));
    assert_eq!(serde_json::from_str::<Amount>(&json).unwrap(), big);

    // The specific value where an f64 round-trip first loses a unit.
    let cliff = Amount::from_base_units((1u128 << 53) + 1);
    let back: Amount = serde_json::from_str(&serde_json::to_string(&cliff).unwrap()).unwrap();
    assert_eq!(back, cliff);
    assert_ne!(
        back.base_units(),
        ((1u128 << 53) + 1) as f64 as u128,
        "the f64 route really does lose this value"
    );
}

#[test]
fn records_round_trip_through_json() {
    let d = deposit(3, 100_000, b32(0xAA), T0);
    let r = release(b32(1), Some(3), 100_000, b32(0xAA), T0 + 60);
    assert_eq!(
        serde_json::from_str::<auditor::DepositEvent>(&serde_json::to_string(&d).unwrap())
            .unwrap(),
        d
    );
    assert_eq!(
        serde_json::from_str::<ReleaseRecord>(&serde_json::to_string(&r).unwrap()).unwrap(),
        r
    );
}

#[test]
fn bytes32_rejects_wrong_length() {
    assert!(serde_json::from_str::<Bytes32>("\"0xdeadbeef\"").is_err());
}
