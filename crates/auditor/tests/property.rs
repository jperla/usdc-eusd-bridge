//! Randomised mutation testing of the matcher.
//!
//! The shape matters, because the easy version of this test is worthless. The
//! mutation is applied to the *records*, never to the detector, and the
//! expected finding and expected exposure are computed by the generator from
//! what it did -- not read back out of the report. So there is no path by
//! which the code under test can influence its own oracle.
//!
//! Each round asserts three things about the mutated ledger: the finding is of
//! the kind the mutation should produce, the exposure equals the value the
//! mutation actually put at risk, and there is *exactly one* finding. The last
//! is the one that catches over-reporting -- a matcher that flagged everything
//! would pass the first two.
//!
//! The un-mutated ledger is asserted clean in the same round, so a matcher
//! that reported nothing and a matcher that reported everything both fail.

mod common;

use std::time::Duration;

use auditor::{audit, Amount, Ledger, MatchPolicy, ReleaseRecord};
use common::{amt, b32, deposit, lenient_policy, release};

/// SplitMix64. Fixed constants, no dependency, and the seed is printed on
/// failure so a counterexample is reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const BASE_TS: u64 = 1_700_000_000;
const SKEW: u64 = 600;

fn policy() -> MatchPolicy {
    MatchPolicy {
        clock_skew_tolerance: Duration::from_secs(SKEW),
        stale_deposit_after: Duration::from_secs(86_400),
    }
}

struct Case {
    deposits: Vec<auditor::DepositEvent>,
    releases: Vec<ReleaseRecord>,
    now: u64,
}

impl Case {
    fn ledger(&self) -> Ledger {
        let mut l = Ledger::new();
        for d in &self.deposits {
            l.ingest_deposit(*d).unwrap();
        }
        for r in &self.releases {
            l.ingest_release(*r).unwrap();
        }
        l
    }
}

/// A ledger in which every deposit has exactly one correct release.
fn honest(rng: &mut Rng) -> Case {
    let n = 3 + rng.below(6);
    let mut deposits = Vec::new();
    let mut releases = Vec::new();

    for i in 0..n {
        let amount = 1_000_000 + rng.below(1_000_000_000) as u128;
        let dest = b32(0x1000 + rng.below(1 << 20));
        let dep_ts = BASE_TS + i * 300;
        let rel_ts = dep_ts + 60 + rng.below(120);

        deposits.push(deposit(i, amount, dest, dep_ts));
        releases.push(ReleaseRecord {
            block_index: i,
            ..release(b32(0x8000_0000 + i), Some(i), amount, dest, rel_ts)
        });
    }

    Case { deposits, releases, now: BASE_TS + n * 300 + 1_000 }
}

/// What a mutation is expected to produce. Both fields are set by the mutation
/// site from the values it changed.
struct Expect {
    kind: &'static str,
    exposure: Amount,
}

fn mutate(case: &mut Case, which: usize, rng: &mut Rng) -> Expect {
    let k = (rng.below(case.releases.len() as u64)) as usize;

    match which {
        // A release against a deposit id that does not exist.
        0 => {
            let amount = 1_000_000 + rng.below(1_000_000_000) as u128;
            case.releases.push(ReleaseRecord {
                block_index: 10_000,
                ..release(
                    b32(0xDEAD_0000),
                    Some(9_999_999),
                    amount,
                    b32(0x1000),
                    case.now - 100,
                )
            });
            Expect { kind: "unbacked-release", exposure: amt(amount) }
        }

        // A second release discharging a deposit that is already discharged.
        1 => {
            let orig = case.releases[k];
            case.releases.push(ReleaseRecord {
                release_id: b32(0xBEEF_0000 + k as u64),
                block_index: 10_000 + k as u64,
                ..orig
            });
            Expect { kind: "double-release", exposure: orig.amount }
        }

        // A release larger than its deposit.
        2 => {
            let excess = 1 + rng.below(1_000_000_000) as u128;
            let orig = case.releases[k].amount.base_units();
            case.releases[k].amount = amt(orig + excess);
            Expect { kind: "over-release", exposure: amt(excess) }
        }

        // A release to somewhere the depositor did not name.
        3 => {
            let orig = case.releases[k];
            // `0x2000_0000` is outside the range `honest` draws destinations
            // from, so the new destination is guaranteed to differ.
            case.releases[k].mob_destination = b32(0x2000_0000 + k as u64);
            Expect { kind: "destination-mismatch", exposure: orig.amount }
        }

        // A release timestamped before the deposit it claims, beyond any skew
        // the policy tolerates.
        4 => {
            let dep_ts = case.deposits[case.releases[k].claimed_deposit_id.unwrap() as usize]
                .timestamp;
            case.releases[k].timestamp = dep_ts - SKEW - 1;
            // The deposit arrived and the amount matches: nothing is at risk
            // from this record, the finding is about the authorisation path.
            Expect { kind: "release-precedes-deposit", exposure: Amount::ZERO }
        }

        _ => unreachable!(),
    }
}

#[test]
fn one_data_mutation_produces_exactly_one_matching_finding() {
    const ROUNDS: u64 = 400;
    const MUTATIONS: usize = 5;

    for seed in 0..ROUNDS {
        for which in 0..MUTATIONS {
            let mut rng = Rng(seed.wrapping_mul(0x2545_F491_4F6C_DD1D) ^ which as u64);
            let mut case = honest(&mut rng);

            // The generator's own output must be clean, or the mutated result
            // proves nothing.
            let clean = case.ledger().reconcile(&policy(), case.now);
            assert!(
                clean.is_clean() && clean.stale_deposits.is_empty(),
                "seed {seed}/{which}: honest ledger was not clean: {:?} {:?}",
                clean.discrepancies,
                clean.stale_deposits
            );
            assert_eq!(clean.matched, case.releases.len());
            assert_eq!(clean.exposure(), Amount::ZERO);

            let expect = mutate(&mut case, which, &mut rng);
            let got = case.ledger().reconcile(&policy(), case.now);

            let kinds: Vec<&str> = got.discrepancies.iter().map(|d| d.kind()).collect();
            assert_eq!(
                kinds,
                vec![expect.kind],
                "seed {seed}/{which}: wrong findings for a single mutation"
            );
            assert_eq!(
                got.exposure(),
                expect.exposure,
                "seed {seed}/{which}: exposure does not equal the value the mutation risked"
            );

            // And the decision layer must turn it into a freeze, every time.
            assert!(
                audit(&case.ledger(), &lenient_policy(), case.now).is_freeze(),
                "seed {seed}/{which}: a detected mutation did not freeze"
            );
        }
    }
}

/// Independently of the mutation catalogue: the honest generator on its own
/// never produces a finding and never produces a freeze. If this failed, every
/// assertion above would be about a ledger that was already broken.
#[test]
fn the_honest_generator_is_clean_and_continues() {
    for seed in 0..400u64 {
        let mut rng = Rng(seed ^ 0xA5A5_A5A5_A5A5_A5A5);
        let case = honest(&mut rng);
        let d = audit(&case.ledger(), &lenient_policy(), case.now);
        assert!(!d.is_freeze(), "seed {seed}: {d:?}");
    }
}

/// The serialised tag and the on-chain slug are the same word, for every
/// variant the mutation catalogue can produce.
#[test]
fn the_serde_tag_matches_the_slug() {
    let mut rng = Rng(1);
    for which in 0..5usize {
        let mut case = honest(&mut rng);
        let expect = mutate(&mut case, which, &mut rng);
        let got = case.ledger().reconcile(&policy(), case.now);
        let json = serde_json::to_value(&got.discrepancies[0]).unwrap();
        assert_eq!(json["kind"], expect.kind);
    }
}
