//! Builders shared by the integration tests.
//!
//! Deliberately dumb: these construct records field-by-field and do not call
//! anything in the crate under test beyond the constructors. A helper that
//! derived a record from the matcher's own view would make every test that
//! used it agree with the matcher by construction.

#![allow(dead_code)]

use std::time::Duration;

use auditor::{
    Amount, AuditPolicy, BoundParams, Bytes32, DepositEvent, EthAddress, MatchPolicy,
    ReleaseRate, ReleaseRecord,
};

/// A distinct 32-byte id, readable in failure output.
pub fn b32(tag: u64) -> Bytes32 {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&tag.to_be_bytes());
    Bytes32(out)
}

pub fn addr(tag: u8) -> EthAddress {
    let mut out = [0u8; 20];
    out[19] = tag;
    EthAddress(out)
}

pub fn amt(v: u128) -> Amount {
    Amount::from_base_units(v)
}

pub fn deposit(
    deposit_id: u64,
    amount: u128,
    dest: Bytes32,
    timestamp: u64,
) -> DepositEvent {
    DepositEvent {
        deposit_id,
        depositor: addr(1),
        amount: amt(amount),
        mob_destination: dest,
        block_number: 1_000 + deposit_id,
        log_index: 0,
        timestamp,
    }
}

pub fn release(
    release_id: Bytes32,
    claimed: Option<u64>,
    amount: u128,
    dest: Bytes32,
    timestamp: u64,
) -> ReleaseRecord {
    ReleaseRecord {
        release_id,
        claimed_deposit_id: claimed,
        amount: amt(amount),
        mob_destination: dest,
        block_index: 500,
        timestamp,
    }
}

/// A permissive policy: nothing here should trip a check on its own, so any
/// finding a test sees comes from the records it built.
pub fn lenient_policy() -> AuditPolicy {
    AuditPolicy {
        matching: MatchPolicy {
            clock_skew_tolerance: Duration::from_secs(600),
            stale_deposit_after: Duration::from_secs(86_400),
        },
        bound: BoundParams {
            remaining_balance: amt(1_000_000_000_000),
            rho: ReleaseRate::new(amt(1_000_000_000_000), Duration::from_secs(60))
                .expect("non-zero window"),
            delta_eff: Duration::from_secs(60),
            recall_horizon: Duration::ZERO,
        },
        freeze_on_anomaly: true,
    }
}
