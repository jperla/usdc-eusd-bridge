//! The two record streams and the store that holds them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::amount::{Amount, Bytes32, EthAddress};
use crate::matcher::{self, MatchPolicy, MatchReport};

/// Escrow's `depositId`.
///
/// `uint256` on-chain, `u64` here: it is `nextDepositId++`, one increment per
/// deposit, so the on-chain value cannot leave `u64` range. Ingest still checks
/// rather than truncating, because a value out of range means the feed is not
/// reading the contract this crate thinks it is.
pub type DepositId = u64;

/// One `Deposited` log from the Ethereum escrow.
///
/// Fields mirror the event exactly. Nothing is derived at this layer -- a
/// deposit record that has been "helpfully" normalised on the way in is a
/// deposit record whose disagreement with the chain is invisible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositEvent {
    /// `Deposited.depositId`.
    pub deposit_id: DepositId,
    /// `Deposited.depositor`.
    pub depositor: EthAddress,
    /// `Deposited.amount`, USDC base units.
    pub amount: Amount,
    /// `Deposited.mobDestination`. Opaque to the escrow; this crate only ever
    /// compares it for equality, never interprets it.
    pub mob_destination: Bytes32,
    /// Ethereum block containing the log.
    pub block_number: u64,
    /// Log index within the block. With `block_number` this is the total order
    /// the deposits actually occurred in.
    pub log_index: u64,
    /// `block.timestamp` of that block, unix seconds.
    pub timestamp: u64,
}

/// One eUSD release performed on the MobileCoin side.
///
/// `claimed_deposit_id` is the operators' assertion of which deposit this
/// release discharges, carried in the release memo. It is an assertion, not a
/// proof -- checking it is the entire point of this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRecord {
    /// The released output's public key: unique per release, and the same
    /// identifier `Escrow.redeemed` keys its replay set on, so the two sides
    /// name a release the same way.
    pub release_id: Bytes32,
    /// The deposit the operators claim this release discharges.
    ///
    /// `None` is a release that named no deposit at all. That is not a missing
    /// field to be tolerated: an unreferenced release is exactly what an
    /// operator minting free eUSD produces, so it is treated as unbacked.
    pub claimed_deposit_id: Option<DepositId>,
    /// Released value, normalised to USDC base units by the escrow's
    /// conversion ratio.
    pub amount: Amount,
    /// Where the eUSD went. Compared against the deposit's `mob_destination`.
    pub mob_destination: Bytes32,
    /// MobileCoin block index containing the release.
    pub block_index: u64,
    /// Timestamp of that MobileCoin block, unix seconds.
    pub timestamp: u64,
}

/// Why a record was refused at ingest.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum IngestError {
    /// Two different deposits arrived under one id.
    ///
    /// Refused rather than last-write-wins. Overwriting would let anything
    /// that can inject one log entry restate an existing deposit's amount
    /// upward and thereby back a release that nothing backs -- the audit would
    /// then pass, which is worse than not running.
    #[error("conflicting deposit records for id {0}")]
    ConflictingDeposit(DepositId),

    /// Two different releases arrived under one output public key. Same
    /// reasoning, other direction: it would let a release be restated
    /// downward until it fits its deposit.
    #[error("conflicting release records for id {0}")]
    ConflictingRelease(Bytes32),
}

/// The reconciled view of both chains.
#[derive(Clone, Debug, Default)]
pub struct Ledger {
    deposits: BTreeMap<DepositId, DepositEvent>,
    releases: BTreeMap<Bytes32, ReleaseRecord>,
}

impl Ledger {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest one deposit log.
    ///
    /// Idempotent for byte-identical records, because both chain feeds replay
    /// on reconnect and re-delivery is normal; contradictory records are an
    /// error, because contradiction is not.
    pub fn ingest_deposit(&mut self, d: DepositEvent) -> Result<(), IngestError> {
        match self.deposits.get(&d.deposit_id) {
            Some(existing) if *existing != d => {
                Err(IngestError::ConflictingDeposit(d.deposit_id))
            }
            Some(_) => Ok(()),
            None => {
                self.deposits.insert(d.deposit_id, d);
                Ok(())
            }
        }
    }

    /// Ingest one release record. Same idempotence rule as deposits.
    pub fn ingest_release(&mut self, r: ReleaseRecord) -> Result<(), IngestError> {
        match self.releases.get(&r.release_id) {
            Some(existing) if *existing != r => {
                Err(IngestError::ConflictingRelease(r.release_id))
            }
            Some(_) => Ok(()),
            None => {
                self.releases.insert(r.release_id, r);
                Ok(())
            }
        }
    }

    /// Deposits, ordered by id.
    pub fn deposits(&self) -> impl Iterator<Item = &DepositEvent> {
        self.deposits.values()
    }

    /// Releases, in a deterministic order.
    ///
    /// Ordered by `(block_index, release_id)` and not by arrival: which of two
    /// releases against one deposit is named "the double" must not depend on
    /// which feed reconnected first, or two auditors comparing notes would
    /// disagree about the evidence while agreeing about the fact.
    pub fn releases_in_order(&self) -> Vec<ReleaseRecord> {
        let mut v: Vec<ReleaseRecord> = self.releases.values().copied().collect();
        v.sort_by_key(|r| (r.block_index, r.release_id));
        v
    }

    /// Look up a deposit.
    pub fn deposit(&self, id: DepositId) -> Option<&DepositEvent> {
        self.deposits.get(&id)
    }

    /// Match releases to deposits one-to-one and report every mismatch.
    pub fn reconcile(&self, policy: &MatchPolicy, now: u64) -> MatchReport {
        matcher::reconcile(self, policy, now)
    }
}
