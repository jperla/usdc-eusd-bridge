//! Durable binding of one-time values to signing contexts, and the anti-rollback
//! anchor that makes that durability mean something.
//!
//! Two separate mechanisms, because they defend against two different failures:
//!
//!   the STORE stops a slot from being bound to two different contexts. That is
//!   the defence against a signer that is merely buggy or merely restarted.
//!
//!   the ANCHOR stops the store itself from being rewound. A store cannot
//!   detect its own rollback -- after a snapshot restore it is, by construction,
//!   a perfectly consistent store that has simply never heard of the binding.
//!   Detection has to come from state that did not roll back with it: an HSM
//!   monotonic counter, a separate append-only log, a TPM NV index. The trait
//!   below is the seam where that hardware plugs in; `MemoryAnchor` is the test
//!   stand-in for it.
//!
//! What the anchor holds is a DIGEST, not just a count. `proofs/tla/NonceSlot.tla`
//! is explicit about why: a counter can only tell you that the number went
//! down, and a signer serving many slots pushes the number back up within a few
//! writes of a restore. After that the fork is invisible to arithmetic --
//! two divergent records at the same sequence both look like progress. So every
//! durable write is hash-chained onto the one before it (`RecordLog`), and the
//! anchor advances by compare-and-swap on that chain: a store that continues a
//! history the anchor never anchored is refused. The same note requires the
//! record to be logged write-ahead, so that a record which lost half of itself
//! can be told apart from a record that was never written -- a bare counter
//! cannot reject "current generation beside stale phase bytes".

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::rc::Rc;

use mc_crypto_hashes::{Blake2b256, Digest};

use crate::context::{ContextId, SlotId};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StoreError {
    /// The slot is already bound to a *different* context. This is the exact
    /// condition that leaks the long-term share if it is allowed through.
    #[error("slot {slot:?} is already bound to {existing}, cannot bind to {attempted}")]
    AlreadyBound {
        slot: SlotId,
        existing: ContextId,
        attempted: ContextId,
    },
    /// bind() was called on a slot that was never reserved, i.e. a share was
    /// about to be produced for a one-time value the store has no record of.
    #[error("slot {0:?} was never reserved")]
    NotReserved(SlotId),
    /// The record in storage is not the record the write-ahead log says was
    /// written. A half-applied write, a partial restore, a corrupted page: in
    /// every case the store no longer knows what this one-time value is
    /// committed to, and guessing is how a nonce gets used twice.
    #[error("record for slot {slot:?} disagrees with the log: logged {logged:?}, found {found:?}")]
    TornRecord {
        slot: SlotId,
        logged: SlotRecord,
        found: Option<SlotRecord>,
    },
    #[error("backing store failed: {0}")]
    Io(String),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotRecord {
    /// The one-time value exists and its commitment may be published.
    Reserved,
    /// The one-time value is committed to this context and no other, ever.
    Bound(ContextId),
}

/// Hash of one durable record, chained onto every record before it.
///
/// Chained rather than standalone so that the anchor's compare-and-swap says
/// something about the whole history and not just the last write: two stores
/// that agree on the latest record but disagree about anything earlier have
/// different digests here.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordDigest([u8; 32]);

impl fmt::Debug for RecordDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecordDigest(")?;
        for b in &self.0[..6] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "..)")
    }
}

impl fmt::Display for RecordDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

const RECORD_DOMAIN: &[u8] = b"bridge/ceremony/record/v1";

/// Every field is fixed width and the phase is tagged, so no two distinct
/// records can hash alike by shifting a boundary.
fn chain(
    prev: Option<RecordDigest>,
    sequence: u64,
    slot: SlotId,
    record: SlotRecord,
) -> RecordDigest {
    let mut h = Blake2b256::new();
    h.update(RECORD_DOMAIN);
    match prev {
        Some(d) => {
            h.update([1u8]);
            h.update(d.0);
        }
        None => {
            h.update([0u8]);
            h.update([0u8; 32]);
        }
    }
    h.update(sequence.to_le_bytes());
    h.update(slot.0.to_le_bytes());
    match record {
        SlotRecord::Reserved => {
            h.update([1u8]);
            h.update([0u8; 32]);
        }
        SlotRecord::Bound(c) => {
            h.update([2u8]);
            h.update(c.0);
        }
    }
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    RecordDigest(out)
}

mod sealed {
    use super::{chain, ContextId, RecordDigest, SlotId, SlotRecord};

    /// Proof that a durable write happened before this point in the program.
    ///
    /// `Authorizer::round_two` takes one by reference, so "produce a share" is
    /// not expressible without having first been through a store. That is only
    /// worth anything if a receipt cannot be conjured: it is minted in exactly
    /// one place, `RecordLog::confirm`, from the record read back out of
    /// storage after the write. There is no public constructor and the fields
    /// are private, so this does not compile:
    ///
    /// ```compile_fail
    /// use ceremony::store::Receipt;
    /// use ceremony::{ContextId, SlotId};
    /// let forged = Receipt::issue(SlotId(0), Some(ContextId([0u8; 32])), 1);
    /// ```
    ///
    /// and neither does this:
    ///
    /// ```compile_fail
    /// use ceremony::store::{Receipt, SlotRecord};
    /// use ceremony::SlotId;
    /// let forged = Receipt { slot: SlotId(0), record: SlotRecord::Reserved };
    /// ```
    ///
    /// The only way to hold one is to have written through a store:
    ///
    /// ```
    /// use ceremony::store::{BindingStore, MemoryStore, SlotRecord};
    /// use ceremony::SlotId;
    /// let mut store = MemoryStore::new();
    /// let receipt = store.reserve(SlotId(0)).unwrap();
    /// assert_eq!(receipt.slot(), SlotId(0));
    /// assert_eq!(receipt.record(), SlotRecord::Reserved);
    /// ```
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Receipt {
        slot: SlotId,
        record: SlotRecord,
        sequence: u64,
        prev_head: Option<RecordDigest>,
        head: RecordDigest,
    }

    impl Receipt {
        /// Visible to `store` only. Callers there must pass the record they read
        /// back out of storage, never the one they meant to write.
        pub(super) fn seal(
            slot: SlotId,
            record: SlotRecord,
            sequence: u64,
            prev_head: Option<RecordDigest>,
            head: RecordDigest,
        ) -> Self {
            Receipt {
                slot,
                record,
                sequence,
                prev_head,
                head,
            }
        }

        pub fn slot(&self) -> SlotId {
            self.slot
        }

        /// What storage held for this slot when the write was confirmed. This,
        /// not the caller's argument, is what a backend must check itself
        /// against.
        pub fn record(&self) -> SlotRecord {
            self.record
        }

        pub fn context(&self) -> Option<ContextId> {
            match self.record {
                SlotRecord::Reserved => None,
                SlotRecord::Bound(c) => Some(c),
            }
        }

        pub fn sequence(&self) -> u64 {
            self.sequence
        }

        /// The chain head this write continued, i.e. the value the anchor must
        /// already hold for the write to be a continuation rather than a fork.
        pub fn prev_head(&self) -> Option<RecordDigest> {
            self.prev_head
        }

        /// The chain head after this write.
        pub fn head(&self) -> RecordDigest {
            self.head
        }

        /// Recompute the chain link from the receipt's own parts. Nothing in the
        /// crate can produce a receipt that fails this; it is here so that a
        /// store which reconstitutes receipts from persisted bytes has one call
        /// to make.
        pub fn is_well_formed(&self) -> bool {
            self.head == chain(self.prev_head, self.sequence, self.slot, self.record)
        }
    }
}

pub use sealed::Receipt;

/// A write that has been logged and not yet confirmed against storage.
///
/// Dropping one leaves the log ahead of the record, which every later `check`
/// reports as a torn record. That is the intended behaviour and not a leak: a
/// crash between the log append and the write leaves exactly this state on
/// disk, and a nonce store that cannot say what it committed to must stop.
#[must_use = "an unconfirmed write leaves the log ahead of storage"]
pub struct PendingWrite {
    slot: SlotId,
    record: SlotRecord,
    sequence: u64,
    prev_head: Option<RecordDigest>,
    head: RecordDigest,
}

/// The write-ahead log: the ordered, hash-chained record of every durable
/// write, and the only thing that can mint a `Receipt`.
///
/// A store implementation drives it in three steps -- `check` what storage
/// holds against what was logged, `prepare` the next entry, then `confirm` it
/// against a read-back. Routing writes through here is what makes the receipt a
/// statement about storage rather than about the caller's intentions.
#[derive(Clone, Default, Debug)]
pub struct RecordLog {
    entries: Vec<LogEntry>,
    head: Option<RecordDigest>,
    sequence: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct LogEntry {
    sequence: u64,
    slot: SlotId,
    record: SlotRecord,
    digest: RecordDigest,
}

impl RecordLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn head(&self) -> Option<RecordDigest> {
        self.head
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// What the log says storage should hold for `slot`.
    pub fn expected(&self, slot: SlotId) -> Option<SlotRecord> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.slot == slot)
            .map(|e| e.record)
    }

    /// Refuse to act on a record that is not the one the log says was written.
    pub fn check(&self, slot: SlotId, found: Option<SlotRecord>) -> Result<(), StoreError> {
        match self.expected(slot) {
            None => Ok(()),
            Some(logged) if Some(logged) == found => Ok(()),
            Some(logged) => Err(StoreError::TornRecord {
                slot,
                logged,
                found,
            }),
        }
    }

    /// Append the intent to write, ahead of the write itself.
    pub fn prepare(&mut self, slot: SlotId, record: SlotRecord) -> PendingWrite {
        let prev_head = self.head;
        let sequence = self.sequence + 1;
        let head = chain(prev_head, sequence, slot, record);
        self.entries.push(LogEntry {
            sequence,
            slot,
            record,
            digest: head,
        });
        self.head = Some(head);
        self.sequence = sequence;
        PendingWrite {
            slot,
            record,
            sequence,
            prev_head,
            head,
        }
    }

    /// Confirm a prepared write against what storage now holds, and mint the
    /// receipt for it. `found` must be re-read from storage after the write; a
    /// caller that passes back the value it meant to write gets a receipt that
    /// attests to its own intentions and nothing else.
    pub fn confirm(
        &mut self,
        pending: PendingWrite,
        found: Option<SlotRecord>,
    ) -> Result<Receipt, StoreError> {
        if found != Some(pending.record) {
            return Err(StoreError::TornRecord {
                slot: pending.slot,
                logged: pending.record,
                found,
            });
        }
        Ok(Receipt::seal(
            pending.slot,
            pending.record,
            pending.sequence,
            pending.prev_head,
            pending.head,
        ))
    }
}

/// The durable side of the ceremony.
///
/// Implementations must make the write durable BEFORE returning the receipt.
/// The machine treats the return of a receipt as "this survives a crash", and
/// publishes the commitment / emits the share only afterwards. They must also
/// route the write through a `RecordLog`, which is the only source of receipts.
pub trait BindingStore {
    /// Monotonically increasing count of durable writes. Never decreases in a
    /// correct implementation; if it does, the store has been rewound.
    fn sequence(&self) -> u64;

    /// Head of the record chain, or `None` before the first write.
    fn head(&self) -> Option<RecordDigest>;

    /// Record that a one-time value exists, before its commitment is published.
    ///
    /// Idempotent, and deliberately so: a signer that crashed between reserving
    /// and publishing must be able to resume, and from the store's side that is
    /// indistinguishable from a signer whose state was rolled back. Refusal
    /// therefore lives entirely in `bind` (which is where reuse becomes
    /// dangerous, since only a *response* leaks anything) and in the anchor
    /// (which is the only thing that can tell a resume from a rewind).
    fn reserve(&mut self, slot: SlotId) -> Result<Receipt, StoreError>;

    /// Bind a reserved one-time value to one context, before any share for it
    /// is produced.
    ///
    /// Re-binding to the *identical* context is permitted, and this is not
    /// laxity: the backend's response is a deterministic function of the full
    /// context, so re-answering an identical context returns bytes the peer
    /// already has. That argument only holds because the key is the full
    /// context. Under a (statement, subset) key it would be false -- two
    /// different round-one packages share that key and do *not* share a
    /// response -- which is why the narrow key is not merely weaker but unsound.
    fn bind(&mut self, slot: SlotId, context: ContextId) -> Result<Receipt, StoreError>;

    fn lookup(&self, slot: SlotId) -> Option<SlotRecord>;
}

/// In-memory store with an explicit snapshot/restore, so tests can perform the
/// rollback that a VM snapshot or a restored backup performs in production.
#[derive(Clone, Default, Debug)]
pub struct MemoryStore {
    slots: BTreeMap<SlotId, SlotRecord>,
    log: RecordLog,
}

/// Opaque snapshot. Deliberately not `SlotRecord`-shaped so a test cannot
/// accidentally "restore" something it hand-built.
#[derive(Clone, Debug)]
pub struct Snapshot(MemoryStore);

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot(self.clone())
    }
    pub fn restore(&mut self, s: &Snapshot) {
        *self = s.0.clone();
    }

    pub fn log(&self) -> &RecordLog {
        &self.log
    }

    /// Fault injection, in the same spirit as `snapshot`/`restore`: overwrite
    /// what storage holds for `slot` without touching the log, which is what a
    /// half-applied write or a partial restore leaves behind. Production stores
    /// have no such method; they get torn records from hardware instead.
    pub fn tear_record(&mut self, slot: SlotId, record: SlotRecord) {
        self.slots.insert(slot, record);
    }

    /// Log-ahead, write, read back, mint.
    fn write(&mut self, slot: SlotId, record: SlotRecord) -> Result<Receipt, StoreError> {
        self.log.check(slot, self.slots.get(&slot).copied())?;
        let pending = self.log.prepare(slot, record);
        self.slots.insert(slot, record);
        let found = self.slots.get(&slot).copied();
        self.log.confirm(pending, found)
    }
}

impl BindingStore for MemoryStore {
    fn sequence(&self) -> u64 {
        self.log.sequence()
    }

    fn head(&self) -> Option<RecordDigest> {
        self.log.head()
    }

    fn reserve(&mut self, slot: SlotId) -> Result<Receipt, StoreError> {
        let record = self.slots.get(&slot).copied().unwrap_or(SlotRecord::Reserved);
        self.write(slot, record)
    }

    fn bind(&mut self, slot: SlotId, context: ContextId) -> Result<Receipt, StoreError> {
        let found = self.slots.get(&slot).copied();
        // Decide on the record only once storage and the log agree about what
        // it is. A torn record that reads `Reserved` while the log says
        // `Bound` would otherwise be re-bound to a second context.
        self.log.check(slot, found)?;
        match found {
            None => Err(StoreError::NotReserved(slot)),
            Some(SlotRecord::Bound(existing)) if existing != context => {
                Err(StoreError::AlreadyBound {
                    slot,
                    existing,
                    attempted: context,
                })
            }
            // The remaining cases are a fresh binding and the idempotent replay
            // of an identical one; see the trait doc for why the replay is safe.
            Some(_) => self.write(slot, SlotRecord::Bound(context)),
        }
    }

    fn lookup(&self, slot: SlotId) -> Option<SlotRecord> {
        self.slots.get(&slot).copied()
    }
}

// A ceremony takes its store by value, but tests need to reach the same store
// afterwards to roll it back. Sharing is a property of the handle, not of the
// discipline, so the impl just forwards.
impl<S: BindingStore> BindingStore for Rc<RefCell<S>> {
    fn sequence(&self) -> u64 {
        self.borrow().sequence()
    }
    fn head(&self) -> Option<RecordDigest> {
        self.borrow().head()
    }
    fn reserve(&mut self, slot: SlotId) -> Result<Receipt, StoreError> {
        self.borrow_mut().reserve(slot)
    }
    fn bind(&mut self, slot: SlotId, context: ContextId) -> Result<Receipt, StoreError> {
        self.borrow_mut().bind(slot, context)
    }
    fn lookup(&self, slot: SlotId) -> Option<SlotRecord> {
        self.borrow().lookup(slot)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AnchorError {
    #[error("store sequence {observed} is below the anchored high-water mark {high_water}")]
    Rewound { observed: u64, high_water: u64 },
    /// The store is continuing a history the anchor never anchored. A rollback
    /// whose counter has caught up looks exactly like this, and so does a
    /// second copy of the same signer: in both cases two divergent records
    /// exist for one one-time value and only one of them is the anchored one.
    #[error("record chain forked: write continues {presented:?}, anchor holds {anchored:?}")]
    Forked {
        presented: Option<RecordDigest>,
        anchored: Option<RecordDigest>,
    },
    /// Once rollback has been seen, this signer is done. Not "done with this
    /// ceremony" -- done. A rewound store may have lost bindings we cannot
    /// enumerate, so there is no safe next signature to produce.
    #[error("anchor is poisoned by an earlier rollback")]
    Poisoned,
}

/// State that does not roll back when the store does.
///
/// Two checks, at two moments, because they see different things. `observe` is
/// the pre-write check: it can only compare counts, since before a write there
/// is no record to compare. `commit` is the post-write compare-and-swap on the
/// record chain, and it is the one that survives a counter catching up.
pub trait Anchor {
    fn high_water(&self) -> u64;

    /// The anchored chain head: the last record this anchor accepted.
    fn head(&self) -> Option<RecordDigest>;

    fn is_poisoned(&self) -> bool;

    /// Record an observation of the store's sequence. Errors -- and poisons --
    /// if the store has gone backwards.
    fn observe(&mut self, sequence: u64) -> Result<(), AnchorError>;

    /// Advance the anchor to the receipt's record, if and only if the receipt
    /// continues the history the anchor already holds.
    ///
    /// The operands come from a `Receipt`, so they are the store's own read-back
    /// and cannot be supplied by a caller. Re-presenting the record the anchor
    /// already holds succeeds: that is a crash between the store's commit and
    /// this call being replayed, not a fork.
    fn commit(&mut self, receipt: &Receipt) -> Result<(), AnchorError>;
}

#[derive(Clone, Default, Debug)]
pub struct MemoryAnchor {
    high_water: u64,
    head: Option<RecordDigest>,
    poisoned: bool,
}

impl MemoryAnchor {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Anchor for MemoryAnchor {
    fn high_water(&self) -> u64 {
        self.high_water
    }
    fn head(&self) -> Option<RecordDigest> {
        self.head
    }
    fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    fn observe(&mut self, sequence: u64) -> Result<(), AnchorError> {
        if self.poisoned {
            return Err(AnchorError::Poisoned);
        }
        if sequence < self.high_water {
            self.poisoned = true;
            return Err(AnchorError::Rewound {
                observed: sequence,
                high_water: self.high_water,
            });
        }
        self.high_water = sequence;
        Ok(())
    }
    fn commit(&mut self, receipt: &Receipt) -> Result<(), AnchorError> {
        if self.poisoned {
            return Err(AnchorError::Poisoned);
        }
        if self.head == Some(receipt.head()) {
            return Ok(());
        }
        if receipt.sequence() < self.high_water {
            self.poisoned = true;
            return Err(AnchorError::Rewound {
                observed: receipt.sequence(),
                high_water: self.high_water,
            });
        }
        if receipt.prev_head() != self.head {
            self.poisoned = true;
            return Err(AnchorError::Forked {
                presented: receipt.prev_head(),
                anchored: self.head,
            });
        }
        self.head = Some(receipt.head());
        self.high_water = receipt.sequence();
        Ok(())
    }
}

impl<A: Anchor> Anchor for Rc<RefCell<A>> {
    fn high_water(&self) -> u64 {
        self.borrow().high_water()
    }
    fn head(&self) -> Option<RecordDigest> {
        self.borrow().head()
    }
    fn is_poisoned(&self) -> bool {
        self.borrow().is_poisoned()
    }
    fn observe(&mut self, sequence: u64) -> Result<(), AnchorError> {
        self.borrow_mut().observe(sequence)
    }
    fn commit(&mut self, receipt: &Receipt) -> Result<(), AnchorError> {
        self.borrow_mut().commit(receipt)
    }
}
