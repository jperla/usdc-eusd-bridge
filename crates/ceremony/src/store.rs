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
//!   Detection has to come from a counter that did not roll back with it: an
//!   HSM monotonic counter, a separate append-only log, a TPM NV index. The
//!   trait below is the seam where that hardware plugs in; `MemoryAnchor` is the
//!   test stand-in for it.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

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

/// Proof that a durable write happened before this point in the program.
///
/// `Authorizer::round_two` takes one by reference, so "produce a share" is not
/// expressible without having first been through the store. The sequence number
/// is what the anchor checks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Receipt {
    slot: SlotId,
    context: Option<ContextId>,
    sequence: u64,
}

impl Receipt {
    /// Minted by store implementations only. Callers outside a store have no
    /// business fabricating one, and there is nothing useful they could do with
    /// a fabricated one except defeat the ordering guarantee for themselves.
    pub fn issue(slot: SlotId, context: Option<ContextId>, sequence: u64) -> Self {
        Receipt {
            slot,
            context,
            sequence,
        }
    }
    pub fn slot(&self) -> SlotId {
        self.slot
    }
    pub fn context(&self) -> Option<ContextId> {
        self.context
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// The durable side of the ceremony.
///
/// Implementations must make the write durable BEFORE returning the receipt.
/// The machine treats the return of a receipt as "this survives a crash", and
/// publishes the commitment / emits the share only afterwards.
pub trait BindingStore {
    /// Monotonically increasing count of durable writes. Never decreases in a
    /// correct implementation; if it does, the store has been rewound.
    fn sequence(&self) -> u64;

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
    sequence: u64,
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
}

impl BindingStore for MemoryStore {
    fn sequence(&self) -> u64 {
        self.sequence
    }

    fn reserve(&mut self, slot: SlotId) -> Result<Receipt, StoreError> {
        self.slots.entry(slot).or_insert(SlotRecord::Reserved);
        self.sequence += 1;
        Ok(Receipt::issue(slot, None, self.sequence))
    }

    fn bind(&mut self, slot: SlotId, context: ContextId) -> Result<Receipt, StoreError> {
        match self.slots.get(&slot) {
            None => Err(StoreError::NotReserved(slot)),
            Some(SlotRecord::Bound(existing)) if *existing != context => {
                Err(StoreError::AlreadyBound {
                    slot,
                    existing: *existing,
                    attempted: context,
                })
            }
            Some(SlotRecord::Bound(_)) => {
                // Idempotent replay of the identical context; see the trait doc.
                self.sequence += 1;
                Ok(Receipt::issue(slot, Some(context), self.sequence))
            }
            Some(SlotRecord::Reserved) => {
                self.slots.insert(slot, SlotRecord::Bound(context));
                self.sequence += 1;
                Ok(Receipt::issue(slot, Some(context), self.sequence))
            }
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
    /// Once rollback has been seen, this signer is done. Not "done with this
    /// ceremony" -- done. A rewound store may have lost bindings we cannot
    /// enumerate, so there is no safe next signature to produce.
    #[error("anchor is poisoned by an earlier rollback")]
    Poisoned,
}

/// A counter that does not roll back when the store does.
pub trait Anchor {
    fn high_water(&self) -> u64;
    fn is_poisoned(&self) -> bool;
    /// Record an observation of the store's sequence. Errors -- and poisons --
    /// if the store has gone backwards.
    fn observe(&mut self, sequence: u64) -> Result<(), AnchorError>;
    fn poison(&mut self);
}

#[derive(Clone, Default, Debug)]
pub struct MemoryAnchor {
    high_water: u64,
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
    fn poison(&mut self) {
        self.poisoned = true;
    }
}

impl<A: Anchor> Anchor for Rc<RefCell<A>> {
    fn high_water(&self) -> u64 {
        self.borrow().high_water()
    }
    fn is_poisoned(&self) -> bool {
        self.borrow().is_poisoned()
    }
    fn observe(&mut self, sequence: u64) -> Result<(), AnchorError> {
        self.borrow_mut().observe(sequence)
    }
    fn poison(&mut self) {
        self.borrow_mut().poison()
    }
}
