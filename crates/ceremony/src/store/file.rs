//! Single-writer durable binding journal. No nonce secrets are stored here.
//! Keep the Anchor in a separate rollback-resistant failure domain. A valid
//! old journal is indistinguishable from a restored snapshot without it.
use super::*;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};
use std::path::Path;

const MAGIC: &[u8; 16] = b"MC-NONCE-LOG-v1\0";
const FRAME: usize = 81; // sequence8, slot8, phase1, context32, chain-digest32
const MAX_BYTES: u64 = 128 * 1024 * 1024;
fn io(e: impl std::fmt::Display) -> StoreError {
    StoreError::Io(e.to_string())
}

/// Holds an OS advisory exclusive lock until drop, including across each
/// fsync/read-back. Only cooperating processes may write the journal; use a
/// private directory. Missing, torn, invalid or oversized journals fail closed.
/// Creating a new journal is explicit and never overwrites an existing one.
pub struct FileStore {
    file: File,
    state: MemoryStore,
    poisoned: bool,
}
impl FileStore {
    pub fn create(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(io)?;
        Self::lock(&file)?;
        let mut this = Self {
            file,
            state: MemoryStore::new(),
            poisoned: false,
        };
        this.file.write_all(MAGIC).map_err(io)?;
        this.file.sync_all().map_err(io)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(parent).and_then(|f| f.sync_all()).map_err(io)?;
        this.read_state()?;
        Ok(this)
    }
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(io)?;
        Self::lock(&file)?;
        let mut this = Self {
            file,
            state: MemoryStore::new(),
            poisoned: false,
        };
        this.state = this.read_state()?;
        Ok(this)
    }
    fn lock(file: &File) -> Result<(), StoreError> {
        // SAFETY: fd is valid and stays owned by File for the lock lifetime.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io(std::io::Error::last_os_error()));
        }
        if !file.metadata().map_err(io)?.is_file() {
            return Err(io("journal is not a regular file"));
        }
        Ok(())
    }
    pub fn head(&self) -> Option<RecordDigest> {
        self.state.head()
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    fn read_state(&mut self) -> Result<MemoryStore, StoreError> {
        let length = self.file.metadata().map_err(io)?.len();
        if length > MAX_BYTES {
            return Err(io("journal capacity exceeded"));
        }
        self.file.seek(SeekFrom::Start(0)).map_err(io)?;
        let mut bytes = Vec::new();
        self.file.read_to_end(&mut bytes).map_err(io)?;
        if !bytes.starts_with(MAGIC) || (bytes.len() - MAGIC.len()) % FRAME != 0 {
            return Err(io("invalid header or torn journal frame"));
        }
        let mut state = MemoryStore::new();
        for f in bytes[MAGIC.len()..].chunks_exact(FRAME) {
            let sequence = u64::from_le_bytes(f[..8].try_into().unwrap());
            let slot = SlotId(u64::from_le_bytes(f[8..16].try_into().unwrap()));
            let receipt = match f[16] {
                1 if f[17..49] == [0; 32] && state.lookup(slot).is_none() => state.reserve(slot)?,
                // Repeated reserve of an existing record is encoded as its
                // actual phase. Replaying either identical operation is safe.
                1 if f[17..49] == [0; 32] && state.lookup(slot) == Some(SlotRecord::Reserved) => {
                    state.reserve(slot)?
                }
                2 => state.bind(slot, ContextId(f[17..49].try_into().unwrap()))?,
                _ => return Err(io("invalid journal phase or transition")),
            };
            if receipt.sequence() != sequence || receipt.head().0 != f[49..81] {
                return Err(io("journal hash chain mismatch"));
            }
        }
        Ok(state)
    }
    fn persist(&mut self, next: MemoryStore, receipt: Receipt) -> Result<Receipt, StoreError> {
        if self.poisoned {
            return Err(io("journal poisoned; restart and reconcile anchor"));
        }
        // Any error after intent may mean the write reached disk. Refuse all
        // further operations until a fresh open validates the whole journal.
        self.poisoned = true;
        let found = self.read_state()?;
        if found.head() != self.state.head() {
            return Err(io("journal changed outside the lock"));
        }
        if self.file.metadata().map_err(io)?.len() + FRAME as u64 > MAX_BYTES {
            return Err(io("journal capacity exceeded"));
        }
        let mut frame = Vec::with_capacity(FRAME);
        frame.extend(receipt.sequence().to_le_bytes());
        frame.extend(receipt.slot().0.to_le_bytes());
        match receipt.record() {
            SlotRecord::Reserved => {
                frame.push(1);
                frame.extend([0; 32]);
            }
            SlotRecord::Bound(c) => {
                frame.push(2);
                frame.extend(c.0);
            }
        }
        frame.extend(receipt.head().0);
        self.file.seek(SeekFrom::End(0)).map_err(io)?;
        self.file.write_all(&frame).map_err(io)?;
        self.file.sync_all().map_err(io)?;
        let found = self.read_state()?;
        if found.head() != next.head() || found.lookup(receipt.slot()) != Some(receipt.record()) {
            return Err(io("journal read-back mismatch"));
        }
        self.state = found;
        self.poisoned = false;
        Ok(receipt)
    }
}
impl BindingStore for FileStore {
    fn sequence(&self) -> u64 {
        self.state.sequence()
    }
    fn lookup(&self, slot: SlotId) -> Option<SlotRecord> {
        self.state.lookup(slot)
    }
    fn reserve(&mut self, slot: SlotId) -> Result<Receipt, StoreError> {
        let mut next = self.state.clone();
        let receipt = next.reserve(slot)?;
        self.persist(next, receipt)
    }
    fn bind(&mut self, slot: SlotId, context: ContextId) -> Result<Receipt, StoreError> {
        let mut next = self.state.clone();
        let receipt = next.bind(slot, context)?;
        self.persist(next, receipt)
    }
}

/// MLSAG adapter. An independent Anchor is mandatory: copying/reconstructing
/// its state from this journal would defeat rollback detection. A crash between
/// journal fsync and anchor commit stops signing until explicit reconciliation.
pub struct DurableNonceGuard<'a, A: Anchor> {
    store: &'a mut FileStore,
    anchor: &'a mut A,
    last_error: Option<String>,
}
impl<'a, A: Anchor> DurableNonceGuard<'a, A> {
    pub fn new(store: &'a mut FileStore, anchor: &'a mut A) -> Result<Self, StoreError> {
        if store.is_poisoned()
            || anchor.is_poisoned()
            || store.head() != anchor.head()
            || store.sequence() != anchor.high_water()
        {
            return Err(io("nonce journal and independent anchor disagree"));
        }
        Ok(Self {
            store,
            anchor,
            last_error: None,
        })
    }
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }
    fn claim(
        &mut self,
        binding: two_cohort::mlsag::SessionBinding,
        seat: two_cohort::mlsag::Seat,
    ) -> Result<(), StoreError> {
        use two_cohort::mlsag::{Seat, SpendRole};
        if self.last_error.is_some()
            || self.store.is_poisoned()
            || self.anchor.is_poisoned()
            || self.store.head() != self.anchor.head()
            || self.store.sequence() != self.anchor.high_water()
        {
            return Err(io("nonce guard halted or anchor mismatch"));
        }
        let (kind, id) = match seat {
            Seat::Spend(SpendRole::View) => (0u8, 0u64),
            Seat::Spend(SpendRole::Owner(id)) => (1, id),
            Seat::Spend(SpendRole::Gate(id)) => (2, id),
            Seat::Mask => (3, 0),
        };
        let mut h = Blake2b256::new();
        h.update(b"bridge-durable-mlsag-reservation-v1");
        h.update(binding.as_bytes());
        h.update([kind]);
        h.update(id.to_le_bytes());
        let context = ContextId(h.finalize().into());
        if self
            .store
            .state
            .slots
            .values()
            .any(|r| *r == SlotRecord::Bound(context))
        {
            return Err(io("nonce already issued"));
        }
        // Fresh monotonic slots, full 256-bit context comparison. No truncated
        // hash index and no secret nonce serialization.
        let slot = SlotId(
            self.store
                .sequence()
                .checked_add(1)
                .ok_or_else(|| io("slot exhaustion"))?,
        );
        if self.store.lookup(slot).is_some() {
            return Err(io("nonce slot collision"));
        }
        let receipt = self.store.reserve(slot)?;
        self.anchor.commit(&receipt).map_err(io)?;
        let receipt = self.store.bind(slot, context)?;
        self.anchor.commit(&receipt).map_err(io)?;
        Ok(())
    }
}
impl<A: Anchor> two_cohort::mlsag::NonceGuard for DurableNonceGuard<'_, A> {
    fn reserve(
        &mut self,
        binding: two_cohort::mlsag::SessionBinding,
        seat: two_cohort::mlsag::Seat,
    ) -> Result<(), two_cohort::mlsag::NonceAlreadyIssued> {
        self.claim(binding, seat).map_err(|e| {
            self.last_error = Some(e.to_string());
            two_cohort::mlsag::NonceAlreadyIssued
        })
    }
}
