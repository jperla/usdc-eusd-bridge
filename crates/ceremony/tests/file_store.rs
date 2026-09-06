#![cfg(unix)]
use ceremony::store::{Anchor, FileStore, MemoryAnchor};
use ceremony::{BindingStore, ContextId, SlotId, SlotRecord, StoreError};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "bridge-journal-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
#[test]
fn restart_preserves_binding_and_rejects_a_second_context() {
    let p = Temp::new();
    let mut s = FileStore::create(&p.0).unwrap();
    s.reserve(SlotId(7)).unwrap();
    let receipt = s.bind(SlotId(7), ContextId([3; 32])).unwrap();
    drop(s);
    let mut s = FileStore::open(&p.0).unwrap();
    assert_eq!(s.head(), Some(receipt.head()));
    assert_eq!(s.sequence(), receipt.sequence());
    assert_eq!(
        s.lookup(SlotId(7)),
        Some(SlotRecord::Bound(ContextId([3; 32])))
    );
    assert!(matches!(
        s.bind(SlotId(7), ContextId([4; 32])),
        Err(StoreError::AlreadyBound { .. })
    ));
    s.bind(SlotId(7), ContextId([3; 32])).unwrap();
    s.reserve(SlotId(7)).unwrap();
    drop(s);
    assert_eq!(FileStore::open(&p.0).unwrap().sequence(), 4);
}
#[test]
fn exclusive_writer_lock_and_create_never_overwrites() {
    let p = Temp::new();
    let s = FileStore::create(&p.0).unwrap();
    assert!(FileStore::create(&p.0).is_err());
    assert!(FileStore::open(&p.0).is_err());
    drop(s);
    assert!(FileStore::open(&p.0).is_ok());
}
#[test]
fn every_torn_tail_and_every_single_byte_corruption_fails_closed() {
    let p = Temp::new();
    let mut s = FileStore::create(&p.0).unwrap();
    s.reserve(SlotId(1)).unwrap();
    s.bind(SlotId(1), ContextId([9; 32])).unwrap();
    drop(s);
    let good = fs::read(&p.0).unwrap();
    for end in 98..good.len() {
        fs::write(&p.0, &good[..end]).unwrap();
        assert!(FileStore::open(&p.0).is_err(), "torn at {end}");
    }
    for i in 0..good.len() {
        let mut bad = good.clone();
        bad[i] ^= 1;
        fs::write(&p.0, &bad).unwrap();
        assert!(FileStore::open(&p.0).is_err(), "corruption at {i}");
    }
    fs::write(&p.0, good).unwrap();
    assert!(FileStore::open(&p.0).is_ok());
}
#[test]
fn missing_files_and_symlinks_are_never_treated_as_empty_stores() {
    let p = Temp::new();
    let link = Temp::new();
    assert!(FileStore::open(&p.0).is_err());
    let s = FileStore::create(&p.0).unwrap();
    drop(s);
    std::os::unix::fs::symlink(&p.0, &link.0).unwrap();
    assert!(FileStore::open(&link.0).is_err());
    assert!(FileStore::create(&link.0).is_err());
}
#[test]
fn valid_old_snapshot_requires_an_independent_anchor() {
    let p = Temp::new();
    let mut anchor = MemoryAnchor::default();
    let mut s = FileStore::create(&p.0).unwrap();
    anchor.commit(&s.reserve(SlotId(1)).unwrap()).unwrap();
    let old = fs::read(&p.0).unwrap();
    anchor
        .commit(&s.bind(SlotId(1), ContextId([1; 32])).unwrap())
        .unwrap();
    drop(s);
    fs::write(&p.0, old).unwrap();
    let restored = FileStore::open(&p.0).unwrap();
    assert_ne!(restored.head(), anchor.head());
    assert!(anchor.observe(restored.sequence()).is_err());
}
#[test]
fn child_writer_crash() {
    let Some(path) = std::env::var_os("BRIDGE_JOURNAL_CRASH_TEST") else {
        return;
    };
    let mut s = FileStore::open(path).unwrap();
    s.reserve(SlotId(42)).unwrap();
    s.bind(SlotId(42), ContextId([8; 32])).unwrap();
    // _exit bypasses Rust destructors: the OS must release the writer lock.
    unsafe {
        libc::_exit(23);
    }
}
#[test]
fn committed_bindings_survive_process_exit_without_destructors() {
    let p = Temp::new();
    drop(FileStore::create(&p.0).unwrap());
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_writer_crash"])
        .env("BRIDGE_JOURNAL_CRASH_TEST", &p.0)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(23), "{:?}", result);
    let mut s = FileStore::open(&p.0).unwrap();
    assert!(matches!(
        s.bind(SlotId(42), ContextId([7; 32])),
        Err(StoreError::AlreadyBound { .. })
    ));
    assert_eq!(
        s.lookup(SlotId(42)),
        Some(SlotRecord::Bound(ContextId([8; 32])))
    );
}

#[test]
fn durable_mlsag_guard_refuses_restart_reissue_and_rollback() {
    use ceremony::store::DurableNonceGuard;
    use curve25519_dalek::scalar::Scalar;
    use two_cohort::fixture::make_ring_from_seed;
    use two_cohort::mlsag::{NonceGuard, Seat, SessionParams, SpendRole};
    use two_cohort::{CohortSpec, CompositeSpend, Gates, Owners};
    let spend = CompositeSpend::simulate_from_seed(
        1,
        &CohortSpec::<Owners>::sequential(2, 3),
        &CohortSpec::<Gates>::sequential(1, 1),
        7,
    )
    .unwrap();
    let (ring, _) = make_ring_from_seed(&spend, 3, 1, 100, &Scalar::ONE, 7);
    let output = ring[1].commitment;
    let id = [1; 32];
    let params = SessionParams {
        session_id: &id,
        message: b"test",
        ring: &ring,
        real_index: 1,
        output_commitment: &output,
    };
    let p = Temp::new();
    let mut s = FileStore::create(&p.0).unwrap();
    let old = fs::read(&p.0).unwrap();
    let mut anchor = MemoryAnchor::default();
    let binding = params.binding();
    let seat = Seat::Spend(SpendRole::Owner(1));
    DurableNonceGuard::new(&mut s, &mut anchor)
        .unwrap()
        .reserve(binding, seat)
        .unwrap();
    drop(s);
    let mut s = FileStore::open(&p.0).unwrap();
    let mut guard = DurableNonceGuard::new(&mut s, &mut anchor).unwrap();
    assert!(guard.reserve(binding, seat).is_err());
    assert_eq!(
        guard.last_error(),
        Some("backing store failed: nonce already issued")
    );
    drop(guard);
    // Another seat is independent, after explicitly opening a new guard.
    DurableNonceGuard::new(&mut s, &mut anchor)
        .unwrap()
        .reserve(binding, Seat::Mask)
        .unwrap();
    drop(s);
    fs::write(&p.0, old).unwrap();
    let mut restored = FileStore::open(&p.0).unwrap();
    assert!(DurableNonceGuard::new(&mut restored, &mut anchor).is_err());
}

#[test]
fn an_unexpected_write_poisons_the_live_handle_without_issuing_a_receipt() {
    let p = Temp::new();
    let mut s = FileStore::create(&p.0).unwrap();
    s.reserve(SlotId(1)).unwrap();
    let mut bytes = fs::read(&p.0).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&p.0, bytes).unwrap();
    assert!(s.bind(SlotId(1), ContextId([1; 32])).is_err());
    assert!(s.is_poisoned());
    assert!(s.reserve(SlotId(2)).is_err());
    assert_eq!(s.lookup(SlotId(2)), None);
}
