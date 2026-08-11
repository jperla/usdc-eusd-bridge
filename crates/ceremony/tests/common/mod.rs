//! Shared fixture: a roster with real Ed25519 identity keys and a real
//! trusted-dealer FROST sharing, plus the plumbing to run a ceremony between
//! several in-process nodes.
//!
//! Everything here is deterministic (seeded ChaCha20) so a failure is
//! reproducible.

#![allow(dead_code)] // each test file uses a different subset of this

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use curve25519_dalek::scalar::Scalar;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use ceremony::frost::{deal, FrostSignature, FrostSigner, GroupKey};
use ceremony::machine::{Ceremony, Roster};
use ceremony::{
    Error, IdentityKey, MemoryAnchor, MemoryStore, ParticipantId, SignedRoundOne, SignedRoundTwo,
    Statement, Subset,
};

pub type Store = Rc<RefCell<MemoryStore>>;
pub type AnchorHandle = Rc<RefCell<MemoryAnchor>>;
pub type Signer = FrostSigner<ChaCha20Rng>;
pub type Machine = Ceremony<Store, AnchorHandle, Signer>;

/// Identity seeds are derived from the participant id so a test can rebuild a
/// participant's key to impersonate it (and fail).
pub fn identity_seed(id: ParticipantId) -> [u8; 32] {
    let mut seed = [0x5au8; 32];
    seed[0] = id.0 as u8;
    seed[1] = (id.0 >> 8) as u8;
    seed
}

pub fn identity(id: ParticipantId) -> IdentityKey {
    IdentityKey::from_seed(&identity_seed(id))
}

pub struct Fixture {
    pub roster: Roster,
    pub group: GroupKey,
    pub shares: BTreeMap<ParticipantId, Scalar>,
    pub ids: Vec<ParticipantId>,
}

pub fn fixture(threshold: u16, n: u16) -> Fixture {
    let ids: Vec<ParticipantId> = (1..=n).map(ParticipantId).collect();
    let mut rng = ChaCha20Rng::seed_from_u64(0xB1D6E_u64 ^ ((threshold as u64) << 16) ^ n as u64);
    let (group, shares) = deal(threshold, &ids, &mut rng);
    let roster = Roster::new(
        ids.iter().map(|id| (*id, identity(*id).public())),
        threshold,
    );
    Fixture {
        roster,
        group,
        shares,
        ids,
    }
}

impl Fixture {
    pub fn signer(&self, id: ParticipantId) -> Signer {
        FrostSigner::new(
            id,
            self.shares[&id],
            self.group.clone(),
            ChaCha20Rng::seed_from_u64(1_000 + id.0 as u64),
        )
    }

    /// A backend that holds public key material only. Used where a *verifier*
    /// is needed -- checking abort evidence, say -- to make clear that
    /// verification needs no secret.
    pub fn public_verifier(&self) -> Signer {
        FrostSigner::new(
            ParticipantId(0),
            Scalar::ZERO,
            self.group.clone(),
            ChaCha20Rng::seed_from_u64(0),
        )
    }

    pub fn node(&self, id: ParticipantId) -> Node {
        let store: Store = Rc::new(RefCell::new(MemoryStore::new()));
        let anchor: AnchorHandle = Rc::new(RefCell::new(MemoryAnchor::new()));
        Node {
            id,
            store: store.clone(),
            anchor: anchor.clone(),
            machine: Ceremony::new(
                self.roster.clone(),
                id,
                identity(id),
                store,
                anchor,
                self.signer(id),
            ),
        }
    }
}

pub struct Node {
    pub id: ParticipantId,
    pub store: Store,
    pub anchor: AnchorHandle,
    pub machine: Machine,
}

/// Drive every node through round one and hand each of them every message.
pub fn round_one(
    nodes: &mut [Node],
    statement: &Statement,
    subset: &Subset,
) -> Result<Vec<SignedRoundOne>, Error> {
    let mut msgs = Vec::new();
    for n in nodes.iter_mut() {
        msgs.push(n.machine.begin(statement.clone(), subset.clone())?);
    }
    for n in nodes.iter_mut() {
        for m in &msgs {
            if m.participant != n.id {
                n.machine.receive_round_one(m.clone())?;
            }
        }
    }
    Ok(msgs)
}

pub fn round_two(nodes: &mut [Node]) -> Result<Vec<SignedRoundTwo>, Error> {
    let mut msgs = Vec::new();
    for n in nodes.iter_mut() {
        msgs.push(n.machine.round_two()?);
    }
    for n in nodes.iter_mut() {
        for m in &msgs {
            if m.participant != n.id {
                n.machine.receive_round_two(m.clone())?;
            }
        }
    }
    Ok(msgs)
}

/// Full honest run. Returns each node's own aggregated signature.
pub fn run(
    nodes: &mut [Node],
    statement: &Statement,
    subset: &Subset,
) -> Result<Vec<FrostSignature>, Error> {
    round_one(nodes, statement, subset)?;
    round_two(nodes)?;
    nodes.iter_mut().map(|n| n.machine.finish()).collect()
}

pub fn statement(bytes: &[u8]) -> Statement {
    Statement(bytes.to_vec())
}
