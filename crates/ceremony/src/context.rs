//! The signing context: the complete statement of *what* is being signed and
//! *with whom*, and the identifier derived from it.
//!
//! The identifier is the key of the one-time-value store, so what goes into it
//! is a security decision rather than a serialisation detail. It covers three
//! things, and all three are load-bearing:
//!
//!   the statement          -- the bytes being authorised;
//!   the participating set  -- it fixes each signer's Lagrange weight, so the
//!                             same statement signed by a different subset is a
//!                             different scalar equation;
//!   the FULL round-one package -- every participant's commitments, not just
//!                             our own. In a FROST-shaped scheme the binding
//!                             factor and the challenge are both functions of
//!                             the aggregated commitment, so a coordinator who
//!                             swaps one peer's commitment and replays gets a
//!                             *different* response out of an *unchanged*
//!                             one-time value. Keyed on (statement, subset)
//!                             alone the store cannot see that at all; see
//!                             `tests/one_time_values.rs`, where three such
//!                             replays recover the long-term share outright.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use mc_crypto_hashes::{Blake2b256, Digest};

/// Roster position. Also the x-coordinate of the participant's secret share in
/// any Shamir-based backend, hence never zero.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ParticipantId(pub u16);

/// A one-time value held by the authorisation backend, named so the machine can
/// talk about it without ever seeing it. The machine's whole job on this axis is
/// to make sure a slot is bound to exactly one context, forever.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SlotId(pub u64);

/// Round-one output of one participant, opaque to the machine.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Commitment(pub Vec<u8>);

/// Round-two output of one participant, opaque to the machine.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Share(pub Vec<u8>);

/// The bytes being authorised. Opaque here on purpose: the ceremony must not
/// grow an opinion about transaction structure, because the moment it parses
/// the statement it becomes possible for it to sign something other than what
/// it showed the operators.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Statement(pub Vec<u8>);

/// The participants that are actually signing this ceremony.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Subset(BTreeSet<ParticipantId>);

impl Subset {
    pub fn new(ids: impl IntoIterator<Item = ParticipantId>) -> Self {
        Subset(ids.into_iter().collect())
    }
    pub fn contains(&self, id: ParticipantId) -> bool {
        self.0.contains(&id)
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = ParticipantId> + '_ {
        self.0.iter().copied()
    }
}

/// Every participant's round-one commitment, in roster order.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RoundOnePackage(BTreeMap<ParticipantId, Commitment>);

impl RoundOnePackage {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, id: ParticipantId, c: Commitment) -> Option<Commitment> {
        self.0.insert(id, c)
    }
    pub fn get(&self, id: ParticipantId) -> Option<&Commitment> {
        self.0.get(&id)
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = (ParticipantId, &Commitment)> {
        self.0.iter().map(|(k, v)| (*k, v))
    }
}

/// The complete signing context. Constructed only once every subset member's
/// round-one message has been received and identity-checked.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SigningContext {
    statement: Statement,
    subset: Subset,
    package: RoundOnePackage,
}

impl SigningContext {
    pub fn new(statement: Statement, subset: Subset, package: RoundOnePackage) -> Self {
        SigningContext {
            statement,
            subset,
            package,
        }
    }
    pub fn statement(&self) -> &Statement {
        &self.statement
    }
    pub fn subset(&self) -> &Subset {
        &self.subset
    }
    pub fn package(&self) -> &RoundOnePackage {
        &self.package
    }

    /// Canonical encoding. Every variable-length field carries a tag and an
    /// explicit length, so no two distinct contexts can encode to the same
    /// bytes by shifting a field boundary -- an id keyed on an ambiguous
    /// encoding would collide exactly where the store must not collide.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(CONTEXT_DOMAIN);
        field(&mut out, TAG_STATEMENT, &self.statement.0);

        let mut subset_bytes = Vec::new();
        for id in self.subset.iter() {
            subset_bytes.extend_from_slice(&id.0.to_le_bytes());
        }
        field(&mut out, TAG_SUBSET, &subset_bytes);

        out.push(TAG_PACKAGE);
        out.extend_from_slice(&(self.package.len() as u64).to_le_bytes());
        for (id, c) in self.package.iter() {
            out.extend_from_slice(&id.0.to_le_bytes());
            out.extend_from_slice(&(c.0.len() as u64).to_le_bytes());
            out.extend_from_slice(&c.0);
        }
        out
    }

    pub fn id(&self) -> ContextId {
        let mut h = Blake2b256::new();
        h.update(self.encode());
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        ContextId(out)
    }
}

const CONTEXT_DOMAIN: &[u8] = b"bridge/ceremony/context/v1";
const TAG_STATEMENT: u8 = 1;
const TAG_SUBSET: u8 = 2;
const TAG_PACKAGE: u8 = 3;

fn field(out: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
    out.push(tag);
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Hash of the full signing context. This is the store key and it is also what
/// the round-two identity signature covers, so a signed share is attributable to
/// one context and one only.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextId(pub [u8; 32]);

impl fmt::Debug for ContextId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContextId(")?;
        for b in &self.0[..6] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "..)")
    }
}

impl fmt::Display for ContextId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}
