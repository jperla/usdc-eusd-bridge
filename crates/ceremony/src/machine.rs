//! The ceremony state machine.
//!
//! One instance is one participant's view of one ceremony. It is not a
//! coordinator: every participant runs the same machine, collects the same
//! messages, and verifies the same aggregate, so a dishonest coordinator can
//! withhold or reorder but cannot make an honest node accept a signature it did
//! not check.
//!
//! Transitions are explicit and one-way. A call in the wrong state returns
//! `Error::WrongState` rather than doing something approximately right, and the
//! security failures (`OneTimeValueReuse`, `StoreRolledBack`) drive the machine
//! into `State::Failed`, from which every subsequent call fails. Failing closed
//! matters more here than availability: the alternative to a stuck ceremony is a
//! second signature over a rewound one-time value, and that is a key
//! disclosure, not an outage.

use std::collections::BTreeMap;

use crate::authorizer::{Authorizer, Rejection};
use crate::context::{ParticipantId, Share, SigningContext, SlotId, Statement, Subset};
use crate::identity::{
    IdentityError, IdentityKey, IdentityPublic, SignedRoundOne, SignedRoundTwo,
};
use crate::store::{Anchor, AnchorError, BindingStore, Receipt, StoreError};

/// Who may sign, under which identity keys, and how many of them it takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Roster {
    members: BTreeMap<ParticipantId, IdentityPublic>,
    threshold: u16,
}

impl Roster {
    /// Checked because both degenerate thresholds are reachable from a config
    /// file: zero authorises every subset, and one above the roster authorises
    /// none, which strands the funds rather than protecting them.
    pub fn new(
        members: impl IntoIterator<Item = (ParticipantId, IdentityPublic)>,
        threshold: u16,
    ) -> Result<Self, Error> {
        let members: BTreeMap<ParticipantId, IdentityPublic> = members.into_iter().collect();
        if threshold == 0 {
            return Err(Error::ThresholdZero);
        }
        if threshold as usize > members.len() {
            return Err(Error::ThresholdExceedsRoster {
                threshold,
                roster: members.len(),
            });
        }
        Ok(Roster { members, threshold })
    }
    pub fn threshold(&self) -> u16 {
        self.threshold
    }
    pub fn len(&self) -> usize {
        self.members.len()
    }
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
    pub fn identity(&self, id: ParticipantId) -> Option<&IdentityPublic> {
        self.members.get(&id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Fresh,
    CollectingRoundOne,
    CollectingRoundTwo,
    Complete,
    /// A specific participant was caught; see `Ceremony::evidence`.
    Aborted(ParticipantId),
    /// Terminal and deliberate. See the module docs.
    Failed,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("call is not valid in state {actual:?} (expected {expected})")]
    WrongState { expected: &'static str, actual: State },

    #[error("this signer has failed closed and will not sign again")]
    Terminated,

    #[error("subset of {have} cannot reach threshold {need}")]
    SubThreshold { have: usize, need: u16 },

    #[error("roster threshold must be at least 1")]
    ThresholdZero,

    #[error("roster threshold {threshold} exceeds roster size {roster}")]
    ThresholdExceedsRoster { threshold: u16, roster: usize },

    #[error("participant {0:?} is not on the roster")]
    UnknownParticipant(ParticipantId),

    #[error("participant {0:?} is not in this ceremony's subset")]
    NotInSubset(ParticipantId),

    #[error("this signer {0:?} is not in the subset it was asked to sign with")]
    SelfNotInSubset(ParticipantId),

    #[error("participant {0:?} already sent a message for this round")]
    Duplicate(ParticipantId),

    #[error("round one is incomplete: {have} of {need} participants")]
    IncompleteRoundOne { have: usize, need: usize },

    #[error("round two is incomplete: {have} of {need} participants")]
    IncompleteRoundTwo { have: usize, need: usize },

    #[error("message from {0:?} is for a different statement or subset")]
    ContextMismatch(ParticipantId),

    #[error("message from {0:?} is for a different signing context")]
    WrongContext(ParticipantId),

    #[error(transparent)]
    Identity(#[from] IdentityError),

    /// The store refused to bind a one-time value twice. See
    /// `tests/one_time_values.rs` for what this error is standing in front of.
    #[error("one-time value reuse: {0}")]
    OneTimeValueReuse(StoreError),

    #[error("store: {0}")]
    Store(StoreError),

    #[error("anti-rollback: {0}")]
    Rollback(AnchorError),

    #[error("backend: {0}")]
    Backend(String),

    #[error("participant {culprit:?} produced an invalid share")]
    IdentifiableAbort { culprit: ParticipantId },

    /// The share was neither accepted nor faulted: the backend could not say.
    /// Held separate from `IdentifiableAbort` because the two lead to opposite
    /// places -- one to a disciplinary proceeding, the other to a pager.
    #[error("could not check {participant:?}'s share ({detail}); this is not a finding about {participant:?}")]
    ShareUncheckable {
        participant: ParticipantId,
        detail: String,
    },

    /// Every individual share verified but the aggregate did not. Reported
    /// without a culprit on purpose: naming one here would be a guess.
    #[error("aggregate signature failed to verify though every share was valid")]
    UnattributableAggregateFailure,
}

/// What a third party needs to hold a participant responsible.
///
/// The round-one messages are included so the verifier can rebuild the context
/// id itself rather than trusting the accuser's version of it, and every message
/// in here is identity-signed. An accuser who is itself part of the quorum can
/// produce the accused's *share bytes* at will; it cannot produce these
/// signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbortEvidence {
    pub round_one: Vec<SignedRoundOne>,
    pub accused: SignedRoundTwo,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EvidenceError {
    #[error("evidence references unknown participant {0:?}")]
    UnknownParticipant(ParticipantId),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("round-one messages disagree about statement or subset")]
    InconsistentRoundOne,
    #[error("round-one set does not match the subset")]
    IncompleteRoundOne,
    #[error("accused message names a context the round-one messages do not produce")]
    WrongContext,
    /// The accused share verifies. The accusation is false, and that is a
    /// finding about the accuser.
    #[error("the accused share is valid; the accusation does not stand")]
    ShareIsValid,
    /// The checker could not run the check -- key material it does not have, a
    /// roster it does not recognise. The evidence is neither upheld nor
    /// refuted, and in particular nobody has been convicted of anything.
    #[error("the accused share could not be checked ({0}); this convicts no one")]
    Unverifiable(String),
}

impl AbortEvidence {
    /// Re-derive the context, check every signature, and confirm the accused
    /// share really is invalid. Returns the culprit on success.
    pub fn verify<A: Authorizer>(
        &self,
        roster: &Roster,
        authorizer: &A,
    ) -> Result<ParticipantId, EvidenceError> {
        let first = self
            .round_one
            .first()
            .ok_or(EvidenceError::IncompleteRoundOne)?;
        let statement = first.statement.clone();
        let subset = first.subset.clone();

        let mut package = crate::context::RoundOnePackage::new();
        for m in &self.round_one {
            if m.statement != statement || m.subset != subset {
                return Err(EvidenceError::InconsistentRoundOne);
            }
            let key = roster
                .identity(m.participant)
                .ok_or(EvidenceError::UnknownParticipant(m.participant))?;
            m.verify(key)?;
            package.insert(m.participant, m.commitment.clone());
        }
        if package.len() != subset.len() || subset.iter().any(|id| package.get(id).is_none()) {
            return Err(EvidenceError::IncompleteRoundOne);
        }

        let context = SigningContext::new(statement, subset, package);
        if context.id() != self.accused.context {
            return Err(EvidenceError::WrongContext);
        }

        let key = roster
            .identity(self.accused.participant)
            .ok_or(EvidenceError::UnknownParticipant(self.accused.participant))?;
        self.accused.verify(key)?;

        // A checker that cannot check must say so rather than convict. The
        // accusation is worth exactly as much as the check behind it, and a
        // checker holding the wrong epoch's key material has performed none.
        match authorizer.verify_share(&context, self.accused.participant, &self.accused.share) {
            Ok(()) => Err(EvidenceError::ShareIsValid),
            Err(Rejection::Fault(_)) => Ok(self.accused.participant),
            Err(Rejection::Error(e)) => Err(EvidenceError::Unverifiable(e.to_string())),
        }
    }
}

pub struct Ceremony<S: BindingStore, K: Anchor, A: Authorizer> {
    roster: Roster,
    me: ParticipantId,
    identity: IdentityKey,
    store: S,
    anchor: K,
    authorizer: A,

    state: State,
    statement: Option<Statement>,
    subset: Subset,
    slot: Option<SlotId>,
    round_one: BTreeMap<ParticipantId, SignedRoundOne>,
    context: Option<SigningContext>,
    round_two: BTreeMap<ParticipantId, SignedRoundTwo>,
    evidence: Option<AbortEvidence>,
}

impl<S: BindingStore, K: Anchor, A: Authorizer> Ceremony<S, K, A> {
    pub fn new(
        roster: Roster,
        me: ParticipantId,
        identity: IdentityKey,
        store: S,
        anchor: K,
        authorizer: A,
    ) -> Self {
        Ceremony {
            roster,
            me,
            identity,
            store,
            anchor,
            authorizer,
            state: State::Fresh,
            statement: None,
            subset: Subset::default(),
            slot: None,
            round_one: BTreeMap::new(),
            context: None,
            round_two: BTreeMap::new(),
            evidence: None,
        }
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn context(&self) -> Option<&SigningContext> {
        self.context.as_ref()
    }

    pub fn evidence(&self) -> Option<&AbortEvidence> {
        self.evidence.as_ref()
    }

    /// Enter round one: allocate a one-time value, durably reserve it, and only
    /// then publish the commitment.
    ///
    /// The order is the point. Publishing first and recording afterwards leaves
    /// a window in which a crash loses all knowledge of a one-time value whose
    /// commitment is already in peers' hands, and a peer that holds the
    /// commitment can later present a context for it.
    pub fn begin(
        &mut self,
        statement: Statement,
        subset: Subset,
    ) -> Result<SignedRoundOne, Error> {
        self.guard_live()?;
        self.expect(State::Fresh, "Fresh")?;

        if !subset.contains(self.me) {
            return Err(Error::SelfNotInSubset(self.me));
        }
        for id in subset.iter() {
            if self.roster.identity(id).is_none() {
                return Err(Error::UnknownParticipant(id));
            }
        }
        // Property 4. Checked before the backend is touched, so a sub-threshold
        // ceremony never produces a share at all -- a partial transcript from an
        // abandoned sub-threshold run is itself material an adversary can
        // combine with a later run.
        if subset.len() < self.roster.threshold() as usize {
            return Err(Error::SubThreshold {
                have: subset.len(),
                need: self.roster.threshold(),
            });
        }

        // Anchor first: if the store has been rewound there must be no new
        // one-time value, not even an unpublished one sitting in the backend.
        self.observe_store()?;
        let (slot, commitment) = self
            .authorizer
            .round_one()
            .map_err(|e| Error::Backend(e.to_string()))?;

        let receipt = match self.store.reserve(slot) {
            Ok(r) => r,
            Err(e) => return Err(self.fail(Error::Store(e))),
        };
        self.commit_receipt(&receipt)?;

        let msg = SignedRoundOne::create(
            &self.identity,
            self.me,
            statement.clone(),
            subset.clone(),
            commitment,
        );

        self.statement = Some(statement);
        self.subset = subset;
        self.slot = Some(slot);
        self.round_one.insert(self.me, msg.clone());
        self.state = State::CollectingRoundOne;
        Ok(msg)
    }

    pub fn receive_round_one(&mut self, msg: SignedRoundOne) -> Result<(), Error> {
        self.guard_live()?;
        self.expect(State::CollectingRoundOne, "CollectingRoundOne")?;

        let key = self
            .roster
            .identity(msg.participant)
            .ok_or(Error::UnknownParticipant(msg.participant))?;
        // Identity check first: an unauthenticated message must not be able to
        // reach any state-dependent branch below.
        msg.verify(key)?;

        if !self.subset.contains(msg.participant) {
            return Err(Error::NotInSubset(msg.participant));
        }
        if self.round_one.contains_key(&msg.participant) {
            return Err(Error::Duplicate(msg.participant));
        }
        if Some(&msg.statement) != self.statement.as_ref() || msg.subset != self.subset {
            return Err(Error::ContextMismatch(msg.participant));
        }

        self.round_one.insert(msg.participant, msg);
        Ok(())
    }

    /// Enter round two: freeze the context, durably bind the one-time value to
    /// it, and only then ask the backend for a share.
    pub fn round_two(&mut self) -> Result<SignedRoundTwo, Error> {
        self.guard_live()?;
        self.expect(State::CollectingRoundOne, "CollectingRoundOne")?;

        if self.round_one.len() != self.subset.len() {
            return Err(Error::IncompleteRoundOne {
                have: self.round_one.len(),
                need: self.subset.len(),
            });
        }

        let mut package = crate::context::RoundOnePackage::new();
        for (id, m) in &self.round_one {
            package.insert(*id, m.commitment.clone());
        }
        let context = SigningContext::new(
            self.statement.clone().expect("set in begin"),
            self.subset.clone(),
            package,
        );
        let context_id = context.id();
        let slot = self.slot.expect("set in begin");

        self.observe_store()?;
        let receipt = match self.store.bind(slot, context_id) {
            Ok(r) => r,
            Err(e @ StoreError::AlreadyBound { .. }) => {
                return Err(self.fail(Error::OneTimeValueReuse(e)))
            }
            Err(e) => return Err(self.fail(Error::Store(e))),
        };
        self.commit_receipt(&receipt)?;

        // Everything above this line is durable. Everything below it is
        // observable.
        let share = self
            .authorizer
            .round_two(slot, &context, &receipt)
            .map_err(|e| Error::Backend(e.to_string()))?;

        let msg = SignedRoundTwo::create(&self.identity, self.me, context_id, share);
        self.context = Some(context);
        self.round_two.insert(self.me, msg.clone());
        self.state = State::CollectingRoundTwo;
        Ok(msg)
    }

    /// Accept a peer's share. The share is verified on arrival so that the
    /// participant responsible is known at the moment of failure, while the
    /// signed message that proves it is still in hand.
    pub fn receive_round_two(&mut self, msg: SignedRoundTwo) -> Result<(), Error> {
        self.guard_live()?;
        self.expect(State::CollectingRoundTwo, "CollectingRoundTwo")?;

        let key = self
            .roster
            .identity(msg.participant)
            .ok_or(Error::UnknownParticipant(msg.participant))?;
        msg.verify(key)?;

        if !self.subset.contains(msg.participant) {
            return Err(Error::NotInSubset(msg.participant));
        }
        if self.round_two.contains_key(&msg.participant) {
            return Err(Error::Duplicate(msg.participant));
        }
        let context = self.context.clone().expect("set in round_two");
        if msg.context != context.id() {
            return Err(Error::WrongContext(msg.participant));
        }

        match self.authorizer.verify_share(&context, msg.participant, &msg.share) {
            Ok(()) => {}
            Err(Rejection::Fault(_)) => {
                let culprit = msg.participant;
                self.evidence = Some(AbortEvidence {
                    round_one: self.round_one.values().cloned().collect(),
                    accused: msg,
                });
                self.state = State::Aborted(culprit);
                return Err(Error::IdentifiableAbort { culprit });
            }
            // Unchecked is not accepted -- the share does not go in, so the
            // ceremony cannot finish without it. But the state is left alone:
            // the backend may come back, and the sender has done nothing.
            Err(Rejection::Error(e)) => {
                return Err(Error::ShareUncheckable {
                    participant: msg.participant,
                    detail: e.to_string(),
                })
            }
        }

        self.round_two.insert(msg.participant, msg);
        Ok(())
    }

    /// Aggregate and verify. A participant that reaches `Complete` has checked
    /// the signature itself.
    pub fn finish(&mut self) -> Result<A::Signature, Error> {
        self.guard_live()?;
        self.expect(State::CollectingRoundTwo, "CollectingRoundTwo")?;

        if self.round_two.len() != self.subset.len() {
            return Err(Error::IncompleteRoundTwo {
                have: self.round_two.len(),
                need: self.subset.len(),
            });
        }

        let context = self.context.clone().expect("set in round_two");
        let shares: Vec<(ParticipantId, Share)> = self
            .round_two
            .iter()
            .map(|(id, m)| (*id, m.share.clone()))
            .collect();

        let signature = self
            .authorizer
            .aggregate(&context, &shares)
            .map_err(|e| Error::Backend(e.to_string()))?;

        if self
            .authorizer
            .verify_signature(&context, &signature)
            .is_err()
        {
            // Shares were checked individually on arrival, so this is not a
            // known-culprit case. Say so instead of blaming someone.
            for (id, share) in &shares {
                match self.authorizer.verify_share(&context, *id, share) {
                    Ok(()) => {}
                    Err(Rejection::Fault(_)) => {
                        let culprit = *id;
                        self.evidence = Some(AbortEvidence {
                            round_one: self.round_one.values().cloned().collect(),
                            accused: self.round_two[&culprit].clone(),
                        });
                        self.state = State::Aborted(culprit);
                        return Err(Error::IdentifiableAbort { culprit });
                    }
                    // Nothing was emitted and nobody is accused; a retry once
                    // the backend answers again can still attribute this.
                    Err(Rejection::Error(e)) => {
                        return Err(Error::ShareUncheckable {
                            participant: *id,
                            detail: e.to_string(),
                        })
                    }
                }
            }
            self.state = State::Failed;
            return Err(Error::UnattributableAggregateFailure);
        }

        self.state = State::Complete;
        Ok(signature)
    }

    // ------------------------------------------------------------- internals

    fn expect(&self, want: State, label: &'static str) -> Result<(), Error> {
        if self.state == want {
            Ok(())
        } else {
            Err(Error::WrongState {
                expected: label,
                actual: self.state.clone(),
            })
        }
    }

    fn guard_live(&mut self) -> Result<(), Error> {
        if self.state == State::Failed || self.anchor.is_poisoned() {
            self.state = State::Failed;
            return Err(Error::Terminated);
        }
        Ok(())
    }

    /// Check the store has not gone backwards before writing to it. Before a
    /// write there is no record to compare, so this can only compare counts --
    /// which is why it is not the whole of the defence; see `commit_receipt`.
    fn observe_store(&mut self) -> Result<(), Error> {
        let seq = self.store.sequence();
        match self.anchor.observe(seq) {
            Ok(()) => Ok(()),
            Err(e) => Err(self.fail(Error::Rollback(e))),
        }
    }

    /// Advance the anchor onto the record that was just written, by
    /// compare-and-swap against the record it already holds. This is what
    /// catches a store whose counter is level but whose history is not, and it
    /// sits between the durable write and the observable step it protects.
    fn commit_receipt(&mut self, receipt: &Receipt) -> Result<(), Error> {
        match self.anchor.commit(receipt) {
            Ok(()) => Ok(()),
            Err(e) => Err(self.fail(Error::Rollback(e))),
        }
    }

    fn fail(&mut self, e: Error) -> Error {
        self.state = State::Failed;
        e
    }
}
