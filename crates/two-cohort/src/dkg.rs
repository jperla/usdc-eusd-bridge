//! Per-cohort distributed key generation: no dealer, and a share a
//! participant can check.
//!
//! This module replaces [`Cohort::deal`](crate::Cohort::deal) on the path that
//! matters. `deal` puts one process in possession of every share of a cohort
//! secret; whoever runs it can spend on that cohort's behalf forever, and no
//! later protocol recovers from that. Here each participant generates its own
//! polynomial, publishes commitments to it, and receives from every other
//! participant a share it can check against those commitments before it accepts
//! anything.
//!
//! # What is used, and what is not written here
//!
//! The protocol is Serai's [`dkg_pedpop`], vendored at `vendor/serai` rev
//! `4b89cf02`. A DKG is not the place to be original: PedPoP is the Pedersen
//! DKG with the proof-of-knowledge fix from the FROST paper, and this module is
//! a wrapper that
//!
//!   * pins its transcript context to a [`CeremonyId`], so the MESSAGES of a
//!     cohort's key generation -- the proof of knowledge inside the round-one
//!     commitments, and the share encryption -- are bound to the composition
//!     they were produced for and do not verify under another one. Note the
//!     scope: PedPoP's context binds the protocol transcript, not the key that
//!     comes out of it. Neither `ThresholdKeys` nor [`CohortKey`] carries the
//!     ceremony id, so a FINISHED cohort key is not itself stamped with the
//!     composition it was generated for, and uniqueness of one context per run
//!     is an operational rule this API does not enforce;
//!   * carries the crate's [`ControlDomain`] rules through it, so an owner
//!     roster cannot be dealt as a gate cohort and an id outside a domain's
//!     band is rejected before any key exists;
//!   * translates PedPoP's participant indices back into the crate's
//!     operational ids, so that every error names the operator an human has to
//!     go and talk to rather than an index into a `HashMap`;
//!   * produces [`CohortKey`] and [`CohortShare`], which are the types the rest
//!     of the crate accepts as PRODUCTION key material -- and which have no
//!     constructor that takes a dealt [`Cohort`](crate::Cohort).
//!
//! # Why participant ids are not the Shamir evaluation points
//!
//! PedPoP's `Participant` is a non-zero `u16` and its polynomial is evaluated
//! at `1..=n`. A [`Gates`](crate::Gates) id is `1_000_001` and up, so the two
//! cannot be the same number. The roster order fixes the mapping: the `k`-th id
//! of a [`CohortSpec`] is DKG participant `k+1`. [`Cohort`](crate::Cohort)
//! therefore carries the evaluation points separately from the ids, and
//! everything a human sees -- errors, [`SpendRole`](crate::mlsag::SpendRole),
//! quorum arguments -- is still in ids.
//!
//! Because the mapping is positional, every participant must agree on the
//! roster ORDER or they are not running the same protocol. [`Roster::new`]
//! therefore requires the ids to be strictly ascending, which makes the
//! ordering canonical rather than a convention.
//!
//! # What this module does NOT establish
//!
//! * **It does not make a cohort's independence auditable.** A trusted dealer
//!   that generates every share and then deletes the secret produces public
//!   data indistinguishable from an honest DKG's -- same commitments shape,
//!   same verification shares, and it can answer every proof of possession
//!   because it knows every share. Within this crate a [`CohortKey`] cannot be
//!   built from a [`Cohort`](crate::Cohort), which is a statement about this
//!   code. It is not a statement a third party can check from published bytes.
//!   See [`ceremony`](crate::ceremony)'s limits.
//! * **It assumes an authenticated broadcast channel.** PedPoP says so
//!   explicitly, and nothing here supplies one. A participant that sends two
//!   different commitment messages to two different peers is faulty, and this
//!   module cannot see it: the messages are values handed to it by a caller.
//! * **Blame is reported, not adjudicated.** PedPoP's `BlameMachine` can decide
//!   whether a rejected share is the sender's fault or the accuser's. This
//!   wrapper reports the accusation with the dealer named and aborts;
//!   adjudicating it needs the blame proof carried over the same authenticated
//!   channel, which is a deployment concern.

use core::{fmt, marker::PhantomData};
use std::{
    collections::HashMap,
    sync::{Mutex, PoisonError},
};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use dalek_ff_group::Ristretto;
use dkg_pedpop::{
    BlameMachine, Commitments, EncryptedMessage, EncryptionKeyMessage, KeyGenMachine, KeyMachine,
    Participant, PedPoPError, SecretShare, SecretShareMachine, ThresholdParams,
};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error as ThisError;
use zeroize::Zeroizing;

use crate::{
    ceremony::{
        CeremonyError, CeremonyId, ComponentClaim, Pop, SealedComposition, MAX_AUDITED_ROSTER,
    },
    cohort::{Cohort, ParticipantTerm},
    composite::CohortSpec,
    control::{ControlDomain, NAMESPACE_SPAN},
};

/// PedPoP's `EncryptionKeyMessage<Ristretto, Commitments<Ristretto>>`.
type PedPoPCommitments = EncryptionKeyMessage<Ristretto, Commitments<Ristretto>>;
/// PedPoP's encrypted secret share.
type PedPoPShare = EncryptedMessage<Ristretto, SecretShare<dalek_ff_group::Scalar>>;

/// Everything key generation can refuse.
///
/// Every variant names the cohort, because the two cohorts run separate DKGs
/// and an operator reading a rejection has to know which ceremony to restart.
/// The variants that name a `dealer` name the participant whose material is at
/// fault, in that cohort's own ids.
#[derive(Clone, Debug, PartialEq, Eq, ThisError)]
#[non_exhaustive]
pub enum DkgError {
    /// A roster rule this crate already had: empty, duplicated, id 0,
    /// threshold above the roster, id outside the domain's band.
    #[error("cohort `{cohort}`: {source}")]
    Roster {
        cohort: &'static str,
        source: crate::Error,
    },

    /// The mapping from roster position to PedPoP participant index is
    /// positional, so a roster all participants do not order identically is a
    /// roster they do not agree on. Requiring ascending ids removes the
    /// question.
    #[error("cohort `{cohort}`: roster {roster:?} is not in strictly ascending order, so participants would not agree on which index is whose")]
    RosterNotCanonical {
        cohort: &'static str,
        roster: Vec<u64>,
    },

    /// A roster larger than [`MAX_AUDITED_ROSTER`].
    ///
    /// The cap is the AUDIT's, not PedPoP's -- PedPoP would index up to
    /// `u16::MAX` participants. It is enforced here, before any key exists,
    /// because a cohort whose artifact cannot be audited is a cohort whose
    /// address must not be funded, and finding that out after key generation is
    /// finding it out too late.
    #[error("cohort `{cohort}`: roster of {n} exceeds the {max} participants an auditable cohort may have")]
    RosterTooLarge {
        cohort: &'static str,
        n: usize,
        max: usize,
    },

    /// The local participant is not on the roster it was handed.
    #[error("cohort `{cohort}`: participant {id} is not on this roster")]
    NotOnRoster { cohort: &'static str, id: u64 },

    /// A round cannot proceed without every participant's message: PedPoP's
    /// commitments and shares are both `n`-of-`n` inputs, whatever the
    /// threshold is. A DKG has no partial completion.
    #[error("cohort `{cohort}`: no round-{round} message from participant {from}")]
    MissingMessage {
        cohort: &'static str,
        round: u8,
        from: u64,
    },

    /// A message from somebody who is not on the roster. Dropped loudly rather
    /// than ignored, because silently ignoring it hides a misrouted ceremony.
    #[error("cohort `{cohort}`: round-{round} message from {from}, who is not on this roster")]
    UnexpectedMessage {
        cohort: &'static str,
        round: u8,
        from: u64,
    },

    /// `dealer`'s VSS commitments do not carry a valid proof of knowledge of
    /// their own constant term. This is PedPoP's WITHIN-cohort rogue-key
    /// defence: without it a participant could choose its polynomial's constant
    /// term as a function of everyone else's and steer the cohort key.
    #[error("cohort `{cohort}`: participant {dealer}'s commitments carry an invalid proof of knowledge")]
    BadCommitments { cohort: &'static str, dealer: u64 },

    /// THE VSS CHECK. `dealer` sent `recipient` a secret share that does not
    /// evaluate its own published commitments at `recipient`'s point.
    ///
    /// This is the failure the brief calls invisible until signing: a dealer
    /// that shares inconsistently produces an address only SOME quorums can
    /// spend, and without this check nothing notices until after the address is
    /// funded. It is refused here, at dealing time, with the dealer named.
    ///
    /// PedPoP reaches this state two ways -- the decrypted value is not a point
    /// on the dealer's committed polynomial, or the message did not
    /// authenticate as the dealer's at all -- and blames the dealer in both.
    /// `blamable` records which: `true` when a blame proof exists, so an
    /// adjudicator can decide sender-versus-accuser; `false` when the message
    /// itself was unauthentic, where there is nothing to adjudicate.
    #[error("cohort `{cohort}`: the secret share participant {dealer} sent participant {recipient} does not satisfy the VSS commitments {dealer} published")]
    InconsistentShare {
        cohort: &'static str,
        dealer: u64,
        recipient: u64,
        blamable: bool,
    },

    /// A share that does not open its own published verification share. The
    /// participant's own final check, after the DKG has otherwise completed.
    #[error("cohort `{cohort}`: participant {id}'s share does not open the verification share published for it")]
    ShareDoesNotOpen { cohort: &'static str, id: u64 },

    /// Anything else PedPoP reports. Kept as a string because the underlying
    /// error is generic over the ciphersuite and not `PartialEq`-comparable
    /// here; the variants above cover everything this crate reacts to.
    #[error("cohort `{cohort}`: distributed key generation failed: {detail}")]
    Protocol {
        cohort: &'static str,
        detail: String,
    },
}

impl DkgError {
    fn roster<C: ControlDomain>(source: crate::Error) -> DkgError {
        DkgError::Roster {
            cohort: C::NAME,
            source,
        }
    }
}

/// One cohort's roster, with the positional mapping to PedPoP indices fixed.
///
/// Cheap to build and carried through every round so that each round's errors
/// can be reported in ids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Roster<C> {
    threshold: usize,
    /// Strictly ascending. Position `k` is PedPoP participant `k + 1`.
    ids: Vec<u64>,
    domain: PhantomData<C>,
}

impl<C: ControlDomain> Roster<C> {
    /// Validate a spec into a roster a DKG can run over.
    pub fn new(spec: &CohortSpec<C>) -> Result<Roster<C>, DkgError> {
        let ids = spec.ids().to_vec();
        let threshold = spec.threshold();

        if ids.is_empty() {
            return Err(DkgError::roster::<C>(crate::Error::EmptyRoster));
        }
        if threshold == 0 {
            return Err(DkgError::roster::<C>(crate::Error::ThresholdZero));
        }
        if threshold > ids.len() {
            return Err(DkgError::roster::<C>(crate::Error::ThresholdExceedsRoster {
                threshold,
                roster: ids.len(),
            }));
        }
        if ids.len() > MAX_AUDITED_ROSTER {
            return Err(DkgError::RosterTooLarge {
                cohort: C::NAME,
                n: ids.len(),
                max: MAX_AUDITED_ROSTER,
            });
        }
        for &id in &ids {
            if !C::owns(id) {
                return Err(DkgError::roster::<C>(crate::Error::IdOutsideDomain {
                    domain: C::NAME,
                    id,
                    base: C::ID_BASE,
                    end: C::ID_BASE + NAMESPACE_SPAN,
                }));
            }
        }
        if ids.windows(2).any(|w| w[0] >= w[1]) {
            return Err(DkgError::RosterNotCanonical {
                cohort: C::NAME,
                roster: ids,
            });
        }

        Ok(Roster {
            threshold,
            ids,
            domain: PhantomData,
        })
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn ids(&self) -> &[u64] {
        &self.ids
    }

    pub fn n(&self) -> usize {
        self.ids.len()
    }

    /// The Shamir evaluation points, which are PedPoP's participant indices.
    fn points(&self) -> Vec<u64> {
        (1..=self.ids.len() as u64).collect()
    }

    fn index_of(&self, id: u64) -> Result<Participant, DkgError> {
        let pos = self
            .ids
            .iter()
            .position(|&i| i == id)
            .ok_or(DkgError::NotOnRoster {
                cohort: C::NAME,
                id,
            })?;
        // +1: PedPoP participants are non-zero, and 0 is the interpolation
        // point in any case.
        Ok(Participant::new(pos as u16 + 1).expect("position + 1 is non-zero"))
    }

    fn id_of(&self, index: Participant) -> u64 {
        let pos = usize::from(u16::from(index)) - 1;
        self.ids[pos]
    }

    fn params(&self, me: u64) -> Result<ThresholdParams, DkgError> {
        ThresholdParams::new(
            self.threshold as u16,
            self.ids.len() as u16,
            self.index_of(me)?,
        )
        .map_err(|e| DkgError::Protocol {
            cohort: C::NAME,
            detail: e.to_string(),
        })
    }

    /// Re-key a map of wire messages from ids to PedPoP indices, dropping the
    /// local participant's own entry (PedPoP's rounds take everyone else's).
    fn by_index<T: Clone>(
        &self,
        round: u8,
        me: u64,
        msgs: &HashMap<u64, T>,
    ) -> Result<HashMap<Participant, T>, DkgError> {
        for &from in msgs.keys() {
            if !self.ids.contains(&from) {
                return Err(DkgError::UnexpectedMessage {
                    cohort: C::NAME,
                    round,
                    from,
                });
            }
        }
        let mut out = HashMap::with_capacity(self.ids.len());
        for &id in &self.ids {
            if id == me {
                continue;
            }
            let msg = msgs.get(&id).ok_or(DkgError::MissingMessage {
                cohort: C::NAME,
                round,
                from: id,
            })?;
            out.insert(self.index_of(id)?, msg.clone());
        }
        Ok(out)
    }

    fn map_pedpop(&self, e: PedPoPError<Ristretto>, recipient: u64) -> DkgError {
        match e {
            PedPoPError::InvalidCommitments(l) => DkgError::BadCommitments {
                cohort: C::NAME,
                dealer: self.id_of(l),
            },
            PedPoPError::InvalidShare { participant, blame } => DkgError::InconsistentShare {
                cohort: C::NAME,
                dealer: self.id_of(participant),
                recipient,
                blamable: blame.is_some(),
            },
            // `by_index` has already required a message from every roster
            // member before any of this reaches PedPoP, so PedPoP reporting one
            // missing means the two disagree about the roster -- which is a
            // protocol fault, not a message a caller can go and fetch. Reported
            // as such rather than dressed up with a round number this wrapper
            // would have to invent.
            PedPoPError::MissingParticipant(l) => DkgError::Protocol {
                cohort: C::NAME,
                detail: format!("participant {} missing inside PedPoP", self.id_of(l)),
            },
            // `PedPoPError` is generic over the ciphersuite and only `Debug`,
            // so the detail is its debug form. Every variant this crate reacts
            // to is matched above; this arm is the ones it cannot act on.
            other => DkgError::Protocol {
                cohort: C::NAME,
                detail: format!("{other:?}"),
            },
        }
    }
}

/// Round-one wire message: one participant's VSS commitments, its proof of
/// knowledge of their constant term, and its encryption key.
///
/// Opaque: a caller routes it, it does not read it. Broadcast to every other
/// participant over an authenticated channel; a participant that broadcasts two
/// different ones is faulty and this crate cannot detect that.
#[derive(Clone)]
pub struct CommitmentMessage(PedPoPCommitments);

impl fmt::Debug for CommitmentMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommitmentMessage").finish_non_exhaustive()
    }
}

/// Round-two wire message: one participant's secret share for one other
/// participant, encrypted to that participant's round-one key.
///
/// Redacted `Debug` for the obvious reason.
#[derive(Clone)]
pub struct ShareMessage(PedPoPShare);

impl fmt::Debug for ShareMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareMessage").finish_non_exhaustive()
    }
}

/// A participant that has published its commitments and is waiting for
/// everyone else's.
pub struct Committing<C: ControlDomain> {
    roster: Roster<C>,
    me: u64,
    machine: SecretShareMachine<Ristretto>,
}

impl<C: ControlDomain> fmt::Debug for Committing<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Committing")
            .field("cohort", &C::NAME)
            .field("me", &self.me)
            .finish_non_exhaustive()
    }
}

impl<C: ControlDomain> Committing<C> {
    /// Begin key generation as participant `me`.
    ///
    /// The PedPoP transcript context is derived from `ceremony` and the cohort
    /// name, so this run's commitments do not verify under a DIFFERENT
    /// [`CeremonyId`] or in the other cohort.
    ///
    /// Not stronger than that. The context is exactly `(CeremonyId, cohort)`,
    /// and nothing enforces that a `CeremonyId` is used for one run -- see this
    /// module's opening note. Two runs of this cohort under the same id share a
    /// context, so "cannot be induced to reuse this run's commitments in a
    /// different composition", which an earlier version of this comment claimed,
    /// is false for the same-id case. The rule that binds a HOLDER to one
    /// composition is [`prove_possession`](crate::ceremony::prove_possession)'s,
    /// enforced per share.
    pub fn begin<R: RngCore + CryptoRng>(
        ceremony: &CeremonyId,
        spec: &CohortSpec<C>,
        me: u64,
        rng: &mut R,
    ) -> Result<(Committing<C>, CommitmentMessage), DkgError> {
        let roster = Roster::new(spec)?;
        let params = roster.params(me)?;
        let (machine, msg) =
            KeyGenMachine::<Ristretto>::new(params, ceremony.dkg_context(C::NAME))
                .generate_coefficients(rng);
        Ok((
            Committing {
                roster,
                me,
                machine,
            },
            CommitmentMessage(msg),
        ))
    }

    pub fn roster(&self) -> &Roster<C> {
        &self.roster
    }

    pub fn me(&self) -> u64 {
        self.me
    }

    /// Verify every other participant's proof of knowledge, then produce this
    /// participant's secret share for each of them.
    ///
    /// Returned keyed by RECIPIENT id: each message goes to exactly one peer,
    /// over an authenticated channel, and broadcasting one is handing that
    /// peer's share to everybody.
    pub fn deal<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        commitments: &HashMap<u64, CommitmentMessage>,
    ) -> Result<(Dealing<C>, HashMap<u64, ShareMessage>), DkgError> {
        let by_index = self.roster.by_index(1, self.me, commitments)?;
        let (machine, shares) = self
            .machine
            .generate_secret_shares(
                rng,
                by_index
                    .into_iter()
                    .map(|(i, m)| (i, m.0))
                    .collect::<HashMap<_, _>>(),
            )
            .map_err(|e| self.roster.map_pedpop(e, self.me))?;

        let shares = shares
            .into_iter()
            .map(|(i, s)| (self.roster.id_of(i), ShareMessage(s)))
            .collect();

        Ok((
            Dealing {
                roster: self.roster,
                me: self.me,
                machine,
            },
            shares,
        ))
    }
}

/// A participant that has dealt its shares and is waiting for everyone else's.
pub struct Dealing<C: ControlDomain> {
    roster: Roster<C>,
    me: u64,
    machine: KeyMachine<Ristretto>,
}

impl<C: ControlDomain> fmt::Debug for Dealing<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dealing")
            .field("cohort", &C::NAME)
            .field("me", &self.me)
            .finish_non_exhaustive()
    }
}

impl<C: ControlDomain> Dealing<C> {
    /// Check every received share against the dealer's published commitments.
    ///
    /// A share that does not satisfy its dealer's commitments is
    /// [`DkgError::InconsistentShare`] with that dealer named. Nothing is
    /// accepted on trust: the check is `share_i * G == sum_k i^k * A_{dealer,k}`
    /// against the commitments broadcast in round one, which is precisely the
    /// property a Shamir dealing has no way to state.
    ///
    /// This does NOT produce a [`CohortShare`]. It produces a [`Confirming`],
    /// which is PedPoP's blame machine and has to be
    /// [`confirm`](Confirming::confirm)ed -- see there for why the wrapper does
    /// not do that for the caller.
    pub fn finish<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        shares: &HashMap<u64, ShareMessage>,
    ) -> Result<Confirming<C>, DkgError> {
        let by_index = self.roster.by_index(2, self.me, shares)?;
        let machine = self
            .machine
            .calculate_share(
                rng,
                by_index
                    .into_iter()
                    .map(|(i, m)| (i, m.0))
                    .collect::<HashMap<_, _>>(),
            )
            .map_err(|e| self.roster.map_pedpop(e, self.me))?;
        Ok(Confirming {
            roster: self.roster,
            me: self.me,
            machine,
        })
    }
}

/// A participant whose shares all checked out, waiting to be told that everyone
/// else's did too.
///
/// # Why this state exists rather than being collapsed into [`Dealing::finish`]
///
/// PedPoP's `BlameMachine::complete` is documented as
/// *"should only be called after having confirmed, with all participants,
/// successful completion"*, and says of itself that it is *"solely intended to
/// force users to acknowledge they're completing the protocol, not processing
/// any blame"* (`vendor/serai/crypto/dkg/pedpop/src/lib.rs`). A wrapper that
/// calls `complete()` for the caller swallows exactly the acknowledgement the
/// upstream API exists to extract, and discards the blame machine before any
/// accusation could be adjudicated against it.
///
/// So the acknowledgement is a call the operator makes:
/// [`Confirming::confirm`]. Reaching it means every share this participant
/// received satisfied its dealer's commitments -- that much IS checked. It does
/// not mean the other participants said the same about theirs, and PedPoP is
/// explicit that agreeing they did is a consensus problem it does not solve and
/// this crate does not either.
pub struct Confirming<C: ControlDomain> {
    roster: Roster<C>,
    me: u64,
    machine: BlameMachine<Ristretto>,
}

impl<C: ControlDomain> fmt::Debug for Confirming<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Confirming")
            .field("cohort", &C::NAME)
            .field("me", &self.me)
            .finish_non_exhaustive()
    }
}

impl<C: ControlDomain> Confirming<C> {
    pub fn roster(&self) -> &Roster<C> {
        &self.roster
    }

    pub fn me(&self) -> u64 {
        self.me
    }

    /// **Acknowledge that every participant has reported successful
    /// completion**, and take the key material.
    ///
    /// The precondition is the caller's, and it is not rhetorical: this
    /// consumes PedPoP's blame machine, after which an accusation that a dealer
    /// sent an invalid share can no longer be adjudicated against it. Call it
    /// when the out-of-band confirmation round has actually happened.
    ///
    /// What the composition ceremony adds is a LATER, independent catch, not a
    /// substitute for this one: a participant that ended up with a share of a
    /// different key than its peers cannot produce a proof of possession that
    /// verifies against the revealed component, so the disagreement surfaces
    /// before funding. That check runs after this call, and it names the
    /// symptom rather than the faulty dealer.
    pub fn confirm(self) -> Result<CohortShare<C>, DkgError> {
        let keys = self.machine.complete();

        let verification: Vec<RistrettoPoint> = self
            .roster
            .ids
            .iter()
            .map(|&id| {
                Ok(keys
                    .original_verification_share(self.roster.index_of(id)?)
                    .0)
            })
            .collect::<Result<_, DkgError>>()?;

        let cohort = Cohort::distributed(
            C::NAME,
            self.roster.threshold,
            &self.roster.ids,
            &self.roster.points(),
            &verification,
        )
        .map_err(DkgError::roster::<C>)?;

        let key = CohortKey {
            cohort,
            component: keys.group_key().0,
            domain: PhantomData,
        };
        let share = CohortShare {
            key,
            id: self.me,
            secret: Zeroizing::new(keys.original_secret_share().0),
            proved_under: Mutex::new(None),
        };
        // The participant's own check, stated as code rather than assumed from
        // the protocol: the scalar it ends up holding opens the point everyone
        // else will use to verify it. If PedPoP's accounting and this wrapper's
        // index mapping ever disagreed, this is where it would show.
        share.verify()?;
        Ok(share)
    }
}

/// One cohort's PUBLIC key material, as produced by a completed DKG.
///
/// There is no constructor taking a [`Cohort`](crate::Cohort), no `new`, and no
/// public field: the only way to obtain one is to run the DKG to completion --
/// [`Dealing::finish`] yields a `Confirming`, and `Confirming::confirm` is what
/// constructs this. That is what makes "production key material" a type rather
/// than a comment.
///
/// It carries no secret. The shares are with the participants that generated
/// them, which is why the [`Cohort`](crate::Cohort) inside it answers
/// [`Error::SharesNotHeld`](crate::Error::SharesNotHeld) to anything that wants
/// a scalar.
pub struct CohortKey<C: ControlDomain> {
    cohort: Cohort,
    component: RistrettoPoint,
    domain: PhantomData<C>,
}

impl<C: ControlDomain> Clone for CohortKey<C> {
    fn clone(&self) -> Self {
        CohortKey {
            cohort: self.cohort.clone(),
            component: self.component,
            domain: PhantomData,
        }
    }
}

impl<C: ControlDomain> fmt::Debug for CohortKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CohortKey")
            .field("cohort", &C::NAME)
            .field("threshold", &self.cohort.threshold())
            .field("roster", &self.cohort.roster())
            .field("component", &self.component.compress())
            .finish()
    }
}

impl<C: ControlDomain> CohortKey<C> {
    /// `B_c`, this cohort's component of the composite spend root.
    pub fn component(&self) -> RistrettoPoint {
        self.component
    }

    pub fn threshold(&self) -> usize {
        self.cohort.threshold()
    }

    pub fn roster(&self) -> &[u64] {
        self.cohort.roster()
    }

    /// `V_i = s_i * G` for each roster member, in roster order.
    pub fn verification_shares(&self) -> Vec<(u64, RistrettoPoint)> {
        self.cohort
            .roster()
            .iter()
            .map(|&id| {
                (
                    id,
                    self.cohort
                        .verification_share(id)
                        .expect("id came from the roster"),
                )
            })
            .collect()
    }

    /// The share-less [`Cohort`](crate::Cohort) view, for the public
    /// interpolation the rest of the crate does.
    pub fn cohort(&self) -> &Cohort {
        &self.cohort
    }
}

/// One participant's private output of the DKG.
///
/// Holds exactly one scalar: this participant's own share. It is what a
/// production signer is built from, and there is no path from it to any other
/// participant's share.
///
/// Nor to the cohort secret -- **except at threshold 1**, where the sole share
/// IS the component secret and no path is needed. The decided gate cohort is
/// `1-of-1`, so this is the production case and not a corner: the gate
/// organisation's single holder holds `b_gate` outright, by construction, and
/// the security argument never claimed otherwise.
pub struct CohortShare<C: ControlDomain> {
    key: CohortKey<C>,
    id: u64,
    secret: Zeroizing<Scalar>,
    /// The one [`SealedComposition`] this share has answered a
    /// proof-of-possession challenge under, if any.
    ///
    /// Interior mutability rather than `&mut self` on the proving methods
    /// because the state belongs to the KEY, not to the borrow: a share that has
    /// answered one composition has answered it whoever is holding the
    /// reference. A `Mutex` rather than a `Cell` because the compare and the set
    /// have to be one step -- a coordinator that asks two ways at once is
    /// precisely the caller the rule is refusing, and a racing read-then-write
    /// would let both requests through while leaving the type `!Sync` into the
    /// bargain.
    ///
    /// See [`prove_possession`](crate::ceremony::prove_possession) for what this
    /// rule reaches and, more importantly, what it does not.
    proved_under: Mutex<Option<SealedComposition>>,
}

impl<C: ControlDomain> fmt::Debug for CohortShare<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CohortShare")
            .field("cohort", &C::NAME)
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl<C: ControlDomain> CohortShare<C> {
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The cohort's public material, as this participant computed it.
    ///
    /// Two participants that disagree here did not run the same DKG. Nothing
    /// in this module compares them -- that comparison is the composition
    /// ceremony's, where a disagreeing participant's proof of possession
    /// fails against the revealed component.
    pub fn key(&self) -> &CohortKey<C> {
        &self.key
    }

    /// Check this share against the cohort's public commitments.
    ///
    /// `s_i * G == V_i`. Called automatically when the DKG completes, in
    /// `Confirming::confirm` rather than in [`Dealing::finish`]; public so a
    /// participant that loaded a share from storage can re-check it before
    /// signing, against public data it can fetch from anywhere.
    pub fn verify(&self) -> Result<(), DkgError> {
        let published = self
            .key
            .cohort
            .verification_share(self.id)
            .map_err(DkgError::roster::<C>)?;
        if *self.secret * RISTRETTO_BASEPOINT_POINT != published {
            return Err(DkgError::ShareDoesNotOpen {
                cohort: C::NAME,
                id: self.id,
            });
        }
        Ok(())
    }

    /// This participant's Lagrange-weighted term for `subset`.
    ///
    /// The same value [`Cohort::weighted`](crate::Cohort::weighted) would
    /// produce for a dealt cohort, computed by the only process entitled to
    /// compute it. Feed it to
    /// [`SpendSigner::owner`](crate::mlsag::SpendSigner::owner) or
    /// [`gate`](crate::mlsag::SpendSigner::gate).
    pub fn term(&self, subset: &[u64]) -> Result<ParticipantTerm, DkgError> {
        // Threshold, duplicates and membership, before any weight is computed:
        // a Lagrange weight over a below-threshold subset is a perfectly
        // well-formed scalar that reconstructs nothing, so this must be a
        // refusal and not a smaller answer.
        self.key
            .cohort
            .check_subset(subset)
            .map_err(DkgError::roster::<C>)?;
        if !subset.contains(&self.id) {
            return Err(DkgError::NotOnRoster {
                cohort: C::NAME,
                id: self.id,
            });
        }
        let lambda = self
            .key
            .cohort
            .lagrange_in(self.id, subset)
            .map_err(DkgError::roster::<C>)?;
        Ok(ParticipantTerm::new(self.id, lambda * *self.secret))
    }

    /// **Prove possession of this share.** The entry point a holder should
    /// reach for, and the reason is that it is the CHECKED one.
    ///
    /// It forwards to [`Pop::prove_for`], which refuses a `claim` that is not
    /// the one this share's own key generation produced, refuses a `salt` that
    /// does not open the commitment `sealed` carries for this cohort, and
    /// spends this share's one proof -- see
    /// [`prove_possession`](crate::ceremony::prove_possession) for the ordering
    /// rule that last part enforces and, more importantly, for what it does not
    /// reach.
    ///
    /// It exists here rather than only on [`Pop`] because this is the type a
    /// holder actually has in hand, and the first entry point a holder finds
    /// should be the one with the checks in it. There is deliberately no raw
    /// counterpart on `CohortShare`: the unchecked prover signs whatever claim
    /// it is handed, and nothing in this crate hands a holder its raw scalar to
    /// feed one.
    ///
    /// What this is NOT: a capability boundary. A holder that means to misuse
    /// its own secret can recover it -- `CohortShare::term` returns
    /// `lambda_i * s_i` and `lambda_i` is public arithmetic, which
    /// `composition.rs::a_holder_can_recover_its_own_share_through_public_api`
    /// performs. Nothing can prevent that, because the share is the holder's.
    /// What this changes is which path a holder takes by DEFAULT, which is a
    /// smaller claim and the only one available.
    pub fn prove(
        &self,
        sealed: &SealedComposition,
        claim: &ComponentClaim,
        salt: &[u8; 32],
    ) -> Result<Pop, CeremonyError> {
        Pop::prove_for(sealed, self, claim, salt)
    }

    /// The raw share.
    ///
    /// `pub(crate)` so the composition ceremony can prove possession of it
    /// directly. This narrows the surface; it does NOT make the scalar
    /// unreachable from outside the crate, and nothing here should be read as
    /// saying it does: [`CohortShare::term`] returns `lambda_i * s_i` and
    /// [`ParticipantTerm::weight`] hands that scalar over, while `lambda_i` is
    /// computable by anyone from the public roster. A caller outside this crate
    /// that wants `s_i` divides. See
    /// [`prove_possession`](crate::ceremony::prove_possession) on what follows
    /// from that, and
    /// `composition.rs::a_holder_can_recover_its_own_share_through_public_api`,
    /// which performs it.
    pub(crate) fn secret(&self) -> &Scalar {
        &self.secret
    }

    /// Record that this share is answering `sealed`, refusing a second,
    /// different one.
    ///
    /// `pub(crate)`: the rule belongs to the ceremony, but the STATE belongs to
    /// the key material, so it lives here. Idempotent for the composition
    /// already recorded -- a holder asked twice for the same proof because a
    /// message was lost is not the thing being refused.
    ///
    /// The compare and the set are one critical section, so two concurrent
    /// requests cannot both pass.
    pub(crate) fn note_proved(
        &self,
        sealed: &crate::ceremony::SealedComposition,
    ) -> Result<(), crate::ceremony::CeremonyError> {
        // A poisoned lock cannot carry corrupt state here: the critical section
        // is one comparison and one assignment, neither of which can panic, so
        // poisoning could only come from elsewhere. Refusing on poison would be
        // a liveness hole an attacker could induce, which is the wrong trade for
        // a rule whose whole purpose is to fire exactly once.
        let mut slot = self
            .proved_under
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match *slot {
            Some(prior) if prior != *sealed => {
                Err(crate::ceremony::CeremonyError::ProofAlreadyIssued {
                    cohort: C::NAME,
                    participant: self.id,
                })
            }
            _ => {
                *slot = Some(*sealed);
                Ok(())
            }
        }
    }

    /// The sealed composition this share has answered, if any.
    ///
    /// Exposed so a holder can see its own state, and so the tests that make a
    /// claim about the rule can check it rather than infer it.
    pub fn proved_under(&self) -> Option<crate::ceremony::SealedComposition> {
        *self
            .proved_under
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Run a whole cohort's DKG in this process.
///
/// **This holds every participant in one memory space**, which is the thing the
/// DKG exists to avoid, and it is here for the same reason
/// [`mlsag::sign`](crate::mlsag::sign) is: a single-host simulation and the
/// tests need to drive the rounds without restating them. What it does NOT do
/// is skip any of the PROTOCOL rounds -- every message is produced and consumed
/// exactly as a networked deployment would produce and consume it, every proof
/// of knowledge is verified, and every share is checked against its dealer's
/// commitments. What it does collapse is the out-of-band step
/// [`Confirming::confirm`] exists for: it confirms on every participant's
/// behalf, which one process legitimately can and a deployment cannot. A
/// deployment runs [`Committing::begin`], [`Committing::deal`],
/// [`Dealing::finish`] and [`Confirming::confirm`] once per participant, on
/// that participant's own machine.
///
/// The returned shares are in roster order.
pub fn run_dkg<C: ControlDomain, R: RngCore + CryptoRng>(
    ceremony: &CeremonyId,
    spec: &CohortSpec<C>,
    rng: &mut R,
) -> Result<Vec<CohortShare<C>>, DkgError> {
    let roster = Roster::new(spec)?;

    let mut committing = Vec::with_capacity(roster.n());
    let mut commitments = HashMap::with_capacity(roster.n());
    for &id in roster.ids() {
        let (state, msg) = Committing::<C>::begin(ceremony, spec, id, rng)?;
        committing.push(state);
        commitments.insert(id, msg);
    }

    // `outbox[sender][recipient]`, then transposed: each participant receives
    // one message per OTHER participant, which is the shape `finish` takes.
    let mut dealing = Vec::with_capacity(roster.n());
    let mut outbox: HashMap<u64, HashMap<u64, ShareMessage>> = HashMap::new();
    for state in committing {
        let me = state.me();
        let (next, shares) = state.deal(rng, &commitments)?;
        dealing.push(next);
        outbox.insert(me, shares);
    }

    let mut out = Vec::with_capacity(roster.n());
    for state in dealing {
        let me = state.me;
        let inbox: HashMap<u64, ShareMessage> = outbox
            .iter()
            .filter(|(&sender, _)| sender != me)
            .map(|(&sender, shares)| {
                Ok((
                    sender,
                    shares
                        .get(&me)
                        .ok_or(DkgError::MissingMessage {
                            cohort: C::NAME,
                            round: 2,
                            from: sender,
                        })?
                        .clone(),
                ))
            })
            .collect::<Result<_, DkgError>>()?;
        // Confirmed immediately because this IS the single-host simulation:
        // one process holds every participant, so "every participant reported
        // success" is a fact it can see. A deployment cannot, which is why
        // `Confirming` exists.
        out.push(state.finish(rng, &inbox)?.confirm()?);
    }
    out.sort_by_key(|s| s.id);
    Ok(out)
}
