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
//!   * **binds each round-one contribution to the seat that AUTHORIZED it, and
//!     to the RUN it was authorized for.** Not "produced by", which is what this
//!     line used to say and is more than a signature can carry: what is checked
//!     is that the roster's key for that seat signed those exact bytes. PedPoP
//!     separately proves that SOMEBODY knew the constant term. The two witnesses
//!     are not linked, and the gap between them is the residual named in
//!     [`Contribution`]. PedPoP's proof of knowledge says its
//!     sender knew the secret behind its own commitment; it says nothing about
//!     who the sender is, and the round-one messages arrive as a map whose keys
//!     are an assertion by whoever assembled it. So a [`Contribution`] carries a
//!     signature by that seat's long-term identity key over the ceremony, the
//!     cohort, the ROSTER (threshold, ids, seat keys), the roster id and the
//!     commitment bytes, and [`Committing::deal`] refuses a map whose entry for
//!     id `i` is not attested by the key the [`SeatRoster`] names for seat `i`.
//!     See [`Contribution`] for why a signature is the right primitive here when
//!     it was the wrong one at the seat endorsement, and for the residual it
//!     leaves. **Note where that guard is and is not load-bearing:** it is a
//!     check an honest participant makes about a message a PEER handed it, so at
//!     a cohort of one -- which is
//!     [`GATE_COUNT`](crate::production::GATE_COUNT) -- there is nothing for it
//!     to check and it checks nothing but the caller's own consistency. What
//!     keeps a party without the seat's key out of a cohort of one is
//!     [`Committing::begin`]'s [`DkgError::IdentityNotOwn`] refusal. Review
//!     found the docs crediting the wrong refusal; see
//!     [`Committing::check_attribution`];
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
//! * **The seat attestations do not make the DKG's own transcript auditable
//!   either, and they are not in the artifact.** They are consumed inside the
//!   protocol, by peers, at the moment they matter. A funder auditing a
//!   [`CompositionArtifact`](crate::CompositionArtifact) never sees a
//!   [`Contribution`] and cannot check one. **The set of secrets needed to
//!   produce an artifact that [`audit`](crate::ceremony::audit) accepts is
//!   exactly what it was before this change**: the seat endorsements already
//!   demanded, per cohort, every seat's identity private key AND a share behind
//!   the verification share the claim publishes for it. So the marginal price of
//!   an artifact-level forgery is ZERO, and any sentence saying this "raises the
//!   price" is about the honest path, not the audit. Review found three places
//!   saying otherwise; they are corrected.
//! * **It does not make `n` keys `n` parties.** A party holding all `n` identity
//!   keys of a cohort still runs every participant itself. Two tests perform the
//!   two halves and neither performs both:
//!   `tests/dkg.rs::a_party_that_holds_every_seat_key_still_runs_the_whole_dkg_alone`
//!   stops at a real DKG output and a reconstructed component, and
//!   `tests/seat_identity.rs::the_residual_is_a_party_that_holds_every_seat_key`
//!   is the one that carries it all the way to an accepted
//!   [`audit`](crate::ceremony::audit). An earlier version of this note credited
//!   the first with the second's assertion; the claim was true and the citation
//!   was not.
//! * **What a party running a cohort alone must now hold, stated narrowly.** Not
//!   "every seat's identity key" full stop -- [`run_dkg`]'s caller supplies the
//!   seat roster as well as the keys, so a party with no real seat key at all can
//!   run both decided cohorts under a seat roster of its own invention.
//!   `tests/dkg.rs::a_process_holding_no_real_seat_key_still_runs_a_whole_cohort_under_its_own_roster`
//!   performs that. The true statement is about LABELLING: a party cannot produce
//!   a dealing whose seat roster names seat-holders it does not hold the keys
//!   for -- and what refuses the invented roster afterwards is the seat
//!   endorsement, not anything in this module.
//! * **It assumes an authenticated broadcast channel, and the attestation is
//!   not one.** PedPoP requires an authenticated channel and nothing here
//!   supplies one. What the attestation adds is ORIGIN authentication of each
//!   round-one message, which is a piece of it -- but a participant that sends
//!   two DIFFERENT, correctly attested contributions to two different peers is
//!   faulty and still invisible here, because each peer sees only what it was
//!   handed. Equivocation became attributable, not detectable. Round two's
//!   share messages carry no attestation of this kind at all.
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
        dkg_contribution_payload, dkg_roster_digest, endorse_seat, CeremonyError, CeremonyId,
        ComponentClaim, Pop, SealedComposition, SeatEndorsement, SeatRoster, MAX_AUDITED_ROSTER,
    },
    cohort::{Cohort, ParticipantTerm},
    composite::CohortSpec,
    control::{ControlDomain, NAMESPACE_SPAN},
    identity::{IdentityKey, IdentityPublic, IdentitySignature},
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

    /// The seat roster this DKG was told to run under does not name exactly the
    /// participants it is dealing to.
    ///
    /// Refused before any key exists, for [`DkgError::RosterTooLarge`]'s reason:
    /// a [`CohortKey`] whose seat roster disagreed with its participant roster
    /// could not produce a well-formed [`ComponentClaim`], and finding that out
    /// after key generation is finding it out too late.
    #[error("cohort `{cohort}`: seat roster {seats:?} does not name exactly the participants {roster:?}")]
    SeatRosterMismatch {
        cohort: &'static str,
        roster: Vec<u64>,
        seats: Vec<u64>,
    },

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

    /// **A round-one contribution filed under `dealer` that `dealer`'s seat did
    /// not attest.** THE identity failure of key generation.
    ///
    /// PedPoP's proof of knowledge says whoever produced a contribution knew the
    /// secret behind it. It does not say WHO, and until this error existed
    /// nothing else did either: the map handed to [`Committing::deal`] was keyed
    /// by roster id, and those keys were an assertion by whoever assembled the
    /// map. One party could generate all `n` contributions, label them, and run
    /// the whole DKG alone.
    ///
    /// So a contribution now carries [`Contribution::attestation`], a signature
    /// by the seat's long-term identity key over
    /// [`dkg_contribution_payload`](crate::ceremony::dkg_contribution_payload),
    /// and this is what a map whose entry for `dealer` does not carry one gets.
    /// `key` is the identity the SEAT ROSTER names for that seat -- the key the
    /// signature was checked under, not one the message supplied.
    #[error("cohort `{cohort}`: the round-one contribution filed under participant {dealer} is not attested by {key}, the identity key this cohort's seat roster names for that seat")]
    ContributionNotAttributable {
        cohort: &'static str,
        dealer: u64,
        key: IdentityPublic,
    },

    /// **The map handed to [`Committing::deal`] carries an entry for the local
    /// participant that is not the contribution the local participant made.**
    ///
    /// Distinct from [`DkgError::ContributionNotAttributable`] because the
    /// question is different, and so is the evidence. For a PEER, all this
    /// participant can ask is whether the seat's key signed it. For ITSELF it can
    /// ask something strictly stronger -- is this the contribution `begin`
    /// produced for me? -- and
    /// it answers by comparing bytes, so no signature has to be trusted and no
    /// key has to be consulted.
    ///
    /// **What it is and is not.** It is a tripwire on the CHANNEL: a coordinator
    /// or a relay that rewrote this participant's own round-one message in the
    /// copy it handed back is telling this participant that its peers are
    /// probably seeing something it did not send. That is the only local signal
    /// this crate can offer against equivocation, and it is a weak one -- it
    /// catches the case where the rewrite is reflected back, not the case where
    /// it is only sent onward. See [`Committing::check_attribution`].
    ///
    /// **And it compares against what `begin` PRODUCED, not against what this
    /// participant broadcast**, which review asked to be separated. The two are
    /// the same only if the caller broadcast the value `begin` returned,
    /// unchanged. Nothing here can check that, because the broadcast happens
    /// outside this crate entirely.
    ///
    /// It is also what makes the attribution loop non-vacuous at `n == 1`, where
    /// there are no peers at all -- and it is a consistency check there, NOT a
    /// security property. Read [`Committing::check_attribution`] on that before
    /// treating it as one.
    #[error("cohort `{cohort}`: the round-one map carries an entry for participant {id} that is not the contribution {id} produced")]
    OwnContributionAltered { cohort: &'static str, id: u64 },

    /// A seat roster naming something that is not a usable identity key.
    ///
    /// The DKG-time twin of
    /// [`CeremonyError::SeatKeyNotUsable`](crate::CeremonyError::SeatKeyNotUsable),
    /// and it is here for that error's reason: a value with no secret behind it,
    /// or with a secret everybody has, that the attestation check cannot
    /// distinguish from a real key. Ed25519 has cofactor 8, and
    /// `Ed25519Public::verify` is `verify_strict` -- which refuses a SMALL-ORDER
    /// signer, the identity element included, but accepts `d*B + T`. A party
    /// holding `d` gets eight distinct 32-byte "keys" out of that one secret and
    /// a verifying signature under each after a handful of tries, so a seat
    /// named by one is a seat that party can attest for while the roster reads
    /// as somebody else's. See
    /// [`IdentityPublic::unusable_reason`](crate::identity::IdentityPublic::unusable_reason),
    /// which is the predicate, and `tests/seat_key_torsion.rs`, which performs
    /// the grind against the composition ceremony's twin of this check.
    ///
    /// Refused in [`Committing::begin`], over the WHOLE seat roster and before
    /// any key material exists, for [`DkgError::RosterTooLarge`]'s reason: a
    /// cohort whose seats cannot be attributed is a cohort whose address must
    /// not be funded, and finding that out after key generation is finding it
    /// out too late.
    #[error("cohort `{cohort}`: seat {participant}'s identity key {key} is not a usable identity key -- {reason}")]
    SeatKeyNotUsable {
        cohort: &'static str,
        participant: u64,
        key: IdentityPublic,
        reason: &'static str,
    },

    /// The identity key a participant began key generation with is not the one
    /// the seat roster names for its seat.
    ///
    /// An honest participant that has been handed somebody else's seat roster,
    /// or has been told it holds a seat it does not. Refused rather than
    /// attested, because the attestation it would produce could never verify --
    /// [`Committing::deal`] checks under the ROSTER's key -- so the alternative
    /// is a ceremony that fails at everyone else's `deal` with this
    /// participant's own mistake reported as their problem.
    #[error("cohort `{cohort}`: participant {id} began key generation with identity {found}, but this cohort's seat roster names {expected} for that seat")]
    IdentityNotOwn {
        cohort: &'static str,
        id: u64,
        expected: IdentityPublic,
        found: IdentityPublic,
    },

    /// [`run_dkg`] was given no identity key for one of the participants it is
    /// simulating.
    ///
    /// Only the single-host driver can reach it: a deployment's participant
    /// holds its own key and passes it to [`Committing::begin`] directly.
    #[error("cohort `{cohort}`: no identity key was supplied for participant {id}")]
    IdentityKeyMissing { cohort: &'static str, id: u64 },

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

/// **One participant's round-one material -- VSS commitments, a proof of
/// knowledge of their constant term, an encryption key -- and its seat's
/// attestation AUTHORIZING exactly those bytes.**
///
/// Not "attestation that it produced them", which is what this line said and
/// review corrected twice: a signature says a key was applied to bytes. And not
/// "wire message": there is no codec -- see *Wire shape* below, where both
/// limits are set out.
///
/// # Why the attestation is here and not left to the channel
///
/// PedPoP's proof of knowledge proves the sender knew the secret behind ITS OWN
/// commitment. It does not prove who the sender is, and the round-one messages
/// reach [`Committing::deal`] as a `HashMap<u64, Contribution>` whose keys are
/// an assertion by whoever assembled the map. Without something binding a
/// contribution to a seat, one party generates all `n` contributions, labels
/// them `1..n`, and runs the whole DKG by itself: every proof of knowledge is
/// real, every share is consistent, and the resulting cohort audits.
///
/// So each contribution carries a signature by that seat's long-term identity
/// key over [`dkg_contribution_payload`], and `deal` refuses a map whose entry
/// for id `i` is not attested by the key this cohort's [`SeatRoster`] names for
/// seat `i`.
///
/// # Why a SIGNATURE is enough here, when it was not enough at the seat
/// endorsement
///
/// [`SeatEndorsement`] used to be a signature and had to stop being one, so the
/// choice needs an answer rather than a precedent. In one sentence a
/// non-cryptographer can check: **there, the party was asked to sign a
/// statement about somebody else's published numbers, which cost it nothing to
/// sign and which a dealer holding every share could therefore collect for
/// free; here it signs bytes it generated itself a moment earlier, from its own
/// randomness, inside the same function call.**
///
/// The longer form, and its limit:
///
///   * the endorsement's subject -- "`V_i` is my seat's verification share" --
///     is public data. A party with no share at all could truthfully believe it
///     and sign it, so the signature separated nobody from anybody, which is
///     what `seat_identity.rs::a_dealer_that_keeps_the_shares_is_refused_at_the_seat_endorsement`
///     used to perform as a PASSING forgery. The fix was to link the signature
///     to a second witness the party could only have if it really held the
///     seat: the share;
///   * a round-one contribution has no second witness this crate can reach. The
///     only secret in the room is the polynomial, and the proof of knowledge of
///     its constant term is a finished Schnorr object with its own internal
///     challenge, produced inside the vendored state machine -- the coefficient
///     never leaves it, so there is nothing here to AND-compose with. (The same
///     reason [`crate::identity`] gives for why a signature cannot be half of a
///     linked proof.);
///   * and it is not needed, because the question is narrower. The contribution
///     already proves SOMEBODY knew its constant term; the attestation only has
///     to answer WHO filed it. A party that holds no identity key cannot answer
///     that at all, which is exactly the property being bought;
///   * **but say what "who filed it" means, because the one-sentence version
///     overstates it.** What an accepted attestation establishes is
///     AUTHORIZATION: the roster's key for that seat signed those exact bytes.
///     It does not establish GENERATION -- that the signer knew the polynomial.
///     The verifier holds two unlinked witnesses, PedPoP's proof of knowledge of
///     the constant term and an Ed25519 signature over the message, and nothing
///     ties them to one party. The "inside the same function call" clause above
///     is irrelevant to the authorization reading and load-bearing for the
///     generation reading -- and it is a property of ONE CODE PATH, not of the
///     type, so the generation reading rests on an operational signing policy
///     this crate cannot check: *a seat signs a `dkg_contribution_payload` only
///     for bytes its own trusted implementation produced in that invocation*.
///     Review made this correction and it is the sharpest thing in the review;
///   * **the residual, named rather than argued away, and this paragraph used to
///     get it wrong.** A seat that will sign bytes it did not generate hands its
///     half of the DKG over for nothing. Nothing in a signature can prevent
///     that, and no linked proof is available to raise the price. What this
///     paragraph used to say next was: *"What this crate does is offer no way to
///     do it ... there is no entry point anywhere -- gated or not -- that attests
///     bytes the caller supplies."* **That was false.**
///     [`dkg_contribution_payload`](crate::ceremony::dkg_contribution_payload)
///     is public and [`IdentityKey::sign`](crate::identity::IdentityKey::sign)
///     is public; their composition IS that entry point, it must be, because an
///     independent implementation and a key in an HSM both need it, and it is the
///     route this crate's own rejection tests take. An argument was standing
///     where a check would have been, which is precisely the failure the last
///     round caught in `identity.rs`.
///
///     So it is now performed rather than argued:
///     `tests/dkg.rs::a_seat_key_that_signs_bytes_it_did_not_generate_hands_its_half_over`
///     takes an impostor's commitments, stamps them with the real seat key
///     through the two public functions with no [`Committing`] involved, and
///     watches the ATTRIBUTION LAYER accept them -- `deal` then refuses with
///     `BadCommitments`, PedPoP's, one step later. It cannot watch a full
///     acceptance and says so; see the test for why this crate cannot build
///     that input. **The refusal that does not exist cannot be given a passing
///     test, so the test performs what acceptance it can and is named as an
///     admission** -- the shape
///     `a_dealer_that_dealt_real_shares_and_kept_copies_still_passes` set.
///
///     The consequence for a deployment is the concrete one: a seat operating its
///     key behind an HSM or a signing service will be asked to sign a
///     `dkg_contribution_payload` it did not itself build, because that is the
///     only shape the public API offers. Whether the thing being signed is this
///     seat's own freshly generated contribution is a question only the caller of
///     the HSM can answer, and this crate cannot check it.
///
/// # Wire shape
///
/// Opaque: a caller routes it, it does not read it. Broadcast to every other
/// participant; a participant that broadcasts two DIFFERENT ones is faulty, and
/// this crate still cannot detect that -- the attestation makes equivocation
/// attributable to the equivocator, which is strictly less than detecting it.
/// [`Committing::deal`] does now refuse a map that hands a participant back an
/// altered copy of its OWN broadcast, which is the one local symptom of
/// equivocation this crate can see; see [`DkgError::OwnContributionAltered`] for
/// how small that is.
///
/// **It has no serialisation, and calling it a "wire message" is aspirational.**
/// [`commitment_bytes`](Contribution::commitment_bytes) can be read out, but
/// there is no way to build one from bytes: `commitments` is private,
/// `PedPoPCommitments` is a private alias, and
/// [`with_attestation`](Contribution::with_attestation) needs one to start from.
/// Parsing PedPoP's own public type would not help -- there is no constructor
/// taking it. [`ShareMessage`] has the same shape and the same gap at round two.
/// So a `Contribution` cannot cross a process boundary today, and the only driver
/// in this crate that consumes one is [`run_dkg`] -- the single-host case where,
/// by this module's own admission, the attestation buys nothing. Two reviews
/// raised this and both are right: **the guard is correct, and it is currently
/// unexercisable in the setting where it would help; in `run_dkg` it is an
/// internal consistency check over values and keys one process already holds.**
/// The missing piece is a `read`/`write` pair for both round messages, over
/// PedPoP's own `EncryptionKeyMessage::read`, and it is a deliberate separate
/// change -- parsing untrusted round-one bytes is its own surface and it should
/// not be smuggled in beside a transcript fix.
///
/// The same gap qualifies the HSM story told above and in
/// [`dkg_contribution_payload`]'s docs. An external signer can rebuild the
/// payload and return a signature over it, which is why that function is public
/// -- but [`Committing::begin`] takes a `&IdentityKey` and signs internally, so
/// there is no unsigned-begin path for a key this process does not hold. An HSM
/// deployment is describable, not reachable, with today's API.
///
/// It does NOT carry its own roster id. The map key is the CLAIM being checked,
/// and a message that also carried the id would either be redundant with the key
/// or a second place for the two to disagree.
#[derive(Clone)]
pub struct Contribution {
    commitments: PedPoPCommitments,
    attestation: IdentitySignature,
}

impl Contribution {
    /// The bytes the attestation covers: PedPoP's round-one message, in its own
    /// canonical serialisation.
    ///
    /// Public so an independent implementation -- or a signer that lives in an
    /// HSM -- can build [`dkg_contribution_payload`] over the same bytes this
    /// crate checks against.
    pub fn commitment_bytes(&self) -> Vec<u8> {
        self.commitments.serialize()
    }

    /// The seat's signature over
    /// [`dkg_contribution_payload`]`(ceremony, cohort, roster_digest, id, commitment_bytes)`.
    ///
    /// A CLAIM, in [`crate::SignedCommitment::signer`]'s sense: it is worth
    /// something only once [`Committing::deal`] has checked it under the key the
    /// SEAT ROSTER names for the seat it was filed under.
    pub fn attestation(&self) -> &IdentitySignature {
        &self.attestation
    }

    /// This contribution with a different attestation stapled to it.
    ///
    /// Public for [`Pop::from_parts`]'s reason: an attacker is not restricted to
    /// this crate's provers, and the rejection tests must be able to present a
    /// contribution whose attestation was made for something else. There is
    /// deliberately no constructor taking raw commitment bytes -- PedPoP's
    /// message type is not public here, so the only way to obtain a well-formed
    /// one is still to run [`Committing::begin`].
    pub fn with_attestation(&self, attestation: IdentitySignature) -> Contribution {
        Contribution {
            commitments: self.commitments.clone(),
            attestation,
        }
    }
}

impl fmt::Debug for Contribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Contribution")
            .field("attestation", &self.attestation)
            .finish_non_exhaustive()
    }
}

/// Round two: one participant's secret share for one other participant,
/// encrypted to that participant's round-one key.
///
/// **Not a wire message either**, for [`Contribution`]'s reason: the tuple field
/// is private, `PedPoPShare` is a private alias, and there is no codec and no
/// constructor. It moves between participants as a Rust value inside one
/// process, and nothing else can move it. It also carries no attestation of any
/// kind -- round two's origin authentication is left entirely to the channel
/// PedPoP assumes and this crate does not supply.
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
    /// WHO holds each seat, fixed BEFORE any key material exists.
    ///
    /// Carried through every round so that it reaches [`CohortKey`], which is
    /// what makes [`ComponentClaim::of`] able to state the seat identities
    /// without a coordinator supplying them -- and therefore what lets an honest
    /// holder refuse a claim that re-attributes a seat.
    ///
    /// It is also what [`Committing::deal`] checks every incoming contribution's
    /// attestation against, which is the round where "who holds each seat" stops
    /// being a label and starts being a refusal.
    seats: SeatRoster<C>,
    /// The ceremony this run belongs to.
    ///
    /// Carried because [`Committing::deal`] has to REBUILD every contribution's
    /// attestation transcript, and the ceremony id is in it. Taking it as a
    /// `deal` argument instead would let a caller check the attestations under a
    /// ceremony that is not the one the local participant committed under, which
    /// is precisely the transplant the field is there to refuse.
    ///
    /// **No test can make this matter and none is constructible**, which is the
    /// standard this crate holds itself to and so is written here: `Committing`
    /// has one constructor, it takes the ceremony, and there is no API through
    /// which a different one could reach `deal`. It is correct by construction
    /// rather than by check. The same is true of [`Committing::roster_digest`]
    /// below and for the same reason.
    ceremony: CeremonyId,
    /// [`dkg_roster_digest`] over this run: threshold, ids, seat keys.
    ///
    /// Computed once in [`Committing::begin`] and carried, rather than recomputed
    /// in `deal`, so that the bytes PedPoP's context was derived from and the
    /// bytes the attestations are checked against are the same bytes by
    /// construction and not by two agreeing computations.
    roster_digest: [u8; 32],
    /// The contribution [`Committing::begin`] produced for this participant.
    ///
    /// Kept so `deal` can answer a question about the local participant's own
    /// entry that no signature check could -- see
    /// [`Committing::check_attribution`] and
    /// [`DkgError::OwnContributionAltered`].
    own: Contribution,
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
    /// Not stronger than that, and the boundary moved this round. The context is
    /// `(CeremonyId, cohort, roster digest)`, so two runs of this cohort under
    /// the same id no longer share a context if they differ in threshold, ids or
    /// seat keys -- which is what the roster digest was added for, and
    /// `a_contribution_does_not_transplant_into_a_run_with_a_different_membership`
    /// and its two siblings perform.
    ///
    /// **What is still open is the SAME roster run twice under one id.** Nothing
    /// enforces that a `CeremonyId` is used for one run -- see this module's
    /// opening note -- and two runs identical in every input this crate hashes
    /// are, to every check here, one run. "Cannot be induced to reuse this run's
    /// commitments in a different composition", which an earlier version of this
    /// comment claimed, is false for that case and remains false. The rule that
    /// binds a HOLDER to one composition is
    /// [`prove_possession`](crate::ceremony::prove_possession)'s, enforced per
    /// share. Drawing a fresh nonce per run -- [`CeremonyId::draw`] -- is the
    /// operational answer, and it is operational because no algebra here can
    /// make it otherwise.
    ///
    /// `seats` names the party holding each roster id. It is required, not
    /// optional: a cohort that cannot say who its seats belong to cannot produce
    /// an artifact a funder can attribute, and the point of taking it HERE
    /// rather than at claim-assembly time is that the answer is then fixed by
    /// the participants' own key generation instead of by whoever assembles the
    /// claim afterwards.
    ///
    /// `identity` is THIS participant's long-term key, and it is used for one
    /// thing: to attest the contribution this call generates, so that every
    /// other participant's [`deal`](Committing::deal) can refuse a contribution
    /// filed under this seat that this seat's key did not attest. (Did not
    /// ATTEST, not did not MAKE: see [`Contribution`] on the distance between
    /// those, which is a residual and not a quibble.) See [`Contribution`]
    /// for why a signature is the right primitive here and what it does not
    /// reach.
    ///
    /// Three refusals before any key material exists, and they answer different
    /// mistakes:
    ///
    ///   * the seat roster must name exactly this cohort's participants --
    ///     [`DkgError::SeatRosterMismatch`];
    ///   * every key it names must BE a key -- [`DkgError::SeatKeyNotUsable`].
    ///     Over the whole roster and not just this seat, because the keys this
    ///     participant will have to verify attestations under are the OTHER
    ///     seats'. It is checked once, here, rather than again in `deal`: a
    ///     `Committing` cannot be built any other way, so a second check there
    ///     could not fail, and a check that cannot fail is a second place for the
    ///     rule to drift from;
    ///   * `identity` must be the key the roster names for `me` --
    ///     [`DkgError::IdentityNotOwn`]. A participant that attested with some
    ///     other key would produce a contribution nobody could verify, and would
    ///     learn about it as everyone else's ceremony failing.
    ///
    /// **Measured, one test per refusal and nothing else in the crate:** the
    /// usable-key loop is killed by
    /// `tests/dkg.rs::a_seat_roster_naming_an_unusable_identity_key_is_refused`,
    /// the own-key check by
    /// `tests/dkg.rs::a_participant_that_begins_with_the_wrong_identity_key_is_refused`.
    /// The seat-roster comparison predates this change and is killed by
    /// `tests/seat_identity.rs::the_dkg_refuses_a_seat_roster_that_is_not_its_participant_roster`.
    pub fn begin<R: RngCore + CryptoRng>(
        ceremony: &CeremonyId,
        spec: &CohortSpec<C>,
        seats: &SeatRoster<C>,
        me: u64,
        identity: &IdentityKey,
        rng: &mut R,
    ) -> Result<(Committing<C>, Contribution), DkgError> {
        let roster = Roster::new(spec)?;
        if seats.ids() != roster.ids() {
            return Err(DkgError::SeatRosterMismatch {
                cohort: C::NAME,
                roster: roster.ids().to_vec(),
                seats: seats.ids(),
            });
        }
        for (id, key) in seats.iter() {
            if let Some(reason) = key.unusable_reason() {
                return Err(DkgError::SeatKeyNotUsable {
                    cohort: C::NAME,
                    participant: id,
                    key,
                    reason,
                });
            }
        }
        // `params` before the identity comparison, and that ordering is the
        // reason there is only ONE place in this function that can say
        // "not on this roster": it resolves `me` to a PedPoP index and returns
        // `DkgError::NotOnRoster` if it cannot. The seat lookup below is then an
        // `expect` rather than a second arm reporting the same thing -- the ids
        // agree by the check at the top of this function, and `me` is one of
        // them by this line.
        let params = roster.params(me)?;
        let mine = seats
            .key_of(me)
            .expect("the seat roster names exactly this roster, and `params` put `me` on it");
        if mine != identity.public() {
            return Err(DkgError::IdentityNotOwn {
                cohort: C::NAME,
                id: me,
                expected: mine,
                found: identity.public(),
            });
        }
        // WHO is running this: threshold, ids, and the key each id is held by.
        // It goes into PedPoP's context AND into every attestation, so a
        // contribution to this run is refused by both layers in any other DECLARED
        // CONTEXT. Not in any other RUN: two executions that reuse the ceremony
        // id, the cohort and the roster are one context and nothing here separates
        // them -- see `begin`'s scope note, and `dkg_roster_digest`, which was the
        // fix for a defect review found.
        //
        // Built from `roster.ids()` rather than from `seats`, so the ORDER is
        // the participant roster's canonical ascending order and not an
        // iteration order that could drift; `Roster::new` requires strictly
        // ascending ids and `SeatRoster` is a `BTreeMap`, so the two agree and
        // there is no ordering a caller can choose. The `expect` is unreachable
        // for the third time in this function and for the same reason -- the ids
        // were compared above -- and it is written as an assertion rather than a
        // refusal because a refusal here could not be falsified by any test.
        let roster_digest = dkg_roster_digest(
            roster.threshold(),
            &roster
                .ids()
                .iter()
                .map(|&id| {
                    (
                        id,
                        seats
                            .key_of(id)
                            .expect("the seat roster names exactly this roster"),
                    )
                })
                .collect::<Vec<_>>(),
        );
        let (machine, msg) =
            KeyGenMachine::<Ristretto>::new(params, ceremony.dkg_context(C::NAME, &roster_digest))
                .generate_coefficients(rng);
        // Signed over the bytes just produced, in the same call that produced
        // them. Read that narrowly: it means this code path has no seam between
        // generating a contribution and attesting it. It does NOT mean the crate
        // has no such seam -- `dkg_contribution_payload` and `IdentityKey::sign`
        // are both public and their composition is exactly one. See
        // [`Contribution`]'s docs, where that residual is named and performed.
        let attestation = identity.sign(&dkg_contribution_payload(
            ceremony,
            C::NAME,
            &roster_digest,
            me,
            &msg.serialize(),
        ));
        let own = Contribution {
            commitments: msg,
            attestation,
        };
        Ok((
            Committing {
                roster,
                seats: seats.clone(),
                ceremony: *ceremony,
                roster_digest,
                own: own.clone(),
                me,
                machine,
            },
            own,
        ))
    }

    pub fn roster(&self) -> &Roster<C> {
        &self.roster
    }

    pub fn me(&self) -> u64 {
        self.me
    }

    /// **Check that every contribution was authorized by the seat it is filed
    /// under**, verify every proof of knowledge, then produce this participant's
    /// secret share for each peer.
    ///
    /// "Authorized by", not "came from": the check is that the roster's key for
    /// that seat signed those exact bytes. See [`Contribution`] for the gap
    /// between that and having generated them.
    ///
    /// # The order, which is the design
    ///
    ///   1. **attribution** -- [`Committing::check_attribution`]. WHICH ROSTER KEY
    ///      authorized each half is a different question from what key material
    ///      exists, and
    ///      it is asked first for the reason
    ///      [`ceremony`](crate::ceremony)'s `check_side` asks the organisation
    ///      signature before anything else: a participant handed a map somebody
    ///      fabricated should be told that, rather than told something about the
    ///      contents of contributions that were never its peers';
    ///   2. **routing** -- `by_index`, which refuses a contribution from
    ///      somebody not on this roster;
    ///   3. **key material** -- PedPoP, which verifies each proof of knowledge
    ///      and produces the shares.
    ///
    /// Step 1 is the one this round did not have. Without it the map's keys were
    /// an assertion by whoever assembled the map, so a single party could
    /// generate every contribution, label them `1..n` and run the cohort's whole
    /// DKG alone -- with real proofs of knowledge throughout, because it really
    /// did know every constant term. See [`Contribution`].
    ///
    /// **Both orderings are tested**, which they were not when this paragraph
    /// first claimed to be "the design":
    ///
    ///   * 1 before 3 -- `tests/dkg.rs::commitments_from_another_ceremony_are_refused_and_name_the_dealer`
    ///     asserts `ContributionNotAttributable` where PedPoP would say
    ///     `BadCommitments`, and swapping the two flips the error it gets;
    ///   * 1 before 2 -- `tests/dkg.rs::a_map_that_is_both_unattributable_and_off_roster_reports_the_attribution`
    ///     builds the only input that can tell them apart: an entry with a bad
    ///     attestation AND an entry from somebody not on the roster. Review found
    ///     this ordering had no test and that nothing in the suite constructed
    ///     such a map; it was constructible, so it is now built rather than
    ///     described.
    ///
    /// Returned keyed by RECIPIENT id: each message goes to exactly one peer,
    /// over an authenticated channel, and broadcasting one is handing that
    /// peer's share to everybody.
    pub fn deal<R: RngCore + CryptoRng>(
        self,
        rng: &mut R,
        contributions: &HashMap<u64, Contribution>,
    ) -> Result<(Dealing<C>, HashMap<u64, ShareMessage>), DkgError> {
        self.check_attribution(contributions)?;
        let by_index = self.roster.by_index(1, self.me, contributions)?;
        let (machine, shares) = self
            .machine
            .generate_secret_shares(
                rng,
                by_index
                    .into_iter()
                    .map(|(i, m)| (i, m.commitments))
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
                seats: self.seats,
                me: self.me,
                machine,
            },
            shares,
        ))
    }

    /// Every contribution this participant is about to consume was attested by
    /// the seat it is filed under.
    ///
    /// The key each signature is checked under comes from `self.seats` -- the
    /// roster this participant itself began under -- and NEVER from the message.
    /// That direction is the whole point, and it is
    /// [`SignedCommitment::check`](crate::SignedCommitment)'s: an artifact
    /// checked against a key it supplied itself has established nothing.
    ///
    /// # The local participant's own entry
    ///
    /// It is not consumed -- PedPoP takes everyone else's -- and for one round it
    /// was simply skipped. Review pointed out what that cost, and it cost two
    /// things:
    ///
    ///   * **at `n == 1` this loop then verified NOTHING AT ALL**, ever, for any
    ///     input. That is the shape [`crate::production`] decided for the gate
    ///     cohort ([`GATE_COUNT`](crate::production::GATE_COUNT) is 1), so the
    ///     guard was inert at half the deployment while the docs described it as
    ///     covering it. A map carrying 64 zero bytes where the gate seat's
    ///     signature belonged was accepted and the whole gate DKG completed;
    ///   * a coordinator that rewrote this participant's own broadcast in the
    ///     copy it handed back was invisible to it.
    ///
    /// So the own entry is now checked, IF PRESENT, by comparing it to the
    /// contribution [`Committing::begin`] produced -- byte equality on the
    /// commitments and on the attestation, no signature verified and no key
    /// consulted, which is strictly stronger than what a peer can be asked. If
    /// absent it is not required, because a participant that does not send itself
    /// its own broadcast is not doing anything wrong and `by_index` skips it too.
    ///
    /// **Do not read the `n == 1` case as a security property.** At `n == 1` the
    /// only entry is the caller's own and the caller made it: comparing it to
    /// itself catches a corrupted or substituted map, not an impostor. **What
    /// keeps a party that does not hold the gate seat's key out of the gate DKG
    /// is [`Committing::begin`]'s [`DkgError::IdentityNotOwn`] refusal**, which
    /// is checked against the seat roster the caller began under, and
    /// `tests/dkg.rs::at_a_cohort_of_one_it_is_begin_that_refuses_a_party_without_the_seat_key`
    /// performs exactly that. This loop is not what carries `n == 1`, and saying
    /// it was is the mistake being corrected.
    ///
    /// # The missing-message arm
    ///
    /// A missing contribution is refused here as well as in `Roster::by_index`,
    /// which runs next. That is a duplicated arm and not a duplicated rule --
    /// same variant, same fields, nothing for the two to disagree about -- and
    /// it is here because this loop needs the message before `by_index` has run.
    ///
    /// **This arm has a killing test, and the crate twice said it could not.**
    /// The first version said nothing dies when it is deleted; that is true for
    /// a map with ONE fault, because `by_index` runs a step later and produces a
    /// byte-identical error. Review pointed out that a map with TWO faults tells
    /// them apart: this loop walks the roster in ascending id order, so an ABSENT
    /// earlier peer and a CORRUPTED later peer distinguish "refuse the absence"
    /// from "skip it and carry on". Replacing the `?` below with a `continue` --
    /// which is the only sensible mutation, since the lookup has to do something
    /// -- changes the reported error from `MissingMessage` to
    /// `ContributionNotAttributable`, and
    /// `tests/dkg.rs::a_missing_earlier_peer_is_reported_before_a_later_peers_bad_attestation`
    /// dies on it.
    ///
    /// `by_index`'s own arm is separately exercised at ROUND TWO, by
    /// `tests/dkg.rs::a_missing_round_two_share_names_the_participant` -- an
    /// earlier version of this sentence asserted that and no such test existed.
    ///
    /// **Measured, in an isolated copy, with the file restored and hash-checked
    /// afterwards.** Deleting the signature refusal below fails exactly ten
    /// tests, all in `tests/dkg.rs`, and nothing else in the crate:
    /// `a_contribution_the_seat_did_not_attest_is_refused`,
    /// `an_attestation_does_not_carry_to_another_contribution_by_the_same_seat`,
    /// `a_contribution_relabelled_between_two_seats_that_share_a_key_is_refused`,
    /// `commitments_from_another_ceremony_are_refused_and_name_the_dealer`,
    /// `an_attestation_built_for_the_other_cohort_does_not_verify_here`,
    /// `a_map_that_is_both_unattributable_and_off_roster_reports_the_attribution`,
    /// `a_missing_earlier_peer_is_reported_before_a_later_peers_bad_attestation`
    /// and the three transplant tests. Ten rather than the four this comment
    /// once claimed, because six of them are new -- the count is written out so
    /// that a future deletion that kills FEWER is visible as coverage lost.
    ///
    /// Deleting the own-entry comparison fails exactly three:
    /// `the_gate_cohorts_attribution_check_is_not_vacuous`,
    /// `a_rewritten_own_contribution_is_refused` and
    /// `an_own_entry_with_the_right_signature_over_the_wrong_commitments_is_refused`.
    /// **Each DISJUNCT is covered separately**, which review asked for after
    /// pointing out that the first two tests survive if only the commitment
    /// comparison goes: deleting the commitments disjunct alone fails the third
    /// test and only that; deleting the attestation disjunct alone fails the
    /// first and only that.
    ///
    /// Replacing the missing-peer `?` with a `continue` fails exactly one:
    /// `a_missing_earlier_peer_is_reported_before_a_later_peers_bad_attestation`.
    /// Swapping steps 1 and 2 of `deal` fails exactly one:
    /// `a_map_that_is_both_unattributable_and_off_roster_reports_the_attribution`.
    fn check_attribution(&self, contributions: &HashMap<u64, Contribution>) -> Result<(), DkgError> {
        for &id in self.roster.ids() {
            if id == self.me {
                // Not required. Checked if supplied, and checked by comparison
                // rather than by signature: this participant knows what it sent.
                if let Some(mine) = contributions.get(&id) {
                    if mine.commitment_bytes() != self.own.commitment_bytes()
                        || mine.attestation != self.own.attestation
                    {
                        return Err(DkgError::OwnContributionAltered {
                            cohort: C::NAME,
                            id,
                        });
                    }
                }
                continue;
            }
            let contribution = contributions.get(&id).ok_or(DkgError::MissingMessage {
                cohort: C::NAME,
                round: 1,
                from: id,
            })?;
            // `begin` checked that the seat roster names exactly this roster, so
            // the lookup cannot miss; and it checked that every key it names is
            // usable, so `verify` is being asked about a key that has a secret
            // behind it and only one.
            //
            // NO TEST CAN MAKE THIS PANIC, and it is written as an `expect`
            // rather than a refusal for that reason: a `Committing` has exactly
            // one constructor, and it rejects a seat roster whose ids are not
            // this roster's before it builds one. A refusal here would be an arm
            // nothing could falsify -- which this crate treats as worse than an
            // assertion that names its own cause.
            let key = self
                .seats
                .key_of(id)
                .expect("`begin` required the seat roster to name exactly this roster");
            if !key.verify(
                &dkg_contribution_payload(
                    &self.ceremony,
                    C::NAME,
                    &self.roster_digest,
                    id,
                    &contribution.commitment_bytes(),
                ),
                &contribution.attestation,
            ) {
                return Err(DkgError::ContributionNotAttributable {
                    cohort: C::NAME,
                    dealer: id,
                    key,
                });
            }
        }
        Ok(())
    }
}

/// A participant that has dealt its shares and is waiting for everyone else's.
pub struct Dealing<C: ControlDomain> {
    roster: Roster<C>,
    seats: SeatRoster<C>,
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
            seats: self.seats,
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
    seats: SeatRoster<C>,
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
            seats: self.seats,
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
    /// WHO holds each seat, as fixed at [`Committing::begin`] and checked there
    /// against this cohort's own roster.
    seats: SeatRoster<C>,
    domain: PhantomData<C>,
}

impl<C: ControlDomain> Clone for CohortKey<C> {
    fn clone(&self) -> Self {
        CohortKey {
            cohort: self.cohort.clone(),
            component: self.component,
            seats: self.seats.clone(),
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
            .field("seats", &self.seats)
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

    /// WHO holds each seat, as this cohort's own key generation was told.
    ///
    /// Not a claim received from a coordinator: it was fixed at
    /// [`Committing::begin`], before any key material existed, and checked there
    /// against this roster. That is what makes it usable as the reference a
    /// holder compares a received [`ComponentClaim`] against.
    pub fn seats(&self) -> &SeatRoster<C> {
        &self.seats
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

    /// **Endorse this seat's own verification share** with the seat-holder's
    /// long-term identity key AND this share.
    ///
    /// The other half of what a seat contributes to an artifact. The proof of
    /// possession says *somebody* knows `s_i`; a threshold transcript can say
    /// nothing more, because the quorum it would incriminate could reproduce it.
    /// This says an act that used a NAMED long-term key AND the share behind
    /// that seat produced the endorsement, which is the statement
    /// [`audit`](crate::audit) checks against a key the funder obtained from
    /// that party. See [`SeatEndorsement`](crate::ceremony::SeatEndorsement) for
    /// the construction and for the two things it still does not say.
    ///
    /// The share comes from `self` and is not a parameter: a caller that could
    /// pass one could pass somebody else's, and the point of this entry point is
    /// that the two secrets it uses are the ones this holder actually has.
    ///
    /// Three refusals, and they answer different mistakes:
    ///
    ///   * `claim` must be this share's own, field for field, so a coordinator
    ///     cannot collect a seat endorsement over its own roster or component --
    ///     [`CeremonyError::ClaimNotOwn`], the same check [`Pop::prove_for`]
    ///     makes and for the same reason;
    ///   * `key` must be the identity the claim attributes to THIS seat, so a
    ///     holder handed a claim that re-attributes its own seat endorses
    ///     nothing -- [`CeremonyError::SeatKeyNotOwn`];
    ///   * this share must open the verification share the claim publishes for
    ///     this seat -- [`CeremonyError::SeatShareNotOwn`]. Unreachable through
    ///     THIS entry point, because the claim comparison above already forces
    ///     the two equal, and said so rather than left to look like a third
    ///     independent guard: it is [`endorse_seat`]'s refusal, and it is what
    ///     protects a holder that reaches for the free function instead.
    ///
    /// It is not a capability boundary. Whoever holds both secrets can produce
    /// the proof without this function; what it changes is what an honest
    /// holder's software does by default. Same limit, stated the same way, as
    /// [`CohortShare::prove`].
    pub fn endorse(
        &self,
        ceremony: &CeremonyId,
        claim: &ComponentClaim,
        key: &IdentityKey,
    ) -> Result<SeatEndorsement, CeremonyError> {
        if *claim != ComponentClaim::of(&self.key) {
            return Err(CeremonyError::ClaimNotOwn {
                cohort: C::NAME,
                participant: self.id,
            });
        }
        endorse_seat(ceremony, claim, self.id, key, &self.secret)
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
/// is skip any of the PROTOCOL rounds -- every message is produced and consumed,
/// every proof of knowledge is verified, every contribution is checked against
/// its seat's identity key, and every share is checked against its dealer's
/// commitments.
///
/// **It is not, however, "exactly as a networked deployment would produce and
/// consume it", which is what this said and review corrected.** The messages
/// never leave the process: they move as Rust values, and neither
/// [`Contribution`] nor [`ShareMessage`] has a serialisation to move them any
/// other way. The rounds are simulated at the level of VALUES, not of bytes, so
/// a deployment's encode/decode step -- and everything that can go wrong in it
/// -- is exercised nowhere in this crate.
///
/// What it does collapse is the out-of-band step [`Confirming::confirm`] exists
/// for: it confirms on every participant's behalf, which one process
/// legitimately can and a deployment cannot. A deployment runs
/// [`Committing::begin`], [`Committing::deal`], [`Dealing::finish`] and
/// [`Confirming::confirm`] once per participant, on that participant's own
/// machine.
///
/// **`identities` is every seat's PRIVATE identity key**, and requiring it is
/// the honest statement of what this function is.
///
/// **What that signature does and does not say, corrected.** It used to say: "a
/// single process can only run a cohort's whole DKG if it holds every one of
/// that cohort's identity keys -- so this signature is the new bar written into
/// a type." Review pointed out that the caller supplies `seats` AND `identities`,
/// so the two can be made to agree with keys the caller minted this morning:
/// `tests/dkg.rs::a_process_holding_no_real_seat_key_still_runs_a_whole_cohort_under_its_own_roster`
/// runs both decided cohorts end to end that way. The narrower and true
/// statement is:
///
/// > a process cannot produce a dealing whose SEAT ROSTER names seat-holders it
/// > does not hold the private keys of.
///
/// That is a claim about labelling, and what enforces it downstream -- refusing
/// a component whose claim names seats that did not endorse it -- is the seat
/// endorsement in [`ceremony`](crate::ceremony), not anything here.
///
/// It is also exactly the residual: holding `n` keys is not being `n` parties,
/// and `tests/dkg.rs::a_party_that_holds_every_seat_key_still_runs_the_whole_dkg_alone`
/// performs that rather than describing it.
///
/// A roster member `identities` has no entry for is [`DkgError::IdentityKeyMissing`]
/// rather than a participant quietly skipped or attested with the nearest key to
/// hand. Measured: replacing that refusal fails
/// `tests/dkg.rs::run_dkg_refuses_a_participant_it_holds_no_identity_key_for`,
/// and nothing else.
///
/// The returned shares are in roster order.
pub fn run_dkg<C: ControlDomain, R: RngCore + CryptoRng>(
    ceremony: &CeremonyId,
    spec: &CohortSpec<C>,
    seats: &SeatRoster<C>,
    identities: &HashMap<u64, IdentityKey>,
    rng: &mut R,
) -> Result<Vec<CohortShare<C>>, DkgError> {
    let roster = Roster::new(spec)?;

    let mut committing = Vec::with_capacity(roster.n());
    let mut commitments = HashMap::with_capacity(roster.n());
    for &id in roster.ids() {
        let identity = identities
            .get(&id)
            .ok_or(DkgError::IdentityKeyMissing { cohort: C::NAME, id })?;
        let (state, msg) = Committing::<C>::begin(ceremony, spec, seats, id, identity, rng)?;
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
