//! The composition ceremony: commit, prove possession, reveal, audit.
//!
//! [`dkg`](crate::dkg) removes the dealer from inside each cohort. It does not
//! touch what happens BETWEEN them, and that is where the address is stolen.
//!
//! # The defect this module exists to close
//!
//! `crates/two-cohort/tests/rogue_key.rs` performs it. The scheme composes the
//! spend root as a plain group addition,
//!
//! ```text
//!     B = B_owner + B_gate
//! ```
//!
//! so a cohort that publishes SECOND picks a `t` it knows and publishes
//! `B_mine = t*G - B_theirs`. It knows no discrete log of that point and does
//! not need one: the sum is `t*G`, whose discrete log it chose. The honest
//! cohort's roster, threshold and shares are then decoration -- the exhibit
//! mounts the same attack against two different honest cohorts and gets a
//! byte-identical signature out of both.
//!
//! Two things are needed, and NEITHER is sufficient alone:
//!
//!   * **Proof of possession.** Each cohort proves knowledge of the discrete
//!     log of the component it publishes. A rogue component's discrete log is
//!     `t - dlog(B_theirs)`, so proving it would mean knowing `dlog(B_theirs)`.
//!   * **Non-adaptive ordering.** A proof of possession produced AFTER seeing
//!     the other component still lets a cohort grind: it can run its DKG
//!     repeatedly until it likes the sum. So both components are sealed under a
//!     commitment before either is revealed.
//!
//! The two are welded together here rather than layered: the proof-of-possession
//! transcript contains BOTH commitments. A cohort cannot produce a valid proof
//! until it holds the other cohort's sealed component, and the thing it is
//! proving possession of is already sealed inside its own commitment. So a
//! cohort's proof is evidence that it held the other side's commitment when it
//! proved -- an ORDERING between two events in the artifact, not a CHRONOLOGY.
//! Nothing here dates anything, and the negative list below says so at length:
//! a party assembling both halves can produce any internally consistent
//! history.
//!
//! ```text
//!   1. each cohort runs its own PedPoP DKG under this ceremony's id
//!   2. each SEALS its component:  ComponentCommitment::seal
//!   3. each SIGNS its own seal under its organisation's long-term identity
//!      key                                    -> SignedCommitment
//!   4. the two signed commitments are exchanged -> SealedComposition
//!   5. each participant proves possession of its share under BOTH
//!      commitments and BOTH organisations     -> Pop
//!   6. each cohort REVEALS                    -> ComponentReveal
//!   7. the reveals are matched against the commitments and the proofs
//!      checked                                -> CompositionArtifact
//!   8. anyone holding the artifact AND the two organisations' identity
//!      public keys can re-run 7 -> audit
//! ```
//!
//! # The third defence: who produced this half
//!
//! Proof of possession and non-adaptive ordering are both statements about KEY
//! MATERIAL, and one process that runs both DKGs satisfies them completely: it
//! holds every share of both cohorts, so it can prove possession of both
//! components, and it can seal both before opening either. An artifact of bare
//! commitments therefore cannot distinguish a composition between two
//! organisations from a solo performance of one.
//! `tests/attribution.rs::one_process_can_produce_an_artifact_that_passes_every_structural_check`
//! carries that out rather than asserting it.
//!
//! So each cohort signs its own sealed commitment under its organisation's
//! long-term Ed25519 identity key -- [`crate::identity`], the same primitive
//! `crates/ceremony` signs round messages with -- and [`audit`] takes the two
//! keys the funder obtained FROM THE ORGANISATIONS and refuses any artifact
//! whose halves were endorsed by anything else. The identities are welded into
//! the proof-of-possession transcript too (see [`pop_challenge`]), so a holder
//! proves possession under a composition that names its counterparty, and an
//! honest cohort's reveal cannot be re-attributed to a different party.
//!
//! The residual is exact and is not a detail: an impostor holding BOTH
//! organisations' identity private keys still produces an artifact that audits.
//! Identity keys are what a funder is trusting; this makes the artifact say so
//! out loud instead of saying nothing.
//!
//! # The proof of possession is per PARTICIPANT, not per cohort
//!
//! Nobody holds the discrete log of `B_c`; that is the entire point of a
//! threshold key. So the cohort does not sign one proof. Each participant `i`
//! proves knowledge of its own share `s_i` against the verification share
//! `V_i = s_i*G` the DKG published, and the auditor checks separately that the
//! `V_i` interpolate to `B_c` at the declared threshold. Together those two
//! facts say the cohort collectively knows `dlog(B_c) = sum_i lambda_i s_i`,
//! which is what a proof of possession has to mean for a threshold key.
//!
//! The interpolation check is not a formality, and it is TWO-SIDED. Shares that
//! do not lie on a degree-`t-1` polynomial are the "inconsistent dealing"
//! failure: an address only SOME quorums can spend, discovered after funding.
//! Shares that lie on a polynomial of LOWER degree are the overstated-threshold
//! failure: a genuine 2-of-4 dealing satisfies every 3-subset test of a declared
//! 3-of-4, because a degree-1 polynomial is also a degree-2 polynomial, so a
//! one-sided check lets a cohort publish any threshold at or above its real one
//! and [`AuditedRoot::structure`] reports seats to a funder that the cohort does
//! not need. [`audit`] therefore checks that every `t`-subset reaches the same
//! component AND that no `(t-1)`-subset reaches it -- together the polynomial
//! condition itself, at `C(n,t) + C(n,t-1)` interpolations.
//!
//! # What a funder can check, and what it still cannot
//!
//! [`audit`] takes a [`CompositionArtifact`] and the two organisations'
//! identity public keys, and nothing else. It establishes:
//!
//!   * that the two identity keys the funder supplied are DIFFERENT KEYS -- one
//!     key given twice is [`CeremonyError::PartiesNotDistinct`], because every
//!     check below would otherwise pass and report a two-party control that was
//!     never claimed. Key inequality, and nothing more: two keys can be two hats
//!     on one organisation, which is the residual stated below;
//!   * that each cohort's commitment was endorsed by the organisation the funder
//!     named for it, under a signature over this ceremony, this cohort and this
//!     digest -- so the artifact is a statement BY those two parties and not
//!     merely a statement about two rosters, and every proof of possession in it
//!     was made under a transcript naming both of them;
//!   * the two rosters, their two thresholds, and that their ids come from
//!     disjoint control domains, so no subset of one is a quorum of the other;
//!   * that each roster is in the canonical ascending order, so the audit's
//!     position-to-evaluation-point mapping is the one the holders' own
//!     Lagrange weights use, and one dealing has ONE audited component rather
//!     than an ordering-dependent choice among them;
//!   * every participant of both cohorts proved knowledge of its share, under a
//!     transcript naming this ceremony, this cohort, this roster, this
//!     threshold and this component -- so no proof is transplanted from
//!     anywhere else -- and that no seat's verification share is the identity,
//!     which every proof satisfies vacuously;
//!   * the verification shares interpolate to the declared component at
//!     EXACTLY the declared threshold: every `t`-subset reaches it and no
//!     `(t-1)`-subset does;
//!   * each revealed component matches the commitment published for it;
//!   * the root is the sum of exactly those two components.
//!
//! [`AuditedRoot::structure`] returns all of that as two [`CohortStructure`]
//! values -- identity, threshold, roster, component -- so a caller comparing an
//! address against a decided structure compares values instead of navigating
//! the artifact's internals.
//!
//! It does NOT establish:
//!
//!   * **That the two organisations are two organisations.** A party holding
//!     both identity private keys signs both halves and this passes. That is the
//!     honest residual of the attribution check and it is exhibited, not
//!     glossed: `tests/attribution.rs`'s last test performs it. What changed is
//!     the bar -- an impostor must now hold the long-term keys of both named
//!     organisations, rather than merely run two processes.
//!
//!   * **That the commitments were published before the reveals.** The artifact
//!     carries both commitments, and the proofs of possession are bound to
//!     both, so a cohort that followed the sequence has evidence it did. The
//!     identity signatures do NOT close this: a signature has no time in it, so
//!     it says the organisation endorsed this digest, never when. An artifact
//!     assembled by one party holding both keys can still have any internally
//!     consistent history, and [`ComponentCommitment::seal`] takes any claim, so
//!     the existence of a [`SealedComposition`] is not evidence that an exchange
//!     happened. What stops a cohort choosing its component after seeing the
//!     other's reveal is that its victim's proofs do not transfer to a second
//!     sealed composition and the victim REFUSES to make new ones --
//!     [`prove_possession`], enforced at the share, not in the artifact. A
//!     funder that saw the commit broadcast should still compare it with
//!     [`CompositionArtifact::commitments`]; that check is independent of
//!     whether the other cohort's holders followed the rule, and the signatures
//!     now make an ARCHIVED broadcast attributable, which is the piece an
//!     authenticated archive would build on.
//!   * **That either cohort really ran a DKG, or that its seats are more than
//!     one entity.** These are one gap, not two, and it is the largest one
//!     remaining. [`Parties`] carries ONE identity key per COHORT. A
//!     [`ComponentClaim`] names its seats by participant id and by verification
//!     share, and by nothing else -- there is no per-seat identity anywhere in
//!     the artifact. So an organisation that runs no DKG, deals every share to
//!     itself with [`Cohort::deal_in`](crate::Cohort), and endorses the seal
//!     with its own real identity key answers every proof of possession
//!     (it knows every share) and produces an artifact byte-indistinguishable in
//!     structure from an honest one.
//!     `tests/forgery.rs::a_dealt_owner_cohort_passes_the_audit_and_the_release_gate`
//!     performs it: [`audit_address`] returns `Ok`,
//!     [`production::check_decided_structure`](crate::production::check_decided_structure)
//!     returns `Ok`, [`production::authorize_release`](crate::production::authorize_release)
//!     issues a `ReleaseAuthorization`, and the published address is then opened
//!     by two principals -- the dealing organisation and the single honest gate
//!     -- against a decided `COMPROMISE_THRESHOLD` of three.
//!
//!     What the artifact rules out is the CROSS-cohort attack, where the victim
//!     is the other cohort rather than that cohort's own members. Nothing here
//!     protects a cohort's members from their own organisation, or a funder from
//!     a cohort with one member wearing every hat. This is not a check that can
//!     be strengthened: `Parties` cannot express the claim, because the decided
//!     structure's security argument is per SEAT and this layer's finest grain
//!     is the cohort. Closing it means putting a per-seat identity into
//!     [`ComponentClaim`] -- sealed by the commitment and named in every pop
//!     transcript -- and taking a seat roster of keys in [`Parties`].
//!     `crates/ceremony/src/machine.rs` already keeps a
//!     `ParticipantId -> IdentityPublic` map for identifiable abort; it does not
//!     reach `CompositionArtifact`.
//!   * **That the two rosters are different organisations.** Disjoint id bands
//!     are enforced and two distinct identity keys are now required -- [`audit`]
//!     refuses a [`Parties`] naming one key twice, with
//!     [`CeremonyError::PartiesNotDistinct`] -- but two keys are two keys:
//!     disjoint control is a fact about the world. The artifact names the
//!     parties; it cannot say they are independent.
//!   * **That a cohort has not been compromised since.** The artifact is a
//!     statement about key generation, not about custody.
//!   * **The subaddress, unless the funder holds the view key.** `D_i = B +
//!     Hs(a||i)*G` needs `a` to recompute. [`audit`] checks the root; only
//!     [`audit_address`] checks that a particular subaddress is a subaddress of
//!     it. A view service that publishes a `D_i` that is not a subaddress of the
//!     audited root sends deposits somewhere the cohorts cannot sign for. That
//!     is a REAL and undefended failure. An earlier version of this paragraph
//!     said such a service "can freeze or misdirect funds; it cannot spend
//!     them", reasoning that it would reach `D = B + off*G` whose discrete log
//!     it does not know. **That is wrong and review caught it.** Nothing forces
//!     a lying publisher to derive `D` from `B` at all: it can pick `d`, publish
//!     `D = d*G` with a matching view component, and open any output paid there
//!     with `Hs(a*R) + d`. Whoever publishes the address and holds `a` can spend
//!     what is sent to it, and the two cohorts never enter the picture. A funder
//!     holding the correct `a` closes this outright with [`audit_address`],
//!     which is why `a` is not an optional convenience.
//!   * **Grinding by restart.** Commit-then-reveal stops adaptivity within one
//!     ceremony. A cohort that aborts after seeing a reveal and demands a fresh
//!     ceremony gets another draw. Each restart is a new [`CeremonyId`] and is
//!     visible to the other cohort, which makes it a governance question rather
//!     than a cryptographic one.

use core::fmt;
use std::collections::BTreeMap;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G, ristretto::RistrettoPoint, scalar::Scalar,
    traits::IsIdentity,
};
use mc_crypto_hashes::{Blake2b512, Digest};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error as ThisError;
use zeroize::Zeroizing;

use crate::{
    control::{ControlDomain, Gates, Owners, NAMESPACE_SPAN},
    derive::subaddress_offset,
    dkg::{CohortKey, CohortShare},
    identity::{IdentityKey, IdentityPublic, IdentitySignature},
    subsets_of,
};

/// Domain separator for [`CeremonyId`].
const CEREMONY_TAG: &[u8] = b"two-cohort/composition/ceremony/v1";
/// Domain separator for the per-cohort PedPoP transcript context.
const DKG_CONTEXT_TAG: &[u8] = b"two-cohort/composition/dkg-context/v1";
/// Domain separator for the sealed-component commitment.
const COMMIT_TAG: &[u8] = b"two-cohort/composition/commit/v1";
/// Domain separator for the proof-of-possession challenge.
const POP_TAG: &[u8] = b"two-cohort/composition/pop/v1";
/// Domain separator for an organisation's identity signature over its own
/// sealed commitment. Distinct from every tag `crates/ceremony` signs under, so
/// a round message can never be replayed as a commitment endorsement or the
/// other way about.
const COMMIT_SIGNATURE_TAG: &[u8] = b"two-cohort/composition/commit-signature/v1";

/// Largest roster [`audit`] will enumerate qualifying subsets of.
///
/// The consistency check is `C(n, t)` interpolations for the upper bound on the
/// degree plus `sum_{s<t} C(n, s)` for the lower bound on the minimum coalition,
/// so at worst `2^n` -- 65536 interpolations at `n = 16`, each over at most 16
/// points. 16 is far above the decided structure (3 owners, 1 gate); a roster
/// past it is refused rather than silently made slow.
///
/// The lower bound sums over every size below `t` rather than over `t-1` alone,
/// which is what makes it exponential rather than a single binomial. See
/// `ComponentClaim::check_consistency` for why the cheaper version checked a
/// weaker claim than the one reported to a funder.
pub const MAX_AUDITED_ROSTER: usize = 16;

/// Everything the composition can refuse.
///
/// Typed, and every variant names the cohort, because a funder reading a
/// rejection needs to know which side of the address failed and how -- "the
/// gate cohort's component does not match the commitment published for it" and
/// "the gate cohort's participant 1000001 could not prove possession of its
/// share" are different incidents with different responses.
#[derive(Clone, Debug, PartialEq, Eq, ThisError)]
#[non_exhaustive]
pub enum CeremonyError {
    /// The revealed component, roster, threshold or verification shares are not
    /// what the commitment sealed. THE non-adaptivity failure: this is what a
    /// cohort that recomputed its component after seeing the other's hits.
    ///
    /// The commitment seals the CLAIM -- see [`commitment_digest`], which
    /// absorbs the ceremony id, the claim and the salt. It does not seal the
    /// proofs; those are bound to the claim from the other direction, by
    /// [`pop_challenge`].
    #[error("cohort `{cohort}`: the revealed component does not match the commitment published for it")]
    CommitmentMismatch { cohort: &'static str },

    /// A participant's proof of knowledge of its share does not verify against
    /// the verification share published for it, under this ceremony's
    /// transcript. THE rogue-key failure: a component nobody can open cannot be
    /// proved.
    #[error("cohort `{cohort}`: participant {participant} did not prove possession of its share")]
    PopFailed {
        cohort: &'static str,
        participant: u64,
    },

    /// A reveal missing a proof for one of its own roster members. Refused
    /// rather than skipped: a component is only proved if EVERY share behind it
    /// is proved, since the missing one is exactly where a rogue term would be
    /// hidden.
    #[error("cohort `{cohort}`: no proof of possession for participant {participant}")]
    PopMissing {
        cohort: &'static str,
        participant: u64,
    },

    /// A proof for somebody not on the declared roster.
    #[error("cohort `{cohort}`: proof of possession from {participant}, who is not on the declared roster")]
    PopUnexpected {
        cohort: &'static str,
        participant: u64,
    },

    /// The verification shares do not lie on a polynomial of the declared
    /// degree: two qualifying quorums interpolate to different components. An
    /// address built on this can be spent by some quorums and not others, and
    /// which is which is only discovered after it is funded.
    #[error("cohort `{cohort}`: verification shares are inconsistent -- quorum {a:?} and quorum {b:?} interpolate to different components")]
    InconsistentVerificationShares {
        cohort: &'static str,
        a: Vec<u64>,
        b: Vec<u64>,
    },

    /// A roster/verification-share list that is not a well-formed cohort:
    /// empty, duplicated ids, id 0, threshold above the roster, or a mismatched
    /// number of verification shares.
    #[error("cohort `{cohort}`: {source}")]
    Roster {
        cohort: &'static str,
        source: crate::Error,
    },

    /// An id outside the cohort's control domain. Checked here as well as in
    /// the DKG because the auditor sees only the artifact and must not have to
    /// assume the DKG ran the check.
    #[error("cohort `{cohort}`: participant id {id} is outside the `{cohort}` id namespace {base}..{end}")]
    IdOutsideDomain {
        cohort: &'static str,
        id: u64,
        base: u64,
        end: u64,
    },

    /// A claim with a different number of verification shares than roster
    /// members. Refused before anything indexes into them.
    #[error("cohort `{cohort}`: {roster} roster members but {verification_shares} verification shares")]
    MalformedClaim {
        cohort: &'static str,
        roster: usize,
        verification_shares: usize,
    },

    /// The verification shares are internally consistent but do not interpolate
    /// to the component the cohort declared.
    #[error("cohort `{cohort}`: quorum {quorum:?} does not interpolate to the declared component")]
    ComponentNotInterpolated {
        cohort: &'static str,
        quorum: Vec<u64>,
    },

    /// A roster past [`MAX_AUDITED_ROSTER`].
    #[error("cohort `{cohort}`: roster of {n} exceeds the {MAX_AUDITED_ROSTER} this audit will enumerate quorums of")]
    RosterTooLargeToAudit { cohort: &'static str, n: usize },

    /// A component that is the identity. `B_c = 0` contributes nothing to the
    /// sum, so the "composite" root is the other cohort's key outright. It is
    /// refused separately from the proofs because the identity's discrete log
    /// is 0 and IS provable.
    #[error("cohort `{cohort}`: the component is the identity, which contributes nothing to the root")]
    IdentityComponent { cohort: &'static str },

    /// The artifact's subaddress spend key is not a subaddress of its root
    /// under the view key supplied. Only [`audit_address`] can reach this.
    #[error("subaddress {index} of the composite root is not the spend key this artifact claims")]
    SubaddressMismatch { index: u64 },

    /// A reveal or commitment presented where the other cohort's belongs.
    ///
    /// Material from a different CEREMONY does not need its own variant: the
    /// ceremony id is inside both the commitment digest and every proof
    /// challenge, so it surfaces as [`CeremonyError::CommitmentMismatch`] or
    /// [`CeremonyError::PopFailed`] -- at the check that actually failed.
    #[error("a `{found}` reveal was presented where a `{expected}` reveal belongs")]
    CohortMismatch {
        expected: &'static str,
        found: &'static str,
    },

    /// A roster that is not in strictly ascending order.
    ///
    /// The audit interpolates the verification shares at evaluation points
    /// `1..=n` assigned BY POSITION, and so does every share-holder's
    /// [`CohortShare::term`]. So a roster and its permutation are two different
    /// dealings that carry the same set of shares, and they interpolate to two
    /// different components. [`Roster::new`](crate::dkg::Roster::new) makes the
    /// order canonical for the participants; this makes it canonical for the
    /// auditor, which sees only wire data and must not have to assume the DKG
    /// ran the check.
    ///
    /// Without it, an artifact whose roster is published in a different order
    /// than the one its holders ran audits cleanly and describes an address
    /// whose holders' Lagrange weights are for a different set of points --
    /// funded, then unspendable, which is the class this module exists to close.
    #[error("cohort `{cohort}`: roster {roster:?} is not in strictly ascending order, so the position-to-evaluation-point mapping is not canonical")]
    RosterNotCanonical {
        cohort: &'static str,
        roster: Vec<u64>,
    },

    /// A verification share that is the identity.
    ///
    /// `V_i = 0` makes the proof-of-possession equation `z*G == R + c*0`, which
    /// is satisfied by `Pop::from_parts(z*G, z)` for any `z` at all -- so a seat
    /// with an identity verification share is a seat anybody can "prove", and
    /// the audit's statement that every participant proved knowledge of its
    /// share would be false for it. Refused separately from
    /// [`CeremonyError::PopFailed`] because the proof does verify; it is the
    /// share that is not a share.
    #[error("cohort `{cohort}`: participant {participant}'s verification share is the identity, which any proof satisfies")]
    IdentityVerificationShare {
        cohort: &'static str,
        participant: u64,
    },

    /// The verification shares are consistent, but at a LOWER degree than the
    /// declared threshold: fewer than `threshold` participants already
    /// reconstruct the component.
    ///
    /// [`ComponentClaim::check_consistency`]'s agreement test is one-sided on
    /// its own -- it says the shares lie on a polynomial of degree AT MOST
    /// `threshold - 1`. A genuine 2-of-4 dealing satisfies every 3-subset check
    /// of a declared 3-of-4, so without this an artifact reports a structure the
    /// cohort does not have and a funder counting seats counts wrong.
    #[error("cohort `{cohort}`: declared threshold {threshold}, but quorum {quorum:?} of {} already reconstructs the component", quorum.len())]
    ThresholdOverstated {
        cohort: &'static str,
        threshold: usize,
        quorum: Vec<u64>,
    },

    /// A share asked to answer a SECOND proof-of-possession challenge, under a
    /// different sealed composition than the one it has already answered.
    ///
    /// This is the non-adaptivity rule, enforced where it can be enforced. See
    /// [`prove_possession`].
    #[error("cohort `{cohort}`: participant {participant} has already proved possession under a different sealed composition in this ceremony")]
    ProofAlreadyIssued {
        cohort: &'static str,
        participant: u64,
    },

    /// A claim handed to a share-holder that is not the claim its own DKG
    /// produced. See [`Pop::prove_for`].
    #[error("cohort `{cohort}`: participant {participant} was asked to prove possession under a claim that is not the one its own key generation produced")]
    ClaimNotOwn {
        cohort: &'static str,
        participant: u64,
    },

    /// The commitment is endorsed by an identity key, and it is not the key the
    /// funder named for this cohort.
    ///
    /// THE attribution failure. Without the identity signatures an artifact
    /// carries no statement about WHO produced either half, so one process that
    /// ran both DKGs produces an artifact indistinguishable from a two-party
    /// one -- `tests/attribution.rs` exhibits exactly that. This is what a
    /// funder holding the two organisations' published keys sees when the
    /// artifact was not produced by them.
    #[error("cohort `{cohort}`: the commitment is signed by identity {found}, but the audit was told the `{cohort}` organisation is {expected}")]
    CommitmentSignerUnexpected {
        cohort: &'static str,
        expected: IdentityPublic,
        found: IdentityPublic,
    },

    /// The commitment's identity signature does not verify under the key the
    /// signature itself names.
    ///
    /// Separate from [`CeremonyError::CommitmentSignerUnexpected`] because the
    /// two are different incidents: that one is a commitment somebody else
    /// endorsed, this one is a commitment nobody did. An artifact assembled
    /// with the expected key pasted in but no private key behind it -- an
    /// all-zero signature, a signature lifted from another ceremony, a
    /// signature over a different digest -- lands here.
    #[error("cohort `{cohort}`: the commitment's identity signature does not verify under {signer}, the key it names")]
    CommitmentSignatureInvalid {
        cohort: &'static str,
        signer: IdentityPublic,
    },

    /// The funder named ONE organisation for both cohorts.
    ///
    /// A defect in the audit's INPUT rather than in the artifact, and refused
    /// for that reason rather than in spite of it. Every other check would
    /// pass: one organisation can hold both cohorts' shares, endorse both
    /// commitments with the one key it has, and satisfy the proofs of
    /// possession, since it genuinely knows every share. [`audit`] would then
    /// return an [`AuditedRoot`] whose two [`CohortStructure`]s report the same
    /// [`identity`](CohortStructure::identity), and
    /// [`production::authorize_release`](crate::production::authorize_release)
    /// would issue a release authorisation for it.
    ///
    /// "Two cohorts under two organisations" is the entire premise. A funder
    /// that supplies one key twice has said the premise does not hold, and the
    /// only honest answer is to refuse rather than to certify a joint control
    /// that was never claimed. This does NOT establish that two distinct keys
    /// are two distinct organisations -- see the module docs, and
    /// `tests/attribution.rs::the_residual_is_a_party_that_holds_both_organisations_identity_keys`.
    /// It refuses the one case the artifact itself can see.
    #[error(
        "the audit was told the same identity {key} is both the `owners` and the `gates` \
         organisation, so there is no two-party control here to check"
    )]
    PartiesNotDistinct { key: IdentityPublic },
}

impl CeremonyError {
    fn roster<C: ControlDomain>(source: crate::Error) -> CeremonyError {
        CeremonyError::Roster {
            cohort: C::NAME,
            source,
        }
    }
}

/// Result alias for the ceremony.
pub type Result<T> = core::result::Result<T, CeremonyError>;

// ---------------------------------------------------------------------------
// Ceremony identity
// ---------------------------------------------------------------------------

/// The identifier every transcript in one composition is bound to.
///
/// Fixed BEFORE either cohort generates a key, and used as the PedPoP context
/// for both DKGs as well as the root of the commitment and proof transcripts.
/// One consequence matters: material from a different ceremony -- a previous
/// attempt, a test run, another address -- does not verify here, so a proof,
/// commitment or endorsement made under one ceremony cannot be presented under
/// another.
///
/// It does NOT stop a cohort re-using a KEY. A finished [`CohortKey`] carries no
/// ceremony id, so the same DKG output can be freshly sealed and endorsed under
/// any number of ceremonies. What the id binds is the transcripts, not the key
/// material -- and the one-composition rule that does bind a holder is
/// [`prove_possession`]'s, per share and per sealed composition rather than per
/// ceremony.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CeremonyId([u8; 32]);

impl CeremonyId {
    /// Derive a ceremony id from a human label and a random nonce.
    ///
    /// The nonce is what makes a restart a DIFFERENT ceremony: two attempts
    /// under the same label and nonce would let a cohort carry a component from
    /// the abandoned attempt into the new one, which is the grinding this
    /// ceremony is meant to cost something.
    pub fn new(label: &str, nonce: &[u8; 32]) -> CeremonyId {
        let mut h = Blake2b512::new();
        h.update(CEREMONY_TAG);
        h.update((label.len() as u64).to_le_bytes());
        h.update(label.as_bytes());
        h.update(nonce);
        CeremonyId(truncate(h))
    }

    /// A ceremony id with a freshly drawn nonce.
    pub fn draw<R: RngCore + CryptoRng>(label: &str, rng: &mut R) -> CeremonyId {
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        CeremonyId::new(label, &nonce)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The PedPoP transcript context for one cohort of this ceremony.
    ///
    /// Per-cohort rather than shared so that a commitment message broadcast in
    /// the owners' DKG cannot be replayed into the gates' -- the proof of
    /// knowledge inside it is over this context.
    pub(crate) fn dkg_context(&self, cohort: &str) -> [u8; 32] {
        let mut h = Blake2b512::new();
        h.update(DKG_CONTEXT_TAG);
        h.update(self.0);
        h.update((cohort.len() as u64).to_le_bytes());
        h.update(cohort.as_bytes());
        truncate(h)
    }
}

impl fmt::Debug for CeremonyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CeremonyId({})", hex32(&self.0))
    }
}

impl fmt::Display for CeremonyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex32(&self.0))
    }
}

// ---------------------------------------------------------------------------
// Wire material
// ---------------------------------------------------------------------------

/// Everything a proof of possession and a commitment are taken over: one
/// cohort's roster, threshold, component and verification shares.
///
/// Split out from [`ComponentReveal`] because the proofs are bound to it and
/// therefore cannot be inside it, and because it is exactly the material an
/// independent implementation needs in order to produce or check either.
///
/// [`ComponentClaim::of`] takes a [`CohortKey`], which only a completed DKG
/// produces -- so the honest path cannot be walked with a dealt cohort.
/// [`ComponentClaim::from_parts`] is the wire form, and is untrusted by
/// definition: an auditor receives one, it does not generate one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentClaim {
    cohort: &'static str,
    threshold: usize,
    /// Roster ids, ascending. Parallel to `verification_shares`.
    roster: Vec<u64>,
    component: RistrettoPoint,
    verification_shares: Vec<RistrettoPoint>,
}

impl ComponentClaim {
    /// The claim one cohort's completed DKG supports.
    pub fn of<C: ControlDomain>(key: &CohortKey<C>) -> ComponentClaim {
        ComponentClaim {
            cohort: C::NAME,
            threshold: key.threshold(),
            roster: key.roster().to_vec(),
            component: key.component(),
            verification_shares: key
                .verification_shares()
                .into_iter()
                .map(|(_, v)| v)
                .collect(),
        }
    }

    /// A claim received over the wire.
    pub fn from_parts(
        cohort: &'static str,
        threshold: usize,
        roster: Vec<u64>,
        component: RistrettoPoint,
        verification_shares: Vec<RistrettoPoint>,
    ) -> ComponentClaim {
        ComponentClaim {
            cohort,
            threshold,
            roster,
            component,
            verification_shares,
        }
    }

    pub fn cohort(&self) -> &'static str {
        self.cohort
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn roster(&self) -> &[u64] {
        &self.roster
    }

    pub fn component(&self) -> RistrettoPoint {
        self.component
    }

    pub fn verification_shares(&self) -> &[RistrettoPoint] {
        &self.verification_shares
    }

    /// The verification share published for `participant`.
    pub fn verification_share(&self, participant: u64) -> Option<RistrettoPoint> {
        let pos = self.roster.iter().position(|&id| id == participant)?;
        self.verification_shares.get(pos).copied()
    }

    /// Roster/threshold/verification-share well-formedness, in the cohort's own
    /// control domain.
    fn check_shape<C: ControlDomain>(&self) -> Result<()> {
        if self.cohort != C::NAME {
            return Err(CeremonyError::CohortMismatch {
                expected: C::NAME,
                found: self.cohort,
            });
        }
        if self.roster.is_empty() {
            return Err(CeremonyError::roster::<C>(crate::Error::EmptyRoster));
        }
        if self.roster.len() > MAX_AUDITED_ROSTER {
            return Err(CeremonyError::RosterTooLargeToAudit {
                cohort: C::NAME,
                n: self.roster.len(),
            });
        }
        if self.threshold == 0 {
            return Err(CeremonyError::roster::<C>(crate::Error::ThresholdZero));
        }
        if self.threshold > self.roster.len() {
            return Err(CeremonyError::roster::<C>(
                crate::Error::ThresholdExceedsRoster {
                    threshold: self.threshold,
                    roster: self.roster.len(),
                },
            ));
        }
        if self.verification_shares.len() != self.roster.len() {
            return Err(CeremonyError::MalformedClaim {
                cohort: C::NAME,
                roster: self.roster.len(),
                verification_shares: self.verification_shares.len(),
            });
        }
        for (i, &id) in self.roster.iter().enumerate() {
            if id == 0 {
                return Err(CeremonyError::roster::<C>(
                    crate::Error::ReservedParticipantId,
                ));
            }
            if self.roster[..i].contains(&id) {
                return Err(CeremonyError::roster::<C>(
                    crate::Error::DuplicateParticipant(id),
                ));
            }
            if !C::owns(id) {
                return Err(CeremonyError::IdOutsideDomain {
                    cohort: C::NAME,
                    id,
                    base: C::ID_BASE,
                    end: C::ID_BASE + NAMESPACE_SPAN,
                });
            }
        }
        // The same rule `Roster::new` applies to the participants, applied here
        // to the wire. Position `k` of this roster is Shamir evaluation point
        // `k + 1` for both the audit's interpolation and every holder's
        // `CohortShare::term`, so a roster published in a different order than
        // the one the cohort ran is a different dealing wearing the same shares.
        // The auditor cannot delegate this to the DKG: it never saw the DKG.
        if self.roster.windows(2).any(|w| w[0] >= w[1]) {
            return Err(CeremonyError::RosterNotCanonical {
                cohort: C::NAME,
                roster: self.roster.clone(),
            });
        }
        // Before the per-seat check below, so that a cohort claiming nothing at
        // all is reported as what it is rather than as its first empty seat.
        if self.component.is_identity() {
            return Err(CeremonyError::IdentityComponent { cohort: C::NAME });
        }
        // An identity verification share satisfies EVERY proof of possession
        // (`z*G == R + c*0` reduces to `z*G == R`), so a seat carrying one is a
        // seat with no share behind it that the proof check cannot distinguish
        // from a real one. Refused here, before `check_pops` is asked a question
        // it has no way to answer.
        for (pos, &id) in self.roster.iter().enumerate() {
            if self.verification_shares[pos].is_identity() {
                return Err(CeremonyError::IdentityVerificationShare {
                    cohort: C::NAME,
                    participant: id,
                });
            }
        }
        Ok(())
    }

    /// The verification shares lie on a polynomial of degree EXACTLY
    /// `threshold - 1` whose value at zero is `component`.
    ///
    /// Two halves, and both are needed:
    ///
    ///   * **At most `threshold - 1`.** Every `threshold`-subset interpolates to
    ///     the same point, and that point is the declared component. This is the
    ///     "inconsistent dealing" check: shares off the polynomial give an
    ///     address only SOME quorums can spend, discovered after funding. It is
    ///     also the form a signer depends on, since a signer interpolates over
    ///     whichever quorum turned up.
    ///   * **At least `threshold - 1`.** No `threshold - 1`-subset interpolates
    ///     to the component. The first half alone is ONE-SIDED: a genuine 2-of-4
    ///     dealing satisfies every 3-subset test of a declared 3-of-4, because a
    ///     degree-1 polynomial is also a degree-2 polynomial. Without this a
    ///     cohort publishes any threshold at or above its real one, [`audit`]
    ///     returns `Ok`, and [`AuditedRoot::structure`] reports seats to a funder
    ///     that the cohort does not need.
    ///
    /// Together they are the polynomial condition, not an approximation of it.
    fn check_consistency<C: ControlDomain>(&self) -> Result<()> {
        // The evaluation points are not recoverable from the artifact and do
        // not need to be, because they are not free: PedPoP evaluates its
        // polynomial at exactly `1..=n`, assigned by participant index, so
        // `1..=n` in roster order is the DKG's own labelling and the only one
        // that reconstructs its group key. It is what `CohortShare::term` uses
        // at the holder's end and what `CompositeSpend::from_ceremony` rebuilds,
        // and `check_shape` has already forced the roster ascending so the
        // position-to-point assignment is canonical. (Interpolation at zero is
        // NOT invariant under relabelling the coordinates -- the labelling is
        // pinned by PedPoP, not free to choose.)
        let points: Vec<u64> = (1..=self.roster.len() as u64).collect();
        let at = |threshold: usize| {
            crate::Cohort::distributed(
                C::NAME,
                threshold,
                &self.roster,
                &points,
                &self.verification_shares,
            )
            .map_err(CeremonyError::roster::<C>)
        };

        let cohort = at(self.threshold)?;
        let mut first: Option<(Vec<u64>, RistrettoPoint)> = None;
        for quorum in subsets_of(&self.roster, self.threshold) {
            let value = cohort.public(&quorum).map_err(CeremonyError::roster::<C>)?;
            match &first {
                None => first = Some((quorum, value)),
                Some((a, expected)) => {
                    if value != *expected {
                        return Err(CeremonyError::InconsistentVerificationShares {
                            cohort: C::NAME,
                            a: a.clone(),
                            b: quorum,
                        });
                    }
                }
            }
        }
        let (a, value) = first.expect("threshold <= roster, so at least one quorum exists");
        if value != self.component {
            return Err(CeremonyError::ComponentNotInterpolated {
                cohort: C::NAME,
                quorum: a,
            });
        }

        // The lower bound, over EVERY subset smaller than the declared
        // threshold and not only the `(t-1)`-subsets.
        //
        // WHY EVERY SIZE. Checking `t-1` alone establishes that the polynomial's
        // degree is exactly `t-1`. Degree is not minimum coalition size, and the
        // two come apart from `t = 3` upward. Review supplied the counterexample:
        //
        //     p(x) = b + a*x*(x - 1)     over evaluation points 1, 2, 3
        //
        // has degree 2, so no PAIR of seats interpolates to `b` and a declared
        // threshold of 3 is not an overstated degree -- but `p(1) = b`, so seat 1
        // holds the component outright. `AuditedRoot::structure` reports the
        // declared threshold to a funder as the number of seats that must act,
        // so the claim being checked has to be the coalition one.
        // `composition.rs::a_dealing_one_seat_can_open_is_refused_even_at_the_declared_degree`
        // performs exactly that dealing, and returned `Ok` from `audit` before
        // this loop enumerated the smaller sizes.
        //
        // `threshold == 1` needs no check: the only smaller subset is empty, it
        // interpolates to the identity, and `check_shape` has already refused an
        // identity component -- so a 1-of-n cohort cannot be overstating
        // anything.
        //
        // Cost: `sum_{s=1}^{t-1} C(n, s)` interpolations, bounded by `2^n` and so
        // by `2^MAX_AUDITED_ROSTER`. See that constant for the budget.
        for size in 1..self.threshold {
            let below = at(size)?;
            for quorum in subsets_of(&self.roster, size) {
                let value = below.public(&quorum).map_err(CeremonyError::roster::<C>)?;
                if value == self.component {
                    return Err(CeremonyError::ThresholdOverstated {
                        cohort: C::NAME,
                        threshold: self.threshold,
                        quorum,
                    });
                }
            }
        }
        Ok(())
    }
}

/// One cohort's published, unopened component.
///
/// A hash over the cohort's CLAIM -- component, verification shares, roster,
/// threshold -- plus the ceremony id, under a salt. It does NOT cover the
/// proofs of possession, which a reveal also carries; those are bound to the
/// claim from the other direction, by [`pop_challenge`]. Publishing this before
/// the other cohort reveals is half the non-adaptivity argument, and
/// [`prove_possession`] is the other half.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ComponentCommitment {
    cohort: &'static str,
    digest: [u8; 32],
}

impl ComponentCommitment {
    /// Seal a component claim under a salt.
    pub fn seal(
        ceremony: &CeremonyId,
        claim: &ComponentClaim,
        salt: &[u8; 32],
    ) -> ComponentCommitment {
        ComponentCommitment {
            cohort: claim.cohort,
            digest: commitment_digest(ceremony, claim, salt),
        }
    }

    pub fn cohort(&self) -> &'static str {
        self.cohort
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

impl fmt::Debug for ComponentCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ComponentCommitment")
            .field("cohort", &self.cohort)
            .field("digest", &hex32(&self.digest))
            .finish()
    }
}

/// A commitment plus the organisation that published it.
///
/// # What this adds, and what was missing without it
///
/// A [`ComponentCommitment`] is a hash. It says what a cohort sealed; it says
/// nothing about WHO sealed it, so an artifact made of bare commitments cannot
/// distinguish a composition between two organisations from one process that
/// ran both DKGs and sealed both halves. Everything else [`audit`] checks --
/// the interpolation, the proofs of possession, the commitment openings -- is
/// satisfied just as well by the single process, because it really does hold
/// every share of both cohorts and every one of those checks is a statement
/// about key material rather than about parties.
/// `tests/attribution.rs::one_process_can_produce_an_artifact_that_passes_every_structural_check`
/// performs that, so the gap is exhibited rather than asserted.
///
/// The signature covers the ceremony id, the cohort name and the digest, under
/// a tag of its own. So it cannot be lifted from another ceremony, cannot be
/// moved from the owner slot to the gate slot, and cannot be reused as any of
/// the round-message signatures `crates/ceremony` produces under the same key.
///
/// # What it still does not add
///
/// **Chronology.** A signature has no time in it. This says the named
/// organisation endorsed this digest, never that it did so before the other
/// side revealed; that half is still [`prove_possession`]'s, at the share.
///
/// **Two organisations.** Two distinct keys are two distinct keys. One party
/// holding both private keys signs both halves and the audit passes -- the
/// honest residual, stated in
/// `tests/attribution.rs::the_residual_is_a_party_that_holds_both_organisations_identity_keys`.
/// What a funder gets is that the artifact now names the parties it is
/// checking against keys it obtained from those parties, so the impostor must
/// hold their long-term keys rather than merely run two processes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SignedCommitment {
    commitment: ComponentCommitment,
    signer: IdentityPublic,
    signature: IdentitySignature,
}

impl SignedCommitment {
    /// Endorse a commitment as the organisation holding `key`.
    pub fn create(
        ceremony: &CeremonyId,
        commitment: ComponentCommitment,
        key: &IdentityKey,
    ) -> SignedCommitment {
        SignedCommitment {
            commitment,
            signer: key.public(),
            signature: key.sign(&commitment_signing_payload(ceremony, &commitment)),
        }
    }

    /// A signed commitment received over the wire. Untrusted until [`audit`]
    /// says otherwise, for the same reason [`ComponentReveal::from_parts`] is:
    /// an auditor receives one, it does not produce one. In particular the
    /// `signer` here is a CLAIM, and it is only worth anything once compared
    /// against a key the funder got from the organisation itself.
    pub fn from_parts(
        commitment: ComponentCommitment,
        signer: IdentityPublic,
        signature: IdentitySignature,
    ) -> SignedCommitment {
        SignedCommitment {
            commitment,
            signer,
            signature,
        }
    }

    pub fn commitment(&self) -> ComponentCommitment {
        self.commitment
    }

    /// The key this signature CLAIMS to be from. Not evidence on its own.
    pub fn signer(&self) -> IdentityPublic {
        self.signer
    }

    pub fn signature(&self) -> &IdentitySignature {
        &self.signature
    }

    /// This commitment is endorsed by `expected`, and the endorsement verifies.
    ///
    /// The order of the two checks is deliberate: a funder whose artifact was
    /// signed by somebody else entirely should be told WHO, which is the more
    /// actionable failure, rather than being told a signature it never expected
    /// did not verify under a key it never named.
    fn check<C: ControlDomain>(
        &self,
        ceremony: &CeremonyId,
        expected: &IdentityPublic,
    ) -> Result<()> {
        if self.signer != *expected {
            return Err(CeremonyError::CommitmentSignerUnexpected {
                cohort: C::NAME,
                expected: *expected,
                found: self.signer,
            });
        }
        // Verified under `expected`, the funder's key, and NOT under
        // `self.signer` -- even though the two are equal by the check just
        // above. An artifact must never be verified against a key it supplied
        // itself, and writing it this way means that stays true if the two
        // checks are ever reordered or one of them is lost.
        if !expected.verify(
            &commitment_signing_payload(ceremony, &self.commitment),
            &self.signature,
        ) {
            return Err(CeremonyError::CommitmentSignatureInvalid {
                cohort: C::NAME,
                signer: *expected,
            });
        }
        Ok(())
    }
}

/// The two organisations a funder expects to jointly control the root.
///
/// Grouped into one value rather than passed as two loose keys so that [`audit`]
/// cannot be called with one side named and the other defaulted: a funder names
/// both parties or it does not audit. Swapping the two is fail-CLOSED -- each
/// key is checked against its own cohort's commitment, so a transposed pair
/// yields [`CeremonyError::CommitmentSignerUnexpected`] rather than a pass.
///
/// **These keys must come from the organisations, not from the artifact.**
/// [`SignedCommitment::signer`] is whatever the artifact says; checking the
/// artifact against its own claims establishes nothing at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Parties {
    owners: IdentityPublic,
    gates: IdentityPublic,
}

impl Parties {
    pub fn new(owners: IdentityPublic, gates: IdentityPublic) -> Parties {
        Parties { owners, gates }
    }

    pub fn owners(&self) -> &IdentityPublic {
        &self.owners
    }

    pub fn gates(&self) -> &IdentityPublic {
        &self.gates
    }

    /// The two named organisations are two.
    ///
    /// Checked in [`audit`] and NOT in [`Parties::new`], which stays infallible:
    /// naming two keys is not the error, auditing an artifact as though one
    /// organisation were two is. Keeping it out of the constructor also keeps it
    /// out of the doctests and fixtures that build a `Parties` in order to
    /// exhibit a refusal.
    ///
    /// [`production::authorize_release`](crate::production::authorize_release)
    /// deliberately does not repeat it. Its `endorsers` come from a
    /// [`CompositeSpend`](crate::CompositeSpend) that only
    /// `from_ceremony` can build, and only from an
    /// [`AuditedAddress`] -- so a degenerate pair cannot reach it: either the
    /// audit refused, or the spend's endorsers are two distinct keys and a
    /// `Parties::new(k, k)` passed to the gate fails `check_endorser` on one
    /// side or the other. One check, one place, nothing to drift.
    fn check_distinct(&self) -> Result<()> {
        if self.owners == self.gates {
            return Err(CeremonyError::PartiesNotDistinct { key: self.owners });
        }
        Ok(())
    }

    /// The key expected for cohort `C`.
    ///
    /// This is an `if`/`else` on `C::NAME`, not an exhaustive match, and the
    /// difference is worth naming because "total" would be too strong.
    /// [`ControlDomain`] is `sealed::Sealed`, so no crate outside this one can
    /// add a domain and the `else` really is [`Gates`] for every caller
    /// downstream -- that part is compiler-enforced. What it is NOT enforced
    /// against is a third domain added INSIDE this crate, which would compile
    /// and route silently to the gate key. Enforced by sealing, in other words,
    /// not by exhaustiveness. `SealedComposition::signed_for` has the same
    /// shape and the same caveat.
    fn expected_for<C: ControlDomain>(&self) -> &IdentityPublic {
        if C::NAME == Owners::NAME {
            &self.owners
        } else {
            &self.gates
        }
    }
}

/// One participant's proof of knowledge of its DKG share.
///
/// A Schnorr proof over `V_i = s_i*G`, with a challenge that names the
/// ceremony, both sealed components, the cohort, its roster, its threshold, the
/// component being proved, every verification share, and the participant.
/// Nothing about it is transferable: change any of those and the challenge
/// changes -- under the collision resistance of Blake2b-512 and of the
/// hash-to-scalar reduction, which is the only sense in which that holds.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Pop {
    nonce_public: RistrettoPoint,
    response: Scalar,
}

impl Pop {
    /// Reassemble a proof received over the wire.
    ///
    /// Public because a proof is untrusted data by definition -- an auditor
    /// receives one, it does not produce one -- and because the rejection
    /// tests need to be able to present a forged one. Every security property
    /// is in [`audit`], not in who can call this.
    pub fn from_parts(nonce_public: RistrettoPoint, response: Scalar) -> Pop {
        Pop {
            nonce_public,
            response,
        }
    }

    pub fn nonce_public(&self) -> RistrettoPoint {
        self.nonce_public
    }

    pub fn response(&self) -> Scalar {
        self.response
    }

    /// Prove knowledge of `secret`, the discrete log of the verification share
    /// `claim` publishes for `participant`.
    ///
    /// **This signs whatever claim it is handed.** It checks that `secret` opens
    /// the holder's OWN entry and nothing else, so a caller that takes a claim
    /// from a coordinator is signing that coordinator's roster, threshold and
    /// component. [`Pop::prove_for`] is the entry point that checks a claim
    /// against the holder's own key generation, and [`prove_possession`] is the
    /// one that derives the claim so there is nothing to check.
    ///
    /// It refuses to produce a proof that would not verify: a secret that does
    /// not open the published share is [`CeremonyError::PopFailed`] here rather
    /// than a proof somebody publishes and is rejected on. That is a
    /// well-formedness check, not a safety one -- it says the proof will verify,
    /// never that the claim is worth proving.
    ///
    /// Reachable from outside the crate only through `Pop::prove_unchecked`,
    /// behind the `unchecked-proving` feature.
    pub(crate) fn prove(
        sealed: &SealedComposition,
        claim: &ComponentClaim,
        participant: u64,
        secret: &Scalar,
    ) -> Result<Pop> {
        let v = claim
            .verification_share(participant)
            .ok_or(CeremonyError::PopUnexpected {
                cohort: claim.cohort,
                participant,
            })?;
        if secret * G != v {
            return Err(CeremonyError::PopFailed {
                cohort: claim.cohort,
                participant,
            });
        }

        // Derived, not sampled, for the reason `mlsag` derives its nonces: a
        // prover restarted from a snapshot with a replayed RNG would answer two
        // different challenges with one nonce, giving up the share as
        // `(z - z')/(c - c')`.
        //
        // WHY THE WHOLE CLAIM IS ABSORBED HERE: determinism is only safe if
        // every independent input to the CHALLENGE is either absorbed into the
        // nonce too or derived from something that is. `pop_challenge` absorbs
        // the claim -- threshold, roster, component, every verification share --
        // and this signs a caller-supplied claim. With the claim omitted from
        // the nonce, one holder answering two claims that differ in any of those
        // fields (a peer's verification share, say, which no holder can check
        // without re-running someone else's DKG) produces one `R` against two
        // challenges, and the share falls out by division.
        //
        // Both hashes call `absorb_composition`, so the same argument covers the
        // two SIGNER KEYS the challenge names: a holder induced to prove under
        // two compositions that seal identical digests but attribute the other
        // half to different organisations would otherwise reuse one `R` across
        // two challenges. Keeping the two nonce/challenge preambles in ONE
        // function is deliberate -- it is what stops a later field being added
        // to the challenge alone, which is precisely the divergence that leaks
        // the share.
        //
        // The two hashes are NOT over identical input lists, and do not need to
        // be: the challenge also takes `V_i`, which is selected out of (claim,
        // participant) and checked equal to `secret*G` just above, and `R`,
        // which is a function of this nonce. Neither is free. The claim was.
        let mut h = Blake2b512::new();
        h.update(POP_TAG);
        h.update(b"nonce");
        absorb_composition(&mut h, sealed);
        absorb_claim(&mut h, claim);
        h.update(participant.to_le_bytes());
        h.update(secret.as_bytes());
        let nonce = Zeroizing::new(Scalar::from_hash(h));
        let nonce_public = *nonce * G;

        let challenge = pop_challenge(sealed, claim, participant, &v, &nonce_public);
        Ok(Pop {
            nonce_public,
            response: *nonce + challenge * secret,
        })
    }

    /// [`Pop::prove`], reachable from outside this crate.
    ///
    /// Behind the `unchecked-proving` feature, which is off by default. The name
    /// is `unchecked` and not `raw` or `low_level` because what it omits is a
    /// CHECK: it signs whatever claim it is handed, so a caller that takes its
    /// claim from a coordinator signs that coordinator's roster, threshold and
    /// component.
    ///
    /// **What this gate is worth, stated rather than implied.** It moves the
    /// default: the first prover a holder finds is
    /// [`CohortShare::prove`](crate::CohortShare::prove), which checks. It is
    /// NOT a containment boundary, and four things it does not do are worth
    /// knowing before anybody rests on it. Each was overstated in an earlier
    /// version of this comment and is written here as review left it:
    ///
    ///   * **A HOLDER can recover `s_i` and prove as often as it likes**, with or
    ///     without this feature --
    ///     `composition.rs::a_holder_can_recover_its_own_share_through_public_api`
    ///     performs the division. It is a holder-only recovery, not an outsider's:
    ///     the division is by a public Lagrange weight, but the value divided is
    ///     [`ParticipantTerm::weight`](crate::ParticipantTerm), which the holder
    ///     obtains from its own secret-bearing [`CohortShare`]. Saying "from
    ///     public material" without that qualification was wrong.
    ///   * **It does not touch the dealer forgery in `tests/forgery.rs`.** The
    ///     conclusion holds; the mechanism previously given for it did not.
    ///     [`Cohort::deal_in`](crate::Cohort) yields a
    ///     [`Cohort`](crate::Cohort), not a [`CohortShare`] -- a `CohortShare`
    ///     exists only after a DKG confirms -- so a dealer does NOT reach the
    ///     checked prover, and `forgery.rs` uses this function. What the gate
    ///     costs such a dealer is a feature flag, which is not a defence.
    ///   * **`Pop::from_parts` is public and [`audit`] accepts any proof that
    ///     verifies.** The artifact carries no evidence of which prover produced
    ///     it, or that its producer compiled without this feature. A verifier
    ///     built feature-off accepts feature-on and hand-written proofs alike.
    ///     This gate constrains a holder's SOURCE, never a verifier's input.
    ///   * **Cargo unifies features within one build**, so the gate is per build
    ///     graph, not per crate, and not something a deployment's own manifest
    ///     fully controls: any dependency in the same graph, or a
    ///     `--features` on the command line, can turn it on. Verified rather than
    ///     assumed: with a probe calling this from `crates/ceremony`'s tests,
    ///     `cargo test -p ceremony` fails with "no function or associated item
    ///     named `prove_unchecked` found", and `cargo test` over the whole
    ///     workspace compiles and passes, because two-cohort's own dev-dependency
    ///     turns the feature on for every crate in that build. That probe is a
    ///     reproducible observation and not a checked-in regression test; there
    ///     is no test in this repo that would fail if the gate were removed.
    #[cfg(feature = "unchecked-proving")]
    pub fn prove_unchecked(
        sealed: &SealedComposition,
        claim: &ComponentClaim,
        participant: u64,
        secret: &Scalar,
    ) -> Result<Pop> {
        Pop::prove(sealed, claim, participant, secret)
    }

    /// **The checked holder entry point.** Prove possession under a claim
    /// received from a coordinator, refusing any claim that is not this holder's
    /// own and any composition that does not seal it.
    ///
    /// The deployment shape [`ComponentClaim`] describes -- a coordinator
    /// assembles the cohort's claim from the DKG's public output and each holder
    /// signs it -- is safe only if each holder checks what it is signing. Two
    /// checks, and they answer different attacks:
    ///
    ///   * the claim must equal [`ComponentClaim::of`] over the holder's own
    ///     [`CohortKey`], field for field, so a coordinator that inflates the
    ///     threshold, permutes the roster, substitutes a peer's verification
    ///     share or swaps the component gets [`CeremonyError::ClaimNotOwn`] from
    ///     every honest holder rather than a signature over its version of
    ///     events;
    ///   * `salt` must be the salt this cohort sealed under, and the resulting
    ///     commitment must be the one this composition carries for this cohort.
    ///     Without that, a holder spends its one proof (see
    ///     [`prove_possession`]) on a composition its own reveal can never open
    ///     -- a coordinator could burn every holder's shot and force a restart
    ///     without ever producing an artifact.
    ///
    /// Prefer this to [`prove_possession`] wherever the claim and salt arrive
    /// over the wire, which in a real deployment is everywhere.
    pub fn prove_for<C: ControlDomain>(
        sealed: &SealedComposition,
        share: &CohortShare<C>,
        claim: &ComponentClaim,
        salt: &[u8; 32],
    ) -> Result<Pop> {
        if *claim != ComponentClaim::of(share.key()) {
            return Err(CeremonyError::ClaimNotOwn {
                cohort: C::NAME,
                participant: share.id(),
            });
        }
        // Checked BEFORE `note_proved`, so a composition this holder's reveal
        // could not open does not consume its one proof.
        if ComponentCommitment::seal(&sealed.ceremony, claim, salt)
            != sealed.signed_for::<C>().commitment()
        {
            return Err(CeremonyError::CommitmentMismatch { cohort: C::NAME });
        }
        share.note_proved(sealed)?;
        Pop::prove(sealed, claim, share.id(), share.secret())
    }

    fn verify(&self, challenge: &Scalar, verification_share: &RistrettoPoint) -> bool {
        // s*G == R + c*V
        self.response * G == self.nonce_public + challenge * verification_share
    }
}

impl fmt::Debug for Pop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pop").finish_non_exhaustive()
    }
}

/// One cohort's opened component: the claim the commitment sealed, plus the
/// per-participant proofs of possession and the salt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentReveal {
    claim: ComponentClaim,
    pops: BTreeMap<u64, Pop>,
    salt: [u8; 32],
}

impl ComponentReveal {
    /// Assemble a cohort's reveal, refusing immediately if a proof is missing
    /// or does not verify.
    ///
    /// A cohort should not publish a reveal it already knows the other side
    /// will reject, so this runs the same proof check [`audit`] will run.
    ///
    /// Said precisely, because the looser version was wrong: each proof is
    /// verified against the VERIFICATION SHARE `V_i` published for that seat,
    /// not against the component. A participant holding a share of a different
    /// key than its peers is caught here only if its own `V_i` is the one in the
    /// claim. That the shares add up to the declared component is a separate
    /// check, `check_consistency`, and it runs in [`audit`].
    pub fn assemble(
        sealed: &SealedComposition,
        claim: ComponentClaim,
        pops: BTreeMap<u64, Pop>,
        salt: [u8; 32],
    ) -> Result<ComponentReveal> {
        let reveal = ComponentReveal { claim, pops, salt };
        reveal.check_pops(sealed)?;
        Ok(reveal)
    }

    /// A reveal received over the wire. Untrusted until [`audit`] says
    /// otherwise, which is why there is nothing to check here.
    pub fn from_parts(
        claim: ComponentClaim,
        pops: BTreeMap<u64, Pop>,
        salt: [u8; 32],
    ) -> ComponentReveal {
        ComponentReveal { claim, pops, salt }
    }

    pub fn claim(&self) -> &ComponentClaim {
        &self.claim
    }

    pub fn cohort(&self) -> &'static str {
        self.claim.cohort
    }

    pub fn threshold(&self) -> usize {
        self.claim.threshold
    }

    pub fn roster(&self) -> &[u64] {
        &self.claim.roster
    }

    pub fn component(&self) -> RistrettoPoint {
        self.claim.component
    }

    pub fn verification_shares(&self) -> &[RistrettoPoint] {
        &self.claim.verification_shares
    }

    pub fn pops(&self) -> &BTreeMap<u64, Pop> {
        &self.pops
    }

    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    /// The commitment this reveal opens.
    ///
    /// Public so a funder that observed the commit broadcast can recompute it
    /// and compare, which is the only way the ORDERING half of the defence can
    /// be checked from outside.
    pub fn commitment(&self, ceremony: &CeremonyId) -> ComponentCommitment {
        ComponentCommitment::seal(ceremony, &self.claim, &self.salt)
    }

    /// Every roster member proved knowledge of its share, under `sealed`.
    fn check_pops(&self, sealed: &SealedComposition) -> Result<()> {
        // This indexes `verification_shares` by roster position, and
        // `ComponentReveal::assemble` accepts a claim built by
        // `ComponentClaim::from_parts` -- which is wire data and may say
        // anything. `audit` reaches here only after `check_shape`, but this
        // path does not, and an out-of-bounds index would be a panic reachable
        // from safe public API.
        if self.claim.verification_shares.len() != self.claim.roster.len() {
            return Err(CeremonyError::MalformedClaim {
                cohort: self.claim.cohort,
                roster: self.claim.roster.len(),
                verification_shares: self.claim.verification_shares.len(),
            });
        }
        for &id in self.pops.keys() {
            if !self.claim.roster.contains(&id) {
                return Err(CeremonyError::PopUnexpected {
                    cohort: self.claim.cohort,
                    participant: id,
                });
            }
        }
        for (pos, &id) in self.claim.roster.iter().enumerate() {
            let pop = self.pops.get(&id).ok_or(CeremonyError::PopMissing {
                cohort: self.claim.cohort,
                participant: id,
            })?;
            let v = self.claim.verification_shares[pos];
            let challenge = pop_challenge(sealed, &self.claim, id, &v, &pop.nonce_public);
            if !pop.verify(&challenge, &v) {
                return Err(CeremonyError::PopFailed {
                    cohort: self.claim.cohort,
                    participant: id,
                });
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The ceremony
// ---------------------------------------------------------------------------

/// Both components sealed and endorsed, neither opened.
///
/// The type carries HALF the ordering rule: a [`Pop`] cannot be produced without
/// one of these, a [`ComponentReveal`] cannot be assembled without one, and one
/// cannot exist until both commitment VALUES are in hand. So a cohort that has
/// not received the other's commitment has nothing to prove possession under.
///
/// It is not evidence that an exchange took place. [`ComponentCommitment::seal`]
/// takes any claim, so one party can build both commitments and hence a
/// `SealedComposition` unilaterally; and holding two commitment values at
/// proving time says nothing about whether the other side had already opened
/// one. The other half of the rule is in [`prove_possession`], which refuses to
/// answer a second sealed composition -- read that first.
///
/// Each commitment is a [`SignedCommitment`], so the composition NAMES the two
/// organisations as well as sealing the two components -- and the proofs of
/// possession are bound to those names as well as to the two digests, so an
/// honest holder's proof is only valid in a composition between the two parties
/// it believed it was dealing with. See [`pop_challenge`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SealedComposition {
    ceremony: CeremonyId,
    owners: SignedCommitment,
    gates: SignedCommitment,
}

impl SealedComposition {
    /// Both signed commitments received.
    ///
    /// Checks the cohorts and NOT the signatures. That is deliberate and matches
    /// [`ComponentReveal::from_parts`]: a `SealedComposition` is assembled from
    /// wire data by auditors as well as by participants, and if this verified
    /// the signatures then a forged artifact would fail at construction, where a
    /// funder is not looking, instead of at [`audit`], which is the one call a
    /// funder makes.
    ///
    /// The accurate form of the rule, which an earlier version overstated as
    /// "every cryptographic check in this module is in `audit`": every check an
    /// UNTRUSTED artifact must pass before acceptance is in `audit`, and none of
    /// them is anywhere else only. Checks do occur outside it --
    /// [`ComponentReveal::assemble`] verifies proofs so a cohort does not publish
    /// a reveal that will be rejected, and the prover verifies `s*G == V` so
    /// a holder does not emit a proof that will be -- but both are conveniences
    /// for honest parties, and `audit` repeats them.
    pub fn new(
        ceremony: CeremonyId,
        owners: SignedCommitment,
        gates: SignedCommitment,
    ) -> Result<SealedComposition> {
        if owners.commitment.cohort != Owners::NAME {
            return Err(CeremonyError::CohortMismatch {
                expected: Owners::NAME,
                found: owners.commitment.cohort,
            });
        }
        if gates.commitment.cohort != Gates::NAME {
            return Err(CeremonyError::CohortMismatch {
                expected: Gates::NAME,
                found: gates.commitment.cohort,
            });
        }
        Ok(SealedComposition {
            ceremony,
            owners,
            gates,
        })
    }

    pub fn ceremony(&self) -> &CeremonyId {
        &self.ceremony
    }

    pub fn commitments(&self) -> (SignedCommitment, SignedCommitment) {
        (self.owners, self.gates)
    }

    /// The signed commitment this composition carries for cohort `C`.
    ///
    /// `SealedComposition::new` has already required the two to be of the right
    /// cohorts, and [`ControlDomain`] is sealed, so the `else` branch is
    /// [`Gates`] for every caller outside this crate. See
    /// `Parties::expected_for` for what sealing does and does not enforce --
    /// a third domain added inside this crate would compile and route here.
    fn signed_for<C: ControlDomain>(&self) -> SignedCommitment {
        if C::NAME == Owners::NAME {
            self.owners
        } else {
            self.gates
        }
    }

    /// Open both components, as a composition between `parties`.
    ///
    /// Checks, in order: each commitment is endorsed by the organisation
    /// `parties` names for it; each is a well-formed cohort in its own domain;
    /// each reveal opens the commitment published for it; each participant
    /// proved possession; the verification shares are consistent at the declared
    /// threshold.
    ///
    /// Takes `parties` for the same reason [`audit`] does. A cohort assembling
    /// the artifact knows perfectly well which organisation it exchanged
    /// commitments with, and an `open` that skipped the check would hand back an
    /// artifact its own producer never verified the attribution of.
    pub fn open(
        self,
        owners: ComponentReveal,
        gates: ComponentReveal,
        parties: &Parties,
    ) -> Result<CompositionArtifact> {
        let artifact = CompositionArtifact {
            sealed: self,
            owners,
            gates,
        };
        audit(&artifact, parties)?;
        Ok(artifact)
    }
}

/// Prove possession of one participant's DKG share.
///
/// The share-holder's entry point: it cannot get the participant, the claim or
/// the secret wrong, because all three come out of its own [`CohortShare`].
///
/// # It answers ONE sealed composition, and refuses a second
///
/// **Read the limits below before relying on this.** It is a safety catch on
/// the holder's own software, not a capability boundary: it stops a holder that
/// goes through this function from being talked into a second proof. It does
/// not, and cannot, stop a process that already holds the share from producing
/// one some other way.
///
/// This is where the non-adaptivity half of the defence is enforced, and it is
/// enforced here because it cannot be enforced in the artifact. The grinding
/// attack does not need to break commit-then-reveal; it needs the honest cohort
/// to prove twice:
///
/// ```text
///   1. gates seal a JUNK component            -> D_junk
///   2. owners prove and reveal under (D_o, D_junk); B_owner is now public
///   3. gates run their DKG repeatedly, score each draw against B_owner,
///      and seal the winner                    -> D_g
///   4. gates tell the owners the first exchange failed and ask them to
///      prove again under (D_o, D_g)
/// ```
///
/// Step 4 is the whole attack. The owners' first proofs do not transfer -- the
/// challenge names both digests -- so the gates cannot reuse them, and an
/// artifact under `(D_o, D_g)` audits perfectly if and only if the owners
/// answered it. [`CohortShare`] therefore remembers the one
/// [`SealedComposition`] it has answered and returns
/// [`CeremonyError::ProofAlreadyIssued`] for any other. Asking again for the
/// SAME one is idempotent, because a lost message is not an attack.
///
/// # What this rule does not reach
///
///   * **A caller that does not go through here.** [`CohortShare::term`] returns
///     `lambda_i * s_i` and [`ParticipantTerm::weight`](crate::ParticipantTerm::weight)
///     hands over that scalar, while `lambda_i` is
///     [`lagrange_at_zero`](crate::lagrange_at_zero) over public data. So a
///     holder can recover its own `s_i` through safe public API and call
///     `Pop::prove_unchecked` as often as it likes -- see there for what the
///     `unchecked-proving` feature gate is and is not worth.
///     `composition.rs::a_holder_can_recover_its_own_share_through_public_api`
///     performs exactly that, so this limit is exhibited rather than asserted.
///     The rule is worth having anyway -- the attack is a coordinator talking an
///     honest holder into a second proof, and an honest holder calls this
///     function -- but it is discipline, not arithmetic, and an artifact carries
///     no evidence that any holder observed it.
///   * **A holder restarted from cold.** The memory is in the share, in this
///     process. Persisting it is a deployment concern this crate cannot reach.
///   * **A fresh ceremony.** A [`CohortShare`] carries no [`CeremonyId`] -- the
///     id is bound into the PedPoP transcript, which binds the DKG's MESSAGES,
///     not the key material that comes out of them. So this says nothing about a
///     cohort that abandons the ceremony and demands a new one, which remains
///     the governance question described in the module docs.
///   * **A composition that can never open.** This records whatever
///     [`SealedComposition`] it is first handed, without checking that the
///     commitment on its own side is one its own claim opens. A coordinator can
///     therefore burn a holder's one shot on a composition that goes nowhere.
///     That is a liveness attack, not a theft: it forces a restart under a new
///     [`CeremonyId`], which is visible to both cohorts.
pub fn prove_possession<C: ControlDomain>(
    sealed: &SealedComposition,
    share: &CohortShare<C>,
) -> Result<Pop> {
    share.note_proved(sealed)?;
    Ok(Pop::prove(
        sealed,
        &ComponentClaim::of(share.key()),
        share.id(),
        share.secret(),
    )
    .expect("a share's own secret opens its own published verification share"))
}

/// A fresh commitment salt.
pub fn draw_salt<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);
    salt
}

// ---------------------------------------------------------------------------
// The artifact
// ---------------------------------------------------------------------------

/// The auditable output of one composition ceremony.
///
/// Everything [`audit`] needs and nothing it does not. A funder deciding
/// whether to pay an address is handed one of these and calls [`audit`]; it
/// does not follow a checklist and it does not have to have been present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompositionArtifact {
    sealed: SealedComposition,
    owners: ComponentReveal,
    gates: ComponentReveal,
}

impl CompositionArtifact {
    /// Reassemble an artifact received over the wire. Untrusted until
    /// [`audit`] says otherwise.
    pub fn from_parts(
        sealed: SealedComposition,
        owners: ComponentReveal,
        gates: ComponentReveal,
    ) -> CompositionArtifact {
        CompositionArtifact {
            sealed,
            owners,
            gates,
        }
    }

    pub fn ceremony(&self) -> &CeremonyId {
        &self.sealed.ceremony
    }

    /// The two sealed, endorsed components, for a funder that observed the
    /// commit broadcast and wants to compare.
    pub fn commitments(&self) -> (SignedCommitment, SignedCommitment) {
        self.sealed.commitments()
    }

    pub fn owners(&self) -> &ComponentReveal {
        &self.owners
    }

    pub fn gates(&self) -> &ComponentReveal {
        &self.gates
    }

    /// `B = B_owner + B_gate` over the two revealed components, UNCHECKED.
    ///
    /// Says nothing on its own: the two components are whatever the artifact
    /// carries until [`audit`] has established that each opens the commitment
    /// published for it and that every seat behind it proved possession.
    /// [`AuditedRoot::root`] is the same sum after that has been established.
    ///
    /// Note what that is not. `audit` establishes that a reveal MATCHES its
    /// commitment; it cannot establish that the commitment was PUBLISHED before
    /// the other side opened. See the module docs, and [`prove_possession`] for
    /// where that half is enforced instead.
    pub fn declared_root(&self) -> RistrettoPoint {
        self.owners.component() + self.gates.component()
    }
}

/// What one cohort turned out to be, as established by [`audit`].
///
/// The whole of the funder's question about one side of the address in one
/// value: WHO (the identity key that endorsed the commitment, checked against
/// the one the funder supplied), HOW MANY seats are required, WHICH seats exist,
/// and what they collectively control.
///
/// It exists so that a caller comparing an audited root against a decided
/// structure compares VALUES rather than reaching into the reveals -- the
/// artifact's internals are wire data, and a caller that navigates into them to
/// answer "is this the roster we agreed" is re-deriving, at every call site, a
/// question the audit already answered.
///
/// `PartialEq` is derived, so the comparison is `audited == expected` rather
/// than a field-by-field walk a caller can get wrong by omission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CohortStructure {
    cohort: &'static str,
    identity: IdentityPublic,
    threshold: usize,
    roster: Vec<u64>,
    component: RistrettoPoint,
}

impl CohortStructure {
    /// `"owners"` or `"gates"`.
    pub fn cohort(&self) -> &'static str {
        self.cohort
    }

    /// The organisation that endorsed this cohort's commitment. Equal, by
    /// construction, to the key [`audit`] was given for this cohort -- the audit
    /// could not have returned otherwise.
    pub fn identity(&self) -> &IdentityPublic {
        &self.identity
    }

    /// Seats required to sign. Established in both directions: every subset this
    /// size reconstructs the component, and no smaller subset does.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// The seats, ascending.
    pub fn roster(&self) -> &[u64] {
        &self.roster
    }

    /// `B_c`, this cohort's half of the root.
    pub fn component(&self) -> RistrettoPoint {
        self.component
    }
}

/// An artifact that passed [`audit`].
///
/// The only way to obtain one, which is what makes "audited" a property of a
/// value rather than of a code path somebody remembered to take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditedRoot {
    ceremony: CeremonyId,
    root: RistrettoPoint,
    owners: ComponentReveal,
    gates: ComponentReveal,
    owner_structure: CohortStructure,
    gate_structure: CohortStructure,
}

impl AuditedRoot {
    /// `B`, the composite spend root.
    pub fn root(&self) -> RistrettoPoint {
        self.root
    }

    pub fn ceremony(&self) -> &CeremonyId {
        &self.ceremony
    }

    /// What each cohort turned out to be: identity, threshold, roster,
    /// component.
    pub fn structure(&self) -> (&CohortStructure, &CohortStructure) {
        (&self.owner_structure, &self.gate_structure)
    }

    pub fn owner_structure(&self) -> &CohortStructure {
        &self.owner_structure
    }

    pub fn gate_structure(&self) -> &CohortStructure {
        &self.gate_structure
    }

    pub(crate) fn owner_reveal(&self) -> &ComponentReveal {
        &self.owners
    }

    pub(crate) fn gate_reveal(&self) -> &ComponentReveal {
        &self.gates
    }
}

/// An audited root plus a subaddress of it, checked against the view key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditedAddress {
    root: AuditedRoot,
    subaddress_index: u64,
    spend_public: RistrettoPublic,
}

impl AuditedAddress {
    pub fn root(&self) -> &AuditedRoot {
        &self.root
    }

    pub fn subaddress_index(&self) -> u64 {
        self.subaddress_index
    }

    /// `D_i`, the subaddress spend public key funds are paid to.
    pub fn spend_public(&self) -> &RistrettoPublic {
        &self.spend_public
    }
}

/// **The check a funder runs.**
///
/// Takes the artifact and the two organisations' identity public keys, and
/// nothing else. See the module docs for exactly what this does and does not
/// establish.
///
/// The keys are an INPUT, not something read out of the artifact. A funder that
/// passes `Parties::new(owners.signer(), gates.signer())` from the artifact it
/// is auditing has asked the artifact to vouch for itself and has established
/// nothing about who produced it.
pub fn audit(artifact: &CompositionArtifact, parties: &Parties) -> Result<AuditedRoot> {
    let sealed = &artifact.sealed;

    // Before anything reads the artifact. A funder that named one organisation
    // twice is asking a question with no two-party answer, and every check below
    // would return one anyway.
    parties.check_distinct()?;

    check_side::<Owners>(sealed, &artifact.owners, &sealed.owners, parties)?;
    check_side::<Gates>(sealed, &artifact.gates, &sealed.gates, parties)?;

    // Disjointness of the two rosters needs no check of its own: `check_shape`
    // has already required every owner id to be in the `Owners` band and every
    // gate id to be in the `Gates` band, and the bands do not overlap. Stated
    // rather than re-asserted, because an assertion that cannot fail is not
    // evidence -- `an_honest_ceremony_produces_an_artifact_that_audits` checks
    // the disjointness on an audited value, where it can.

    // COMPUTED, not checked: the artifact carries no independent claim about
    // the root, so there is nothing here to disagree with. What makes this root
    // trustworthy is everything `check_side` established about the two
    // components that went into it.
    let root = artifact.owners.component() + artifact.gates.component();

    Ok(AuditedRoot {
        ceremony: sealed.ceremony,
        root,
        owner_structure: structure_of::<Owners>(&artifact.owners, parties),
        gate_structure: structure_of::<Gates>(&artifact.gates, parties),
        owners: artifact.owners.clone(),
        gates: artifact.gates.clone(),
    })
}

/// One audited cohort's structure.
///
/// Private, and reachable only from inside `audit` after `check_side` has
/// returned, because every field it reports is a wire value until then. The
/// identity comes from `parties` rather than from the artifact: `check_side` has
/// just established the two are equal, and taking the funder's copy makes it
/// impossible for a future edit to report the artifact's claim by accident.
fn structure_of<C: ControlDomain>(reveal: &ComponentReveal, parties: &Parties) -> CohortStructure {
    CohortStructure {
        cohort: C::NAME,
        identity: *parties.expected_for::<C>(),
        threshold: reveal.threshold(),
        roster: reveal.roster().to_vec(),
        component: reveal.component(),
    }
}

/// [`audit`], plus: subaddress `index` of the audited root really is
/// `spend_public`.
///
/// Needs the view private key, because the offset `Hs(a||i)` is derived from it
/// alone. A funder without `a` can still audit the ROOT; it must take the
/// subaddress on trust from whoever gave it the address.
pub fn audit_address(
    artifact: &CompositionArtifact,
    parties: &Parties,
    view_private: &RistrettoPrivate,
    subaddress_index: u64,
    spend_public: &RistrettoPublic,
) -> Result<AuditedAddress> {
    let root = audit(artifact, parties)?;
    let offset = Zeroizing::new(subaddress_offset(view_private.as_ref(), subaddress_index));
    let expected = root.root + *offset * G;
    if &expected != spend_public.as_ref() {
        return Err(CeremonyError::SubaddressMismatch {
            index: subaddress_index,
        });
    }
    Ok(AuditedAddress {
        root,
        subaddress_index,
        spend_public: *spend_public,
    })
}

fn check_side<C: ControlDomain>(
    sealed: &SealedComposition,
    reveal: &ComponentReveal,
    signed: &SignedCommitment,
    parties: &Parties,
) -> Result<()> {
    // ATTRIBUTION first, because everything below it is a statement about key
    // material and none of it says who produced the key material. A funder
    // reading a rejection should be told "this is not your counterparty's
    // artifact" before it is told anything about the contents of an artifact
    // that was never theirs.
    signed.check::<C>(&sealed.ceremony, parties.expected_for::<C>())?;
    // Shape next: the commitment, proof and consistency checks all index into
    // parallel vectors, and a claim whose lengths disagree must not reach them.
    reveal.claim.check_shape::<C>()?;
    if reveal.commitment(&sealed.ceremony) != signed.commitment {
        return Err(CeremonyError::CommitmentMismatch { cohort: C::NAME });
    }
    reveal.check_pops(sealed)?;
    reveal.claim.check_consistency::<C>()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Transcripts
// ---------------------------------------------------------------------------

/// Length-prefixed so no two distinct claims can hash alike by shifting a field
/// boundary -- the same reason `mlsag`'s seat tags are fixed-width.
fn absorb_claim(h: &mut Blake2b512, claim: &ComponentClaim) {
    h.update((claim.cohort.len() as u64).to_le_bytes());
    h.update(claim.cohort.as_bytes());
    h.update((claim.threshold as u64).to_le_bytes());
    h.update((claim.roster.len() as u64).to_le_bytes());
    for &id in &claim.roster {
        h.update(id.to_le_bytes());
    }
    h.update(claim.component.compress().as_bytes());
    h.update((claim.verification_shares.len() as u64).to_le_bytes());
    for v in &claim.verification_shares {
        h.update(v.compress().as_bytes());
    }
}

fn commitment_digest(ceremony: &CeremonyId, claim: &ComponentClaim, salt: &[u8; 32]) -> [u8; 32] {
    let mut h = Blake2b512::new();
    h.update(COMMIT_TAG);
    h.update(ceremony.as_bytes());
    absorb_claim(&mut h, claim);
    h.update(salt);
    truncate(h)
}

/// What an organisation signs when it endorses its own sealed commitment.
///
/// The ceremony id and the cohort name are already inside `digest`, and the two
/// repetitions are NOT equally load-bearing -- said plainly, because a reader
/// deciding what this signature means should not have to guess:
///
///   * **The ceremony id is live.** `digest` is opaque to the signer's
///     counterparty, so an endorsement made over the same digest value in some
///     other ceremony would otherwise carry into this one.
///     `tests/attribution.rs`'s cross-ceremony transplant fails without this
///     line.
///   * **The cohort name is defence in depth and nothing more.** No test fails
///     without it, and none can: [`absorb_claim`] already puts the cohort inside
///     the digest, so two cohorts' digests differ before this ever runs. It is
///     here so that the signed message says what it is at the layer that signed
///     it, rather than depending on a property of a hash preimage the verifier
///     never sees.
///
/// Length-prefixed for the same reason [`absorb_claim`] is.
fn commitment_signing_payload(ceremony: &CeremonyId, commitment: &ComponentCommitment) -> Vec<u8> {
    let mut out = Vec::from(COMMIT_SIGNATURE_TAG);
    out.extend_from_slice(ceremony.as_bytes());
    out.extend_from_slice(&(commitment.cohort.len() as u64).to_le_bytes());
    out.extend_from_slice(commitment.cohort.as_bytes());
    out.extend_from_slice(&commitment.digest);
    out
}

/// The composition a proof of possession is taken under: the ceremony, both
/// sealed digests, and both organisations.
///
/// The two SIGNER KEYS are in here; the two SIGNATURES are not. What a holder is
/// binding its proof to is the counterparty's identity, and the identity is the
/// key -- the signature is evidence for that identity, checked separately by
/// [`SignedCommitment::check`]. Absorbing the signature bytes instead would make
/// the transcript depend on a value the signature scheme is free to choose (any
/// re-signing under a randomised scheme would invalidate every proof), while
/// adding nothing: a substituted signature that verifies is by the same key, and
/// one that does not verify is refused by the audit.
fn absorb_composition(h: &mut Blake2b512, sealed: &SealedComposition) {
    h.update(sealed.ceremony.as_bytes());
    h.update(sealed.owners.commitment.digest);
    h.update(sealed.gates.commitment.digest);
    h.update(sealed.owners.signer.as_bytes());
    h.update(sealed.gates.signer.as_bytes());
}

/// The proof-of-possession challenge.
///
/// It names BOTH sealed components. That is the weld between the two halves of
/// the defence: a cohort cannot produce this challenge, and therefore cannot
/// produce a proof, until it holds the other cohort's commitment -- and what it
/// is proving possession of is already sealed inside its own.
///
/// It also names BOTH ORGANISATIONS, via [`absorb_composition`]. So a holder's
/// proof is a statement about the composition it believed it was in, including
/// who the other party was: an honest cohort's reveal cannot be lifted into an
/// artifact that attributes the other half to a different organisation, even
/// one willing to endorse the identical digest. Without that, the identity
/// signatures would be a layer beside the proofs rather than part of the same
/// transcript, and the two could disagree about who was in the room.
fn pop_challenge(
    sealed: &SealedComposition,
    claim: &ComponentClaim,
    participant: u64,
    verification_share: &RistrettoPoint,
    nonce_public: &RistrettoPoint,
) -> Scalar {
    let mut h = Blake2b512::new();
    h.update(POP_TAG);
    h.update(b"challenge");
    absorb_composition(&mut h, sealed);
    absorb_claim(&mut h, claim);
    h.update(participant.to_le_bytes());
    h.update(verification_share.compress().as_bytes());
    h.update(nonce_public.compress().as_bytes());
    Scalar::from_hash(h)
}

fn truncate(h: Blake2b512) -> [u8; 32] {
    let full = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
