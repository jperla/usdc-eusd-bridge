//! The decided production access structure.
//!
//! Written as code rather than left in a document because a parameter that
//! lives only in prose drifts from the parameter the signer actually uses, and
//! nothing notices. Anything that builds a production composite key should
//! take its shape from here.
//!
//! **Decided: 3 operators at 2-of-3, and 1 independent gate.** Four seats;
//! three must be compromised before funds can move -- *given* three premises.
//! **One of the three is now enforced in code; the other two are not, and
//! nothing any artifact can carry would enforce them:**
//!
//!   1. **UNBUILDABLE.** The four seats are four independent principals. Four
//!      keys are four keys; whether four keys are four organisations is a fact
//!      about the world that no algebra reaches.
//!   2. **UNBUILDABLE.** Nobody else holds a copy of a seat's share -- a dealer
//!      that dealt to four real parties and kept copies is one principal, not
//!      three, and the artifact is identical either way. Possession is copyable;
//!      no proof of possession is a proof of EXCLUSIVE possession.
//!   3. **CLOSED IN CODE.** The party that endorsed a seat knows a share behind
//!      it. This was FALSE in this crate and is now enforced: a seat endorsement
//!      is an AND-composed proof of knowledge of the seat's identity secret and
//!      of the share the claim publishes for it, under one challenge. Stated
//!      exactly -- an accepted endorsement is an ARGUMENT OF KNOWLEDGE for
//!      `Id = d*B AND V_i = s*G` under the discrete-log and random-oracle
//!      assumptions, `Id` being the key the CHECKER supplied. Read it narrowly:
//!      not that one actor held both secrets, not that the endorser is the
//!      share's only holder (that is premise 2), not that the two witnesses are
//!      distinct, and not present possession.
//!
//! Premise 2 was missing from this headline and premise 3 was not stated
//! anywhere until review; both are rows in
//! `proofs/tla/AttributionCoverage.tla`, and each of them alone drops the
//! minimum coalition below three. Premise 3's row is now the `TRUE` baseline and
//! the `FALSE` row prices the fix. See "What this module does NOT encode".
//!
//! There is a fourth thing, and it is not a premise but an ADMISSIBILITY check,
//! recorded here because closing premise 3 opened it TWICE: a seat key must be a
//! key. Replacing the seat endorsement's Ed25519 signature with a sigma proof
//! dropped `verify_strict`'s small-order refusal, and a 32-byte string on the
//! curve but outside the prime-order subgroup admitted a verifying identity half
//! with no secret behind it at all -- so a dealer holding every share could fill
//! three seats with values that are not keys and the artifact audited. The first
//! fix, a subgroup check, then let the IDENTITY element through: it is in the
//! subgroup, and its `d = 0` is public, so its identity half verifies for every
//! challenge with no work at all. Both are now refused by
//! `ComponentClaim::check_shape` as `CeremonyError::SeatKeyNotUsable`, with the
//! cause named, and `tests/seat_key_torsion.rs` performs both forgeries.
//!
//! Recorded rather than smoothed over because the pattern is the point: each
//! time, a CHECK was replaced by an ARGUMENT about why the check was
//! unnecessary, and each argument was wrong in a way only an attempt at the
//! forgery revealed.
//!
//! Why four and not three, since three was the stated constraint: three
//! entities *can* reach the same compromise threshold, as 2-of-2 operators
//! plus a gate. The fourth entity buys tolerance of one lost OPERATOR key.
//!
//! It is not a free win, and the trade runs both ways. Both configurations
//! have `T = 3`, but they differ in how MANY coalitions of that size work:
//! `2-of-2 + gate` has exactly one, `{O1,O2,G}`; `2-of-3 + gate` has three.
//! The extra operator therefore does not raise the cost of the cheapest
//! targeted attack at all -- it adds attack paths. Under independent
//! compromise at probability `p` per principal: `p^3` against `3p^3 - 2p^4`.
//!
//! Neither configuration tolerates losing the GATE. It is indispensable in
//! both, and there is deliberately no recovery path, so losing it freezes the
//! funds permanently. Tolerating the loss of ANY one principal -- gate
//! included -- is impossible at four entities without the structure
//! collapsing to a plain `3-of-4`; a nonredundant role split with that
//! property needs five.
//!
//! `T` records minimum coalition SIZE and nothing else: not how many such
//! coalitions exist, not which principals are critical, not correlation
//! between them, and not availability. Reading it as a general key-theft or
//! probabilistic security threshold overstates it.
//!
//! Participant ids come from each domain's own band, which `ControlDomain`
//! enforces in the type system — a subset drawn from one cohort cannot be
//! accepted by the other. That is not cosmetic: with both rosters over the
//! same ids, every owner subset is also a qualifying gate subset, and review
//! found exactly that defect in the spike this crate was promoted from.
//!
//! What this module does NOT encode, because none of it is a number: **that the
//! four entities are four entities.** Two separate facts, and only the first has
//! ever been written down here:
//!
//!   * Whether the GATE is a separate compromise domain from the operators. A
//!     gate an operator organisation administers, or can recover from, is the
//!     same domain in different hardware. That does not turn the structure into
//!     an ordinary `2-of-3` -- an earlier version said it collapses to a plain
//!     `max(k,g)`-of-n multisig and that is wrong: the other two operators still
//!     cannot move funds without the gate. What it does is drop the minimum
//!     coalition from three principals to two, that one operator plus one other,
//!     which is the fourth entity's whole contribution and then some.
//!   * Whether the three OPERATOR SEATS are three entities. `T = 3` counts
//!     seats; three seats held by one organisation are one principal wearing
//!     three hats, and `2-of-3` of them is no barrier at all.
//!
//!     **The artifact now distinguishes those cases by KEY, which it did not
//!     before.** [`audit`](crate::audit) is told one identity key per SEAT as
//!     well as one per cohort, each seat's verification share carries that
//!     seat's own endorsement, and the endorsement is checked under the key the
//!     funder obtained from the party -- so an organisation that deals all three
//!     operator shares to itself must produce a valid endorsement from each of
//!     the three seat keys the funder holds, rather than one organisation key.
//!     `tests/forgery.rs::a_dealt_owner_cohort_is_refused_at_the_seat_attribution`
//!     performs the two ways it can mount that WITHOUT those endorsements -- its
//!     own keys, or the real holders' public keys it is free to copy -- and both
//!     are refused at `audit_address`, before any spend exists.
//!
//!     Read "must produce a valid endorsement" exactly. It is not "must hold the
//!     seat keys": whoever holds a key can endorse, and the funder cannot tell
//!     one holder of a key from another. What it now also requires is the SHARE
//!     behind the seat, because a seat endorsement is a proof of knowledge of
//!     both -- so the three seat-holders can no longer supply it for a dealing
//!     they were not dealt into, which is the paragraph below and was the
//!     opposite of the paragraph below until the linked proof landed.
//!
//! Both remain organisational facts and no test here can see them, and neither
//! is fully closable by any artifact. Said exactly, so this paragraph is not
//! read as more than it is: per-seat keys do NOT establish that four keys are
//! four entities, and they do NOT stop a dealer that distributed shares to four
//! real parties while keeping copies.
//!
//! A third item stood here, and it has since been CLOSED: they did not bind the
//! party that signed for a seat to a share behind it, so a dealer could keep
//! every share, make every proof of possession itself, and collect the seat
//! signatures it needed over public bytes that cost the signers nothing. A seat
//! endorsement is now a proof of knowledge of the seat's identity secret AND of
//! the share behind it, AND-composed under one challenge -- see
//! `ceremony::SeatEndorsement`. The two tests that performed that forgery, and
//! passed, are now refusals with named errors:
//! `tests/seat_identity.rs::a_dealer_that_keeps_the_shares_is_refused_at_the_seat_endorsement`
//! and
//! `tests/seat_forgery.rs::a_seat_holder_with_a_real_share_cannot_endorse_a_substituted_dealing`.
//!
//! **Read that narrowly.** It says the share was USED, not that one actor holds
//! both secrets, and not that the named party is the share's only holder. The
//! second residual above is exactly the case it leaves open, and it is performed
//! by name:
//! `tests/seat_identity.rs::a_dealer_that_dealt_real_shares_and_kept_copies_still_passes`
//! deals real shares to the three named parties, keeps copies, collects genuine
//! endorsements from parties that really do hold what they endorse with, and it
//! audits -- while the dealer alone reconstructs the owner component.
//!
//! What per-seat keys changed is the number of distinct ENDORSEMENTS a forgery
//! must collect, counted per FORGERY rather than per artifact: from one to FOUR
//! for a dealt-owner forgery at this shape -- the owner organisation's plus one
//! from each of the three operator SEATS, the gate organisation's signature and
//! the gate seat's endorsement being the honest gate's own and not the forger's
//! to collect -- or from two to six if both cohorts are fabricated. An earlier
//! version of this line said "from one to five", which is neither count, and a
//! later one described the same forgery as collecting four SEAT signatures,
//! which is the artifact's total; see `ceremony`'s module docs, where the
//! arithmetic is written out. What the LINKED endorsement changed is what each
//! of those costs: they can only be made where a share is.
//!
//! # The release gate
//!
//! The constants above are only worth writing down if something REFUSES a key
//! that does not match them. [`Provenance`] has existed since
//! [`CompositeSpend`] did, and until now nothing outside a test read it: a root
//! one process generated by itself and a root two organisations generated
//! between them answered [`CompositeSpend::spend_public`] identically, and a
//! deployment publishing a deposit address had nothing to consult.
//! `tests/release_gate.rs::a_simulated_root_reaches_the_funding_path_today`
//! performs the consequence -- it publishes an address and then spends it from
//! the one process that made it.
//!
//! [`authorize_release`] is the refusal. It answers three questions the value
//! could not previously be asked: did this root reach a [`CompositeSpend`] by
//! the AUDITED route rather than by [`CompositeSpend::simulate`] -- a fact about
//! this crate's constructors, not evidence that a distributed ceremony
//! historically occurred -- was the artifact audited against the identity keys
//! of the organisations AND the seat-holders this deployment names, and are the
//! two cohorts the decided structure. The attribution arms matter as much as the
//! first, because a ceremony run by an entirely
//! different pair of organisations audits perfectly under THEIR keys and differs
//! from the real thing in nothing else --
//! `tests/release_gate.rs::the_gate_refuses_a_key_audited_under_organisations_this_deployment_does_not_name`
//! runs one.
//!
//! [`ReleaseAuthorization`] is what makes it a gate rather than advice. The
//! token has no public constructor, no `Default` and no public fields, so the
//! ONLY way to obtain one is to pass the check; and it borrows the
//! [`CompositeSpend`] it was issued against, so it cannot be checked over one
//! value and presented for another. [`deposit_spend_key`] therefore cannot
//! RETURN a key that did not pass. What that is and is not worth is set out
//! under "What a funder does" below, because two earlier versions of this
//! paragraph both claimed more than it supports.
//!
//! # What a funder does, holding only bytes
//!
//! [`audit`](crate::audit) establishes the public STRUCTURE the artifact reports
//! -- rosters, thresholds, components, and a valid proof of possession behind
//! every published verification share -- endorsed under the identity keys the
//! funder supplies. It does not establish who HOLDS those shares, and it does
//! not know which rosters and thresholds were DECIDED; the second is this
//! module's job and the first is nobody's, here. The two halves in sequence are:
//!
//! ```text
//!     audit_address(artifact, parties, a, i, D)  -> AuditedAddress
//!     check_decided_structure(address.root())    -> Ok
//! ```
//!
//! `tests/release_gate.rs::the_funder_question_is_answerable_from_the_artifact`
//! performs exactly that, and the same test answers NO for a ceremony that ran
//! at a shape nobody decided.
//!
//! **What that sequence answers, written as narrowly as it is true.** It is not
//! *"is this subaddress spend key jointly controlled by exactly these two
//! rosters at exactly these thresholds?"* -- an earlier version of this file
//! said it was, and `tests/forgery.rs` returns YES to the sequence for a root a
//! single operator entity controls outright. What it answers is:
//!
//! > Does this `D_i` equal `B_owner + B_gate + Hs(a||i)*G`, where each component
//! > opens a commitment endorsed under the identity key I supplied for its
//! > cohort, every published verification share carries a proof of possession
//! > bound to this ceremony, this composition and both endorsers, and the
//! > audited canonical rosters and exact polynomial degrees are the decided
//! > ones?
//!
//! Three things in that are load-bearing and were wrong in the first attempt at
//! this paragraph. `D_i` is the root PLUS the subaddress offset, not the bare
//! component sum. "Every published verification share carries a proof" is still
//! not "every seat answered a proof" -- a proof of possession is reproducible by
//! anyone holding the share, so it says a share exists and never who holds it.
//! What connects seat `i` to a party is the seat's own `SeatEndorsement`,
//! checked under the key the funder supplied. **This sentence is stale in the
//! source it was written against and review caught it**: it said "the seat's own
//! identity SIGNATURE over `V_i` ... a different statement standing BESIDE the
//! proof". That describes the version that was replaced. An endorsement is now
//! one linked argument of knowledge of the identity scalar AND the share, under
//! a single challenge, which is exactly what "beside" failed to give -- a
//! signature beside a proof was answerable by a dealer holding every share, and
//! that is the forgery the change closed. And
//! "endorsed under the identity key I supplied" is a statement about a KEY, not
//! about an organisation -- at the seat grain as much as at the cohort grain.
//!
//! What the sequence establishes beyond that restatement, and which is worth
//! listing because it is real: the two supplied keys are unequal; each roster is
//! canonical, non-empty, bounded, in its own control domain and disjoint from
//! the other's; no component and no verification share is the identity; each
//! reveal opens the commitment that was signed; and the declared degree is
//! exact, so no subset smaller than the declared threshold reconstructs a
//! component.
//!
//! Further trust conditions ride along and are named rather than folded in: the
//! funder must have the two keys FROM the two organisations; must hold the view
//! private key `a`, without which only the ROOT is checkable and `D_i` is taken
//! on trust from whoever published it -- and an address publisher holding `a`
//! can publish a `D` it can spend alone, so this is not a formality; must
//! remember to run the second call at all; must trust that these compiled
//! constants are the approved policy; and must have some reason to believe this
//! artifact is the CURRENT one, since nothing in it is dated and `audit` accepts
//! whatever [`CeremonyId`](crate::CeremonyId) the artifact names rather than one
//! the funder expected.
//!
//! Finally, "holding only bytes" is a figure of speech and not an implemented
//! interface. [`audit`](crate::audit) takes a typed `&CompositionArtifact`;
//! there is no canonical encoding, serialiser or parser for one anywhere in this
//! crate. A funder is trusting somebody's decoder.
//!
//! Note what [`check_decided_structure`] is and is not. The narrow type property
//! is sound: [`ReleaseAuthorization`] has no constructor but the gate and
//! borrows the spend it was issued against, so [`deposit_spend_key`] cannot
//! return a key that did not pass. Everything wider than that is false, and two
//! successive attempts at this paragraph were both too generous:
//!
//!   * Not "a funding path cannot be reached without it". That is true only of
//!     a path that takes a [`ReleaseAuthorization`] AND publishes what
//!     [`deposit_spend_key`] returns. A path can take the token, ignore it, and
//!     publish something else; nothing here can see that.
//!   * The public routes to a fundable key are several, not one:
//!     [`CompositeSpend::spend_public`], [`CompositeSpend::simulate`] and
//!     [`CompositeSpend::simulate_from_seed`],
//!     [`AuditedAddress::spend_public`](crate::AuditedAddress) before any
//!     decided-shape check has run, and
//!     [`CompositionArtifact::declared_root`](crate::CompositionArtifact) plus
//!     [`derive::subaddress_offset`](crate::derive::subaddress_offset).
//!     `tests/release_gate.rs`'s own gap test
//!     `todays_funding_path(spend: &CompositeSpend)` still compiles and still
//!     publishes a simulated address -- it is simultaneously the demonstration
//!     of the gap and the demonstration that the bypass remains.
//!   * The final funding sink is an ordinary `RistrettoPublic` outside this type
//!     system entirely.
//!
//! The funder is not inside this program at all, so their half is an ordinary
//! `Result` they have to remember to ask for, and no type here can reach across
//! that gap. Said plainly: the construction argument covers a deployment that
//! routes its funding path through [`deposit_spend_key`] and publishes its
//! return value, and nothing else.

use core::fmt;

use mc_crypto_keys::RistrettoPublic;
use thiserror::Error as ThisError;

use crate::{
    ceremony::{AuditedRoot, CeremonyId, Parties, SeatRoster},
    identity::IdentityPublic,
    CohortSpec, CompositeSpend, Gates, Owners, Provenance,
};

/// Operators: any 2 of 3.
pub const OWNER_THRESHOLD: usize = 2;
pub const OWNER_COUNT: usize = 3;

/// Gates: the single independent gate must sign.
pub const GATE_THRESHOLD: usize = 1;
pub const GATE_COUNT: usize = 1;

/// SEATS in the decided structure, one per compromise domain the deployment
/// intends.
///
/// It is a count of seats, not of entities. Whether the four seats are four
/// distinct compromise domains is an organisational fact no artifact this crate
/// produces can carry -- one principal may hold all four seat keys, and
/// `tests/seat_identity.rs::the_residual_is_a_party_that_holds_every_seat_key`
/// performs exactly that against an artifact that audits. An earlier version of
/// this line read "distinct compromise domains in the decided structure", which
/// asserts the thing the module docs spend two paragraphs saying is not
/// establishable here.
pub const ENTITIES: usize = OWNER_COUNT + GATE_COUNT;

/// SEATS that must be compromised before funds can move:
/// `T = max(k, g, k + g - r)` with no overlap, so `k + g`.
///
/// Reads as *principals* only under the assumption that distinct seats are
/// distinct principals, which is the residual named above and in the module
/// docs. `tests::no_coalition_of_fewer_than_three_seats_qualifies` enumerates
/// the seat subsets and checks this number against the access structure rather
/// than against itself.
pub const COMPROMISE_THRESHOLD: usize = OWNER_THRESHOLD + GATE_THRESHOLD;

pub fn owners() -> CohortSpec<Owners> {
    CohortSpec::<Owners>::sequential(OWNER_THRESHOLD, OWNER_COUNT)
}

pub fn gates() -> CohortSpec<Gates> {
    CohortSpec::<Gates>::sequential(GATE_THRESHOLD, GATE_COUNT)
}

// ---------------------------------------------------------------------------
// The release gate
// ---------------------------------------------------------------------------

/// Why a key was refused for production use.
///
/// Typed, and each variant carries what was found alongside what was decided,
/// because the responses differ completely: a simulated root is a key that must
/// never be funded and must be regenerated, whereas a roster or threshold
/// mismatch is a key that was generated correctly for a structure nobody
/// approved.
#[derive(Clone, Debug, PartialEq, Eq, ThisError)]
#[non_exhaustive]
pub enum ReleaseRefused {
    /// [`Provenance::Simulated`]: a trusted dealer generated both component
    /// secrets and every share in ONE process, so that process can spend the
    /// address alone no matter what the rosters say.
    #[error(
        "the composite root was generated by a trusted dealer in a single process, not by a \
         composition ceremony, so one process can spend it alone"
    )]
    NotFromCeremony,

    /// The cohort's roster is not the decided one.
    ///
    /// Compared as an ordered sequence rather than as a set -- but that
    /// distinction is **not a defence this arm provides**, and an earlier
    /// version of this comment argued at length that it was. Sorting both sides
    /// before comparing breaks nothing in the suite and cannot: every path into
    /// `check_cohort` has already been through `ComponentClaim::check_shape`,
    /// which refuses a non-ascending roster with
    /// `CeremonyError::RosterNotCanonical`, and the decided constants are
    /// ascending. A permutation therefore never reaches here. Said the way the
    /// cohort-name comment in `ceremony::commitment_signing_payload` is said: a
    /// sequence comparison is the right shape for the values being compared, and
    /// no test reaching this through the crate's public API can fail without it.
    /// A test inside this module could call `check_cohort` directly with a
    /// permutation and would fail -- so "none can be written" would be too
    /// absolute, and what is true is that no reachable path exercises it.
    ///
    /// The reason permutation matters at all is real and lives one layer down:
    /// position `k` of a roster is Shamir evaluation point `k + 1` for the audit
    /// and for every holder's `CohortShare::term` alike, so a permuted dealing
    /// is a different dealing carrying the same seats -- the funded-then-
    /// unspendable class. `RosterNotCanonical` is what closes it.
    #[error("cohort `{cohort}`: roster {found:?}, but the decided structure is {expected:?}")]
    Roster {
        cohort: &'static str,
        expected: Vec<u64>,
        found: Vec<u64>,
    },

    /// The cohort's threshold is not the decided one.
    ///
    /// Refused in BOTH directions. A lower threshold than decided is the
    /// obvious hole; a higher one is refused too, because the decided structure
    /// is what was reviewed and what [`COMPROMISE_THRESHOLD`] is computed over,
    /// and a key that is stronger in an unreviewed way is still a key nobody
    /// signed off -- and, for the gate, one nobody has a recovery story for.
    #[error("cohort `{cohort}`: threshold {found}, but the decided structure is {expected}")]
    Threshold {
        cohort: &'static str,
        expected: usize,
        found: usize,
    },

    /// The composition behind this root was audited against an identity key
    /// that is not the one this deployment names for that cohort.
    ///
    /// [`audit`](crate::audit) checks each commitment against a key its CALLER
    /// supplies, so an artifact produced by an entirely different pair of
    /// organisations audits perfectly under that pair's own keys and yields a
    /// `CompositeSpend` indistinguishable from the real one at every other arm
    /// of this gate: same shape, same rosters, same `Provenance::Ceremony`. The
    /// difference is only visible because
    /// [`CompositeSpend::endorsers`] carries the audited keys forward to here.
    #[error(
        "cohort `{cohort}`: the composition was audited against identity key {found}, not the \
         {expected} this deployment names for that organisation"
    )]
    Endorser {
        cohort: &'static str,
        expected: IdentityPublic,
        found: IdentityPublic,
    },

    /// The composition behind this root was audited against a different party
    /// for one of the SEATS than this deployment names for it.
    ///
    /// [`ReleaseRefused::Endorser`]'s argument, one grain finer, and it is the
    /// grain that matters: [`COMPROMISE_THRESHOLD`] counts seats. A spend
    /// audited under a `Parties` whose owner seats are three keys of one
    /// dealer's own making satisfies every other arm of this gate -- same shape,
    /// same rosters, same `Provenance::Ceremony`, and the two ORGANISATION keys
    /// can be the genuine ones.
    #[error(
        "cohort `{cohort}`: seat {participant} was audited as identity {found}, not the \
         {expected} this deployment names for that seat"
    )]
    Seat {
        cohort: &'static str,
        participant: u64,
        expected: IdentityPublic,
        found: IdentityPublic,
    },

    /// The two seat rosters do not name the same seats.
    ///
    /// Separate from [`ReleaseRefused::Seat`] because there is no per-seat
    /// disagreement to report: the audit was run over a different set of seats
    /// than this deployment is asking about, and reporting the first mismatched
    /// id would hide that.
    #[error(
        "cohort `{cohort}`: the composition was audited over seats {found:?}, not the {expected:?} \
         this deployment names"
    )]
    SeatRoster {
        cohort: &'static str,
        expected: Vec<u64>,
        found: Vec<u64>,
    },
}

/// Evidence that a [`CompositeSpend`] passed [`authorize_release`].
///
/// There is no public constructor, no public field, no `Default` and no
/// `From` -- [`authorize_release`] is the only thing in the program that can
/// produce one. That is the difference between this and a `bool`: a `bool`
/// records that somebody could have looked, and this records that they did.
///
/// It BORROWS the spend it was issued against. Without that, a caller could
/// authorise one key and hand the token along beside a different one, which is
/// the same convention-not-construction failure one level up.
///
/// ```compile_fail
/// // The token cannot be fabricated: the fields are private and there is no
/// // constructor but the gate.
/// use two_cohort::production::ReleaseAuthorization;
/// use two_cohort::{CohortSpec, CompositeSpend, Gates, Owners};
///
/// let spend = CompositeSpend::simulate_from_seed(
///     0,
///     &CohortSpec::<Owners>::sequential(2, 3),
///     &CohortSpec::<Gates>::sequential(1, 1),
///     7,
/// )
/// .unwrap();
/// let _auth = ReleaseAuthorization { spend: &spend };
/// ```
pub struct ReleaseAuthorization<'a> {
    spend: &'a CompositeSpend,
    /// The ceremony the root came out of. Carried so a caller that logs a
    /// release does not have to re-match on [`Provenance`] to name it.
    ceremony: CeremonyId,
}

impl<'a> ReleaseAuthorization<'a> {
    /// The authorised spend. The lifetime is the one the check was run over.
    pub fn spend(&self) -> &'a CompositeSpend {
        self.spend
    }

    /// The composition ceremony this root came out of.
    pub fn ceremony(&self) -> CeremonyId {
        self.ceremony
    }
}

/// Redacted for the same reason [`CompositeSpend`]'s is: it holds one.
impl fmt::Debug for ReleaseAuthorization<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReleaseAuthorization")
            .field("ceremony", &self.ceremony)
            .field("subaddress_index", &self.spend.subaddress_index())
            .field("spend_public", &self.spend.spend_public())
            .finish()
    }
}

/// **The check a deployment must pass before a key is used.**
///
/// Refuses unless four things hold at once: the root came out of a composition
/// ceremony; that ceremony was audited against the identity keys of the
/// organisations named in `parties`; it was audited against the same key for
/// every SEAT that `parties` names; and both cohorts are exactly the decided
/// structure -- [`owners`] at [`OWNER_THRESHOLD`], [`gates`] at
/// [`GATE_THRESHOLD`].
///
/// The seat arm is the one that makes this gate count the same things
/// [`COMPROMISE_THRESHOLD`] counts. Without it a `Parties` carrying the four
/// keys a deployment collected would still admit a spend whose audit ran against
/// four keys of somebody else's choosing, because the two ORGANISATION keys
/// would match -- and cohort-level attribution is exactly what
/// `tests/forgery.rs` used to walk through to a published address.
///
/// `parties` is an ARGUMENT for the same reason it is an argument to
/// [`audit`](crate::audit): the keys have to come from the organisations. This
/// crate has no business holding them, since they are the one part of the
/// production structure that is not a number and cannot be a constant. A
/// deployment that passes `spend.endorsers().unwrap()` here has asked the value
/// to vouch for itself and has established nothing.
///
/// What the provenance arm is worth resting on: [`Provenance::Ceremony`] is
/// recorded by [`CompositeSpend::from_ceremony`] and by nothing else, and
/// `from_ceremony` takes an [`AuditedAddress`](crate::AuditedAddress), which
/// only [`audit_address`](crate::audit_address) issues. The field is private and
/// no public constructor sets it, so a caller outside this crate cannot present
/// a spend that claims a ceremony it did not have -- it is not a self-declared
/// label. It is still a statement about THIS crate's construction rules and not
/// a signature: what it inherits is exactly what [`audit`](crate::audit)
/// establishes, and [`ceremony`](crate::ceremony)'s limits are unchanged by
/// being checked here. In particular, all three of these pass this gate:
///
///   * a root whose cohorts have been compromised at any time SINCE key
///     generation -- the artifact is a statement about key generation;
///   * a root whose gate organisation is not a separate compromise domain from
///     the operators;
///   * a root whose four named SEATS are fewer than four entities. The seat arm
///     checks four keys against four parties the deployment named; four keys can
///     still be four hats, and three real parties can still have handed their
///     seat keys to a fourth. What it no longer admits is the dealer that holds
///     one organisation key and nothing else --
///     `tests/forgery.rs::a_dealt_owner_cohort_is_refused_at_the_seat_attribution`.
///
/// Disjointness of the two rosters is not a separate arm. Both are required to
/// equal the two decided rosters, and those are disjoint by
/// [`ControlDomain`](crate::ControlDomain)'s id bands -- asserted on the
/// constants by `the_cohorts_occupy_disjoint_id_ranges` in this module. An arm
/// here could not fail, and a check that cannot fail is not evidence.
pub fn authorize_release<'a>(
    spend: &'a CompositeSpend,
    parties: &Parties,
) -> Result<ReleaseAuthorization<'a>, ReleaseRefused> {
    // The two are read TOGETHER because they are set together, by
    // `from_ceremony`, in one struct literal. Matching on the pair means the
    // "ceremony with no endorsers" combination has to be written down and
    // answered rather than unwrapped: it cannot occur today, and if some future
    // constructor makes it occur, this refuses instead of panicking on a value
    // that is already in a release path.
    let (ceremony, endorsers) = match (spend.provenance(), spend.endorsers()) {
        (Provenance::Simulated, _) => return Err(ReleaseRefused::NotFromCeremony),
        (Provenance::Ceremony(id), Some(endorsers)) => (id, endorsers),
        // Fail closed, and honestly: without the endorsers this cannot establish
        // that the root came out of a ceremony anybody in particular ran.
        (Provenance::Ceremony(_), None) => return Err(ReleaseRefused::NotFromCeremony),
    };
    check_endorser(owners().name(), parties.owners(), endorsers.owners())?;
    check_endorser(gates().name(), parties.gates(), endorsers.gates())?;
    // PER SEAT, and this is the arm that makes the gate count the same things
    // `COMPROMISE_THRESHOLD` counts. Without it, `parties` could carry the four
    // seat keys a deployment collected and still admit a spend whose audit ran
    // against four keys of somebody else's choosing, because the two cohort keys
    // would match. That is the cohort-level attribution the module docs used to
    // admit; it is refused here.
    check_seats::<Owners>(parties.owner_seats(), endorsers.owner_seats())?;
    check_seats::<Gates>(parties.gate_seats(), endorsers.gate_seats())?;
    check_decided_shape(
        spend.owners().threshold(),
        spend.owners().roster(),
        spend.gates().threshold(),
        spend.gates().roster(),
    )?;
    Ok(ReleaseAuthorization { spend, ceremony })
}

/// Every seat this deployment names was audited as that same party.
///
/// `expected` is the deployment's own roster, `found` is the one the audit
/// behind the spend actually ran against. Compared by SET of ids first, so a
/// disagreement about which seats exist is reported as itself rather than as the
/// first key that happens to differ.
fn check_seats<C: crate::ControlDomain>(
    expected: &SeatRoster<C>,
    found: &SeatRoster<C>,
) -> Result<(), ReleaseRefused> {
    if expected.ids() != found.ids() {
        return Err(ReleaseRefused::SeatRoster {
            cohort: C::NAME,
            expected: expected.ids(),
            found: found.ids(),
        });
    }
    for (participant, want) in expected.iter() {
        let got = found
            .key_of(participant)
            .expect("the id sets are equal, checked immediately above");
        if want != got {
            return Err(ReleaseRefused::Seat {
                cohort: C::NAME,
                participant,
                expected: want,
                found: got,
            });
        }
    }
    Ok(())
}

fn check_endorser(
    cohort: &'static str,
    expected: &IdentityPublic,
    found: &IdentityPublic,
) -> Result<(), ReleaseRefused> {
    if expected != found {
        return Err(ReleaseRefused::Endorser {
            cohort,
            expected: *expected,
            found: *found,
        });
    }
    Ok(())
}

/// The shape half of the funder's question, against an audited artifact rather
/// than a constructed spend.
///
/// [`audit`] says what the structure IS -- which participant ids hold seats,
/// which identity key the funder named for each of them, how many must act, and
/// which key endorsed each cohort's commitment. This says whether that structure
/// is the one that was DECIDED.
///
/// It compares SHAPE only: rosters and thresholds. The seat identities are
/// deployment facts and not constants of this crate, so they are compared where
/// the deployment's own copy is available -- [`authorize_release`], against the
/// keys the audit behind the spend actually ran under. Repeating them here
/// against something this file made up would be checking the artifact against
/// itself, which is the same reason `identity` is not compared here.
///
/// It deliberately does not compare [`CohortStructure::identity`]. The two
/// organisations' keys are deployment facts and not constants of this crate, and
/// [`audit`] has already checked each commitment against the key the funder
/// itself supplied -- comparing them again here, against something this file
/// made up, would be checking the artifact against itself.
///
/// [`audit`]: crate::audit
/// [`CohortStructure::identity`]: crate::ceremony::CohortStructure::identity
pub fn check_decided_structure(audited: &AuditedRoot) -> Result<(), ReleaseRefused> {
    let (owners_found, gates_found) = audited.structure();
    check_decided_shape(
        owners_found.threshold(),
        owners_found.roster(),
        gates_found.threshold(),
        gates_found.roster(),
    )
}

/// `D_i`, the subaddress spend key a depositor is told to pay.
///
/// It takes the AUTHORISATION and not the spend, which is the whole point: this
/// function cannot be reached with a key that has not passed
/// [`authorize_release`], and a deployment's own funding and release paths
/// should take the same argument for the same reason.
///
/// The two doctests below are the evidence, and they share a prefix so the
/// second's failure is attributable to its last line alone. A simulated spend
/// is used because it has the decided SHAPE and the right subaddress -- the only
/// thing it lacks is the authorisation. First, that the prefix compiles and runs
/// and that the gate is what refuses the key:
///
/// ```
/// use two_cohort::ceremony::{Parties, SeatRoster};
/// use two_cohort::identity::IdentityKey;
/// use two_cohort::{production, CohortSpec, CompositeSpend, ControlDomain, Gates, Owners};
///
/// let seat = |n: u64| IdentityKey::from_seed(&[0x10 + n as u8; 32]).public();
/// let parties = Parties::new(
///     IdentityKey::from_seed(&[0x01; 32]).public(),
///     SeatRoster::<Owners>::new((0..3).map(|k| (Owners::nth(k), seat(k)))).unwrap(),
///     IdentityKey::from_seed(&[0x02; 32]).public(),
///     SeatRoster::<Gates>::new([(Gates::nth(0), seat(9))]).unwrap(),
/// );
/// let spend = CompositeSpend::simulate_from_seed(
///     0,
///     &CohortSpec::<Owners>::sequential(2, 3),
///     &CohortSpec::<Gates>::sequential(1, 1),
///     7,
/// )
/// .unwrap();
/// assert_eq!(
///     production::authorize_release(&spend, &parties).unwrap_err(),
///     production::ReleaseRefused::NotFromCeremony,
/// );
/// ```
///
/// ...and second, that walking past the gate is not something a caller can do
/// by forgetting to look:
///
/// ```compile_fail
/// use two_cohort::ceremony::{Parties, SeatRoster};
/// use two_cohort::identity::IdentityKey;
/// use two_cohort::{production, CohortSpec, CompositeSpend, ControlDomain, Gates, Owners};
///
/// let seat = |n: u64| IdentityKey::from_seed(&[0x10 + n as u8; 32]).public();
/// let parties = Parties::new(
///     IdentityKey::from_seed(&[0x01; 32]).public(),
///     SeatRoster::<Owners>::new((0..3).map(|k| (Owners::nth(k), seat(k)))).unwrap(),
///     IdentityKey::from_seed(&[0x02; 32]).public(),
///     SeatRoster::<Gates>::new([(Gates::nth(0), seat(9))]).unwrap(),
/// );
/// let spend = CompositeSpend::simulate_from_seed(
///     0,
///     &CohortSpec::<Owners>::sequential(2, 3),
///     &CohortSpec::<Gates>::sequential(1, 1),
///     7,
/// )
/// .unwrap();
/// let _ = &parties;
/// // The one changed line.
/// let _paid_to = production::deposit_spend_key(&spend);
/// ```
pub fn deposit_spend_key(auth: &ReleaseAuthorization<'_>) -> RistrettoPublic {
    *auth.spend().spend_public()
}

/// Both cohorts against the decided structure.
///
/// One function so that the spend-side gate and the artifact-side funder check
/// cannot drift apart -- two copies of this comparison is exactly how a
/// deployment ends up refusing what a funder accepted.
fn check_decided_shape(
    owner_threshold: usize,
    owner_roster: &[u64],
    gate_threshold: usize,
    gate_roster: &[u64],
) -> Result<(), ReleaseRefused> {
    let decided_owners = owners();
    let decided_gates = gates();
    check_cohort(
        decided_owners.name(),
        decided_owners.threshold(),
        decided_owners.ids(),
        owner_threshold,
        owner_roster,
    )?;
    check_cohort(
        decided_gates.name(),
        decided_gates.threshold(),
        decided_gates.ids(),
        gate_threshold,
        gate_roster,
    )
}

fn check_cohort(
    cohort: &'static str,
    expected_threshold: usize,
    expected_roster: &[u64],
    found_threshold: usize,
    found_roster: &[u64],
) -> Result<(), ReleaseRefused> {
    if found_roster != expected_roster {
        return Err(ReleaseRefused::Roster {
            cohort,
            expected: expected_roster.to_vec(),
            found: found_roster.to_vec(),
        });
    }
    if found_threshold != expected_threshold {
        return Err(ReleaseRefused::Threshold {
            cohort,
            expected: expected_threshold,
            found: found_threshold,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_decided_structure_is_two_of_three_owners_and_one_gate() {
        assert_eq!(owners().threshold(), 2);
        assert_eq!(owners().ids().len(), 3);
        assert_eq!(gates().threshold(), 1);
        assert_eq!(gates().ids().len(), 1);
        assert_eq!(ENTITIES, 4);
    }

    /// **No coalition of fewer than [`COMPROMISE_THRESHOLD`] SEATS satisfies
    /// both quorums, checked by enumerating the seat subsets of the structure
    /// these functions actually return.**
    ///
    /// It replaces a test named `three_principals_must_be_compromised` whose
    /// body was `assert_eq!(COMPROMISE_THRESHOLD, 3)` plus one comparison
    /// against `owners().threshold()`. Review was right that this asserted an
    /// integer equals three and would have passed under every residual in the
    /// crate -- including a dealer holding all four seats. The constant is
    /// *defined* as `OWNER_THRESHOLD + GATE_THRESHOLD`, so reading it back
    /// tests the equals sign.
    ///
    /// What is enumerated below is the access structure: every subset of the
    /// four seats, kept if it holds an operator quorum AND a gate quorum, and
    /// the smallest survivor compared against the constant. That fails if
    /// anyone edits `owners()` or `gates()` away from the constants, if the two
    /// rosters stop being disjoint (the `r` in `T = max(k, g, k + g - r)`), or
    /// if the constant is raised without the structure moving under it.
    /// `AccessStructure.tla` proves the formula and its tightness in general;
    /// this checks the decided instance. Mutation-checked at three points --
    /// `owners()` drifting to 1-of-3, `gates()` drifting to 0-of-1, and the
    /// constant inflated by one -- and the enumeration catches each.
    ///
    /// What it deliberately does NOT catch, so nobody reads it as more: editing
    /// `OWNER_THRESHOLD` itself. The constant is defined over it, so the
    /// structure and the claim move together and the pair stays consistent --
    /// which is the correct outcome, since that edit changes what was decided
    /// rather than breaking the relation between the decision and the code.
    /// `docs/FINAL-PLAN.md` §2 is where the decision lives.
    ///
    /// **It counts SEATS.** Turning that into "three principals" needs the
    /// assumption that distinct seats are distinct principals, which nothing
    /// here establishes and `tests/seat_identity.rs` performs the failure of.
    /// The old name asserted the conclusion this test cannot reach.
    #[test]
    fn no_coalition_of_fewer_than_three_seats_qualifies() {
        let owner_ids = owners().ids().to_vec();
        let gate_ids = gates().ids().to_vec();

        // r = 0 in the formula. The type system already keeps the two domains
        // apart; this is the arithmetic's own premise, checked where the
        // arithmetic is.
        for id in &owner_ids {
            assert!(
                !gate_ids.contains(id),
                "the rosters must be disjoint or the threshold formula's r is \
                 not zero and this structure is not the one that was decided"
            );
        }

        let seats: Vec<bool> = owner_ids
            .iter()
            .map(|_| true)
            .chain(gate_ids.iter().map(|_| false))
            .collect();
        assert_eq!(seats.len(), ENTITIES);

        let mut smallest_qualifying = None::<usize>;
        for mask in 0u32..(1 << seats.len()) {
            let chosen: Vec<bool> = seats
                .iter()
                .enumerate()
                .filter(|(i, _)| mask >> i & 1 == 1)
                .map(|(_, &is_owner)| is_owner)
                .collect();
            let owners_in = chosen.iter().filter(|&&is_owner| is_owner).count();
            let gates_in = chosen.len() - owners_in;
            if owners_in >= owners().threshold() && gates_in >= gates().threshold() {
                smallest_qualifying =
                    Some(smallest_qualifying.map_or(chosen.len(), |s: usize| s.min(chosen.len())));
            }
        }

        assert_eq!(
            smallest_qualifying,
            Some(COMPROMISE_THRESHOLD),
            "the smallest coalition that satisfies both quorums must be exactly \
             the compromise threshold: larger means the constant understates the \
             structure, smaller means it overstates it"
        );
        assert!(
            COMPROMISE_THRESHOLD > owners().threshold(),
            "the gate must raise the bar above an operator quorum alone, or it \
             is not doing anything"
        );
    }

    #[test]
    fn one_lost_operator_key_is_survivable_and_one_lost_gate_key_is_not() {
        // This asymmetry is the reason for the fourth entity, and the reason
        // gate key management needs the same rigor as operator key management
        // despite there being only one of them.
        assert!(
            owners().ids().len() > owners().threshold(),
            "operators must tolerate one loss"
        );
        assert_eq!(
            gates().ids().len(),
            gates().threshold(),
            "the gate tolerates NO loss: losing it loses the funds, and there \
             is deliberately no recovery path"
        );
    }

    #[test]
    fn the_cohorts_occupy_disjoint_id_ranges() {
        let o: Vec<u64> = owners().ids().to_vec();
        let g: Vec<u64> = gates().ids().to_vec();
        assert!(
            o.iter().all(|i| !g.contains(i)),
            "overlapping ids let a gate subset be silently replaced by an \
             owner one: {o:?} vs {g:?}"
        );
    }
}
