//! The decided production access structure.
//!
//! Written as code rather than left in a document because a parameter that
//! lives only in prose drifts from the parameter the signer actually uses, and
//! nothing notices. Anything that builds a production composite key should
//! take its shape from here.
//!
//! **Decided: 3 operators at 2-of-3, and 1 independent gate.** Four entities;
//! three must be compromised before funds can move -- *given* that the four
//! seats are four independent principals, which is an assumption about the world
//! and not something the constants below, or anything in this crate, establish.
//! See "What this module does NOT encode".
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
//!     three hats, and `2-of-3` of them is no barrier at all. Nothing in the
//!     artifact distinguishes the two cases:
//!     [`audit`](crate::audit) is told ONE identity key per COHORT, not one per
//!     seat, so a single organisation that deals all three operator shares to
//!     itself and endorses the commitment with its own real key produces an
//!     artifact that audits, passes [`authorize_release`], and reaches
//!     [`deposit_spend_key`] --
//!     `tests/forgery.rs::a_dealt_owner_cohort_passes_the_audit_and_the_release_gate`
//!     performs it and then opens an output paid to the published address with
//!     two principals rather than three.
//!
//! Both are organisational facts and no test here can see them, and neither is
//! fully closable by any artifact. Per-seat identity keys -- which
//! `crates/ceremony/src/machine.rs` already carries as a
//! `ParticipantId -> IdentityPublic` map for identifiable abort, and which do
//! not reach `CompositionArtifact` today -- would put per-seat KEY ATTRIBUTION
//! inside the artifact. They would not establish that four keys are four
//! entities, for the same reason two cohort keys do not establish two
//! organisations, and they would not stop a dealer that distributed shares to
//! four real parties while keeping copies. What they would change is the bar:
//! the funder's check is over 2 keys today while [`COMPROMISE_THRESHOLD`] is 3,
//! and it would become 4 keys obtained from 4 named parties.
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
//! of the organisations this deployment names, and are the two cohorts the
//! decided structure. The middle
//! one matters as much as the first, because a ceremony run by an entirely
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
//! component sum. "Every published verification share carries a proof" is not
//! "every seat answered a proof": with no per-seat identity in the artifact,
//! nothing connects the proof for `V_i` to whoever really holds seat `i` -- see
//! the operator-seat paragraph above. And "endorsed under the identity key I
//! supplied" is a statement about a KEY, not about an organisation.
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
    ceremony::{AuditedRoot, CeremonyId, Parties},
    identity::IdentityPublic,
    CohortSpec, CompositeSpend, Gates, Owners, Provenance,
};

/// Operators: any 2 of 3.
pub const OWNER_THRESHOLD: usize = 2;
pub const OWNER_COUNT: usize = 3;

/// Gates: the single independent gate must sign.
pub const GATE_THRESHOLD: usize = 1;
pub const GATE_COUNT: usize = 1;

/// Distinct compromise domains in the decided structure.
pub const ENTITIES: usize = OWNER_COUNT + GATE_COUNT;

/// Principals that must be compromised before funds can move:
/// `T = max(k, g, k + g - r)` with no overlap, so `k + g`.
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
/// Refuses unless three things hold at once: the root came out of a composition
/// ceremony; that ceremony was audited against the identity keys of the
/// organisations named in `parties`; and both cohorts are exactly the decided
/// structure -- [`owners`] at [`OWNER_THRESHOLD`], [`gates`] at
/// [`GATE_THRESHOLD`].
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
///   * a root whose three OPERATOR SEATS are one entity. The endorser arm checks
///     one identity key per cohort, so an operator organisation that ran no DKG,
///     dealt all three shares to itself and endorsed the seal with its own real
///     key is admitted here --
///     `tests/forgery.rs::a_dealt_owner_cohort_passes_the_audit_and_the_release_gate`
///     runs it to `deposit_spend_key` and then spends the published address with
///     two principals against a [`COMPROMISE_THRESHOLD`] of three.
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
    check_decided_shape(
        spend.owners().threshold(),
        spend.owners().roster(),
        spend.gates().threshold(),
        spend.gates().roster(),
    )?;
    Ok(ReleaseAuthorization { spend, ceremony })
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
/// [`audit`] says what the structure IS -- which participant IDS hold seats, how
/// many of them must act, and which identity key endorsed each cohort's
/// commitment. It does not say WHO those ids are; there is no per-seat identity
/// in the artifact. This says whether that structure is the one that was
/// DECIDED.
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
/// use two_cohort::ceremony::Parties;
/// use two_cohort::identity::IdentityKey;
/// use two_cohort::{production, CohortSpec, CompositeSpend, Gates, Owners};
///
/// let parties = Parties::new(
///     IdentityKey::from_seed(&[0x01; 32]).public(),
///     IdentityKey::from_seed(&[0x02; 32]).public(),
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
/// use two_cohort::ceremony::Parties;
/// use two_cohort::identity::IdentityKey;
/// use two_cohort::{production, CohortSpec, CompositeSpend, Gates, Owners};
///
/// let parties = Parties::new(
///     IdentityKey::from_seed(&[0x01; 32]).public(),
///     IdentityKey::from_seed(&[0x02; 32]).public(),
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

    #[test]
    fn three_principals_must_be_compromised() {
        // T = max(k, g, k + g - r), r = 0 because the rosters are disjoint.
        // Stated here as the consequence a reader cares about rather than as
        // the formula; AccessStructure.tla proves the formula and its
        // tightness.
        assert_eq!(COMPROMISE_THRESHOLD, 3);
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
