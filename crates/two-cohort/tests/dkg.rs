//! Per-cohort key generation: no dealer, and a share that can be checked.
//!
//! What entitles these tests to their conclusions:
//!
//!   * The DKG is driven through its own three rounds, one state machine per
//!     participant, with every message an explicit value routed by hand. No
//!     test calls anything that generates a cohort secret.
//!   * Every rejection test uses the SAME driver as the happy path, and each
//!     carries a CONTROL: the same participant, same run, same messages, with
//!     only the substitution removed, completing successfully. A rejection with
//!     no control beside it proves only that something broke.
//!
//!     This used to say "and changes exactly one message". Review found that
//!     false and it is worth keeping the correction rather than quietly
//!     rewording: `a_contribution_relabelled_between_two_seats_that_share_a_key_is_refused`
//!     swaps TWO map entries, and
//!     `a_missing_earlier_peer_is_reported_before_a_later_peers_bad_attestation`
//!     and `a_map_that_is_both_unattributable_and_off_roster_reports_the_attribution`
//!     are ABOUT maps with two faults -- a single fault cannot distinguish the
//!     orderings they are testing. The rule that actually holds is the control,
//!     and each of those three has one per fault.
//!   * The inconsistent-dealing test constructs a genuinely malicious dealer --
//!     one that publishes commitments to polynomial B while dealing shares from
//!     polynomial A. Both polynomials come from real PedPoP runs under the same
//!     ceremony, so the commitments carry a valid proof of knowledge and the
//!     share message is properly encrypted and authenticated. The only thing
//!     wrong with it is the thing the VSS check exists to catch.
//!   * The attribution tests at the end of the file present REAL round-one
//!     messages from real PedPoP runs, never fabricated bytes.
//!
//!     They are NOT all "wrong in their attestation alone", which this said
//!     before review checked it, and the sentence that replaced it was wrong the
//!     other way. The accurate division is:
//!
//!       - **attestation-only** -- `an_attestation_does_not_carry_to_another_contribution_by_the_same_seat`
//!         and `an_attestation_built_for_the_other_cohort_does_not_verify_here`.
//!         Both present a message this very run produced at this very slot, so
//!         PedPoP has no objection and the attestation is the only thing
//!         separating accept from refuse;
//!       - **layered** -- the two transplant tests, the foreign-ceremony test and
//!         the impostor test. Each presents a message from another context, which
//!         PedPoP also refuses a step later, and each asserts BOTH layers rather
//!         than pretending to isolate one;
//!       - **also layered, though it reads as attestation-only** -- the shared-key
//!         relabelling test. The swap moves a message between two INDICES, and
//!         PedPoP binds the index, so it would be refused a round later too. Its
//!         own prose says so.
//!
//!     What this crate cannot build is a message well-formed for this run's slot
//!     produced by a party WITHOUT that seat's key: `Committing::begin` is the
//!     only source of a `Contribution` and it demands the key first. An
//!     independent implementation can build one -- every input is public -- and
//!     against that message the attestation is the only refusal there is. It
//!     cannot presently be fed in either, because `Contribution` has no parser.
//!
//! What none of it establishes: that a cohort's `n` seat keys are `n` parties,
//! or that a seat which signs on request has kept anything. The residual tests
//! near the end of the file perform both rather than describing them.

use std::collections::HashMap;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G, edwards::CompressedEdwardsY,
    ristretto::RistrettoPoint, traits::IsIdentity,
};
use mc_crypto_keys::Ed25519Public;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use two_cohort::{
    ceremony::{dkg_contribution_payload, dkg_roster_digest},
    dkg::{run_dkg, CohortShare, Committing, Contribution, DkgError, ShareMessage},
    identity::{IdentityKey, IdentityPublic, IdentitySignature},
    production, subsets_of, CeremonyId, Cohort, CohortSpec, ComponentClaim, ControlDomain, Error,
    Gates, Owners, SeatRoster,
};

mod common;

fn ceremony(seed: u8) -> CeremonyId {
    CeremonyId::new("dkg tests", &[seed; 32])
}

/// The seat roster a cohort of `n` runs under: the first `n` ids of the domain,
/// each held by its own party.
///
/// Built from the DOMAIN rather than from the spec so that the malformed-spec
/// rejection tests below can still pass a well-formed one. That is not a way
/// round those tests: `Committing::begin` validates the participant roster
/// before it compares the seats, so the error they assert is still the one they
/// get, and `a_seat_roster_that_is_not_the_participant_roster_is_refused`
/// covers the seat comparison on its own.
fn seats<C: ControlDomain>(n: usize) -> SeatRoster<C> {
    common::seats_over::<C>(&(0..n as u64).map(C::nth).collect::<Vec<_>>())
}

/// The long-term identity key of the party holding seat `id` of cohort `C`.
///
/// The same key the [`seats`] roster names for it -- so a participant driven
/// through [`Committing::begin`] with this attests under the key its peers will
/// check against. A test that wants a key the seat does NOT hold makes its own.
fn sk<C: ControlDomain>(id: u64) -> IdentityKey {
    common::seat_key_of::<C>(id)
}

/// Every seat's PRIVATE identity key for a cohort of `n`, which is what
/// [`run_dkg`] needs in order to drive every participant from one process.
///
/// That this file can build it is the residual, not a convenience -- see
/// [`a_party_that_holds_every_seat_key_still_runs_the_whole_dkg_alone`].
fn identities<C: ControlDomain>(n: usize) -> HashMap<u64, IdentityKey> {
    common::seat_identities_over::<C>(&(0..n as u64).map(C::nth).collect::<Vec<_>>())
}

/// The digest of WHO is running a cohort, as `Committing::begin` computes it.
///
/// Rebuilt here from the public API rather than exported from the crate, because
/// a test that asked the crate for the bytes it is checking against would be
/// checking the crate against itself. `spec.ids()` is ascending -- `Roster::new`
/// requires it -- so this is the same vector, in the same order.
fn roster_digest<C: ControlDomain>(spec: &CohortSpec<C>, seats: &SeatRoster<C>) -> [u8; 32] {
    dkg_roster_digest(
        spec.threshold(),
        &spec
            .ids()
            .iter()
            .map(|&id| {
                (
                    id,
                    seats.key_of(id).expect("the seat roster names this roster"),
                )
            })
            .collect::<Vec<_>>(),
    )
}

/// One participant's state machine together with the round-one map a
/// coordinator would hand it, INCLUDING its own entry.
///
/// **Repeatable**: called twice with the same seed it produces byte-identical
/// results, so a test can drive several attempts that differ in exactly one
/// thing -- the map -- without the state machines differing too.
///
/// It has to be built this way now, and the tests below used to be built the
/// other way. They ran the broadcast loop once and then rebuilt the victim's
/// state from a CLONE of the RNG taken after the loop, so the victim's state
/// machine held a polynomial whose commitments were not the ones in the map. It
/// did not matter while `deal` skipped the caller's own entry. It matters now:
/// `deal` compares that entry against the contribution the caller produced, and
/// a state machine drawn from a different point in the stream is a real
/// inconsistency -- in a deployment it would deal shares that no peer could
/// check against the commitments it had broadcast. So the fixture was wrong and
/// the guard found it, which is the outcome one wants from a guard.
fn round_one<C: ControlDomain>(
    cid: &CeremonyId,
    spec: &CohortSpec<C>,
    seats: &SeatRoster<C>,
    identities: &HashMap<u64, IdentityKey>,
    me: u64,
    seed: u64,
) -> (Committing<C>, HashMap<u64, Contribution>) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut map = HashMap::new();
    let mut mine = None;
    for &id in spec.ids() {
        let (state, msg) = Committing::<C>::begin(
            cid,
            spec,
            seats,
            id,
            identities.get(&id).expect("an identity key for every seat"),
            &mut rng,
        )
        .expect("roster");
        if id == me {
            mine = Some(state);
        }
        map.insert(id, msg);
    }
    (mine.expect("`me` is on the roster"), map)
}

// ---------------------------------------------------------------------------
// The rounds, driven by hand so a test can choose what one participant sees.
// ---------------------------------------------------------------------------

/// Run a whole cohort's DKG, with `victim` given a substituted round-one
/// message in place of the honest broadcast from one dealer.
///
/// Everyone else, including the dealer, behaves honestly and deals from the
/// polynomial it committed to. Returns each participant's outcome, so a test
/// can assert who was affected as well as how.
///
/// One knock-on is worth naming, because a test asserts around it: PedPoP's
/// round-one message carries the sender's ENCRYPTION key as well as its VSS
/// commitments, so a victim handed a substituted message also holds the wrong
/// encryption key for that dealer, and the share the victim sends BACK to it is
/// unreadable. So the substitution disturbs exactly two participants -- the
/// victim, on the VSS check this test is about, and the dealer, on decryption.
/// Everyone else is untouched, and that is what the tests check.
fn run_with_substituted_commitments<C: ControlDomain>(
    ceremony: &CeremonyId,
    spec: &CohortSpec<C>,
    seed: u64,
    victim: u64,
    substitute: Option<(u64, Contribution)>,
) -> HashMap<u64, Result<CohortShare<C>, DkgError>> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    // Round one: every participant publishes commitments.
    let mut committing = Vec::new();
    let mut broadcast = HashMap::new();
    for &id in spec.ids() {
        let (state, msg) = Committing::<C>::begin(ceremony, spec, &seats::<C>(spec.ids().len()), id, &sk::<C>(id), &mut rng)
            .expect("roster");
        broadcast.insert(id, msg);
        committing.push((id, state));
    }

    // What the victim is given, which is the only thing that varies.
    let mut victim_sees = broadcast.clone();
    if let Some((dealer, msg)) = substitute {
        victim_sees.insert(dealer, msg);
    }

    // Round two: every participant deals. The victim registers the substituted
    // commitments here -- this is where PedPoP records what it will later check
    // the shares it receives against.
    let mut dealing = Vec::new();
    let mut outbox: HashMap<u64, HashMap<u64, ShareMessage>> = HashMap::new();
    for (id, state) in committing {
        let seen = if id == victim { &victim_sees } else { &broadcast };
        let (next, shares) = state.deal(&mut rng, seen).expect("honest round two");
        outbox.insert(id, shares);
        dealing.push((id, next));
    }

    // Round three: each participant checks every received share against the
    // commitments it registered.
    let mut out = HashMap::new();
    for (id, state) in dealing {
        let inbox: HashMap<u64, ShareMessage> = outbox
            .iter()
            .filter(|(&sender, _)| sender != id)
            .map(|(&sender, shares)| (sender, shares[&id].clone()))
            .collect();
        // `finish` checks every received share against its dealer's
        // commitments; `confirm` is the separate acknowledgement that everyone
        // ELSE reported success too, which one process legitimately can make on
        // every participant's behalf. Chained here so these tests keep asserting
        // on the same `Result<CohortShare, _>` they always did -- what changed
        // is that a deployment now has to make that call itself.
        out.insert(
            id,
            state.finish(&mut rng, &inbox).and_then(|c| c.confirm()),
        );
    }
    out
}

/// A valid commitment message from `dealer` over a DIFFERENT polynomial.
///
/// A real round-one message from a real (if throwaway) PedPoP run under
/// `ceremony`: its proof of knowledge verifies, because the polynomial behind
/// it genuinely exists and the dealer genuinely knows its constant term.
fn commitments_over_another_polynomial<C: ControlDomain>(
    ceremony: &CeremonyId,
    spec: &CohortSpec<C>,
    dealer: u64,
    seed: u64,
) -> Contribution {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    Committing::<C>::begin(ceremony, spec, &seats::<C>(spec.ids().len()), dealer, &sk::<C>(dealer), &mut rng)
        .expect("well-formed roster")
        .1
}

// ---------------------------------------------------------------------------
// Happy path.
// ---------------------------------------------------------------------------

/// Every participant ends up with a share of ONE cohort key, and that key is
/// the interpolation of the published verification shares over any qualifying
/// quorum.
#[test]
fn a_completed_dkg_gives_every_participant_a_share_of_one_key() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let shares = run_dkg::<Owners, _>(&ceremony(1), &spec, &seats::<Owners>(spec.ids().len()), &identities::<Owners>(spec.ids().len()), &mut rng).expect("honest dkg");

    assert_eq!(shares.len(), 3);
    let component = shares[0].key().component();

    for share in &shares {
        // Every participant computed the same public material...
        assert_eq!(share.key().component(), component);
        assert_eq!(share.key().roster(), spec.ids());
        assert_eq!(share.key().threshold(), 2);
        // ...and holds a share that opens the verification share published for
        // it. That is the participant's own check, against public data.
        share
            .verify()
            .expect("own share opens own verification share");
    }

    // The verification shares are not a separate claim: every qualifying quorum
    // interpolates them to the same component. A dealing that failed this is
    // the "only some quorums can spend" defect, discovered after funding.
    for quorum in subsets_of(spec.ids(), 2) {
        assert_eq!(
            shares[0]
                .key()
                .cohort()
                .public(&quorum)
                .expect("qualifying quorum"),
            component,
            "quorum {quorum:?} interpolates to a different component"
        );
    }
}

/// A quorum's Lagrange-weighted terms sum, in the group, to the cohort key.
///
/// Asserted in the group because that is the only place it can be asserted
/// without materialising the cohort secret -- which is the thing no process is
/// supposed to be able to do.
#[test]
fn a_quorums_terms_sum_to_the_cohort_key() {
    let spec = CohortSpec::<Gates>::sequential(3, 5);
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let shares = run_dkg::<Gates, _>(&ceremony(2), &spec, &seats::<Gates>(spec.ids().len()), &identities::<Gates>(spec.ids().len()), &mut rng).expect("honest dkg");
    let component = shares[0].key().component();

    for quorum in subsets_of(spec.ids(), 3) {
        let sum: RistrettoPoint = quorum
            .iter()
            .map(|&id| {
                let share = shares.iter().find(|s| s.id() == id).expect("on roster");
                share.term(&quorum).expect("quorum member").in_group(&G)
            })
            .sum();
        assert_eq!(
            sum, component,
            "quorum {quorum:?}'s terms do not sum to the cohort key"
        );
    }
}

/// A below-threshold subset is refused, not interpolated into a wrong scalar.
#[test]
fn a_below_threshold_subset_has_no_term() {
    let spec = CohortSpec::<Gates>::sequential(3, 5);
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let shares = run_dkg::<Gates, _>(&ceremony(3), &spec, &seats::<Gates>(spec.ids().len()), &identities::<Gates>(spec.ids().len()), &mut rng).expect("honest dkg");

    let short = vec![Gates::nth(0), Gates::nth(1)];
    let err = shares[0].term(&short).unwrap_err();
    assert!(
        matches!(&err, DkgError::Roster { source, .. }
            if matches!(source.kind(), Error::BelowThreshold { have: 2, threshold: 3 })),
        "expected a below-threshold rejection, got {err}"
    );

    // Control: the same participant, one more member, and the term exists.
    let full = vec![Gates::nth(0), Gates::nth(1), Gates::nth(2)];
    assert!(shares[0].term(&full).is_ok());
}

/// A participant outside the quorum has no term for it.
#[test]
fn a_participant_outside_the_quorum_has_no_term() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let mut rng = ChaCha20Rng::seed_from_u64(4);
    let shares = run_dkg::<Owners, _>(&ceremony(4), &spec, &seats::<Owners>(spec.ids().len()), &identities::<Owners>(spec.ids().len()), &mut rng).expect("honest dkg");

    let quorum = vec![Owners::nth(0), Owners::nth(1)];
    let outsider = shares.iter().find(|s| s.id() == Owners::nth(2)).unwrap();
    assert_eq!(
        outsider.term(&quorum).unwrap_err(),
        DkgError::NotOnRoster {
            cohort: "owners",
            id: Owners::nth(2)
        }
    );
    // Control: an insider does have one.
    assert!(shares[0].term(&quorum).is_ok());
}

// ---------------------------------------------------------------------------
// The VSS check: an inconsistent dealing, refused, with the dealer named.
// ---------------------------------------------------------------------------

/// **REQUIRED: a share inconsistent with the VSS commitments is refused, and
/// the error names the dealer.**
///
/// Dealer `D` broadcasts commitments to polynomial B while dealing shares from
/// polynomial A. Both are genuine PedPoP polynomials under this ceremony, so:
///
///   * the substituted commitments carry a valid proof of knowledge -- round
///     two accepts them, so that is not what rejects this;
///   * the share message is encrypted to the victim's own round-one key and
///     authenticated as `D`'s -- decryption is not what rejects this either;
///   * the decrypted value is a canonical scalar.
///
/// The only defect is that `share_{D->victim} * G` does not evaluate the
/// commitments `D` published at the victim's point. That is the VSS check and
/// nothing else.
#[test]
fn an_inconsistent_dealing_is_refused_and_names_the_dealer() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let cid = ceremony(5);
    let (dealer, victim, bystander) = (Owners::nth(0), Owners::nth(1), Owners::nth(2));

    // CONTROL: the identical run with no substitution. Every participant
    // completes. Without this, the rejection below could be the harness.
    let control = run_with_substituted_commitments::<Owners>(&cid, &spec, 50, victim, None);
    for &id in spec.ids() {
        control[&id]
            .as_ref()
            .expect("the unmodified run completes for everyone");
    }

    let other = commitments_over_another_polynomial::<Owners>(&cid, &spec, dealer, 51);
    let run =
        run_with_substituted_commitments::<Owners>(&cid, &spec, 50, victim, Some((dealer, other)));

    assert_eq!(
        run[&victim].as_ref().err().cloned().expect(
            "the VSS check must refuse a share that does not open its dealer's commitments"
        ),
        DkgError::InconsistentShare {
            cohort: "owners",
            dealer,
            recipient: victim,
            // Blamable: the message authenticated as the dealer's and decrypted
            // to a canonical scalar, so a blame proof exists and an adjudicator
            // could confirm the dealer, not the accuser, is at fault.
            blamable: true,
        },
        "the error must name the dealer whose commitments the share does not satisfy"
    );

    // The bystander is untouched: it saw the honest broadcast and completes.
    // So the rejection is attributable to what the victim was told, not to the
    // run having been perturbed generally.
    run[&bystander]
        .as_ref()
        .expect("a participant that saw the honest broadcast completes");

    // The dealer also fails, and for a DIFFERENT reason: the victim, believing
    // a lie about the dealer's encryption key, encrypted its own share to that
    // wrong key, so what the dealer decrypts is noise and fails the VSS check
    // against the victim's commitments. Asserted rather than ignored, so this
    // file states every effect the substitution has -- and note the blame lands
    // on the victim, which is correct: from the dealer's side the victim really
    // did send an unusable share.
    assert_eq!(
        run[&dealer].as_ref().err().cloned().unwrap(),
        DkgError::InconsistentShare {
            cohort: "owners",
            dealer: victim,
            recipient: dealer,
            blamable: true,
        }
    );
}

/// Commitments whose proof of knowledge is over a DIFFERENT ceremony are
/// refused, naming the dealer -- **at both layers, in the order `deal` checks
/// them.**
///
/// The ceremony id is in two independent places, and this test walks through
/// both because the order decides what a participant is told:
///
///   * it is in the ATTESTATION transcript
///     ([`dkg_contribution_payload`]), and `deal` checks attribution first, so
///     a foreign contribution carrying its foreign attestation is reported as
///     `ContributionNotAttributable` -- "this is not the message that seat sent
///     in this ceremony". **That assertion is what fails if the ceremony id is
///     deleted from `dkg_contribution_payload`**: the signature then verifies
///     and the run falls through to the second layer;
///   * it is in PedPoP's own proof-of-knowledge context
///     ([`CeremonyId::dkg_context`]), so a dealer that really does hold its seat
///     key and RE-ATTESTS the foreign message under this ceremony gets past the
///     first layer and is refused by the second, as `BadCommitments`. That is
///     the original claim of this test and it is unchanged; the re-attestation
///     is what isolates it now that the first layer exists.
#[test]
fn commitments_from_another_ceremony_are_refused_and_name_the_dealer() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let (here, elsewhere) = (ceremony(6), ceremony(7));
    let (dealer, victim) = (Owners::nth(0), Owners::nth(2));

    let control = run_with_substituted_commitments::<Owners>(&here, &spec, 60, victim, None);
    for &id in spec.ids() {
        control[&id].as_ref().expect("the unmodified run completes");
    }

    // A perfectly valid commitment message -- for a different ceremony.
    let foreign = commitments_over_another_polynomial::<Owners>(&elsewhere, &spec, dealer, 61);
    let ids = identities::<Owners>(spec.ids().len());
    let fixture = || {
        round_one(
            &here,
            &spec,
            &seats::<Owners>(spec.ids().len()),
            &ids,
            victim,
            600,
        )
    };
    let (_, honest_broadcast) = fixture();
    let mut rng = ChaCha20Rng::seed_from_u64(6000);

    // ---- layer one: the foreign message with its foreign attestation ----
    let mut transplanted = honest_broadcast.clone();
    transplanted.insert(dealer, foreign.clone());
    let (state_a, _) = fixture();
    assert_eq!(
        state_a
            .deal(&mut rng, &transplanted)
            .err()
            .expect("an attestation made in another ceremony must not verify here"),
        DkgError::ContributionNotAttributable {
            cohort: "owners",
            dealer,
            key: sk::<Owners>(dealer).public(),
        },
    );

    // ---- layer two: the same message, RE-ATTESTED under this ceremony ----
    //
    // The dealer holds its own seat key, so this is a thing it can really do:
    // it is only the polynomial that came from elsewhere. Attribution now
    // passes, and PedPoP's own context binding is what refuses it.
    let reattested = foreign.with_attestation(sk::<Owners>(dealer).sign(
        &dkg_contribution_payload(
            &here,
            "owners",
            &roster_digest(&spec, &seats::<Owners>(spec.ids().len())),
            dealer,
            &foreign.commitment_bytes(),
        ),
    ));
    let mut broadcast = honest_broadcast.clone();
    broadcast.insert(dealer, reattested);
    let (mine, _) = fixture();
    let err = mine
        .deal(&mut rng, &broadcast)
        .err()
        .expect("a proof of knowledge over another ceremony must not verify");
    assert_eq!(
        err,
        DkgError::BadCommitments {
            cohort: "owners",
            dealer
        }
    );

    let (again, _) = fixture();
    assert!(
        again.deal(&mut rng, &honest_broadcast).is_ok(),
        "the same round with the honest message is accepted"
    );
}

/// A round missing a participant's message names the participant, rather than
/// proceeding with a smaller set.
#[test]
fn a_missing_message_names_the_participant() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let cid = ceremony(8);
    let mut rng = ChaCha20Rng::seed_from_u64(80);

    let mut broadcast = HashMap::new();
    let mut mine = None;
    for &id in spec.ids() {
        let (state, msg) = Committing::<Owners>::begin(&cid, &spec, &seats::<Owners>(spec.ids().len()), id, &sk::<Owners>(id), &mut rng)
            .expect("roster");
        broadcast.insert(id, msg);
        if id == Owners::nth(0) {
            mine = Some(state);
        }
    }
    let mine = mine.unwrap();

    let mut short = broadcast.clone();
    short.remove(&Owners::nth(1));
    assert_eq!(
        mine.deal(&mut rng, &short).err().unwrap(),
        DkgError::MissingMessage {
            cohort: "owners",
            round: 1,
            from: Owners::nth(1),
        }
    );
}

// ---------------------------------------------------------------------------
// Roster rules carried through the DKG.
// ---------------------------------------------------------------------------

/// A gate id cannot be dealt into an owner cohort: the control-domain rule,
/// enforced before any key exists.
#[test]
fn an_id_from_the_wrong_domain_is_refused_before_any_key_exists() {
    let spec = CohortSpec::<Owners>::with_ids(2, &[Owners::nth(0), Gates::nth(0), Owners::nth(1)]);
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let err = run_dkg::<Owners, _>(&ceremony(9), &spec, &seats::<Owners>(spec.ids().len()), &identities::<Owners>(spec.ids().len()), &mut rng).unwrap_err();
    assert!(
        matches!(
            &err,
            DkgError::Roster {
                cohort: "owners",
                source: Error::IdOutsideDomain { id, .. }
            } if *id == Gates::nth(0)
        ),
        "got {err}"
    );
}

/// The roster-position-to-index mapping is positional, so a roster whose order
/// is not canonical is refused rather than run with participants disagreeing
/// about who holds which evaluation point.
#[test]
fn a_non_canonical_roster_order_is_refused() {
    let spec = CohortSpec::<Owners>::with_ids(2, &[Owners::nth(2), Owners::nth(0), Owners::nth(1)]);
    let mut rng = ChaCha20Rng::seed_from_u64(10);
    assert_eq!(
        run_dkg::<Owners, _>(&ceremony(10), &spec, &seats::<Owners>(spec.ids().len()), &identities::<Owners>(spec.ids().len()), &mut rng).unwrap_err(),
        DkgError::RosterNotCanonical {
            cohort: "owners",
            roster: vec![Owners::nth(2), Owners::nth(0), Owners::nth(1)],
        }
    );
    // Control: the same ids in ascending order run.
    assert!(run_dkg::<Owners, _>(
        &ceremony(10),
        &CohortSpec::<Owners>::sequential(2, 3),
        &seats::<Owners>(3),
        &identities::<Owners>(3),
        &mut rng
    )
    .is_ok());
}

/// Degenerate thresholds are refused.
#[test]
fn degenerate_thresholds_are_refused() {
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    assert!(matches!(
        run_dkg::<Owners, _>(&ceremony(11), &CohortSpec::sequential(4, 3), &seats::<Owners>(3), &identities::<Owners>(3), &mut rng).unwrap_err(),
        DkgError::Roster {
            source: Error::ThresholdExceedsRoster { .. },
            ..
        }
    ));
    assert!(matches!(
        run_dkg::<Owners, _>(&ceremony(11), &CohortSpec::sequential(0, 3), &seats::<Owners>(3), &identities::<Owners>(3), &mut rng).unwrap_err(),
        DkgError::Roster {
            source: Error::ThresholdZero,
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// What a DKG cohort refuses to do that a dealt one does not.
// ---------------------------------------------------------------------------

/// The cohort a DKG produces holds NO shares, so nothing can reconstruct its
/// secret from it -- not even the process that drove every participant in one
/// memory space.
///
/// Asserted against a DEALT cohort of the same shape, which does answer, so the
/// contrast is a property of the construction rather than of the roster.
#[test]
fn a_dkg_cohort_cannot_be_asked_for_a_secret_and_a_dealt_one_can() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let mut rng = ChaCha20Rng::seed_from_u64(12);
    let shares = run_dkg::<Owners, _>(&ceremony(12), &spec, &seats::<Owners>(spec.ids().len()), &identities::<Owners>(spec.ids().len()), &mut rng).expect("honest dkg");
    let cohort = shares[0].key().cohort();
    let quorum = vec![Owners::nth(0), Owners::nth(1)];

    assert!(!cohort.holds_shares());
    assert_eq!(
        cohort.reconstruct(&quorum).unwrap_err().kind(),
        &Error::SharesNotHeld
    );
    assert_eq!(
        cohort.weighted(&quorum).unwrap_err().kind(),
        &Error::SharesNotHeld
    );
    assert_eq!(
        cohort.share(Owners::nth(0)).unwrap_err().kind(),
        &Error::SharesNotHeld
    );

    // The PUBLIC interpolation, which is all a coordinator needs, still works.
    // So the refusals above are about secrets and not about the cohort being
    // unusable.
    assert_eq!(
        cohort.public(&quorum).expect("public interpolation"),
        shares[0].key().component()
    );

    let dealt = Cohort::deal_in::<Owners, _>(
        &curve25519_dalek::scalar::Scalar::from(5u64),
        2,
        spec.ids(),
        &mut rng,
    )
    .expect("dealt");
    assert!(dealt.holds_shares());
    assert_eq!(
        *dealt.reconstruct(&quorum).expect("a dealer holds them all"),
        curve25519_dalek::scalar::Scalar::from(5u64),
    );
}

// ---------------------------------------------------------------------------
// Who contributed round one.
// ---------------------------------------------------------------------------
//
// The hole these tests close, stated once here rather than in each of them:
// PedPoP's round-one proof of knowledge proves the sender knew the secret
// behind ITS OWN commitment, and nothing more. It does not say WHO the sender
// is. `Committing::deal` takes a `HashMap<u64, Contribution>`, and until the
// attestation existed the map's KEYS -- the claim about which roster id
// contributed which commitment -- were an assertion by whoever assembled the
// map. One party could generate all `n` contributions, label them, and run the
// cohort's whole key generation alone; every proof of knowledge would be real,
// because it really did know every constant term.
//
// What every test below is measuring is one thing: a contribution filed under
// seat `i` must carry a signature by the identity key that cohort's seat roster
// names for seat `i`, over the ceremony, the cohort, `i` and the commitment
// bytes. The last test in the section performs what that does NOT buy.

/// A contribution that is real, and attested by somebody who is not the seat it
/// is filed under.
///
/// The forger runs `Committing::begin` under a seat roster of its OWN key --
/// which it can, because that roster names it at every seat -- and files the
/// result into an honest cohort's round-one map. The commitments are
/// well-formed, the proof of knowledge verifies, the participant index is
/// right. Only the attestation is somebody else's.
fn contribution_from_an_impostor(
    ceremony: &CeremonyId,
    spec: &CohortSpec<Owners>,
    seat: u64,
    forger: &IdentityKey,
    seed: u64,
) -> Contribution {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mine = SeatRoster::<Owners>::new(spec.ids().iter().map(|&id| (id, forger.public())))
        .expect("a roster naming one key at every seat is well-formed");
    Committing::<Owners>::begin(ceremony, spec, &mine, seat, forger, &mut rng)
        .expect("the forger holds the key its own roster names")
        .1
}

/// **THE hole, closed: a contribution filed under a seat that seat did not
/// make is refused, naming the seat and the key it was checked under.**
///
/// **The refusal is NOT attributable to the attestation alone**, which is what
/// this said and review corrected. Since the roster digest entered PedPoP's
/// context, the forger's message -- generated under a seat roster naming the
/// forger's own key -- is also PedPoP-invalid here. CONTROL 2 below shows it:
/// re-attesting under the real seat key moves the refusal to `BadCommitments`
/// rather than clearing it. For the tests where the attestation IS the only
/// thing separating accept from refuse, see this file's header.
///
/// Note which participant does the refusing. This is a check an HONEST peer
/// makes about a message it was handed; it is not, and cannot be, a check on a
/// party that is alone in the room. See
/// [`a_party_that_holds_every_seat_key_still_runs_the_whole_dkg_alone`].
#[test]
fn a_contribution_the_seat_did_not_attest_is_refused() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let cid = ceremony(20);
    let (impersonated, victim) = (Owners::nth(0), Owners::nth(2));
    let forger = IdentityKey::from_seed(&[0xF0; 32]);
    assert_ne!(forger.public(), sk::<Owners>(impersonated).public());

    // The victim's own state machine is rebuilt for each of the three rounds
    // below rather than reused, because `deal` consumes it. Each rebuild comes
    // from `round_one` at the SAME SEED, so the three attempts differ in exactly
    // one thing: the map they are handed.
    let ids = identities::<Owners>(3);
    let fixture = || round_one(&cid, &spec, &seats::<Owners>(3), &ids, victim, 200);
    let (_, honest) = fixture();

    let forged = contribution_from_an_impostor(&cid, &spec, impersonated, &forger, 201);
    let mut broadcast = honest.clone();
    broadcast.insert(impersonated, forged.clone());

    let mut deal_rng = ChaCha20Rng::seed_from_u64(2000);
    let (state, _) = fixture();
    assert_eq!(
        state
            .deal(&mut deal_rng, &broadcast)
            .err()
            .expect("a contribution the seat did not attest must not be consumed"),
        DkgError::ContributionNotAttributable {
            cohort: "owners",
            dealer: impersonated,
            key: sk::<Owners>(impersonated).public(),
        },
    );

    // CONTROL 1: the same round with the honest message in that slot completes.
    let (control, _) = fixture();
    control
        .deal(&mut deal_rng, &honest)
        .expect("CONTROL: the honest broadcast is accepted");

    // CONTROL 2 -- LAYER TWO, and what it used to be is worth recording.
    //
    // It used to re-attest the forger's bytes under the real seat key and watch
    // them be ACCEPTED, which made the refusal above attributable to the
    // attestation and to nothing else. That control can no longer be built, and
    // the reason is this round's other change: the forger generates its
    // contribution under a seat roster naming its OWN key, so the contribution
    // carries a different `dkg_roster_digest`, so PedPoP's context differs and
    // the message fails there too. Re-attesting it moves the refusal from
    // `ContributionNotAttributable` to `BadCommitments`, which is what this now
    // asserts -- the layered shape
    // `commitments_from_another_ceremony_are_refused_and_name_the_dealer` has.
    //
    // **What that means, said rather than hidden.** Through THIS crate's API, a
    // message well-formed for this run's slot can only be produced by the holder
    // of that seat's identity key, because `begin` refuses to generate one
    // otherwise. So this crate cannot construct the input that separates the two
    // layers. An independent implementation can -- the roster digest is public
    // data -- and against that input the attestation is the only refusal there
    // is. The tests that isolate the attestation with a message this run really
    // produced are `an_attestation_does_not_carry_to_another_contribution_by_the_same_seat`
    // and `a_contribution_relabelled_between_two_seats_that_share_a_key_is_refused`.
    //
    // Note HOW the re-attestation is built: `dkg_contribution_payload` and
    // `IdentityKey::sign`, both public, with no `Committing` anywhere. That
    // composition is an entry point which attests bytes its caller supplied; the
    // crate's docs used to say no such entry point existed, and this line was
    // always the counter-example. It is performed on its own in
    // `a_seat_key_that_signs_bytes_it_did_not_generate_hands_its_half_over`.
    let mut relabelled = honest.clone();
    relabelled.insert(
        impersonated,
        forged.with_attestation(sk::<Owners>(impersonated).sign(&dkg_contribution_payload(
            &cid,
            "owners",
            &roster_digest(&spec, &seats::<Owners>(3)),
            impersonated,
            &forged.commitment_bytes(),
        ))),
    );
    let (second, _) = fixture();
    assert_eq!(
        second
            .deal(&mut deal_rng, &relabelled)
            .err()
            .expect("the forger's message was built for the forger's roster"),
        DkgError::BadCommitments {
            cohort: "owners",
            dealer: impersonated,
        },
        "with the attestation repaired the SECOND layer refuses it, because the \
         roster it was generated under is not this run's",
    );
}

/// **An attestation does not carry from one contribution to another by the same
/// seat in the same ceremony.**
///
/// The commitment bytes are in the transcript, so a seat's signature attests
/// ONE message rather than licensing everything that seat ever files. Without
/// them a party that had obtained a single attestation from a seat -- or one
/// that had simply observed the broadcast -- could substitute any polynomial it
/// liked underneath it.
///
/// **This is the test that dies if the commitment bytes are dropped from
/// `dkg_contribution_payload`.** Both contributions here are that seat's own,
/// so ceremony, cohort and roster id are identical between them and the only
/// field that separates the two is the one under test.
///
/// CONTROL: the same message with its own attestation is accepted.
#[test]
fn an_attestation_does_not_carry_to_another_contribution_by_the_same_seat() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let cid = ceremony(21);
    let (dealer, victim) = (Owners::nth(0), Owners::nth(2));

    let ids = identities::<Owners>(3);
    let fixture = || round_one(&cid, &spec, &seats::<Owners>(3), &ids, victim, 210);
    let (_, broadcast) = fixture();

    // A SECOND round-one message from the same seat, same ceremony, different
    // randomness. Equivocation, which this crate cannot detect -- but each half
    // of it is separately attested, which is what this asserts.
    let mut other_rng = ChaCha20Rng::seed_from_u64(211);
    let (_, second) = Committing::<Owners>::begin(
        &cid,
        &spec,
        &seats::<Owners>(3),
        dealer,
        &sk::<Owners>(dealer),
        &mut other_rng,
    )
    .expect("roster");
    assert_ne!(
        second.commitment_bytes(),
        broadcast[&dealer].commitment_bytes(),
        "the two contributions must really differ, or this test is vacuous",
    );

    let mut swapped = broadcast.clone();
    swapped.insert(
        dealer,
        second.with_attestation(*broadcast[&dealer].attestation()),
    );

    let mut deal_rng = ChaCha20Rng::seed_from_u64(2100);
    let (state, _) = fixture();
    assert_eq!(
        state
            .deal(&mut deal_rng, &swapped)
            .err()
            .expect("an attestation covers the bytes it was made over"),
        DkgError::ContributionNotAttributable {
            cohort: "owners",
            dealer,
            key: sk::<Owners>(dealer).public(),
        },
    );

    // CONTROL: the second message with its OWN attestation is accepted, so the
    // refusal is the transplant and not the message. This is one of the two
    // places in the file where the message under test is genuinely well-formed
    // for this run -- same ceremony, same roster, same index -- so the
    // attestation really is the only thing separating accept from refuse.
    let mut control = broadcast.clone();
    control.insert(dealer, second);
    let (state, _) = fixture();
    state
        .deal(&mut deal_rng, &control)
        .expect("CONTROL: correctly attested, and accepted");
}

/// **An attestation says WHICH SEAT it is about**, so two contributions cannot
/// be relabelled between two seats that happen to share an identity key.
///
/// **This is the test that dies if the roster id is dropped from
/// `dkg_contribution_payload`**, and it has to be built this way to isolate that
/// field: with distinct keys per seat the key lookup already refuses a
/// relabelling, so the id would never be reached. Two seats holding one key is
/// a thing [`SeatRoster`] permits -- the check that two SEATS must not share a
/// key lives at the audit, in `Parties::check_distinct`, over both cohorts.
///
/// Note that a relabelling is refused twice over: PedPoP binds the participant
/// INDEX inside its own proof of knowledge, so with the id deleted this same
/// swap fails a round later as `BadCommitments`. The point of the id is that the
/// attestation states the seat itself rather than inheriting it from a property
/// of the bytes it covers -- and the assertion below is on the exact error, so
/// the deletion is a failure and not a silent relocation.
///
/// CONTROL: the same round, unswapped, completes.
#[test]
fn a_contribution_relabelled_between_two_seats_that_share_a_key_is_refused() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let cid = ceremony(22);
    let (a, b, victim) = (Owners::nth(0), Owners::nth(1), Owners::nth(2));

    // One key at seats `a` and `b`; `victim` keeps its own.
    let shared = IdentityKey::from_seed(&[0x5D; 32]);
    let key_of = |id: u64| -> IdentityKey {
        if id == victim {
            sk::<Owners>(victim)
        } else {
            IdentityKey::from_seed(&[0x5D; 32])
        }
    };
    let roster = SeatRoster::<Owners>::new(vec![
        (a, shared.public()),
        (b, shared.public()),
        (victim, sk::<Owners>(victim).public()),
    ])
    .expect("a seat roster may name one key twice; the audit is where that is refused");

    let ids: HashMap<u64, IdentityKey> = spec.ids().iter().map(|&id| (id, key_of(id))).collect();
    let fixture = || round_one(&cid, &spec, &roster, &ids, victim, 220);
    let (_, honest) = fixture();

    // Swap the two seats that share a key. Every signature still verifies under
    // the key the roster names -- it is the SAME key -- so only the id in the
    // transcript separates them.
    let mut broadcast = honest.clone();
    let (from_a, from_b) = (honest[&a].clone(), honest[&b].clone());
    broadcast.insert(a, from_b);
    broadcast.insert(b, from_a);

    let mut deal_rng = ChaCha20Rng::seed_from_u64(2200);
    let (state, _) = fixture();
    assert_eq!(
        state
            .deal(&mut deal_rng, &broadcast)
            .err()
            .expect("an attestation made about seat b is not one about seat a"),
        DkgError::ContributionNotAttributable {
            cohort: "owners",
            dealer: a,
            key: shared.public(),
        },
    );

    let (state, _) = fixture();
    state
        .deal(&mut deal_rng, &honest)
        .expect("CONTROL: unswapped, the same round completes");
}

/// **A participant will not attest with a key its cohort's seat roster does not
/// name for it.**
///
/// An honest participant handed somebody else's seat roster, or told it holds a
/// seat it does not. It is refused at `begin`, before any key material exists,
/// because the alternative is a contribution that cannot verify anywhere and a
/// ceremony that fails at every peer with this participant's mistake reported as
/// theirs.
///
/// CONTROL: the same call with the roster's own key returns.
#[test]
fn a_participant_that_begins_with_the_wrong_identity_key_is_refused() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let cid = ceremony(23);
    let me = Owners::nth(1);
    let stranger = IdentityKey::from_seed(&[0xC3; 32]);
    let mut rng = ChaCha20Rng::seed_from_u64(230);

    assert_eq!(
        Committing::<Owners>::begin(&cid, &spec, &seats::<Owners>(3), me, &stranger, &mut rng)
            .expect_err("this key is not the one the seat roster names for this seat"),
        DkgError::IdentityNotOwn {
            cohort: "owners",
            id: me,
            expected: sk::<Owners>(me).public(),
            found: stranger.public(),
        },
    );

    Committing::<Owners>::begin(&cid, &spec, &seats::<Owners>(3), me, &sk::<Owners>(me), &mut rng)
        .expect("CONTROL: the roster's own key for this seat");
}

/// **A seat roster naming something that is not a usable identity key is refused
/// before any key material exists.**
///
/// Two causes, and `Ed25519Public::verify` -- which is `verify_strict` -- catches
/// exactly one of them:
///
///   * **the identity element.** `d = 0` is public, so anybody can sign under
///     it. `verify_strict` refuses a small-order signer outright, so without
///     this guard the refusal would still happen, one round later and reported
///     as `ContributionNotAttributable` -- "that seat did not attest" for what is
///     really "that is not a key". A worse answer to a different question;
///   * **outside the prime-order subgroup**, `Id = d*B + T`. `verify_strict`
///     does NOT refuse this one: the point is not small-order, and a party
///     holding `d` gets a verifying signature under it by grinding `k` until the
///     challenge is `0 mod 8`. That gives one secret eight distinct 32-byte
///     "keys", each of which reads as a different seat-holder. Without this
///     guard the DKG accepts such a roster and the forgery is live.
///     `tests/seat_key_torsion.rs` performs the grind against the composition
///     ceremony's twin of this check.
///
/// Checked over the WHOLE roster, not just the caller's own seat: the keys this
/// participant will verify attestations under are the other seats'. The unusable
/// key here is at a seat the caller does not hold, which is what makes that
/// assertion mean something.
///
/// CONTROL: the same roster with a real key in that position runs.
#[test]
fn a_seat_roster_naming_an_unusable_identity_key_is_refused() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let cid = ceremony(24);
    let (me, bad_seat) = (Owners::nth(0), Owners::nth(2));
    let mut rng = ChaCha20Rng::seed_from_u64(240);

    let roster_with = |key: IdentityPublic| {
        SeatRoster::<Owners>::new(spec.ids().iter().map(|&id| {
            (
                id,
                if id == bad_seat {
                    key
                } else {
                    sk::<Owners>(id).public()
                },
            )
        }))
        .expect("the ids are well-formed; SeatRoster does not judge the keys")
    };

    // ---- the identity element ----
    let identity_element = IdentityPublic::from(
        Ed25519Public::try_from(&hexb("0100000000000000000000000000000000000000000000000000000000000000")[..])
            .expect("on the curve"),
    );
    assert!(
        CompressedEdwardsY(*identity_element.as_bytes())
            .decompress()
            .expect("on the curve")
            .is_identity(),
        "the constant really is the identity element",
    );
    assert_eq!(
        Committing::<Owners>::begin(
            &cid,
            &spec,
            &roster_with(identity_element),
            me,
            &sk::<Owners>(me),
            &mut rng,
        )
        .expect_err("the identity element is a key whose secret everybody has"),
        DkgError::SeatKeyNotUsable {
            cohort: "owners",
            participant: bad_seat,
            key: identity_element,
            reason: "the identity element, whose discrete log is 0 and is public",
        },
    );

    // ---- a real key shifted off the prime-order subgroup ----
    //
    // Built from a REAL seat key plus the unique point of order 2, so the party
    // that holds `d` for the honest key is the party this admits. That is the
    // forgery: one secret, several encodings, each reading as a different seat.
    let order_two = CompressedEdwardsY(hexb(
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ))
    .decompress()
    .expect("on the curve");
    assert!(
        !order_two.is_identity() && (order_two + order_two).is_identity(),
        "the constant really is the point of order 2",
    );
    let shifted_bytes = (CompressedEdwardsY(*sk::<Owners>(bad_seat).public().as_bytes())
        .decompress()
        .expect("a real key is on the curve")
        + order_two)
        .compress()
        .to_bytes();
    let shifted = IdentityPublic::from(
        Ed25519Public::try_from(&shifted_bytes[..]).expect("still on the curve"),
    );
    assert_ne!(
        shifted,
        sk::<Owners>(bad_seat).public(),
        "the shift really produces a different 32-byte string",
    );
    assert_eq!(
        Committing::<Owners>::begin(
            &cid,
            &spec,
            &roster_with(shifted),
            me,
            &sk::<Owners>(me),
            &mut rng,
        )
        .expect_err("a torsion-shifted key is not a key"),
        DkgError::SeatKeyNotUsable {
            cohort: "owners",
            participant: bad_seat,
            key: shifted,
            reason: "outside the prime-order subgroup, so no secret exists behind it",
        },
    );

    // CONTROL: the identical roster with the real key in that position runs.
    Committing::<Owners>::begin(
        &cid,
        &spec,
        &roster_with(sk::<Owners>(bad_seat).public()),
        me,
        &sk::<Owners>(me),
        &mut rng,
    )
    .expect("CONTROL: a roster of real keys");
}

/// The single-host driver refuses to simulate a participant whose identity key
/// it was not given, rather than skipping it or attesting with somebody else's.
///
/// CONTROL: the same call with the full map runs.
#[test]
fn run_dkg_refuses_a_participant_it_holds_no_identity_key_for() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let mut rng = ChaCha20Rng::seed_from_u64(250);
    let mut short = identities::<Owners>(3);
    short.remove(&Owners::nth(1));

    assert_eq!(
        run_dkg::<Owners, _>(&ceremony(25), &spec, &seats::<Owners>(3), &short, &mut rng)
            .expect_err("no key for that seat"),
        DkgError::IdentityKeyMissing {
            cohort: "owners",
            id: Owners::nth(1),
        },
    );

    run_dkg::<Owners, _>(
        &ceremony(25),
        &spec,
        &seats::<Owners>(3),
        &identities::<Owners>(3),
        &mut rng,
    )
    .expect("CONTROL: the full map runs");
}

/// **THE RESIDUAL. A party that holds every seat's identity key still runs the
/// whole DKG by itself, and what comes out is a real DKG output.**
///
/// Named so it reads as an admission, the way
/// `seat_identity.rs::a_dealer_that_dealt_real_shares_and_kept_copies_still_passes`
/// is. Binding each contribution to a seat raised the price of fabricating a
/// cohort's key generation from "every share" to "every identity key". It did
/// not, and could not, make four keys four parties.
///
/// What the attestation moved, exactly:
///
///   * before, one party could generate all `n` contributions, label them, and
///     complete the DKG with no long-term key at all --
///     [`a_contribution_the_seat_did_not_attest_is_refused`] is what that costs
///     now, when there is an honest peer in the room;
///   * after, it must hold all `n` identity private keys. This test holds them
///     and succeeds, so the new bar is exactly that and no higher. `run_dkg`'s
///     signature says the same thing in a type: it takes every seat's private
///     key, because that is what running a cohort alone now costs.
///
/// And note the second half, which no per-message check can reach: with every
/// seat key in hand the sole party also holds every SHARE, so it can
/// reconstruct the component outright. Asserted below rather than described.
///
/// # If this test fails, it has been FIXED, not broken
///
/// Like the two residuals in `tests/seat_identity.rs` it asserts that something
/// SUCCEEDS. Nobody knows how to close it -- "n keys are n entities" is a fact
/// about the world, not about this crate -- so a red here almost certainly means
/// an unrelated change broke the DKG, not that the residual is gone.
#[test]
fn a_party_that_holds_every_seat_key_still_runs_the_whole_dkg_alone() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let cid = ceremony(26);
    let mut rng = ChaCha20Rng::seed_from_u64(260);

    // One process, every seat's long-term key, every participant.
    let all_keys = identities::<Owners>(3);
    let shares = run_dkg::<Owners, _>(&cid, &spec, &seats::<Owners>(3), &all_keys, &mut rng)
        .expect("THIS IS THE RESIDUAL: it runs");

    // What comes out is not distinguishable from an honest cohort's: the claim
    // names the three real seat keys, which is what a funder would be shown.
    let claim = ComponentClaim::of(shares[0].key());
    assert_eq!(
        claim.seat_keys(),
        spec.ids()
            .iter()
            .map(|&id| sk::<Owners>(id).public())
            .collect::<Vec<_>>(),
    );

    // THE HARM: the sole party holds every share, so it reconstructs the
    // component that the whole two-cohort construction assumes no one party can
    // reach.
    let quorum = vec![Owners::nth(0), Owners::nth(1)];
    let b: curve25519_dalek::scalar::Scalar = quorum
        .iter()
        .map(|&id| {
            *shares
                .iter()
                .find(|s| s.id() == id)
                .expect("on the roster")
                .term(&quorum)
                .expect("a quorum member's own term")
                .weight()
        })
        .sum();
    assert_eq!(
        b * G,
        claim.component(),
        "one process, one component scalar, three seats that read as three parties",
    );
}

// ---------------------------------------------------------------------------
// The cohort of one, which is the shape `production` decided for the gate.
// ---------------------------------------------------------------------------

/// **At `n == 1` the attribution loop has no peer to check, and what refuses a
/// party without the seat's key is `begin`, not `deal`.**
///
/// Review found the docs crediting the wrong refusal, and it mattered:
/// `GATE_COUNT` is 1, so for one of the two decided cohorts `check_attribution`
/// iterated over an empty set of peers and verified nothing at all. Every test of
/// the mechanism in this file is at `n = 3`; none of them said anything about the
/// shape actually deployed.
///
/// This is that shape, and it asserts where the property really lives: a party
/// holding a key the gate's seat roster does not name is refused before any key
/// material exists.
#[test]
fn at_a_cohort_of_one_it_is_begin_that_refuses_a_party_without_the_seat_key() {
    let spec = production::gates();
    assert_eq!(spec.ids().len(), production::GATE_COUNT);
    assert_eq!(production::GATE_COUNT, 1, "this test is about n = 1");
    let cid = ceremony(30);
    let me = Gates::nth(0);
    let honest = seats::<Gates>(1);
    let not_the_seat = IdentityKey::from_seed(&[0xEE; 32]);
    assert_ne!(not_the_seat.public(), sk::<Gates>(me).public());

    let mut rng = ChaCha20Rng::seed_from_u64(300);
    assert_eq!(
        Committing::<Gates>::begin(&cid, &spec, &honest, me, &not_the_seat, &mut rng)
            .err()
            .expect("a party the seat roster does not name must not begin as that seat"),
        DkgError::IdentityNotOwn {
            cohort: "gates",
            id: me,
            expected: sk::<Gates>(me).public(),
            found: not_the_seat.public(),
        },
    );

    // CONTROL: the real seat-holder begins.
    let mut rng = ChaCha20Rng::seed_from_u64(300);
    Committing::<Gates>::begin(&cid, &spec, &honest, me, &sk::<Gates>(me), &mut rng)
        .expect("CONTROL: the seat the roster names begins");
}

/// **The attribution check is not vacuous at `n == 1` -- it checks the one
/// thing there is to check.**
///
/// The loop used to `continue` past the caller's own entry, so at a cohort of one
/// it ran zero iterations for any input whatsoever: a map carrying 64 zero bytes
/// where the gate seat's signature belonged was accepted and the gate DKG
/// completed. That is now refused, by comparison against the contribution `begin`
/// produced.
///
/// **Read what this is.** It is a consistency check on the map, not a security
/// property: at `n == 1` the only entry is the caller's own and the caller made
/// it. The security property at this shape is
/// [`at_a_cohort_of_one_it_is_begin_that_refuses_a_party_without_the_seat_key`].
/// What this buys is that the guard is no longer INERT at the deployed shape, so
/// a future change that breaks it fails a test here rather than nowhere.
#[test]
fn the_gate_cohorts_attribution_check_is_not_vacuous() {
    let spec = production::gates();
    let cid = ceremony(31);
    let me = Gates::nth(0);
    let mut rng = ChaCha20Rng::seed_from_u64(310);
    let (state, own) =
        Committing::<Gates>::begin(&cid, &spec, &seats::<Gates>(1), me, &sk::<Gates>(me), &mut rng)
            .expect("the gate seat begins");

    let mut zeroed = HashMap::new();
    zeroed.insert(me, own.with_attestation(IdentitySignature([0u8; 64])));
    assert_eq!(
        state
            .deal(&mut rng, &zeroed)
            .err()
            .expect("64 zero bytes are not this seat's attestation"),
        DkgError::OwnContributionAltered {
            cohort: "gates",
            id: me,
        },
    );

    // CONTROL 1: the untouched map completes the round.
    let mut rng = ChaCha20Rng::seed_from_u64(310);
    let (state, own) =
        Committing::<Gates>::begin(&cid, &spec, &seats::<Gates>(1), me, &sk::<Gates>(me), &mut rng)
            .expect("the gate seat begins");
    let mut honest = HashMap::new();
    honest.insert(me, own);
    state
        .deal(&mut rng, &honest)
        .expect("CONTROL: the map the participant actually broadcast is accepted");

    // CONTROL 2: an EMPTY map is also accepted -- the own entry is checked if
    // present, not required. A participant that does not send itself its own
    // broadcast is not doing anything wrong.
    let mut rng = ChaCha20Rng::seed_from_u64(310);
    let (state, _) =
        Committing::<Gates>::begin(&cid, &spec, &seats::<Gates>(1), me, &sk::<Gates>(me), &mut rng)
            .expect("the gate seat begins");
    state
        .deal(&mut rng, &HashMap::new())
        .expect("CONTROL: the own entry is optional");
}

/// **A participant handed back an altered copy of its OWN broadcast refuses it.**
///
/// The one local symptom of equivocation this crate can see, and it is a weak
/// one: it catches a coordinator that rewrote this participant's message in the
/// copy it reflected back, not one that only sent the rewrite onward. See
/// `DkgError::OwnContributionAltered`.
///
/// The comparison is byte equality against the contribution `begin` produced --
/// not a signature check -- which is why the substituted message here is a
/// perfectly well-attested one made by somebody else under their own roster: no
/// key of this participant's is consulted, so nothing about the substitute can
/// make it pass.
#[test]
fn a_rewritten_own_contribution_is_refused() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let cid = ceremony(32);
    let victim = Owners::nth(2);
    let ids = identities::<Owners>(3);
    let fixture = || round_one(&cid, &spec, &seats::<Owners>(3), &ids, victim, 320);
    let (state, honest) = fixture();

    let other = IdentityKey::from_seed(&[0xD3; 32]);
    let substitute = contribution_from_an_impostor(&cid, &spec, victim, &other, 321);
    let mut rewritten = honest.clone();
    rewritten.insert(victim, substitute);

    let mut deal_rng = ChaCha20Rng::seed_from_u64(3200);
    assert_eq!(
        state
            .deal(&mut deal_rng, &rewritten)
            .err()
            .expect("this is not the contribution `begin` produced here"),
        DkgError::OwnContributionAltered {
            cohort: "owners",
            id: victim,
        },
    );

    // CONTROL: unrewritten, the same round completes.
    let (state, _) = fixture();
    state
        .deal(&mut deal_rng, &honest)
        .expect("CONTROL: the participant's own broadcast is accepted");
}

/// **The own-entry comparison covers the COMMITMENTS, not only the
/// attestation.**
///
/// Review found the gap at finer mutation granularity: the comparison is a
/// disjunction, and the two tests above kill it only when BOTH disjuncts go --
/// one changes the attestation alone and the other changes both, so deleting the
/// commitment comparison on its own left the suite green. This is the input that
/// isolates it: a DIFFERENT contribution by the same participant, carrying the
/// participant's OWN attestation byte for byte.
///
/// That map entry is not forgeable in any interesting sense -- it takes a second
/// `begin` by the same party -- and that is the point. The check is a tripwire
/// on the channel, not a proof of anything, so what it has to catch is a
/// substitution the attestation bytes cannot distinguish.
#[test]
fn an_own_entry_with_the_right_signature_over_the_wrong_commitments_is_refused() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let cid = ceremony(42);
    let victim = Owners::nth(2);
    let ids = identities::<Owners>(3);
    let fixture = || round_one(&cid, &spec, &seats::<Owners>(3), &ids, victim, 420);
    let (state, honest) = fixture();

    // A second round-one message by the same participant, same run.
    let mut other_rng = ChaCha20Rng::seed_from_u64(421);
    let (_, second) = Committing::<Owners>::begin(
        &cid,
        &spec,
        &seats::<Owners>(3),
        victim,
        &sk::<Owners>(victim),
        &mut other_rng,
    )
    .expect("roster");
    assert_ne!(
        second.commitment_bytes(),
        honest[&victim].commitment_bytes(),
        "the two must really differ, or this test is vacuous",
    );

    let mut swapped = honest.clone();
    swapped.insert(victim, second.with_attestation(*honest[&victim].attestation()));
    assert_eq!(
        swapped[&victim].attestation(),
        honest[&victim].attestation(),
        "the attestation must be byte-identical, or the OTHER disjunct catches it \
         and this test is not about the commitments",
    );

    let mut deal_rng = ChaCha20Rng::seed_from_u64(4200);
    assert_eq!(
        state.deal(&mut deal_rng, &swapped).err().expect("refused"),
        DkgError::OwnContributionAltered {
            cohort: "owners",
            id: victim,
        },
    );

    // CONTROL: unswapped, the same round completes.
    let (state, _) = fixture();
    state
        .deal(&mut deal_rng, &honest)
        .expect("CONTROL: the participant's own broadcast is accepted");
}

// ---------------------------------------------------------------------------
// The roster binding: an attestation is for ONE RUN.
// ---------------------------------------------------------------------------

/// **A contribution does not transplant into a run with a different
/// membership**, and it is refused in both layers.
///
/// Review found this open: the attestation named the ceremony, the cohort and
/// the seat, but not WHO ELSE was taking part, so a seat's attested round-one
/// message was accepted in any other run of the same ceremony and cohort that
/// kept that seat's position. PedPoP did not close it either -- its proof of
/// knowledge binds the participant INDEX, which the substitution preserves.
///
/// **This is the test that dies if the IDS are dropped from
/// `dkg_roster_digest`**, and it has to be built carefully to isolate them: the
/// departing seat and the arriving seat are given ONE identity key, so the two
/// runs' seat KEY vectors are identical and the threshold is identical, and the
/// id list is the only component of the digest that differs.
///
/// Both layers are asserted separately, and they die under different deletions:
///
///   * layer one, the attestation, dies if the roster digest is dropped from
///     `dkg_contribution_payload`;
///   * layer two, PedPoP's own context, dies if it is dropped from
///     `CeremonyId::dkg_context`.
#[test]
fn a_contribution_does_not_transplant_into_a_run_with_a_different_membership() {
    let cid = ceremony(33);
    let (i0, i1, i2, i3) = (
        Owners::nth(0),
        Owners::nth(1),
        Owners::nth(2),
        Owners::nth(3),
    );
    // The seat that leaves and the seat that arrives hold the SAME key, so the
    // key vector is unchanged between the two runs and only the ids move.
    let key_of = |id: u64| -> IdentityKey {
        if id == i2 || id == i3 {
            IdentityKey::from_seed(&[0x6E; 32])
        } else {
            sk::<Owners>(id)
        }
    };
    let roster_of = |ids: &[u64]| {
        SeatRoster::<Owners>::new(ids.iter().map(|&id| (id, key_of(id).public())))
            .expect("well-formed")
    };
    let keys_of = |ids: &[u64]| -> HashMap<u64, IdentityKey> {
        ids.iter().map(|&id| (id, key_of(id))).collect()
    };

    let spec_a = CohortSpec::<Owners>::with_ids(2, &[i0, i1, i2]);
    let spec_b = CohortSpec::<Owners>::with_ids(2, &[i0, i1, i3]);
    let (seats_a, seats_b) = (roster_of(&[i0, i1, i2]), roster_of(&[i0, i1, i3]));
    assert_eq!(
        (0..3)
            .map(|k| seats_a.key_of([i0, i1, i2][k]).unwrap())
            .collect::<Vec<_>>(),
        (0..3)
            .map(|k| seats_b.key_of([i0, i1, i3][k]).unwrap())
            .collect::<Vec<_>>(),
        "the two runs must have the SAME key vector, or this test is about the \
         keys and not the ids",
    );

    // Run A: seats 0, 1, 2 broadcast honestly.
    let (_, from_a) = round_one(
        &cid,
        &spec_a,
        &seats_a,
        &keys_of(&[i0, i1, i2]),
        i0,
        330,
    );

    // Run B: seat 3 is the only participant taking part for real. Seats 0 and 1
    // never agreed to be in it; their run-A messages are replayed verbatim, at
    // the same positions.
    let (state, _) = round_one(&cid, &spec_b, &seats_b, &keys_of(&[i0, i1, i3]), i3, 331);
    let mut replayed = HashMap::new();
    replayed.insert(i0, from_a[&i0].clone());
    replayed.insert(i1, from_a[&i1].clone());

    let mut deal_rng = ChaCha20Rng::seed_from_u64(3300);
    assert_eq!(
        state
            .deal(&mut deal_rng, &replayed)
            .err()
            .expect("an attestation made for run A is not one for run B"),
        DkgError::ContributionNotAttributable {
            cohort: "owners",
            dealer: i0,
            key: sk::<Owners>(i0).public(),
        },
        "LAYER ONE: the attestation names the roster",
    );

    // ---- layer two: the same messages, RE-ATTESTED for run B ----
    //
    // Seats 0 and 1's keys would have to do this, so it is not something an
    // outsider can reach -- it is here to show that the roster is bound TWICE,
    // and that removing it from PedPoP's context alone would leave this open.
    let digest_b = roster_digest(&spec_b, &seats_b);
    let mut reattested = HashMap::new();
    for &id in &[i0, i1] {
        let c = &from_a[&id];
        reattested.insert(
            id,
            c.with_attestation(key_of(id).sign(&dkg_contribution_payload(
                &cid,
                "owners",
                &digest_b,
                id,
                &c.commitment_bytes(),
            ))),
        );
    }
    let (state, _) = round_one(&cid, &spec_b, &seats_b, &keys_of(&[i0, i1, i3]), i3, 331);
    assert_eq!(
        state
            .deal(&mut deal_rng, &reattested)
            .err()
            .expect("a proof of knowledge over run A's roster must not verify in run B"),
        DkgError::BadCommitments {
            cohort: "owners",
            dealer: i0,
        },
        "LAYER TWO: PedPoP's own context names the roster",
    );

    // CONTROL: run B's own round one completes.
    let (state, honest_b) = round_one(&cid, &spec_b, &seats_b, &keys_of(&[i0, i1, i3]), i3, 331);
    state
        .deal(&mut deal_rng, &honest_b)
        .expect("CONTROL: run B's own broadcast is accepted");
}

/// **A contribution does not transplant into a run that reseats one of its
/// peers**, even though the ids and the threshold are unchanged.
///
/// **This is the test that dies if the SEAT KEYS are dropped from
/// `dkg_roster_digest`.** Two runs of the same ceremony and cohort over the same
/// three ids, differing only in who holds the third seat. Seats 0 and 1's keys
/// are identical between the two runs, so the key each attestation is checked
/// under is the same and nothing but the digest separates them.
///
/// The shape matters: a party that acquires the third seat can otherwise take
/// two peers' round-one messages from a run they consented to and stand up a
/// different run around them.
#[test]
fn a_contribution_does_not_transplant_into_a_run_that_reseats_one_of_its_peers() {
    let cid = ceremony(34);
    let ids = [Owners::nth(0), Owners::nth(1), Owners::nth(2)];
    let spec = CohortSpec::<Owners>::with_ids(2, &ids);
    let replacement = IdentityKey::from_seed(&[0x7A; 32]);
    assert_ne!(replacement.public(), sk::<Owners>(ids[2]).public());

    let seats_a = seats::<Owners>(3);
    let seats_b = SeatRoster::<Owners>::new(vec![
        (ids[0], sk::<Owners>(ids[0]).public()),
        (ids[1], sk::<Owners>(ids[1]).public()),
        (ids[2], replacement.public()),
    ])
    .expect("well-formed");
    let keys_a = identities::<Owners>(3);
    let mut keys_b = identities::<Owners>(3);
    keys_b.insert(ids[2], IdentityKey::from_seed(&[0x7A; 32]));

    let (_, from_a) = round_one(&cid, &spec, &seats_a, &keys_a, ids[0], 340);
    let (state, _) = round_one(&cid, &spec, &seats_b, &keys_b, ids[2], 341);
    let mut replayed = HashMap::new();
    replayed.insert(ids[0], from_a[&ids[0]].clone());
    replayed.insert(ids[1], from_a[&ids[1]].clone());

    let mut deal_rng = ChaCha20Rng::seed_from_u64(3400);
    assert_eq!(
        state
            .deal(&mut deal_rng, &replayed)
            .err()
            .expect("run A's seats did not agree to a run with this third seat"),
        DkgError::ContributionNotAttributable {
            cohort: "owners",
            dealer: ids[0],
            key: sk::<Owners>(ids[0]).public(),
        },
    );

    // CONTROL: run B's own broadcast is accepted, so the ids and the threshold
    // are not what refused it.
    let (state, honest_b) = round_one(&cid, &spec, &seats_b, &keys_b, ids[2], 341);
    state
        .deal(&mut deal_rng, &honest_b)
        .expect("CONTROL: run B's own broadcast is accepted");
}

/// **A contribution does not transplant across a change of threshold, and the
/// refusal names the attribution.**
///
/// **This is the test that dies if the THRESHOLD is dropped from
/// `dkg_roster_digest`, and it dies on the ERROR rather than on the refusal.**
/// PedPoP refuses a threshold change on its own -- the commitment vector's length
/// is part of the bytes its challenge hashes -- so without the threshold here the
/// transplant is still refused, as `BadCommitments`. What the threshold buys is
/// that a participant is told the message was not made for this run rather than
/// that somebody's polynomial is wrong, and `deal` checks attribution first so it
/// is the refusal reported.
///
/// The distinction is worth a test rather than a comment because "refused
/// anyway" is exactly how a field ends up in a transcript with nothing checking
/// it.
#[test]
fn a_contribution_does_not_transplant_across_a_change_of_threshold() {
    let cid = ceremony(35);
    let ids = [Owners::nth(0), Owners::nth(1), Owners::nth(2)];
    let spec_a = CohortSpec::<Owners>::with_ids(2, &ids);
    let spec_b = CohortSpec::<Owners>::with_ids(3, &ids);
    let seats = seats::<Owners>(3);
    let keys = identities::<Owners>(3);

    let (_, from_a) = round_one(&cid, &spec_a, &seats, &keys, ids[0], 350);
    let (state, _) = round_one(&cid, &spec_b, &seats, &keys, ids[2], 351);
    let mut replayed = HashMap::new();
    replayed.insert(ids[0], from_a[&ids[0]].clone());
    replayed.insert(ids[1], from_a[&ids[1]].clone());

    let mut deal_rng = ChaCha20Rng::seed_from_u64(3500);
    assert_eq!(
        state
            .deal(&mut deal_rng, &replayed)
            .err()
            .expect("a 2-of-3 contribution is not a 3-of-3 one"),
        DkgError::ContributionNotAttributable {
            cohort: "owners",
            dealer: ids[0],
            key: sk::<Owners>(ids[0]).public(),
        },
        "the threshold is in the digest, so the ATTRIBUTION is what refuses it; \
         without it PedPoP still refuses, as BadCommitments",
    );

    // CONTROL: run B's own broadcast is accepted at the new threshold.
    let (state, honest_b) = round_one(&cid, &spec_b, &seats, &keys, ids[2], 351);
    state
        .deal(&mut deal_rng, &honest_b)
        .expect("CONTROL: run B's own broadcast is accepted");
}

// ---------------------------------------------------------------------------
// Order, arms, and the residuals.
// ---------------------------------------------------------------------------

/// **`deal` asks WHO before it asks WHETHER THEY ARE ON THE ROSTER.**
///
/// The three-step order in `deal` was described as "the order, which is the
/// design" with nothing testing steps 1 and 2 against each other; review found
/// that no input in the suite could tell them apart. This is that input: a map
/// carrying an entry with a bad attestation AND an entry from somebody not on
/// this roster. Swapping the two steps makes it `UnexpectedMessage`.
///
/// Both faults are real, and the CONTROLS below show it: with only the
/// off-roster entry the map is refused as `UnexpectedMessage`, and with only the
/// bad attestation as `ContributionNotAttributable`. So the test is about the
/// ORDER and not about either check.
#[test]
fn a_map_that_is_both_unattributable_and_off_roster_reports_the_attribution() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let cid = ceremony(36);
    let (bad, victim) = (Owners::nth(0), Owners::nth(2));
    let stranger = Owners::nth(9);
    let ids = identities::<Owners>(3);
    let fixture = || round_one(&cid, &spec, &seats::<Owners>(3), &ids, victim, 360);
    let (_, honest) = fixture();

    let mut unattributable = honest.clone();
    unattributable.insert(
        bad,
        honest[&bad].with_attestation(IdentitySignature([0u8; 64])),
    );
    let mut off_roster = honest.clone();
    off_roster.insert(stranger, honest[&Owners::nth(1)].clone());
    let mut both = unattributable.clone();
    both.insert(stranger, honest[&Owners::nth(1)].clone());

    let mut deal_rng = ChaCha20Rng::seed_from_u64(3600);
    let (state, _) = fixture();
    assert_eq!(
        state.deal(&mut deal_rng, &both).err().expect("refused"),
        DkgError::ContributionNotAttributable {
            cohort: "owners",
            dealer: bad,
            key: sk::<Owners>(bad).public(),
        },
        "attribution runs before routing",
    );

    // CONTROL 1: the off-roster entry alone IS refused, so it is a real fault.
    let (state, _) = fixture();
    assert_eq!(
        state.deal(&mut deal_rng, &off_roster).err().expect("refused"),
        DkgError::UnexpectedMessage {
            cohort: "owners",
            round: 1,
            from: stranger,
        },
    );

    // CONTROL 2: the bad attestation alone.
    let (state, _) = fixture();
    assert_eq!(
        state
            .deal(&mut deal_rng, &unattributable)
            .err()
            .expect("refused"),
        DkgError::ContributionNotAttributable {
            cohort: "owners",
            dealer: bad,
            key: sk::<Owners>(bad).public(),
        },
    );
}

/// **An attestation built with the OTHER cohort's label does not verify here.**
///
/// **This is the test that dies if the cohort name is dropped from
/// `dkg_contribution_payload`**, and until review constructed it the crate said
/// flatly that no such test could exist: *"the cohort name -- NOT load-bearing,
/// and no test can make it be."* The reasoning behind that sentence was about
/// GENUINE contributions -- the two cohorts' ids come from disjoint bands and
/// `dkg_context` already separates them, so a real gate message cannot be filed
/// under an owner seat. That reasoning is still correct and is why there is no
/// genuine cross-cohort replay to test.
///
/// It is not the same as "no test can make it be". The payload builder is
/// public and takes the cohort as a string, so a seat's key can be asked to sign
/// a payload that labels its own genuine owner contribution `"gates"`. With the
/// field present that attestation does not rebuild and the contribution is
/// refused; with the field deleted the two labels produce the identical signed
/// bytes and it is accepted.
///
/// So what this covers is narrower than the other three fields and is worth
/// saying exactly: it binds the label supplied on the public signing path. It is
/// not evidence about cross-cohort replay of genuine messages.
#[test]
fn an_attestation_built_for_the_other_cohort_does_not_verify_here() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let cid = ceremony(40);
    let (dealer, victim) = (Owners::nth(0), Owners::nth(2));
    let ids = identities::<Owners>(3);
    let fixture = || round_one(&cid, &spec, &seats::<Owners>(3), &ids, victim, 400);
    let (_, honest) = fixture();

    // The seat's OWN genuine contribution -- so PedPoP has nothing to object to
    // -- re-attested under the other cohort's label.
    let genuine = &honest[&dealer];
    let mislabelled = genuine.with_attestation(sk::<Owners>(dealer).sign(
        &dkg_contribution_payload(
            &cid,
            Gates::NAME,
            &roster_digest(&spec, &seats::<Owners>(3)),
            dealer,
            &genuine.commitment_bytes(),
        ),
    ));
    let mut map = honest.clone();
    map.insert(dealer, mislabelled);

    let mut deal_rng = ChaCha20Rng::seed_from_u64(4000);
    let (state, _) = fixture();
    assert_eq!(
        state
            .deal(&mut deal_rng, &map)
            .err()
            .expect("an attestation labelled `gates` is not one labelled `owners`"),
        DkgError::ContributionNotAttributable {
            cohort: "owners",
            dealer,
            key: sk::<Owners>(dealer).public(),
        },
    );

    // A SECOND label, chosen the same LENGTH as `"owners"`. Review pointed out
    // that `"gates"` differs from `"owners"` in its length prefix as well as its
    // bytes, so the assertion above does not isolate `cohort.as_bytes()` from
    // `cohort.len()`. This one does. (The converse -- isolating the length
    // prefix -- is not constructible here: two labels of different lengths
    // always differ in their bytes too.)
    let same_length = "owner5";
    assert_eq!(same_length.len(), Owners::NAME.len());
    assert_ne!(same_length, Owners::NAME);
    let mut map = honest.clone();
    map.insert(
        dealer,
        genuine.with_attestation(sk::<Owners>(dealer).sign(&dkg_contribution_payload(
            &cid,
            same_length,
            &roster_digest(&spec, &seats::<Owners>(3)),
            dealer,
            &genuine.commitment_bytes(),
        ))),
    );
    let (state, _) = fixture();
    assert_eq!(
        state
            .deal(&mut deal_rng, &map)
            .err()
            .expect("a label of the same length is still a different label"),
        DkgError::ContributionNotAttributable {
            cohort: "owners",
            dealer,
            key: sk::<Owners>(dealer).public(),
        },
    );

    // CONTROL: the identical bytes with the right label are accepted, so it is
    // the label and nothing else.
    let (state, _) = fixture();
    state
        .deal(&mut deal_rng, &honest)
        .expect("CONTROL: correctly labelled, and accepted");
}

/// **A map missing an EARLIER peer reports that, not a LATER peer's bad
/// attestation.**
///
/// `check_attribution`'s missing-message arm duplicates `Roster::by_index`'s, and
/// the crate said no test could tell them apart because `by_index` runs one step
/// later and returns a byte-identical error. Review showed that is only true for
/// a map with ONE fault. With two -- an earlier peer absent and a later peer's
/// attestation corrupted -- the arms are distinguishable: this loop visits the
/// roster in ascending id order and reports the absence, while a version that
/// skipped an absent peer instead of refusing would reach the corrupted
/// attestation first and report that.
///
/// So the arm has a killing test after all, and the mutation it dies under is
/// replacing its `?` with a `continue`. Recorded here because "no test is
/// possible" was written in the source and was wrong.
#[test]
fn a_missing_earlier_peer_is_reported_before_a_later_peers_bad_attestation() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let cid = ceremony(41);
    let (absent, corrupt, victim) = (Owners::nth(0), Owners::nth(1), Owners::nth(2));
    assert!(absent < corrupt, "the absence must be the EARLIER id");
    let ids = identities::<Owners>(3);
    let fixture = || round_one(&cid, &spec, &seats::<Owners>(3), &ids, victim, 410);
    let (_, honest) = fixture();

    let mut both = honest.clone();
    both.remove(&absent);
    both.insert(
        corrupt,
        honest[&corrupt].with_attestation(IdentitySignature([0u8; 64])),
    );

    let mut deal_rng = ChaCha20Rng::seed_from_u64(4100);
    let (state, _) = fixture();
    assert_eq!(
        state.deal(&mut deal_rng, &both).err().expect("refused"),
        DkgError::MissingMessage {
            cohort: "owners",
            round: 1,
            from: absent,
        },
        "the loop refuses an absent peer rather than skipping to the next",
    );

    // CONTROL: the corrupted attestation on its own IS refused, so the map has
    // two real faults and the test is about which one is reported.
    let mut only_corrupt = honest.clone();
    only_corrupt.insert(
        corrupt,
        honest[&corrupt].with_attestation(IdentitySignature([0u8; 64])),
    );
    let (state, _) = fixture();
    assert_eq!(
        state
            .deal(&mut deal_rng, &only_corrupt)
            .err()
            .expect("refused"),
        DkgError::ContributionNotAttributable {
            cohort: "owners",
            dealer: corrupt,
            key: sk::<Owners>(corrupt).public(),
        },
    );
}

/// **A missing ROUND-TWO share names the participant it is missing from.**
///
/// `Roster::by_index`'s missing-message arm is duplicated at round one by
/// `Committing::check_attribution`, which runs first, so nothing at round one can
/// exercise `by_index`'s own arm. The docs claimed round two did; review checked
/// and no test in the crate asserted a round-two `MissingMessage`. This is it.
#[test]
fn a_missing_round_two_share_names_the_participant() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let cid = ceremony(37);
    let (absent, victim) = (Owners::nth(0), Owners::nth(2));
    let ids = identities::<Owners>(3);
    let (state, broadcast) = round_one(&cid, &spec, &seats::<Owners>(3), &ids, victim, 370);
    let mut rng = ChaCha20Rng::seed_from_u64(3700);
    let (dealing, _) = state.deal(&mut rng, &broadcast).expect("round one completes");

    assert_eq!(
        dealing
            .finish(&mut rng, &HashMap::new())
            .err()
            .expect("round two cannot proceed with a smaller set"),
        DkgError::MissingMessage {
            cohort: "owners",
            round: 2,
            from: absent,
        },
    );
}

/// **THE RESIDUAL: a seat key that will sign bytes it did not generate satisfies
/// the attribution check.**
///
/// Named as an admission, in the shape
/// `a_dealer_that_dealt_real_shares_and_kept_copies_still_passes` set: it asserts
/// that something SUCCEEDS. What succeeds is the guard this whole round is
/// about -- `check_attribution` -- against a contribution the seat did not make.
///
/// The route is two PUBLIC functions, `ceremony::dkg_contribution_payload` and
/// `IdentityKey::sign`, with no `Committing` anywhere. The crate's docs used to
/// say "there is no entry point anywhere -- gated or not -- that attests bytes
/// the caller supplies" and used that to justify omitting this test. Both halves
/// were wrong: the entry point exists, it must exist (an independent
/// implementation and a key in an HSM both need it), and it is the route this
/// file's own rejection tests take.
///
/// # What this test can and cannot perform, precisely
///
/// It performs the attribution layer: `check_attribution` passes, and the error
/// `deal` returns is `BadCommitments` -- PedPoP's, one step later -- rather than
/// `ContributionNotAttributable`. **It cannot perform an acceptance**, and the
/// reason is worth stating because it is not a weakness of the residual:
/// `Committing::begin` will not generate a round-one message for slot `i` of this
/// run without seat `i`'s identity key, and there is no other constructor for a
/// `Contribution`, so THIS CRATE cannot build a message that is well-formed for
/// the slot it is filed under and unattested by its seat. An independent
/// implementation can -- the roster digest, the ceremony id and PedPoP's
/// parameters are all public -- and against that message the attestation is the
/// only refusal there is.
///
/// # If this test fails, it has been FIXED
///
/// Nothing in a signature can stop a party that signs on request. Closing it
/// needs a witness the seat could only have if it really produced the
/// contribution, and `Contribution`'s docs explain why none is reachable here.
#[test]
fn a_seat_key_that_signs_bytes_it_did_not_generate_hands_its_half_over() {
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let cid = ceremony(38);
    let (impersonated, victim) = (Owners::nth(0), Owners::nth(2));
    let outsider = IdentityKey::from_seed(&[0xC1; 32]);
    assert_ne!(outsider.public(), sk::<Owners>(impersonated).public());

    let foreign = contribution_from_an_impostor(&cid, &spec, impersonated, &outsider, 380);
    let stamped = foreign.with_attestation(sk::<Owners>(impersonated).sign(
        &dkg_contribution_payload(
            &cid,
            "owners",
            &roster_digest(&spec, &seats::<Owners>(3)),
            impersonated,
            &foreign.commitment_bytes(),
        ),
    ));

    let ids = identities::<Owners>(3);
    let (state, honest) = round_one(&cid, &spec, &seats::<Owners>(3), &ids, victim, 381);
    let mut map = honest.clone();
    map.insert(impersonated, stamped);
    let mut rng = ChaCha20Rng::seed_from_u64(3800);
    let err = state.deal(&mut rng, &map).err().expect("PedPoP refuses it");
    assert_eq!(
        err,
        DkgError::BadCommitments {
            cohort: "owners",
            dealer: impersonated,
        },
        "THIS IS THE RESIDUAL: the attribution check PASSED on a contribution \
         the seat did not make, because the seat's key signed it. What refused \
         it is PedPoP, and only because this crate cannot build bytes that are \
         well-formed for the slot without the seat's key",
    );
    assert_ne!(
        err,
        DkgError::ContributionNotAttributable {
            cohort: "owners",
            dealer: impersonated,
            key: sk::<Owners>(impersonated).public(),
        },
    );
}

/// **THE RESIDUAL, second half: a process holding NO real seat key runs a whole
/// cohort under a seat roster of its own.**
///
/// `run_dkg`'s docs said its signature -- taking every seat's private key -- was
/// "the new bar written into a type". Review pointed out the caller supplies the
/// seat roster too, so the two can be made to agree with keys minted this
/// morning. This performs it, at the DECIDED production shape, for both cohorts.
///
/// The true statement the corrected docs make is about labelling: a party cannot
/// produce a dealing whose seat roster names seat-holders it does not hold the
/// keys of. What refuses the invented roster is downstream -- the seat
/// endorsements, checked against the funder's own `Parties` -- and
/// `tests/seat_identity.rs` is where that is performed.
///
/// # If this test fails, it has been FIXED
#[test]
fn a_process_holding_no_real_seat_key_still_runs_a_whole_cohort_under_its_own_roster() {
    let cid = ceremony(39);
    let owners = production::owners();
    let gates = production::gates();
    let mint = |tag: u8, id: u64| {
        let mut seed = [tag; 32];
        seed[8..16].copy_from_slice(&id.to_le_bytes());
        IdentityKey::from_seed(&seed)
    };
    let o_keys: HashMap<u64, IdentityKey> =
        owners.ids().iter().map(|&id| (id, mint(0x11, id))).collect();
    let g_keys: HashMap<u64, IdentityKey> =
        gates.ids().iter().map(|&id| (id, mint(0x22, id))).collect();
    for &id in owners.ids() {
        assert_ne!(
            o_keys[&id].public(),
            sk::<Owners>(id).public(),
            "none of these may be a real seat key, or the test is vacuous",
        );
    }
    let o_seats = SeatRoster::<Owners>::new(o_keys.iter().map(|(&id, k)| (id, k.public())))
        .expect("well-formed");
    let g_seats = SeatRoster::<Gates>::new(g_keys.iter().map(|(&id, k)| (id, k.public())))
        .expect("well-formed");

    let mut rng = ChaCha20Rng::seed_from_u64(390);
    let o = run_dkg::<Owners, _>(&cid, &owners, &o_seats, &o_keys, &mut rng)
        .expect("THIS IS THE RESIDUAL: it runs, with no real seat key at all");
    let g = run_dkg::<Gates, _>(&cid, &gates, &g_seats, &g_keys, &mut rng)
        .expect("THIS IS THE RESIDUAL: and the gate cohort too");
    assert_eq!(o.len(), production::OWNER_COUNT);
    assert_eq!(g.len(), production::GATE_COUNT);

    // And the claim it produces names the invented seats, which is exactly what
    // makes this a claim about LABELLING rather than about key material.
    let claim = ComponentClaim::of(o[0].key());
    assert_eq!(
        claim.seat_keys(),
        owners
            .ids()
            .iter()
            .map(|&id| o_keys[&id].public())
            .collect::<Vec<_>>(),
    );
}

/// A 32-byte constant written as hex, so the values above read as the encodings
/// they are.
fn hexb(s: &str) -> [u8; 32] {
    let mut o = [0u8; 32];
    for (i, b) in o.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex");
    }
    o
}
