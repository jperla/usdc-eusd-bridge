//! Per-cohort key generation: no dealer, and a share that can be checked.
//!
//! What entitles these tests to their conclusions:
//!
//!   * The DKG is driven through its own three rounds, one state machine per
//!     participant, with every message an explicit value routed by hand. No
//!     test calls anything that generates a cohort secret.
//!   * Every rejection test uses the SAME driver as the happy path and changes
//!     exactly one message, and each carries a CONTROL: the same participant,
//!     same run, same messages, with only the substitution removed, completing
//!     successfully. A rejection with no control beside it proves only that
//!     something broke.
//!   * The inconsistent-dealing test constructs a genuinely malicious dealer --
//!     one that publishes commitments to polynomial B while dealing shares from
//!     polynomial A. Both polynomials come from real PedPoP runs under the same
//!     ceremony, so the commitments carry a valid proof of knowledge and the
//!     share message is properly encrypted and authenticated. The only thing
//!     wrong with it is the thing the VSS check exists to catch.

use std::collections::HashMap;

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, ristretto::RistrettoPoint};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use two_cohort::{
    dkg::{run_dkg, CohortShare, CommitmentMessage, Committing, DkgError, ShareMessage},
    subsets_of, CeremonyId, Cohort, CohortSpec, ControlDomain, Error, Gates, Owners, SeatRoster,
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
    substitute: Option<(u64, CommitmentMessage)>,
) -> HashMap<u64, Result<CohortShare<C>, DkgError>> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    // Round one: every participant publishes commitments.
    let mut committing = Vec::new();
    let mut broadcast = HashMap::new();
    for &id in spec.ids() {
        let (state, msg) = Committing::<C>::begin(ceremony, spec, &seats::<C>(spec.ids().len()), id, &mut rng).expect("roster");
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
) -> CommitmentMessage {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    Committing::<C>::begin(ceremony, spec, &seats::<C>(spec.ids().len()), dealer, &mut rng)
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
    let shares = run_dkg::<Owners, _>(&ceremony(1), &spec, &seats::<Owners>(spec.ids().len()), &mut rng).expect("honest dkg");

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
    let shares = run_dkg::<Gates, _>(&ceremony(2), &spec, &seats::<Gates>(spec.ids().len()), &mut rng).expect("honest dkg");
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
    let shares = run_dkg::<Gates, _>(&ceremony(3), &spec, &seats::<Gates>(spec.ids().len()), &mut rng).expect("honest dkg");

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
    let shares = run_dkg::<Owners, _>(&ceremony(4), &spec, &seats::<Owners>(spec.ids().len()), &mut rng).expect("honest dkg");

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
/// refused, naming the dealer.
///
/// This is PedPoP's within-cohort rogue-key defence and, at the same time, the
/// binding of a cohort's key generation to one composition: material from
/// another ceremony does not verify here.
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
    let mut rng = ChaCha20Rng::seed_from_u64(600);
    let mut broadcast = HashMap::new();
    let mut mine = None;
    for &id in spec.ids() {
        let (state, msg) = Committing::<Owners>::begin(&here, &spec, &seats::<Owners>(spec.ids().len()), id, &mut rng).expect("roster");
        broadcast.insert(id, msg);
        if id == victim {
            mine = Some(state);
        }
    }
    // Control on the same state machine: the honest broadcast is accepted.
    let mut honest_rng = rng.clone();
    let honest_broadcast = broadcast.clone();
    broadcast.insert(dealer, foreign);

    let err = mine
        .expect("victim is on the roster")
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

    let (again, _) =
        Committing::<Owners>::begin(&here, &spec, &seats::<Owners>(spec.ids().len()), victim, &mut honest_rng).expect("roster");
    assert!(
        again.deal(&mut honest_rng, &honest_broadcast).is_ok(),
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
        let (state, msg) = Committing::<Owners>::begin(&cid, &spec, &seats::<Owners>(spec.ids().len()), id, &mut rng).expect("roster");
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
    let err = run_dkg::<Owners, _>(&ceremony(9), &spec, &seats::<Owners>(spec.ids().len()), &mut rng).unwrap_err();
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
        run_dkg::<Owners, _>(&ceremony(10), &spec, &seats::<Owners>(spec.ids().len()), &mut rng).unwrap_err(),
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
        &mut rng
    )
    .is_ok());
}

/// Degenerate thresholds are refused.
#[test]
fn degenerate_thresholds_are_refused() {
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    assert!(matches!(
        run_dkg::<Owners, _>(&ceremony(11), &CohortSpec::sequential(4, 3), &seats::<Owners>(3), &mut rng).unwrap_err(),
        DkgError::Roster {
            source: Error::ThresholdExceedsRoster { .. },
            ..
        }
    ));
    assert!(matches!(
        run_dkg::<Owners, _>(&ceremony(11), &CohortSpec::sequential(0, 3), &seats::<Owners>(3), &mut rng).unwrap_err(),
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
    let shares = run_dkg::<Owners, _>(&ceremony(12), &spec, &seats::<Owners>(spec.ids().len()), &mut rng).expect("honest dkg");
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
