//! The two cohorts must not be interchangeable.
//!
//! Everything else in this crate is arithmetic, and arithmetic cannot tell the
//! difference between an owner roster and a gate roster: interpolation over
//! `{1,2,3}` is the same computation whichever group those ids were meant to
//! name. If both cohorts are dealt over the same ids then every owner subset
//! is also a qualifying gate subset, `gates.weighted(owner_subset)` succeeds,
//! and a `CompositeSpend` that never consults the gate argument at all passes
//! the entire rest of the suite.
//!
//! These tests are what stands between the crate and that. They assert about
//! cohort IDENTITY rather than about key images, so they keep failing however
//! carefully the algebra is preserved.

use two_cohort::{
    subsets_of, CohortSpec, CompositeSpend, ControlDomain, Error, Gates, Owners, NAMESPACE_SPAN,
};

fn spend() -> CompositeSpend {
    CompositeSpend::simulate_from_seed(
        0xC0_1D,
        &CohortSpec::<Owners>::sequential(2, 3),
        &CohortSpec::<Gates>::sequential(2, 3),
        4,
    )
    .expect("well-formed cohort specs")
}

/// The heart of it: with equal rosters this test would pass trivially and
/// every mutation that drops the gate subset would go undetected. It passes
/// non-trivially only because the two id bands cannot overlap.
#[test]
fn no_owner_subset_is_ever_a_gate_quorum_or_the_reverse() {
    let s = spend();

    // Same shape on both sides -- 2-of-3 against 2-of-3 -- so nothing here is
    // riding on the cohorts happening to differ in size or threshold.
    assert_eq!(
        (s.owners().threshold(), s.owners().n()),
        (s.gates().threshold(), s.gates().n()),
    );

    for osub in subsets_of(s.owners().roster(), 2) {
        for gsub in subsets_of(s.gates().roster(), 2) {
            // Each subset is a quorum of its own cohort...
            s.owners().weighted(&osub).expect("owner quorum");
            s.gates().weighted(&gsub).expect("gate quorum");

            // ...and of nothing else. Not "produces a different answer" --
            // refused outright, because the ids are not on that roster.
            for (cohort, foreign) in [(s.gates(), &osub), (s.owners(), &gsub)] {
                let err = cohort
                    .weighted(foreign)
                    .expect_err("a subset from the other cohort must be refused");
                assert!(
                    matches!(err.kind(), Error::UnknownParticipant(_)),
                    "expected an unknown-participant refusal, got {err}"
                );
            }

            // And at the composite API, where the two subsets are adjacent
            // arguments and swapping them is the easy mistake to make.
            assert!(s.key_image_from_shares(&gsub, &osub).is_err());
            assert!(s.onetime(&gsub, &osub).is_err());
            assert!(s.composite_root(&gsub, &osub).is_err());
            assert!(s.key_image_terms(&gsub, &osub).is_err());

            // Passing the owner subset where the gate subset belongs is the
            // specific mutation that made the gate argument dead code.
            assert!(s.key_image_from_shares(&osub, &osub).is_err());
            assert!(s.onetime(&osub, &osub).is_err());
        }
    }
}

/// The disjointness the test above relies on, asserted directly against the
/// bands rather than against one dealt pair of cohorts.
#[test]
fn the_two_control_domains_own_disjoint_id_bands() {
    let owner_band = Owners::ID_BASE..Owners::ID_BASE + NAMESPACE_SPAN;
    let gate_band = Gates::ID_BASE..Gates::ID_BASE + NAMESPACE_SPAN;
    assert!(
        owner_band.end <= gate_band.start || gate_band.end <= owner_band.start,
        "owner ids {owner_band:?} and gate ids {gate_band:?} overlap, so an \
         owner roster could be a gate roster"
    );

    // Endpoints, which is where an off-by-one would live.
    for id in [
        Owners::ID_BASE,
        Owners::ID_BASE + NAMESPACE_SPAN - 1,
        Gates::ID_BASE,
        Gates::ID_BASE + NAMESPACE_SPAN - 1,
    ] {
        assert!(
            Owners::owns(id) ^ Gates::owns(id),
            "id {id} must belong to exactly one control domain"
        );
    }

    // 0 belongs to neither: it is the interpolation point.
    assert!(!Owners::owns(0) && !Gates::owns(0));
}

/// Dealing is where the band is enforced, so a roster that reaches across it is
/// refused before any share exists.
#[test]
fn a_roster_that_strays_out_of_its_own_band_is_refused() {
    let owners = CohortSpec::<Owners>::sequential(2, 3);

    // A gate roster containing an owner id -- which is what a config file
    // copied from the wrong cohort would look like.
    let poached = CohortSpec::<Gates>::with_ids(2, &[Gates::nth(0), Owners::nth(1)]);
    let err = CompositeSpend::simulate_from_seed(1, &owners, &poached, 0).unwrap_err();
    assert!(
        matches!(
            err.kind(),
            Error::IdOutsideDomain { id, domain: "gates", .. } if *id == Owners::nth(1)
        ),
        "{err}"
    );

    // The mirror case, so this is not one-directional.
    let poached = CohortSpec::<Owners>::with_ids(2, &[Owners::nth(0), Gates::nth(1)]);
    let err =
        CompositeSpend::simulate_from_seed(1, &poached, &CohortSpec::<Gates>::sequential(2, 3), 0)
            .unwrap_err();
    assert!(
        matches!(
            err.kind(),
            Error::IdOutsideDomain { id, domain: "owners", .. } if *id == Gates::nth(1)
        ),
        "{err}"
    );
}

/// A roster wider than its band would run into the neighbouring domain, so it
/// is refused rather than truncated or wrapped.
#[test]
fn a_roster_wider_than_its_band_is_refused() {
    let mut wide: Vec<u64> = (0..3).map(Owners::nth).collect();
    wide.push(Owners::ID_BASE + NAMESPACE_SPAN);
    assert!(
        Gates::owns(Owners::ID_BASE + NAMESPACE_SPAN),
        "the id just past the owner band is a gate id -- that is the collision \
         this rejection prevents"
    );

    let err = CompositeSpend::simulate_from_seed(
        2,
        &CohortSpec::<Owners>::with_ids(2, &wide),
        &CohortSpec::<Gates>::sequential(2, 3),
        0,
    )
    .unwrap_err();
    assert!(matches!(err.kind(), Error::IdOutsideDomain { .. }), "{err}");

    // `sequential` cannot be used to sneak past it either.
    assert!(CompositeSpend::simulate_from_seed(
        2,
        &CohortSpec::<Owners>::sequential(2, NAMESPACE_SPAN as usize + 1),
        &CohortSpec::<Gates>::sequential(2, 3),
        0,
    )
    .is_err());
}

/// A spec carries its domain in its type, so the two cannot be swapped at the
/// call site and both halves cannot be drawn from one domain. That is a
/// COMPILE-time claim and lives where it can be checked: the `compile_fail`
/// doctests on `CohortSpec`, which `cargo test --doc` runs. Left here is the
/// half a `compile_fail` block cannot establish -- that the right way round is
/// still accepted, so those blocks are failing for the intended reason.
#[test]
fn cohort_specs_are_not_interchangeable_at_the_type_level() {
    assert!(CompositeSpend::simulate_from_seed(
        3,
        &CohortSpec::<Owners>::sequential(2, 3),
        &CohortSpec::<Gates>::sequential(2, 3),
        0,
    )
    .is_ok());
}
