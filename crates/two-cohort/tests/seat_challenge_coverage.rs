//! **The one challenge must fix BOTH commitments before either response
//! exists.** That is the entire AND-composition; without it the two halves are
//! not linked and either witness alone suffices.
//!
//! `seat_endorsement_challenge_of` says so:
//!
//! > "`A` and `R` are both absorbed before either response exists, so a prover
//! > cannot choose one commitment after learning the challenge that fixes the
//! > other."
//!
//! For one round that sentence had nothing behind it. Deleting either `h.update`
//! left all 326 tests green -- including both inverted exhibits, whose whole
//! purpose is to rule out exactly the forgery either deletion admits. These two
//! tests are what it needs.
//!
//! The shape of both is the standard "choose the response first" attack on a
//! sigma protocol whose challenge does not cover its commitment. The prover
//! picks `z`, obtains `c`, and SOLVES for the commitment: `A = z_d*B - c*Id`
//! satisfies `z_d*B == A + c*Id` identically, for any `z_d`, with no knowledge
//! of `d`. It fails here only because `c` is a function of `A`, so solving for
//! `A` changes the `c` the verifier recomputes.
//!
//! Each test is written from the position of a party holding ONE witness, which
//! is what makes it a forgery rather than an arithmetic curiosity:
//!
//!   * test 1 is a share-holder with no identity key, and it fails under the
//!     deletion of `A` from the challenge and not under the deletion of `R`;
//!   * test 2 is an identity-key holder with no share -- the position both
//!     inverted exhibits are about -- and it fails under the deletion of `R` and
//!     not under the deletion of `A`.
//!
//! Verified in both directions: green on the real code, and each one red under
//! its own mutation and not under the other's.
//!
//! Stated exactly, because "and only its own" would have been the tidier and
//! wrong version: deleting `R` fails test 2 and nothing else in the suite.
//! Deleting `A` fails test 1 and ALSO three tests in `tests/seat_key_torsion.rs`,
//! whose bounded grind searches for a challenge that depends on `A` and panics
//! by its cap when one stops existing. Those are a second detector of the same
//! mutation, not a second cover of this property -- none of them would notice
//! `R` going missing, which is the direction that matters most here.

mod common;

use common::{own_share_scalar, seat_key_of, CohortSide};
use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT as B, RISTRETTO_BASEPOINT_POINT as G},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use two_cohort::{
    ceremony::{seat_endorsement_challenge, SeatEndorsement},
    identity::IdentityPublic,
    CeremonyId, CohortSpec, Owners,
};

/// `Id` as a point, from the 32 published bytes -- the same decompression an
/// outside verifier does. `IdentityPublic::edwards` is `pub(crate)`.
fn signer_point(k: &IdentityPublic) -> EdwardsPoint {
    CompressedEdwardsY(*k.as_bytes())
        .decompress()
        .expect("a published key is a point")
}

fn side(seed: u64) -> (CeremonyId, CohortSide<Owners>) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let ceremony = CeremonyId::draw("challenge coverage", &mut rng);
    let spec = CohortSpec::<Owners>::sequential(2, 3);
    let s = CohortSide::<Owners>::generate(&ceremony, &spec, &mut rng);
    (ceremony, s)
}

/// A share-holder that does NOT hold the seat's identity key cannot solve for
/// `A` after the fact, because the challenge is a function of `A`.
#[test]
fn a_share_holder_cannot_solve_for_the_identity_commitment_after_the_challenge() {
    let (ceremony, s) = side(0xC0DE);
    let id = s.claim.roster()[0];
    let v = s.claim.verification_share(id).expect("on the roster");
    let signer = seat_key_of::<Owners>(id).public();
    // The one witness this prover has.
    let share = own_share_scalar(&s, id);

    let k_s = Scalar::from(31337u64);
    let r = k_s * G;
    // The response it wants, chosen freely and FIRST.
    let z_d = Scalar::from(99u64);
    // The challenge it can compute without having committed to `A` -- if `A` is
    // not absorbed, any placeholder gives the same `c`, and this is one.
    let placeholder = (Scalar::from(1u64) * B).compress().to_bytes();
    let c = seat_endorsement_challenge(&ceremony, &s.claim, id, &signer, &placeholder, &r)
        .expect("on the roster");
    // Solve: this `A` satisfies `z_d*B == A + c*Id` by construction, with no `d`.
    let a = (z_d * B - c * signer_point(&signer)).compress().to_bytes();
    let forged = SeatEndorsement::from_parts(a, r, z_d, k_s + c * share);

    assert!(
        !forged.verify(&ceremony, &s.claim, id, &v, &signer),
        "FORGERY ACCEPTED: a share-holder with no identity key endorsed this seat \
         by solving for A after the challenge. The challenge must be a function of A.",
    );

    // CONTROL: the same seat, endorsed with BOTH witnesses, does verify -- so the
    // refusal above is not the whole verification path saying no to everything.
    let honest = s.endorsements.get(&id).expect("honest endorsement");
    assert!(
        honest.verify(&ceremony, &s.claim, id, &v, &signer),
        "CONTROL: the honest endorsement of the same seat verifies",
    );
}

/// The mirror, and the one that matters most: an identity-key holder that was
/// never dealt a share cannot solve for `R` after the fact.
///
/// This is precisely the position of the dealer's victim in
/// `seat_identity.rs::a_dealer_that_keeps_the_shares_is_refused_at_the_seat_endorsement`
/// and of every share-less endorser the rework exists to refuse.
#[test]
fn an_identity_key_holder_cannot_solve_for_the_share_commitment_after_the_challenge() {
    let (ceremony, s) = side(0xC0DF);
    let id = s.claim.roster()[0];
    let v = s.claim.verification_share(id).expect("on the roster");
    let signer = seat_key_of::<Owners>(id).public();

    // The identity half is answered honestly -- this prover holds `d`. `d` itself
    // is `pub(crate)`, so this seat's own honest `A` and `z_d` stand in for the
    // act of answering with it: what is under test is the SHARE half, and the
    // challenge has to be computed over the SAME `A` the verifier will see.
    let honest = s.endorsements.get(&id).expect("honest endorsement");
    let a = honest.identity_commitment();
    // The response it wants, chosen freely and FIRST.
    let z_s = Scalar::from(7u64);
    let placeholder = Scalar::from(1u64) * G;
    let c = seat_endorsement_challenge(&ceremony, &s.claim, id, &signer, &a, &placeholder)
        .expect("on the roster");
    // Solve: this `R` satisfies `z_s*G == R + c*V` by construction, with no `s`.
    let r = z_s * G - c * v;
    let forged = SeatEndorsement::from_parts(a, r, honest.identity_response(), z_s);

    assert!(
        !forged.verify(&ceremony, &s.claim, id, &v, &signer),
        "FORGERY ACCEPTED: a share-less party endorsed this seat by solving for R \
         after the challenge. The challenge must be a function of R.",
    );

    assert!(
        honest.verify(&ceremony, &s.claim, id, &v, &signer),
        "CONTROL: the honest endorsement of the same seat verifies",
    );
}
