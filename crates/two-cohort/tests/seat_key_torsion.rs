//! **A seat key must be a key.** Ed25519 has cofactor 8, and a 32-byte string
//! can be on the curve without being in the prime-order subgroup `<B>`.
//!
//! This file exists because replacing the seat endorsement's Ed25519 SIGNATURE
//! with a Schnorr proof of knowledge of `d` silently dropped a check and wrote
//! an argument where the check had been. The signature went through
//! `verify_strict`, which refuses a small-order signer before it looks at the
//! signature. The proof went through `IdentityPublic::edwards`, whose comment
//! said:
//!
//! > The caller verifies `z*B == A + c*Id`. The left side is in `<B>`, so the
//! > equation can only hold when `A + c*Id` is too [...] A key with a torsion
//! > component therefore cannot have a verifying endorsement.
//!
//! **`A` is the PROVER's choice.** Nothing constrained it to `<B>`. With `Id`
//! of order 8 and `A = k*B`, the equation holds with `z = k` for every challenge
//! that is `0 mod 8` -- so a prover holding no `d` at all, and for a pure-torsion
//! `Id` no `d` EXISTS, grinds `k` until the challenge falls that way. Expected 8
//! tries. A dealer that keeps every share then supplies the share half honestly
//! and the artifact audits, which is the artifact
//! `seat_identity.rs::a_dealer_that_keeps_the_shares_is_refused_at_the_seat_endorsement`
//! asserts cannot exist.
//!
//! # And the first fix for it was also wrong
//!
//! It used `is_torsion_free` alone. **The Edwards IDENTITY is in the prime-order
//! subgroup**, so that predicate passes it -- and `Id = 0*B` has `d = 0`, a
//! secret everybody has. `z_d*B == A + c*Id` collapses to `z_d*B == A`, so any
//! `A = k*B` with `z_d = k` verifies for every challenge with **no grinding at
//! all**: strictly cheaper than the torsion forgery. Adversarial review found it
//! after the torsion hole was closed. Both predicates are now applied, because
//! `is_small_order` catches the identity and misses `d*B + T`, and
//! `is_torsion_free` catches `d*B + T` and misses the identity.
//!
//! `the_identity_element_is_not_a_seat_key_either` performs it, and it is the
//! exact twin of `CeremonyError::IdentityVerificationShare`, which was already
//! refusing `V = 0` on the share side for the same reason.
//!
//! What entitles these tests to their conclusions, in this file's own terms:
//!
//!   * the forgery tests assert the FORGERY ARITHMETIC WORKS before asserting
//!     that the audit refuses it. Without that, a green test could mean "the
//!     refusal fired" or "my forgery was broken", and those are different
//!     results. The equation is recomputed in the test from the challenge the
//!     PUBLIC `seat_endorsement_challenge` returns -- no hash layout is
//!     duplicated here;
//!   * **every artifact here is COMPLETE**, and that is the second thing an
//!     adversarial review asked for rather than the first. An exact typed error
//!     proves which branch returned; it does not prove the rest of a hand-built
//!     artifact was sound enough that removing the branch would let the attack
//!     through. So every seat of every claim below is endorsed, and this was
//!     CHECKED by removing both guards in a throwaway clone: all three
//!     audit-based tests then fail because `audit` returns `Ok` -- an
//!     `AuditedRoot`, not a different error. Two of them did not have that
//!     property when first written;
//!   * every rejection names the exact error AND its `reason`, so a test about
//!     the identity element cannot pass on the subgroup refusal or the reverse;
//!   * the two guards are separated. `check_shape` is what refuses through
//!     `audit` with a named cause; `IdentityPublic::edwards` is what refuses
//!     through the public `SeatEndorsement::verify`, which never sees
//!     `check_shape`. Deleting either one alone fails a test here and only here.
//!
//! What this file does NOT establish: anything about a seat key that IS a
//! well-formed key. Every residual in `seat_identity.rs` is untouched.

mod common;

use std::collections::BTreeMap;

use common::{identity_of, seal_and_sign, seat_key_of, CohortSide, Honest};
use curve25519_dalek::{
    constants::{ED25519_BASEPOINT_POINT as B, RISTRETTO_BASEPOINT_POINT as G},
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{Identity, IsIdentity},
};
use mc_crypto_keys::Ed25519Public;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use two_cohort::{
    audit,
    ceremony::{
        seat_endorsement_challenge, ComponentClaim, ComponentReveal, SealedComposition,
        SeatEndorsement, SeatRoster,
    },
    identity::IdentityPublic,
    CeremonyError, CeremonyId, CohortSpec, CompositionArtifact, ControlDomain, Gates, Owners,
    Parties,
};

fn hexb(s: &str) -> [u8; 32] {
    let mut o = [0u8; 32];
    for (i, b) in o.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex");
    }
    o
}

/// A 32-byte string that `Ed25519Public` accepts and that is NOT a key: it has
/// no discrete log to the basepoint, because it is not in `<B>` at all.
fn point_that_is_not_a_key(bytes: [u8; 32]) -> IdentityPublic {
    IdentityPublic::from(Ed25519Public::try_from(&bytes[..]).expect("on the curve"))
}

/// Three DISTINCT small-order encodings -- order 8, order 8, order 4 -- so that
/// `Parties::check_distinct` and `CeremonyError::SeatKeysNotDistinct` are
/// satisfied and the refusal, if any, has to come from somewhere else.
const SMALL_ORDER: [&str; 3] = [
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "0000000000000000000000000000000000000000000000000000000000000000",
];

/// The two refusal reasons `CeremonyError::SeatKeyNotUsable` carries.
///
/// Restated here rather than imported so that a test asserting one of them
/// cannot silently start matching the other after an edit to the source string.
const OUTSIDE_SUBGROUP: &str = "outside the prime-order subgroup, so no secret exists behind it";
const IS_THE_IDENTITY: &str = "the identity element, whose discrete log is 0 and is public";

/// The Edwards IDENTITY: `y = 1`, `x = 0`.
///
/// **In the prime-order subgroup**, so `is_torsion_free` says yes about it --
/// which is what made it the gap in the first version of this file's fix.
const THE_IDENTITY: &str = "0100000000000000000000000000000000000000000000000000000000000000";

/// The unique point of order 2: `(0, -1)` in Edwards coordinates.
///
/// Written as its encoding and then CHECKED to be order 2 by the test that uses
/// it, rather than trusted, because `curve25519_dalek::constants::EIGHT_TORSION`
/// is not public in this version and a wrong constant here would make the test
/// pass for the wrong reason.
const ORDER_TWO: &str = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";

fn decompress(k: &IdentityPublic) -> EdwardsPoint {
    CompressedEdwardsY(*k.as_bytes())
        .decompress()
        .expect("the published bytes are on the curve")
}

/// Does the identity half of `e` satisfy its own equation, `z_d*B == A + c*Id`?
///
/// This is the arithmetic `SeatEndorsement::verify` performs, recomputed here so
/// a test can say "the forgery is sound and the refusal came from the KEY check"
/// rather than leaving the two indistinguishable. The challenge comes from the
/// public `seat_endorsement_challenge`, so nothing about the transcript's byte
/// layout is restated in this file.
fn identity_half_satisfies_its_equation(
    ceremony: &CeremonyId,
    claim: &ComponentClaim,
    seat: u64,
    key: &IdentityPublic,
    e: &SeatEndorsement,
) -> bool {
    let c = seat_endorsement_challenge(
        ceremony,
        claim,
        seat,
        key,
        &e.identity_commitment(),
        &e.share_commitment(),
    )
    .expect("the seat is on the roster");
    let a = CompressedEdwardsY(e.identity_commitment())
        .decompress()
        .expect("the commitment is on the curve");
    e.identity_response() * B == a + c * decompress(key)
}

/// Forge `seat`'s endorsement holding the SHARE and no identity secret at all.
///
/// The share half is produced honestly -- the caller has `s`. The identity half
/// is `z_d = k_d` with `A = k_d*B`, which verifies exactly when `c*Id` is the
/// neutral element; every small-order `Id` is killed by 8, so grind `k_d` until
/// the low three bits of `c` are zero. Returns the number of attempts so the
/// test can assert the cost is a handful of hashes, not a search.
///
/// **Bounded, and the bound is not a formality.** A grind whose exit condition
/// depends on the code under test is a HANG waiting for a mutation: with `A`
/// removed from the challenge, `c` stops depending on `k_d` and this loop never
/// terminates. That is a real result being reported as a stalled run, so the cap
/// turns it into a panic that names the cause. `GRIND_CAP` is ~2^-25 of failing
/// by luck at one bit in eight.
const GRIND_CAP: u64 = 200;

fn forge_without_an_identity_secret(
    ceremony: &CeremonyId,
    claim: &ComponentClaim,
    seat: u64,
    not_a_key: &IdentityPublic,
    share: &Scalar,
    tweak: u64,
) -> (SeatEndorsement, u64) {
    let k_s = Scalar::from(tweak + 7);
    let r = k_s * G;
    for tries in 1..=GRIND_CAP {
        let k_d = Scalar::from(tries);
        let a = (k_d * B).compress().to_bytes();
        let c = seat_endorsement_challenge(ceremony, claim, seat, not_a_key, &a, &r)
            .expect("the seat is on the roster");
        if c.as_bytes()[0] & 7 == 0 {
            return (SeatEndorsement::from_parts(a, r, k_d, k_s + c * share), tries);
        }
    }
    panic!(
        "{GRIND_CAP} attempts without a challenge that is 0 mod 8 -- either the \
         challenge stopped depending on A, or this grind is broken",
    );
}

/// An honest prover run BY HAND, for a `(d, Id)` pair this file chose rather
/// than one `IdentityKey` produced.
///
/// The tests below need every seat of a claim endorsed so that removing the
/// guard under test would let the artifact AUDIT -- otherwise an exact typed
/// error proves only which branch returned first, not that the branch is what
/// stops the attack. Adversarial review made exactly that distinction, and two
/// tests here were on the wrong side of it.
///
/// This is `prove_seat_endorsement`'s arithmetic with a sampled nonce instead of
/// a derived one, over the public `seat_endorsement_challenge`. Nothing about
/// the transcript's byte layout is restated.
fn endorse_by_hand(
    ceremony: &CeremonyId,
    claim: &ComponentClaim,
    seat: u64,
    key: &IdentityPublic,
    d: &Scalar,
    s: &Scalar,
    nonce: u64,
) -> SeatEndorsement {
    let k_d = Scalar::from(nonce + 1);
    let k_s = Scalar::from(nonce + 1000);
    let a = (k_d * B).compress().to_bytes();
    let r = k_s * G;
    let c = seat_endorsement_challenge(ceremony, claim, seat, key, &a, &r)
        .expect("the seat is on the roster");
    SeatEndorsement::from_parts(a, r, k_d + c * d, k_s + c * s)
}

/// The three-seat owner claim a dealer that kept every share would publish, over
/// `seats` as the claimed identities.
struct Kept {
    ceremony: CeremonyId,
    ids: Vec<u64>,
    claim: ComponentClaim,
    sealed: SealedComposition,
    gates: CohortSide<Gates>,
    salt: [u8; 32],
    dealt: two_cohort::Cohort,
    b_owner: Scalar,
}

fn dealer_that_keeps_the_shares(seed: u64, seats: &[IdentityPublic]) -> Kept {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let ceremony = CeremonyId::draw("a seat key that is not a key", &mut rng);
    let ids = CohortSpec::<Owners>::sequential(2, 3).ids().to_vec();

    // The dealer's own secret, dealt to itself, exactly as in
    // `seat_identity.rs::a_dealer_that_keeps_the_shares_is_refused_at_the_seat_endorsement`.
    let b_owner = Scalar::random(&mut rng);
    let dealt =
        two_cohort::Cohort::deal_in::<Owners, _>(&b_owner, 2, &ids, &mut rng).expect("dealt");
    let claim = ComponentClaim::from_parts(
        Owners::NAME,
        2,
        ids.clone(),
        b_owner * G,
        ids.iter()
            .map(|&id| dealt.verification_share(id).expect("on the roster"))
            .collect(),
        seats.to_vec(),
    );
    let salt = [0x91; 32];
    let signed = seal_and_sign::<Owners>(&ceremony, &claim, &salt);
    let gate_spec = CohortSpec::<Gates>::sequential(1, 1);
    let gates = CohortSide::<Gates>::generate(&ceremony, &gate_spec, &mut rng);
    let sealed = SealedComposition::new(ceremony, signed, gates.commitment).expect("well-formed");
    Kept {
        ceremony,
        ids,
        claim,
        sealed,
        gates,
        salt,
        dealt,
        b_owner,
    }
}

impl Kept {
    /// Every proof of possession is the dealer's, and every one is genuine: it
    /// holds every share. So a refusal below is attributable to the seat keys and
    /// to nothing else.
    fn pops(&self) -> BTreeMap<u64, two_cohort::Pop> {
        self.ids
            .iter()
            .map(|&id| {
                (
                    id,
                    two_cohort::Pop::prove_unchecked(
                        &self.sealed,
                        &self.claim,
                        id,
                        &self.dealt.share(id).expect("dealt"),
                    )
                    .expect("the dealer holds every share"),
                )
            })
            .collect()
    }

    fn artifact(&self, endorsements: BTreeMap<u64, SeatEndorsement>) -> CompositionArtifact {
        CompositionArtifact::from_parts(
            self.sealed,
            ComponentReveal::from_parts(self.claim.clone(), self.pops(), endorsements, self.salt),
            self.gates.reveal(&self.sealed),
        )
    }

    fn parties(&self, seats: &[IdentityPublic]) -> Parties {
        Parties::new(
            identity_of::<Owners>().public(),
            SeatRoster::<Owners>::new(self.ids.iter().copied().zip(seats.iter().copied()))
                .expect("roster"),
            identity_of::<Gates>().public(),
            SeatRoster::<Gates>::new(
                self.gates
                    .claim
                    .roster()
                    .iter()
                    .map(|&id| (id, seat_key_of::<Gates>(id).public())),
            )
            .expect("roster"),
        )
    }
}

/// **THE EXHIBIT.** A dealer that keeps every share and holds no identity secret
/// forges all three identity halves, and the audit refuses the KEYS.
///
/// The endorsements it assembles are asserted to be arithmetically sound first,
/// so the refusal cannot be read as "the forgery failed".
#[test]
fn a_dealer_that_keeps_the_shares_cannot_use_seat_keys_that_are_not_keys() {
    let seats: Vec<IdentityPublic> = SMALL_ORDER
        .iter()
        .map(|h| point_that_is_not_a_key(hexb(h)))
        .collect();
    let k = dealer_that_keeps_the_shares(0x5EC0, &seats);

    let mut worst = 0u64;
    let endorsements: BTreeMap<u64, SeatEndorsement> = k
        .ids
        .iter()
        .enumerate()
        .map(|(pos, &id)| {
            let (e, tries) = forge_without_an_identity_secret(
                &k.ceremony,
                &k.claim,
                id,
                &seats[pos],
                &k.dealt.share(id).expect("dealt"),
                pos as u64,
            );
            worst = worst.max(tries);
            // The forgery is SOUND: this endorsement's identity half satisfies
            // its own equation under a key with no secret behind it. What the
            // audit below refuses is the key, not this.
            assert!(
                identity_half_satisfies_its_equation(&k.ceremony, &k.claim, id, &seats[pos], &e),
                "the forged identity half must satisfy z_d*B == A + c*Id, or the \
                 refusal below is not attributable to the seat-key check",
            );
            (id, e)
        })
        .collect();
    assert!(
        worst < 200,
        "the forgery is a handful of hashes, not a search: worst seat took {worst}",
    );

    // The payoff the refusal denies: the dealer alone holds the discrete log of
    // the component the funder would have been accepting.
    assert_eq!(k.claim.component(), k.b_owner * G);

    let artifact = k.artifact(endorsements);
    assert_eq!(
        audit(&artifact, &k.parties(&seats))
            .expect_err("no identity secret exists for any owner seat"),
        CeremonyError::SeatKeyNotUsable {
            cohort: Owners::NAME,
            participant: k.ids[0],
            key: seats[0],
            reason: OUTSIDE_SUBGROUP,
        },
    );

    // CONTROL, and it is the only one this test can have: the attack needs a
    // claim built by hand over keys that are not keys, so there is no one-input
    // variant of it. An honest ceremony at the same shape publishes.
    let honest = Honest::run(
        0x5EC1,
        &CohortSpec::<Owners>::sequential(2, 3),
        &CohortSpec::<Gates>::sequential(1, 1),
    );
    audit(&honest.artifact, &honest.parties).expect("CONTROL: an honest ceremony audits");
}

/// The reason the check is `is_torsion_free` and not `is_small_order`.
///
/// One secret `d`, two encodings: `Id = d*B` and `Id + T` with `T` of order 2.
/// The second is NOT small-order, so the cheaper check would pass it, and its
/// holder can still produce a verifying identity half by grinding two challenges
/// -- which means one principal could occupy two seats that
/// [`CeremonyError::SeatKeysNotDistinct`] reads as two.
#[test]
fn one_secret_cannot_wear_two_seat_keys_through_a_torsion_shift() {
    let t = CompressedEdwardsY(hexb(ORDER_TWO))
        .decompress()
        .expect("on the curve");
    assert!(
        t + t == EdwardsPoint::identity() && t != EdwardsPoint::identity(),
        "the constant must really be the point of order 2",
    );

    // One secret, worn twice.
    let d = Scalar::from(0x0BAD_5EED_u64);
    let plain = point_that_is_not_a_key((d * B).compress().to_bytes());
    let shifted = point_that_is_not_a_key((d * B + t).compress().to_bytes());
    assert_ne!(
        plain.as_bytes(),
        shifted.as_bytes(),
        "two encodings, so `SeatKeysNotDistinct` sees two seats",
    );
    assert!(
        !decompress(&shifted).is_small_order(),
        "a torsion-SHIFTED key is not small-order: `is_small_order` would pass it, \
         which is why the check is `is_torsion_free`",
    );

    // A THIRD key whose secret this test also holds, so that every seat of the
    // claim below can be endorsed and the artifact is complete. That is what
    // makes the refusal attributable: with the guard removed this artifact
    // AUDITS, so the typed error is not merely the first branch to return.
    let d3 = Scalar::from(0x0D15_EA5E_u64);
    let third = point_that_is_not_a_key((d3 * B).compress().to_bytes());
    let seats = vec![plain, shifted, third];
    let k = dealer_that_keeps_the_shares(0x5EC2, &seats);

    // The holder of `d` forges the shifted seat's identity half. `A` carries a
    // matching torsion component, so `A + c*Id' = (k + c*d)*B + (t' + c)*T`, and
    // the torsion cancels whenever `t' + c` is even -- expected 2 tries.
    let seat = k.ids[1];
    let share = k.dealt.share(seat).expect("dealt");
    let k_s = Scalar::from(11u64);
    let r = k_s * G;
    // Bounded for `forge_without_an_identity_secret`'s reason: an unbounded
    // grind whose exit condition is the code under test hangs under a mutation
    // instead of failing.
    let mut found = None;
    'grind: for tries in 1..=GRIND_CAP {
        let k_d = Scalar::from(tries);
        for t_prime in [0u8, 1u8] {
            let a_point = if t_prime == 0 { k_d * B } else { k_d * B + t };
            let a = a_point.compress().to_bytes();
            let c = seat_endorsement_challenge(&k.ceremony, &k.claim, seat, &shifted, &a, &r)
                .expect("on the roster");
            // `A + c*Id' = (k_d + c*d)*B + (t' + c)*T`, and `T` has order 2, so
            // the torsion cancels exactly when `t' + c` is even.
            if (c.as_bytes()[0] & 1) == t_prime {
                found = Some((
                    SeatEndorsement::from_parts(a, r, k_d + c * d, k_s + c * *share),
                    tries,
                ));
                break 'grind;
            }
        }
    }
    let (forged, tries) = found.expect("a challenge of each parity within the cap");
    assert!(tries < 20, "expected a couple of tries, took {tries}");
    assert!(
        identity_half_satisfies_its_equation(&k.ceremony, &k.claim, seat, &shifted, &forged),
        "the shifted key's identity half must verify, or this test proves nothing \
         about why the check is `is_torsion_free`",
    );

    // A COMPLETE artifact: the other two seats endorsed honestly, by the same
    // principal, with the secrets it chose. Nothing here is missing or
    // malformed, so the only thing left for the audit to object to is the
    // torsion in seat 1's key.
    let mut endorsements = BTreeMap::new();
    endorsements.insert(seat, forged);
    for (pos, (key, secret)) in [(0usize, (&plain, &d)), (2usize, (&third, &d3))] {
        let id = k.ids[pos];
        endorsements.insert(
            id,
            endorse_by_hand(
                &k.ceremony,
                &k.claim,
                id,
                key,
                secret,
                &k.dealt.share(id).expect("dealt"),
                pos as u64,
            ),
        );
    }
    for (pos, &id) in k.ids.iter().enumerate() {
        assert!(
            identity_half_satisfies_its_equation(
                &k.ceremony,
                &k.claim,
                id,
                &seats[pos],
                endorsements.get(&id).expect("every seat endorsed"),
            ),
            "seat {id}'s identity half must verify, or the refusal below is not \
             attributable to the seat-key check",
        );
    }

    assert_eq!(
        audit(&k.artifact(endorsements), &k.parties(&seats))
            .expect_err("the shifted key is not in the prime-order subgroup"),
        CeremonyError::SeatKeyNotUsable {
            cohort: Owners::NAME,
            participant: seat,
            key: shifted,
            reason: OUTSIDE_SUBGROUP,
        },
    );
}

/// **The gap the FIRST version of the fix left, found by adversarial review
/// after the torsion forgery had been closed.**
///
/// The Edwards identity is *in* the prime-order subgroup, so `is_torsion_free`
/// passes it. Its discrete log is `0`, which everybody has: `z_d*B == A + c*Id`
/// collapses to `z_d*B == A`, so `A = k*B` with `z_d = k` verifies for EVERY
/// challenge -- **no grinding at all**, strictly cheaper than the torsion
/// forgery this file was written for.
///
/// It is the exact twin of `CeremonyError::IdentityVerificationShare`, which was
/// already refusing `V = 0` on the share side for the identical reason. The
/// sigma protocol needed both and had one.
#[test]
fn the_identity_element_is_not_a_seat_key_either() {
    let zero = point_that_is_not_a_key(hexb(THE_IDENTITY));
    let p = decompress(&zero);
    assert!(
        p == EdwardsPoint::identity(),
        "the constant must really be the identity element",
    );
    assert!(
        p.is_torsion_free(),
        "THIS is why `is_torsion_free` alone was not enough: it passes the \
         identity element, whose discrete log is 0",
    );

    // Seat 0 is the identity element; seats 1 and 2 are the two order-8 points,
    // so EVERY seat of this claim is forgeable and the artifact below is
    // complete. With the guard removed it audits, which is what makes the typed
    // error attributable to the guard rather than to whatever would have failed
    // next.
    let seats = vec![
        zero,
        point_that_is_not_a_key(hexb(SMALL_ORDER[0])),
        point_that_is_not_a_key(hexb(SMALL_ORDER[1])),
    ];
    let k = dealer_that_keeps_the_shares(0x5EC5, &seats);
    let seat = k.ids[0];
    let share = k.dealt.share(seat).expect("dealt");

    // No grind. Any `k_d` works, for any challenge, because `c * 0 = 0`.
    let k_d = Scalar::from(12345u64);
    let k_s = Scalar::from(6789u64);
    let r = k_s * G;
    let a = (k_d * B).compress().to_bytes();
    let c = seat_endorsement_challenge(&k.ceremony, &k.claim, seat, &zero, &a, &r)
        .expect("on the roster");
    let forged = SeatEndorsement::from_parts(a, r, k_d, k_s + c * *share);
    assert!(
        identity_half_satisfies_its_equation(&k.ceremony, &k.claim, seat, &zero, &forged),
        "the identity half must verify on the FIRST attempt, or this test is not \
         showing what makes the identity element worse than a torsion point",
    );

    // The other two seats, forged by grinding, so nothing is missing.
    let mut endorsements = BTreeMap::new();
    endorsements.insert(seat, forged);
    for pos in [1usize, 2usize] {
        let id = k.ids[pos];
        let (e, _) = forge_without_an_identity_secret(
            &k.ceremony,
            &k.claim,
            id,
            &seats[pos],
            &k.dealt.share(id).expect("dealt"),
            pos as u64,
        );
        endorsements.insert(id, e);
    }
    for (pos, &id) in k.ids.iter().enumerate() {
        assert!(
            identity_half_satisfies_its_equation(
                &k.ceremony,
                &k.claim,
                id,
                &seats[pos],
                endorsements.get(&id).expect("every seat endorsed"),
            ),
            "seat {id}'s identity half must verify, or the refusal below is not \
             attributable to the seat-key check",
        );
    }

    // The audit names the IDENTITY cause, not the subgroup one -- seat 0 is the
    // identity element and seats 1 and 2 are merely small-order, so a check that
    // only looked at torsion would report seat 1 instead.
    assert_eq!(
        audit(&k.artifact(endorsements), &k.parties(&seats))
            .expect_err("the identity element is not a key"),
        CeremonyError::SeatKeyNotUsable {
            cohort: Owners::NAME,
            participant: seat,
            key: zero,
            reason: IS_THE_IDENTITY,
        },
    );

    // The public verifier refuses it too, and this assertion comes AFTER the
    // audit deliberately: with both guards removed the audit returns `Ok`, and
    // that is the failure this test should report first. A `verify` assertion
    // ahead of it would mask the interesting one.
    let v = k.claim.verification_share(seat).expect("on the roster");
    assert!(
        !forged.verify(&k.ceremony, &k.claim, seat, &v, &zero),
        "`verify` must refuse the identity element as a signer",
    );
}

/// The OTHER guard: the public `SeatEndorsement::verify` takes any signer a
/// caller hands it and never sees `check_shape`.
///
/// This is the only test that can falsify `IdentityPublic::edwards`' subgroup
/// check, because no audit reaches it -- `check_shape` refuses first.
#[test]
fn the_public_seat_endorsement_verify_refuses_a_signer_outside_the_subgroup() {
    let seats: Vec<IdentityPublic> = SMALL_ORDER
        .iter()
        .map(|h| point_that_is_not_a_key(hexb(h)))
        .collect();
    let k = dealer_that_keeps_the_shares(0x5EC3, &seats);
    let seat = k.ids[0];
    let v = k.claim.verification_share(seat).expect("on the roster");
    let (forged, _) = forge_without_an_identity_secret(
        &k.ceremony,
        &k.claim,
        seat,
        &seats[0],
        &k.dealt.share(seat).expect("dealt"),
        0,
    );
    // The arithmetic is sound -- asserted, not assumed.
    assert!(identity_half_satisfies_its_equation(
        &k.ceremony,
        &k.claim,
        seat,
        &seats[0],
        &forged
    ));
    assert!(
        !forged.verify(&k.ceremony, &k.claim, seat, &v, &seats[0]),
        "`verify` must refuse a signer outside the prime-order subgroup even \
         though the equation it would check is satisfied",
    );

    // CONTROL: an honest seat's endorsement, through the same public entry point,
    // does verify.
    let honest = Honest::run(
        0x5EC4,
        &CohortSpec::<Owners>::sequential(2, 3),
        &CohortSpec::<Gates>::sequential(1, 1),
    );
    let hid = honest.owners.claim.roster()[0];
    assert!(honest
        .owners
        .endorsements
        .get(&hid)
        .expect("honest endorsement")
        .verify(
            &honest.ceremony,
            &honest.owners.claim,
            hid,
            &honest.owners.claim.verification_share(hid).expect("roster"),
            &seat_key_of::<Owners>(hid).public(),
        ));
}

/// **Non-canonical Edwards encodings, settled by enumeration rather than by an
/// argument.**
///
/// Dalek's decompression accepts a `y` that is not reduced mod `p`, and neither
/// `Id` nor `A` is recompressed and compared with its input bytes. Adversarial
/// review raised it as a scope note: a stricter independent implementation could
/// disagree, and `IdentityPublic` equality is BYTE equality, so two encodings of
/// one point would read as two seats to
/// [`CeremonyError::SeatKeysNotDistinct`].
///
/// It is closed for `Id`, and this test is why. A 255-bit `y` can only be
/// non-canonical for `y` in `p ..= p+18`, which reduce to `0 ..= 18` -- so the
/// whole space is 19 candidates and can simply be ENUMERATED. Every one of them
/// that is on the curve at all is either the identity or outside the prime-order
/// subgroup, so the two admissibility predicates refuse the lot. No recompression
/// check is needed, and this is a measurement of that rather than the reasoning
/// for it.
///
/// It is closed for `A` for a different and simpler reason, asserted in the same
/// test: the challenge absorbs `A`'s RAW BYTES, so a re-encoded `A` produces a
/// different `c` and the responses that answered the old one do not answer it.
#[test]
fn every_non_canonical_seat_key_encoding_is_refused() {
    // y = p + k for k in 0..19, little-endian. p = 2^255 - 19, so p + k has the
    // low byte 0xed + k and the top byte 0x7f, with 0xff between.
    let mut on_the_curve = 0;
    for k in 0..19u16 {
        let mut y = [0xffu8; 32];
        let low = 0xedu16 + k;
        y[0] = (low & 0xff) as u8;
        if low > 0xff {
            // carries into the next limb; 0xff + 1 wraps, so walk it.
            let mut i = 1;
            loop {
                let (v, c) = y[i].overflowing_add(1);
                y[i] = v;
                if !c {
                    break;
                }
                i += 1;
            }
        }
        y[31] = 0x7f;
        let Some(p) = CompressedEdwardsY(y).decompress() else {
            continue;
        };
        on_the_curve += 1;
        assert!(
            p.is_identity() || !p.is_torsion_free(),
            "non-canonical encoding y = p + {k} decompressed to a point that is \
             neither the identity nor torsion-bearing -- the enumeration argument \
             for skipping a recompression check does not hold",
        );
        // And the crate refuses it, through the same funnel the audit uses.
        let key = point_that_is_not_a_key(y);
        assert!(
            key.unusable_reason().is_some(),
            "non-canonical encoding y = p + {k} must be refused as a seat key",
        );
    }
    assert!(
        on_the_curve >= 2,
        "the enumeration must actually reach some curve points, or it proves \
         nothing; reached {on_the_curve}",
    );

    // `A` needs no such check: the challenge absorbs its raw bytes, so any
    // re-encoding is a different transcript. One honest endorsement, its `A`
    // replaced by a non-canonical encoding of the same point, does not verify.
    let honest = Honest::run(
        0x5EC6,
        &CohortSpec::<Owners>::sequential(2, 3),
        &CohortSpec::<Gates>::sequential(1, 1),
    );
    let seat = honest.owners.claim.roster()[0];
    let e = *honest
        .artifact
        .owners()
        .seat_endorsements()
        .get(&seat)
        .expect("endorsed");
    let mut a = e.identity_commitment();
    a[31] ^= 0x80; // flip the sign bit: a different encoding, a different point
    let tampered = SeatEndorsement::from_parts(
        a,
        e.share_commitment(),
        e.identity_response(),
        e.share_response(),
    );
    let v = honest
        .owners
        .claim
        .verification_share(seat)
        .expect("on the roster");
    let signer = seat_key_of::<Owners>(seat).public();
    assert!(
        !tampered.verify(&honest.ceremony, &honest.owners.claim, seat, &v, &signer),
        "an endorsement whose `A` was re-encoded is a different transcript and \
         must not verify",
    );
    assert!(
        e.verify(&honest.ceremony, &honest.owners.claim, seat, &v, &signer),
        "CONTROL: the untouched endorsement verifies",
    );
}

/// This was a REGRESSION, not a gap the signature also had.
///
/// `IdentityPublic::verify` goes to `verify_strict`, which refuses a small-order
/// signer before it looks at the signature. Stated as a test rather than as a
/// sentence, because the sentence is a claim about what the old code guaranteed
/// and this repo has shipped four of those that were false.
#[test]
fn the_signature_this_replaced_refused_these_keys_too() {
    let key = identity_of::<Owners>();
    let sig = key.sign(b"anything");
    assert!(key.public().verify(b"anything", &sig), "CONTROL");
    for hex in SMALL_ORDER {
        let weak = point_that_is_not_a_key(hexb(hex));
        assert!(
            !weak.verify(b"anything", &sig),
            "the signature path refuses a small-order key before the signature",
        );
    }
}
