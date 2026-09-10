//! **EXHIBIT.** The rogue-key attack on the composite spend root, performed.
//!
//! These tests are expected to PASS. They pass because the attack works. They
//! are not a regression suite and they are not a defence; they are the thing a
//! defence will later be measured against, and the intent is that once
//! cross-cohort proof-of-possession and a commit-then-reveal composition
//! ceremony land, [`exhibit_rogue_gate_component_captures_the_root`] and
//! [`exhibit_the_attack_is_independent_of_the_honest_cohort`] are inverted into
//! rejection tests -- the composition must refuse the rogue component, and the
//! signature must never come into existence.
//!
//! # What is being attacked
//!
//! `crates/two-cohort/src/lib.rs` states the scheme as
//!
//! ```text
//!     b = b_owner + b_gate
//! ```
//!
//! and `CompositeSpend::composite_root` implements the public half of it as a
//! plain group addition, `self.owners.public(o)? + self.gates.public(g)?`,
//! with nothing binding either component to a proof that its publisher can
//! open it. That is the whole attack surface. A cohort that publishes its
//! component SECOND, after seeing the first's, picks a `t` it knows and
//! publishes
//!
//! ```text
//!     B_mine = t*G - B_theirs
//! ```
//!
//! for which it knows no discrete log at all -- and does not need one, because
//! the SUM is `t*G`, whose discrete log it chose.
//!
//! # Why the algebra is driven directly here
//!
//! `CompositeSpend::from_parts` is private and `simulate` is the only
//! constructor, so there is no API that composes a root out of two
//! independently generated components. The code this attack targets does not
//! exist yet; only its shape is fixed, by `composite_root`. So the exhibit
//! builds the composition itself, out of the crate's own pieces:
//!
//!   * the honest cohort is dealt by the crate's own `Cohort::deal_in::<Owners>`
//!     and publishes `Cohort::public`, the same per-participant point terms
//!     `composite_root` sums;
//!   * the payment derivation is restated in
//!     [`pay_to`]/[`common_of`]/[`onetime_of`] and PINNED, by
//!     [`calibration_the_exhibits_derivation_is_the_crates_own`], against an
//!     honest `CompositeSpend` built by `simulate_from_seed`. That calibration
//!     asserts the exhibit's `D_i`, `P`, `common`, `x*G` and key image equal
//!     the crate's `spend_public()`, `target()`, `common()` and
//!     `key_image_from_shares()`. If the exhibit's derivation drifted from the
//!     crate's, that test fails and this file proves nothing;
//!   * acceptance is decided by the vendored, unmodified `RingMLSAG::verify`.
//!     Nothing in this file is asserted against a number this file also chose.
//!
//! # What the attacker is given, stated once and exactly
//!
//! [`Attacker`] holds two scalars and nothing else -- no `Cohort`, no share, no
//! honest secret. The type is the claim.
//!
//!   * `t`, which it invents.
//!   * the view private key `a`. This is NOT a concession that weakens the
//!     exhibit: `a` is not a cohort secret in this design. It derives
//!     subaddresses for anyone who scans for deposits, `src/composite.rs` says
//!     of the view term that it "belongs to whoever runs the view service and
//!     to neither cohort", and `src/mlsag.rs` seats it as a single
//!     un-thresholded `SpendSigner::view`. The scheme's security claim is that
//!     spending needs an owner quorum AND a gate quorum. What this exhibit
//!     shows is that with a rogue component neither quorum is needed: the
//!     honest owner cohort is cancelled, and the attacker never deals a gate
//!     cohort at all, because it has no scalar to share.
//!
//! The input amount blinding is likewise not a cohort secret. MLSAG row 1 is
//! documented in `src/lib.rs` under "No mask-row split" as not split across
//! cohorts at all, so it cannot be the thing that stops this; and in MobileCoin
//! an output's blinding is recovered from the amount shared secret by whoever
//! holds the view key. As in the crate's own `fixture::make_ring`, it is chosen
//! directly here.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G, ristretto::RistrettoPoint, scalar::Scalar,
    traits::Identity,
};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_crypto_ring_signature::{
    generators, Commitment, CompressedCommitment, Error as MlsagError, KeyImage, PedersenGens,
    ReducedTxOut, RingMLSAG,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use two_cohort::{
    derive::{hash_to_point, hash_to_scalar, subaddress_offset},
    Cohort, CohortSpec, CompositeSpend, ControlDomain, Gates, Owners, EUSD_TOKEN_ID,
};

/// The subaddress the bridge would publish for a depositor.
const SUBADDRESS: u64 = 7;

const MESSAGE: &[u8] = b"rogue-key exhibit: release from the composite root";

const RING_SIZE: usize = 11;
const REAL_INDEX: usize = 5;
const VALUE: u64 = 5_000;

// ---------------------------------------------------------------------------
// The MobileCoin payment derivation, restated locally and pinned by
// `calibration_the_exhibits_derivation_is_the_crates_own` against the crate's
// own honest path. Restated because `CompositeSpend::from_parts` is private,
// so a root composed out of two independent components cannot be handed to the
// crate at all.
// ---------------------------------------------------------------------------

/// One output paid to subaddress `index` of spend root `B` by a depositor who
/// knows only the public address.
struct Payment {
    /// `D_i = B + Hs(a||i)*G`, the subaddress spend public key.
    d: RistrettoPoint,
    /// `R = r*D_i`, the output's tx public key.
    r_pub: RistrettoPoint,
    /// `P = Hs(r*C_i)*G + D_i`, the output's one-time target key.
    p: RistrettoPoint,
}

/// The sender's side: exactly the expressions in `CompositeSpend::from_parts`.
fn pay_to(root: &RistrettoPoint, view: &Scalar, index: u64, tx_private: &Scalar) -> Payment {
    let d = root + subaddress_offset(view, index) * G;
    // C_i = a*D_i, the subaddress view public key.
    let c = view * d;
    Payment {
        d,
        r_pub: tx_private * d,
        p: hash_to_scalar(tx_private * c) * G + d,
    }
}

/// `common = Hs(a*R) + Hs(a||i)`: everything in the one-time key that comes
/// from the view key. No cohort secret appears in it.
fn common_of(view: &Scalar, r_pub: &RistrettoPoint, index: u64) -> Scalar {
    hash_to_scalar(view * r_pub) + subaddress_offset(view, index)
}

/// `x = common + b`, where `b` is the discrete log of the spend root. In the
/// honest scheme `b = b_owner + b_gate` and no single party has it.
fn onetime_of(view: &Scalar, r_pub: &RistrettoPoint, index: u64, root_dlog: &Scalar) -> Scalar {
    common_of(view, r_pub, index) + root_dlog
}

/// A ring with the real output at [`REAL_INDEX`]. Mirrors `fixture::make_ring`,
/// which cannot be reused because it takes a `&CompositeSpend`.
fn ring_around(
    payment: &Payment,
    blinding: &Scalar,
    rng: &mut ChaCha20Rng,
) -> (Vec<ReducedTxOut>, PedersenGens) {
    let gens = generators(EUSD_TOKEN_ID);
    let ring = (0..RING_SIZE)
        .map(|i| {
            let (public_key, target_key) = if i == REAL_INDEX {
                (payment.r_pub, payment.p)
            } else {
                (Scalar::random(rng) * G, Scalar::random(rng) * G)
            };
            let b = if i == REAL_INDEX {
                *blinding
            } else {
                Scalar::random(rng)
            };
            ReducedTxOut {
                public_key: (&RistrettoPublic::from(public_key)).into(),
                target_key: (&RistrettoPublic::from(target_key)).into(),
                commitment: CompressedCommitment::from(&Commitment::new(VALUE, b, &gens)),
            }
        })
        .collect();
    (ring, gens)
}

// ---------------------------------------------------------------------------
// The two parties.
// ---------------------------------------------------------------------------

/// The honest cohort's published component, and (for the lock-out test only)
/// the secret behind it.
struct HonestOwners {
    /// `b_owner`. Returned only so that
    /// [`exhibit_the_honest_cohort_is_locked_out_of_its_own_address`] can show
    /// that even the FULL honest secret is useless. The attack path never
    /// receives it.
    secret: Scalar,
    /// `B_owner = b_owner*G`, assembled from a quorum's point terms.
    component: RistrettoPoint,
}

/// Run the honest cohort's dealing and publish its component.
///
/// The cohort value is dropped before this returns, so no share outlives the
/// function: everything downstream sees one group element, which is all a real
/// cohort would broadcast.
fn honest_owners(seed: u64, k: usize, n: usize) -> HonestOwners {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let secret = Scalar::random(&mut rng);
    let ids: Vec<u64> = (0..n as u64).map(Owners::nth).collect();
    let cohort = Cohort::deal_in::<Owners, _>(&secret, k, &ids, &mut rng).expect("well-formed");

    let component = cohort.public(&ids[..k]).expect("qualifying quorum");
    // The dealing really is a k-of-n sharing of `secret`: a second, disjoint
    // quorum assembles the same component, and it is `secret*G`. Without this
    // the "honest" side could be degenerate and the exhibit would be attacking
    // a strawman.
    assert_eq!(component, secret * G, "component is b_owner*G");
    assert_eq!(
        cohort.public(&ids[n - k..]).expect("second quorum"),
        component,
        "every qualifying quorum assembles the same component"
    );

    HonestOwners { secret, component }
}

/// Everything the attacker holds. No `Cohort`, no share, no honest secret --
/// see the module docs on why the view key is in here.
struct Attacker {
    /// The discrete log the attacker chooses for the WHOLE composite root.
    t: Scalar,
    /// The view private key `a`.
    view: Scalar,
}

impl Attacker {
    fn new(seed: u64) -> Attacker {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        Attacker {
            t: Scalar::random(&mut rng),
            view: Scalar::random(&mut rng),
        }
    }

    /// The rogue second component: `B_mine = t*G - B_theirs`.
    ///
    /// The attacker knows no discrete log of this point, and never needs one.
    /// That is also why it never runs a gate DKG: there is no scalar to share.
    fn rogue_component(&self, theirs: &RistrettoPoint) -> RistrettoPoint {
        self.t * G - theirs
    }
}

/// The result of the attack, with every intermediate kept so the exhibit test
/// can assert each step rather than only the outcome.
struct Stolen {
    rogue_component: RistrettoPoint,
    root: RistrettoPoint,
    payment: Payment,
    common: Scalar,
    /// The one-time private key the attacker derived, alone.
    x: Scalar,
    key_image: KeyImage,
    sig: RingMLSAG,
    ring: Vec<ReducedTxOut>,
    out_commitment: CompressedCommitment,
    blinding: Scalar,
    out_blinding: Scalar,
}

impl Stolen {
    fn verify(&self) -> Result<(), MlsagError> {
        self.sig.verify(MESSAGE, &self.ring, &self.out_commitment)
    }
}

/// The attack, start to finish. Construction only -- every claim about it is
/// asserted in the tests below, so that nothing here can quietly assert itself.
fn mount_attack(honest_component: &RistrettoPoint, attacker: &Attacker) -> Stolen {
    // 1. The attacker moves second and publishes t*G - B_theirs.
    let rogue_component = attacker.rogue_component(honest_component);

    // 2. Composition, in the shape `CompositeSpend::composite_root` fixes:
    //    a plain group addition of the two components.
    let root = honest_component + rogue_component;

    // 3. A depositor pays subaddress 7 of that root. `tx_private` is the
    //    sender's, not the attacker's; it is modelled only so there is a real
    //    output to spend.
    let mut rng = ChaCha20Rng::seed_from_u64(0xDE_0051);
    let tx_private = Scalar::random(&mut rng);
    let payment = pay_to(&root, &attacker.view, SUBADDRESS, &tx_private);

    // 4. The attacker, alone, derives the one-time key: it knows `common` from
    //    the view key and the root's discrete log because it chose it.
    let common = common_of(&attacker.view, &payment.r_pub, SUBADDRESS);
    let x = onetime_of(&attacker.view, &payment.r_pub, SUBADDRESS, &attacker.t);
    let key_image = KeyImage::from(&RistrettoPrivate::from(x));

    // 5. It signs a release out of that output with the STOCK MobileCoin
    //    signer. No protocol, no quorum, no second party.
    let (blinding, out_blinding) = (Scalar::from(9u64), Scalar::from(4u64));
    let (ring, gens) = ring_around(&payment, &blinding, &mut rng);
    let out_commitment = CompressedCommitment::from(&Commitment::new(VALUE, out_blinding, &gens));
    let sig = RingMLSAG::sign(
        MESSAGE,
        &ring,
        REAL_INDEX,
        &RistrettoPrivate::from(x),
        VALUE,
        &blinding,
        &out_blinding,
        &gens,
        &mut rng,
    )
    .expect("stock signer");

    Stolen {
        rogue_component,
        root,
        payment,
        common,
        x,
        key_image,
        sig,
        ring,
        out_commitment,
        blinding,
        out_blinding,
    }
}

// ---------------------------------------------------------------------------
// Calibration. If this fails, nothing else in the file means anything.
// ---------------------------------------------------------------------------

/// The exhibit's local derivation IS the crate's derivation.
///
/// Checked against an honest `CompositeSpend`, whose `D_i`, `P`, `common` and
/// key image come from `composite.rs` operating on raw `b_owner`/`b_gate` --
/// values this test never sees.
#[test]
fn calibration_the_exhibits_derivation_is_the_crates_own() {
    let spend = CompositeSpend::simulate_from_seed(
        1234,
        &CohortSpec::<Owners>::sequential(2, 3),
        &CohortSpec::<Gates>::sequential(2, 3),
        SUBADDRESS,
    )
    .expect("well-formed cohort specs");

    let osub = [Owners::nth(0), Owners::nth(1)];
    let gsub = [Gates::nth(0), Gates::nth(2)];

    let a = *spend.view_private().as_ref();
    let root = spend.composite_root(&osub, &gsub).expect("quorums");
    let r_pub = *spend.tx_public().as_ref();

    assert_eq!(
        common_of(&a, &r_pub, SUBADDRESS),
        *spend.common(),
        "common = Hs(a*R) + Hs(a||i)"
    );

    let d = root + subaddress_offset(&a, SUBADDRESS) * G;
    assert_eq!(d, *spend.spend_public().as_ref(), "D_i = B + Hs(a||i)*G");

    // Receiver-side form of P. It agrees with `pay_to`'s sender-side form
    // because R = r*D_i, so a*R = r*(a*D_i) = r*C_i.
    let p = hash_to_scalar(a * r_pub) * G + d;
    assert_eq!(p, *spend.target().as_ref(), "P = Hs(a*R)*G + D_i");

    let x = *spend.onetime(&osub, &gsub).expect("quorums");
    assert_eq!(
        x,
        onetime_of(&a, &r_pub, SUBADDRESS, &(x - *spend.common())),
        "x = common + b"
    );
    assert_eq!(x * G, p, "the one-time private key opens the target key");
    assert_eq!(
        x * hash_to_point(&RistrettoPublic::from(p)),
        spend.key_image_from_shares(&osub, &gsub).expect("quorums"),
        "I = x*Hp(P)"
    );
    assert_eq!(
        KeyImage::from(&RistrettoPrivate::from(x)),
        KeyImage {
            point: spend
                .key_image_from_shares(&osub, &gsub)
                .expect("quorums")
                .compress()
        },
        "upstream's own KeyImage derivation agrees"
    );

    // `pay_to`'s sender-side and receiver-side expressions for P coincide, so
    // the two helpers are two views of one output.
    let (root2, a2, r2) = (Scalar::from(77u64) * G, Scalar::from(31u64), Scalar::from(5u64));
    let pay = pay_to(&root2, &a2, 3, &r2);
    assert_eq!(hash_to_scalar(a2 * pay.r_pub) * G + pay.d, pay.p);
}

// ---------------------------------------------------------------------------
// The exhibit.
// ---------------------------------------------------------------------------

/// EXPECTED TO PASS: the attack works today.
///
/// Second cohort sees `B_owner`, answers `t*G - B_owner`, and ends up owning
/// the composite address outright.
#[test]
fn exhibit_rogue_gate_component_captures_the_root() {
    let honest = honest_owners(0xA11CE, 2, 3);
    let attacker = Attacker::new(0xBADCA7);
    let stolen = mount_attack(&honest.component, &attacker);

    // (a) The rogue component is a response to the honest one: it is not a
    //     value the attacker could have published first.
    assert_eq!(
        stolen.rogue_component,
        attacker.t * G - honest.component,
        "B_mine = t*G - B_theirs"
    );
    assert_ne!(
        stolen.rogue_component,
        RistrettoPoint::identity(),
        "and it is an ordinary-looking, non-identity group element"
    );

    // (b) The composite root collapses to a key the attacker chose.
    assert_eq!(stolen.root, attacker.t * G, "B = B_owner + B_gate = t*G");

    // (c) The attacker alone opens the output paid to a subaddress of it.
    assert_eq!(
        stolen.x,
        stolen.common + attacker.t,
        "x = common + t, and the attacker holds both"
    );
    assert_eq!(
        stolen.x * G,
        stolen.payment.p,
        "x*G is the output's one-time target key"
    );

    // (d) ...and the key image, which is what consensus deduplicates on.
    assert_eq!(
        stolen.key_image.point,
        (stolen.x * hash_to_point(&RistrettoPublic::from(stolen.payment.p))).compress(),
        "I = x*Hp(P)"
    );
    assert_eq!(
        stolen.sig.key_image, stolen.key_image,
        "the signature spends that exact image"
    );

    // (e) THE POINT. Unmodified, vendored RingMLSAG::verify accepts a
    //     signature produced by one party over the two-cohort address.
    stolen
        .verify()
        .expect("stock verifier accepts the solo signature -- this is the defect");
}

/// EXPECTED TO PASS: the honest cohort's shares are not an input to any of it.
///
/// Two entirely different honest cohorts -- different secrets, different
/// rosters, different thresholds -- and one attacker with one `t`. The
/// attacker's rogue component differs between the runs, because it is a
/// response to what it saw. Everything downstream is byte-identical: the root,
/// the address, the output, the key image and the signature itself.
///
/// This is the demonstration, rather than the assertion, that the honest
/// cohort is cancelled. It contributes to the root and to nothing else.
#[test]
fn exhibit_the_attack_is_independent_of_the_honest_cohort() {
    let attacker = Attacker::new(0xBADCA7);

    let a = mount_attack(&honest_owners(0xA11CE, 2, 3).component, &attacker);
    let b = mount_attack(&honest_owners(0x0FF1CE, 4, 5).component, &attacker);

    assert_ne!(
        a.rogue_component, b.rogue_component,
        "the attacker adapted its component to each honest cohort"
    );

    assert_eq!(a.root, b.root, "both roots are t*G");
    assert_eq!(a.payment.d, b.payment.d, "same subaddress");
    assert_eq!(a.payment.p, b.payment.p, "same output target key");
    assert_eq!(a.common, b.common);
    assert_eq!(a.x, b.x, "same one-time private key");
    assert_eq!(a.key_image, b.key_image, "same key image");
    assert!(
        a.sig == b.sig,
        "same signature, scalar for scalar: b_owner is nowhere in it"
    );

    a.verify().expect("first accepted");
    b.verify().expect("second accepted");
}

/// EXPECTED TO PASS: the asymmetry, stated as its other half.
///
/// The attacker spends alone. The honest owner cohort, reconstructing its FULL
/// secret -- not a quorum's worth, all of it -- cannot. There is no gate secret
/// anywhere for it to combine with, because the attacker never dealt one.
///
/// A rejection test earns nothing on its own -- almost any breakage makes a
/// signature fail to verify. Two things make this one attributable:
///
///   * the stock signer is asserted to SUCCEED, so the test is about
///     spendability and not about a signer that refused;
///   * the SAME ring and the SAME output commitment are asserted to accept the
///     attacker's signature, so the rejection is caused by the key and not by a
///     malformed ring.
#[test]
fn exhibit_the_honest_cohort_is_locked_out_of_its_own_address() {
    let honest = honest_owners(0xA11CE, 2, 3);
    let attacker = Attacker::new(0xBADCA7);
    let stolen = mount_attack(&honest.component, &attacker);
    stolen
        .verify()
        .expect("this ring and commitment DO accept a correctly keyed signature");

    // Everything the honest side can possibly assemble for this output.
    let x_honest = stolen.common + honest.secret;
    assert_ne!(x_honest, stolen.x);
    assert_ne!(
        x_honest * G,
        stolen.payment.p,
        "the honest secret does not open the output it believes it co-controls"
    );

    let mut rng = ChaCha20Rng::seed_from_u64(0x105E5);
    let gens = generators(EUSD_TOKEN_ID);
    let honest_sig = RingMLSAG::sign(
        MESSAGE,
        &stolen.ring,
        REAL_INDEX,
        &RistrettoPrivate::from(x_honest),
        VALUE,
        &stolen.blinding,
        &stolen.out_blinding,
        &gens,
        &mut rng,
    )
    .expect("the stock signer produces a signature; the defect is not here");

    assert_ne!(
        honest_sig.key_image, stolen.key_image,
        "it lands on an image belonging to no output in the ring"
    );
    assert_eq!(
        honest_sig
            .verify(MESSAGE, &stolen.ring, &stolen.out_commitment)
            .unwrap_err(),
        MlsagError::InvalidSignature,
        "and the stock verifier rejects it"
    );
}
