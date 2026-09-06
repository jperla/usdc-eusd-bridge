//! The two-round distributed MLSAG protocol, driven end to end.
//!
//! The first test is the whole point: an unmodified `RingMLSAG::verify` from
//! the vendored MobileCoin crate accepts a signature over a real ring at the
//! eUSD token id, produced entirely through `two_cohort::mlsag`, in which no
//! process at any moment formed the composite one-time scalar `x`.
//!
//! Every test that mentions `x` computes it in the TEST, out of
//! `CompositeSpend::onetime`, purely as an independent answer to check the
//! protocol's output against. `onetime` is never on the protocol's path -- it
//! is called only inside `#[test]` bodies in this file, which is checkable by
//! grepping `src/mlsag.rs` for it.
//!
//! # What is and is not an independent check here
//!
//! `assert_eq!(sig.key_image, KeyImage::from(&x))` is NOT independent on its
//! own: the test's `x` comes from `CompositeSpend::onetime` -> `reconstruct`,
//! which is `weighted(subset).map(weight).sum()`, and `quorum_signers` builds
//! every seat from that same `weighted`. A wrong Lagrange weight moves both
//! sides together. What actually pins the protocol is `RingMLSAG::verify`
//! against a ring whose real `target_key` is `CompositeSpend::target()`, which
//! `composite.rs` derives from the raw `b_owner`/`b_gate` and never through
//! Lagrange. Cite the verifier, not the image comparison.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto,
    ristretto::RistrettoPoint, scalar::Scalar,
};
use mc_crypto_keys::RistrettoPrivate;
use mc_crypto_ring_signature::{
    Commitment, CompressedCommitment, Error as MlsagError, KeyImage, ReducedTxOut, RingMLSAG,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use two_cohort::{
    fixture::make_ring_from_seed,
    mlsag::{
        quorum_signers, sign, MaskNonce, MaskSigner, MemoryNonceGuard, RoundOne, Seat, Session,
        SessionParams, SigningError, SpendNonce, SpendResponse, SpendRole, SpendSigner,
    },
    subsets_of, CohortSpec, CompositeSpend, ControlDomain, Error as CohortError, Gates, Owners,
};

const MESSAGE: &[u8] = b"two-cohort distributed mlsag";

/// A session id is the coordinator's per-attempt nonce. Distinct ids give
/// distinct session bindings, which is what makes two attempts at the same
/// transaction draw different one-time nonces.
fn sid(tag: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&tag.to_le_bytes());
    out
}

/// One spend, one ring, one set of amounts. The ring is built by the crate's
/// own fixture, at `EUSD_TOKEN_ID` generators.
struct Setup {
    spend: CompositeSpend,
    ring: Vec<ReducedTxOut>,
    out_commitment: CompressedCommitment,
    blinding: Scalar,
    out_blinding: Scalar,
    real_index: usize,
}

fn setup(seed: u64, k: usize, n: usize, g: usize, m: usize) -> Setup {
    let spend = CompositeSpend::simulate_from_seed(
        seed,
        &CohortSpec::<Owners>::sequential(k, n),
        &CohortSpec::<Gates>::sequential(g, m),
        7,
    )
    .expect("well-formed cohort specs");

    let (value, blinding, out_blinding) = (5_000u64, Scalar::from(9u64), Scalar::from(4u64));
    let real_index = 5;
    let (ring, gens) = make_ring_from_seed(&spend, 11, real_index, value, &blinding, seed ^ 0xD2D);
    let out_commitment = CompressedCommitment::from(&Commitment::new(value, out_blinding, &gens));

    Setup {
        spend,
        ring,
        out_commitment,
        blinding,
        out_blinding,
        real_index,
    }
}

impl Setup {
    fn params<'a>(&'a self, session_id: &'a [u8; 32]) -> SessionParams<'a> {
        SessionParams {
            session_id,
            message: MESSAGE,
            ring: &self.ring,
            real_index: self.real_index,
            output_commitment: &self.out_commitment,
        }
    }

    fn params_over<'a>(&'a self, session_id: &'a [u8; 32], message: &'a [u8]) -> SessionParams<'a> {
        SessionParams {
            session_id,
            message,
            ring: &self.ring,
            real_index: self.real_index,
            output_commitment: &self.out_commitment,
        }
    }

    fn mask(&self) -> MaskSigner {
        MaskSigner::owner_held(&self.out_blinding, &self.blinding)
    }

    /// The canonical one-time key. TEST ONLY -- this is the value the protocol
    /// must reach without ever forming it.
    fn canonical_x(&self, osub: &[u64], gsub: &[u64]) -> Scalar {
        *self.spend.onetime(osub, gsub).expect("qualifying subsets")
    }

    fn verify(&self, sig: &RingMLSAG) -> Result<(), MlsagError> {
        sig.verify(MESSAGE, &self.ring, &self.out_commitment)
    }
}

/// `Result::unwrap_err` needs `T: Debug`, and `RingMLSAG` has no `Debug` impl
/// with the feature set this workspace pins. Same assertion, spelled out.
fn expect_refused<T>(result: Result<T, SigningError>) -> SigningError {
    match result {
        Ok(_) => panic!("expected the protocol to refuse, but it produced a signature"),
        Err(e) => e,
    }
}

fn owner_ids(positions: &[usize]) -> Vec<u64> {
    positions.iter().map(|&p| Owners::nth(p as u64)).collect()
}

fn gate_ids(positions: &[usize]) -> Vec<u64> {
    positions.iter().map(|&p| Gates::nth(p as u64)).collect()
}

/// Run round one for a set of seats. Returns the published messages and the
/// armed signers, in seat order.
type Armed = (
    Vec<SpendNonce>,
    Vec<two_cohort::mlsag::ArmedSpendSigner>,
    MaskNonce,
    two_cohort::mlsag::ArmedMaskSigner,
);

fn commit_all(
    params: &SessionParams<'_>,
    seats: Vec<SpendSigner>,
    mask: MaskSigner,
    guard: &mut MemoryNonceGuard,
) -> Armed {
    let (mut nonces, mut armed) = (Vec::new(), Vec::new());
    for seat in seats {
        let (n, a) = seat.commit(params, guard).expect("commit");
        nonces.push(n);
        armed.push(a);
    }
    let (mask_nonce, armed_mask) = mask.commit(params, guard).expect("mask commit");
    (nonces, armed, mask_nonce, armed_mask)
}

// ---------------------------------------------------------------------------
// 1. The stock verifier accepts it.
// ---------------------------------------------------------------------------

/// THE test. Both rounds are driven explicitly here rather than through the
/// `sign` helper, so that what each party publishes is visible: participants
/// emit group elements in round one and a single blinded scalar in round two,
/// and the coordinator only ever adds those up.
#[test]
fn the_stock_verifier_accepts_a_signature_produced_without_forming_the_scalar() {
    let s = setup(101, 2, 3, 2, 3);
    let (osub, gsub) = (owner_ids(&[0, 2]), gate_ids(&[1, 2]));
    let mut rng = ChaCha20Rng::seed_from_u64(0xA11CE);
    let mut guard = MemoryNonceGuard::new();

    let id = sid(1);
    let params = s.params(&id);
    let session = Session::open(params, &mut rng).expect("open session");

    let seats = quorum_signers(&s.spend, &osub, &gsub).expect("qualifying subsets");
    assert_eq!(
        seats.iter().map(|seat| seat.role()).collect::<Vec<_>>(),
        vec![
            SpendRole::View,
            SpendRole::Owner(osub[0]),
            SpendRole::Owner(osub[1]),
            SpendRole::Gate(gsub[0]),
            SpendRole::Gate(gsub[1]),
        ],
        "the view term plus one seat per participant of each cohort"
    );

    // ROUND ONE: each seat derives its own base from the ring, derives its own
    // nonce from the session binding, and publishes four points.
    let (nonces, armed, mask_nonce, armed_mask) = commit_all(&params, seats, s.mask(), &mut guard);
    assert_eq!(guard.len(), 6, "five spend seats and the mask row");

    // Every seat reached the same base without being handed one.
    assert_eq!(params.spend_base().unwrap(), session.spend_base());

    // No single seat owns the output; together they do.
    let target: RistrettoPoint = *s.spend.target().as_ref();
    for nonce in &nonces {
        assert_ne!(
            nonce.share_public, target,
            "{} alone owns the output",
            nonce.role
        );
    }
    session
        .preflight(&nonces)
        .expect("this quorum owns the output");

    let challenged = session
        .round_one(&nonces, &mask_nonce)
        .expect("challenge chain");

    // The key image exists after ROUND ONE -- assembled from the published
    // `w_i * Hp(P)` terms, before any response scalar has been sent.
    let image_after_round_one = challenged.key_image();
    let transcript = challenged.round_one_transcript().clone();

    // ROUND TWO: every participant re-runs the chain over the published
    // transcript and its OWN copy of the session. Nobody is handed a challenge.
    let responses: Vec<SpendResponse> = armed
        .into_iter()
        .map(|a| a.respond(&params, &transcript).expect("respond"))
        .collect();
    let mask_response = armed_mask.respond(&params, &transcript).expect("mask");
    let sig = challenged
        .finish(&responses, &mask_response)
        .expect("assemble the signature");

    // The unmodified vendored verifier.
    s.verify(&sig)
        .expect("unmodified RingMLSAG::verify must accept the distributed signature");

    // The canonical one-time key, computed HERE and nowhere in the protocol.
    let x = RistrettoPrivate::from(s.canonical_x(&osub, &gsub));
    assert_eq!(
        sig.key_image,
        KeyImage::from(&x),
        "the assembled image must be the image of the canonical one-time key"
    );
    assert_eq!(image_after_round_one, KeyImage::from(&x));

    assert_eq!(sig.responses.len(), 2 * s.ring.len());
    for (i, r) in sig.responses.iter().enumerate() {
        assert_ne!(r.scalar, Scalar::ZERO, "response {i} was left unset");
    }

    // It is a genuinely different signature object from what the stock signer
    // would emit for the same key -- same image, different responses -- so the
    // acceptance above is not an artefact of reproducing upstream's output.
    let mut stock_rng = ChaCha20Rng::seed_from_u64(0xB0B);
    let stock = RingMLSAG::sign(
        MESSAGE,
        &s.ring,
        s.real_index,
        &x,
        5_000,
        &s.blinding,
        &s.out_blinding,
        &mc_crypto_ring_signature::generators(two_cohort::EUSD_TOKEN_ID),
        &mut stock_rng,
    )
    .expect("stock sign");
    assert_eq!(stock.key_image, sig.key_image);
    assert_ne!(stock.c_zero.scalar, sig.c_zero.scalar);
}

// ---------------------------------------------------------------------------
// 2. The scalar is never formed.
// ---------------------------------------------------------------------------

/// Behavioural half of the "no process forms `x`" claim. The structural half
/// is in `src/mlsag.rs`: `SpendSigner`/`ArmedSpendSigner` keep the share in a
/// private field with no accessor (there is a `compile_fail` doctest on
/// `SpendSigner` for reading it), and `Session`/`ChallengedSession` are handed
/// no share at all.
///
/// Here: take the ENTIRE public transcript -- every round message, both
/// challenges, and the finished signature -- and show `x` is not in it, and is
/// not one arithmetic step away from it. The one relation that involves `x` is
/// `sum_i r_i = alpha_0 - c*x`, and recovering `x` from that needs `alpha_0`,
/// which appears in the transcript only as `alpha_0 * G`.
///
/// This is a bounded enumeration, not a proof of unrecoverability. The load
/// bearing assertion is the last one: the relation the transcript satisfies is
/// stated and checked, so the claim is about a relation this protocol really
/// has. Cross-session recovery -- the attack this enumeration cannot see -- is
/// `two_sessions_with_one_seat_set_do_not_expose_a_share`.
#[test]
fn the_one_time_scalar_is_in_neither_the_protocol_nor_its_transcript() {
    let s = setup(202, 2, 3, 2, 3);
    let (osub, gsub) = (owner_ids(&[0, 1]), gate_ids(&[0, 2]));
    let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE);
    let mut guard = MemoryNonceGuard::new();

    let id = sid(2);
    let params = s.params(&id);
    let session = Session::open(params, &mut rng).expect("open session");
    let seats = quorum_signers(&s.spend, &osub, &gsub).unwrap();
    let (nonces, armed, mask_nonce, armed_mask) = commit_all(&params, seats, s.mask(), &mut guard);

    let challenged = session.round_one(&nonces, &mask_nonce).unwrap();
    let c = *challenged.challenge();
    let transcript_msgs = challenged.round_one_transcript().clone();
    let responses: Vec<SpendResponse> = armed
        .into_iter()
        .map(|a| a.respond(&params, &transcript_msgs).unwrap())
        .collect();
    let mask_response = armed_mask.respond(&params, &transcript_msgs).unwrap();
    let sig = challenged.finish(&responses, &mask_response).unwrap();
    s.verify(&sig).expect("still a valid signature");

    let x = s.canonical_x(&osub, &gsub);

    // Every scalar anybody publishes, anywhere.
    let mut transcript: Vec<Scalar> = Vec::new();
    transcript.push(*c.scalar());
    transcript.push(sig.c_zero.scalar);
    transcript.extend(responses.iter().map(|r| r.response));
    transcript.push(mask_response.response);
    transcript.extend(sig.responses.iter().map(|r| r.scalar));
    transcript.extend(transcript_msgs.responses.iter().copied());

    for t in &transcript {
        assert_ne!(
            *t, x,
            "the one-time scalar appeared verbatim in the transcript"
        );
    }

    // The obvious rearrangements of `sum_i r_i = alpha_0 - c*x` with `alpha_0`
    // guessed as zero.
    let sum: Scalar = responses.iter().map(|r| r.response).sum();
    let c_inv = c.scalar().invert();
    for candidate in [sum, -sum, sum * c_inv, -sum * c_inv] {
        assert_ne!(candidate, x);
    }
    // Pairwise sums and differences of DISTINCT transcript scalars. `i + 1`
    // rather than `i`: `a - a == 0` and `a + a == 2a` for the same element are
    // not rearrangements of anything, and asserting `0 != x` repeatedly is not
    // a check.
    for (i, a) in transcript.iter().enumerate() {
        for b in &transcript[i + 1..] {
            assert_ne!(*a + *b, x, "a pairwise sum of transcript scalars was x");
            assert_ne!(
                *a - *b,
                x,
                "a pairwise difference of transcript scalars was x"
            );
            assert_ne!((*a - *b) * c_inv, x);
        }
    }

    // `alpha_0` is what would close the gap, and no published scalar is it:
    // the transcript carries `alpha_0` only as the point `sum_i alpha_i * G`.
    let alpha_0_g: RistrettoPoint = nonces
        .iter()
        .map(|n| {
            n.nonce_public
                + transcript_msgs.binding_factor(&params, Seat::Spend(n.role)) * n.binding_public
        })
        .sum();
    for t in &transcript {
        assert_ne!(*t * RISTRETTO_BASEPOINT_POINT, alpha_0_g);
    }

    // And the sum relation really is the one described, checked against the
    // TEST's `x`: `sum_i r_i + c*x = alpha_0`.
    assert_eq!(
        (sum + *c.scalar() * x) * RISTRETTO_BASEPOINT_POINT,
        alpha_0_g,
        "the responses must sum to alpha_0 - c*x, or the claim above is about \
         a relation this protocol does not satisfy"
    );

    // No individual participant's published share is the target key, and no
    // cohort's contribution alone is: the seats are all load-bearing.
    let target: RistrettoPoint = *s.spend.target().as_ref();
    let owners_only: RistrettoPoint = nonces
        .iter()
        .filter(|n| !matches!(n.role, SpendRole::Gate(_)))
        .map(|n| n.share_public)
        .sum();
    assert_ne!(owners_only, target);
    assert_eq!(
        target - owners_only,
        s.spend.gates().public(&gsub).unwrap(),
        "what the owner seats are missing is exactly the gate cohort's public key"
    );
}

// ---------------------------------------------------------------------------
// 2b. Two sessions with the same seats.
// ---------------------------------------------------------------------------

/// The cross-session attack the single-session transcript test cannot see.
///
/// If one seat's `alpha_i` is repeated under two different challenges, then
/// `(r - r')/(c' - c) = w_i` gives up that seat's weighted share, and summing
/// over the quorum gives up `x` -- and, because `w_i = lambda_i * s_i` over a
/// SUBSET rather than an output, what it really gives up is the long-term
/// component root, not one UTXO.
///
/// Nonces here are `H(NONCE_DOMAIN | binding | seat | w_i)`. No RNG reaches a
/// participant, so "the signer restarted from a snapshot and replayed its RNG
/// stream" cannot repeat a nonce; only replaying the same session binding can,
/// and `NonceGuard` refuses that (see `a_seat_cannot_draw_two_nonces_for_one_session`).
#[test]
fn two_sessions_with_one_seat_set_do_not_expose_a_share() {
    // POSITIVE CONTROL for the recovery formula itself, so that the negative
    // assertions below are known to be testing something. If a nonce WERE
    // repeated, this is exactly the arithmetic that would recover the share.
    {
        let w = Scalar::from(424_242u64);
        let alpha = Scalar::from(1_717u64);
        let (c1, c2) = (Scalar::from(3u64), Scalar::from(5u64));
        let (r1, r2) = (alpha - c1 * w, alpha - c2 * w);
        assert_eq!(
            (r1 - r2) * (c2 - c1).invert(),
            w,
            "the recovery formula must work on a genuinely repeated nonce, or \
             the assertions below prove nothing"
        );
    }

    let s = setup(2020, 2, 3, 2, 3);
    let (osub, gsub) = (owner_ids(&[0, 2]), gate_ids(&[1, 2]));
    // ONE guard across both sessions, as a real signer would have.
    let mut guard = MemoryNonceGuard::new();

    // The seats' weights, computed in the TEST, to check the recovery against.
    let mut weights: Vec<(SpendRole, Scalar)> = vec![(SpendRole::View, *s.spend.common())];
    for t in s.spend.owners().weighted(&osub).unwrap().iter() {
        weights.push((SpendRole::Owner(t.id()), *t.weight()));
    }
    for t in s.spend.gates().weighted(&gsub).unwrap().iter() {
        weights.push((SpendRole::Gate(t.id()), *t.weight()));
    }

    let run = |session_id: &[u8; 32],
               message: &'static [u8],
               rng_seed: u64,
               guard: &mut MemoryNonceGuard| {
        let params = s.params_over(session_id, message);
        let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
        let session = Session::open(params, &mut rng).unwrap();
        let seats = quorum_signers(&s.spend, &osub, &gsub).unwrap();
        let (nonces, armed, mask_nonce, armed_mask) = commit_all(&params, seats, s.mask(), guard);
        session.preflight(&nonces).unwrap();
        let challenged = session.round_one(&nonces, &mask_nonce).unwrap();
        let c = *challenged.challenge().scalar();
        let t = challenged.round_one_transcript().clone();
        let responses: Vec<SpendResponse> = armed
            .into_iter()
            .map(|a| a.respond(&params, &t).unwrap())
            .collect();
        let sig = challenged
            .finish(&responses, &armed_mask.respond(&params, &t).unwrap())
            .unwrap();
        assert_eq!(
            sig.verify(message, &s.ring, &s.out_commitment),
            Ok(()),
            "the honest run must verify, or a 'nothing leaked' result is just \
             a broken signer"
        );
        (c, nonces, responses)
    };

    // Two sessions over the SAME output and the SAME seats. Different session
    // ids and different messages: the ordinary case of one participant signing
    // two transactions, and of a retried attempt.
    let (id_a, id_b) = (sid(0xA), sid(0xB));
    let (c_a, nonces_a, resp_a) = run(&id_a, b"payout to alice", 0x5EED, &mut guard);
    // Deliberately the SAME rng seed for the coordinator: the participants take
    // no RNG at all, so a replayed coordinator stream must not repeat a nonce.
    let (c_b, nonces_b, resp_b) = run(&id_b, b"payout to bob", 0x5EED, &mut guard);

    assert_ne!(c_a, c_b, "two sessions must not share a challenge");

    // Every seat's nonce commitment differs between the two sessions.
    for a in &nonces_a {
        let b = nonces_b
            .iter()
            .find(|b| b.role == a.role)
            .expect("same seat set in both sessions");
        assert_eq!(a.share_public, b.share_public, "same share, both sessions");
        assert_ne!(
            a.nonce_public, b.nonce_public,
            "{} published the same nonce twice",
            a.role
        );
        assert_ne!(a.nonce_image, b.nonce_image, "{} on Hp(P)", a.role);
    }

    // And the recovery formula, applied per seat, reaches nothing.
    let denom = (c_b - c_a).invert();
    let mut total = Scalar::ZERO;
    for (role, weight) in &weights {
        let ra = resp_a.iter().find(|r| r.role == *role).unwrap().response;
        let rb = resp_b.iter().find(|r| r.role == *role).unwrap().response;
        let recovered = (ra - rb) * denom;
        assert_ne!(recovered, *weight, "{role}'s weighted share fell out");
        total += recovered;
    }
    let x = s.canonical_x(&osub, &gsub);
    assert_ne!(total, x, "the composite one-time scalar fell out");

    // The summed form, spelled the way an attacker would write it: the two
    // signatures' real-row responses.
    let sum_a: Scalar = resp_a.iter().map(|r| r.response).sum();
    let sum_b: Scalar = resp_b.iter().map(|r| r.response).sum();
    assert_ne!((sum_a - sum_b) * denom, x);
    assert_ne!((sum_b - sum_a) * (c_a - c_b).invert(), x);
}

/// The other half of the nonce story: the guard. One seat, one session
/// binding, one nonce, forever -- including across the process restart that
/// makes the derivation repeat.
#[test]
fn a_seat_cannot_draw_two_nonces_for_one_session() {
    let s = setup(2121, 2, 3, 2, 3);
    let (osub, gsub) = (owner_ids(&[0, 1]), gate_ids(&[0, 1]));
    let id = sid(0x2121);
    let params = s.params(&id);
    let mut guard = MemoryNonceGuard::new();

    let seats = quorum_signers(&s.spend, &osub, &gsub).unwrap();
    let first_gate = SpendRole::Gate(gsub[0]);
    let mut first_nonce = None;
    for seat in seats {
        let role = seat.role();
        let (n, _) = seat.commit(&params, &mut guard).expect("first commit");
        if role == first_gate {
            first_nonce = Some(n);
        }
    }
    let first_nonce = first_nonce.expect("the first gate seat is in the quorum");
    s.mask().commit(&params, &mut guard).expect("mask");

    // A SECOND, freshly constructed seat for the same participant -- a
    // restarted process, not a cloned object. The type system cannot see it;
    // the guard can.
    let terms = s.spend.gates().weighted(&gsub).unwrap();
    let again = SpendSigner::gate(&terms[0]);
    assert_eq!(again.role(), first_gate);
    let err = expect_refused(again.commit(&params, &mut guard));
    assert_eq!(
        err,
        SigningError::NonceAlreadyIssued {
            seat: Seat::Spend(first_gate)
        },
        "got {err}"
    );

    // The mask row is guarded too.
    let err = expect_refused(s.mask().commit(&params, &mut guard));
    assert_eq!(err, SigningError::NonceAlreadyIssued { seat: Seat::Mask });

    // A different session id is a different binding, so a retry is allowed --
    // and it is safe precisely because it draws a different nonce.
    let retry_id = sid(0x2122);
    let retry = s.params(&retry_id);
    let terms = s.spend.gates().weighted(&gsub).unwrap();
    let (retry_nonce, _) = SpendSigner::gate(&terms[0])
        .commit(&retry, &mut guard)
        .expect("a retry under a fresh session id is allowed");
    assert_ne!(
        first_nonce.nonce_public, retry_nonce.nonce_public,
        "a retry must not reuse the nonce"
    );
    assert_eq!(
        first_nonce.share_public, retry_nonce.share_public,
        "...while carrying the same share"
    );
}

// ---------------------------------------------------------------------------
// 2c. Round one is bound to the transaction it was made for.
// ---------------------------------------------------------------------------

/// A coordinator collects round one for one transaction and then tries to spend
/// the same input somewhere else with those messages. Both routes are closed.
///
/// This is not a forgery test in the "wrong points" sense -- every participant
/// is honest and every message is well formed. It is the question of whether a
/// gate that agrees to one release has thereby agreed to any release of that
/// input, which is the difference between a gate and a liveness switch.
#[test]
fn round_one_messages_cannot_be_carried_into_another_transaction() {
    let s = setup(2323, 2, 3, 2, 3);
    let (osub, gsub) = (owner_ids(&[0, 1]), gate_ids(&[0, 1]));
    let mut guard = MemoryNonceGuard::new();

    let approved_id = sid(0x1);
    let approved = s.params_over(&approved_id, b"release 5000 eUSD to the approved payee");
    let seats = quorum_signers(&s.spend, &osub, &gsub).unwrap();
    let (nonces, armed, mask_nonce, armed_mask) =
        commit_all(&approved, seats, s.mask(), &mut guard);

    // The coordinator abandons that session and opens another over a different
    // message, reusing the round-one messages verbatim. Nothing stops it: they
    // are values.
    let attacker_id = sid(0x2);
    let attacker = s.params_over(&attacker_id, b"release 5000 eUSD to the attacker");
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EA1);
    let session = Session::open(attacker, &mut rng).unwrap();
    session
        .preflight(&nonces)
        .expect("the same seats still own the output");
    let challenged = session.round_one(&nonces, &mask_nonce).unwrap();
    let transcript = challenged.round_one_transcript().clone();

    // ROUTE 1: hand the participants the attacker's session. Every one of them
    // refuses -- the binding is not the one it committed under. Asserted for a
    // spend seat and for the mask row, and for EVERY seat, so this is not one
    // lucky participant.
    for a in armed {
        let role = a.role();
        let err = expect_refused(a.respond(&attacker, &transcript));
        assert_eq!(err, SigningError::SessionMismatch, "{role}: got {err}");
    }
    let err = expect_refused(armed_mask.respond(&attacker, &transcript));
    assert_eq!(err, SigningError::SessionMismatch, "got {err}");

    // ROUTE 2: let the participants respond honestly against the session they
    // DID approve, and let the coordinator try to close the attacker's chain
    // with those responses. They derive `c` over the approved message; the
    // coordinator's chain ran over the attacker's. The responses do not open
    // the round-one commitments under the attacker's challenge, so no signature
    // comes out. Fresh seats, because the ones above are consumed.
    let approved2_id = sid(0x3);
    let approved2 = s.params_over(&approved2_id, b"release 5000 eUSD to the approved payee");
    let seats = quorum_signers(&s.spend, &osub, &gsub).unwrap();
    let (nonces2, armed2, mask_nonce2, armed_mask2) =
        commit_all(&approved2, seats, s.mask(), &mut guard);

    let attacker2_id = sid(0x4);
    let attacker2 = s.params_over(&attacker2_id, b"release 5000 eUSD to the attacker");
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EA2);
    let session = Session::open(attacker2, &mut rng).unwrap();
    let challenged = session.round_one(&nonces2, &mask_nonce2).unwrap();
    let transcript2 = challenged.round_one_transcript().clone();

    let responses2: Vec<SpendResponse> = armed2
        .into_iter()
        .map(|a| {
            a.respond(&approved2, &transcript2)
                .expect("honest response")
        })
        .collect();
    let mask2 = armed_mask2.respond(&approved2, &transcript2).unwrap();
    let err = expect_refused(challenged.finish(&responses2, &mask2));
    assert!(
        matches!(err, SigningError::ResponseDoesNotOpenNonce { .. }),
        "the attacker's chain must not be closeable by responses to another \
         session's challenge, got {err}"
    );

    // And the control: the same seats, responding to the session they approved,
    // under a coordinator that ran the chain over that same session, do produce
    // a signature the stock verifier accepts. So route 2's refusal is about the
    // substitution and not about a broken fixture.
    let control_id = sid(0x5);
    let control = s.params_over(&control_id, b"release 5000 eUSD to the approved payee");
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EA3);
    let session = Session::open(control, &mut rng).unwrap();
    let seats = quorum_signers(&s.spend, &osub, &gsub).unwrap();
    let (nonces3, armed3, mask_nonce3, armed_mask3) =
        commit_all(&control, seats, s.mask(), &mut guard);
    let challenged = session.round_one(&nonces3, &mask_nonce3).unwrap();
    let t3 = challenged.round_one_transcript().clone();
    let responses3: Vec<SpendResponse> = armed3
        .into_iter()
        .map(|a| a.respond(&control, &t3).unwrap())
        .collect();
    let sig = challenged
        .finish(&responses3, &armed_mask3.respond(&control, &t3).unwrap())
        .expect("the approved transaction signs");
    assert_eq!(
        sig.verify(
            b"release 5000 eUSD to the approved payee",
            &s.ring,
            &s.out_commitment
        ),
        Ok(())
    );
}

/// A participant will not respond to a transcript its own round-one message is
/// not in: the challenge derived from such a transcript is not one this nonce
/// is a summand of.
#[test]
fn a_participant_refuses_a_transcript_it_is_not_in() {
    let s = setup(2424, 2, 3, 2, 3);
    let (osub, gsub) = (owner_ids(&[0, 1]), gate_ids(&[0, 1]));
    let id = sid(0x2424);
    let params = s.params(&id);
    let mut guard = MemoryNonceGuard::new();
    let mut rng = ChaCha20Rng::seed_from_u64(0x2424);

    let session = Session::open(params, &mut rng).unwrap();
    let seats = quorum_signers(&s.spend, &osub, &gsub).unwrap();
    let (nonces, armed, mask_nonce, _) = commit_all(&params, seats, s.mask(), &mut guard);
    let challenged = session.round_one(&nonces, &mask_nonce).unwrap();

    // A transcript with the last gate seat dropped.
    let dropped = armed.last().unwrap().role();
    let mut trimmed = challenged.round_one_transcript().clone();
    trimmed.nonces.retain(|n| n.role != dropped);

    let victim = armed.into_iter().last().unwrap();
    assert_eq!(victim.role(), dropped);
    let err = expect_refused(victim.respond(&params, &trimmed));
    assert_eq!(
        err,
        SigningError::NotInTranscript {
            seat: Seat::Spend(dropped)
        },
        "got {err}"
    );
}

// ---------------------------------------------------------------------------
// 3. Every qualifying subset pair works and agrees on one key image.
// ---------------------------------------------------------------------------

#[test]
fn every_subset_pair_verifies_and_they_all_carry_one_key_image() {
    let s = setup(303, 2, 3, 2, 3);

    let osubs = subsets_of(s.spend.owners().roster(), 2);
    let gsubs = subsets_of(s.spend.gates().roster(), 2);
    assert_eq!((osubs.len(), gsubs.len()), (3, 3));

    // The canonical image, computed once in the TEST from the canonical `x`.
    let canonical = KeyImage::from(&RistrettoPrivate::from(s.canonical_x(&osubs[0], &gsubs[0])));

    // One guard for all nine attempts, so that a session id reused by accident
    // would be caught rather than silently reusing a nonce.
    let mut guard = MemoryNonceGuard::new();
    let mut pairs = 0u64;
    for osub in &osubs {
        for gsub in &gsubs {
            let mut rng = ChaCha20Rng::seed_from_u64(4000 + pairs);
            let id = sid(3000 + pairs);
            let seats = quorum_signers(&s.spend, osub, gsub).expect("qualifying subsets");
            let sig = sign(s.params(&id), seats, s.mask(), &mut guard, &mut rng)
                .unwrap_or_else(|e| panic!("owners {osub:?} gates {gsub:?}: {e}"));

            s.verify(&sig)
                .unwrap_or_else(|e| panic!("owners {osub:?} gates {gsub:?}: verify: {e}"));
            assert_eq!(
                sig.key_image, canonical,
                "owners {osub:?} gates {gsub:?} produced a different key image -- \
                 a subset-dependent image is a double spend created by the \
                 signing scheme"
            );
            pairs += 1;
        }
    }
    assert_eq!(pairs, 9, "the full owner x gate product");
}

/// The same, over asymmetric cohorts and the decided production shape, so the
/// claim does not depend on the two cohorts having equal geometry.
#[test]
fn subset_pairs_agree_across_asymmetric_cohorts_and_the_production_shape() {
    for (seed, k, n, g, m, expected) in [(404u64, 3, 4, 2, 3, 12u64), (505, 2, 3, 1, 1, 3)] {
        let s = setup(seed, k, n, g, m);
        let osubs = subsets_of(s.spend.owners().roster(), k);
        let gsubs = subsets_of(s.spend.gates().roster(), g);

        let canonical =
            KeyImage::from(&RistrettoPrivate::from(s.canonical_x(&osubs[0], &gsubs[0])));

        let mut guard = MemoryNonceGuard::new();
        let mut pairs = 0u64;
        for osub in &osubs {
            for gsub in &gsubs {
                let mut rng = ChaCha20Rng::seed_from_u64(seed * 1000 + pairs);
                let id = sid(seed * 1000 + pairs);
                let seats = quorum_signers(&s.spend, osub, gsub).unwrap();
                let sig = sign(s.params(&id), seats, s.mask(), &mut guard, &mut rng)
                    .unwrap_or_else(|e| panic!("{k}-of-{n} x {g}-of-{m}: {e}"));
                s.verify(&sig).expect("stock verify");
                assert_eq!(sig.key_image, canonical);
                pairs += 1;
            }
        }
        assert_eq!(pairs, expected);
    }
}

/// The decoy rows must be uniform and per-session. A constant, or a repeat
/// across sessions, makes the real row distinguishable from the decoys and the
/// ring stops hiding the input it is there to hide.
#[test]
fn decoy_responses_are_fresh_per_session_and_never_repeat() {
    let s = setup(3030, 2, 3, 2, 3);
    let (osub, gsub) = (owner_ids(&[0, 1]), gate_ids(&[0, 1]));
    let mut guard = MemoryNonceGuard::new();

    let sign_once = |tag: u64, rng_seed: u64, guard: &mut MemoryNonceGuard| {
        let id = sid(tag);
        let mut rng = ChaCha20Rng::seed_from_u64(rng_seed);
        let seats = quorum_signers(&s.spend, &osub, &gsub).unwrap();
        let sig = sign(s.params(&id), seats, s.mask(), guard, &mut rng).unwrap();
        s.verify(&sig).expect("stock verify");
        sig
    };
    let a = sign_once(0xD1, 0xD1, &mut guard);
    let b = sign_once(0xD2, 0xD2, &mut guard);

    let decoys = |sig: &RingMLSAG| -> Vec<Scalar> {
        sig.responses
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 2 * s.real_index && *i != 2 * s.real_index + 1)
            .map(|(_, r)| r.scalar)
            .collect()
    };
    let (da, db) = (decoys(&a), decoys(&b));
    assert_eq!(da.len(), 2 * (s.ring.len() - 1));

    // No decoy repeats another, within a signature or across the two.
    for (i, x) in da.iter().enumerate() {
        assert_ne!(*x, Scalar::ZERO, "decoy {i} was left unset");
        for y in &da[i + 1..] {
            assert_ne!(*x, *y, "two decoy responses in one signature are equal");
        }
        for y in &db {
            assert_ne!(*x, *y, "a decoy response repeated across two sessions");
        }
    }
    // ...and none of them is the real row's.
    let real = a.responses[2 * s.real_index].scalar;
    for x in &da {
        assert_ne!(*x, real);
    }
}

// ---------------------------------------------------------------------------
// 4. A missing gate participant cannot sign.
// ---------------------------------------------------------------------------

/// Three separate outcomes, each asserted exactly. "The signer errored" on its
/// own would prove nothing, so each arm names the variant it expects, and the
/// last arm forces a signature to exist and pins what the STOCK VERIFIER does
/// with it.
#[test]
fn a_missing_gate_cohort_cannot_produce_an_acceptable_signature() {
    let s = setup(606, 2, 3, 2, 3);
    let osub = owner_ids(&[0, 1]);
    let gsub = gate_ids(&[0, 1]);

    // (a) No gate participants at all: refused when the quorum is assembled.
    let err = quorum_signers(&s.spend, &osub, &[]).unwrap_err();
    let SigningError::Cohort(ref cohort_err) = err else {
        panic!("expected a cohort rejection, got {err}");
    };
    assert!(
        matches!(cohort_err, CohortError::InCohort { name, .. } if name == "gates"),
        "the GATE cohort must be the one that refuses, got {err}"
    );
    assert_eq!(
        *cohort_err.kind(),
        CohortError::BelowThreshold {
            have: 0,
            threshold: 2
        },
        "got {err}"
    );

    // (a') Sub-threshold gates: same refusal, different count.
    let err = quorum_signers(&s.spend, &osub, &gate_ids(&[0])).unwrap_err();
    let SigningError::Cohort(ref cohort_err) = err else {
        panic!("expected a cohort rejection, got {err}");
    };
    assert_eq!(
        *cohort_err.kind(),
        CohortError::BelowThreshold {
            have: 1,
            threshold: 2
        },
        "got {err}"
    );

    // (b) An owner-only quorum that reaches the coordinator: preflight names
    // it, and the difference it reports is exactly the missing cohort.
    let mut rng = ChaCha20Rng::seed_from_u64(0xDEAD);
    let mut guard = MemoryNonceGuard::new();
    let id = sid(606);
    let params = s.params(&id);
    let session = Session::open(params, &mut rng).unwrap();

    let owner_terms = s.spend.owners().weighted(&osub).unwrap();
    let mut seats = vec![SpendSigner::view(s.spend.common())];
    seats.extend(owner_terms.iter().map(SpendSigner::owner));
    let (nonces, armed, mask_nonce, armed_mask) = commit_all(&params, seats, s.mask(), &mut guard);

    let err = session.preflight(&nonces).unwrap_err();
    assert!(
        matches!(err, SigningError::QuorumDoesNotOwnOutput { .. }),
        "expected the quorum to be refused, got {err}"
    );
    let assembled: RistrettoPoint = nonces.iter().map(|n| n.share_public).sum();
    let target: RistrettoPoint = *s.spend.target().as_ref();
    assert_eq!(
        target - assembled,
        s.spend.gates().public(&gsub).unwrap(),
        "the shortfall must be exactly the gate cohort's public key"
    );

    // (c) Push past the diagnostic: the owner-only quorum runs both rounds and
    // a signature IS produced. Every participant in it is internally honest,
    // so nothing in the coordinator's response checks fires. The stock
    // verifier is what refuses -- with exactly InvalidSignature.
    let challenged = session.round_one(&nonces, &mask_nonce).unwrap();
    let transcript = challenged.round_one_transcript().clone();
    let responses: Vec<SpendResponse> = armed
        .into_iter()
        .map(|a| a.respond(&params, &transcript).unwrap())
        .collect();
    let sig = challenged
        .finish(
            &responses,
            &armed_mask.respond(&params, &transcript).unwrap(),
        )
        .expect("an owner-only quorum can still assemble a well-formed RingMLSAG");

    assert_eq!(sig.responses.len(), 2 * s.ring.len());
    assert_eq!(
        s.verify(&sig),
        Err(MlsagError::InvalidSignature),
        "an owner-only signature must be rejected as InvalidSignature, not \
         accepted and not rejected for some incidental reason"
    );

    // ...and the image it carries belongs to no output in the ring.
    let x = RistrettoPrivate::from(s.canonical_x(&osub, &gsub));
    assert_ne!(sig.key_image, KeyImage::from(&x));
    assert_eq!(
        sig.key_image.point,
        s.spend.key_image_without_gates(&osub).unwrap().compress(),
        "it is precisely the gate-less image"
    );
}

/// A gate seat that LIES on the `G` base: it publishes the gate cohort's real
/// public key `B_gate` (which is public), so `preflight` is satisfied, but it
/// does not hold the share behind it. The coordinator names it in round two
/// rather than emitting a signature nobody can attribute.
#[test]
fn a_forged_gate_contribution_is_named_in_round_two() {
    let s = setup(707, 2, 3, 2, 3);
    let (osub, gsub) = (owner_ids(&[0, 1]), gate_ids(&[0, 1]));
    let mut rng = ChaCha20Rng::seed_from_u64(0xBEEF);
    let mut guard = MemoryNonceGuard::new();
    let id = sid(707);
    let params = s.params(&id);
    let base = params.spend_base().unwrap();

    let session = Session::open(params, &mut rng).unwrap();
    let owner_terms = s.spend.owners().weighted(&osub).unwrap();
    let mut seats = vec![SpendSigner::view(s.spend.common())];
    seats.extend(owner_terms.iter().map(SpendSigner::owner));
    let (mut nonces, armed, mask_nonce, armed_mask) =
        commit_all(&params, seats, s.mask(), &mut guard);

    // The forger picks a scalar it actually knows, but claims the gate
    // cohort's public key so the sum comes out right.
    let forged_weight = Scalar::from(1234567u64);
    let forged_alpha = Scalar::from(7654321u64);
    let forged_role = SpendRole::Gate(gsub[0]);
    nonces.push(SpendNonce {
        role: forged_role,
        share_public: s.spend.gates().public(&gsub).unwrap(),
        image_term: forged_weight * base,
        nonce_public: forged_alpha * RISTRETTO_BASEPOINT_POINT,
        nonce_image: forged_alpha * base,
        binding_public: RistrettoPoint::default(),
        binding_image: RistrettoPoint::default(),
    });

    session
        .preflight(&nonces)
        .expect("the forgery is built to satisfy the diagnostic");

    let challenged = session.round_one(&nonces, &mask_nonce).unwrap();
    let transcript = challenged.round_one_transcript().clone();
    let c = *challenged.challenge();

    let mut responses: Vec<SpendResponse> = armed
        .into_iter()
        .map(|a| a.respond(&params, &transcript).unwrap())
        .collect();
    responses.push(SpendResponse {
        role: forged_role,
        response: forged_alpha - c.scalar() * forged_weight,
    });

    let err = expect_refused(challenged.finish(
        &responses,
        &armed_mask.respond(&params, &transcript).unwrap(),
    ));
    assert_eq!(
        err,
        SigningError::ResponseDoesNotOpenNonce { role: forged_role },
        "the forger must be named, got {err}"
    );
}

/// The forgery the `G` check cannot see: a gate seat whose `G` values are a
/// perfectly consistent opening and whose two `Hp(P)` values are both shifted
/// by the same delta.
///
/// `preflight` passes (its `W_i` is the honest weighted share), the
/// `r*G + c*W == alpha*G` check passes (its `G` triple opens exactly), and the
/// only thing standing between this and a well-formed `RingMLSAG` carrying a
/// key image that belongs to no output is `ResponseDoesNotOpenImageTerm`. The
/// image really does move -- asserted below, before the protocol refuses -- so
/// this check is not redundant with the `G` one, and the round-two forger in
/// `a_forged_gate_contribution_is_named_in_round_two` cannot reach it, because
/// that one's `W_i` is wrong and it dies on `G` first.
///
/// The fault is modelled as the SEAT lying, not the coordinator tampering: a
/// coordinator that edits a published `SpendNonce` is caught earlier and by
/// somebody else, in `a_participant_refuses_a_transcript_it_is_not_in`.
#[test]
fn a_shifted_key_image_term_is_named_in_round_two() {
    let s = setup(717, 2, 3, 2, 3);
    let (osub, gsub) = (owner_ids(&[0, 1]), gate_ids(&[0, 1]));
    let mut rng = ChaCha20Rng::seed_from_u64(0x1_A6E);
    let mut guard = MemoryNonceGuard::new();
    let id = sid(717);
    let params = s.params(&id);
    let base = params.spend_base().unwrap();

    let session = Session::open(params, &mut rng).unwrap();

    // Every seat but the second gate, honestly.
    let owner_terms = s.spend.owners().weighted(&osub).unwrap();
    let gate_terms = s.spend.gates().weighted(&gsub).unwrap();
    let mut seats = vec![SpendSigner::view(s.spend.common())];
    seats.extend(owner_terms.iter().map(SpendSigner::owner));
    seats.push(SpendSigner::gate(&gate_terms[0]));
    let (mut nonces, armed, mask_nonce, armed_mask) =
        commit_all(&params, seats, s.mask(), &mut guard);

    // The liar: the real weighted share on G, a nonce it knows, and both
    // Hp(P) values shifted by one delta.
    let liar_role = SpendRole::Gate(gsub[1]);
    let liar_weight = *gate_terms[1].weight();
    let liar_alpha = Scalar::from(31_337u64);
    let delta = Scalar::from(0xDE17Au64) * base;
    nonces.push(SpendNonce {
        role: liar_role,
        share_public: liar_weight * RISTRETTO_BASEPOINT_POINT,
        image_term: liar_weight * base + delta,
        nonce_public: liar_alpha * RISTRETTO_BASEPOINT_POINT,
        nonce_image: liar_alpha * base + delta,
        binding_public: RistrettoPoint::default(),
        binding_image: RistrettoPoint::default(),
    });

    session
        .preflight(&nonces)
        .expect("the G values are honest, so the quorum still owns the output");

    let challenged = session.round_one(&nonces, &mask_nonce).unwrap();
    // The damage is real: the image the chain was built over is not this
    // output's, and it is off by exactly the delta.
    let x = RistrettoPrivate::from(s.canonical_x(&osub, &gsub));
    let canonical = KeyImage::from(&x);
    assert_ne!(
        challenged.key_image(),
        canonical,
        "the shift must actually move the key image, or this test forges nothing"
    );
    assert_eq!(
        challenged.key_image().point,
        (canonical.point.decompress().unwrap() + delta).compress(),
        "and it moves by the delta, so nothing else is going on here"
    );

    let transcript = challenged.round_one_transcript().clone();
    let mut responses: Vec<SpendResponse> = armed
        .into_iter()
        .map(|a| a.respond(&params, &transcript).unwrap())
        .collect();
    // The liar's response opens its G commitment exactly.
    let c = *challenged.challenge().scalar();
    responses.push(SpendResponse {
        role: liar_role,
        response: liar_alpha - c * liar_weight,
    });

    let err = expect_refused(challenged.finish(
        &responses,
        &armed_mask.respond(&params, &transcript).unwrap(),
    ));
    assert_eq!(
        err,
        SigningError::ResponseDoesNotOpenImageTerm { role: liar_role },
        "the Hp(P) opening check must name the shifted seat, got {err}"
    );
}

// ---------------------------------------------------------------------------
// 5. A wrong-cohort subset is refused.
// ---------------------------------------------------------------------------

/// The two cohorts occupy disjoint `ControlDomain` id bands, so a subset drawn
/// from one is not a quorum of the other -- at runtime, through a `&[u64]`
/// that has lost its provenance. (The type-level half, where a `CohortSpec` of
/// the wrong domain does not compile, has `compile_fail` doctests on
/// `CohortSpec`.)
#[test]
fn a_wrong_cohort_subset_is_a_typed_error_and_not_a_signature() {
    let s = setup(808, 2, 3, 2, 3);
    let osub = owner_ids(&[0, 1]);
    let gsub = gate_ids(&[0, 1]);

    // Owner subset where the gate subset belongs.
    let err = quorum_signers(&s.spend, &osub, &osub).unwrap_err();
    let SigningError::Cohort(ref cohort_err) = err else {
        panic!("expected a cohort rejection, got {err}");
    };
    assert!(
        matches!(cohort_err, CohortError::InCohort { name, .. } if name == "gates"),
        "got {err}"
    );
    assert_eq!(
        *cohort_err.kind(),
        CohortError::UnknownParticipant(osub[0]),
        "got {err}"
    );

    // ...and the reverse.
    let err = quorum_signers(&s.spend, &gsub, &gsub).unwrap_err();
    let SigningError::Cohort(ref cohort_err) = err else {
        panic!("expected a cohort rejection, got {err}");
    };
    assert!(
        matches!(cohort_err, CohortError::InCohort { name, .. } if name == "owners"),
        "got {err}"
    );
    assert_eq!(
        *cohort_err.kind(),
        CohortError::UnknownParticipant(gsub[0]),
        "got {err}"
    );

    // Nothing partial escapes: the honest pairing still works, so the two
    // rejections above are about provenance and not about a broken fixture.
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let mut guard = MemoryNonceGuard::new();
    let id = sid(808);
    let seats = quorum_signers(&s.spend, &osub, &gsub).unwrap();
    let sig = sign(s.params(&id), seats, s.mask(), &mut guard, &mut rng).unwrap();
    s.verify(&sig).expect("stock verify");
}

// ---------------------------------------------------------------------------
// Protocol mechanics: the state machine has to refuse malformed rounds too.
// ---------------------------------------------------------------------------

#[test]
fn a_participant_that_goes_silent_in_round_two_stops_the_signature() {
    let s = setup(909, 2, 3, 2, 3);
    let (osub, gsub) = (owner_ids(&[0, 1]), gate_ids(&[0, 1]));
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let mut guard = MemoryNonceGuard::new();
    let id = sid(909);
    let params = s.params(&id);

    let session = Session::open(params, &mut rng).unwrap();
    let seats = quorum_signers(&s.spend, &osub, &gsub).unwrap();
    let (nonces, armed, mask_nonce, armed_mask) = commit_all(&params, seats, s.mask(), &mut guard);
    let challenged = session.round_one(&nonces, &mask_nonce).unwrap();
    let transcript = challenged.round_one_transcript().clone();

    let silent = SpendRole::Gate(gsub[1]);
    assert!(challenged.awaiting().contains(&silent));
    let responses: Vec<SpendResponse> = armed
        .into_iter()
        .filter(|a| a.role() != silent)
        .map(|a| a.respond(&params, &transcript).unwrap())
        .collect();

    let err = expect_refused(challenged.finish(
        &responses,
        &armed_mask.respond(&params, &transcript).unwrap(),
    ));
    assert_eq!(err, SigningError::MissingResponse { role: silent });
}

#[test]
fn a_response_from_a_seat_that_never_committed_is_refused() {
    let s = setup(1010, 2, 3, 2, 3);
    let (osub, gsub) = (owner_ids(&[0, 1]), gate_ids(&[0, 1]));
    let mut rng = ChaCha20Rng::seed_from_u64(13);
    let mut guard = MemoryNonceGuard::new();
    let id = sid(1010);
    let params = s.params(&id);

    let session = Session::open(params, &mut rng).unwrap();
    let seats = quorum_signers(&s.spend, &osub, &gsub).unwrap();
    let (nonces, armed, mask_nonce, armed_mask) = commit_all(&params, seats, s.mask(), &mut guard);
    let challenged = session.round_one(&nonces, &mask_nonce).unwrap();
    let transcript = challenged.round_one_transcript().clone();

    let intruder = SpendRole::Owner(Owners::nth(2));
    let mut responses: Vec<SpendResponse> = armed
        .into_iter()
        .map(|a| a.respond(&params, &transcript).unwrap())
        .collect();
    responses.push(SpendResponse {
        role: intruder,
        response: Scalar::from(5u64),
    });

    let err = expect_refused(challenged.finish(
        &responses,
        &armed_mask.respond(&params, &transcript).unwrap(),
    ));
    assert_eq!(err, SigningError::UnexpectedResponse { role: intruder });
}

#[test]
fn a_seat_cannot_contribute_twice_in_one_round() {
    let s = setup(1111, 2, 3, 2, 3);
    let (osub, gsub) = (owner_ids(&[0, 1]), gate_ids(&[0, 1]));
    let mut rng = ChaCha20Rng::seed_from_u64(17);
    let mut guard = MemoryNonceGuard::new();
    let id = sid(1111);
    let params = s.params(&id);

    let session = Session::open(params, &mut rng).unwrap();
    let seats = quorum_signers(&s.spend, &osub, &gsub).unwrap();
    let (mut nonces, _, mask_nonce, _) = commit_all(&params, seats, s.mask(), &mut guard);
    let doubled = nonces[1].clone();
    nonces.push(doubled.clone());

    let err = session.round_one(&nonces, &mask_nonce).unwrap_err();
    assert_eq!(
        err,
        SigningError::DuplicateContribution { role: doubled.role }
    );
}

/// The round-two twin of the test above. Two responses from one seat: the
/// coordinator must not pick one and proceed, because which one it picked
/// decides the signature and nothing records the choice.
#[test]
fn a_seat_cannot_respond_twice_in_one_round() {
    let s = setup(1122, 2, 3, 2, 3);
    let (osub, gsub) = (owner_ids(&[0, 1]), gate_ids(&[0, 1]));
    let mut rng = ChaCha20Rng::seed_from_u64(0x1122);
    let mut guard = MemoryNonceGuard::new();
    let id = sid(1122);
    let params = s.params(&id);

    let session = Session::open(params, &mut rng).unwrap();
    let seats = quorum_signers(&s.spend, &osub, &gsub).unwrap();
    let (nonces, armed, mask_nonce, armed_mask) = commit_all(&params, seats, s.mask(), &mut guard);
    let challenged = session.round_one(&nonces, &mask_nonce).unwrap();
    let transcript = challenged.round_one_transcript().clone();

    let mut responses: Vec<SpendResponse> = armed
        .into_iter()
        .map(|a| a.respond(&params, &transcript).unwrap())
        .collect();
    // The SAME response twice -- not a contradictory one, so nothing else in
    // `finish` could notice.
    let doubled = responses[2];
    responses.push(doubled);

    let err = expect_refused(challenged.finish(
        &responses,
        &armed_mask.respond(&params, &transcript).unwrap(),
    ));
    assert_eq!(
        err,
        SigningError::DuplicateResponse { role: doubled.role },
        "got {err}"
    );
}

/// `Session::preflight` takes a slice, and `Session::round_one` takes another.
/// Nothing ties them together, so preflighting a qualifying quorum and then
/// chaining a different one passes the diagnostic while the set that actually
/// built the chain does not own the output.
///
/// `ChallengedSession::preflight` is the check over the list that cannot be
/// swapped, and it catches exactly that.
#[test]
fn preflighting_one_quorum_and_chaining_another_is_caught_after_the_chain() {
    let s = setup(1616, 2, 3, 2, 3);
    let (osub, gsub) = (owner_ids(&[0, 1]), gate_ids(&[0, 1]));
    let id = sid(1616);
    let params = s.params(&id);
    let mut guard = MemoryNonceGuard::new();
    let mut rng = ChaCha20Rng::seed_from_u64(0x1616);

    let session = Session::open(params, &mut rng).unwrap();
    let seats = quorum_signers(&s.spend, &osub, &gsub).unwrap();
    let (nonces, _, mask_nonce, _) = commit_all(&params, seats, s.mask(), &mut guard);

    // The full quorum passes the pre-round-one diagnostic.
    session
        .preflight(&nonces)
        .expect("the full quorum owns the output");

    // ...and the coordinator then chains a list with the gates dropped.
    let gateless: Vec<SpendNonce> = nonces
        .iter()
        .filter(|n| !matches!(n.role, SpendRole::Gate(_)))
        .cloned()
        .collect();
    assert_eq!(gateless.len(), nonces.len() - 2);
    let challenged = session.round_one(&gateless, &mask_nonce).unwrap();

    let err = expect_refused(challenged.preflight());
    let SigningError::QuorumDoesNotOwnOutput { .. } = err else {
        panic!("expected the chained list to be refused, got {err}");
    };
    // ...and the shortfall it reports is the gate cohort, so it is naming the
    // right absence and not merely erroring.
    let assembled: RistrettoPoint = gateless.iter().map(|n| n.share_public).sum();
    let target: RistrettoPoint = *s.spend.target().as_ref();
    assert_eq!(target - assembled, s.spend.gates().public(&gsub).unwrap());

    // The honest path passes both checks, so the refusal above is about the
    // substitution and not about `ChallengedSession::preflight` being broken.
    let honest_id = sid(1617);
    let honest = s.params(&honest_id);
    let mut rng = ChaCha20Rng::seed_from_u64(0x1617);
    let session = Session::open(honest, &mut rng).unwrap();
    let seats = quorum_signers(&s.spend, &osub, &gsub).unwrap();
    let (nonces, _, mask_nonce, _) = commit_all(&honest, seats, s.mask(), &mut guard);
    session.preflight(&nonces).unwrap();
    session
        .round_one(&nonces, &mask_nonce)
        .unwrap()
        .preflight()
        .expect("the honest quorum passes the post-chain check too");
}

/// Upstream's `check_value_is_preserved`, reproduced without the coordinator
/// knowing `z`. A mask row for the wrong amount must not reach the verifier.
#[test]
fn an_unbalanced_mask_row_is_refused_before_the_signature_is_assembled() {
    let s = setup(1212, 2, 3, 2, 3);
    let (osub, gsub) = (owner_ids(&[0, 1]), gate_ids(&[0, 1]));
    let mut rng = ChaCha20Rng::seed_from_u64(19);
    let mut guard = MemoryNonceGuard::new();

    let seats = quorum_signers(&s.spend, &osub, &gsub).unwrap();
    // Blinding that does not match the ring's real commitment.
    let wrong = MaskSigner::owner_held(&s.out_blinding, &Scalar::from(12345u64));
    let id = sid(1212);
    let err = expect_refused(sign(s.params(&id), seats, wrong, &mut guard, &mut rng));
    assert!(
        matches!(err, SigningError::ValueNotConserved { .. }),
        "got {err}"
    );

    // The honest mask row over the same quorum still signs -- under a fresh
    // session id, because the seats already spent their nonces on the failed
    // attempt.
    let seats = quorum_signers(&s.spend, &osub, &gsub).unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(19);
    let retry = sid(1213);
    let sig = sign(s.params(&retry), seats, s.mask(), &mut guard, &mut rng).unwrap();
    s.verify(&sig).expect("stock verify");
}

#[test]
fn a_real_index_outside_the_ring_is_refused_before_any_round() {
    let s = setup(1313, 2, 3, 2, 3);
    let mut rng = ChaCha20Rng::seed_from_u64(23);
    let id = sid(1313);
    let params = SessionParams {
        session_id: &id,
        message: MESSAGE,
        ring: &s.ring,
        real_index: s.ring.len(),
        output_commitment: &s.out_commitment,
    };
    let err = Session::open(params, &mut rng).unwrap_err();
    assert_eq!(
        err,
        SigningError::RealIndexOutOfBounds {
            index: s.ring.len(),
            ring_size: s.ring.len()
        }
    );
    // A participant handed the same session refuses it too, and refuses it
    // BEFORE spending its one nonce for that binding.
    let mut guard = MemoryNonceGuard::new();
    let seat = SpendSigner::view(s.spend.common());
    let err = expect_refused(seat.commit(&params, &mut guard));
    assert_eq!(
        err,
        SigningError::RealIndexOutOfBounds {
            index: s.ring.len(),
            ring_size: s.ring.len()
        }
    );
    assert!(guard.is_empty(), "a refused session must not burn a slot");
}

/// The remaining shapes of malformed session, each named rather than panicking
/// somewhere downstream.
#[test]
fn malformed_sessions_are_refused_with_the_variant_that_describes_them() {
    let s = setup(1414, 2, 3, 2, 3);
    let mut rng = ChaCha20Rng::seed_from_u64(29);
    let id = sid(1414);

    // Empty ring.
    let empty: Vec<ReducedTxOut> = Vec::new();
    let params = SessionParams {
        session_id: &id,
        message: MESSAGE,
        ring: &empty,
        real_index: 0,
        output_commitment: &s.out_commitment,
    };
    assert_eq!(
        Session::open(params, &mut rng).unwrap_err(),
        SigningError::EmptyRing
    );
    assert_eq!(params.spend_base().unwrap_err(), SigningError::EmptyRing);

    // A ring member whose commitment does not decompress. Put it at a DECOY
    // index, so the failure is about the ring and not about the real input.
    let bad_point = CompressedRistretto([0xFFu8; 32]);
    let mut broken_ring = s.ring.clone();
    let broken_index = if s.real_index == 0 { 1 } else { 0 };
    broken_ring[broken_index].commitment = CompressedCommitment { point: bad_point };
    let params = SessionParams {
        session_id: &id,
        message: MESSAGE,
        ring: &broken_ring,
        real_index: s.real_index,
        output_commitment: &s.out_commitment,
    };
    assert_eq!(
        Session::open(params, &mut rng).unwrap_err(),
        SigningError::RingMemberInvalid {
            index: broken_index
        }
    );

    // An output commitment that does not decompress.
    let bad_out = CompressedCommitment { point: bad_point };
    let params = SessionParams {
        session_id: &id,
        message: MESSAGE,
        ring: &s.ring,
        real_index: s.real_index,
        output_commitment: &bad_out,
    };
    assert_eq!(
        Session::open(params, &mut rng).unwrap_err(),
        SigningError::OutputCommitmentInvalid
    );

    // Round one with nobody in it, on both the diagnostic and the chain.
    let good = s.params(&id);
    let session = Session::open(good, &mut rng).unwrap();
    assert_eq!(
        session.preflight(&[]).unwrap_err(),
        SigningError::NoContributions
    );
    let mask_nonce = MaskNonce {
        nonce_public: RISTRETTO_BASEPOINT_POINT,
        binding_public: RistrettoPoint::default(),
    };
    assert_eq!(
        session.round_one(&[], &mask_nonce).unwrap_err(),
        SigningError::NoContributions
    );
}

/// `RoundOne` is wire data, so a coordinator can hand a participant one that
/// does not describe the ring at all. Named, not indexed out of bounds.
#[test]
fn a_transcript_that_does_not_describe_the_ring_is_refused() {
    let s = setup(1515, 2, 3, 2, 3);
    let (osub, gsub) = (owner_ids(&[0, 1]), gate_ids(&[0, 1]));
    let id = sid(1515);
    let params = s.params(&id);
    let mut guard = MemoryNonceGuard::new();

    let seats = quorum_signers(&s.spend, &osub, &gsub).unwrap();
    let (nonces, armed, mask_nonce, _) = commit_all(&params, seats, s.mask(), &mut guard);

    let short = RoundOne {
        nonces,
        mask: mask_nonce,
        responses: vec![Scalar::ONE; 4],
    };
    let victim = armed.into_iter().next().unwrap();
    let err = expect_refused(victim.respond(&params, &short));
    assert_eq!(
        err,
        SigningError::TranscriptSizeMismatch {
            expected: 2 * s.ring.len(),
            found: 4
        },
        "got {err}"
    );
}

#[test]
fn both_nonce_commitments_are_required_in_the_participants_transcript() {
    let s = setup(7001, 2, 3, 1, 1);
    let id = sid(701);
    let params = s.params(&id);
    let osub = owner_ids(&[0, 1]);
    let gsub = gate_ids(&[0]);
    for image in [false, true] {
        let seats = quorum_signers(&s.spend, &osub, &gsub).unwrap();
        let (mut nonces, armed, mask, _) =
            commit_all(&params, seats, s.mask(), &mut MemoryNonceGuard::new());
        assert_ne!(nonces[0].nonce_public, nonces[0].binding_public);
        if image {
            nonces[0].binding_image += RISTRETTO_BASEPOINT_POINT;
        } else {
            nonces[0].binding_public += RISTRETTO_BASEPOINT_POINT;
        }
        let mut rng = ChaCha20Rng::seed_from_u64(52);
        let session = Session::open(params, &mut rng)
            .unwrap()
            .round_one(&nonces, &mask)
            .unwrap();
        let err = armed
            .into_iter()
            .next()
            .unwrap()
            .respond(&params, session.round_one_transcript())
            .unwrap_err();
        assert_eq!(
            err,
            SigningError::NotInTranscript {
                seat: Seat::Spend(SpendRole::View)
            }
        );
    }
}

#[test]
fn binding_factor_covers_all_commitments_roles_session_and_decoys() {
    let s = setup(7701, 2, 3, 1, 1);
    let id = sid(7701);
    let params = s.params(&id);
    let seats = quorum_signers(&s.spend, &owner_ids(&[0, 1]), &gate_ids(&[0])).unwrap();
    let (nonces, _, mask, _) = commit_all(&params, seats, s.mask(), &mut MemoryNonceGuard::new());
    let mut rng = ChaCha20Rng::seed_from_u64(77);
    let session = Session::open(params, &mut rng)
        .unwrap()
        .round_one(&nonces, &mask)
        .unwrap();
    let t = session.round_one_transcript();
    let seat = Seat::Spend(SpendRole::View);
    let rho = t.binding_factor(&params, seat);
    assert_ne!(rho, Scalar::ZERO);
    assert_ne!(rho, Scalar::ONE);
    for field in 0..9 {
        let mut altered = t.clone();
        let n = &mut altered.nonces[1];
        match field {
            0 => n.share_public += RISTRETTO_BASEPOINT_POINT,
            1 => n.image_term += RISTRETTO_BASEPOINT_POINT,
            2 => n.nonce_public += RISTRETTO_BASEPOINT_POINT,
            3 => n.nonce_image += RISTRETTO_BASEPOINT_POINT,
            4 => n.binding_public += RISTRETTO_BASEPOINT_POINT,
            5 => n.binding_image += RISTRETTO_BASEPOINT_POINT,
            6 => altered.mask.nonce_public += RISTRETTO_BASEPOINT_POINT,
            7 => altered.mask.binding_public += RISTRETTO_BASEPOINT_POINT,
            _ => altered.responses[0] += Scalar::ONE,
        }
        assert_ne!(rho, altered.binding_factor(&params, seat), "field {field}");
    }
    assert_ne!(rho, t.binding_factor(&params, Seat::Mask));
    assert_ne!(rho, t.binding_factor(&s.params(&sid(7702)), seat));
    let mut reordered = t.clone();
    reordered.nonces.reverse();
    assert_eq!(
        rho,
        reordered.binding_factor(&params, seat),
        "canonical seat ordering"
    );
    // Load-bearing effective nonce is nonlinear in the peer commitment set.
    let mut peer = t.clone();
    peer.nonces[1].binding_public += RISTRETTO_BASEPOINT_POINT;
    let mine = &t.nonces[0];
    assert_ne!(
        mine.nonce_public + rho * mine.binding_public,
        mine.nonce_public + peer.binding_factor(&params, seat) * mine.binding_public
    );
}
