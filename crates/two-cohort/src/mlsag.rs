//! Version 2 uses effective nonces `alpha_i + rho_i*beta_i`, where the
//! independently derived beta nonce and every participant commitment enter
//! the transcript-bound rho. In the algebra below, aggregate `alpha_0` means
//! the sum of these effective nonces. `SpendNonce` carries both commitments
//! on both bases; packet authentication is available in [`wire`].
//!
//! Two-round distributed MLSAG signing over a composite spend root.
//!
//! This is the module that closes the gap the rest of the crate leaves open.
//! Everywhere else the composite spend key is algebra:
//! [`CompositeSpend::onetime`](crate::CompositeSpend::onetime) materialises the
//! one-time scalar `x` in one process so the stock MobileCoin signer can be
//! driven, and its own doc comment says a production signer must not call it.
//! Here the signature is produced without any process ever forming `x`.
//!
//! # What the upstream signer does, and where `x` enters it
//!
//! `mlsag_sign.rs` closes the real row of the ring with
//!
//! ```text
//!     responses[2*real_index] = alpha_0 - c_real * s        where s = x
//! ```
//!
//! and `x = common + b_owner + b_gate`. `b_owner` and `b_gate` are Shamir
//! secrets, each recoverable only from a qualifying subset of its own cohort;
//! `common = Hs(a*R) + Hs(a||i)` is view-derived and belongs to neither cohort.
//! A qualifying subset holds Lagrange-weighted shares `w_i` with
//! `sum(w_i) = b_owner` over the owner subset, and likewise for the gates. So
//! with `common` carried by one more participant (the view service), and
//! writing the whole signing set as `S = {view} u owners u gates`,
//!
//! ```text
//!     sum_{i in S} w_i     = common + b_owner + b_gate = x
//!     alpha_0              = sum_{i in S} alpha_i
//!     responses[2*real]    = alpha_0 - c_real * x
//!                          = sum_{i in S} (alpha_i - c_real * w_i)
//! ```
//!
//! Each summand is one participant's own arithmetic on its own two secrets.
//! Nobody needs `x`, and no participant needs any other participant's share.
//!
//! # Why two rounds
//!
//! The MLSAG challenge chain needs `alpha_0*G` and `alpha_0*Hp(P)` *before*
//! `c_real` exists, because `c_real` is the hash that closes the loop around
//! the ring back to the real index. So the nonce commitments must be published
//! first and the responses second:
//!
//! ```text
//!   ROUND 1  every participant publishes  w_i*G, w_i*Hp(P), alpha_i*G,
//!            alpha_i*Hp(P)                              -> SpendNonce
//!            the coordinator sums them into the row-0 commitments, assembles
//!            the key image out of the w_i*Hp(P) terms, and runs the challenge
//!            chain around the ring                      -> ChallengedSession
//!            and PUBLISHES the whole round-one transcript -> RoundOne
//!
//!   ROUND 2  every participant RE-RUNS the same chain over that transcript to
//!            derive c_real for itself, then publishes
//!            r_i = alpha_i - c_real*w_i                 -> SpendResponse
//!            the coordinator sums and writes the result into
//!            responses[2*real_index]                    -> RingMLSAG
//! ```
//!
//! The key image is never computed from a scalar: it is
//! `sum_i w_i*Hp(P)`, the same per-participant group terms
//! [`CompositeSpend::key_image_terms`](crate::CompositeSpend::key_image_terms)
//! already exposed, published by their owners in round one.
//!
//! # What a participant is agreeing to
//!
//! A participant is never handed a challenge. It is handed a
//! [`SessionParams`] -- session id, message, ring, real index, output
//! commitment -- at commit time, and the round-one transcript at respond time,
//! and it derives everything else itself:
//!
//!   * `Hp(P)`, the base its share and nonce are carried onto, comes from
//!     `ring[real_index].target_key`. The coordinator does not get to name the
//!     output being spent.
//!   * `c_real` comes from [`ArmedSpendSigner::respond`] re-running
//!     `chain_around` over the transcript. The same code the coordinator ran,
//!     over the participant's own copy of the session.
//!   * The two are tied together by [`SessionBinding`], a hash over every field
//!     of [`SessionParams`]. `respond` refuses a session whose binding differs
//!     from the one `commit` was called under.
//!
//! Consequence: a coordinator that collects round one for one transaction and
//! then reuses those messages under a different message, ring, or output
//! commitment gets [`SigningError::SessionMismatch`], not a signature. Round
//! one is bound to the transaction from the moment it is published.
//!
//! What a participant still does NOT get is a *decoded* transaction: it sees
//! the MLSAG message as opaque bytes, not amounts and recipients. Turning those
//! bytes into a policy decision needs MobileCoin's `TxSummary` /
//! `TxSummaryUnblindingData` and the streaming verifier in
//! `transaction/summary/src/verifier.rs`, so that a gate can recompute the
//! signing digest from a summary it has read. That is real remaining work and
//! it is listed under "Limits" below. This module supplies the half that has to
//! come first: the participant holds the exact bytes the signature will be
//! over, and can refuse.
//!
//! # Nonces
//!
//! Every nonce is derived, not sampled:
//!
//! ```text
//!     alpha_i = H(NONCE_DOMAIN | binding | seat | w_i)
//! ```
//!
//! No participant RNG is required: two domain-separated hashes derive the
//! hiding and binding nonces from the secret, session and seat. Replaying a
//! coordinator RNG cannot repeat a participant's nonces across different
//! bindings. Both nonces must nevertheless be treated as one-time secrets.
//!
//! [`NonceGuard`] reserves `(binding, seat)` before either nonce commitment
//! is returned and refuses a second reservation. A retry uses a fresh session
//! ID and an independently authorized intent. DurableNonceGuard in the ceremony
//! crate supplies an fsynced journal and requires a separate rollback anchor.
//! Transcript binding is an additional defence, not permission to reuse the
//! two nonces. Secret-keyed derivation also needs independent cryptographic
//! review in this custom MLSAG composition.
//!
//! # What the coordinator can and cannot check
//!
//! Because every participant publishes `W_i = w_i*G` alongside its nonce, the
//! coordinator can check everything that decides whether the finished signature
//! will verify, using public data only:
//!
//!   * [`Session::preflight`] -- `sum_i W_i == P`, the output's target key. A
//!     quorum missing a cohort does not satisfy this. (`sum_i K_i == I` needs
//!     no check: the coordinator DEFINES `I` that way.)
//!   * [`ChallengedSession::finish`], row 0 -- for each participant,
//!     `r_i*G + c*W_i == alpha_i*G` and `r_i*Hp + c*K_i == alpha_i*Hp`. A
//!     participant that lies in round two, or goes silent, is named rather
//!     than silently folded into a signature that consensus will reject.
//!   * [`ChallengedSession::finish`], row 1 -- `z*G`, recovered from public
//!     data as `(alpha_1*G - r_1*G)/c`, equals `output - input`. This is
//!     upstream's `check_value_is_preserved` done without knowing `z`.
//!
//! Those are jointly SUFFICIENT. Substituting them into the verifier's
//! recomputation at the real index gives `L0' = L0 - c*(sum_i W_i - P)`,
//! `R0' = R0 - c*(sum_i K_i - I)` and `L1' = L1 + c*((output - input) - z*G)`,
//! and each correction term is zero whenever the corresponding check passes --
//! so the challenge the verifier recomputes at the real index is the one the
//! chain was built from, and the loop closes.
//!
//! They are not NECESSARY, and the docs used to overstate this by saying each
//! correction vanishes "exactly when" its check passes. Only the aggregate has
//! to be zero: two seats whose openings are wrong by `+delta` and `-delta`
//! both fail their per-seat check while `sum_i W_i` is untouched, and the
//! signature those two could have produced would have verified. The per-seat
//! form is deliberately the stronger one, because a check on the aggregate can
//! only say that somebody is wrong.
//!
//! `preflight` is deliberately a separate call rather than part of
//! [`Session::round_one`], because it is a diagnostic, not the security
//! boundary. The security boundary is that a signature assembled without the
//! gate cohort is rejected by the stock verifier, and `tests/mlsag_protocol.rs`
//! drives the protocol past `preflight` to show exactly that.
//!
//! Because it is separate, [`Session::preflight`] says nothing about the list
//! [`Session::round_one`] is later handed: preflighting one set of nonces and
//! chaining another passes the first check while `sum_i W_i != P` for the set
//! that actually built the chain. [`ChallengedSession::preflight`] is the same
//! check over the list the chain really used, and is the one to call if only
//! one of them is called.
//!
//! What the coordinator cannot check is that a participant's `W_i` is the
//! weighted share it was actually dealt. It does not have to for VALIDITY: a
//! participant that publishes a `W_i` it cannot open moves `sum_i W_i` away
//! from `P`, and `preflight` fails; one that publishes an inconsistent `r_i` is
//! caught by `finish`. Neither can produce a signature that verifies. It does
//! matter for ATTRIBUTION: `ResponseDoesNotOpenNonce { role }` names the seat
//! whose published values are inconsistent, which is the seat that holds the
//! wrong share only if seats hold what they were dealt. The DKG now provides
//! verification shares, and `CohortShare::term` derives a holder's weighted
//! term from them. This coordinator does not receive an authenticated DKG
//! registry or compare each advertised `W_i` with its roster's expected term.
//!
//! # Limits
//!
//! * **Row 1 is not split.** MLSAG row 1 is the commitment/mask row, whose
//!   secret is `z = output_blinding - blinding`. It belongs to the OWNER
//!   cohort alone ([`MaskSigner`]), exactly as before. This is a known,
//!   documented limitation and not a bypass: the two MLSAG rows are mandatory
//!   conjuncts -- the verifier recomputes `L0`, `R0` *and* `L1` into one
//!   challenge -- so row 1 cannot compensate for a missing gate term in row 0.
//! * **Key generation is supplied by the caller.** Production holders can use
//!   [`CohortShare::term`](crate::CohortShare::term) after DKG and composition;
//!   [`quorum_signers`] instead takes the trusted-dealer simulation, which
//!   generates both component secrets in one process. The coordinator's
//!   signature checks do not establish which of those paths supplied a seat.
//! * **No policy over a decoded transaction.** See above: participants hold the
//!   message bytes, not amounts and recipients.
//! * **Concurrency hardening, not a composition proof.** Each seat now uses
//!   two independently domain-separated secret-keyed nonces, with a FROST-style
//!   binding factor over the complete session and canonical round-one set.
//!   Both G and Hp(P) commitments use the same factor. This closes the known
//!   linear aggregate-nonce shape; it does not establish a formal concurrent
//!   security theorem for this custom two-cohort MLSAG construction. Independent
//!   cryptographic review and durable per-seat nonce guards remain required.
//! * **No deployed transport or automatic blame service.** Raw round messages
//!   remain low-level values. [`wire`] adds bounded identity-signed packets for
//!   callers that supply an authenticated roster and expected round context. A coordinator cannot forge a *valid*
//!   signature -- the checks above are jointly sufficient -- but anyone on the
//!   wire can kill a session unattributably, and the errors below are a label
//!   for an honest coordinator's retry logic, not evidence against a
//!   participant. `crates/ceremony/src/identity.rs` states the principle this
//!   wire module follows: abort evidence is a signature, never a transcript.
//!   Operating the network service and retaining evidence remain deployment work.
//! * **Best-effort zeroization**, for the reason given at the crate root.

use core::fmt;
use std::collections::BTreeSet;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use mc_crypto_hashes::{Blake2b256, Blake2b512, Digest};
use mc_crypto_keys::RistrettoPublic;
use mc_crypto_ring_signature::{
    Commitment, CompressedCommitment, CurveScalar, KeyImage, ReducedTxOut, RingMLSAG,
};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error as ThisError;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    cohort::{random_scalar, ParticipantTerm},
    composite::CompositeSpend,
    derive::hash_to_point,
    error::Error as CohortError,
};

/// `mc-crypto-ring-signature::domain_separators::RING_MLSAG_CHALLENGE_DOMAIN_TAG`.
///
/// Restated for the same reason as everything in [`derive`](crate::derive):
/// upstream's `challenge` and its domain separator are `pub(crate)`, so a
/// coordinator outside that crate cannot call them. The restatement is pinned
/// by every test that hands the result to the unmodified `RingMLSAG::verify` --
/// one wrong byte here and the recomputed challenge chain does not close.
pub const RING_MLSAG_CHALLENGE_DOMAIN_TAG: &str = "mc_ring_mlsag_challenge";

/// Domain separator for [`SessionBinding`]. Local to this crate: nothing
/// upstream hashes a session description, because upstream has no session.
const SESSION_BINDING_DOMAIN: &[u8] = b"bridge/two-cohort/mlsag/session/v2";

/// Domain separator for deterministic nonce derivation.
const NONCE_DOMAIN: &[u8] = b"bridge/two-cohort/mlsag/nonce/v2";

/// `Hn( m | key_image | L0 | R0 | L1 )`, byte for byte as
/// `mlsag_sign.rs`/`mlsag_verify.rs` compute it.
fn challenge(
    message: &[u8],
    key_image: &KeyImage,
    l0: &RistrettoPoint,
    r0: &RistrettoPoint,
    l1: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Blake2b512::new();
    hasher.update(RING_MLSAG_CHALLENGE_DOMAIN_TAG);
    hasher.update(message);
    hasher.update(key_image);
    hasher.update(l0.compress().as_bytes());
    hasher.update(r0.compress().as_bytes());
    hasher.update(l1.compress().as_bytes());
    Scalar::from_hash(hasher)
}

fn hex32(point: &RistrettoPoint) -> String {
    point
        .compress()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Which seat at the table a round message came from.
///
/// Carried on every round message so the coordinator can pair round two with
/// round one and name a participant that misbehaves. It is an identity, not a
/// capability: knowing a role tells you nothing about the share behind it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SpendRole {
    /// The view-derived term `common = Hs(a*R) + Hs(a||i)`.
    ///
    /// Not a cohort secret. Whoever runs the view service holds it, it is the
    /// same for every qualifying subset, and it authorises nothing on its own
    /// -- `common*G` is not the output's target key. It is a participant here
    /// only so that the coordinator holds no secret at all.
    View,
    /// An owner-cohort participant, by its [`Owners`](crate::Owners) id.
    Owner(u64),
    /// A gate-cohort participant, by its [`Gates`](crate::Gates) id.
    Gate(u64),
}

impl fmt::Display for SpendRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpendRole::View => write!(f, "view"),
            SpendRole::Owner(id) => write!(f, "owner {id}"),
            SpendRole::Gate(id) => write!(f, "gate {id}"),
        }
    }
}

/// Every holder of a one-time nonce in one session: the spend-row seats, plus
/// the owner-held mask row.
///
/// Distinct from [`SpendRole`] because the mask row is not a spend-row
/// participant -- it publishes no share, no key-image term, and no role on the
/// wire -- but it draws a nonce and therefore needs the same one-time
/// treatment. Its nonce reuse gives up `z`, which is amount bookkeeping rather
/// than spend authority, but it is still a secret that a repeated nonce hands
/// over for free.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Seat {
    Spend(SpendRole),
    Mask,
}

impl Seat {
    /// A fixed-width tag, so that no two distinct seats can hash alike by
    /// shifting a field boundary.
    fn tag(&self) -> [u8; 9] {
        let (kind, id) = match self {
            Seat::Spend(SpendRole::View) => (0u8, 0u64),
            Seat::Spend(SpendRole::Owner(id)) => (1u8, *id),
            Seat::Spend(SpendRole::Gate(id)) => (2u8, *id),
            Seat::Mask => (3u8, 0u64),
        };
        let mut out = [0u8; 9];
        out[0] = kind;
        out[1..].copy_from_slice(&id.to_le_bytes());
        out
    }
}

impl fmt::Display for Seat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Seat::Spend(role) => write!(f, "{role}"),
            Seat::Mask => write!(f, "mask row"),
        }
    }
}

/// Everything that can go wrong driving the protocol.
///
/// Typed rather than `bool` or panic because each of these names a different
/// operational fault -- a misconfigured quorum, a participant that dropped out,
/// a participant that lied -- and a coordinator has to react differently to
/// each.
#[derive(Clone, Debug, PartialEq, Eq, ThisError)]
#[non_exhaustive]
pub enum SigningError {
    /// A cohort refused the subset it was handed: below threshold, unknown id,
    /// or an id from the other cohort's band.
    #[error("cohort refused the signing subset: {0}")]
    Cohort(#[from] CohortError),

    /// A ring with no members has no real input.
    #[error("the ring is empty")]
    EmptyRing,

    /// The real input has to be inside the ring it hides in.
    #[error("real index {index} is outside a ring of {ring_size}")]
    RealIndexOutOfBounds { index: usize, ring_size: usize },

    /// Ring member `index` does not decompress. The verifier will reject it
    /// too, so failing here saves two rounds of signing.
    #[error("ring member {index} is not a valid Ristretto point / commitment")]
    RingMemberInvalid { index: usize },

    /// The output commitment does not decompress.
    #[error("the output commitment is not a valid Ristretto point")]
    OutputCommitmentInvalid,

    /// This seat already drew a nonce for this session binding. Answering a
    /// second challenge with the same nonce publishes the share:
    /// `(r - r')/(c' - c) = w_i`. Retry under a fresh session id instead.
    #[error("{seat} has already issued a nonce for this session")]
    NonceAlreadyIssued { seat: Seat },

    /// [`ArmedSpendSigner::respond`] was called with a session that is not the
    /// one [`SpendSigner::commit`] was called under -- a different message,
    /// ring, real index, output commitment, or session id.
    ///
    /// This is the check that stops round-one messages from being carried into
    /// a transaction the participant never saw.
    #[error("this armed signer belongs to a different session")]
    SessionMismatch,

    /// The published round-one transcript does not contain this seat's own
    /// commitment, so the challenge derived from it is not a challenge this
    /// seat's nonce is part of.
    #[error("{seat}'s round-one commitment is not in the published transcript")]
    NotInTranscript { seat: Seat },

    /// The transcript's decoy-response vector is not `2 * ring_size` long, so
    /// it does not describe this ring.
    #[error("the transcript carries {found} responses, but this ring needs {expected}")]
    TranscriptSizeMismatch { expected: usize, found: usize },

    /// Round one with nobody in it. The row-0 nonce would be the identity and
    /// the "signature" would be a public transcript of nothing.
    #[error("round one received no contributions")]
    NoContributions,

    /// Two round-one messages from one seat. Summing both would double-count
    /// that participant's weight, which no subsequent check would catch --
    /// `preflight` would simply fail, having lost the reason why.
    #[error("{role} published two round-one commitments")]
    DuplicateContribution { role: SpendRole },

    /// The quorum's public shares do not sum to the output's target key, so
    /// this set of participants cannot spend this output. In practice: a
    /// cohort is missing, or somebody is on the wrong subset.
    ///
    /// Both values are reported because the difference is the diagnosis --
    /// it is the missing cohort's public key.
    #[error(
        "this quorum does not own the output: sum of published shares is {assembled}, \
         but the output's target key is {target}"
    )]
    QuorumDoesNotOwnOutput { assembled: String, target: String },

    /// A participant that committed in round one did not respond in round two.
    #[error("{role} committed in round one but sent no round-two response")]
    MissingResponse { role: SpendRole },

    /// Two round-two messages from one seat.
    #[error("{role} sent two round-two responses")]
    DuplicateResponse { role: SpendRole },

    /// A round-two message from a seat that never committed. Adding it would
    /// put a term in the response sum that no term in the nonce sum cancels.
    #[error("{role} sent a round-two response without a round-one commitment")]
    UnexpectedResponse { role: SpendRole },

    /// `r_i*G + c*W_i != alpha_i*G`: the response does not open the round-one
    /// nonce commitment against the published share. Whoever sent it is either
    /// broken or lying.
    #[error("{role}'s response does not open its round-one commitment on G")]
    ResponseDoesNotOpenNonce { role: SpendRole },

    /// `r_i*Hp(P) + c*K_i != alpha_i*Hp(P)`: the same check on the key-image
    /// base. Separate from the `G` check because passing one and failing the
    /// other means the published key-image term does not match the published
    /// share, which is a different fault -- and the one that decides the key
    /// image, the consensus-visible artefact.
    #[error("{role}'s response does not open its round-one commitment on Hp(P)")]
    ResponseDoesNotOpenImageTerm { role: SpendRole },

    /// The mask row's response does not open its nonce, or the input and
    /// output amounts differ. Upstream's `check_value_is_preserved`, done from
    /// public data: `z*G` is recovered as `(alpha_1*G - r_1*G) / c` and
    /// compared against `output_commitment - input_commitment`.
    #[error(
        "value is not conserved: the mask row opens to {recovered}, but \
         output - input commits to {expected}"
    )]
    ValueNotConserved { recovered: String, expected: String },

    /// `c_real` came out zero, so the mask row cannot be opened by division.
    /// A Blake2b output landing exactly on zero is negligible; refusing beats
    /// dividing by it.
    ///
    /// A deliberate DEVIATION from upstream, which has no such test and would
    /// close the signature: upstream knows `z` and never has to divide by `c`.
    /// It costs nothing -- a signature this refuses is one no honest run will
    /// ever produce.
    #[error("the real challenge is zero")]
    DegenerateChallenge,

    /// The challenge chain did not produce both `c_real` and `c_zero`. Not
    /// reachable through this module's own API -- it is the assertion that the
    /// chain, transcribed from upstream, walked the whole ring.
    #[error("the challenge chain did not close")]
    ChainDidNotClose,
}

// ---------------------------------------------------------------------------
// Session identity
// ---------------------------------------------------------------------------

/// The public description of one signing session.
///
/// Held identically by the coordinator and by every participant. Its
/// [`binding`](SessionParams::binding) is what ties a round-one commitment to
/// the transaction it was made for.
///
/// `session_id` is the coordinator's; it distinguishes two *attempts* at the
/// same transaction. It must be fresh per attempt, because a fresh binding is
/// what makes a retry produce fresh nonces. Reusing one is not a silent
/// failure: [`NonceGuard`] refuses the second commit.
#[derive(Clone, Copy)]
pub struct SessionParams<'a> {
    pub session_id: &'a [u8; 32],
    pub message: &'a [u8],
    pub ring: &'a [ReducedTxOut],
    pub real_index: usize,
    pub output_commitment: &'a CompressedCommitment,
}

/// A 32-byte commitment to every field of a [`SessionParams`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionBinding([u8; 32]);

impl fmt::Debug for SessionBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionBinding(")?;
        for b in &self.0[..6] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "..)")
    }
}

impl SessionBinding {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl SessionParams<'_> {
    /// `H(session_id | message | ring | real_index | output_commitment)`.
    ///
    /// Every variable-length field is length-prefixed and every fixed-width
    /// one is written at its full width, so no two distinct sessions can share
    /// a PREIMAGE by moving a boundary between fields. Distinct sessions
    /// therefore reach distinct bindings under Blake2b-256's collision
    /// resistance -- with overwhelming probability, not by construction: this
    /// is a 256-bit digest of an unbounded input and cannot be injective.
    pub fn binding(&self) -> SessionBinding {
        let mut h = Blake2b256::new();
        h.update(SESSION_BINDING_DOMAIN);
        h.update(self.session_id);
        h.update((self.message.len() as u64).to_le_bytes());
        h.update(self.message);
        h.update((self.ring.len() as u64).to_le_bytes());
        for member in self.ring {
            h.update(member.public_key.as_bytes());
            h.update(member.target_key.as_bytes());
            h.update(member.commitment.point.as_bytes());
        }
        h.update((self.real_index as u64).to_le_bytes());
        h.update(self.output_commitment.point.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        SessionBinding(out)
    }

    /// `Hp(P)` for the output being spent, derived from the ring rather than
    /// accepted from the coordinator.
    ///
    /// WHY it is here and not only on [`Session`]: a participant that is handed
    /// its base has no way to know which output it is authorising a spend of.
    pub fn spend_base(&self) -> Result<RistrettoPoint, SigningError> {
        Ok(hash_to_point(&self.target()?))
    }

    /// `P`, the target key of the output being spent.
    pub fn target(&self) -> Result<RistrettoPublic, SigningError> {
        if self.ring.is_empty() {
            return Err(SigningError::EmptyRing);
        }
        let member = self
            .ring
            .get(self.real_index)
            .ok_or(SigningError::RealIndexOutOfBounds {
                index: self.real_index,
                ring_size: self.ring.len(),
            })?;
        RistrettoPublic::try_from(&member.target_key).map_err(|_| SigningError::RingMemberInvalid {
            index: self.real_index,
        })
    }
}

impl fmt::Debug for SessionParams<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionParams")
            .field("binding", &self.binding())
            .field("ring_size", &self.ring.len())
            .field("real_index", &self.real_index)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// One-time nonce reservation
// ---------------------------------------------------------------------------

/// Refusal from a [`NonceGuard`]: this `(binding, seat)` was reserved before.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonceAlreadyIssued;

/// The seam where a signer's durable one-time-value store plugs in.
///
/// [`SpendSigner::commit`] and [`MaskSigner::commit`] call `reserve` before
/// deriving a nonce, and refuse to proceed if it fails. An implementation MUST
/// return `Err` for a `(binding, seat)` it has ever seen before, **including
/// across process restarts** -- that is the whole point, because a nonce
/// derived from a binding is identical on both sides of a restart.
///
/// A store cannot detect its own rollback: after a snapshot restore it is a
/// perfectly consistent store that has simply never heard of the reservation.
/// `crates/ceremony/src/store.rs` carries the anchor that makes durability
/// mean something; this trait is deliberately the minimum interface that
/// module can be adapted to.
pub trait NonceGuard {
    fn reserve(&mut self, binding: SessionBinding, seat: Seat) -> Result<(), NonceAlreadyIssued>;
}

/// In-memory [`NonceGuard`]. **Test stand-in only** -- it forgets everything
/// when the process ends, which is exactly the case the guard exists for.
#[derive(Debug, Default)]
pub struct MemoryNonceGuard {
    used: BTreeSet<([u8; 32], [u8; 9])>,
}

impl MemoryNonceGuard {
    pub fn new() -> MemoryNonceGuard {
        MemoryNonceGuard::default()
    }

    /// How many one-time nonces this guard has handed out.
    pub fn len(&self) -> usize {
        self.used.len()
    }

    pub fn is_empty(&self) -> bool {
        self.used.is_empty()
    }
}

impl NonceGuard for MemoryNonceGuard {
    fn reserve(&mut self, binding: SessionBinding, seat: Seat) -> Result<(), NonceAlreadyIssued> {
        if self.used.insert((binding.0, seat.tag())) {
            Ok(())
        } else {
            Err(NonceAlreadyIssued)
        }
    }
}

/// `alpha = H(NONCE_DOMAIN | binding | seat | secret)`.
///
/// Deterministic, and secret-keyed: unpredictable to anyone who does not hold
/// `secret`, and identical for a given `(secret, binding, seat)` no matter how
/// many times the process restarts. See the module docs for why that is the
/// property wanted here.
///
/// "Different session, different nonce" is a collision-resistance statement,
/// not an injectivity one: `Scalar::from_hash` reduces a 512-bit digest into
/// the scalar field, so two sessions COULD in principle reach one `alpha`. The
/// probability is the same negligible quantity every Fiat-Shamir argument in
/// this file already depends on.
fn derive_nonce(secret: &Scalar, binding: &SessionBinding, seat: Seat) -> Scalar {
    let mut h = Blake2b512::new();
    h.update(NONCE_DOMAIN);
    h.update(binding.0);
    h.update(seat.tag());
    h.update(secret.to_bytes());
    Scalar::from_hash(h)
}

/// Independent secret-keyed binding nonce; version separated from hiding nonce.
fn derive_binding_nonce(secret: &Scalar, binding: &SessionBinding, seat: Seat) -> Scalar {
    let mut h = Blake2b512::new();
    h.update(b"mc-bridge-mlsag-binding-nonce-v2");
    h.update(binding.0);
    h.update(seat.tag());
    h.update(secret.to_bytes());
    Scalar::from_hash(h)
}

/// FROST-style two-commitment binding (RFC 9591 sections 4.4-4.5),
/// adapted to both MLSAG bases. This is NOT an RFC 9591 ciphersuite or a
/// security proof for the composed MLSAG protocol. Sort by role for a unique
/// encoding; chain_around separately rejects duplicates before using it.
fn binding_factor(binding: SessionBinding, round: &RoundOne, seat: Seat) -> Scalar {
    let mut h = Blake2b512::new();
    h.update(b"mc-bridge-mlsag-binding-factor-v2");
    h.update(binding.0);
    h.update(seat.tag());
    h.update((round.nonces.len() as u64).to_le_bytes());
    let mut nonces: Vec<_> = round.nonces.iter().collect();
    nonces.sort_by_key(|n| n.role);
    for n in nonces {
        h.update(Seat::Spend(n.role).tag());
        for point in [
            n.share_public,
            n.image_term,
            n.nonce_public,
            n.nonce_image,
            n.binding_public,
            n.binding_image,
        ] {
            h.update(point.compress().as_bytes());
        }
    }
    h.update(round.mask.nonce_public.compress().as_bytes());
    h.update(round.mask.binding_public.compress().as_bytes());
    h.update((round.responses.len() as u64).to_le_bytes());
    for response in &round.responses {
        h.update(response.to_bytes());
    }
    Scalar::from_hash(h)
}

// ---------------------------------------------------------------------------
// Participants
// ---------------------------------------------------------------------------

/// One participant's signing seat: its own weighted share, and nothing else.
///
/// This is the type the "no process forms `x`" claim rests on. It holds one
/// scalar, `w_i`, in a private field with **no accessor** -- there is no method
/// on `SpendSigner` or on [`ArmedSpendSigner`] that returns a share, a nonce,
/// or any scalar other than the blinded round-two response. A holder of every
/// signer in a quorum therefore still has no API by which to add them up.
///
/// The share cannot be read back out:
///
/// ```compile_fail
/// use two_cohort::mlsag::SpendSigner;
/// use curve25519_dalek::scalar::Scalar;
///
/// let signer = SpendSigner::view(&Scalar::ONE);
/// let _ = signer.weight;
/// ```
///
/// (What this does NOT claim: the surrounding crate still deals every share in
/// one process, and [`Cohort::reconstruct`](crate::Cohort::reconstruct) and
/// [`CompositeSpend::onetime`](crate::CompositeSpend::onetime) are still there
/// for the tests that need an independent answer. The structural claim is
/// scoped to this module's protocol types -- and, within this module, to the
/// three seat constructors, which are the deployable surface.
/// [`quorum_signers`] is a single-process simulation helper and takes a whole
/// [`CompositeSpend`]; see its own docs.)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SpendSigner {
    #[zeroize(skip)]
    role: SpendRole,
    weight: Scalar,
}

impl SpendSigner {
    /// The view service's seat, carrying `common`.
    pub fn view(common: &Scalar) -> SpendSigner {
        SpendSigner {
            role: SpendRole::View,
            weight: *common,
        }
    }

    /// An owner-cohort seat, from that participant's Lagrange-weighted term.
    pub fn owner(term: &ParticipantTerm) -> SpendSigner {
        SpendSigner {
            role: SpendRole::Owner(term.id()),
            weight: *term.weight(),
        }
    }

    /// A gate-cohort seat.
    pub fn gate(term: &ParticipantTerm) -> SpendSigner {
        SpendSigner {
            role: SpendRole::Gate(term.id()),
            weight: *term.weight(),
        }
    }

    pub fn role(&self) -> SpendRole {
        self.role
    }

    /// ROUND ONE. Derive this session's two nonces and publish the six group
    /// elements.
    ///
    /// Takes the whole [`SessionParams`], not a base point: the base is
    /// `Hp(ring[real_index].target_key)`, computed here, so the participant --
    /// not the coordinator -- decides which output it is spending. Takes no
    /// RNG: the nonce is derived from `(w_i, binding, seat)`. Reserves the seat
    /// in `guard` first, and fails without publishing anything if that seat
    /// already committed for this binding.
    ///
    /// Consumes the signer, so one seat contributes at most one nonce per
    /// in-process seat as well as at most one per binding.
    pub fn commit(
        self,
        params: &SessionParams<'_>,
        guard: &mut dyn NonceGuard,
    ) -> Result<(SpendNonce, ArmedSpendSigner), SigningError> {
        let g = RISTRETTO_BASEPOINT_POINT;
        // Validate the session before burning the guard slot: a malformed
        // session should not cost this seat its one commitment.
        let base = params.spend_base()?;
        let binding = params.binding();
        let seat = Seat::Spend(self.role);
        guard
            .reserve(binding, seat)
            .map_err(|NonceAlreadyIssued| SigningError::NonceAlreadyIssued { seat })?;

        // Read before `self` drops; `Scalar` is `Copy`, so this is a copy and
        // the original is still zeroized on drop.
        let (role, weight) = (self.role, self.weight);
        let alpha = derive_nonce(&weight, &binding, seat);
        let beta = derive_binding_nonce(&weight, &binding, seat);

        let nonce = SpendNonce {
            role,
            share_public: weight * g,
            image_term: weight * base,
            nonce_public: alpha * g,
            nonce_image: alpha * base,
            binding_public: beta * g,
            binding_image: beta * base,
        };
        let armed = ArmedSpendSigner {
            role,
            binding,
            base,
            weight,
            alpha,
            beta,
        };
        Ok((nonce, armed))
    }
}

impl fmt::Debug for SpendSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpendSigner")
            .field("role", &self.role)
            .field("weight", &"<redacted>")
            .finish()
    }
}

/// A [`SpendSigner`] that has committed to a nonce and is waiting for the
/// round-one transcript.
///
/// Deliberately not `Clone` and consumed by [`respond`](Self::respond): a nonce
/// that answered two different challenges leaks the share, since
/// `(r - r') / (c' - c) = w_i`.
///
/// That is only the IN-PROCESS half of the defence, and on its own it is not
/// enough -- two `ArmedSpendSigner`s built in two processes could carry the
/// same nonce. The other half is that the nonce is a function of the session
/// binding and [`NonceGuard`] refuses a second commitment under one binding;
/// see the module docs.
///
/// Not `Clone`, so a second copy cannot be kept back for a second challenge:
///
/// ```compile_fail
/// use two_cohort::mlsag::ArmedSpendSigner;
/// fn needs_clone<T: Clone>(_: &T) {}
/// fn duplicate(armed: &ArmedSpendSigner) { needs_clone(armed) }
/// ```
///
/// and neither the nonce nor the share can be read out of one:
///
/// ```compile_fail
/// use two_cohort::mlsag::ArmedSpendSigner;
/// fn peek(armed: &ArmedSpendSigner) { let _ = armed.alpha; }
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ArmedSpendSigner {
    #[zeroize(skip)]
    role: SpendRole,
    #[zeroize(skip)]
    binding: SessionBinding,
    #[zeroize(skip)]
    base: RistrettoPoint,
    weight: Scalar,
    alpha: Scalar,
    beta: Scalar,
}

impl ArmedSpendSigner {
    pub fn role(&self) -> SpendRole {
        self.role
    }

    /// The session this seat committed under. Public data; it is the value
    /// [`respond`](Self::respond) refuses to be moved off.
    pub fn binding(&self) -> SessionBinding {
        self.binding
    }

    /// ROUND TWO. Derive `c_real` from the published transcript and publish
    /// `r_i = alpha_i - c_real * w_i`.
    ///
    /// The challenge is not an argument. `params` is the participant's OWN copy
    /// of the session; the transcript is the coordinator's round-one output.
    /// Three things are checked before any scalar is emitted:
    ///
    ///   1. `params` binds to the same session `commit` was called under, so
    ///      the coordinator cannot carry round one into another transaction;
    ///   2. this seat's own round-one message is in the transcript, so the
    ///      challenge derived from it is one this nonce is part of;
    ///   3. the chain is re-run here, from `params.message` and `params.ring`,
    ///      by the same `chain_around` the coordinator used.
    ///
    /// What is deliberately NOT checked: that the quorum owns the output
    /// (`sum_i W_i == P`). A participant that refused there could not be shown
    /// to produce the unacceptable-signature outcome that
    /// `tests/mlsag_protocol.rs` pins, and validity is the verifier's job, not
    /// a participant's. [`Session::preflight`] is where that check lives.
    ///
    /// This is the only scalar any participant ever emits, and it is blinded
    /// by a nonce that appears in the transcript only as `alpha_i*G` and
    /// `alpha_i*Hp(P)`.
    pub fn respond(
        self,
        params: &SessionParams<'_>,
        round_one: &RoundOne,
    ) -> Result<SpendResponse, SigningError> {
        if params.binding() != self.binding {
            return Err(SigningError::SessionMismatch);
        }
        let g = RISTRETTO_BASEPOINT_POINT;
        let mine = SpendNonce {
            role: self.role,
            share_public: self.weight * g,
            image_term: self.weight * self.base,
            nonce_public: self.alpha * g,
            nonce_image: self.alpha * self.base,
            binding_public: self.beta * g,
            binding_image: self.beta * self.base,
        };
        if !round_one.nonces.iter().any(|n| *n == mine) {
            return Err(SigningError::NotInTranscript {
                seat: Seat::Spend(self.role),
            });
        }

        let ground = Ground::open(params)?;
        let chained = chain_around(params.message, &ground, round_one)?;
        Ok(SpendResponse {
            role: self.role,
            response: self.alpha
                + binding_factor(self.binding, round_one, Seat::Spend(self.role)) * self.beta
                - chained.c_real * self.weight,
        })
    }
}

impl fmt::Debug for ArmedSpendSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArmedSpendSigner")
            .field("role", &self.role)
            .field("binding", &self.binding)
            .field("weight", &"<redacted>")
            .field("alpha", &"<redacted>")
            .finish()
    }
}

/// The MLSAG mask row (row 1), held by the OWNER cohort alone.
///
/// Its secret is `z = output_blinding - blinding`, which is amount bookkeeping,
/// not spend authority. Splitting it across cohorts is explicitly NOT part of
/// this work: see the module docs. Row 1 being owner-only is not a bypass,
/// because the verifier folds `L0`, `R0` and `L1` into a single challenge, so
/// the rows are conjuncts -- a correct row 1 cannot rescue a row 0 that is
/// missing the gate term.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MaskSigner {
    z: Scalar,
}

impl MaskSigner {
    /// `z = output_blinding - blinding`.
    pub fn owner_held(output_blinding: &Scalar, blinding: &Scalar) -> MaskSigner {
        MaskSigner {
            z: output_blinding - blinding,
        }
    }

    /// ROUND ONE for the mask row: publish `alpha_1 * G`.
    ///
    /// There is no `Hp(P)` term because row 1 has no key image -- upstream
    /// omits it deliberately, since a commitment to zero does not need to be
    /// linkable. Same nonce derivation and same guard as a spend seat.
    pub fn commit(
        self,
        params: &SessionParams<'_>,
        guard: &mut dyn NonceGuard,
    ) -> Result<(MaskNonce, ArmedMaskSigner), SigningError> {
        // Validated for the same reason as in `SpendSigner::commit`.
        params.spend_base()?;
        let binding = params.binding();
        guard
            .reserve(binding, Seat::Mask)
            .map_err(|NonceAlreadyIssued| SigningError::NonceAlreadyIssued { seat: Seat::Mask })?;

        let z = self.z;
        let alpha = derive_nonce(&z, &binding, Seat::Mask);
        let beta = derive_binding_nonce(&z, &binding, Seat::Mask);
        Ok((
            MaskNonce {
                nonce_public: alpha * RISTRETTO_BASEPOINT_POINT,
                binding_public: beta * RISTRETTO_BASEPOINT_POINT,
            },
            ArmedMaskSigner {
                binding,
                z,
                alpha,
                beta,
            },
        ))
    }
}

impl fmt::Debug for MaskSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MaskSigner")
            .field("z", &"<redacted>")
            .finish()
    }
}

/// A [`MaskSigner`] waiting for the transcript. Not `Clone`, for the same
/// reason as [`ArmedSpendSigner`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ArmedMaskSigner {
    #[zeroize(skip)]
    binding: SessionBinding,
    z: Scalar,
    alpha: Scalar,
    beta: Scalar,
}

impl ArmedMaskSigner {
    /// ROUND TWO for the mask row: `r_1 = alpha_1 - c_real * z`, with `c_real`
    /// derived here from the transcript exactly as a spend seat derives it.
    pub fn respond(
        self,
        params: &SessionParams<'_>,
        round_one: &RoundOne,
    ) -> Result<MaskResponse, SigningError> {
        if params.binding() != self.binding {
            return Err(SigningError::SessionMismatch);
        }
        if round_one.mask.nonce_public != self.alpha * RISTRETTO_BASEPOINT_POINT
            || round_one.mask.binding_public != self.beta * RISTRETTO_BASEPOINT_POINT
        {
            return Err(SigningError::NotInTranscript { seat: Seat::Mask });
        }
        let ground = Ground::open(params)?;
        let chained = chain_around(params.message, &ground, round_one)?;
        Ok(MaskResponse {
            response: self.alpha + binding_factor(self.binding, round_one, Seat::Mask) * self.beta
                - chained.c_real * self.z,
        })
    }
}

impl fmt::Debug for ArmedMaskSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArmedMaskSigner")
            .field("binding", &self.binding)
            .field("z", &"<redacted>")
            .field("alpha", &"<redacted>")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Round messages. Every field is a value that goes on the wire in the clear.
// ---------------------------------------------------------------------------

/// ROUND ONE message from one spend-row participant.
///
/// All four fields are public: two of them (`share_public`, `image_term`) are
/// exactly what
/// [`Cohort::point_terms`](crate::Cohort::point_terms) already returns, and the
/// other two are commitments to a nonce that is discarded after round two.
/// Public fields because this is wire data, and because a test that wants to
/// forge one should be able to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendNonce {
    pub role: SpendRole,
    /// `w_i * G` -- this participant's share of the target key.
    pub share_public: RistrettoPoint,
    /// `w_i * Hp(P)` -- this participant's share of the key image.
    pub image_term: RistrettoPoint,
    /// `alpha_i * G`.
    pub nonce_public: RistrettoPoint,
    /// `alpha_i * Hp(P)`.
    pub nonce_image: RistrettoPoint,
    /// Independently derived beta_i * G, combined using transcript rho_i.
    pub binding_public: RistrettoPoint,
    /// The same beta_i on Hp(P).
    pub binding_image: RistrettoPoint,
}

/// ROUND TWO message from one spend-row participant: `r_i = alpha_i - c*w_i`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendResponse {
    pub role: SpendRole,
    pub response: Scalar,
}

/// ROUND ONE message for the mask row: `alpha_1 * G`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaskNonce {
    pub nonce_public: RistrettoPoint,
    pub binding_public: RistrettoPoint,
}

/// ROUND TWO message for the mask row: `r_1 = alpha_1 - c*z`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaskResponse {
    pub response: Scalar,
}

/// The complete published output of round one: every input to the challenge
/// chain that is not already in [`SessionParams`].
///
/// This is what makes the challenge reproducible by a participant instead of
/// dictated to it. It is entirely public -- the decoy responses appear verbatim
/// in the finished `RingMLSAG`, and the nonce commitments are group elements
/// the coordinator was going to broadcast anyway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundOne {
    pub nonces: Vec<SpendNonce>,
    pub mask: MaskNonce,
    /// `2 * ring_size` scalars: the decoy rows' responses, with both real-row
    /// slots left at zero until [`ChallengedSession::finish`] closes them. The
    /// chain never reads the real slots, so their contents do not affect
    /// `c_real`.
    pub responses: Vec<Scalar>,
}

impl RoundOne {
    /// Digest of the full public transcript for authenticated round-two packets.
    pub fn context_id(&self, params: &SessionParams<'_>) -> [u8; 32] {
        let mut h = Blake2b256::new();
        h.update(b"mc-bridge-mlsag-wire-context-v2");
        h.update(params.binding().as_bytes());
        // binding_factor already commits to every canonical transcript field.
        h.update(self.binding_factor(params, Seat::Mask).to_bytes());
        h.finalize().into()
    }

    /// Public transcript coefficient for independent inspection. Signing APIs
    /// validate the session and unique participant roles before using it.
    pub fn binding_factor(&self, params: &SessionParams<'_>, seat: Seat) -> Scalar {
        binding_factor(params.binding(), self, seat)
    }
}

/// `c_real`, the challenge that closes the loop back to the real ring index.
///
/// Public -- it is a hash of public data, and both the verifier and every
/// participant recompute it. A newtype rather than a bare `Scalar` so it cannot
/// be confused with a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealChallenge(Scalar);

impl RealChallenge {
    pub fn scalar(&self) -> &Scalar {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// The challenge chain, run identically by the coordinator and by participants
// ---------------------------------------------------------------------------

/// The decompressed, hashed form of a session's ring. Derived, never sent.
struct Ground {
    binding: SessionBinding,
    real_index: usize,
    ring: Vec<(RistrettoPublic, Commitment)>,
    /// `Hp(P_i)` for every ring member, precomputed because the chain uses
    /// each exactly once.
    hp: Vec<RistrettoPoint>,
    output_commitment: Commitment,
}

impl Ground {
    fn open(params: &SessionParams<'_>) -> Result<Ground, SigningError> {
        let ring_size = params.ring.len();
        if ring_size == 0 {
            return Err(SigningError::EmptyRing);
        }
        if params.real_index >= ring_size {
            return Err(SigningError::RealIndexOutOfBounds {
                index: params.real_index,
                ring_size,
            });
        }

        let mut ring = Vec::with_capacity(ring_size);
        for (index, member) in params.ring.iter().enumerate() {
            let decompressed: (RistrettoPublic, Commitment) = member
                .try_into()
                .map_err(|_| SigningError::RingMemberInvalid { index })?;
            ring.push(decompressed);
        }
        let hp = ring.iter().map(|(p, _)| hash_to_point(p)).collect();

        let output_commitment = Commitment::try_from(params.output_commitment)
            .map_err(|_| SigningError::OutputCommitmentInvalid)?;

        Ok(Ground {
            binding: params.binding(),
            real_index: params.real_index,
            ring,
            hp,
            output_commitment,
        })
    }

    fn spend_base(&self) -> RistrettoPoint {
        self.hp[self.real_index]
    }

    fn target(&self) -> &RistrettoPublic {
        &self.ring[self.real_index].0
    }

    /// `output_commitment - input_commitment` at the real index: what `z*G`
    /// has to equal for the amounts to balance.
    fn balance_target(&self) -> RistrettoPoint {
        self.output_commitment.point - self.ring[self.real_index].1.point
    }
}

struct Chained {
    key_image: KeyImage,
    c_real: Scalar,
    c_zero: Scalar,
}

/// Transcribed from `MlsagSignCtx::update`: start at the real index and walk
/// the ring once, each step hashing the previous challenge into the next.
///
/// A free function on public inputs, deliberately: the coordinator and every
/// participant run *this* function, so "the coordinator computed the challenge
/// honestly" is not something anyone has to take on trust.
fn chain_around(
    message: &[u8],
    ground: &Ground,
    round_one: &RoundOne,
) -> Result<Chained, SigningError> {
    let ring_size = ground.ring.len();
    if round_one.nonces.is_empty() {
        return Err(SigningError::NoContributions);
    }
    for (i, n) in round_one.nonces.iter().enumerate() {
        if round_one.nonces[..i].iter().any(|m| m.role == n.role) {
            return Err(SigningError::DuplicateContribution { role: n.role });
        }
    }
    if round_one.responses.len() != 2 * ring_size {
        return Err(SigningError::TranscriptSizeMismatch {
            expected: 2 * ring_size,
            found: round_one.responses.len(),
        });
    }

    // The key image, assembled entirely out of group elements published by
    // their owners. At no point is it `x * Hp(P)` for a materialised `x`.
    let image: RistrettoPoint = round_one.nonces.iter().map(|n| n.image_term).sum();
    let key_image = KeyImage {
        point: image.compress(),
    };

    // Row-0 and row-1 commitments for the real index.
    let l0_real: RistrettoPoint = round_one
        .nonces
        .iter()
        .map(|n| {
            n.nonce_public
                + binding_factor(ground.binding, round_one, Seat::Spend(n.role)) * n.binding_public
        })
        .sum();
    let r0_real: RistrettoPoint = round_one
        .nonces
        .iter()
        .map(|n| {
            n.nonce_image
                + binding_factor(ground.binding, round_one, Seat::Spend(n.role)) * n.binding_image
        })
        .sum();
    let l1_real = round_one.mask.nonce_public
        + binding_factor(ground.binding, round_one, Seat::Mask) * round_one.mask.binding_public;

    let g = RISTRETTO_BASEPOINT_POINT;
    let real = ground.real_index;
    let mut last: Option<Scalar> = None;
    let (mut c_real, mut c_zero) = (None, None);

    for step in 0..ring_size {
        let i = (real + step) % ring_size;
        let (p_i, input_commitment) = &ground.ring[i];

        let (l0, r0, l1) = if i == real {
            (l0_real, r0_real, l1_real)
        } else {
            let c = last.ok_or(SigningError::ChainDidNotClose)?;
            (
                round_one.responses[2 * i] * g + c * p_i.as_ref(),
                round_one.responses[2 * i] * ground.hp[i] + c * image,
                round_one.responses[2 * i + 1] * g
                    + c * (ground.output_commitment.point - input_commitment.point),
            )
        };

        let c = challenge(message, &key_image, &l0, &r0, &l1);
        if (i + 1) % ring_size == real {
            c_real = Some(c);
        }
        if (i + 1) % ring_size == 0 {
            c_zero = Some(c);
        }
        last = Some(c);
    }

    let (c_real, c_zero) = match (c_real, c_zero) {
        (Some(r), Some(z)) => (r, z),
        _ => return Err(SigningError::ChainDidNotClose),
    };
    if c_real == Scalar::ZERO {
        return Err(SigningError::DegenerateChallenge);
    }

    Ok(Chained {
        key_image,
        c_real,
        c_zero,
    })
}

// ---------------------------------------------------------------------------
// Coordinator
// ---------------------------------------------------------------------------

/// `sum_i W_i == P`, shared by [`Session::preflight`] and
/// [`ChallengedSession::preflight`] so that the two cannot drift apart.
fn quorum_owns_output(nonces: &[SpendNonce], target: &RistrettoPublic) -> Result<(), SigningError> {
    if nonces.is_empty() {
        return Err(SigningError::NoContributions);
    }
    let assembled: RistrettoPoint = nonces.iter().map(|n| n.share_public).sum();
    let target = *target.as_ref();
    if assembled != target {
        return Err(SigningError::QuorumDoesNotOwnOutput {
            assembled: hex32(&assembled),
            target: hex32(&target),
        });
    }
    Ok(())
}

/// What the coordinator remembers about one round-one message, so that round
/// two can be checked against it.
#[derive(Clone, Debug)]
struct Committed {
    role: SpendRole,
    share_public: RistrettoPoint,
    image_term: RistrettoPoint,
    nonce_public: RistrettoPoint,
    nonce_image: RistrettoPoint,
}

/// The coordinator, before round one.
///
/// Holds no secret. Its fields are the session description, the decompressed
/// ring, and the random responses for the decoy rows -- which are uniform
/// scalars unrelated to any share. There is no field from which any part of
/// `x` could be recovered, because none was ever handed to it.
pub struct Session<'a> {
    params: SessionParams<'a>,
    ground: Ground,
    /// `2 * ring_size`, decoy rows filled, real row left at zero until round
    /// two closes it.
    decoy_responses: Vec<Scalar>,
}

impl<'a> Session<'a> {
    /// Open a session: decompress the ring and draw the decoy responses.
    ///
    /// The decoy responses are drawn here rather than at round two because the
    /// challenge chain consumes them, and the chain runs before round two.
    /// They must be uniform and independent per session: a decoy response
    /// distinguishable from a real one is a ring that does not hide the real
    /// input.
    pub fn open<R: RngCore + CryptoRng>(
        params: SessionParams<'a>,
        rng: &mut R,
    ) -> Result<Session<'a>, SigningError> {
        let ground = Ground::open(&params)?;
        let ring_size = ground.ring.len();

        let mut decoy_responses = vec![Scalar::ZERO; 2 * ring_size];
        for i in 0..ring_size {
            if i != params.real_index {
                decoy_responses[2 * i] = random_scalar(rng);
                decoy_responses[2 * i + 1] = random_scalar(rng);
            }
        }

        Ok(Session {
            params,
            ground,
            decoy_responses,
        })
    }

    /// The session every participant must hold a byte-identical copy of.
    pub fn params(&self) -> &SessionParams<'a> {
        &self.params
    }

    /// `Hp(P)` for the output being spent.
    ///
    /// Kept for the coordinator's own diagnostics. Participants derive their
    /// own from [`SessionParams::spend_base`] and do not accept this one.
    pub fn spend_base(&self) -> RistrettoPoint {
        self.ground.spend_base()
    }

    /// `P`, the target key of the output being spent.
    pub fn target(&self) -> &RistrettoPublic {
        self.ground.target()
    }

    /// Check, from round-one messages alone, that this quorum can spend this
    /// output: `sum_i W_i == P`.
    ///
    /// A diagnostic, not the security boundary -- see the module docs. Skipping
    /// it does not make an unqualified quorum's signature acceptable; it only
    /// means the coordinator finds out from the verifier instead of finding out
    /// here. The error names both points, and their difference is the missing
    /// cohort's public key.
    ///
    /// It says nothing about the list [`round_one`](Session::round_one) is
    /// subsequently handed, which is a different argument to a different call.
    /// [`ChallengedSession::preflight`] is the same check over the list that
    /// actually built the chain.
    pub fn preflight(&self, nonces: &[SpendNonce]) -> Result<(), SigningError> {
        quorum_owns_output(nonces, self.target())
    }

    /// ROUND ONE, coordinator side. Publish the transcript, assemble the key
    /// image from the published image terms, and run the challenge chain around
    /// the ring to obtain `c_real`.
    ///
    /// Consumes the session: the chain depends on the decoy responses, so the
    /// same `Session` must not be chained twice against different nonces.
    pub fn round_one(
        self,
        nonces: &[SpendNonce],
        mask: &MaskNonce,
    ) -> Result<ChallengedSession, SigningError> {
        let round_one = RoundOne {
            nonces: nonces.to_vec(),
            mask: *mask,
            responses: self.decoy_responses,
        };
        let chained = chain_around(self.params.message, &self.ground, &round_one)?;

        let committed = round_one
            .nonces
            .iter()
            .map(|n| Committed {
                role: n.role,
                share_public: n.share_public,
                image_term: n.image_term,
                nonce_public: n.nonce_public
                    + binding_factor(self.params.binding(), &round_one, Seat::Spend(n.role))
                        * n.binding_public,
                nonce_image: n.nonce_image
                    + binding_factor(self.params.binding(), &round_one, Seat::Spend(n.role))
                        * n.binding_image,
            })
            .collect();

        let mask_commitment = round_one.mask.nonce_public
            + binding_factor(self.params.binding(), &round_one, Seat::Mask)
                * round_one.mask.binding_public;
        Ok(ChallengedSession {
            mask_commitment,
            real_index: self.ground.real_index,
            hp_real: self.ground.spend_base(),
            target: *self.ground.target(),
            balance_target: self.ground.balance_target(),
            key_image: chained.key_image,
            challenge: RealChallenge(chained.c_real),
            c_zero: chained.c_zero,
            committed,
            round_one,
        })
    }
}

impl fmt::Debug for Session<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("ring_size", &self.ground.ring.len())
            .field("real_index", &self.ground.real_index)
            .finish()
    }
}

/// The coordinator between the rounds: the chain has run and `c_real` is
/// available.
///
/// Like [`Session`], holds no secret.
#[derive(Debug)]
pub struct ChallengedSession {
    mask_commitment: RistrettoPoint,
    real_index: usize,
    hp_real: RistrettoPoint,
    target: RistrettoPublic,
    balance_target: RistrettoPoint,
    key_image: KeyImage,
    challenge: RealChallenge,
    c_zero: Scalar,
    committed: Vec<Committed>,
    round_one: RoundOne,
}

impl ChallengedSession {
    /// The round-one transcript to broadcast. Participants derive `c_real`
    /// from this plus their own copy of the session; they are never sent the
    /// challenge itself.
    pub fn round_one_transcript(&self) -> &RoundOne {
        &self.round_one
    }

    /// `c_real` as the coordinator computed it.
    ///
    /// Exposed for diagnostics and for tests that want to compare it against
    /// what a participant derives. Sending it to a participant achieves
    /// nothing: [`ArmedSpendSigner::respond`] does not accept one.
    pub fn challenge(&self) -> &RealChallenge {
        &self.challenge
    }

    /// The key image assembled from round one's `w_i * Hp(P)` terms.
    ///
    /// Available before round two, and never derived from a scalar.
    pub fn key_image(&self) -> KeyImage {
        self.key_image
    }

    /// The roles the coordinator is waiting on.
    pub fn awaiting(&self) -> Vec<SpendRole> {
        self.committed.iter().map(|c| c.role).collect()
    }

    /// `sum_i W_i == P` over the round-one list the challenge chain was
    /// actually built from.
    ///
    /// [`Session::preflight`] takes a slice, and nothing ties that slice to the
    /// one [`Session::round_one`] is handed afterwards -- a coordinator can
    /// preflight a qualifying set and chain a different one, passing the first
    /// check with `sum_i W_i != P` for the set that matters. This is the same
    /// arithmetic over `self.round_one.nonces`, which is not an argument and
    /// cannot be swapped. Prefer it.
    pub fn preflight(&self) -> Result<(), SigningError> {
        quorum_owns_output(&self.round_one.nonces, &self.target)
    }

    /// ROUND TWO, coordinator side. Check each response against its round-one
    /// commitment, sum them into the real row, and hand back a finished
    /// `RingMLSAG`.
    ///
    /// `responses[2*real] = sum_i r_i`, which equals `alpha_0 - c_real * x`
    /// term by term without `alpha_0` or `x` existing anywhere.
    pub fn finish(
        self,
        responses: &[SpendResponse],
        mask: &MaskResponse,
    ) -> Result<RingMLSAG, SigningError> {
        let g = RISTRETTO_BASEPOINT_POINT;
        let c = self.challenge.0;

        let mut matched = vec![false; responses.len()];
        let mut total = Scalar::ZERO;

        for expected in &self.committed {
            let mut found: Option<usize> = None;
            for (k, r) in responses.iter().enumerate() {
                if r.role == expected.role {
                    if found.is_some() {
                        return Err(SigningError::DuplicateResponse {
                            role: expected.role,
                        });
                    }
                    found = Some(k);
                }
            }
            let k = found.ok_or(SigningError::MissingResponse {
                role: expected.role,
            })?;
            matched[k] = true;
            let r = responses[k].response;

            // The response has to open the round-one commitment on both bases.
            // Without this a single faulty participant produces a signature
            // that only consensus rejects, and nobody can say who caused it.
            if r * g + c * expected.share_public != expected.nonce_public {
                return Err(SigningError::ResponseDoesNotOpenNonce {
                    role: expected.role,
                });
            }
            // Separately, because this one is what decides the KEY IMAGE: a
            // seat whose G-values are consistent but whose Hp(P)-values are
            // shifted by a common delta passes the check above and moves the
            // image, which is the consensus-visible artefact.
            if r * self.hp_real + c * expected.image_term != expected.nonce_image {
                return Err(SigningError::ResponseDoesNotOpenImageTerm {
                    role: expected.role,
                });
            }

            total += r;
        }

        if let Some(k) = matched.iter().position(|m| !m) {
            return Err(SigningError::UnexpectedResponse {
                role: responses[k].role,
            });
        }

        // Upstream's `check_value_is_preserved`, done without knowing `z`:
        // `alpha_1*G - r_1*G = c*z*G`, and `c != 0` was checked when the chain
        // closed.
        let recovered = (self.mask_commitment - mask.response * g) * c.invert();
        if recovered != self.balance_target {
            return Err(SigningError::ValueNotConserved {
                recovered: hex32(&recovered),
                expected: hex32(&self.balance_target),
            });
        }

        let mut out = self.round_one.responses;
        out[2 * self.real_index] = total;
        out[2 * self.real_index + 1] = mask.response;

        Ok(RingMLSAG {
            c_zero: CurveScalar::from(self.c_zero),
            responses: out.into_iter().map(CurveScalar::from).collect(),
            key_image: self.key_image,
        })
    }
}

// ---------------------------------------------------------------------------
// Assembling a quorum, and driving the two rounds in one process
// ---------------------------------------------------------------------------

/// The signing seats for one (owner-subset x gate-subset) pair: the view seat,
/// then one seat per owner, then one seat per gate.
///
/// **A single-process simulation helper, not part of the deployable surface.**
/// It takes a whole [`CompositeSpend`] -- every share of both cohorts, in one
/// memory space -- and calls
/// [`Cohort::weighted`](crate::Cohort::weighted) twice. A caller that can call
/// this is a caller that can sum the [`ParticipantTerm`]s itself, since
/// [`ParticipantTerm::weight`](crate::ParticipantTerm::weight) is public. The
/// "no process forms `x`" claim is about the protocol types --
/// [`SpendSigner`], [`ArmedSpendSigner`], [`Session`], [`ChallengedSession`] --
/// and about a deployment that builds each seat where its share lives, from
/// [`SpendSigner::view`] / [`owner`](SpendSigner::owner) /
/// [`gate`](SpendSigner::gate). It is not a claim about this function.
///
/// It is also where the cohort rules are enforced, and the only place they can
/// be: a below-threshold subset, an unknown id, or an id from the other
/// cohort's band is rejected by [`Cohort::weighted`](crate::Cohort::weighted)
/// before any seat exists. Because [`Owners`](crate::Owners) and
/// [`Gates`](crate::Gates) own disjoint id bands, passing an owner subset where
/// the gate subset belongs is
/// [`UnknownParticipant`](crate::Error::UnknownParticipant) inside the `gates`
/// cohort, not a silently valid interpolation.
///
/// A `Vec<SpendSigner>` and not a struct with a `combine` method: a type that
/// could add these up is the type this module exists to not have.
pub fn quorum_signers(
    spend: &CompositeSpend,
    owner_subset: &[u64],
    gate_subset: &[u64],
) -> Result<Vec<SpendSigner>, SigningError> {
    let owners = spend.owners().weighted(owner_subset)?;
    let gates = spend.gates().weighted(gate_subset)?;

    let mut seats = Vec::with_capacity(1 + owners.len() + gates.len());
    seats.push(SpendSigner::view(spend.common()));
    seats.extend(owners.iter().map(SpendSigner::owner));
    seats.extend(gates.iter().map(SpendSigner::gate));
    Ok(seats)
}

/// Drive both rounds in one call, including [`Session::preflight`].
///
/// Every step it takes is public API; it exists so that a caller which really
/// is the coordinator *and* holds the participants -- a test, a single-host
/// simulation -- does not restate the sequence each time. A deployment drives
/// the same steps across a network instead, which is the point of the messages
/// being values.
///
/// `guard` is threaded through rather than created here, because a guard whose
/// lifetime is one call is not a guard: it would let two calls on the same
/// `params` issue the same nonces against two different sets of decoy
/// responses, which is exactly the leak [`NonceGuard`] exists to stop.
///
/// Note what holding every `SpendSigner` in one process does NOT give this
/// function: there is no point in it where the shares are summed. It sums
/// nonce commitments (group elements) and blinded responses, exactly as a
/// remote coordinator would.
pub fn sign<R: RngCore + CryptoRng>(
    params: SessionParams<'_>,
    signers: Vec<SpendSigner>,
    mask: MaskSigner,
    guard: &mut dyn NonceGuard,
    rng: &mut R,
) -> Result<RingMLSAG, SigningError> {
    let session = Session::open(params, rng)?;

    let mut nonces = Vec::with_capacity(signers.len());
    let mut armed = Vec::with_capacity(signers.len());
    for signer in signers {
        let (nonce, a) = signer.commit(&params, guard)?;
        nonces.push(nonce);
        armed.push(a);
    }
    let (mask_nonce, armed_mask) = mask.commit(&params, guard)?;

    session.preflight(&nonces)?;
    let challenged = session.round_one(&nonces, &mask_nonce)?;
    // The binding one: the same check over the list the chain really used.
    challenged.preflight()?;
    let transcript = challenged.round_one_transcript();

    let mut responses = Vec::with_capacity(armed.len());
    for a in armed {
        responses.push(a.respond(&params, transcript)?);
    }
    let mask_response = armed_mask.respond(&params, transcript)?;

    challenged.finish(&responses, &mask_response)
}

#[path = "mlsag_wire.rs"]
pub mod wire;
