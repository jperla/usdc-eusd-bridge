//! One cohort: its own roster, its own threshold, its own secret.
//!
//! A `Cohort` never refers to a second cohort. That is the structural point --
//! a design with one roster and one `t/n` shared between roles cannot express
//! operators-and-gates at all, because the gate cohort has a different size, a
//! different threshold and a different set of humans behind it.
//!
//! Separateness of the two rosters is not this type's business either; it is
//! [`control`](crate::control)'s, and [`Cohort::deal_in`] is where the two
//! meet.

use core::fmt;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    control::{ControlDomain, NAMESPACE_SPAN},
    error::{Error, Result},
};

/// One participant's Lagrange-weighted contribution for a particular subset.
///
/// Exposed rather than pre-summed so a caller can carry each term to the
/// participant that owns it and combine in the group. `weight` is secret --
/// it is the participant's share times a public constant, so anyone holding
/// enough of these holds the cohort secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ParticipantTerm {
    id: u64,
    weight: Scalar,
}

impl ParticipantTerm {
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The weighted share `lambda_i * s_i`.
    pub fn weight(&self) -> &Scalar {
        &self.weight
    }

    /// `weight * base`, the form a participant can publish without revealing
    /// its share. With `base = G` this is a public-key term; with
    /// `base = Hp(target)` it is a key-image term.
    pub fn in_group(&self, base: &RistrettoPoint) -> RistrettoPoint {
        self.weight * base
    }
}

/// Deliberately redacted: a `Debug` that printed shares would put cohort
/// secrets into every log line that formats a signing session.
impl fmt::Debug for ParticipantTerm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParticipantTerm")
            .field("id", &self.id)
            .field("weight", &"<redacted>")
            .finish()
    }
}

/// A Shamir-shared secret over one roster.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Cohort {
    #[zeroize(skip)]
    name: String,
    #[zeroize(skip)]
    threshold: usize,
    #[zeroize(skip)]
    ids: Vec<u64>,
    /// Parallel to `ids`. Held in one process because this crate simulates the
    /// algebra rather than running a ceremony -- see the crate-level docs.
    shares: Vec<Scalar>,
}

impl Cohort {
    /// Shamir-share `secret` at `threshold` over the roster `ids`.
    ///
    /// The roster is explicit rather than "1..=n" because participant ids are
    /// operational identities that outlive any one dealing: an operator that
    /// leaves must not have its id silently reissued to its replacement, since
    /// the two would then hold shares of the same evaluation point.
    pub fn deal<R: RngCore + CryptoRng>(
        name: &str,
        secret: &Scalar,
        threshold: usize,
        ids: &[u64],
        rng: &mut R,
    ) -> Result<Cohort> {
        validate_roster(threshold, ids).map_err(|e| Error::in_cohort(name, e))?;

        // coeffs[0] = secret, so p(0) = secret. The remaining `threshold - 1`
        // coefficients are uniform, which is what makes any `threshold - 1`
        // shares independent of the secret.
        let mut coeffs: Zeroizing<Vec<Scalar>> = Zeroizing::new(Vec::with_capacity(threshold));
        coeffs.push(*secret);
        for _ in 1..threshold {
            coeffs.push(random_scalar(rng));
        }

        let shares = ids
            .iter()
            .map(|&id| {
                let x = Scalar::from(id);
                // Horner, high coefficient first.
                let mut acc = Scalar::ZERO;
                for c in coeffs.iter().rev() {
                    acc = acc * x + c;
                }
                acc
            })
            .collect();

        Ok(Cohort {
            name: name.to_owned(),
            threshold,
            ids: ids.to_vec(),
            shares,
        })
    }

    /// Deal a cohort inside a control domain.
    ///
    /// The domain supplies the cohort's name and, more importantly, the id
    /// band the roster must lie in. Rejecting an out-of-band id here is what
    /// makes the two cohorts of a [`CompositeSpend`](crate::CompositeSpend)
    /// non-interchangeable: their rosters cannot intersect, so a subset drawn
    /// from one is never a quorum of the other.
    pub fn deal_in<C: ControlDomain, R: RngCore + CryptoRng>(
        secret: &Scalar,
        threshold: usize,
        ids: &[u64],
        rng: &mut R,
    ) -> Result<Cohort> {
        for &id in ids {
            if !C::owns(id) {
                return Err(Error::in_cohort(
                    C::NAME,
                    Error::IdOutsideDomain {
                        domain: C::NAME,
                        id,
                        base: C::ID_BASE,
                        end: C::ID_BASE + NAMESPACE_SPAN,
                    },
                ));
            }
        }
        Cohort::deal(C::NAME, secret, threshold, ids, rng)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn roster(&self) -> &[u64] {
        &self.ids
    }

    pub fn n(&self) -> usize {
        self.ids.len()
    }

    /// One participant's raw share.
    ///
    /// Reachable only because this crate holds every share in one process; a
    /// real deployment would have each share live only inside its own HSM.
    pub fn share(&self, id: u64) -> Result<Zeroizing<Scalar>> {
        let pos = self
            .ids
            .iter()
            .position(|&i| i == id)
            .ok_or_else(|| Error::in_cohort(&self.name, Error::UnknownParticipant(id)))?;
        Ok(Zeroizing::new(self.shares[pos]))
    }

    /// Each participant's Lagrange-weighted contribution for `subset`.
    ///
    /// Summing the weights reconstructs the cohort secret. The terms are
    /// returned individually so a caller can avoid ever forming that sum.
    pub fn weighted(&self, subset: &[u64]) -> Result<Vec<ParticipantTerm>> {
        self.check_subset(subset)?;
        subset
            .iter()
            .map(|&id| {
                let lambda = lagrange_at_zero(id, subset)?;
                let share = self.share(id)?;
                Ok(ParticipantTerm {
                    id,
                    weight: lambda * *share,
                })
            })
            .collect()
    }

    /// Each participant's contribution carried into the group: `w_i * base`.
    ///
    /// This is the shape a real signer uses -- no participant's scalar leaves
    /// its own term, and no sum of the returned points is a secret.
    pub fn point_terms(
        &self,
        subset: &[u64],
        base: &RistrettoPoint,
    ) -> Result<Vec<(u64, RistrettoPoint)>> {
        Ok(self
            .weighted(subset)?
            .iter()
            .map(|t| (t.id(), t.in_group(base)))
            .collect())
    }

    /// The cohort's public key `secret * G`, assembled from the point terms of
    /// any qualifying subset.
    pub fn public(&self, subset: &[u64]) -> Result<RistrettoPoint> {
        Ok(self
            .point_terms(subset, &RISTRETTO_BASEPOINT_POINT)?
            .into_iter()
            .map(|(_, p)| p)
            .sum())
    }

    /// The cohort secret, reconstructed.
    ///
    /// Present because this crate is the algebra, not a signer. A production
    /// signer must never call this; see the crate-level limitations.
    pub fn reconstruct(&self, subset: &[u64]) -> Result<Zeroizing<Scalar>> {
        Ok(Zeroizing::new(
            self.weighted(subset)?
                .iter()
                .map(|t| t.weight())
                .sum::<Scalar>(),
        ))
    }

    fn check_subset(&self, subset: &[u64]) -> Result<()> {
        let wrap = |e| Error::in_cohort(&self.name, e);
        if subset.len() < self.threshold {
            return Err(wrap(Error::BelowThreshold {
                have: subset.len(),
                threshold: self.threshold,
            }));
        }
        for (i, &id) in subset.iter().enumerate() {
            if subset[..i].contains(&id) {
                return Err(wrap(Error::DuplicateParticipant(id)));
            }
            if !self.ids.contains(&id) {
                return Err(wrap(Error::UnknownParticipant(id)));
            }
        }
        Ok(())
    }
}

/// Redacted for the same reason as `ParticipantTerm`'s.
impl fmt::Debug for Cohort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cohort")
            .field("name", &self.name)
            .field("threshold", &self.threshold)
            .field("roster", &self.ids)
            .field("shares", &"<redacted>")
            .finish()
    }
}

/// The Lagrange basis polynomial for `id` evaluated at 0, over `subset`:
///
/// ```text
///     lambda_i = prod_{j in subset, j != i}  x_j / (x_j - x_i)
/// ```
///
/// The weight depends on the SUBSET, not just on the participant, which is why
/// the same operator contributes a different scalar in two different signing
/// sessions -- and why a naive sum of raw shares does not reconstruct anything.
pub fn lagrange_at_zero(id: u64, subset: &[u64]) -> Result<Scalar> {
    validate_subset(subset)?;
    if !subset.contains(&id) {
        return Err(Error::UnknownParticipant(id));
    }

    let xi = Scalar::from(id);
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &j in subset {
        if j != id {
            let xj = Scalar::from(j);
            num *= xj;
            den *= xj - xi;
        }
    }
    // `den` is a product of differences of distinct non-zero ids, so it is
    // non-zero: `validate_subset` has already rejected duplicates, and Scalar
    // arithmetic is over a prime field where distinct u64 ids stay distinct.
    Ok(num * den.invert())
}

fn validate_subset(subset: &[u64]) -> Result<()> {
    if subset.is_empty() {
        return Err(Error::EmptyRoster);
    }
    for (i, &id) in subset.iter().enumerate() {
        if id == 0 {
            return Err(Error::ReservedParticipantId);
        }
        if subset[..i].contains(&id) {
            return Err(Error::DuplicateParticipant(id));
        }
    }
    Ok(())
}

fn validate_roster(threshold: usize, ids: &[u64]) -> Result<()> {
    if threshold == 0 {
        return Err(Error::ThresholdZero);
    }
    validate_subset(ids)?;
    if threshold > ids.len() {
        return Err(Error::ThresholdExceedsRoster {
            threshold,
            roster: ids.len(),
        });
    }
    Ok(())
}

/// Uniform scalar by wide reduction, matching how MobileCoin draws scalars.
pub(crate) fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    let mut bytes = Zeroizing::new([0u8; 64]);
    rng.fill_bytes(bytes.as_mut());
    Scalar::from_bytes_mod_order_wide(&bytes)
}
