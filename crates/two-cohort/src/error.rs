//! Failure modes of cohort construction and interpolation.
//!
//! These are errors rather than panics because every one of them is reachable
//! from configuration a human types: a roster pasted with a repeated id, a
//! threshold copied from the wrong cohort, an operator id left at its default.
//! A release path that aborts the process on bad config is a release path that
//! can be taken down by bad config.

use thiserror::Error;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Error {
    /// A 0-of-n cohort is not a cohort: the empty subset qualifies, so the
    /// secret is recoverable by nobody and authorised by everybody.
    #[error("threshold must be at least 1")]
    ThresholdZero,

    /// A threshold above the roster size can never be met, which bricks the
    /// funds rather than protecting them.
    #[error("threshold {threshold} exceeds roster size {roster}")]
    ThresholdExceedsRoster { threshold: usize, roster: usize },

    /// An empty roster has no share to hold the secret.
    #[error("roster is empty")]
    EmptyRoster,

    /// Two participants sharing an id are one participant as far as Lagrange
    /// interpolation is concerned: the weight for the repeated id is computed
    /// against a subset that skips its own duplicate, so the reconstructed
    /// value is not the secret.
    #[error("participant id {0} appears more than once")]
    DuplicateParticipant(u64),

    /// 0 is the interpolation point. A share evaluated at x = 0 IS the secret,
    /// so a participant issued id 0 holds the whole cohort secret alone.
    #[error("participant id 0 is the interpolation point and would hold the cohort secret outright")]
    ReservedParticipantId,

    /// Fewer signers than the threshold. Refusing here is the whole point of a
    /// threshold; interpolating anyway would produce a wrong scalar silently.
    #[error("subset of {have} is below threshold {threshold}")]
    BelowThreshold { have: usize, threshold: usize },

    /// An id that was never dealt a share.
    #[error("participant {0} is not on this roster")]
    UnknownParticipant(u64),

    /// Wrapper that names which cohort rejected the input, since the two
    /// cohorts have separate rosters and thresholds and the caller needs to
    /// know which one it got wrong.
    #[error("cohort `{name}`: {source}")]
    InCohort { name: String, source: Box<Error> },
}

impl Error {
    pub(crate) fn in_cohort(name: &str, source: Error) -> Error {
        Error::InCohort {
            name: name.to_owned(),
            source: Box::new(source),
        }
    }

    /// The underlying failure with any cohort-name wrappers stripped.
    ///
    /// Callers that want to react to *what* went wrong rather than *where*
    /// match on this.
    pub fn kind(&self) -> &Error {
        match self {
            Error::InCohort { source, .. } => source.kind(),
            other => other,
        }
    }
}
