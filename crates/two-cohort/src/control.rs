//! Which control domain a roster belongs to.
//!
//! Two thresholds only buy anything if they are held by DIFFERENT entities. A
//! 2-of-3 owner quorum plus a 2-of-3 gate quorum drawn from the same three
//! people is a 2-of-3, not a two-cohort scheme. Nothing in the algebra notices
//! that: Lagrange interpolation over `{1,2,3}` works the same whichever roster
//! the ids were meant to name.
//!
//! So the separation cannot live in the naming convention. Here it lives in
//! two places at once:
//!
//!   * **In the type.** [`Owners`] and [`Gates`] are distinct types, so a
//!     [`CohortSpec`](crate::CohortSpec) for one cannot be passed where the
//!     other is expected. That mistake does not compile.
//!   * **In the ids.** Each domain owns a disjoint band of participant ids, so
//!     an id is either an owner id or a gate id and never both. A subset that
//!     reaches the wrong cohort at runtime -- through a `&[u64]` that has lost
//!     its provenance -- is rejected as
//!     [`UnknownParticipant`](crate::Error::UnknownParticipant) rather than
//!     silently interpolated into a valid answer.
//!
//! The second half is the one that has teeth. With both rosters equal to
//! `{1,2,3}`, every owner subset is also a qualifying gate subset, so
//! `gates.weighted(owner_subset)` succeeds, the gate argument becomes dead code
//! and no test can tell whether the gate cohort was consulted at all.

/// A control domain: one side of the two-cohort structure.
///
/// Implemented only by [`Owners`] and [`Gates`]. Sealed because a third domain
/// would need its own id band, and bands that overlap defeat the purpose.
pub trait ControlDomain: sealed::Sealed + Copy + core::fmt::Debug + 'static {
    /// Name used in error messages, so an operator reading a rejection knows
    /// which roster it got wrong.
    const NAME: &'static str;

    /// First participant id in this domain's band.
    const ID_BASE: u64;

    /// Whether `id` was issued in this domain.
    fn owns(id: u64) -> bool {
        id >= Self::ID_BASE && id < Self::ID_BASE + NAMESPACE_SPAN
    }

    /// The `nth` id of this domain, counting from 0.
    ///
    /// Callers name positions on a roster; the absolute integer is this
    /// module's business and deliberately not something a config file spells
    /// out by hand.
    fn nth(nth: u64) -> u64 {
        Self::ID_BASE + nth
    }
}

/// Width of one domain's id band.
///
/// A million ids per domain is far past any roster a human operates, so the
/// bands never have to be widened later -- and widening one is exactly the
/// change that would make them overlap.
pub const NAMESPACE_SPAN: u64 = 1_000_000;

/// The operator cohort: k-of-n, the entities that run the bridge day to day.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Owners;

/// The gate cohort: g-of-m, held by entities that are not the operators. Its
/// share enters the one-time key, so a release without it lands on a key image
/// that belongs to no output in the ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Gates;

impl ControlDomain for Owners {
    const NAME: &'static str = "owners";
    // 1 rather than 0: 0 is the Shamir interpolation point and a participant
    // issued it would hold the cohort secret outright.
    const ID_BASE: u64 = 1;
}

impl ControlDomain for Gates {
    const NAME: &'static str = "gates";
    const ID_BASE: u64 = Owners::ID_BASE + NAMESPACE_SPAN;
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Owners {}
    impl Sealed for super::Gates {}
}
