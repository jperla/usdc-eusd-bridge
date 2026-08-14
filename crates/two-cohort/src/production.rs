//! The decided production access structure.
//!
//! Written as code rather than left in a document because a parameter that
//! lives only in prose drifts from the parameter the signer actually uses, and
//! nothing notices. Anything that builds a production composite key should
//! take its shape from here.
//!
//! **Decided: 3 operators at 2-of-3, and 1 independent gate.** Four entities;
//! three must be compromised before funds can move.
//!
//! Why four and not three, since three was the stated constraint: three
//! entities *can* reach the same compromise threshold, as 2-of-2 operators
//! plus a gate. The fourth entity buys tolerance of one lost OPERATOR key.
//!
//! It is not a free win, and the trade runs both ways. Both configurations
//! have `T = 3`, but they differ in how MANY coalitions of that size work:
//! `2-of-2 + gate` has exactly one, `{O1,O2,G}`; `2-of-3 + gate` has three.
//! The extra operator therefore does not raise the cost of the cheapest
//! targeted attack at all -- it adds attack paths. Under independent
//! compromise at probability `p` per principal: `p^3` against `3p^3 - 2p^4`.
//!
//! Neither configuration tolerates losing the GATE. It is indispensable in
//! both, and there is deliberately no recovery path, so losing it freezes the
//! funds permanently. Tolerating the loss of ANY one principal -- gate
//! included -- is impossible at four entities without the structure
//! collapsing to a plain `3-of-4`; a nonredundant role split with that
//! property needs five.
//!
//! `T` records minimum coalition SIZE and nothing else: not how many such
//! coalitions exist, not which principals are critical, not correlation
//! between them, and not availability. Reading it as a general key-theft or
//! probabilistic security threshold overstates it.
//!
//! Participant ids come from each domain's own band, which `ControlDomain`
//! enforces in the type system — a subset drawn from one cohort cannot be
//! accepted by the other. That is not cosmetic: with both rosters over the
//! same ids, every owner subset is also a qualifying gate subset, and review
//! found exactly that defect in the spike this crate was promoted from.
//!
//! What this module does NOT encode, because it is not a number: whether the
//! gate is genuinely a separate compromise domain. A gate an operator
//! organisation administers, or can recover from, is the same domain in
//! different hardware, and the whole structure collapses to an ordinary
//! `max(k,g)`-of-n multisig. That is an organisational fact and no test here
//! can see it.

use crate::{CohortSpec, Gates, Owners};

/// Operators: any 2 of 3.
pub const OWNER_THRESHOLD: usize = 2;
pub const OWNER_COUNT: usize = 3;

/// Gates: the single independent gate must sign.
pub const GATE_THRESHOLD: usize = 1;
pub const GATE_COUNT: usize = 1;

/// Distinct compromise domains in the decided structure.
pub const ENTITIES: usize = OWNER_COUNT + GATE_COUNT;

/// Principals that must be compromised before funds can move:
/// `T = max(k, g, k + g - r)` with no overlap, so `k + g`.
pub const COMPROMISE_THRESHOLD: usize = OWNER_THRESHOLD + GATE_THRESHOLD;

pub fn owners() -> CohortSpec<Owners> {
    CohortSpec::<Owners>::sequential(OWNER_THRESHOLD, OWNER_COUNT)
}

pub fn gates() -> CohortSpec<Gates> {
    CohortSpec::<Gates>::sequential(GATE_THRESHOLD, GATE_COUNT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_decided_structure_is_two_of_three_owners_and_one_gate() {
        assert_eq!(owners().threshold(), 2);
        assert_eq!(owners().ids().len(), 3);
        assert_eq!(gates().threshold(), 1);
        assert_eq!(gates().ids().len(), 1);
        assert_eq!(ENTITIES, 4);
    }

    #[test]
    fn three_principals_must_be_compromised() {
        // T = max(k, g, k + g - r), r = 0 because the rosters are disjoint.
        // Stated here as the consequence a reader cares about rather than as
        // the formula; AccessStructure.tla proves the formula and its
        // tightness.
        assert_eq!(COMPROMISE_THRESHOLD, 3);
        assert!(
            COMPROMISE_THRESHOLD > owners().threshold(),
            "the gate must raise the bar above an operator quorum alone, or it \
             is not doing anything"
        );
    }

    #[test]
    fn one_lost_operator_key_is_survivable_and_one_lost_gate_key_is_not() {
        // This asymmetry is the reason for the fourth entity, and the reason
        // gate key management needs the same rigor as operator key management
        // despite there being only one of them.
        assert!(
            owners().ids().len() > owners().threshold(),
            "operators must tolerate one loss"
        );
        assert_eq!(
            gates().ids().len(),
            gates().threshold(),
            "the gate tolerates NO loss: losing it loses the funds, and there \
             is deliberately no recovery path"
        );
    }

    #[test]
    fn the_cohorts_occupy_disjoint_id_ranges() {
        let o: Vec<u64> = owners().ids().to_vec();
        let g: Vec<u64> = gates().ids().to_vec();
        assert!(
            o.iter().all(|i| !g.contains(i)),
            "overlapping ids let a gate subset be silently replaced by an \
             owner one: {o:?} vs {g:?}"
        );
    }
}
