#!/usr/bin/env python3
"""Independent bounded mirror for the Bridge V2 capacity/generation stage.

This checker is intentionally written from BRIDGE_V2_TEST_PLAN.md and
BRIDGE_V2_CAPACITY_INTERFACE.md, not from BridgeCapacityV2.tla.  It is not a
cryptographic model.  It checks finite transition-system obligations for
correlated exposure, bonded release capacity, backing eligibility,
capitalization ordering, generation lifecycle, and historical bond binding.

No result is authoritative until the final runner validates configuration
parity and reconciles this graph with TLC.
"""

from __future__ import annotations

import argparse
import json
from collections import deque
from dataclasses import asdict, dataclass, replace
from typing import Callable, Iterable, Iterator, NamedTuple


GENERATIONS = (0, 1)
G0, G1 = GENERATIONS

ABSENT = "Absent"
OWNER_READY = "OwnerReady"
CAPITALIZED = "Capitalized"
ACTIVE = "Active"
DEPOSITS_CLOSED = "DepositsClosed"
DRAINED = "Drained"
DEACTIVATED = "Deactivated"
PHASES = (
    ABSENT,
    OWNER_READY,
    CAPITALIZED,
    ACTIVE,
    DEPOSITS_CLOSED,
    DRAINED,
    DEACTIVATED,
)

P_ABSENT = "Absent"
AVAILABLE = "Available"
RESERVED = "Reserved"
SPENT = "Spent"
UNSAFE = "Unsafe"
STRANDED = "Stranded"
POSITION_STATES = (P_ABSENT, AVAILABLE, RESERVED, SPENT, UNSAFE, STRANDED)

NO_PENDING = "None"
AUTHORIZED = "Authorized"
FINALIZED = "Finalized"
CANCELED = "Canceled"
PENDING_STATES = (NO_PENDING, AUTHORIZED, FINALIZED, CANCELED)

EUSD = "eUSD"
USDC = "USDC"
ETH_TO_MOB = "ETH_TO_MOB"
MOB_TO_ETH = "MOB_TO_ETH"
SHARED_DOMAIN = "shared-custody"

# Stable value positions.  G0 is the already-capitalized active generation.
# G1 has two prospective external-eUSD positions, each worth one normalized
# policy unit.  The bounded config explicitly assumes eUSD and USDC are valued
# at par for cap arithmetic; it does not prove that economic assumption.
POSITION_IDS = ("E0A", "E0B", "U0A", "U0B", "E1A", "E1B")
POSITION_GENERATION = (G0, G0, G0, G0, G1, G1)
POSITION_ASSET = (EUSD, EUSD, USDC, USDC, EUSD, EUSD)
POSITION_VALUE = (1, 1, 1, 1, 1, 1)
POSITION_DOMAINS = tuple(frozenset({SHARED_DOMAIN}) for _ in POSITION_IDS)

# Stable capacity positions / release candidates.  Direction and generation
# are attributes of a unique bucket, never separate copies of its value.
RELEASE_IDS = ("R0", "R1", "R2", "R3", "R4")
RELEASE_POSITION = (0, 2, 1, 4, 3)
RELEASE_DIRECTION = (
    ETH_TO_MOB,
    MOB_TO_ETH,
    ETH_TO_MOB,
    ETH_TO_MOB,
    MOB_TO_ETH,
)
RELEASE_GENERATION = tuple(POSITION_GENERATION[i] for i in RELEASE_POSITION)
RELEASE_VALUE = tuple(POSITION_VALUE[i] for i in RELEASE_POSITION)

BOND_IDS = ("bond-a", "bond-b")
BOND_VALUE = (2, 2)
BOUND_BONDS = frozenset(range(len(BOND_IDS)))

C_LOSS = 5
BOND_FACTOR = 2
PROOF_WINDOW_END = 2
MAX_TIME = 3

BUGS = (
    "NONE",
    "RESERVE_CAP_BYPASS",
    "OMIT_PENDING_EXPOSURE",
    "UNDERCOUNT_CROSS_DIRECTION",
    "UNDERCOUNT_CROSS_GENERATION",
    "DOUBLE_COUNT_OVERLAP_BOND",
    "UNFUNDED_SUCCESSOR",
    "FUND_BEFORE_OWNER_AUTHORITY_READY",
    "INELIGIBLE_BACKING",
    "EARLY_BOND_EXIT",
)

BUG_TARGET = {
    "RESERVE_CAP_BYPASS": "ReserveExposureBound",
    "OMIT_PENDING_EXPOSURE": "CorrelatedBondCapacityBound",
    "UNDERCOUNT_CROSS_DIRECTION": "CorrelatedBondCapacityBound",
    "UNDERCOUNT_CROSS_GENERATION": "CorrelatedBondCapacityBound",
    "DOUBLE_COUNT_OVERLAP_BOND": "CorrelatedBondCapacityBound",
    "UNFUNDED_SUCCESSOR": "CapitalizationSound",
    "FUND_BEFORE_OWNER_AUTHORITY_READY": "CapitalizationSound",
    "INELIGIBLE_BACKING": "NoIneligibleBacking",
    "EARLY_BOND_EXIT": "HistoricalBondBinding",
}


@dataclass(frozen=True, slots=True)
class State:
    phase: tuple[str, str]
    owner_ready: tuple[bool, bool]
    gate_ready: tuple[bool, bool]
    roles_ready: tuple[bool, bool]
    bond_manifest_ready: tuple[bool, bool]
    position_state: tuple[str, ...]
    capital_logged: tuple[bool, ...]
    funding_owner_valid: tuple[bool, ...]
    funding_source_valid: tuple[bool, ...]
    pending_state: tuple[str, ...]
    pending_window_end: tuple[int, ...]
    liability_backing: tuple[int, int]
    liability_admission_eligible: tuple[bool, bool]
    liability_admission_capitalized: tuple[bool, bool]
    bond_locked: tuple[bool, ...]
    bond_exit_requested: tuple[bool, ...]
    time: int
    event_kinds: frozenset[str]


INITIAL = State(
    phase=(ACTIVE, ABSENT),
    owner_ready=(True, False),
    gate_ready=(True, False),
    roles_ready=(True, False),
    bond_manifest_ready=(True, False),
    position_state=(AVAILABLE, AVAILABLE, AVAILABLE, AVAILABLE, P_ABSENT, P_ABSENT),
    capital_logged=(True, True, True, True, False, False),
    funding_owner_valid=(True, True, True, True, False, False),
    funding_source_valid=(True, True, True, True, False, False),
    pending_state=(NO_PENDING,) * len(RELEASE_IDS),
    pending_window_end=(0,) * len(RELEASE_IDS),
    liability_backing=(-1, -1),
    liability_admission_eligible=(False, False),
    liability_admission_capitalized=(False, False),
    bond_locked=(True,) * len(BOND_IDS),
    bond_exit_requested=(False,) * len(BOND_IDS),
    time=0,
    event_kinds=frozenset(),
)


class Step(NamedTuple):
    action: str
    state: State


def tuple_set(values: tuple, index: int, value) -> tuple:
    mutable = list(values)
    mutable[index] = value
    return tuple(mutable)


def add_event(st: State, kind: str) -> frozenset[str]:
    return st.event_kinds | {kind}


def live_position(index: int, st: State) -> bool:
    return st.position_state[index] not in (P_ABSENT, SPENT)


def position_eligible_for_new_backing(index: int, st: State) -> bool:
    return (
        st.position_state[index] == AVAILABLE
        and st.capital_logged[index]
        and st.funding_owner_valid[index]
        and st.funding_source_valid[index]
    )


def actual_domain_exposure(st: State, domain: str = SHARED_DOMAIN) -> int:
    # AVAILABLE and RESERVED are disjoint states.  Unsafe/Stranded remain live
    # impaired value and therefore cannot make the correlated-loss exposure
    # disappear merely by reclassification.
    return sum(
        POSITION_VALUE[i]
        for i in range(len(POSITION_IDS))
        if live_position(i, st) and domain in POSITION_DOMAINS[i]
    )


def release_within_window(index: int, st: State) -> bool:
    return (
        st.pending_state[index] in (AUTHORIZED, FINALIZED)
        and st.time <= st.pending_window_end[index]
    )


def actual_loss_capacity(st: State) -> int:
    return sum(
        RELEASE_VALUE[i]
        for i in range(len(RELEASE_IDS))
        if release_within_window(i, st)
    )


def actual_bond_capacity(st: State) -> int:
    # One unique bond position per identity, even when that identity occupies
    # multiple roles or approves both directions and generations.
    return sum(BOND_VALUE[i] for i in BOUND_BONDS if st.bond_locked[i])


def reported_loss_after_authorization(st: State, release: int, bug: str) -> int:
    prospective = [i for i in range(len(RELEASE_IDS)) if release_within_window(i, st)]
    prospective.append(release)
    unique = set(prospective)
    if bug == "OMIT_PENDING_EXPOSURE":
        unique = {release}
    elif bug == "UNDERCOUNT_CROSS_DIRECTION":
        direction = RELEASE_DIRECTION[release]
        unique = {i for i in unique if RELEASE_DIRECTION[i] == direction}
    elif bug == "UNDERCOUNT_CROSS_GENERATION":
        generation = RELEASE_GENERATION[release]
        unique = {i for i in unique if RELEASE_GENERATION[i] == generation}
    return sum(RELEASE_VALUE[i] for i in unique)


def reported_bond_capacity(st: State, bug: str) -> int:
    unique = actual_bond_capacity(st)
    if bug == "DOUBLE_COUNT_OVERLAP_BOND":
        # The erroneous implementation counts the same two identity bonds once
        # for each of two overlapping approval roles.
        return 2 * unique
    return unique


def logged_capital(st: State, generation: int) -> int:
    return sum(
        POSITION_VALUE[i]
        for i in range(len(POSITION_IDS))
        if POSITION_GENERATION[i] == generation
        and st.capital_logged[i]
        and st.funding_source_valid[i]
    )


def admitted_liabilities(st: State, generation: int) -> int:
    return sum(
        1
        for backing in st.liability_backing
        if backing >= 0 and POSITION_GENERATION[backing] == generation
    )


def live_generation_inventory(st: State, generation: int) -> int:
    return sum(
        POSITION_VALUE[i]
        for i in range(len(POSITION_IDS))
        if POSITION_GENERATION[i] == generation and live_position(i, st)
    )


def live_generation_pending(st: State, generation: int) -> int:
    return sum(
        RELEASE_VALUE[i]
        for i in range(len(RELEASE_IDS))
        if RELEASE_GENERATION[i] == generation and release_within_window(i, st)
    )


def inv_type_ok(st: State) -> bool:
    return (
        len(st.phase) == 2
        and all(p in PHASES for p in st.phase)
        and len(st.position_state) == len(POSITION_IDS)
        and all(p in POSITION_STATES for p in st.position_state)
        and len(st.pending_state) == len(RELEASE_IDS)
        and all(p in PENDING_STATES for p in st.pending_state)
        and len(st.pending_window_end) == len(RELEASE_IDS)
        and len(st.bond_locked) == len(BOND_IDS)
        and len(st.bond_exit_requested) == len(BOND_IDS)
        and 0 <= st.time <= MAX_TIME
        and all(-1 <= i < len(POSITION_IDS) for i in st.liability_backing)
    )


def inv_reserve_exposure_bound(st: State) -> bool:
    return actual_domain_exposure(st) <= C_LOSS


def inv_correlated_bond_capacity_bound(st: State) -> bool:
    return actual_bond_capacity(st) >= BOND_FACTOR * actual_loss_capacity(st)


def inv_no_ineligible_backing(st: State) -> bool:
    return all(
        backing < 0 or st.liability_admission_eligible[i]
        for i, backing in enumerate(st.liability_backing)
    )


def inv_capitalization_sound(st: State) -> bool:
    for i in range(len(POSITION_IDS)):
        if st.position_state[i] != P_ABSENT:
            if not (
                st.capital_logged[i]
                and st.funding_owner_valid[i]
                and st.funding_source_valid[i]
            ):
                return False
    for g in GENERATIONS:
        if st.phase[g] in (ACTIVE, DEPOSITS_CLOSED, DRAINED, DEACTIVATED):
            if not (
                st.owner_ready[g]
                and st.gate_ready[g]
                and st.roles_ready[g]
                and st.bond_manifest_ready[g]
                and logged_capital(st, g) > 0
            ):
                return False
        if logged_capital(st, g) < admitted_liabilities(st, g):
            return False
    return all(
        backing < 0 or st.liability_admission_capitalized[i]
        for i, backing in enumerate(st.liability_backing)
    )


def inv_generation_lifecycle_sound(st: State) -> bool:
    for g in GENERATIONS:
        phase = st.phase[g]
        if phase in (ACTIVE, DEPOSITS_CLOSED, DRAINED, DEACTIVATED):
            if not (
                st.owner_ready[g]
                and st.gate_ready[g]
                and st.roles_ready[g]
                and st.bond_manifest_ready[g]
            ):
                return False
        if phase in (DRAINED, DEACTIVATED):
            if live_generation_inventory(st, g) != 0:
                return False
            if live_generation_pending(st, g) != 0:
                return False
    return True


def inv_historical_bond_binding(st: State) -> bool:
    for r in range(len(RELEASE_IDS)):
        if release_within_window(r, st):
            if not all(st.bond_locked[b] for b in BOUND_BONDS):
                return False
    return True


INVARIANTS: tuple[tuple[str, Callable[[State], bool]], ...] = (
    ("TypeOK", inv_type_ok),
    ("ReserveExposureBound", inv_reserve_exposure_bound),
    ("CorrelatedBondCapacityBound", inv_correlated_bond_capacity_bound),
    ("NoIneligibleBacking", inv_no_ineligible_backing),
    ("CapitalizationSound", inv_capitalization_sound),
    ("GenerationLifecycleSound", inv_generation_lifecycle_sound),
    ("HistoricalBondBinding", inv_historical_bond_binding),
)


def violations(st: State) -> tuple[str, ...]:
    return tuple(name for name, predicate in INVARIANTS if not predicate(st))


def successors(st: State, bug: str) -> Iterator[Step]:
    # Prepare exact ownership authority for the successor.  In the injected
    # fund-before-owner trace this may happen after capitalization, preserving
    # the historical fact that funding itself was premature.
    if not st.owner_ready[G1] and st.phase[G1] in (ABSENT, CAPITALIZED):
        new_phase = OWNER_READY if st.phase[G1] == ABSENT else st.phase[G1]
        yield Step(
            "OwnerAuthorityReady(G1)",
            replace(
                st,
                phase=tuple_set(st.phase, G1, new_phase),
                owner_ready=tuple_set(st.owner_ready, G1, True),
                event_kinds=add_event(st, "OWNER_AUTHORITY_READY"),
            ),
        )

    # Gate/role manifests are separate readiness facts, not inferred from
    # Capitalized.  They may be prepared before or after capitalization.
    if (
        st.owner_ready[G1]
        and not st.gate_ready[G1]
        and st.phase[G1] in (OWNER_READY, CAPITALIZED)
    ):
        yield Step(
            "GateAndRoleAuthorityReady(G1)",
            replace(
                st,
                gate_ready=tuple_set(st.gate_ready, G1, True),
                roles_ready=tuple_set(st.roles_ready, G1, True),
                event_kinds=add_event(st, "GATE_AUTHORITY_READY"),
            ),
        )

    if (
        st.owner_ready[G1]
        and not st.bond_manifest_ready[G1]
        and st.phase[G1] in (OWNER_READY, CAPITALIZED)
    ):
        yield Step(
            "LockBondManifest(G1)",
            replace(
                st,
                bond_manifest_ready=tuple_set(st.bond_manifest_ready, G1, True),
                event_kinds=add_event(st, "LOCK_BOND_MANIFEST"),
            ),
        )

    # External eUSD capitalization.  There is deliberately no customer-USDC
    # transition capable of setting capital_logged for a G1 eUSD position.
    for position in (4, 5):
        if st.position_state[position] != P_ABSENT:
            continue
        phase_ok = st.phase[G1] in (OWNER_READY, CAPITALIZED)
        owner_ok = st.owner_ready[G1]
        premature = (
            bug == "FUND_BEFORE_OWNER_AUTHORITY_READY"
            and st.phase[G1] == ABSENT
            and not st.owner_ready[G1]
        )
        if not ((phase_ok and owner_ok) or premature):
            continue
        projected = actual_domain_exposure(st) + POSITION_VALUE[position]
        if projected > C_LOSS and bug != "RESERVE_CAP_BYPASS":
            continue
        yield Step(
            f"CapitalizeExternalEusd({POSITION_IDS[position]})",
            replace(
                st,
                phase=tuple_set(st.phase, G1, CAPITALIZED),
                position_state=tuple_set(st.position_state, position, AVAILABLE),
                capital_logged=tuple_set(st.capital_logged, position, True),
                funding_owner_valid=tuple_set(
                    st.funding_owner_valid, position, st.owner_ready[G1]
                ),
                funding_source_valid=tuple_set(st.funding_source_valid, position, True),
                event_kinds=add_event(st, "CAPITALIZE_EXTERNAL_EUSD"),
            ),
        )

    if st.phase[G1] in (OWNER_READY, CAPITALIZED):
        exact_manifests = (
            st.owner_ready[G1]
            and st.gate_ready[G1]
            and st.roles_ready[G1]
            and st.bond_manifest_ready[G1]
        )
        has_capital = logged_capital(st, G1) > 0
        if exact_manifests and (
            (st.phase[G1] == CAPITALIZED and has_capital)
            or (bug == "UNFUNDED_SUCCESSOR" and not has_capital)
        ):
            yield Step(
                "ActivateGeneration(G1)",
                replace(
                    st,
                    phase=tuple_set(st.phase, G1, ACTIVE),
                    event_kinds=add_event(st, "ACTIVATE_GENERATION"),
                ),
            )

    # Admit one liability per generation.  The state stores whether eligibility
    # and sufficient logged capital were true at admission, so a later incident
    # does not retroactively falsify an honest historical check.
    for liability in range(2):
        if st.liability_backing[liability] >= 0:
            continue
        generation = liability
        if st.phase[generation] != ACTIVE:
            continue
        for position in range(len(POSITION_IDS)):
            if POSITION_GENERATION[position] != generation:
                continue
            eligible = position_eligible_for_new_backing(position, st)
            if not eligible and bug != "INELIGIBLE_BACKING":
                continue
            enough_capital = logged_capital(st, generation) >= (
                admitted_liabilities(st, generation) + 1
            )
            if not enough_capital:
                continue
            yield Step(
                f"AdmitLiability(L{liability},{POSITION_IDS[position]})",
                replace(
                    st,
                    liability_backing=tuple_set(
                        st.liability_backing, liability, position
                    ),
                    liability_admission_eligible=tuple_set(
                        st.liability_admission_eligible, liability, eligible
                    ),
                    liability_admission_capitalized=tuple_set(
                        st.liability_admission_capitalized,
                        liability,
                        enough_capital
                        and st.owner_ready[generation]
                        and st.gate_ready[generation]
                        and st.roles_ready[generation]
                        and st.bond_manifest_ready[generation],
                    ),
                    event_kinds=add_event(st, "ADMIT_LIABILITY"),
                ),
            )

    # One incident-classification transition is enough to make ineligible
    # admission representable without exploding the state space.
    if st.position_state[0] == AVAILABLE:
        yield Step(
            "DeclareUnsafe(E0A)",
            replace(
                st,
                position_state=tuple_set(st.position_state, 0, UNSAFE),
                event_kinds=add_event(st, "DECLARE_UNSAFE"),
            ),
        )

    # Authorize pending releases only while the selected generation is active.
    # The bug affects the guard's reported arithmetic; the invariant always
    # recomputes the actual unique coalition capacity.
    for release in range(len(RELEASE_IDS)):
        if st.pending_state[release] != NO_PENDING:
            continue
        position = RELEASE_POSITION[release]
        generation = RELEASE_GENERATION[release]
        if st.phase[generation] != ACTIVE:
            continue
        if st.position_state[position] != AVAILABLE:
            continue
        if not all(st.bond_locked[b] for b in BOUND_BONDS):
            continue
        reported_l = reported_loss_after_authorization(st, release, bug)
        reported_b = reported_bond_capacity(st, bug)
        if reported_b < BOND_FACTOR * reported_l:
            continue
        yield Step(
            f"AuthorizePending({RELEASE_IDS[release]})",
            replace(
                st,
                position_state=tuple_set(st.position_state, position, RESERVED),
                pending_state=tuple_set(st.pending_state, release, AUTHORIZED),
                pending_window_end=tuple_set(
                    st.pending_window_end, release, PROOF_WINDOW_END
                ),
                event_kinds=add_event(st, "AUTHORIZE_PENDING_RELEASE"),
            ),
        )

    for release in range(len(RELEASE_IDS)):
        if st.pending_state[release] != AUTHORIZED:
            continue
        position = RELEASE_POSITION[release]
        yield Step(
            f"FinalizeRelease({RELEASE_IDS[release]})",
            replace(
                st,
                position_state=tuple_set(st.position_state, position, SPENT),
                pending_state=tuple_set(st.pending_state, release, FINALIZED),
                event_kinds=add_event(st, "FINALIZE_RELEASE"),
            ),
        )
        yield Step(
            f"CancelPending({RELEASE_IDS[release]})",
            replace(
                st,
                position_state=tuple_set(st.position_state, position, AVAILABLE),
                pending_state=tuple_set(st.pending_state, release, CANCELED),
                event_kinds=add_event(st, "CANCEL_PENDING_RELEASE"),
            ),
        )

    if st.phase[G1] == ACTIVE:
        yield Step(
            "CloseGenerationDeposits(G1)",
            replace(
                st,
                phase=tuple_set(st.phase, G1, DEPOSITS_CLOSED),
                event_kinds=add_event(st, "CLOSE_GENERATION_DEPOSITS"),
            ),
        )

    if (
        st.phase[G1] == DEPOSITS_CLOSED
        and live_generation_inventory(st, G1) == 0
        and live_generation_pending(st, G1) == 0
    ):
        yield Step(
            "DrainGeneration(G1)",
            replace(
                st,
                phase=tuple_set(st.phase, G1, DRAINED),
                event_kinds=add_event(st, "DRAIN_GENERATION"),
            ),
        )

    if st.phase[G1] == DRAINED:
        yield Step(
            "DeactivateGeneration(G1)",
            replace(
                st,
                phase=tuple_set(st.phase, G1, DEACTIVATED),
                event_kinds=add_event(st, "DEACTIVATE_GENERATION"),
            ),
        )

    if st.time < MAX_TIME:
        yield Step("AdvanceTime", replace(st, time=st.time + 1))

    for bond in range(len(BOND_IDS)):
        if st.bond_locked[bond] and not st.bond_exit_requested[bond]:
            yield Step(
                f"RequestBondExit({BOND_IDS[bond]})",
                replace(
                    st,
                    bond_exit_requested=tuple_set(
                        st.bond_exit_requested, bond, True
                    ),
                    event_kinds=add_event(st, "REQUEST_BOND_EXIT"),
                ),
            )
        if st.bond_locked[bond] and st.bond_exit_requested[bond]:
            historical_window_open = any(
                release_within_window(r, st) for r in range(len(RELEASE_IDS))
            )
            if not historical_window_open or bug == "EARLY_BOND_EXIT":
                yield Step(
                    f"CompleteBondExit({BOND_IDS[bond]})",
                    replace(
                        st,
                        bond_locked=tuple_set(st.bond_locked, bond, False),
                        event_kinds=add_event(st, "COMPLETE_BOND_EXIT"),
                    ),
                )


def state_key(st: State) -> State:
    return st


@dataclass(slots=True)
class Exploration:
    states: int
    violation: str | None
    violation_state: State | None
    trace: list[str]
    witnesses: frozenset[str]


def witness_names(st: State) -> set[str]:
    found: set[str] = set()
    if actual_domain_exposure(st) == C_LOSS:
        found.add("ReserveCapBoundary")
    if actual_bond_capacity(st) == BOND_FACTOR * actual_loss_capacity(st) and actual_loss_capacity(st) > 0:
        found.add("BondCapacityBoundary")
    if st.phase[G1] == ACTIVE and logged_capital(st, G1) > 0:
        found.add("CapitalizedSuccessorActive")
    if st.phase[G1] == DEACTIVATED:
        found.add("GenerationDeactivated")
    if st.position_state[0] == UNSAFE:
        found.add("UnsafeInventoryRepresentable")
    directions = {
        RELEASE_DIRECTION[r]
        for r in range(len(RELEASE_IDS))
        if release_within_window(r, st)
    }
    if directions == {ETH_TO_MOB, MOB_TO_ETH}:
        found.add("CrossDirectionCapacityCombined")
    return found


REQUIRED_BASELINE_WITNESSES = frozenset(
    {
        "ReserveCapBoundary",
        "BondCapacityBoundary",
        "CapitalizedSuccessorActive",
        "GenerationDeactivated",
        "UnsafeInventoryRepresentable",
        "CrossDirectionCapacityCombined",
    }
)


def explore(bug: str, stop_on_violation: bool = True) -> Exploration:
    if bug not in BUGS:
        raise ValueError(f"unknown bug {bug}")
    queue: deque[State] = deque([INITIAL])
    parent: dict[State, tuple[State | None, str]] = {INITIAL: (None, "Init")}
    seen: set[State] = {INITIAL}
    witnesses: set[str] = set()

    while queue:
        st = queue.popleft()
        witnesses.update(witness_names(st))
        bad = violations(st)
        if bad:
            target = BUG_TARGET.get(bug)
            chosen = target if target in bad else bad[0]
            trace: list[str] = []
            cursor: State | None = st
            while cursor is not None:
                previous, action = parent[cursor]
                trace.append(action)
                cursor = previous
            trace.reverse()
            if stop_on_violation:
                return Exploration(len(seen), chosen, st, trace, frozenset(witnesses))
        for step in successors(st, bug):
            nxt = state_key(step.state)
            if nxt not in seen:
                seen.add(nxt)
                parent[nxt] = (st, step.action)
                queue.append(nxt)

    return Exploration(len(seen), None, None, [], frozenset(witnesses))


def self_test() -> None:
    assert len(set(POSITION_IDS)) == len(POSITION_IDS)
    assert len(set(RELEASE_IDS)) == len(RELEASE_IDS)
    assert len(set(BOND_IDS)) == len(BOND_IDS)
    assert actual_domain_exposure(INITIAL) == 4
    assert actual_bond_capacity(INITIAL) == 4
    assert actual_loss_capacity(INITIAL) == 0
    assert logged_capital(INITIAL, G0) == 4
    assert logged_capital(INITIAL, G1) == 0
    assert not violations(INITIAL)

    # Cross-role bond dedup: the erroneous reported value doubles, the actual
    # value remains the unique sum.
    assert reported_bond_capacity(INITIAL, "NONE") == 4
    assert reported_bond_capacity(INITIAL, "DOUBLE_COUNT_OVERLAP_BOND") == 8

    # Raw asset units are tagged.  The bounded normalized-value assumption is
    # explicit in POSITION_VALUE rather than accidental tuple summation.
    assert {EUSD, USDC} == set(POSITION_ASSET)
    assert all(v == 1 for v in POSITION_VALUE)


def state_as_json(st: State | None):
    if st is None:
        return None
    data = asdict(st)
    data["event_kinds"] = sorted(st.event_kinds)
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bug", choices=BUGS, default="NONE")
    parser.add_argument("--count-only", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("BridgeCapacityV2 Python self-test: PASS")
        return 0

    result = explore(args.bug)
    expected = BUG_TARGET.get(args.bug)

    if args.count_only:
        if result.violation is not None:
            return 1
        print(result.states)
        return 0

    payload = {
        "bug": args.bug,
        "states": result.states,
        "violation": result.violation,
        "expected_violation": expected,
        "trace": result.trace,
        "violation_state": state_as_json(result.violation_state),
        "witnesses": sorted(result.witnesses),
        "missing_baseline_witnesses": sorted(
            REQUIRED_BASELINE_WITNESSES - result.witnesses
        ) if args.bug == "NONE" else [],
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))

    if args.bug == "NONE":
        return int(
            result.violation is not None
            or not REQUIRED_BASELINE_WITNESSES.issubset(result.witnesses)
        )
    return int(result.violation != expected)


if __name__ == "__main__":
    raise SystemExit(main())
