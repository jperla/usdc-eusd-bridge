#!/usr/bin/env python3
"""Independent bounded reference model for the MobileCoin bridge v3 draft.

This file is deliberately independent of the TLA+ implementation.  It models
the protocol state transitions with immutable Python values, explores a small
finite domain with breadth-first search, and runs focused defect selectors.

It is a reference/state model, not cryptographic code and not an unbounded
proof.  Signatures, finality proofs, authenticated dictionaries, and
ReserveInputProofs are represented by typed validity tokens at their protocol
boundaries.  The model's job is to test lifecycle, conservation, ordering,
accountability, and chain-local composition claims.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from collections import Counter, deque
from dataclasses import asdict, dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Iterator, Optional, Sequence


ETHEREUM = "ETHEREUM"
MOBILECOIN = "MOBILECOIN"
USDC = "USDC"
EUSD = "EUSD"


class Reject(Exception):
    """A closed protocol guard rejected a proposed transition."""


class Defect(str, Enum):
    NONE = "NONE"
    DOUBLE_RESERVATION = "DOUBLE_RESERVATION"
    RESERVE_BYPASS = "RESERVE_BYPASS"
    UNSAFE_CANCELLATION = "UNSAFE_CANCELLATION"
    NULLIFIER_REPLAY = "NULLIFIER_REPLAY"
    LEASE_REPLAY = "LEASE_REPLAY"
    SERIAL_DRAIN = "SERIAL_DRAIN"
    FALSE_SOURCE_TRUTH_GUARD = "FALSE_SOURCE_TRUTH_GUARD"
    UNDER_SLASH = "UNDER_SLASH"
    CHALLENGER_MISPUNISH = "CHALLENGER_MISPUNISH"
    GLOBAL_PAUSE_COUPLING = "GLOBAL_PAUSE_COUPLING"


@dataclass(frozen=True, order=True)
class Intent:
    id: str
    liability_id: str
    source_id: str
    nullifier: str
    direction: str
    destination_chain: str
    destination_asset: str
    amount: int
    lot_id: str
    lease_tag: str
    ring_binding: str
    wardens: tuple[str, ...]
    accounts: tuple[str, ...]


@dataclass(frozen=True, order=True)
class Lot:
    id: str
    chain: str
    asset: str
    amount: int
    status: str  # AVAILABLE | RESERVED | SPENT
    ref: str = ""
    provenance: str = "SEED"


@dataclass(frozen=True, order=True)
class SourcePosition:
    id: str
    chain: str
    asset: str
    amount: int
    liability_id: str
    status: str  # ENCUMBERED | AVAILABLE
    local_finalized: bool = False
    promoted_lot_id: str = ""


@dataclass(frozen=True, order=True)
class Liability:
    id: str
    intent_id: str
    nullifier: str
    status: str  # OPEN | CAPACITY_RESERVED | SETTLED
    reservation_id: str = ""
    release_id: str = ""


@dataclass(frozen=True, order=True)
class ClaimLock:
    nullifier: str
    liability_id: str
    status: str  # BOUND | SETTLED
    release_id: str = ""


@dataclass(frozen=True, order=True)
class Reservation:
    id: str
    liability_id: str
    intent_id: str
    nullifier: str
    lot_id: str
    lease_tag: str
    destination_chain: str
    amount: int
    status: str  # LIVE | FINALIZED | CANCELLED
    consensus_predecessor: bool
    release_id: str = ""
    cancel_proof_valid: Optional[bool] = None


@dataclass(frozen=True, order=True)
class Nullifier:
    id: str
    status: str  # FREE | RESERVED | CONSUMED
    ref: str = ""


@dataclass(frozen=True, order=True)
class Lease:
    tag: str
    status: str  # FREE | LIVE | CONSUMED
    ref: str = ""
    ring_binding: str = ""


@dataclass(frozen=True, order=True)
class Risk:
    id: str  # reservation id is the stable risk-position id
    reservation_id: str
    destination_chain: str
    amount: int
    status: str  # CAPACITY_RESERVED | FINALIZED_UNCLEARED | CLEARED | CANCELLED
    release_id: str = ""


@dataclass(frozen=True, order=True)
class Release:
    id: str
    reservation_id: str
    liability_id: str
    intent_id: str
    nullifier: str
    lease_tag: str
    destination_chain: str
    asset: str
    amount: int
    wardens: tuple[str, ...]
    accounts: tuple[str, ...]
    loss_fixed: Optional[int] = None


@dataclass(frozen=True, order=True)
class Bond:
    identity: str
    face: int
    status: str  # LOCKED | FROZEN | DISTRIBUTED
    incident_id: str = ""
    debited: int = 0


@dataclass(frozen=True, order=True)
class Freeze:
    incident_id: str
    release_ids: tuple[str, ...]
    culprits: tuple[str, ...]
    held: tuple[tuple[str, int], ...]


@dataclass(frozen=True, order=True)
class Distribution:
    incident_id: str
    held_total: int
    proof_claim: int
    proof_cost_cap: int
    bounty_rate_num: int
    bounty_rate_den: int
    bounty_cap: int
    restitution: int
    proof_cost: int
    bounty: int
    insurance: int
    debits: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class State:
    lots: tuple[Lot, ...]
    sources: tuple[SourcePosition, ...]
    liabilities: tuple[Liability, ...]
    claim_locks: tuple[ClaimLock, ...]
    reservations: tuple[Reservation, ...]
    nullifiers: tuple[Nullifier, ...]
    leases: tuple[Lease, ...]
    risks: tuple[Risk, ...]
    releases: tuple[Release, ...]
    objective_truth: frozenset[str]
    nullifier_consumptions: tuple[tuple[str, str], ...]
    lease_consumptions: tuple[tuple[str, str], ...]
    paused_chains: frozenset[str]
    pause_events: frozenset[str]
    bonds: tuple[Bond, ...]
    freezes: tuple[Freeze, ...]
    distributions: tuple[Distribution, ...]
    challenger_applied: bool
    challenger_operator_effect: bool
    rotated_chains: frozenset[str]


# B0 uses 3-member, 2-of-3 WARDEN and ACCOUNT rosters.  The executable
# approvals below select one valid 2-member quorum in each role and exercise
# the B0 cross-role identity-overlap fixture.  Role signatures remain abstract
# and distinct even for the shared physical identity; its bond is counted once.
WARDEN_ROSTER = ("operator-overlap", "warden-2", "warden-3")
ACCOUNT_ROSTER = ("operator-overlap", "account-2", "account-3")
WARDENS = ("operator-overlap", "warden-2")
ACCOUNTS = ("operator-overlap", "account-2")


B0_PROFILE: dict[str, object] = {
    "chains": [ETHEREUM, MOBILECOIN],
    "directions": ["ETH_TO_MOB", "MOB_TO_ETH"],
    "assets": [USDC, EUSD],
    "generations": ["g0", "g1"],
    "policy_epochs_per_chain": 2,
    "warden_roster": {"n": 3, "k": 2},
    "account_roster": {"n": 3, "k": 2},
    "owner_mlsag_roster": {"n": 3, "k": 2},
    "frost_gate_roster": {"n": 3, "k": 2},
    "ethereum_execution_roster": {"n": 3, "k": 2},
    "source_events_per_direction_max": 2,
    "liabilities_per_direction_max": 2,
    "capacity_lots_per_asset_generation": 2,
    "principal_units": [0, 1, 2],
    "local_allocation_per_direction": 2,
    "common_risk_cap": 2,
    "input_lease_tags": 2,
    "local_block_heights": [0, 1, 2, 3],
    "accounting_backends": ["ZK_V1", "SGX_V1"],
    "source_adapter_profiles": ["V2_AUTO", "V1_CONTRACTUAL"],
    "fault_classes": ["FALSE_SOURCE", "EQUIVOCATION"],
    "verdict_classes": ["OPERATOR_FAULT", "CHALLENGER_FAULT"],
}


MODEL_PROFILE_DEVIATIONS = [
    "Generations and epoch rotation are not enumerated; only chain-local pause is modeled.",
    "Owner/MLSAG, FROST-gate, and Ethereum execution quorums are typed validity tokens, not roster-state variables.",
    "Principal transitions use one unit; 0 and 2 appear only as boundary/cap values.",
    "Capacity lots are not indexed by generation; the focused domain has two MobileCoin seed lots and one promoted Ethereum lot.",
    "Prior-block ordering is represented by a distinct committed reservation predecessor marker rather than heights 0..3.",
    "Risk-window completion and admissible loss evidence are typed clearance tokens; their wall-clock/finality schedules are not enumerated.",
    "Accounting backends and V1/V2 source adapters are closed validity-token boundaries, not independently enumerated choices.",
    "The focused exhaustive relation covers FALSE_SOURCE; EQUIVOCATION culprit intersections are outside this executable subset.",
    "False releases sharing this one physical culprit-bond set aggregate into one incident; partially overlapping culprit sets and multi-incident apportionment are not modeled.",
    "Common risk is measured in normalized one-unit principal equivalents; production valuation, haircut, and price-oracle arithmetic are outside this focused relation.",
    "The model covers 10 focused selectors, not the contract's full 28-event/176-selector acceptance surface.",
]


INTENTS: dict[str, Intent] = {
    "A": Intent(
        "A", "L_A", "S_USDC_DEPOSIT", "N_USDC_DEPOSIT", "ETH_TO_MOB",
        MOBILECOIN, EUSD, 1, "LOT_MOB_SEED", "TAG_A", "RING_A",
        WARDENS, ACCOUNTS,
    ),
    "F": Intent(
        "F", "L_FALSE", "S_FALSE_USDC", "N_FALSE_USDC", "ETH_TO_MOB",
        MOBILECOIN, EUSD, 1, "LOT_MOB_FALSE", "TAG_F", "RING_F",
        WARDENS, ACCOUNTS,
    ),
    "B": Intent(
        "B", "L_B", "S_EUSD_RETURN", "N_EUSD_RETURN", "MOB_TO_ETH",
        ETHEREUM, USDC, 1, "PROMOTED:S_USDC_DEPOSIT", "", "",
        WARDENS, ACCOUNTS,
    ),
    "C": Intent(
        "C", "L_CANCEL", "S_CANCEL", "N_CANCEL", "ETH_TO_MOB",
        MOBILECOIN, EUSD, 1, "LOT_MOB_CANCEL", "TAG_C", "RING_C",
        WARDENS, ACCOUNTS,
    ),
    "X": Intent(
        "X", "L_X", "S_X", "N_X", "ETH_TO_MOB",
        MOBILECOIN, EUSD, 1, "LOT_SERIAL_X", "TAG_X", "RING_X",
        WARDENS, ACCOUNTS,
    ),
    "Y": Intent(
        "Y", "L_Y", "S_Y", "N_Y", "ETH_TO_MOB",
        MOBILECOIN, EUSD, 1, "LOT_SERIAL_Y", "TAG_Y", "RING_Y",
        WARDENS, ACCOUNTS,
    ),
}


SOURCE_FIELDS: dict[str, tuple[str, str, int]] = {
    "S_USDC_DEPOSIT": (ETHEREUM, USDC, 1),
    "S_EUSD_RETURN": (MOBILECOIN, EUSD, 1),
    "S_CANCEL": (ETHEREUM, USDC, 1),
    "S_X": (ETHEREUM, USDC, 1),
    "S_Y": (ETHEREUM, USDC, 1),
}


def _sorted(items: Iterable[object]) -> tuple:
    return tuple(sorted(items))


def _one(items: Sequence, attr: str, value: str):
    found = [item for item in items if getattr(item, attr) == value]
    if len(found) != 1:
        raise Reject(f"expected exactly one {attr}={value}; found {len(found)}")
    return found[0]


def _maybe(items: Sequence, attr: str, value: str):
    found = [item for item in items if getattr(item, attr) == value]
    if len(found) > 1:
        raise Reject(f"non-unique {attr}={value}")
    return found[0] if found else None


def _put(items: Sequence, new_item, attr: str = "id") -> tuple:
    key = getattr(new_item, attr)
    result = [x for x in items if getattr(x, attr) != key]
    result.append(new_item)
    return _sorted(result)


def _intent_for_liability(state: State, liability_id: str) -> Intent:
    liability = _one(state.liabilities, "id", liability_id)
    return INTENTS[liability.intent_id]


def _freeze_for_release(state: State, release_id: str) -> Freeze:
    found = [freeze for freeze in state.freezes if release_id in freeze.release_ids]
    if len(found) != 1:
        raise Reject(
            f"expected exactly one freeze covering release_id={release_id}; "
            f"found {len(found)}"
        )
    return found[0]


def initial_state(
    *,
    include_false: bool = True,
    include_cancel: bool = False,
    serial_profile: bool = False,
) -> State:
    if serial_profile:
        lots = (
            Lot("LOT_SERIAL_X", MOBILECOIN, EUSD, 1, "AVAILABLE"),
            Lot("LOT_SERIAL_Y", MOBILECOIN, EUSD, 1, "AVAILABLE"),
        )
        nullifier_intents = ("X", "Y")
    else:
        lots_list = [Lot("LOT_MOB_SEED", MOBILECOIN, EUSD, 1, "AVAILABLE")]
        nullifier_intents = ["A", "B"]
        if include_false:
            lots_list.append(Lot("LOT_MOB_FALSE", MOBILECOIN, EUSD, 1, "AVAILABLE"))
            nullifier_intents.append("F")
        if include_cancel:
            lots_list.append(Lot("LOT_MOB_CANCEL", MOBILECOIN, EUSD, 1, "AVAILABLE"))
            nullifier_intents.append("C")
        lots = tuple(lots_list)

    nullifiers = tuple(
        Nullifier(INTENTS[i].nullifier, "FREE") for i in nullifier_intents
    )
    leases = tuple(
        Lease(INTENTS[i].lease_tag, "FREE", ring_binding=INTENTS[i].ring_binding)
        for i in nullifier_intents
        if INTENTS[i].lease_tag
    )
    identities = sorted(set(WARDEN_ROSTER + ACCOUNT_ROSTER))
    bonds = tuple(Bond(identity, 10, "LOCKED") for identity in identities)
    return State(
        lots=_sorted(lots),
        sources=(),
        liabilities=(),
        claim_locks=(),
        reservations=(),
        nullifiers=_sorted(nullifiers),
        leases=_sorted(leases),
        risks=(),
        releases=(),
        objective_truth=frozenset(),
        nullifier_consumptions=(),
        lease_consumptions=(),
        paused_chains=frozenset(),
        pause_events=frozenset(),
        bonds=_sorted(bonds),
        freezes=(),
        distributions=(),
        challenger_applied=False,
        challenger_operator_effect=False,
        rotated_chains=frozenset(),
    )


class BridgeModel:
    """Deterministic transition relation for one selected defect."""

    def __init__(
        self,
        defect: Defect = Defect.NONE,
        *,
        allocation_mob: int = 2,
        allocation_eth: int = 2,
        common_risk_cap: int = 2,
    ) -> None:
        self.defect = defect
        self.allocations = {MOBILECOIN: allocation_mob, ETHEREUM: allocation_eth}
        self.common_risk_cap = common_risk_cap

    def observe_objective_source(self, state: State, source_id: str) -> State:
        if source_id in state.objective_truth:
            raise Reject("objective source already observed")
        if source_id not in SOURCE_FIELDS:
            raise Reject("source is outside the finite environment domain")
        related_intents = {
            intent.id for intent in INTENTS.values() if intent.source_id == source_id
        }
        if any(
            liability.intent_id in related_intents for liability in state.liabilities
        ):
            raise Reject("checkpoint truth is fixed before related protocol admission")
        return replace(state, objective_truth=state.objective_truth | {source_id})

    def record_source_inflow(self, state: State, intent_id: str) -> State:
        intent = INTENTS[intent_id]
        if intent.source_id not in SOURCE_FIELDS:
            raise Reject("no authenticated source adapter record exists")
        if _maybe(state.sources, "id", intent.source_id):
            raise Reject("source inflow is exact-once")
        chain, asset, amount = SOURCE_FIELDS[intent.source_id]
        position = SourcePosition(
            intent.source_id, chain, asset, amount, intent.liability_id, "ENCUMBERED"
        )
        return replace(state, sources=_put(state.sources, position))

    def finalize_source_inflow(self, state: State, source_id: str) -> State:
        source = _one(state.sources, "id", source_id)
        if source.local_finalized:
            raise Reject("source inflow finality already recorded")
        return replace(
            state,
            sources=_put(state.sources, replace(source, local_finalized=True)),
        )

    def open_liability(self, state: State, intent_id: str) -> State:
        intent = INTENTS[intent_id]
        if intent.destination_chain in state.paused_chains:
            raise Reject("destination policy is locally paused")
        if _maybe(state.liabilities, "id", intent.liability_id):
            raise Reject("liability id already exists")
        if _maybe(state.claim_locks, "nullifier", intent.nullifier):
            raise Reject("stable source claim already bound")
        if _maybe(state.lots, "id", intent.lot_id) is None:
            raise Reject("precommitted candidate lot does not exist")
        if (
            self.defect == Defect.FALSE_SOURCE_TRUTH_GUARD
            and intent.source_id not in state.objective_truth
        ):
            raise Reject("DEFECT: release path consulted objective truth")
        # WARDEN/ACCOUNT signature bytes are abstract tokens, but their B0
        # roster/threshold/bond consequences are checked concretely.
        if not (
            len(intent.wardens) == 2
            and len(set(intent.wardens)) == 2
            and set(intent.wardens) <= set(WARDEN_ROSTER)
            and len(intent.accounts) == 2
            and len(set(intent.accounts)) == 2
            and set(intent.accounts) <= set(ACCOUNT_ROSTER)
        ):
            raise Reject("missing or malformed attributable 2-of-3 role quorum")
        for identity in set(intent.wardens) | set(intent.accounts):
            bond = _one(state.bonds, "identity", identity)
            if bond.status != "LOCKED":
                raise Reject("historical approver bond is not available for new capacity")
        liability = Liability(
            intent.liability_id, intent.id, intent.nullifier, "OPEN"
        )
        lock = ClaimLock(intent.nullifier, intent.liability_id, "BOUND")
        return replace(
            state,
            liabilities=_put(state.liabilities, liability),
            claim_locks=_put(state.claim_locks, lock, "nullifier"),
        )

    def exposure(self, state: State, chain: str, *, admission_view: bool = False) -> int:
        states = {"CAPACITY_RESERVED", "FINALIZED_UNCLEARED"}
        if admission_view and self.defect == Defect.SERIAL_DRAIN:
            states = {"CAPACITY_RESERVED"}
        return sum(
            risk.amount
            for risk in state.risks
            if risk.destination_chain == chain and risk.status in states
        )

    def common_exposure(self, state: State, *, admission_view: bool = False) -> int:
        states = {"CAPACITY_RESERVED", "FINALIZED_UNCLEARED"}
        if admission_view and self.defect == Defect.SERIAL_DRAIN:
            states = {"CAPACITY_RESERVED"}
        return sum(risk.amount for risk in state.risks if risk.status in states)

    def reserve_release_intent(self, state: State, liability_id: str) -> State:
        liability = _one(state.liabilities, "id", liability_id)
        intent = INTENTS[liability.intent_id]
        if intent.destination_chain in state.paused_chains:
            raise Reject("destination policy is locally paused")
        if liability.status != "OPEN" or liability.reservation_id:
            raise Reject("liability is not an unreserved Open obligation")
        for identity in set(intent.wardens) | set(intent.accounts):
            bond = _one(state.bonds, "identity", identity)
            if bond.status != "LOCKED":
                raise Reject("approver bond changed after OPEN")
        if any(r.status == "LIVE" and r.liability_id == liability.id for r in state.reservations):
            raise Reject("liability already owns a live reservation")
        lot = _one(state.lots, "id", intent.lot_id)
        nullifier = _one(state.nullifiers, "id", intent.nullifier)
        if lot.status != "AVAILABLE" or lot.amount < intent.amount:
            raise Reject("candidate CapacityLot is unavailable or insufficient")
        if nullifier.status != "FREE":
            raise Reject("source nullifier is not Free")
        lease = None
        if intent.lease_tag:
            lease = _one(state.leases, "tag", intent.lease_tag)
            if lease.status != "FREE":
                raise Reject("network-global input lease is not Free")
            if lease.ring_binding != intent.ring_binding:
                raise Reject("permanent key-image/ring binding mismatch")
        projected = self.exposure(
            state, intent.destination_chain, admission_view=True
        ) + intent.amount
        if projected > self.allocations[intent.destination_chain]:
            raise Reject("local allocation/exposure cap exceeded")
        projected_common = self.common_exposure(
            state, admission_view=True
        ) + intent.amount
        if projected_common > self.common_risk_cap:
            raise Reject("common-risk exposure cap exceeded")
        reservation_id = f"R_{intent.id}"
        if _maybe(state.reservations, "id", reservation_id):
            raise Reject("deterministic reservation id has immutable history")
        reservation = Reservation(
            reservation_id,
            liability.id,
            intent.id,
            intent.nullifier,
            intent.lot_id,
            intent.lease_tag,
            intent.destination_chain,
            intent.amount,
            "LIVE",
            True,
        )
        liability2 = replace(
            liability, status="CAPACITY_RESERVED", reservation_id=reservation_id
        )
        lot2 = replace(lot, status="RESERVED", ref=reservation_id)
        nullifier2 = replace(nullifier, status="RESERVED", ref=reservation_id)
        risks = _put(
            state.risks,
            Risk(
                reservation_id,
                reservation_id,
                intent.destination_chain,
                intent.amount,
                "CAPACITY_RESERVED",
            ),
        )
        leases = state.leases
        if lease is not None:
            leases = _put(
                leases,
                replace(lease, status="LIVE", ref=reservation_id),
                "tag",
            )
        next_state = replace(
            state,
            liabilities=_put(state.liabilities, liability2),
            lots=_put(state.lots, lot2),
            nullifiers=_put(state.nullifiers, nullifier2),
            leases=leases,
            reservations=_put(state.reservations, reservation),
            risks=risks,
        )
        if self.defect == Defect.DOUBLE_RESERVATION:
            shadow = replace(reservation, id=reservation_id + "_SHADOW")
            next_state = replace(
                next_state,
                reservations=_put(next_state.reservations, shadow),
            )
        return next_state

    def _finalize_parts(
        self, state: State, liability: Liability, reservation: Reservation
    ) -> State:
        intent = INTENTS[liability.intent_id]
        if intent.destination_chain in state.paused_chains:
            raise Reject("local pause rejects later old-epoch finalization")
        lot = _one(state.lots, "id", reservation.lot_id)
        nullifier = _one(state.nullifiers, "id", reservation.nullifier)
        risk = _one(state.risks, "id", reservation.id)
        if lot.status != "RESERVED" or lot.ref != reservation.id:
            raise Reject("exact CapacityLot reservation mismatch")
        if nullifier.status != "RESERVED" or nullifier.ref != reservation.id:
            raise Reject("exact source-nullifier reservation mismatch")
        lease = None
        if reservation.lease_tag:
            lease = _one(state.leases, "tag", reservation.lease_tag)
            if lease.status != "LIVE" or lease.ref != reservation.id:
                raise Reject("exact MobileCoin lease reservation mismatch")
        if risk.status != "CAPACITY_RESERVED":
            raise Reject("pending risk position absent")
        release_id = f"REL_{reservation.id}"
        release = Release(
            release_id,
            reservation.id,
            liability.id,
            intent.id,
            intent.nullifier,
            intent.lease_tag,
            intent.destination_chain,
            intent.destination_asset,
            intent.amount,
            intent.wardens,
            intent.accounts,
        )
        liability2 = replace(
            liability,
            status="SETTLED",
            reservation_id="",
            release_id=release_id,
        )
        reservation2 = replace(
            reservation, status="FINALIZED", release_id=release_id
        )
        lot2 = replace(lot, status="SPENT", ref=release_id)
        nullifier2 = replace(nullifier, status="CONSUMED", ref=release_id)
        risk2 = replace(
            risk, status="FINALIZED_UNCLEARED", release_id=release_id
        )
        lock = _one(state.claim_locks, "nullifier", intent.nullifier)
        lock2 = replace(lock, status="SETTLED", release_id=release_id)
        leases = state.leases
        lease_history = state.lease_consumptions
        if lease is not None:
            leases = _put(
                leases, replace(lease, status="CONSUMED", ref=release_id), "tag"
            )
            lease_history = _sorted(
                state.lease_consumptions + ((lease.tag, release_id),)
            )
        return replace(
            state,
            liabilities=_put(state.liabilities, liability2),
            reservations=_put(state.reservations, reservation2),
            lots=_put(state.lots, lot2),
            nullifiers=_put(state.nullifiers, nullifier2),
            leases=leases,
            risks=_put(state.risks, risk2),
            releases=_put(state.releases, release),
            claim_locks=_put(state.claim_locks, lock2, "nullifier"),
            nullifier_consumptions=_sorted(
                state.nullifier_consumptions + ((intent.nullifier, release_id),)
            ),
            lease_consumptions=lease_history,
        )

    def finalize_release(self, state: State, liability_id: str) -> State:
        liability = _one(state.liabilities, "id", liability_id)
        if liability.status == "CAPACITY_RESERVED":
            reservation = _one(
                state.reservations, "id", liability.reservation_id
            )
            if reservation.status != "LIVE" or not reservation.consensus_predecessor:
                raise Reject("no prior destination-consensus reservation")
            return self._finalize_parts(state, liability, reservation)

        if self.defect != Defect.RESERVE_BYPASS or liability.status != "OPEN":
            raise Reject("liability lacks a live reservation")

        # Defect selector: fabricate the same atomic terminal projection without
        # a previously live destination-consensus reservation.  The marker is
        # retained so ReservePrecedesFinal can detect the precise violation.
        intent = INTENTS[liability.intent_id]
        lot = _one(state.lots, "id", intent.lot_id)
        nullifier = _one(state.nullifiers, "id", intent.nullifier)
        if lot.status != "AVAILABLE" or nullifier.status != "FREE":
            raise Reject("bypass fixture resources unavailable")
        lease = None
        leases = state.leases
        if intent.lease_tag:
            lease = _one(state.leases, "tag", intent.lease_tag)
            if lease.status != "FREE":
                raise Reject("bypass fixture lease unavailable")
        rid = f"R_BYPASS_{intent.id}"
        reservation = Reservation(
            rid,
            liability.id,
            intent.id,
            intent.nullifier,
            intent.lot_id,
            intent.lease_tag,
            intent.destination_chain,
            intent.amount,
            "LIVE",
            False,
        )
        state2 = replace(
            state,
            liabilities=_put(
                state.liabilities,
                replace(liability, status="CAPACITY_RESERVED", reservation_id=rid),
            ),
            reservations=_put(state.reservations, reservation),
            lots=_put(state.lots, replace(lot, status="RESERVED", ref=rid)),
            nullifiers=_put(
                state.nullifiers,
                replace(nullifier, status="RESERVED", ref=rid),
            ),
            leases=(
                _put(leases, replace(lease, status="LIVE", ref=rid), "tag")
                if lease is not None
                else leases
            ),
            risks=_put(
                state.risks,
                Risk(rid, rid, intent.destination_chain, intent.amount,
                     "CAPACITY_RESERVED"),
            ),
        )
        return self._finalize_parts(
            state2, _one(state2.liabilities, "id", liability.id), reservation
        )

    def cancel_pending_release(
        self, state: State, liability_id: str, *, proof_valid: bool
    ) -> State:
        liability = _one(state.liabilities, "id", liability_id)
        if liability.status != "CAPACITY_RESERVED":
            raise Reject("liability is not CapacityReserved")
        reservation = _one(state.reservations, "id", liability.reservation_id)
        if reservation.status != "LIVE":
            raise Reject("reservation is not live")
        accepted_proof = proof_valid
        if not accepted_proof and self.defect != Defect.UNSAFE_CANCELLATION:
            raise Reject("objective nonexecutability proof failed")
        lot = _one(state.lots, "id", reservation.lot_id)
        nullifier = _one(state.nullifiers, "id", reservation.nullifier)
        risk = _one(state.risks, "id", reservation.id)
        lease = None
        if reservation.lease_tag:
            lease = _one(state.leases, "tag", reservation.lease_tag)
        if (
            lot.status != "RESERVED"
            or nullifier.status != "RESERVED"
            or risk.status != "CAPACITY_RESERVED"
        ):
            raise Reject("cancellation projection mismatch")
        leases = state.leases
        if lease is not None:
            if lease.status != "LIVE" or lease.ref != reservation.id:
                raise Reject("cancellation lease mismatch")
            leases = _put(
                leases, replace(lease, status="FREE", ref=""), "tag"
            )
        return replace(
            state,
            liabilities=_put(
                state.liabilities,
                replace(liability, status="OPEN", reservation_id=""),
            ),
            reservations=_put(
                state.reservations,
                replace(
                    reservation,
                    status="CANCELLED",
                    cancel_proof_valid=accepted_proof,
                ),
            ),
            lots=_put(state.lots, replace(lot, status="AVAILABLE", ref="")),
            nullifiers=_put(
                state.nullifiers,
                replace(nullifier, status="FREE", ref=""),
            ),
            leases=leases,
            risks=_put(state.risks, replace(risk, status="CANCELLED")),
        )

    def clear_finalized_risk(
        self, state: State, release_id: str, *, loss_fixed: int
    ) -> State:
        release = _one(state.releases, "id", release_id)
        if release.loss_fixed is not None:
            raise Reject("loss assessment already fixed")
        if not (0 <= loss_fixed <= release.amount):
            raise Reject("loss assessment outside finite value domain")
        risk = _one(state.risks, "reservation_id", release.reservation_id)
        if risk.status != "FINALIZED_UNCLEARED":
            raise Reject("risk is not FinalizedUncleared")
        return replace(
            state,
            releases=_put(
                state.releases, replace(release, loss_fixed=loss_fixed)
            ),
            risks=_put(state.risks, replace(risk, status="CLEARED")),
        )

    def promote_settled_source_inflow(self, state: State, source_id: str) -> State:
        source = _one(state.sources, "id", source_id)
        if source.status != "ENCUMBERED" or not source.local_finalized:
            raise Reject("local inflow is absent, already promoted, or unfinalized")
        liability = _maybe(state.liabilities, "id", source.liability_id)
        if liability is None or liability.status != "SETTLED":
            raise Reject("paired remote FinalCommit is absent")
        release = _one(state.releases, "id", liability.release_id)
        if release.liability_id != source.liability_id:
            raise Reject("paired final receipt mismatch")
        lot_id = f"PROMOTED:{source.id}"
        if _maybe(state.lots, "id", lot_id):
            raise Reject("source inventory was already converted")
        lot = Lot(
            lot_id,
            source.chain,
            source.asset,
            source.amount,
            "AVAILABLE",
            provenance=source.id,
        )
        source2 = replace(
            source, status="AVAILABLE", promoted_lot_id=lot_id
        )
        return replace(
            state,
            sources=_put(state.sources, source2),
            lots=_put(state.lots, lot),
        )

    def freeze_false_source_fault(self, state: State, release_id: str) -> State:
        if any(release_id in freeze.release_ids for freeze in state.freezes):
            raise Reject("fault already frozen")
        release = _one(state.releases, "id", release_id)
        intent = INTENTS[release.intent_id]
        if intent.source_id in state.objective_truth:
            raise Reject("authenticated proof does not establish false source")
        culprits = tuple(sorted(set(release.wardens) | set(release.accounts)))
        existing = next(
            (freeze for freeze in state.freezes if freeze.culprits == culprits),
            None,
        )
        if existing is not None:
            updated = replace(
                existing,
                release_ids=tuple(sorted(existing.release_ids + (release.id,))),
            )
            return replace(
                state,
                freezes=_put(state.freezes, updated, "incident_id"),
            )

        incident = "INC_" + "_".join(culprits)
        held: list[tuple[str, int]] = []
        bonds = state.bonds
        for culprit in culprits:
            bond = _one(bonds, "identity", culprit)
            if bond.status != "LOCKED":
                raise Reject("culprit bond is not collectible exactly once")
            held.append((culprit, bond.face))
            bonds = _put(
                bonds,
                replace(bond, status="FROZEN", incident_id=incident),
                "identity",
            )
        freeze = Freeze(incident, (release.id,), culprits, tuple(sorted(held)))
        paused = state.paused_chains
        if self.defect == Defect.GLOBAL_PAUSE_COUPLING:
            # The precise forbidden mutation: Ethereum bond consensus directly
            # changes MobileCoin's pause bit without a MobileCoin pause event.
            paused = paused | {MOBILECOIN}
        return replace(
            state,
            bonds=bonds,
            freezes=_put(state.freezes, freeze, "incident_id"),
            paused_chains=paused,
        )

    def pause_policy_epoch(self, state: State, chain: str) -> State:
        if chain not in {ETHEREUM, MOBILECOIN}:
            raise Reject("unknown chain")
        if not state.freezes:
            raise Reject("pause lacks a typed fault causal reference")
        if chain in state.paused_chains:
            raise Reject("chain already paused")
        return replace(
            state,
            paused_chains=state.paused_chains | {chain},
            pause_events=state.pause_events | {chain},
        )

    def distribute_fault_collateral(
        self,
        state: State,
        incident_id: str,
        *,
        proof_claim: int = 2,
        proof_cost_cap: int = 2,
        bounty_rate_num: int = 1,
        bounty_rate_den: int = 10,
        bounty_cap: int = 3,
    ) -> State:
        if _maybe(state.distributions, "incident_id", incident_id):
            raise Reject("incident collateral already distributed")
        if (
            proof_claim < 0
            or proof_cost_cap < 0
            or bounty_rate_num < 0
            or bounty_rate_den <= 0
            or bounty_cap < 0
        ):
            raise Reject("invalid immutable penalty manifest constants")
        freeze = _one(state.freezes, "incident_id", incident_id)
        releases = tuple(
            _one(state.releases, "id", release_id)
            for release_id in freeze.release_ids
        )
        for release in releases:
            risk = _one(state.risks, "reservation_id", release.reservation_id)
            if risk.status != "CLEARED" or release.loss_fixed is None:
                raise Reject("implicated risk/loss is unresolved")
        for release in state.releases:
            exact = tuple(sorted(set(release.wardens) | set(release.accounts)))
            intent = INTENTS[release.intent_id]
            if (
                exact == freeze.culprits
                and intent.source_id not in state.objective_truth
                and release.id not in freeze.release_ids
            ):
                raise Reject("related false release is outside the incident")
        for liability in state.liabilities:
            intent = INTENTS[liability.intent_id]
            exact = tuple(sorted(set(intent.wardens) | set(intent.accounts)))
            if (
                exact == freeze.culprits
                and intent.source_id not in state.objective_truth
                and liability.status != "SETTLED"
            ):
                raise Reject("related potentially false authorization is not terminal")
        held_total = sum(amount for _, amount in freeze.held)
        restitution = min(
            sum(release.loss_fixed or 0 for release in releases), held_total
        )
        proof_cost = min(proof_claim, proof_cost_cap, held_total - restitution)
        remainder = held_total - restitution - proof_cost
        bounty = min(
            bounty_cap,
            (bounty_rate_num * remainder) // bounty_rate_den,
            remainder,
        )
        insurance = remainder - bounty
        bonds = state.bonds
        debits: list[tuple[str, int]] = []
        for identity, amount in freeze.held:
            debit = amount
            if self.defect == Defect.UNDER_SLASH and not debits:
                debit = amount - 1
            bond = _one(bonds, "identity", identity)
            bonds = _put(
                bonds,
                replace(bond, status="DISTRIBUTED", debited=debit),
                "identity",
            )
            debits.append((identity, debit))
        distribution = Distribution(
            incident_id,
            held_total,
            proof_claim,
            proof_cost_cap,
            bounty_rate_num,
            bounty_rate_den,
            bounty_cap,
            restitution,
            proof_cost,
            bounty,
            insurance,
            tuple(sorted(debits)),
        )
        return replace(
            state,
            bonds=bonds,
            distributions=_put(
                state.distributions, distribution, "incident_id"
            ),
        )

    def apply_challenger_fault(self, state: State) -> State:
        if state.challenger_applied:
            raise Reject("challenge bond already applied")
        operator_effect = self.defect == Defect.CHALLENGER_MISPUNISH
        rotated = state.rotated_chains
        paused = state.paused_chains
        pause_events = state.pause_events
        if operator_effect:
            # Model the exact prohibited consequence while keeping its local
            # event bookkeeping well-formed; ChallengerIsolation must reject it.
            rotated = rotated | {ETHEREUM}
            paused = paused | {ETHEREUM}
            pause_events = pause_events | {ETHEREUM}
        return replace(
            state,
            challenger_applied=True,
            challenger_operator_effect=operator_effect,
            rotated_chains=rotated,
            paused_chains=paused,
            pause_events=pause_events,
        )

    def inject_nullifier_replay(self, state: State, nullifier_id: str) -> State:
        if self.defect != Defect.NULLIFIER_REPLAY:
            raise Reject("selector disabled")
        uses = [x for x in state.nullifier_consumptions if x[0] == nullifier_id]
        if len(uses) != 1:
            raise Reject("fixture requires exactly one prior consumption")
        return replace(
            state,
            nullifier_consumptions=_sorted(
                state.nullifier_consumptions
                + ((nullifier_id, uses[0][1] + "_REPLAY"),)
            ),
        )

    def inject_lease_replay(self, state: State, tag: str) -> State:
        if self.defect != Defect.LEASE_REPLAY:
            raise Reject("selector disabled")
        uses = [x for x in state.lease_consumptions if x[0] == tag]
        if len(uses) != 1:
            raise Reject("fixture requires exactly one prior lease consumption")
        return replace(
            state,
            lease_consumptions=_sorted(
                state.lease_consumptions + ((tag, uses[0][1] + "_REPLAY"),)
            ),
        )


def _groups(values: Iterable[tuple[str, str]]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for key, value in values:
        result.setdefault(key, []).append(value)
    return result


def invariant_violations(state: State, model: BridgeModel) -> tuple[str, ...]:
    violations: list[str] = []

    # P26/P27/P29-style atomic projection checks.
    for reservation in state.reservations:
        liability = _maybe(state.liabilities, "id", reservation.liability_id)
        lot = _maybe(state.lots, "id", reservation.lot_id)
        nullifier = _maybe(state.nullifiers, "id", reservation.nullifier)
        risk = _maybe(state.risks, "id", reservation.id)
        lease = (
            _maybe(state.leases, "tag", reservation.lease_tag)
            if reservation.lease_tag
            else None
        )
        if None in (liability, lot, nullifier, risk):
            violations.append("ProjectionAtomic")
            continue
        if reservation.status == "LIVE":
            if not (
                liability.status == "CAPACITY_RESERVED"
                and liability.reservation_id == reservation.id
                and lot.status == "RESERVED"
                and lot.ref == reservation.id
                and nullifier.status == "RESERVED"
                and nullifier.ref == reservation.id
                and risk.status == "CAPACITY_RESERVED"
                and (lease is None or (lease.status == "LIVE" and lease.ref == reservation.id))
            ):
                violations.append("ProjectionAtomic")
        elif reservation.status == "FINALIZED":
            if not (
                liability.status == "SETTLED"
                and liability.release_id == reservation.release_id
                and lot.status == "SPENT"
                and lot.ref == reservation.release_id
                and nullifier.status == "CONSUMED"
                and nullifier.ref == reservation.release_id
                and risk.status in {"FINALIZED_UNCLEARED", "CLEARED"}
                and risk.release_id == reservation.release_id
                and (lease is None or (lease.status == "CONSUMED" and lease.ref == reservation.release_id))
            ):
                violations.append("ProjectionAtomic")
        elif reservation.status == "CANCELLED":
            if not (
                liability.status == "OPEN"
                and not liability.reservation_id
                and lot.status == "AVAILABLE"
                and not lot.ref
                and nullifier.status == "FREE"
                and not nullifier.ref
                and risk.status == "CANCELLED"
                and (lease is None or (lease.status == "FREE" and not lease.ref))
            ):
                violations.append("ProjectionAtomic")

    locks = Counter(lock.nullifier for lock in state.claim_locks)
    liabilities_by_sn = Counter(liability.nullifier for liability in state.liabilities)
    if any(v != 1 for v in locks.values()) or any(v != 1 for v in liabilities_by_sn.values()):
        violations.append("ClaimLockInjective")
    for liability in state.liabilities:
        lock = _maybe(state.claim_locks, "nullifier", liability.nullifier)
        if lock is None or lock.liability_id != liability.id:
            violations.append("ClaimLockInjective")
        elif liability.status == "SETTLED":
            if lock.status != "SETTLED" or lock.release_id != liability.release_id:
                violations.append("ClaimLockInjective")
        elif lock.status != "BOUND" or lock.release_id:
            violations.append("ClaimLockInjective")

    live = [r for r in state.reservations if r.status == "LIVE"]
    for field in ("liability_id", "nullifier", "lot_id", "lease_tag"):
        values = [getattr(r, field) for r in live if getattr(r, field)]
        if len(values) != len(set(values)):
            violations.append("LiveReservationInjective")
            break

    if any(
        not reservation.consensus_predecessor
        for reservation in state.reservations
        if reservation.status == "FINALIZED"
    ):
        violations.append("ReservePrecedesFinal")

    if any(
        r.status == "CANCELLED" and r.cancel_proof_valid is not True
        for r in state.reservations
    ):
        violations.append("SafeCancellation")
    for reservation in state.reservations:
        if reservation.status == "CANCELLED":
            lock = _maybe(state.claim_locks, "nullifier", reservation.nullifier)
            if not (
                lock is not None
                and lock.status == "BOUND"
                and lock.liability_id == reservation.liability_id
            ):
                violations.append("SafeCancellation")

    nullifier_uses = _groups(state.nullifier_consumptions)
    if any(len(set(releases)) != 1 or len(releases) != 1 for releases in nullifier_uses.values()):
        violations.append("NullifierExactlyOnce")
    for nullifier in state.nullifiers:
        uses = nullifier_uses.get(nullifier.id, [])
        if (nullifier.status == "CONSUMED") != (len(uses) == 1):
            violations.append("NullifierExactlyOnce")

    lease_uses = _groups(state.lease_consumptions)
    if any(len(set(releases)) != 1 or len(releases) != 1 for releases in lease_uses.values()):
        violations.append("LeaseExactlyOnce")
    for lease in state.leases:
        uses = lease_uses.get(lease.tag, [])
        if (lease.status == "CONSUMED") != (len(uses) == 1):
            violations.append("LeaseExactlyOnce")

    for chain in (ETHEREUM, MOBILECOIN):
        actual = sum(
            risk.amount
            for risk in state.risks
            if risk.destination_chain == chain
            and risk.status in {"CAPACITY_RESERVED", "FINALIZED_UNCLEARED"}
        )
        if actual > model.allocations[chain]:
            violations.append("ExposureBound")
    if model.common_exposure(state) > model.common_risk_cap:
        violations.append("ExposureBound")

    for source in state.sources:
        expected = SOURCE_FIELDS.get(source.id)
        if expected is None or expected != (source.chain, source.asset, source.amount):
            violations.append("SourceAuthenticity")
        liability_ids = {
            intent.liability_id
            for intent in INTENTS.values()
            if intent.source_id == source.id
        }
        if source.liability_id not in liability_ids:
            violations.append("SourceAuthenticity")
        if source.status == "AVAILABLE":
            liability = _maybe(state.liabilities, "id", source.liability_id)
            lot = _maybe(state.lots, "id", source.promoted_lot_id)
            if not (
                source.local_finalized
                and liability is not None
                and liability.status == "SETTLED"
                and lot is not None
                and lot.provenance == source.id
                and lot.amount == source.amount
                and lot.asset == source.asset
                and lot.chain == source.chain
            ):
                violations.append("SourcePromotionSound")

    lot_reservations = Counter(r.lot_id for r in live)
    if any(count > 1 for count in lot_reservations.values()):
        violations.append("LotConservation")
    if any(lot.amount < 0 for lot in state.lots):
        violations.append("LotConservation")
    # Every funded lot is either current inventory or has funded exactly one
    # matching final outflow.  This is a typed per-chain/per-asset equation;
    # USDC and eUSD are never added to each other.
    for chain, asset in ((ETHEREUM, USDC), (MOBILECOIN, EUSD)):
        funded = sum(
            lot.amount for lot in state.lots
            if lot.chain == chain and lot.asset == asset
        )
        current = sum(
            lot.amount for lot in state.lots
            if lot.chain == chain and lot.asset == asset
            and lot.status in {"AVAILABLE", "RESERVED"}
        )
        outflow = sum(
            release.amount for release in state.releases
            if release.destination_chain == chain and release.asset == asset
        )
        if funded != current + outflow:
            violations.append("PerAssetConservation")

    # False releases are deliberately legal, but never anonymous/unbonded.
    bond_ids = {bond.identity for bond in state.bonds}
    for release in state.releases:
        intent = INTENTS[release.intent_id]
        if intent.source_id not in state.objective_truth:
            approvers = set(release.wardens) | set(release.accounts)
            if not approvers or not approvers <= bond_ids:
                violations.append("FalseSourceAccountable")
                continue
            exact = tuple(sorted(approvers))
            bonds_locked = all(
                _one(state.bonds, "identity", identity).status == "LOCKED"
                for identity in exact
            )
            matching = [
                freeze for freeze in state.freezes
                if freeze.culprits == exact
            ]
            if not bonds_locked and len(matching) != 1:
                violations.append("FalseSourceAccountable")
            if matching:
                distributed = _maybe(
                    state.distributions,
                    "incident_id",
                    matching[0].incident_id,
                )
                if distributed is not None and release.id not in matching[0].release_ids:
                    violations.append("FalseSourceAccountable")

    for freeze in state.freezes:
        releases = [
            _maybe(state.releases, "id", release_id)
            for release_id in freeze.release_ids
        ]
        if not freeze.release_ids or any(release is None for release in releases):
            violations.append("PenaltyExact")
            continue
        exact_sets = {
            tuple(sorted(set(release.wardens) | set(release.accounts)))
            for release in releases
            if release is not None
        }
        held_map = dict(freeze.held)
        if exact_sets != {freeze.culprits}:
            violations.append("PenaltyExact")
        if tuple(x for x, _ in freeze.held) != freeze.culprits:
            violations.append("PenaltyExact")
        if len(set(x for x, _ in freeze.held)) != len(freeze.held):
            violations.append("PenaltyExact")
        for culprit in freeze.culprits:
            bond = _maybe(state.bonds, "identity", culprit)
            if bond is None or held_map.get(culprit) != bond.face:
                violations.append("PenaltyExact")
    for distribution in state.distributions:
        freeze = _maybe(state.freezes, "incident_id", distribution.incident_id)
        if freeze is None:
            violations.append("PenaltyExact")
            continue
        exact_debits = dict(freeze.held)
        if dict(distribution.debits) != exact_debits:
            violations.append("PenaltyExact")
        if (
            distribution.restitution
            + distribution.proof_cost
            + distribution.bounty
            + distribution.insurance
            != distribution.held_total
        ):
            violations.append("PenaltyExact")
        releases = [
            _one(state.releases, "id", release_id)
            for release_id in freeze.release_ids
        ]
        expected_restitution = min(
            sum(release.loss_fixed or 0 for release in releases),
            distribution.held_total,
        )
        if distribution.restitution != expected_restitution:
            violations.append("PenaltyExact")
        expected_proof = min(
            distribution.proof_claim,
            distribution.proof_cost_cap,
            distribution.held_total - expected_restitution,
        )
        remainder = distribution.held_total - expected_restitution - expected_proof
        expected_bounty = min(
            distribution.bounty_cap,
            (distribution.bounty_rate_num * remainder)
            // distribution.bounty_rate_den,
            remainder,
        )
        expected_insurance = remainder - expected_bounty
        if (
            distribution.proof_cost != expected_proof
            or distribution.bounty != expected_bounty
            or distribution.insurance != expected_insurance
        ):
            violations.append("PenaltyExact")

    if state.challenger_operator_effect:
        violations.append("ChallengerIsolation")

    # A pause bit can change only through that chain's local PAUSE event.
    if state.paused_chains != state.pause_events:
        violations.append("ChainLocalPause")

    return tuple(sorted(set(violations)))


def require_clean(state: State, model: BridgeModel, where: str) -> None:
    violations = invariant_violations(state, model)
    if violations:
        raise AssertionError(f"{where}: invariant violations {violations}")


def _apply(
    state: State, action: Callable[[State], State], model: BridgeModel, name: str
) -> State:
    result = action(state)
    require_clean(result, model, name)
    return result


def scenario_full_bidirectional_roundtrip() -> State:
    """The mandatory V2 USDC -> eUSD -> eUSD -> USDC customer cycle."""
    model = BridgeModel(allocation_mob=1, allocation_eth=1)
    s = initial_state(include_false=False)
    s = _apply(s, lambda x: model.observe_objective_source(x, "S_USDC_DEPOSIT"), model, "truth A")
    s = _apply(s, lambda x: model.record_source_inflow(x, "A"), model, "record USDC")
    s = _apply(s, lambda x: model.finalize_source_inflow(x, "S_USDC_DEPOSIT"), model, "finalize USDC")
    s = _apply(s, lambda x: model.open_liability(x, "A"), model, "open A")
    s = _apply(s, lambda x: model.reserve_release_intent(x, "L_A"), model, "reserve A")
    s = _apply(s, lambda x: model.finalize_release(x, "L_A"), model, "release eUSD")
    s = _apply(s, lambda x: model.promote_settled_source_inflow(x, "S_USDC_DEPOSIT"), model, "promote USDC")
    s = _apply(s, lambda x: model.clear_finalized_risk(x, "REL_R_A", loss_fixed=0), model, "clear A")

    s = _apply(s, lambda x: model.observe_objective_source(x, "S_EUSD_RETURN"), model, "truth B")
    s = _apply(s, lambda x: model.record_source_inflow(x, "B"), model, "record eUSD return")
    s = _apply(s, lambda x: model.finalize_source_inflow(x, "S_EUSD_RETURN"), model, "finalize eUSD return")
    s = _apply(s, lambda x: model.open_liability(x, "B"), model, "open B")
    s = _apply(s, lambda x: model.reserve_release_intent(x, "L_B"), model, "reserve B")
    s = _apply(s, lambda x: model.finalize_release(x, "L_B"), model, "release USDC")
    s = _apply(s, lambda x: model.promote_settled_source_inflow(x, "S_EUSD_RETURN"), model, "promote returned eUSD")
    s = _apply(s, lambda x: model.clear_finalized_risk(x, "REL_R_B", loss_fixed=0), model, "clear B")

    assert _one(s.liabilities, "id", "L_A").status == "SETTLED"
    assert _one(s.liabilities, "id", "L_B").status == "SETTLED"
    assert _one(s.nullifiers, "id", "N_USDC_DEPOSIT").status == "CONSUMED"
    assert _one(s.nullifiers, "id", "N_EUSD_RETURN").status == "CONSUMED"
    assert _one(s.sources, "id", "S_USDC_DEPOSIT").status == "AVAILABLE"
    assert _one(s.sources, "id", "S_EUSD_RETURN").status == "AVAILABLE"
    assert model.exposure(s, MOBILECOIN) == 0
    assert model.exposure(s, ETHEREUM) == 0
    return s


def scenario_false_source_release_and_penalty() -> State:
    model = BridgeModel()
    s = initial_state()
    # Intentionally no ObjectiveSourceHistory or source-inflow event for F.
    s = _apply(s, lambda x: model.open_liability(x, "F"), model, "open false")
    s = _apply(s, lambda x: model.reserve_release_intent(x, "L_FALSE"), model, "reserve false")
    s = _apply(s, lambda x: model.finalize_release(x, "L_FALSE"), model, "release false")
    s = _apply(s, lambda x: model.freeze_false_source_fault(x, "REL_R_F"), model, "freeze false")
    # Freeze itself does not pause either chain.
    assert not s.paused_chains
    incident = _freeze_for_release(s, "REL_R_F").incident_id
    freeze = _one(s.freezes, "incident_id", incident)
    assert freeze.culprits == ("account-2", "operator-overlap", "warden-2")
    assert sum(v for _, v in freeze.held) == 30  # overlap counted once
    try:
        model.distribute_fault_collateral(s, incident)
    except Reject:
        pass
    else:
        raise AssertionError("collateral distributed before risk/loss resolution")
    s = _apply(s, lambda x: model.pause_policy_epoch(x, ETHEREUM), model, "pause ETH")
    assert ETHEREUM in s.paused_chains and MOBILECOIN not in s.paused_chains
    s = _apply(s, lambda x: model.clear_finalized_risk(x, "REL_R_F", loss_fixed=1), model, "clear false")
    s = _apply(s, lambda x: model.distribute_fault_collateral(x, incident), model, "distribute")
    distribution = _one(s.distributions, "incident_id", incident)
    assert distribution.restitution == 1
    assert distribution.proof_cost == 2
    assert distribution.restitution + distribution.proof_cost + distribution.bounty + distribution.insurance == distribution.held_total
    assert sum(v for _, v in distribution.debits) == distribution.held_total
    return s


def scenario_common_risk_cap_across_chains() -> State:
    """Two charged MobileCoin units block a third Ethereum unit globally."""
    model = BridgeModel(allocation_mob=2, allocation_eth=2, common_risk_cap=2)
    s = initial_state()
    # A pre-existing Ethereum USDC lot is a focused capacity fixture.  The
    # scenario is about cross-chain admission arithmetic, not promotion.
    s = replace(
        s,
        lots=_put(
            s.lots,
            Lot(
                "PROMOTED:S_USDC_DEPOSIT",
                ETHEREUM,
                USDC,
                1,
                "AVAILABLE",
                provenance="FOCUSED_COMMON_RISK_FIXTURE",
            ),
        ),
    )
    require_clean(s, model, "common-risk fixture")
    s = _apply(s, lambda x: model.open_liability(x, "A"), model, "open A")
    s = _apply(s, lambda x: model.reserve_release_intent(x, "L_A"), model, "reserve A")
    s = _apply(s, lambda x: model.open_liability(x, "F"), model, "open F")
    s = _apply(s, lambda x: model.reserve_release_intent(x, "L_FALSE"), model, "reserve F")
    s = _apply(s, lambda x: model.open_liability(x, "B"), model, "open B")
    try:
        model.reserve_release_intent(s, "L_B")
    except Reject:
        pass
    else:
        raise AssertionError("cross-chain common-risk cap admitted a third unit")
    assert model.exposure(s, MOBILECOIN) == 2
    assert model.exposure(s, ETHEREUM) == 0
    assert model.common_exposure(s) == 2
    return s


def scenario_shared_bond_incident_waits_for_all_risk() -> State:
    """One physical bond set covers both false releases and distributes last."""
    model = BridgeModel(allocation_mob=2, common_risk_cap=2)
    s = initial_state()
    for intent_id, liability_id in (("A", "L_A"), ("F", "L_FALSE")):
        s = _apply(
            s,
            lambda x, iid=intent_id: model.open_liability(x, iid),
            model,
            f"open false {intent_id}",
        )
        s = _apply(
            s,
            lambda x, lid=liability_id: model.reserve_release_intent(x, lid),
            model,
            f"reserve false {intent_id}",
        )
        s = _apply(
            s,
            lambda x, lid=liability_id: model.finalize_release(x, lid),
            model,
            f"final false {intent_id}",
        )
    s = _apply(
        s,
        lambda x: model.clear_finalized_risk(x, "REL_R_A", loss_fixed=0),
        model,
        "clear first false release",
    )
    s = _apply(
        s,
        lambda x: model.freeze_false_source_fault(x, "REL_R_A"),
        model,
        "freeze first false release",
    )
    incident = _freeze_for_release(s, "REL_R_A").incident_id
    try:
        model.distribute_fault_collateral(s, incident)
    except Reject:
        pass
    else:
        raise AssertionError("shared bonds distributed before related release joined")
    s = _apply(
        s,
        lambda x: model.freeze_false_source_fault(x, "REL_R_F"),
        model,
        "aggregate second false release",
    )
    assert _freeze_for_release(s, "REL_R_A") == _freeze_for_release(s, "REL_R_F")
    try:
        model.distribute_fault_collateral(s, incident)
    except Reject:
        pass
    else:
        raise AssertionError("shared bonds distributed before all related risk cleared")
    s = _apply(
        s,
        lambda x: model.clear_finalized_risk(x, "REL_R_F", loss_fixed=1),
        model,
        "clear second false release",
    )
    s = _apply(
        s,
        lambda x: model.distribute_fault_collateral(x, incident),
        model,
        "distribute aggregate incident",
    )
    assert _one(s.distributions, "incident_id", incident).restitution == 1
    return s


def scenario_reserve_revalidates_approver_bonds() -> State:
    """An OPEN created before a freeze cannot reserve against frozen bonds."""
    model = BridgeModel()
    s = initial_state(include_cancel=True)
    s = _apply(s, lambda x: model.open_liability(x, "C"), model, "open C")
    s = _apply(s, lambda x: model.open_liability(x, "F"), model, "open F")
    s = _apply(s, lambda x: model.reserve_release_intent(x, "L_FALSE"), model, "reserve F")
    s = _apply(s, lambda x: model.finalize_release(x, "L_FALSE"), model, "final F")
    s = _apply(s, lambda x: model.freeze_false_source_fault(x, "REL_R_F"), model, "freeze F")
    try:
        model.reserve_release_intent(s, "L_CANCEL")
    except Reject:
        pass
    else:
        raise AssertionError("RESERVE failed to revalidate approver bonds after OPEN")
    return s


def scenario_safe_cancellation() -> State:
    model = BridgeModel(allocation_mob=1)
    s = initial_state(include_false=False, include_cancel=True)
    s = _apply(s, lambda x: model.open_liability(x, "C"), model, "open cancel")
    s = _apply(s, lambda x: model.reserve_release_intent(x, "L_CANCEL"), model, "reserve cancel")
    try:
        model.cancel_pending_release(s, "L_CANCEL", proof_valid=False)
    except Reject:
        pass
    else:
        raise AssertionError("baseline accepted cancellation without objective proof")
    s = _apply(s, lambda x: model.cancel_pending_release(x, "L_CANCEL", proof_valid=True), model, "safe cancel")
    assert _one(s.liabilities, "id", "L_CANCEL").status == "OPEN"
    assert _one(s.claim_locks, "nullifier", "N_CANCEL").status == "BOUND"
    assert _one(s.nullifiers, "id", "N_CANCEL").status == "FREE"
    assert _one(s.leases, "tag", "TAG_C").status == "FREE"
    assert _one(s.reservations, "id", "R_C").status == "CANCELLED"
    return s


def scenario_chain_local_pause_with_pending_reservation() -> State:
    """A local pause preserves pending risk and blocks only that chain's final."""
    model = BridgeModel(allocation_mob=2)
    s = initial_state()
    s = _apply(s, lambda x: model.open_liability(x, "A"), model, "open pending A")
    s = _apply(s, lambda x: model.reserve_release_intent(x, "L_A"), model, "reserve pending A")
    s = _apply(s, lambda x: model.open_liability(x, "F"), model, "open false F")
    s = _apply(s, lambda x: model.reserve_release_intent(x, "L_FALSE"), model, "reserve false F")
    s = _apply(s, lambda x: model.finalize_release(x, "L_FALSE"), model, "final false F")
    s = _apply(s, lambda x: model.freeze_false_source_fault(x, "REL_R_F"), model, "freeze F")
    s = _apply(s, lambda x: model.pause_policy_epoch(x, MOBILECOIN), model, "local MOB pause")
    try:
        model.finalize_release(s, "L_A")
    except Reject:
        pass
    else:
        raise AssertionError("post-pause old-epoch finalization was accepted")
    assert _one(s.reservations, "id", "R_A").status == "LIVE"
    assert _one(s.risks, "id", "R_A").status == "CAPACITY_RESERVED"
    assert model.exposure(s, MOBILECOIN) == 2
    # Containment may still finish an objectively safe cancellation.
    s = _apply(s, lambda x: model.cancel_pending_release(x, "L_A", proof_valid=True), model, "cancel pending A")
    return s


def truth_noninterference_check(defect: Defect) -> bool:
    model = BridgeModel(defect)
    left = initial_state()
    right = replace(left, objective_truth=frozenset({"S_FALSE_USDC"}))

    def observable(s: State) -> State:
        return replace(s, objective_truth=frozenset())

    release_path = (
        lambda s: model.open_liability(s, "F"),
        lambda s: model.reserve_release_intent(s, "L_FALSE"),
        lambda s: model.finalize_release(s, "L_FALSE"),
    )
    for action in release_path:
        try:
            next_left = action(left)
            accepted_left = True
        except Reject:
            next_left = left
            accepted_left = False
        try:
            next_right = action(right)
            accepted_right = True
        except Reject:
            next_right = right
            accepted_right = False
        if accepted_left != accepted_right:
            return False
        if accepted_left and observable(next_left) != observable(next_right):
            return False
        left, right = next_left, next_right
    return True


def _try(label: str, fn: Callable[[], State]) -> Optional[tuple[str, State]]:
    try:
        return label, fn()
    except Reject:
        return None


def successors(state: State, model: BridgeModel) -> Iterator[tuple[str, State]]:
    """Finite baseline transition relation used by exhaustive BFS."""
    candidates: list[Optional[tuple[str, State]]] = []
    for source_id in ("S_USDC_DEPOSIT", "S_EUSD_RETURN"):
        candidates.append(_try(f"TRUTH:{source_id}", lambda sid=source_id: model.observe_objective_source(state, sid)))
    for iid in ("A", "B"):
        candidates.append(_try(f"INFLOW:{iid}", lambda i=iid: model.record_source_inflow(state, i)))
    for source_id in ("S_USDC_DEPOSIT", "S_EUSD_RETURN"):
        candidates.append(_try(f"SOURCE_FINAL:{source_id}", lambda sid=source_id: model.finalize_source_inflow(state, sid)))
    for iid in ("A", "F", "B"):
        intent = INTENTS[iid]
        candidates.append(_try(f"OPEN:{iid}", lambda i=iid: model.open_liability(state, i)))
        candidates.append(_try(f"RESERVE:{iid}", lambda lid=intent.liability_id: model.reserve_release_intent(state, lid)))
        candidates.append(_try(f"FINAL:{iid}", lambda lid=intent.liability_id: model.finalize_release(state, lid)))
        candidates.append(_try(f"CANCEL:{iid}", lambda lid=intent.liability_id: model.cancel_pending_release(state, lid, proof_valid=True)))
    for source_id in ("S_USDC_DEPOSIT", "S_EUSD_RETURN"):
        candidates.append(_try(f"PROMOTE:{source_id}", lambda sid=source_id: model.promote_settled_source_inflow(state, sid)))
    for release in state.releases:
        candidates.append(_try(f"CLEAR:{release.id}", lambda rid=release.id: model.clear_finalized_risk(state, rid, loss_fixed=0)))
        candidates.append(_try(f"FREEZE:{release.id}", lambda rid=release.id: model.freeze_false_source_fault(state, rid)))
    for chain in (ETHEREUM, MOBILECOIN):
        candidates.append(_try(f"PAUSE:{chain}", lambda c=chain: model.pause_policy_epoch(state, c)))
    candidates.append(_try("CHALLENGER", lambda: model.apply_challenger_fault(state)))
    for freeze in state.freezes:
        candidates.append(_try(f"DISTRIBUTE:{freeze.incident_id}", lambda inc=freeze.incident_id: model.distribute_fault_collateral(state, inc)))
    for candidate in candidates:
        if candidate is not None and candidate[1] != state:
            yield candidate


@dataclass(frozen=True)
class ExploreResult:
    states: int
    transitions: int
    max_depth: int
    max_common_exposure: int
    false_release_depth: Optional[int]
    roundtrip_depth: Optional[int]
    complete: bool


def _is_false_release(state: State) -> bool:
    return any(release.intent_id == "F" for release in state.releases)


def _is_roundtrip(state: State) -> bool:
    ids = {release.intent_id for release in state.releases}
    promoted = {source.id for source in state.sources if source.status == "AVAILABLE"}
    return {"A", "B"} <= ids and {"S_USDC_DEPOSIT", "S_EUSD_RETURN"} <= promoted


def explore(
    model: BridgeModel,
    *,
    max_states: int = 500_000,
    check_invariants: bool = True,
) -> ExploreResult:
    start = initial_state()
    queue = deque([(start, 0)])
    seen = {start}
    transitions = 0
    max_depth_seen = 0
    max_common_exposure_seen = 0
    false_depth: Optional[int] = None
    roundtrip_depth: Optional[int] = None
    complete = True
    while queue:
        state, depth = queue.popleft()
        max_depth_seen = max(max_depth_seen, depth)
        max_common_exposure_seen = max(
            max_common_exposure_seen, model.common_exposure(state)
        )
        if check_invariants:
            require_clean(state, model, f"BFS depth {depth}")
        if false_depth is None and _is_false_release(state):
            false_depth = depth
        if roundtrip_depth is None and _is_roundtrip(state):
            roundtrip_depth = depth
        for _, nxt in successors(state, model):
            transitions += 1
            if nxt not in seen:
                seen.add(nxt)
                if len(seen) >= max_states:
                    complete = False
                    queue.clear()
                    break
                queue.append((nxt, depth + 1))
    return ExploreResult(
        states=len(seen),
        transitions=transitions,
        max_depth=max_depth_seen,
        max_common_exposure=max_common_exposure_seen,
        false_release_depth=false_depth,
        roundtrip_depth=roundtrip_depth,
        complete=complete,
    )


def defect_results() -> dict[str, dict[str, object]]:
    results: dict[str, dict[str, object]] = {}

    def save(defect: Defect, target: str, state: State) -> None:
        observed = invariant_violations(state, BridgeModel(defect, allocation_mob=1))
        if target not in observed:
            raise AssertionError(f"{defect}: expected {target}, observed {observed}")
        results[defect.value] = {"target": target, "observed": list(observed)}

    # Double reservation.
    m = BridgeModel(Defect.DOUBLE_RESERVATION, allocation_mob=1)
    s = initial_state(include_false=False)
    s = m.open_liability(s, "A")
    s = m.reserve_release_intent(s, "L_A")
    save(Defect.DOUBLE_RESERVATION, "LiveReservationInjective", s)

    # Finalization bypassing a prior consensus reservation.
    m = BridgeModel(Defect.RESERVE_BYPASS, allocation_mob=1)
    s = initial_state(include_false=False)
    s = m.open_liability(s, "A")
    s = m.finalize_release(s, "L_A")
    save(Defect.RESERVE_BYPASS, "ReservePrecedesFinal", s)

    # Cancellation accepted while the exact action remains executable.
    m = BridgeModel(Defect.UNSAFE_CANCELLATION, allocation_mob=1)
    s = initial_state(include_false=False, include_cancel=True)
    s = m.open_liability(s, "C")
    s = m.reserve_release_intent(s, "L_CANCEL")
    s = m.cancel_pending_release(s, "L_CANCEL", proof_valid=False)
    save(Defect.UNSAFE_CANCELLATION, "SafeCancellation", s)

    # Stable source-nullifier consumption replay.
    m = BridgeModel(Defect.NULLIFIER_REPLAY, allocation_mob=1)
    s = initial_state(include_false=False)
    s = m.open_liability(s, "A")
    s = m.reserve_release_intent(s, "L_A")
    s = m.finalize_release(s, "L_A")
    s = m.inject_nullifier_replay(s, "N_USDC_DEPOSIT")
    save(Defect.NULLIFIER_REPLAY, "NullifierExactlyOnce", s)

    # MobileCoin network-global input lease replay.
    m = BridgeModel(Defect.LEASE_REPLAY, allocation_mob=1)
    s = initial_state(include_false=False)
    s = m.open_liability(s, "A")
    s = m.reserve_release_intent(s, "L_A")
    s = m.finalize_release(s, "L_A")
    s = m.inject_lease_replay(s, "TAG_A")
    save(Defect.LEASE_REPLAY, "LeaseExactlyOnce", s)

    # Serial-drain bug: finalized-but-uncleared risk omitted at admission.
    m = BridgeModel(Defect.SERIAL_DRAIN, allocation_mob=1)
    s = initial_state(serial_profile=True)
    s = m.open_liability(s, "X")
    s = m.reserve_release_intent(s, "L_X")
    s = m.finalize_release(s, "L_X")
    s = m.open_liability(s, "Y")
    s = m.reserve_release_intent(s, "L_Y")
    save(Defect.SERIAL_DRAIN, "ExposureBound", s)

    # False-source truth guard is a reachability/hyperproperty failure.
    m = BridgeModel(Defect.FALSE_SOURCE_TRUTH_GUARD)
    s = initial_state()
    rejected = False
    try:
        m.open_liability(s, "F")
    except Reject:
        rejected = True
    if not rejected or truth_noninterference_check(Defect.FALSE_SOURCE_TRUTH_GUARD):
        raise AssertionError("truth-guard selector did not remove false release path")
    results[Defect.FALSE_SOURCE_TRUTH_GUARD.value] = {
        "target": "FalseSourceReleaseReachable/TruthNoninterference",
        "observed": ["false OPEN rejected solely by objective truth"],
    }

    # Full culprit bond must be debited after loss resolution.
    m = BridgeModel(Defect.UNDER_SLASH)
    s = initial_state()
    s = m.open_liability(s, "F")
    s = m.reserve_release_intent(s, "L_FALSE")
    s = m.finalize_release(s, "L_FALSE")
    s = m.freeze_false_source_fault(s, "REL_R_F")
    s = m.clear_finalized_risk(s, "REL_R_F", loss_fixed=1)
    incident = _freeze_for_release(s, "REL_R_F").incident_id
    s = m.distribute_fault_collateral(s, incident)
    save(Defect.UNDER_SLASH, "PenaltyExact", s)

    # ChallengerFault may consume only the challenge bond.
    m = BridgeModel(Defect.CHALLENGER_MISPUNISH, allocation_mob=1)
    s = initial_state(include_false=False)
    s = m.apply_challenger_fault(s)
    save(Defect.CHALLENGER_MISPUNISH, "ChallengerIsolation", s)

    # Ethereum fault freeze cannot directly mutate MobileCoin pause state.
    m = BridgeModel(Defect.GLOBAL_PAUSE_COUPLING)
    s = initial_state()
    s = m.open_liability(s, "F")
    s = m.reserve_release_intent(s, "L_FALSE")
    s = m.finalize_release(s, "L_FALSE")
    s = m.freeze_false_source_fault(s, "REL_R_F")
    save(Defect.GLOBAL_PAUSE_COUPLING, "ChainLocalPause", s)

    return results


def selftest(*, run_bfs: bool = True, max_states: int = 500_000) -> dict[str, object]:
    scenario_full_bidirectional_roundtrip()
    scenario_false_source_release_and_penalty()
    scenario_common_risk_cap_across_chains()
    scenario_shared_bond_incident_waits_for_all_risk()
    scenario_reserve_revalidates_approver_bonds()
    scenario_safe_cancellation()
    scenario_chain_local_pause_with_pending_reservation()
    if not truth_noninterference_check(Defect.NONE):
        raise AssertionError("baseline release-path enabledness reads objective truth")
    defects = defect_results()
    report: dict[str, object] = {
        "status": "PASS",
        "semantics": "bounded finite-state evidence; not an unbounded theorem",
        "python": platform.python_version(),
        "bounded_profile": B0_PROFILE,
        "profile_deviations": MODEL_PROFILE_DEVIATIONS,
        "scenarios": {
            "full_bidirectional_roundtrip": "PASS",
            "false_source_release_and_penalty": "PASS",
            "common_risk_cap_across_chains": "PASS",
            "shared_bond_incident_waits_for_all_risk": "PASS",
            "reserve_revalidates_approver_bonds": "PASS",
            "safe_cancellation": "PASS",
            "chain_local_pause_with_pending_reservation": "PASS",
            "truth_noninterference_pair": "PASS",
        },
        "defects": defects,
    }
    if run_bfs:
        baseline = explore(BridgeModel(), max_states=max_states)
        if not baseline.complete:
            raise AssertionError(
                f"BFS hit max_states={max_states}; result is not exhaustive"
            )
        if baseline.false_release_depth is None:
            raise AssertionError("baseline BFS has no false-source release witness")
        if baseline.roundtrip_depth is None:
            raise AssertionError("baseline BFS has no complete round-trip witness")
        report["bfs"] = asdict(baseline)
    return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command", nargs="?", choices=("selftest", "explore", "all"), default="all"
    )
    parser.add_argument("--max-states", type=int, default=500_000)
    args = parser.parse_args(argv)
    if args.max_states <= 0:
        parser.error("--max-states must be positive")
    if args.command == "explore":
        result: object = asdict(explore(BridgeModel(), max_states=args.max_states))
    else:
        result = selftest(run_bfs=True, max_states=args.max_states)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
