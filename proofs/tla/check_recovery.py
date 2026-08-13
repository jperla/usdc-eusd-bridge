#!/usr/bin/env python3
"""Independent finite-state mirror of ReserveRecovery.tla.

The baseline explores the complete graph and must match TLC's distinct-state
count exactly. Bug runs search for the documented counterexample, like TLC
stopping at its first invariant violation. Agreement establishes transition
fidelity only; it does not establish that the model is the right abstraction.
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
from collections import deque
from dataclasses import dataclass, replace
from pathlib import Path


CUSTODIANS = frozenset({"c1", "c2", "c3", "c4"})
INITIAL_ROSTER = CUSTODIANS
REPLACEMENT_ROSTER = frozenset({"c3", "c4"})
GATE_OPERATORS = frozenset({"g1", "g2", "g3"})
RECOVERY_OPERATORS = frozenset({"r1", "r2"})
ALL_ACTORS = CUSTODIANS | GATE_OPERATORS | RECOVERY_OPERATORS

K_OWN = 2
K_GATE = 2
K_RECOVERY = 2

MODES = ("LONG_LIVED", "RESHARE", "DELAYED", "STRAND")
SCOPES = ("GLOBAL", "SEGREGATED")
INCIDENT_KINDS = (
    "FALSE_1",
    "FALSE_2",
    "PARTIAL_LOSS",
    "CATASTROPHIC_LOSS",
    "THRESHOLD_COMPROMISE",
)

K0, KR, KS = "K0", "KR", "KS"
LEGACY, SUCCESSOR = "legacy", "successor"
POOLS = (LEGACY, SUCCESSOR)
UNITS = ("u1", "u2")
LIABILITY_IDS = ("q1", "q2")
INTENT_IDS = ("intent1",)

RECOVERY_DELAY = 1
MAX_TIME = 2


def old(unit):
    return (LEGACY, unit, 0)


def moved(unit):
    return (LEGACY, unit, 1)


def fresh(unit):
    return (SUCCESSOR, unit, 0)


OLD_OUTPUTS = frozenset(old(u) for u in UNITS)
MOVED_OUTPUTS = frozenset(moved(u) for u in UNITS)
FRESH_OUTPUTS = frozenset(fresh(u) for u in UNITS)
ALL_OUTPUTS = tuple(sorted(OLD_OUTPUTS | MOVED_OUTPUTS | FRESH_OUTPUTS))
OUTPUT_INDEX = {o: i for i, o in enumerate(ALL_OUTPUTS)}
INITIAL_OWNER_KEYS = tuple(
    K0 if o in OLD_OUTPUTS else KR if o in MOVED_OUTPUTS else KS
    for o in ALL_OUTPUTS
)
INITIAL_SHARES = frozenset((c, K0, 0) for c in INITIAL_ROSTER)


BUGS = (
    "NONE",
    "RESHARE_WITHOUT_THRESHOLD",
    "ERASE_SHARE_KNOWLEDGE",
    "CLEAR_HISTORICAL_EXPOSURE",
    "RESUME_BEFORE_GATE_DKG",
    "ACCEPT_OLD_GATE",
    "ROTATE_OWNER_IN_PLACE",
    "RECOVER_BEFORE_DELAY",
    "RECOVERY_DOES_NOT_CONSUME",
    "RECOVERY_EXTERNAL_RECIPIENT",
    "ACTIVATE_PARTIAL_MIGRATION",
    "COUNT_INELIGIBLE_BACKING",
    "ERASE_LEGACY_LIABILITY",
    "RESET_NULLIFIERS",
)

EXPECTED = {
    "RESHARE_WITHOUT_THRESHOLD": "ReshareSound",
    "ERASE_SHARE_KNOWLEDGE": "ShareIssuanceAccounted",
    "CLEAR_HISTORICAL_EXPOSURE": "HistoricalExposurePreserved",
    "RESUME_BEFORE_GATE_DKG": "ActiveGateReady",
    "ACCEPT_OLD_GATE": "NoStaleAuthorization",
    "ROTATE_OWNER_IN_PLACE": "OutputMetadataImmutable",
    "RECOVER_BEFORE_DELAY": "RecoveryDelayHonored",
    "RECOVERY_DOES_NOT_CONSUME": "MigrationConsumesOld",
    "RECOVERY_EXTERNAL_RECIPIENT": "MigrationConservative",
    "ACTIVATE_PARTIAL_MIGRATION": "FreshKeyRequiresFullMigration",
    "COUNT_INELIGIBLE_BACKING": "NewLiabilitySound",
    "ERASE_LEGACY_LIABILITY": "LiabilitiesAccounted",
    "RESET_NULLIFIERS": "NullifierHistoryPreserved",
}


# Audit record tuple layouts mirror the TLA+ record fields.
# Share: kind, oldKey, newKey, fromEpoch, toEpoch, contributors,
#        availableSnapshot, newShares
# Migration: unit, kind, old, new, time, maturity, signers, internal, consumedOld
# Liability: id, pool, hadCapacity
# Authorization: usedEpoch, expectedEpoch, stale


@dataclass(frozen=True, slots=True)
class State:
    mode: str
    scope: str
    legacy_phase: str
    successor_phase: str
    now: int
    raised: frozenset
    unavailable: frozenset
    current_share_epoch: int
    current_legacy_key: str

    issued: frozenset
    compromised: frozenset
    compromise_history: frozenset
    exposed: frozenset
    exposure_history: frozenset

    gate_ready: frozenset
    active_gate_epoch: int
    successor_gate_ready: bool

    created: frozenset
    live: frozenset
    consumed: frozenset
    owner_keys: tuple
    stranded: frozenset
    quarantined: frozenset

    recovery_armed: bool
    recovery_maturity: int
    recovery_signers: frozenset
    migration_kind: str
    migrated: frozenset

    liabilities: tuple
    nullifiers: frozenset
    nullifier_history: frozenset

    share_log: frozenset
    migration_log: frozenset
    liability_log: frozenset
    authorization_log: frozenset


def initial_states():
    for mode in MODES:
        for scope in SCOPES:
            yield State(
                mode=mode,
                scope=scope,
                legacy_phase="Active",
                successor_phase="Absent",
                now=0,
                raised=frozenset(),
                unavailable=frozenset(),
                current_share_epoch=0,
                current_legacy_key=K0,
                issued=INITIAL_SHARES,
                compromised=frozenset(),
                compromise_history=frozenset(),
                exposed=frozenset(),
                exposure_history=frozenset(),
                gate_ready=frozenset({0}),
                active_gate_epoch=0,
                successor_gate_ready=False,
                created=OLD_OUTPUTS,
                live=OLD_OUTPUTS,
                consumed=frozenset(),
                owner_keys=INITIAL_OWNER_KEYS,
                stranded=frozenset(),
                quarantined=frozenset(),
                recovery_armed=False,
                recovery_maturity=0,
                recovery_signers=frozenset(),
                migration_kind="NONE",
                migrated=frozenset(),
                liabilities=(2, 0),
                nullifiers=frozenset(),
                nullifier_history=frozenset(),
                share_log=frozenset(),
                migration_log=frozenset(),
                liability_log=frozenset(),
                authorization_log=frozenset(),
            )


def pool_index(pool):
    return 0 if pool == LEGACY else 1


def liability(st, pool):
    return st.liabilities[pool_index(pool)]


def owner_key(st, output):
    return st.owner_keys[OUTPUT_INDEX[output]]


def set_owner_key(st, output, key):
    keys = list(st.owner_keys)
    keys[OUTPUT_INDEX[output]] = key
    return tuple(keys)


def value_of(output):
    return 1 if output[1] == "u1" else 2


def policy_of(output):
    return "LEGACY_POLICY" if output[0] == LEGACY else "SUCCESSOR_POLICY"


def roster_for(key, epoch):
    if key == K0 and epoch == 0:
        return INITIAL_ROSTER
    if key == K0 and epoch == 1:
        return REPLACEMENT_ROSTER
    if key in {KR, KS} and epoch == 0:
        return REPLACEMENT_ROSTER
    return frozenset()


def shares_for(key, epoch, roster):
    return frozenset((c, key, epoch) for c in roster)


def holders(st, key, epoch):
    return frozenset(c for c in CUSTODIANS if (c, key, epoch) in st.issued)


def compromised_holders(st, key, epoch):
    return frozenset(c for c in CUSTODIANS if (c, key, epoch) in st.compromised)


def operational_holders(st, key, epoch):
    return holders(st, key, epoch) - st.unavailable - compromised_holders(st, key, epoch)


def can_operate(st, key, epoch):
    return len(operational_holders(st, key, epoch)) >= K_OWN


def owner_epoch(st, key):
    return st.current_share_epoch if key == K0 else 0


def threshold_known(known, key):
    return any(
        len({c for c in CUSTODIANS if (c, key, epoch) in known}) >= K_OWN
        for epoch in (0, 1)
    )


def unsafe_outputs(st):
    return frozenset(o for o in st.live if owner_key(st, o) in st.exposed)


def controllable(st, output):
    key = owner_key(st, output)
    return can_operate(st, key, owner_epoch(st, key))


def candidate_eligible(st, pool):
    unsafe = unsafe_outputs(st)
    return frozenset(
        o
        for o in st.live
        if o[0] == pool
        and o not in st.stranded
        and o not in st.quarantined
        and o not in unsafe
        and controllable(st, o)
    )


def pool_active(st, pool):
    return (
        st.legacy_phase == "Active"
        if pool == LEGACY
        else st.successor_phase == "Active"
    )


def active_eligible(st, pool):
    return candidate_eligible(st, pool) if pool_active(st, pool) else frozenset()


def backing_value(outputs):
    return sum(value_of(o) for o in outputs)


def total_liability(st):
    return sum(st.liabilities)


def total_active_backing(st):
    return backing_value(active_eligible(st, LEGACY)) + backing_value(
        active_eligible(st, SUCCESSOR)
    )


def correct_capacity(st, pool):
    if st.scope == "GLOBAL":
        return total_active_backing(st) >= total_liability(st) + 1
    return backing_value(active_eligible(st, pool)) >= liability(st, pool) + 1


def reported_capacity(st, pool):
    if st.scope == "GLOBAL":
        return backing_value(st.live) >= total_liability(st) + 1
    return backing_value(o for o in st.live if o[0] == pool) >= liability(st, pool) + 1


def prospective_solvent(st, pool):
    other = SUCCESSOR if pool == LEGACY else LEGACY
    backing = backing_value(candidate_eligible(st, pool)) + backing_value(
        active_eligible(st, other)
    )
    if st.scope == "GLOBAL":
        return backing >= total_liability(st)
    return backing_value(candidate_eligible(st, pool)) >= liability(st, pool)


def loss_set(kind, epoch):
    if kind in {"FALSE_1", "FALSE_2", "THRESHOLD_COMPROMISE"}:
        return frozenset()
    if kind == "PARTIAL_LOSS":
        return frozenset({"c1"} if epoch == 0 else {"c3"})
    if kind == "CATASTROPHIC_LOSS":
        return frozenset({"c1", "c2", "c3"}) if epoch == 0 else REPLACEMENT_ROSTER
    raise AssertionError(kind)


def compromise_set(kind, epoch):
    if kind != "THRESHOLD_COMPROMISE":
        return frozenset()
    return frozenset({"c1", "c2"}) if epoch == 0 else REPLACEMENT_ROSTER


def subsets(items):
    items = sorted(items)
    for n in range(len(items) + 1):
        for combo in itertools.combinations(items, n):
            yield frozenset(combo)


def successors(st: State, bug: str):
    out = []

    # Arbitrary, repeatable (by distinct incident id) environment input.
    for kind in INCIDENT_KINDS:
        if kind in st.raised or st.active_gate_epoch != 0:
            continue
        if st.successor_phase == "Active" and kind not in {"FALSE_1", "FALSE_2"}:
            continue
        newly = shares_for(K0, st.current_share_epoch, compromise_set(kind, st.current_share_epoch))
        all_compromised = st.compromised | newly
        newly_exposed = frozenset({K0}) if threshold_known(all_compromised, K0) else frozenset()
        nxt = replace(
            st,
            legacy_phase="Frozen" if st.legacy_phase == "Active" else st.legacy_phase,
            raised=st.raised | {kind},
            unavailable=st.unavailable | loss_set(kind, st.current_share_epoch),
            compromised=all_compromised,
            compromise_history=st.compromise_history | newly,
            exposed=st.exposed | newly_exposed,
            exposure_history=st.exposure_history | newly_exposed,
        )
        out.append((f"RaiseIncident({kind})", nxt))

    if st.legacy_phase == "Frozen":
        out.append(("StartGateDKG", replace(st, legacy_phase="GateDKG")))

    if st.legacy_phase == "GateDKG" and len(GATE_OPERATORS) >= K_GATE:
        out.append(
            (
                "CompleteGateDKG",
                replace(st, legacy_phase="Ownership", gate_ready=st.gate_ready | {1}),
            )
        )

    if (
        bug == "RESUME_BEFORE_GATE_DKG"
        and st.legacy_phase == "Frozen"
        and can_operate(st, st.current_legacy_key, owner_epoch(st, st.current_legacy_key))
        and prospective_solvent(st, LEGACY)
    ):
        out.append(
            (
                "BypassGateDKG",
                replace(st, legacy_phase="Active", active_gate_epoch=1),
            )
        )

    if (
        st.legacy_phase == "Ownership"
        and st.mode == "LONG_LIVED"
        and can_operate(st, K0, st.current_share_epoch)
    ):
        out.append(("KeepLongLivedOwner", replace(st, legacy_phase="Ready")))

    if st.legacy_phase == "Ownership" and st.mode == "RESHARE":
        operational = operational_holders(st, K0, st.current_share_epoch)
        for contributors in subsets(operational):
            if not contributors:
                continue
            if len(contributors) < K_OWN and bug != "RESHARE_WITHOUT_THRESHOLD":
                continue
            new_shares = shares_for(K0, 1, REPLACEMENT_ROSTER)
            event = (
                "reshare",
                K0,
                K0,
                st.current_share_epoch,
                1,
                contributors,
                ALL_ACTORS - st.unavailable,
                new_shares,
            )
            issued = new_shares if bug == "ERASE_SHARE_KNOWLEDGE" else st.issued | new_shares
            exposed = st.exposed - {K0} if bug == "CLEAR_HISTORICAL_EXPOSURE" else st.exposed
            out.append(
                (
                    f"Reshare({','.join(sorted(contributors))})",
                    replace(
                        st,
                        legacy_phase="Ready",
                        current_share_epoch=1,
                        issued=issued,
                        exposed=exposed,
                        share_log=st.share_log | {event},
                    ),
                )
            )

    if (
        st.legacy_phase == "Ownership"
        and st.mode == "DELAYED"
        and len(RECOVERY_OPERATORS) >= K_RECOVERY
    ):
        out.append(
            (
                "ArmDelayedRecovery",
                replace(
                    st,
                    legacy_phase="RecoveryDelay",
                    recovery_armed=True,
                    recovery_maturity=st.now + RECOVERY_DELAY,
                    recovery_signers=RECOVERY_OPERATORS,
                ),
            )
        )

    if st.legacy_phase == "RecoveryDelay" and st.now < MAX_TIME:
        out.append(("Tick", replace(st, now=st.now + 1)))

    if (
        st.legacy_phase == "RecoveryDelay"
        and st.recovery_armed
        and (st.now >= st.recovery_maturity or bug == "RECOVER_BEFORE_DELAY")
    ):
        new_shares = shares_for(KR, 0, REPLACEMENT_ROSTER)
        event = (
            "new-key",
            K0,
            KR,
            st.current_share_epoch,
            0,
            st.recovery_signers,
            ALL_ACTORS - st.unavailable,
            new_shares,
        )
        out.append(
            (
                "BeginDelayedMigration",
                replace(
                    st,
                    legacy_phase="Migrating",
                    issued=st.issued | new_shares,
                    migration_kind="RECOVERY",
                    migrated=frozenset(),
                    share_log=st.share_log | {event},
                ),
            )
        )

    if (
        st.legacy_phase == "Ready"
        and st.mode in {"LONG_LIVED", "RESHARE"}
        and st.current_legacy_key == K0
        and K0 in st.exposed
        and 1 in st.gate_ready
        and can_operate(st, K0, st.current_share_epoch)
    ):
        new_shares = shares_for(KR, 0, REPLACEMENT_ROSTER)
        contributors = operational_holders(st, K0, st.current_share_epoch)
        event = (
            "new-key",
            K0,
            KR,
            st.current_share_epoch,
            0,
            contributors,
            ALL_ACTORS - st.unavailable,
            new_shares,
        )
        out.append(
            (
                "BeginOwnerMigration",
                replace(
                    st,
                    legacy_phase="Migrating",
                    issued=st.issued | new_shares,
                    migration_kind="OWNER",
                    migrated=frozenset(),
                    share_log=st.share_log | {event},
                ),
            )
        )

    if st.legacy_phase == "Migrating" and st.migration_kind in {"OWNER", "RECOVERY"}:
        for unit in UNITS:
            if unit in st.migrated or old(unit) not in st.live:
                continue
            if st.migration_kind == "OWNER" and not (
                1 in st.gate_ready and can_operate(st, K0, st.current_share_epoch)
            ):
                continue
            consume = not (
                bug == "RECOVERY_DOES_NOT_CONSUME"
                and st.migration_kind == "RECOVERY"
            )
            internal = not (
                bug == "RECOVERY_EXTERNAL_RECIPIENT"
                and st.migration_kind == "RECOVERY"
            )
            event = (
                unit,
                st.migration_kind,
                old(unit),
                moved(unit),
                st.now,
                st.recovery_maturity if st.migration_kind == "RECOVERY" else st.now,
                st.recovery_signers
                if st.migration_kind == "RECOVERY"
                else operational_holders(st, K0, st.current_share_epoch),
                internal,
                consume,
            )
            live = (st.live - {old(unit)} if consume else st.live) | {moved(unit)}
            consumed = st.consumed | {old(unit)} if consume else st.consumed
            out.append(
                (
                    f"MigrateOne({unit})",
                    replace(
                        st,
                        created=st.created | {moved(unit)},
                        live=live,
                        consumed=consumed,
                        migrated=st.migrated | {unit},
                        migration_log=st.migration_log | {event},
                    ),
                )
            )

    if (
        st.legacy_phase == "Migrating"
        and st.migrated
        and (st.migrated == frozenset(UNITS) or bug == "ACTIVATE_PARTIAL_MIGRATION")
    ):
        out.append(
            (
                "FinishMigration",
                replace(
                    st,
                    legacy_phase="Ready",
                    current_legacy_key=KR,
                    current_share_epoch=0,
                    migration_kind="NONE",
                ),
            )
        )

    if st.legacy_phase in {"Ownership", "Ready"}:
        may_strand = st.mode == "STRAND" or (
            st.mode in {"LONG_LIVED", "RESHARE"}
            and not can_operate(st, st.current_legacy_key, owner_epoch(st, st.current_legacy_key))
        )
        if may_strand:
            legacy_live = frozenset(o for o in st.live if o[0] == LEGACY)
            out.append(
                (
                    "DeclareStranded",
                    replace(
                        st,
                        legacy_phase="Stranded",
                        stranded=st.stranded | legacy_live,
                    ),
                )
            )

    if bug == "ROTATE_OWNER_IN_PLACE" and st.legacy_phase == "Ownership":
        for output in sorted(st.live & OLD_OUTPUTS):
            out.append(
                (
                    f"RotateOwnerInPlace({output[1]})",
                    replace(st, owner_keys=set_owner_key(st, output, KR)),
                )
            )

    if (
        st.legacy_phase == "Ready"
        and 1 in st.gate_ready
        and can_operate(st, st.current_legacy_key, owner_epoch(st, st.current_legacy_key))
        and prospective_solvent(st, LEGACY)
    ):
        out.append(
            (
                "ActivateLegacy",
                replace(st, legacy_phase="Active", active_gate_epoch=1),
            )
        )

    if st.raised and st.successor_phase == "Absent":
        new_shares = shares_for(KS, 0, REPLACEMENT_ROSTER)
        event = (
            "new-key",
            K0,
            KS,
            st.current_share_epoch,
            0,
            REPLACEMENT_ROSTER,
            ALL_ACTORS - st.unavailable,
            new_shares,
        )
        legacy_live = frozenset(o for o in st.live if o[0] == LEGACY)
        liabilities = (
            (0, st.liabilities[1])
            if bug == "ERASE_LEGACY_LIABILITY"
            else st.liabilities
        )
        nullifiers = frozenset() if bug == "RESET_NULLIFIERS" else st.nullifiers
        out.append(
            (
                "PrepareSuccessor",
                replace(
                    st,
                    successor_phase="Ready",
                    legacy_phase="Stranded" if st.legacy_phase == "Stranded" else "Retired",
                    issued=st.issued | new_shares,
                    successor_gate_ready=True,
                    created=st.created | FRESH_OUTPUTS,
                    live=st.live | FRESH_OUTPUTS,
                    quarantined=st.quarantined | legacy_live,
                    liabilities=liabilities,
                    nullifiers=nullifiers,
                    share_log=st.share_log | {event},
                ),
            )
        )

    if (
        st.successor_phase == "Ready"
        and st.successor_gate_ready
        and can_operate(st, KS, 0)
        and prospective_solvent(st, SUCCESSOR)
    ):
        out.append(("ActivateSuccessor", replace(st, successor_phase="Active")))

    used_ids = frozenset(event[0] for event in st.liability_log)
    for pool in POOLS:
        if not pool_active(st, pool):
            continue
        for event_id in LIABILITY_IDS:
            if event_id in used_ids:
                continue
            correct = correct_capacity(st, pool)
            if not correct and not (
                bug == "COUNT_INELIGIBLE_BACKING" and reported_capacity(st, pool)
            ):
                continue
            values = list(st.liabilities)
            values[pool_index(pool)] += 1
            event = (event_id, pool, correct)
            out.append(
                (
                    f"AcceptLiability({pool},{event_id})",
                    replace(
                        st,
                        liabilities=tuple(values),
                        liability_log=st.liability_log | {event},
                    ),
                )
            )

    for intent in INTENT_IDS:
        if intent not in st.nullifiers:
            out.append(
                (
                    f"ConsumeIntent({intent})",
                    replace(
                        st,
                        nullifiers=st.nullifiers | {intent},
                        nullifier_history=st.nullifier_history | {intent},
                    ),
                )
            )

    if st.legacy_phase == "Active" and st.raised:
        for used in sorted(st.gate_ready):
            if used != st.active_gate_epoch and bug != "ACCEPT_OLD_GATE":
                continue
            event = (used, st.active_gate_epoch, used != st.active_gate_epoch)
            out.append(
                (
                    f"AcceptGateAuthorization(e{used})",
                    replace(st, authorization_log=st.authorization_log | {event}),
                )
            )

    return out


def invariants(st: State):
    bad = []

    # OutputMetadataImmutable
    if st.owner_keys != INITIAL_OWNER_KEYS:
        bad.append("OutputMetadataImmutable")

    # OutputVersionExclusive
    if st.live & st.consumed or not st.live <= st.created:
        bad.append("OutputVersionExclusive")
    elif any(len(st.live & {old(u), moved(u)}) > 1 for u in UNITS):
        bad.append("OutputVersionExclusive")

    logged_shares = frozenset().union(*(e[7] for e in st.share_log)) if st.share_log else frozenset()
    if st.issued != INITIAL_SHARES | logged_shares:
        bad.append("ShareIssuanceAccounted")

    if not st.compromise_history <= st.compromised:
        bad.append("CompromiseKnowledgePreserved")
    if not st.exposure_history <= st.exposed:
        bad.append("HistoricalExposurePreserved")

    for event in st.share_log:
        kind, old_key, new_key, old_epoch, _, contributors, snapshot, _ = event
        if kind == "reshare" and not (
            len(contributors) >= K_OWN
            and contributors <= (roster_for(old_key, old_epoch) & snapshot)
            and old_key == new_key
        ):
            bad.append("ReshareSound")
            break

    for event in st.migration_log:
        unit, kind, old_output, new_output, time, maturity, signers, internal, consumed_old = event
        if kind == "RECOVERY" and time < maturity:
            bad.append("RecoveryDelayHonored")
            break
    for event in st.migration_log:
        if event[1] == "RECOVERY" and not (
            event[6] <= RECOVERY_OPERATORS and len(event[6]) >= K_RECOVERY
        ):
            bad.append("RecoveryAuthorized")
            break
    for event in st.migration_log:
        if not (
            event[8]
            and event[2] in st.consumed
            and event[2] not in st.live
            and event[3] in st.live
        ):
            bad.append("MigrationConsumesOld")
            break
    for event in st.migration_log:
        unit = event[0]
        if not (
            event[2] == old(unit)
            and event[3] == moved(unit)
            and value_of(event[2]) == value_of(event[3])
            and policy_of(event[2]) == policy_of(event[3])
            and event[7]
        ):
            bad.append("MigrationConservative")
            break

    if st.legacy_phase == "Active" and st.raised and not (
        st.active_gate_epoch == 1 and 1 in st.gate_ready
    ):
        bad.append("ActiveGateReady")
    if st.successor_phase == "Active" and not st.successor_gate_ready:
        bad.append("ActiveGateReady")

    if any(event[2] for event in st.authorization_log):
        bad.append("NoStaleAuthorization")

    if (
        st.legacy_phase == "Active"
        and st.current_legacy_key == KR
        and st.migrated != frozenset(UNITS)
    ):
        bad.append("FreshKeyRequiresFullMigration")

    if st.legacy_phase == "Active" and not can_operate(
        st, st.current_legacy_key, owner_epoch(st, st.current_legacy_key)
    ):
        bad.append("ActiveOwnershipOperable")
    if st.successor_phase == "Active" and not can_operate(st, KS, 0):
        bad.append("ActiveOwnershipOperable")

    legacy_live = frozenset(o for o in st.live if o[0] == LEGACY)
    if st.legacy_phase == "Stranded" and not legacy_live <= st.stranded:
        bad.append("StrandingSound")

    if any(not event[2] for event in st.liability_log):
        bad.append("NewLiabilitySound")

    expected = [2, 0]
    for _, pool, _ in st.liability_log:
        expected[pool_index(pool)] += 1
    if tuple(expected) != st.liabilities:
        bad.append("LiabilitiesAccounted")

    if not st.nullifier_history <= st.nullifiers:
        bad.append("NullifierHistoryPreserved")

    if st.legacy_phase == "Active":
        solvent = (
            total_active_backing(st) >= total_liability(st)
            if st.scope == "GLOBAL"
            else backing_value(active_eligible(st, LEGACY)) >= liability(st, LEGACY)
        )
        if not solvent:
            bad.append("ActiveSolvency")
    if st.successor_phase == "Active":
        solvent = (
            total_active_backing(st) >= total_liability(st)
            if st.scope == "GLOBAL"
            else backing_value(active_eligible(st, SUCCESSOR)) >= liability(st, SUCCESSOR)
        )
        if not solvent and "ActiveSolvency" not in bad:
            bad.append("ActiveSolvency")

    if st.successor_phase == "Active" and not (
        st.successor_gate_ready
        and FRESH_OUTPUTS <= st.created
        and FRESH_OUTPUTS <= st.live
        and st.legacy_phase in {"Stranded", "Retired"}
        and legacy_live <= st.quarantined
    ):
        bad.append("SuccessorIsolation")

    return bad


SCENARIOS = (
    "partial_reshare_active",
    "catastrophic_reshare_stranded",
    "exposure_persists_after_reshare",
    "delayed_recovery_active",
    "strand_reached",
    "successor_continuity",
)


def scenario_hits(st):
    hits = set()
    if (
        st.mode == "RESHARE"
        and "PARTIAL_LOSS" in st.raised
        and st.current_share_epoch == 1
        and st.legacy_phase == "Active"
        and st.current_legacy_key == K0
    ):
        hits.add("partial_reshare_active")
    if (
        st.mode == "RESHARE"
        and "CATASTROPHIC_LOSS" in st.raised
        and st.legacy_phase == "Stranded"
    ):
        hits.add("catastrophic_reshare_stranded")
    if (
        "THRESHOLD_COMPROMISE" in st.raised
        and st.current_share_epoch == 1
        and K0 in st.exposure_history
        and K0 in st.exposed
    ):
        hits.add("exposure_persists_after_reshare")
    if (
        st.mode == "DELAYED"
        and st.legacy_phase == "Active"
        and st.current_legacy_key == KR
        and st.migrated == frozenset(UNITS)
    ):
        hits.add("delayed_recovery_active")
    if st.mode == "STRAND" and st.legacy_phase == "Stranded":
        hits.add("strand_reached")
    if (
        st.successor_phase == "Active"
        and st.legacy_phase in {"Stranded", "Retired"}
        and st.liabilities[0] >= 2
    ):
        hits.add("successor_continuity")
    return hits


def trace_to(state, parents):
    trace = []
    current = state
    while current in parents and parents[current] is not None:
        previous, action = parents[current]
        trace.append(action)
        current = previous
    return list(reversed(trace))


def check(bug="NONE", exhaustive=True, keep_parents=False):
    starts = list(initial_states())
    seen = set(starts)
    queue = deque(starts)
    parents = {st: None for st in starts} if keep_parents else None
    found = {}
    scenarios = set()

    while queue:
        st = queue.popleft()
        scenarios.update(scenario_hits(st))
        for name in invariants(st):
            found.setdefault(name, st)
        if not exhaustive and bug != "NONE" and EXPECTED[bug] in found:
            break
        for action, nxt in successors(st, bug):
            if nxt in seen:
                continue
            seen.add(nxt)
            queue.append(nxt)
            if parents is not None:
                parents[nxt] = (st, action)

    return len(seen), found, scenarios, parents


def run_one(bug, exhaustive, verbose):
    states, found, scenarios, parents = check(
        bug=bug, exhaustive=exhaustive, keep_parents=verbose
    )
    expected = EXPECTED.get(bug)
    if bug == "NONE":
        passed = not found and set(SCENARIOS) <= scenarios
    else:
        passed = expected in found

    result = {
        "bug": bug,
        "states": states,
        "exhaustive": exhaustive,
        "violations": sorted(found),
        "expected": expected,
        "scenarios": sorted(scenarios),
        "passed": passed,
    }
    if verbose and expected in found:
        result["trace"] = trace_to(found[expected], parents)
    return result


def parse_config_bug(path):
    """Parse the one typed Bug assignment, ignoring TLA+ comments."""
    text = Path(path).read_text(encoding="utf-8")
    text = re.sub(r"\(\*.*?\*\)", "", text, flags=re.DOTALL)
    uncommented = []
    for line in text.splitlines():
        uncommented.append(re.sub(r"\\\*.*$", "", line))
    matches = re.findall(
        r'^\s*(?:CONSTANT\s+)?Bug\s*=\s*"([A-Z0-9_]+)"\s*$',
        "\n".join(uncommented),
        flags=re.MULTILINE,
    )
    if len(matches) != 1:
        raise ValueError(
            f"{path}: expected exactly one uncommented Bug assignment, found {matches}"
        )
    if matches[0] not in BUGS:
        raise ValueError(f"{path}: unknown Bug value {matches[0]!r}")
    return matches[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bug", choices=BUGS)
    parser.add_argument("--full-bugs", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--count-only", action="store_true")
    parser.add_argument("--validate-config")
    parser.add_argument("--expect-bug", choices=BUGS)
    args = parser.parse_args()

    if args.validate_config:
        parsed = parse_config_bug(args.validate_config)
        if args.expect_bug is not None and parsed != args.expect_bug:
            parser.error(
                f"{args.validate_config}: Bug is {parsed}, expected {args.expect_bug}"
            )
        print(parsed)
        return 0

    selected = [args.bug] if args.bug else list(BUGS)
    results = []
    for bug in selected:
        exhaustive = bug == "NONE" or args.full_bugs
        result = run_one(bug, exhaustive, args.verbose)
        results.append(result)
        if not args.json and not args.count_only:
            detail = "clean" if not result["violations"] else "violates " + str(result["violations"])
            suffix = "" if exhaustive else " (counterexample search)"
            print(
                f"  {bug:<31} {result['states']:>8} states  "
                f"{'PASS' if result['passed'] else 'FAIL':<4}  {detail}{suffix}"
            )
            if args.verbose and "trace" in result:
                print("      " + " -> ".join(result["trace"]))

    if args.count_only:
        if len(results) != 1:
            parser.error("--count-only requires --bug")
        print(results[0]["states"])
    elif args.json:
        print(json.dumps(results[0] if args.bug else results, sort_keys=True))

    return 0 if all(result["passed"] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
