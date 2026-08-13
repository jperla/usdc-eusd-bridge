#!/usr/bin/env python3
"""Independent finite-state mirror for :mod:`ReserveRecoveryV2.tla`.

This checker is intentionally handwritten.  It gives the design two
independent executable interpretations: TLC evaluates the TLA+ module and
this program evaluates an isomorphic Python transition system.

Synchronization contract
========================

``ReserveRecoveryV2.tla`` is the normative action vocabulary.  Keep the
following items identical before comparing reachable-state counts:

* every finite universe, threshold, phase, feature subset, and accounting
  scope;
* all fields represented by ``State`` and every tuple layout documented
  below;
* every guard, nondeterministic subset choice, simultaneous update, and typed
  ``Bug`` branch in ``ACTION_ORDER``;
* every predicate in ``INVARIANTS``.

Python omits an explicit stutter successor because it cannot add a reachable
state.  Compact representations such as ``owner_overrides`` and
``delayed_outputs`` are bijective encodings of the corresponding TLA+
functions over this bounded universe.

Authority is derived only from explicit share triples.  ``known`` and
``known_history`` never infer historical knowledge from actor identity, and
an honest holder may still use a copied share unless that holder is separately
lost, offline, or expelled.  Consequently c1@K0/e0 plus c3@K0/e1 is not a
threshold in either epoch.

Exact tuple layouts (in TLA+ record-field order)
------------------------------------------------

* Gate event: ``pool, epoch, key, policy, signers, availableSnapshot``
* Owner event: ``key, epoch, roster, signers, availableSnapshot, newShares``
* Reshare event: ``key, fromEpoch, toEpoch, contributors, issuedSnapshot,
  lostSnapshot, expelledSnapshot, offlineSnapshot, newShares``
* Recovery request: ``incident, domain, recoveryPolicy, oldOutputs,
  newOutputs, newOwner, policy, gateKey, ownerDkg, gateDkg, armedAt,
  maturity``
* Recovery authorization: ``request, signedRequest, signers,
  availableSnapshot``
* Owner authorization: ``oldOutputs, newOutputs, oldKey, newKey, shareEpoch,
  signers, availableSnapshot, gateKey, ownerDkg, gateDkg``
* Migration event: ``unit, kind, old, new, time, recoveryAuth, ownerAuth,
  consumedOld``
* Liability event: ``id, pool, eligibleValue, requiredBefore``
* Capital event: ``pool, suppliedOutputs, amount, external``
* Gate authorization event: ``pool, usedKey, expectedKey``
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
from collections import deque
from dataclasses import dataclass, replace
from pathlib import Path


# ---------------------------------------------------------------------------
# Exact finite constants from ReserveRecoveryV2.tla.

RESHARE = "RESHARE"
RECOVERY = "RECOVERY"
SUCCESSOR = "SUCCESSOR"
FEATURE_KINDS = frozenset({RESHARE, RECOVERY, SUCCESSOR})
SCOPES = ("GLOBAL", "SEGREGATED")

CUSTODIANS = frozenset({"c1", "c2", "c3", "c4"})
INITIAL_ROSTER = CUSTODIANS
REPLACEMENT_ROSTER = frozenset({"c3", "c4"})
GATE_OPERATORS = frozenset({"g1", "g2", "g3"})
RECOVERY_OPERATORS = frozenset({"r1", "r2"})
ALL_ACTORS = CUSTODIANS | GATE_OPERATORS | RECOVERY_OPERATORS

K_OWN = 2
K_GATE = 2
K_RECOVERY = 2

INCIDENT_NONE = "NONE"
INCIDENTS = (
    "FALSE",
    "PARTIAL_LOSS",
    "CATASTROPHIC_LOSS",
    "THRESHOLD_COMPROMISE",
    "MIXED_EPOCH",
    "GATE_OUTAGE",
    "RECOVERY_OUTAGE",
)

LEGACY_PHASES = frozenset(
    {
        "Active",
        "Frozen",
        "GateDKG",
        "Ownership",
        "RecoveryDelay",
        "Migrating",
        "Ready",
        "Stranded",
    }
)
SUCCESSOR_PHASES = frozenset({"Absent", "OwnerReady", "Funded", "Ready", "Active"})

K0, KR, KS, KX = "K0", "KR", "KS", "KX"
OWNER_KEYS = frozenset({K0, KR, KS, KX})
G0, G1, GS, NO_GATE = "G0", "G1", "GS", "NO_GATE"
GATE_KEYS = frozenset({G0, G1, GS, NO_GATE})
SHARE_EPOCHS = (0, 1)

RECOVERY_POLICY_V1 = "RECOVERY_V1"
RECOVERY_POLICY_IDS = frozenset({"NONE", RECOVERY_POLICY_V1})
RECOVERY_DOMAIN_V1 = "EUSD_ETH_BRIDGE_V1"
RECOVERY_DOMAINS = frozenset({RECOVERY_DOMAIN_V1, "OTHER_DOMAIN"})

LEGACY_POOL = "legacy"
SUCCESSOR_POOL = "successor"
EXTERNAL_POOL = "external"
POOLS = (LEGACY_POOL, SUCCESSOR_POOL)
UNITS = ("u1", "u2")

LIABILITY_IDS = ("q1", "q2")
INTENT_IDS = ("intent1",)
RECOVERY_DELAY = 1
MAX_TIME = 2


def powerset(values):
    ordered = sorted(values)
    for size in range(len(ordered) + 1):
        for chosen in itertools.combinations(ordered, size):
            yield frozenset(chosen)


FEATURE_CONFIGS = tuple(powerset(FEATURE_KINDS))


# ---------------------------------------------------------------------------
# Physical output universe.  Every injected migration defect creates a real
# alternative output with independently defined metadata.


def old(unit):
    return f"old:{unit}"


def moved(unit):
    return f"moved:{unit}"


def wrong_owner(unit):
    return f"wrong-owner:{unit}"


def wrong_policy(unit):
    return f"wrong-policy:{unit}"


def wrong_value(unit):
    return f"wrong-value:{unit}"


def external(unit):
    return f"external:{unit}"


def fresh(unit):
    return f"fresh:{unit}"


OLD_OUTPUTS = frozenset(old(u) for u in UNITS)
MOVED_OUTPUTS = frozenset(moved(u) for u in UNITS)
WRONG_OWNER_OUTPUTS = frozenset(wrong_owner(u) for u in UNITS)
WRONG_POLICY_OUTPUTS = frozenset(wrong_policy(u) for u in UNITS)
WRONG_VALUE_OUTPUTS = frozenset(wrong_value(u) for u in UNITS)
EXTERNAL_OUTPUTS = frozenset(external(u) for u in UNITS)
FRESH_OUTPUTS = frozenset(fresh(u) for u in UNITS)
REPLACEMENT_VERSIONS = frozenset(
    MOVED_OUTPUTS
    | WRONG_OWNER_OUTPUTS
    | WRONG_POLICY_OUTPUTS
    | WRONG_VALUE_OUTPUTS
    | EXTERNAL_OUTPUTS
)
ALL_OUTPUTS = frozenset(OLD_OUTPUTS | REPLACEMENT_VERSIONS | FRESH_OUTPUTS)


def output_unit(output):
    return output.split(":", 1)[1]


def pool_of(output):
    if output in FRESH_OUTPUTS:
        return SUCCESSOR_POOL
    if output in EXTERNAL_OUTPUTS:
        return EXTERNAL_POOL
    return LEGACY_POOL


def base_value(unit):
    return 1 if unit == "u1" else 2


def value_of(output):
    value = base_value(output_unit(output))
    return value + 1 if output in WRONG_VALUE_OUTPUTS else value


def policy_of(output):
    if output in WRONG_POLICY_OUTPUTS or output in EXTERNAL_OUTPUTS:
        return "OTHER_POLICY"
    if output in FRESH_OUTPUTS:
        return "SUCCESSOR_POLICY"
    return "LEGACY_POLICY"


def birth_owner(output):
    if output in OLD_OUTPUTS:
        return K0
    if output in FRESH_OUTPUTS:
        return KS
    if output in WRONG_OWNER_OUTPUTS or output in EXTERNAL_OUTPUTS:
        return KX
    return KR


INITIAL_SHARES = frozenset((c, K0, 0) for c in INITIAL_ROSTER)


# ---------------------------------------------------------------------------
# State.  Tuple-valued maps use POOLS order: legacy, successor.


@dataclass(frozen=True, slots=True)
class State:
    features: frozenset
    scope: str
    legacy_phase: str
    successor_phase: str
    now: int
    incident: str
    incident_share_epoch: int
    current_share_epoch: int
    current_legacy_key: str

    offline: frozenset

    issued: frozenset
    lost: frozenset
    lost_history: frozenset
    known: frozenset
    known_history: frozenset
    expelled: frozenset

    active_gates: tuple

    created: frozenset
    live: frozenset
    consumed: frozenset
    owner_overrides: frozenset
    delayed_outputs: frozenset
    quarantined: frozenset

    recovery_kind: str
    migrated: frozenset
    recovery_auth_log: frozenset
    owner_auth_log: frozenset

    liabilities: tuple
    reserved: tuple
    capital: tuple
    nullifiers: frozenset
    nullifier_history: frozenset

    gate_log: frozenset
    owner_log: frozenset
    reshare_log: frozenset
    migration_log: frozenset
    liability_log: frozenset
    capital_log: frozenset
    authorization_log: frozenset


INITIAL_GATE_EVENT = (
    LEGACY_POOL,
    0,
    G0,
    "LEGACY_POLICY",
    GATE_OPERATORS,
    ALL_ACTORS,
)

PREMATURE_KR_EVENT = (
    KR,
    0,
    REPLACEMENT_ROSTER,
    REPLACEMENT_ROSTER,
    ALL_ACTORS,
    frozenset((c, KR, 0) for c in REPLACEMENT_ROSTER),
)


def initial_states(feature_filter=None, scope_filter=None):
    for features in FEATURE_CONFIGS:
        if feature_filter is not None and features != feature_filter:
            continue
        for scope in SCOPES:
            if scope_filter is not None and scope != scope_filter:
                continue
            yield State(
                features=features,
                scope=scope,
                legacy_phase="Active",
                successor_phase="Absent",
                now=0,
                incident=INCIDENT_NONE,
                incident_share_epoch=0,
                current_share_epoch=0,
                current_legacy_key=K0,
                offline=frozenset(),
                issued=INITIAL_SHARES,
                lost=frozenset(),
                lost_history=frozenset(),
                known=frozenset(),
                known_history=frozenset(),
                expelled=frozenset(),
                active_gates=(G0, NO_GATE),
                created=OLD_OUTPUTS,
                live=OLD_OUTPUTS,
                consumed=frozenset(),
                owner_overrides=frozenset(),
                delayed_outputs=OLD_OUTPUTS if RECOVERY in features else frozenset(),
                quarantined=frozenset(),
                recovery_kind="NONE",
                migrated=frozenset(),
                recovery_auth_log=frozenset(),
                owner_auth_log=frozenset(),
                liabilities=(2, 0),
                reserved=(1, 0),
                capital=(3, 0),
                nullifiers=frozenset(),
                nullifier_history=frozenset(),
                gate_log=frozenset({INITIAL_GATE_EVENT}),
                owner_log=frozenset(),
                reshare_log=frozenset(),
                migration_log=frozenset(),
                liability_log=frozenset(),
                capital_log=frozenset(),
                authorization_log=frozenset(),
            )


# ---------------------------------------------------------------------------
# Derived authority, inventory, and accounting.


def pool_index(pool):
    return 0 if pool == LEGACY_POOL else 1


def map_get(values, pool):
    return values[pool_index(pool)]


def map_set(values, pool, value):
    result = list(values)
    result[pool_index(pool)] = value
    return tuple(result)


def shares_for(key, epoch, roster):
    return frozenset((c, key, epoch) for c in roster)


def roster_for(key, epoch):
    if key == K0 and epoch == 0:
        return INITIAL_ROSTER
    if key == K0 and epoch == 1:
        return REPLACEMENT_ROSTER
    if key in {KR, KS} and epoch == 0:
        return REPLACEMENT_ROSTER
    return frozenset()


def holders(st, key, epoch):
    return frozenset(c for c in CUSTODIANS if (c, key, epoch) in st.issued)


def usable_holders(st, key, epoch):
    return frozenset(
        c
        for c in holders(st, key, epoch)
        if (c, key, epoch) not in st.lost
        and c not in st.expelled
        and c not in st.offline
    )


def can_operate(st, key, epoch):
    return len(usable_holders(st, key, epoch)) >= K_OWN


def durable_holders(st, key, epoch):
    return frozenset(
        c
        for c in holders(st, key, epoch)
        if (c, key, epoch) not in st.lost and c not in st.expelled
    )


def can_eventually_operate(st, key, epoch):
    return len(durable_holders(st, key, epoch)) >= K_OWN


def adversary_can(st, key):
    return any(
        len({c for c in CUSTODIANS if (c, key, epoch) in st.known}) >= K_OWN
        for epoch in SHARE_EPOCHS
    )


def owner_epoch(st, key):
    return st.current_share_epoch if key == K0 else 0


def owner_key(st, output):
    overrides = dict(st.owner_overrides)
    return overrides.get(output, birth_owner(output))


def active_gate(st, pool):
    return map_get(st.active_gates, pool)


def legacy_live(st):
    return frozenset(o for o in st.live if pool_of(o) == LEGACY_POOL)


def available_actors(st):
    return (ALL_ACTORS - st.offline) - st.expelled


def available_gate_operators(st):
    return GATE_OPERATORS & available_actors(st)


def available_recovery_operators(st):
    return RECOVERY_OPERATORS & available_actors(st)


def available_replacement(st):
    return REPLACEMENT_ROSTER & available_actors(st)


def recovery_bound_on_all_old(st):
    return OLD_OUTPUTS <= st.delayed_outputs


def viable_recovery_capability(st, output):
    return (
        RECOVERY in st.features
        and output in st.delayed_outputs
        and len(RECOVERY_OPERATORS) >= K_RECOVERY
        and len(REPLACEMENT_ROSTER - st.expelled) >= K_OWN
        and len(GATE_OPERATORS) >= K_GATE
    )


def derived_stranded_outputs(st):
    return frozenset(
        output
        for output in legacy_live(st)
        if st.incident != INCIDENT_NONE
        and not adversary_can(st, owner_key(st, output))
        and not can_eventually_operate(
            st, owner_key(st, output), owner_epoch(st, owner_key(st, output))
        )
        and not viable_recovery_capability(st, output)
    )


def controllable(st, output):
    key = owner_key(st, output)
    return can_operate(st, key, owner_epoch(st, key))


def unsafe_outputs(st):
    return frozenset(o for o in st.live if adversary_can(st, owner_key(st, o)))


def candidate_eligible(st, pool):
    stranded = derived_stranded_outputs(st)
    unsafe = unsafe_outputs(st)
    return frozenset(
        o
        for o in st.live
        if pool_of(o) == pool
        and o not in st.quarantined
        and o not in stranded
        and o not in unsafe
        and controllable(st, o)
    )


def pool_active(st, pool):
    return (
        st.legacy_phase == "Active"
        if pool == LEGACY_POOL
        else st.successor_phase == "Active"
    )


def active_eligible(st, pool):
    return candidate_eligible(st, pool) if pool_active(st, pool) else frozenset()


def backing_value(outputs):
    return sum(value_of(output) for output in outputs)


def obligation(st, pool):
    return map_get(st.liabilities, pool) + map_get(st.reserved, pool)


def total_obligation(st):
    return sum(obligation(st, p) for p in POOLS)


def total_active_backing(st):
    return sum(backing_value(active_eligible(st, p)) for p in POOLS)


def correct_capacity(st, pool):
    if st.scope == "GLOBAL":
        return total_active_backing(st) >= total_obligation(st) + 1
    return backing_value(active_eligible(st, pool)) >= obligation(st, pool) + 1


def reported_capacity(st, pool):
    if st.scope == "GLOBAL":
        return backing_value(st.live) >= total_obligation(st) + 1
    return backing_value(o for o in st.live if pool_of(o) == pool) >= obligation(st, pool) + 1


def other_pool(pool):
    return SUCCESSOR_POOL if pool == LEGACY_POOL else LEGACY_POOL


def prospective_backing(st, pool):
    return backing_value(candidate_eligible(st, pool)) + backing_value(
        active_eligible(st, other_pool(pool))
    )


def prospective_solvent(st, pool):
    if st.scope == "GLOBAL":
        return prospective_backing(st, pool) >= total_obligation(st)
    return backing_value(candidate_eligible(st, pool)) >= obligation(st, pool)


def expected_gate_key(pool, epoch):
    if pool == LEGACY_POOL and epoch == 0:
        return G0
    if pool == LEGACY_POOL and epoch == 1:
        return G1
    return GS


def expected_gate_policy(pool):
    return "LEGACY_POLICY" if pool == LEGACY_POOL else "SUCCESSOR_POLICY"


def gate_recorded(st, pool, epoch):
    return any(e[0] == pool and e[1] == epoch for e in st.gate_log)


def owner_recorded(st, key):
    return any(e[0] == key for e in st.owner_log)


def used_liability_ids(st):
    return frozenset(e[0] for e in st.liability_log)


def subsets_at_least(values, threshold):
    return tuple(s for s in powerset(values) if len(s) >= threshold)


def subsets_exact(values, size):
    return tuple(s for s in powerset(values) if len(s) == size)


# ---------------------------------------------------------------------------
# Typed injected defects and exact action ordering.


BUGS = (
    "NONE",
    "RESHARE_WITHOUT_THRESHOLD",
    "RESHARE_WITH_NONHOLDER",
    "RESHARE_WITH_MIXED_EPOCH",
    "ERASE_ISSUED_SHARES",
    "ERASE_LOST_SHARES",
    "ERASE_SHARE_KNOWLEDGE",
    "COMPLETE_GATE_WITHOUT_QUORUM",
    "REUSE_OLD_GATE_KEY",
    "RESUME_BEFORE_GATE_DKG",
    "OWNER_DKG_WITHOUT_QUORUM",
    "OWNER_DKG_WRONG_ROSTER",
    "OWNER_UNBOUND_REQUEST",
    "OWNER_UNLOGGED_AUTH",
    "RETROACTIVE_RECOVERY",
    "RECOVERY_BEFORE_OWNER_DKG",
    "RECOVERY_UNLOGGED_AUTH",
    "RECOVERY_WITHOUT_QUORUM",
    "RECOVERY_UNBOUND_REQUEST",
    "RECOVER_BEFORE_DELAY",
    "RECOVERY_DOES_NOT_CONSUME",
    "RECOVERY_EXTERNAL_RECIPIENT",
    "RECOVERY_WRONG_OWNER",
    "RECOVERY_WRONG_POLICY",
    "RECOVERY_WRONG_VALUE",
    "ROTATE_OWNER_IN_PLACE",
    "ACTIVATE_PARTIAL_MIGRATION",
    "ACTIVATE_UNSAFE_KEY",
    "SUCCESSOR_WITHOUT_DKG",
    "SUCCESSOR_REUSES_GATE",
    "FUND_BEFORE_OWNER_DKG",
    "UNFUNDED_SUCCESSOR",
    "COUNT_INELIGIBLE_BACKING",
    "ERASE_LEGACY_LIABILITY",
    "RESET_RESERVATIONS",
    "RESET_NULLIFIERS",
    "ACCEPT_OLD_GATE",
)


EXPECTED = {
    "RESHARE_WITHOUT_THRESHOLD": "ReshareSound",
    "RESHARE_WITH_NONHOLDER": "ReshareSound",
    "RESHARE_WITH_MIXED_EPOCH": "ReshareSound",
    "ERASE_ISSUED_SHARES": "ShareIssuanceAccounted",
    "ERASE_LOST_SHARES": "ShareHistoryMonotonic",
    "ERASE_SHARE_KNOWLEDGE": "ShareHistoryMonotonic",
    "COMPLETE_GATE_WITHOUT_QUORUM": "GateCeremonySound",
    "REUSE_OLD_GATE_KEY": "FreshGateCeremonies",
    "RESUME_BEFORE_GATE_DKG": "ActiveGateSound",
    "OWNER_DKG_WITHOUT_QUORUM": "OwnerCeremonySound",
    "OWNER_DKG_WRONG_ROSTER": "OwnerCeremonySound",
    "OWNER_UNBOUND_REQUEST": "OwnerMigrationSound",
    "OWNER_UNLOGGED_AUTH": "OwnerMigrationSound",
    "RETROACTIVE_RECOVERY": "RecoveryPolicyImmutable",
    "RECOVERY_BEFORE_OWNER_DKG": "RecoveryAuthorizationSound",
    "RECOVERY_UNLOGGED_AUTH": "RecoveryMigrationBound",
    "RECOVERY_WITHOUT_QUORUM": "RecoveryAuthorizationSound",
    "RECOVERY_UNBOUND_REQUEST": "RecoveryAuthorizationSound",
    "RECOVER_BEFORE_DELAY": "RecoveryDelayHonored",
    "RECOVERY_DOES_NOT_CONSUME": "MigrationConsumesOld",
    "RECOVERY_EXTERNAL_RECIPIENT": "MigrationConservative",
    "RECOVERY_WRONG_OWNER": "MigrationConservative",
    "RECOVERY_WRONG_POLICY": "MigrationConservative",
    "RECOVERY_WRONG_VALUE": "MigrationConservative",
    "ROTATE_OWNER_IN_PLACE": "OutputMetadataImmutable",
    "ACTIVATE_PARTIAL_MIGRATION": "FreshOwnerRequiresFullMigration",
    "ACTIVATE_UNSAFE_KEY": "ActiveOwnershipSound",
    "SUCCESSOR_WITHOUT_DKG": "SuccessorSound",
    "SUCCESSOR_REUSES_GATE": "FreshGateCeremonies",
    "FUND_BEFORE_OWNER_DKG": "CapitalizationSound",
    "UNFUNDED_SUCCESSOR": "CapitalizationSound",
    "COUNT_INELIGIBLE_BACKING": "LiabilityAdmissionSound",
    "ERASE_LEGACY_LIABILITY": "LiabilitiesAccounted",
    "RESET_RESERVATIONS": "ReservationsAccounted",
    "RESET_NULLIFIERS": "NullifierHistoryPreserved",
    "ACCEPT_OLD_GATE": "NoStaleAuthorization",
}


ACTION_ORDER = (
    "ProactiveReshare",
    "RaiseIncident",
    "StartLegacyGateDKG",
    "CompleteLegacyGateDKG",
    "KeepOwner",
    "IncidentReshare",
    "CompleteLegacyOwnerDKG",
    "RetroactivelyEnableRecovery",
    "AuthorizeRecovery",
    "Tick",
    "BeginRecoveryMigration",
    "BeginOwnerMigration",
    "MigrateOne",
    "FinishMigration",
    "DeclareStranded",
    "RotateOwnerInPlace",
    "ActivateLegacy",
    "BypassLegacyGate",
    "ContributeSuccessorCapital",
    "CompleteSuccessorOwnerDKG",
    "CompleteSuccessorGateDKG",
    "ActivateSuccessor",
    "BypassSuccessorDKG",
    "AcceptLiability",
    "ConsumeNullifier",
    "AcceptGateAuthorization",
)


# ---------------------------------------------------------------------------
# Next-state relation.  Each block below has the same name and order as TLA+.


def incident_lost(kind, epoch):
    if kind == "PARTIAL_LOSS":
        if epoch == 0:
            return frozenset({("c1", K0, 0)})
        return frozenset({("c3", K0, 1)})
    if kind == "CATASTROPHIC_LOSS":
        if epoch == 0:
            return frozenset(
                {
                    ("c1", K0, 0),
                    ("c2", K0, 0),
                    ("c3", K0, 0),
                }
            )
        return shares_for(K0, 1, REPLACEMENT_ROSTER)
    return frozenset()


def incident_known(kind, epoch):
    if kind == "THRESHOLD_COMPROMISE":
        if epoch == 0:
            return frozenset({("c1", K0, 0), ("c2", K0, 0)})
        return shares_for(K0, 1, REPLACEMENT_ROSTER)
    if kind == "MIXED_EPOCH":
        return frozenset({("c1", K0, 0), ("c3", K0, 1)})
    return frozenset()


def incident_expelled(kind, epoch):
    if kind == "THRESHOLD_COMPROMISE":
        return (
            frozenset({"c1", "c2"})
            if epoch == 0
            else REPLACEMENT_ROSTER
        )
    if kind == "MIXED_EPOCH":
        return frozenset({"c1"})
    return frozenset()


def incident_offline(kind):
    if kind == "GATE_OUTAGE":
        return frozenset({"g1", "g2"})
    if kind == "RECOVERY_OUTAGE":
        return frozenset({"r1"})
    return frozenset()


def canonical_recovery_request(st, owner_event, gate_event):
    return (
        st.incident,
        RECOVERY_DOMAIN_V1,
        RECOVERY_POLICY_V1,
        OLD_OUTPUTS,
        MOVED_OUTPUTS,
        KR,
        "LEGACY_POLICY",
        G1,
        owner_event,
        gate_event,
        st.now,
        st.now + RECOVERY_DELAY,
    )


def migration_target(unit, bug):
    if bug == "RECOVERY_EXTERNAL_RECIPIENT":
        return external(unit)
    if bug == "RECOVERY_WRONG_OWNER":
        return wrong_owner(unit)
    if bug == "RECOVERY_WRONG_POLICY":
        return wrong_policy(unit)
    if bug == "RECOVERY_WRONG_VALUE":
        return wrong_value(unit)
    return moved(unit)


def successors(st: State, bug: str):
    out = []

    # ProactiveReshare
    if (
        RESHARE in st.features
        and st.incident == INCIDENT_NONE
        and st.legacy_phase == "Active"
        and st.current_share_epoch == 0
    ):
        for contributors in subsets_at_least(usable_holders(st, K0, 0), K_OWN):
            contributor_shares = frozenset((c, K0, 0) for c in contributors)
            new_shares = shares_for(K0, 1, REPLACEMENT_ROSTER)
            event = (
                K0,
                0,
                1,
                contributor_shares,
                st.issued,
                st.lost,
                st.expelled,
                st.offline,
                new_shares,
            )
            out.append(
                (
                    f"ProactiveReshare({','.join(sorted(contributors))})",
                    replace(
                        st,
                        current_share_epoch=1,
                        issued=(
                            new_shares
                            if bug == "ERASE_ISSUED_SHARES"
                            else st.issued | new_shares
                        ),
                        reshare_log=st.reshare_log | {event},
                    ),
                )
            )

    # RaiseIncident
    if st.incident == INCIDENT_NONE and st.legacy_phase == "Active":
        for kind in INCIDENTS:
            if kind == "MIXED_EPOCH" and st.current_share_epoch != 1:
                continue
            lost = incident_lost(kind, st.current_share_epoch)
            known = incident_known(kind, st.current_share_epoch)
            if not lost <= st.issued or not known <= st.issued:
                continue
            out.append(
                (
                    f"RaiseIncident({kind})",
                    replace(
                        st,
                        legacy_phase="Frozen",
                        incident=kind,
                        incident_share_epoch=st.current_share_epoch,
                        offline=st.offline | incident_offline(kind),
                        lost=st.lost | lost,
                        lost_history=st.lost_history | lost,
                        known=st.known | known,
                        known_history=st.known_history | known,
                        expelled=st.expelled
                        | incident_expelled(kind, st.current_share_epoch),
                    ),
                )
            )

    # StartLegacyGateDKG
    if st.legacy_phase == "Frozen":
        out.append(("StartLegacyGateDKG", replace(st, legacy_phase="GateDKG")))

    # CompleteLegacyGateDKG
    if st.legacy_phase == "GateDKG":
        eligible = available_gate_operators(st)
        signer_sets = (
            subsets_exact(eligible, 1)
            if bug == "COMPLETE_GATE_WITHOUT_QUORUM"
            else subsets_at_least(eligible, K_GATE)
        )
        for signers in signer_sets:
            key = G0 if bug == "REUSE_OLD_GATE_KEY" else G1
            event = (
                LEGACY_POOL,
                1,
                key,
                "LEGACY_POLICY",
                signers,
                available_actors(st),
            )
            out.append(
                (
                    f"CompleteLegacyGateDKG({','.join(sorted(signers))})",
                    replace(
                        st,
                        legacy_phase="Ownership",
                        gate_log=st.gate_log | {event},
                    ),
                )
            )

    # KeepOwner
    if (
        st.legacy_phase == "Ownership"
        and can_operate(
            st,
            st.current_legacy_key,
            owner_epoch(st, st.current_legacy_key),
        )
    ):
        out.append(("KeepOwner", replace(st, legacy_phase="Ready")))

    # IncidentReshare
    if (
        st.legacy_phase == "Ownership"
        and RESHARE in st.features
        and st.current_legacy_key == K0
        and st.current_share_epoch == 0
    ):
        eligible = usable_holders(st, K0, 0)
        if bug == "RESHARE_WITH_NONHOLDER":
            chosen_sets = tuple(s for s in powerset(eligible) if s)
        elif bug == "RESHARE_WITH_MIXED_EPOCH":
            chosen_sets = tuple(s for s in powerset(eligible) if s)
        elif bug == "RESHARE_WITHOUT_THRESHOLD":
            chosen_sets = tuple(s for s in powerset(eligible) if s)
        else:
            chosen_sets = subsets_at_least(eligible, K_OWN)
        for chosen in chosen_sets:
            if bug == "RESHARE_WITH_NONHOLDER":
                contributor_shares = frozenset({("g1", K0, 0), ("g2", K0, 0)})
            elif bug == "RESHARE_WITH_MIXED_EPOCH":
                contributor_shares = frozenset({("c1", K0, 0), ("c3", K0, 1)})
            else:
                contributor_shares = frozenset((c, K0, 0) for c in chosen)
            new_shares = shares_for(K0, 1, REPLACEMENT_ROSTER)
            event = (
                K0,
                0,
                1,
                contributor_shares,
                st.issued,
                st.lost,
                st.expelled,
                st.offline,
                new_shares,
            )
            out.append(
                (
                    f"IncidentReshare({','.join(sorted(chosen))})",
                    replace(
                        st,
                        legacy_phase="Ready",
                        current_share_epoch=1,
                        issued=(
                            new_shares
                            if bug == "ERASE_ISSUED_SHARES"
                            else st.issued | new_shares
                        ),
                        lost=(
                            frozenset()
                            if bug == "ERASE_LOST_SHARES"
                            else st.lost
                        ),
                        lost_history=(
                            frozenset()
                            if bug == "ERASE_LOST_SHARES"
                            else st.lost_history
                        ),
                        known=(
                            frozenset()
                            if bug == "ERASE_SHARE_KNOWLEDGE"
                            else st.known
                        ),
                        known_history=(
                            frozenset()
                            if bug == "ERASE_SHARE_KNOWLEDGE"
                            else st.known_history
                        ),
                        reshare_log=st.reshare_log | {event},
                    ),
                )
            )

    # CompleteLegacyOwnerDKG
    if (
        st.legacy_phase in {"Ownership", "Ready", "RecoveryDelay"}
        and not owner_recorded(st, KR)
    ):
        eligible = available_replacement(st)
        signer_sets = (
            subsets_exact(eligible, 1)
            if bug == "OWNER_DKG_WITHOUT_QUORUM"
            else subsets_at_least(eligible, K_OWN)
        )
        for signers in signer_sets:
            roster = (
                INITIAL_ROSTER
                if bug == "OWNER_DKG_WRONG_ROSTER"
                else REPLACEMENT_ROSTER
            )
            new_shares = shares_for(KR, 0, roster)
            event = (
                KR,
                0,
                roster,
                signers,
                available_actors(st),
                new_shares,
            )
            out.append(
                (
                    f"CompleteLegacyOwnerDKG({','.join(sorted(signers))})",
                    replace(
                        st,
                        issued=st.issued | new_shares,
                        owner_log=st.owner_log | {event},
                    ),
                )
            )

    # RetroactivelyEnableRecovery
    if (
        bug == "RETROACTIVE_RECOVERY"
        and st.legacy_phase == "Ownership"
        and RECOVERY not in st.features
    ):
        out.append(
            (
                "RetroactivelyEnableRecovery",
                replace(st, delayed_outputs=st.delayed_outputs | OLD_OUTPUTS),
            )
        )

    # AuthorizeRecovery
    if (
        st.legacy_phase == "Ownership"
        and (RECOVERY in st.features or bug == "RETROACTIVE_RECOVERY")
        and recovery_bound_on_all_old(st)
    ):
        owner_events = (
            (PREMATURE_KR_EVENT,)
            if bug == "RECOVERY_BEFORE_OWNER_DKG"
            else tuple(e for e in st.owner_log if e[0] == KR)
        )
        gate_events = tuple(
            e
            for e in st.gate_log
            if e[0] == LEGACY_POOL and e[1] == 1 and e[2] == G1
        )
        eligible = available_recovery_operators(st)
        signer_sets = (
            subsets_exact(eligible, 1)
            if bug == "RECOVERY_WITHOUT_QUORUM"
            else subsets_at_least(eligible, K_RECOVERY)
        )
        for owner_event in owner_events:
            for gate_event in gate_events:
                for signers in signer_sets:
                    request = canonical_recovery_request(
                        st, owner_event, gate_event
                    )
                    if bug == "RECOVERY_UNBOUND_REQUEST":
                        signed_request = request[:7] + (G0,) + request[8:]
                    else:
                        signed_request = request
                    auth = (
                        request,
                        signed_request,
                        signers,
                        available_actors(st),
                    )
                    out.append(
                        (
                            f"AuthorizeRecovery({','.join(sorted(signers))})",
                            replace(
                                st,
                                legacy_phase="RecoveryDelay",
                                recovery_auth_log=st.recovery_auth_log | {auth},
                            ),
                        )
                    )

    # Tick
    if st.legacy_phase == "RecoveryDelay" and st.now < MAX_TIME:
        out.append(("Tick", replace(st, now=st.now + 1)))

    # BeginRecoveryMigration
    if (
        st.legacy_phase == "RecoveryDelay"
        and st.recovery_auth_log
        and owner_recorded(st, KR)
        and any(
            st.now >= auth[0][11] or bug == "RECOVER_BEFORE_DELAY"
            for auth in st.recovery_auth_log
        )
    ):
        out.append(
            (
                "BeginRecoveryMigration",
                replace(
                    st,
                    legacy_phase="Migrating",
                    recovery_kind="RECOVERY",
                    migrated=frozenset(),
                ),
            )
        )

    # BeginOwnerMigration
    if (
        st.legacy_phase in {"Ownership", "Ready"}
        and st.current_legacy_key == K0
        and adversary_can(st, K0)
    ):
        owner_events = tuple(e for e in st.owner_log if e[0] == KR)
        gate_events = tuple(
            e
            for e in st.gate_log
            if e[0] == LEGACY_POOL and e[1] == 1 and e[2] == G1
        )
        for owner_event in owner_events:
            for gate_event in gate_events:
                for signers in subsets_at_least(
                    usable_holders(st, K0, st.current_share_epoch), K_OWN
                ):
                    auth = (
                        OLD_OUTPUTS,
                        MOVED_OUTPUTS,
                        KR if bug == "OWNER_UNBOUND_REQUEST" else K0,
                        KR,
                        st.current_share_epoch,
                        signers,
                        available_actors(st),
                        G1,
                        owner_event,
                        gate_event,
                    )
                    out.append(
                        (
                            f"BeginOwnerMigration({','.join(sorted(signers))})",
                            replace(
                                st,
                                legacy_phase="Migrating",
                                recovery_kind="OWNER",
                                migrated=frozenset(),
                                owner_auth_log=st.owner_auth_log | {auth},
                            ),
                        )
                    )

    # MigrateOne
    if st.legacy_phase == "Migrating" and st.recovery_kind in {"OWNER", "RECOVERY"}:
        for unit in UNITS:
            if unit in st.migrated or old(unit) not in st.live:
                continue
            if st.recovery_kind == "OWNER" and not st.owner_auth_log:
                continue
            if st.recovery_kind == "RECOVERY" and not st.recovery_auth_log:
                continue
            target = (
                migration_target(unit, bug)
                if st.recovery_kind == "RECOVERY"
                else moved(unit)
            )
            consume = not (
                bug == "RECOVERY_DOES_NOT_CONSUME"
                and st.recovery_kind == "RECOVERY"
            )
            r_auth = (
                frozenset(
                    (auth[0], auth[1], frozenset(), auth[3])
                    for auth in st.recovery_auth_log
                )
                if st.recovery_kind == "RECOVERY"
                and bug == "RECOVERY_UNLOGGED_AUTH"
                else st.recovery_auth_log
                if st.recovery_kind == "RECOVERY"
                else frozenset()
            )
            o_auth = (
                frozenset(
                    auth[:6] + (ALL_ACTORS,) + auth[7:]
                    for auth in st.owner_auth_log
                )
                if st.recovery_kind == "OWNER"
                and bug == "OWNER_UNLOGGED_AUTH"
                else st.owner_auth_log
                if st.recovery_kind == "OWNER"
                else frozenset()
            )
            event = (
                unit,
                st.recovery_kind,
                old(unit),
                target,
                st.now,
                r_auth,
                o_auth,
                consume,
            )
            out.append(
                (
                    f"MigrateOne({unit})",
                    replace(
                        st,
                        migrated=st.migrated | {unit},
                        created=st.created | {target},
                        live=((st.live - {old(unit)}) if consume else st.live)
                        | {target},
                        consumed=(
                            st.consumed | {old(unit)} if consume else st.consumed
                        ),
                        quarantined=(
                            st.quarantined - {old(unit)}
                            if consume
                            else st.quarantined
                        ),
                        migration_log=st.migration_log | {event},
                    ),
                )
            )

    # FinishMigration
    if (
        st.legacy_phase == "Migrating"
        and st.migrated
        and (
            st.migrated == frozenset(UNITS)
            or bug == "ACTIVATE_PARTIAL_MIGRATION"
        )
    ):
        out.append(
            (
                "FinishMigration",
                replace(
                    st,
                    legacy_phase="Ready",
                    current_legacy_key=KR,
                    current_share_epoch=0,
                    recovery_kind="NONE",
                ),
            )
        )

    # DeclareStranded
    if (
        st.incident != INCIDENT_NONE
        and st.legacy_phase
        in {"Frozen", "GateDKG", "Ownership", "Ready", "RecoveryDelay"}
        and legacy_live(st)
        and legacy_live(st) <= derived_stranded_outputs(st)
    ):
        out.append(("DeclareStranded", replace(st, legacy_phase="Stranded")))

    # RotateOwnerInPlace
    if bug == "ROTATE_OWNER_IN_PLACE" and st.legacy_phase == "Ownership":
        for output in sorted(st.live & OLD_OUTPUTS):
            overrides = dict(st.owner_overrides)
            overrides[output] = KR
            out.append(
                (
                    f"RotateOwnerInPlace({output_unit(output)})",
                    replace(st, owner_overrides=frozenset(overrides.items())),
                )
            )

    # ActivateLegacy
    if (
        st.legacy_phase == "Ready"
        and gate_recorded(st, LEGACY_POOL, 1)
        and can_operate(
            st,
            st.current_legacy_key,
            owner_epoch(st, st.current_legacy_key),
        )
        and (
            not adversary_can(st, st.current_legacy_key)
            or bug == "ACTIVATE_UNSAFE_KEY"
        )
        and (
            prospective_solvent(st, LEGACY_POOL)
            or bug in {"ACTIVATE_PARTIAL_MIGRATION", "ACTIVATE_UNSAFE_KEY"}
        )
    ):
        out.append(
            (
                "ActivateLegacy",
                replace(
                    st,
                    legacy_phase="Active",
                    active_gates=map_set(st.active_gates, LEGACY_POOL, G1),
                ),
            )
        )

    # BypassLegacyGate
    if (
        bug == "RESUME_BEFORE_GATE_DKG"
        and st.legacy_phase == "Frozen"
        and can_operate(
            st,
            st.current_legacy_key,
            owner_epoch(st, st.current_legacy_key),
        )
    ):
        out.append(
            (
                "BypassLegacyGate",
                replace(
                    st,
                    legacy_phase="Active",
                    active_gates=map_set(st.active_gates, LEGACY_POOL, G1),
                ),
            )
        )

    # ContributeSuccessorCapital
    if (
        SUCCESSOR in st.features
        and st.incident != INCIDENT_NONE
        and (
            st.successor_phase == "OwnerReady"
            or (
                bug == "FUND_BEFORE_OWNER_DKG"
                and st.successor_phase == "Absent"
            )
        )
    ):
        event = (SUCCESSOR_POOL, FRESH_OUTPUTS, 3, True)
        out.append(
            (
                "ContributeSuccessorCapital",
                replace(
                    st,
                    successor_phase="Funded",
                    created=st.created | FRESH_OUTPUTS,
                    live=st.live | FRESH_OUTPUTS,
                    capital=(
                        st.capital
                        if bug == "UNFUNDED_SUCCESSOR"
                        else map_set(st.capital, SUCCESSOR_POOL, map_get(st.capital, SUCCESSOR_POOL) + 3)
                    ),
                    liabilities=(
                        map_set(st.liabilities, LEGACY_POOL, 0)
                        if bug == "ERASE_LEGACY_LIABILITY"
                        else st.liabilities
                    ),
                    reserved=(
                        map_set(st.reserved, LEGACY_POOL, 0)
                        if bug == "RESET_RESERVATIONS"
                        else st.reserved
                    ),
                    nullifiers=(
                        frozenset()
                        if bug == "RESET_NULLIFIERS"
                        else st.nullifiers
                    ),
                    capital_log=(
                        st.capital_log
                        if bug == "UNFUNDED_SUCCESSOR"
                        else st.capital_log | {event}
                    ),
                ),
            )
        )

    # CompleteSuccessorOwnerDKG
    if (
        SUCCESSOR in st.features
        and st.incident != INCIDENT_NONE
        and st.successor_phase == "Absent"
    ):
        for signers in subsets_at_least(available_replacement(st), K_OWN):
            roster = (
                INITIAL_ROSTER
                if bug == "OWNER_DKG_WRONG_ROSTER"
                else REPLACEMENT_ROSTER
            )
            new_shares = shares_for(KS, 0, roster)
            event = (
                KS,
                0,
                roster,
                signers,
                available_actors(st),
                new_shares,
            )
            out.append(
                (
                    f"CompleteSuccessorOwnerDKG({','.join(sorted(signers))})",
                    replace(
                        st,
                        successor_phase="OwnerReady",
                        issued=st.issued | new_shares,
                        owner_log=st.owner_log | {event},
                    ),
                )
            )

    # CompleteSuccessorGateDKG
    if st.successor_phase == "Funded":
        for signers in subsets_at_least(available_gate_operators(st), K_GATE):
            key = G1 if bug == "SUCCESSOR_REUSES_GATE" else GS
            event = (
                SUCCESSOR_POOL,
                0,
                key,
                "SUCCESSOR_POLICY",
                signers,
                available_actors(st),
            )
            out.append(
                (
                    f"CompleteSuccessorGateDKG({','.join(sorted(signers))})",
                    replace(
                        st,
                        successor_phase="Ready",
                        gate_log=st.gate_log | {event},
                    ),
                )
            )

    # ActivateSuccessor
    if (
        st.successor_phase == "Ready"
        and owner_recorded(st, KS)
        and gate_recorded(st, SUCCESSOR_POOL, 0)
        and can_operate(st, KS, 0)
        and prospective_solvent(st, SUCCESSOR_POOL)
    ):
        out.append(
            (
                "ActivateSuccessor",
                replace(
                    st,
                    successor_phase="Active",
                    active_gates=map_set(st.active_gates, SUCCESSOR_POOL, GS),
                    quarantined=(
                        st.quarantined
                        if st.legacy_phase == "Active"
                        else st.quarantined | legacy_live(st)
                    ),
                ),
            )
        )

    # BypassSuccessorDKG
    if bug == "SUCCESSOR_WITHOUT_DKG" and st.successor_phase == "Funded":
        out.append(
            (
                "BypassSuccessorDKG",
                replace(
                    st,
                    successor_phase="Active",
                    active_gates=map_set(st.active_gates, SUCCESSOR_POOL, GS),
                    quarantined=(
                        st.quarantined
                        if st.legacy_phase == "Active"
                        else st.quarantined | legacy_live(st)
                    ),
                ),
            )
        )

    # AcceptLiability
    for pool in POOLS:
        if not pool_active(st, pool):
            continue
        for liability_id in LIABILITY_IDS:
            if liability_id in used_liability_ids(st):
                continue
            if not (
                correct_capacity(st, pool)
                or (bug == "COUNT_INELIGIBLE_BACKING" and reported_capacity(st, pool))
            ):
                continue
            eligible_value = (
                total_active_backing(st)
                if st.scope == "GLOBAL"
                else backing_value(active_eligible(st, pool))
            )
            required = (
                total_obligation(st)
                if st.scope == "GLOBAL"
                else obligation(st, pool)
            )
            event = (liability_id, pool, eligible_value, required)
            out.append(
                (
                    f"AcceptLiability({pool},{liability_id})",
                    replace(
                        st,
                        liabilities=map_set(
                            st.liabilities,
                            pool,
                            map_get(st.liabilities, pool) + 1,
                        ),
                        liability_log=st.liability_log | {event},
                    ),
                )
            )

    # ConsumeNullifier
    for intent in INTENT_IDS:
        if intent not in st.nullifiers:
            out.append(
                (
                    f"ConsumeNullifier({intent})",
                    replace(
                        st,
                        nullifiers=st.nullifiers | {intent},
                        nullifier_history=st.nullifier_history | {intent},
                    ),
                )
            )

    # AcceptGateAuthorization
    if st.legacy_phase == "Active" and st.incident != INCIDENT_NONE:
        used = G0 if bug == "ACCEPT_OLD_GATE" else active_gate(st, LEGACY_POOL)
        event = (LEGACY_POOL, used, active_gate(st, LEGACY_POOL))
        out.append(
            (
                "AcceptGateAuthorization",
                replace(st, authorization_log=st.authorization_log | {event}),
            )
        )

    return out


# ---------------------------------------------------------------------------
# TypeOK and invariant mirror.  No invariant branches on ``bug``.


def is_share_triple(value):
    return (
        isinstance(value, tuple)
        and len(value) == 3
        and value[0] in CUSTODIANS
        and value[1] in OWNER_KEYS
        and value[2] in SHARE_EPOCHS
    )


def is_share_claim(value):
    return (
        isinstance(value, tuple)
        and len(value) == 3
        and value[0] in ALL_ACTORS
        and value[1] in OWNER_KEYS
        and value[2] in SHARE_EPOCHS
    )


def is_subset_field(value, universe):
    return isinstance(value, frozenset) and value <= universe


def is_gate_event(e):
    return (
        isinstance(e, tuple)
        and len(e) == 6
        and e[0] in POOLS
        and e[1] in SHARE_EPOCHS
        and e[2] in GATE_KEYS
        and e[3] in {"LEGACY_POLICY", "SUCCESSOR_POLICY"}
        and is_subset_field(e[4], ALL_ACTORS)
        and is_subset_field(e[5], ALL_ACTORS)
    )


def is_owner_event(e):
    return (
        isinstance(e, tuple)
        and len(e) == 6
        and e[0] in OWNER_KEYS
        and e[1] in SHARE_EPOCHS
        and is_subset_field(e[2], CUSTODIANS)
        and is_subset_field(e[3], ALL_ACTORS)
        and is_subset_field(e[4], ALL_ACTORS)
        and isinstance(e[5], frozenset)
        and all(is_share_triple(x) for x in e[5])
    )


def is_reshare_event(e):
    return (
        isinstance(e, tuple)
        and len(e) == 9
        and e[0] in OWNER_KEYS
        and e[1] in SHARE_EPOCHS
        and e[2] in SHARE_EPOCHS
        and isinstance(e[3], frozenset)
        and all(is_share_claim(x) for x in e[3])
        and isinstance(e[4], frozenset)
        and all(is_share_triple(x) for x in e[4])
        and isinstance(e[5], frozenset)
        and all(is_share_triple(x) for x in e[5])
        and is_subset_field(e[6], CUSTODIANS)
        and is_subset_field(e[7], ALL_ACTORS)
        and isinstance(e[8], frozenset)
        and all(is_share_triple(x) for x in e[8])
    )


def is_recovery_request(r):
    return (
        isinstance(r, tuple)
        and len(r) == 12
        and r[0] in INCIDENTS
        and r[1] in RECOVERY_DOMAINS
        and r[2] in RECOVERY_POLICY_IDS
        and is_subset_field(r[3], ALL_OUTPUTS)
        and is_subset_field(r[4], ALL_OUTPUTS)
        and r[5] in OWNER_KEYS
        and r[6] in {"LEGACY_POLICY", "SUCCESSOR_POLICY", "OTHER_POLICY"}
        and r[7] in GATE_KEYS
        and is_owner_event(r[8])
        and is_gate_event(r[9])
        and type(r[10]) is int
        and 0 <= r[10] <= MAX_TIME
        and type(r[11]) is int
        and 0 <= r[11] <= MAX_TIME
    )


def is_recovery_auth(a):
    return (
        isinstance(a, tuple)
        and len(a) == 4
        and is_recovery_request(a[0])
        and is_recovery_request(a[1])
        and is_subset_field(a[2], ALL_ACTORS)
        and is_subset_field(a[3], ALL_ACTORS)
    )


def is_owner_auth(a):
    return (
        isinstance(a, tuple)
        and len(a) == 10
        and is_subset_field(a[0], ALL_OUTPUTS)
        and is_subset_field(a[1], ALL_OUTPUTS)
        and a[2] in OWNER_KEYS
        and a[3] in OWNER_KEYS
        and a[4] in SHARE_EPOCHS
        and is_subset_field(a[5], ALL_ACTORS)
        and is_subset_field(a[6], ALL_ACTORS)
        and a[7] in GATE_KEYS
        and is_owner_event(a[8])
        and is_gate_event(a[9])
    )


def is_migration_event(m):
    return (
        isinstance(m, tuple)
        and len(m) == 8
        and m[0] in UNITS
        and m[1] in {"OWNER", "RECOVERY"}
        and m[2] in ALL_OUTPUTS
        and m[3] in ALL_OUTPUTS
        and type(m[4]) is int
        and 0 <= m[4] <= MAX_TIME
        and isinstance(m[5], frozenset)
        and all(is_recovery_auth(a) for a in m[5])
        and isinstance(m[6], frozenset)
        and all(is_owner_auth(a) for a in m[6])
        and isinstance(m[7], bool)
    )


def type_ok(st):
    if not isinstance(st, State):
        return False
    if not is_subset_field(st.features, FEATURE_KINDS) or st.scope not in SCOPES:
        return False
    if st.legacy_phase not in LEGACY_PHASES or st.successor_phase not in SUCCESSOR_PHASES:
        return False
    if type(st.now) is not int or not 0 <= st.now <= MAX_TIME:
        return False
    if st.incident not in {INCIDENT_NONE, *INCIDENTS}:
        return False
    if st.incident_share_epoch not in SHARE_EPOCHS:
        return False
    if st.current_share_epoch not in SHARE_EPOCHS or st.current_legacy_key not in {K0, KR}:
        return False
    if not is_subset_field(st.offline, ALL_ACTORS):
        return False
    for field in (st.issued, st.lost, st.lost_history, st.known, st.known_history):
        if not isinstance(field, frozenset) or not all(is_share_triple(x) for x in field):
            return False
    if not is_subset_field(st.expelled, CUSTODIANS):
        return False
    if (
        not isinstance(st.active_gates, tuple)
        or len(st.active_gates) != 2
        or any(k not in GATE_KEYS for k in st.active_gates)
    ):
        return False
    for field in (st.created, st.live, st.consumed, st.delayed_outputs, st.quarantined):
        if not is_subset_field(field, ALL_OUTPUTS):
            return False
    if (
        not isinstance(st.owner_overrides, frozenset)
        or any(
            not isinstance(pair, tuple)
            or len(pair) != 2
            or pair[0] not in ALL_OUTPUTS
            or pair[1] not in OWNER_KEYS
            for pair in st.owner_overrides
        )
        or len(dict(st.owner_overrides)) != len(st.owner_overrides)
        or any(
            value == birth_owner(output)
            for output, value in st.owner_overrides
        )
    ):
        return False
    if st.recovery_kind not in {"NONE", "OWNER", "RECOVERY"}:
        return False
    if not is_subset_field(st.migrated, frozenset(UNITS)):
        return False
    if not isinstance(st.recovery_auth_log, frozenset) or not all(is_recovery_auth(a) for a in st.recovery_auth_log):
        return False
    if not isinstance(st.owner_auth_log, frozenset) or not all(is_owner_auth(a) for a in st.owner_auth_log):
        return False
    for values, maximum in ((st.liabilities, 4), (st.reserved, 2), (st.capital, 6)):
        if (
            not isinstance(values, tuple)
            or len(values) != 2
            or any(type(v) is not int or not 0 <= v <= maximum for v in values)
        ):
            return False
    if not is_subset_field(st.nullifiers, frozenset(INTENT_IDS)) or not is_subset_field(st.nullifier_history, frozenset(INTENT_IDS)):
        return False
    if not isinstance(st.gate_log, frozenset) or not all(is_gate_event(e) for e in st.gate_log):
        return False
    if not isinstance(st.owner_log, frozenset) or not all(is_owner_event(e) for e in st.owner_log):
        return False
    if not isinstance(st.reshare_log, frozenset) or not all(is_reshare_event(e) for e in st.reshare_log):
        return False
    if not isinstance(st.migration_log, frozenset) or not all(is_migration_event(e) for e in st.migration_log):
        return False
    if not isinstance(st.liability_log, frozenset) or not all(
        isinstance(e, tuple)
        and len(e) == 4
        and e[0] in LIABILITY_IDS
        and e[1] in POOLS
        and type(e[2]) is int
        and 0 <= e[2] <= 20
        and type(e[3]) is int
        and 0 <= e[3] <= 20
        for e in st.liability_log
    ):
        return False
    if not isinstance(st.capital_log, frozenset) or not all(
        isinstance(e, tuple)
        and len(e) == 4
        and e[0] in POOLS
        and is_subset_field(e[1], ALL_OUTPUTS)
        and type(e[2]) is int
        and 0 <= e[2] <= 20
        and isinstance(e[3], bool)
        for e in st.capital_log
    ):
        return False
    if not isinstance(st.authorization_log, frozenset) or not all(
        isinstance(e, tuple)
        and len(e) == 3
        and e[0] in POOLS
        and e[1] in GATE_KEYS
        and e[2] in GATE_KEYS
        for e in st.authorization_log
    ):
        return False
    return True


def logged_reshare_shares(st):
    result = set()
    for event in st.reshare_log:
        result.update(event[8])
    return frozenset(result)


def logged_owner_shares(st):
    result = set()
    for event in st.owner_log:
        result.update(event[5])
    return frozenset(result)


def expected_liability(st, pool):
    return (2 if pool == LEGACY_POOL else 0) + sum(
        1 for event in st.liability_log if event[1] == pool
    )


def expected_capital(st, pool):
    return (3 if pool == LEGACY_POOL else 0) + (
        3 if any(event[0] == pool for event in st.capital_log) else 0
    )


def inv_output_metadata_immutable(st):
    return all(owner_key(st, o) == birth_owner(o) for o in ALL_OUTPUTS)


def inv_recovery_policy_immutable(st):
    expected = OLD_OUTPUTS if RECOVERY in st.features else frozenset()
    return st.delayed_outputs == expected


def inv_output_conservation(st):
    if st.live & st.consumed:
        return False
    if st.created != st.live | st.consumed:
        return False
    if not st.quarantined <= st.live:
        return False
    for unit in UNITS:
        versions = {
            old(unit),
            moved(unit),
            wrong_owner(unit),
            wrong_policy(unit),
            wrong_value(unit),
            external(unit),
        }
        if len(st.live & versions) > 1:
            return False
    return True


def inv_share_issuance_accounted(st):
    return st.issued == INITIAL_SHARES | logged_reshare_shares(st) | logged_owner_shares(st)


def inv_share_history_monotonic(st):
    expected_lost = (
        frozenset()
        if st.incident == INCIDENT_NONE
        else incident_lost(st.incident, st.incident_share_epoch)
    )
    expected_known = (
        frozenset()
        if st.incident == INCIDENT_NONE
        else incident_known(st.incident, st.incident_share_epoch)
    )
    return (
        st.lost_history == expected_lost
        and st.known_history == expected_known
        and st.lost_history <= st.lost
        and st.known_history <= st.known
        and st.lost <= st.issued
        and st.known <= st.issued
    )


def inv_mixed_epoch_not_threshold(st):
    return st.incident != "MIXED_EPOCH" or not adversary_can(st, K0)


def inv_reshare_sound(st):
    for e in st.reshare_log:
        key, from_epoch, to_epoch, contributor_shares, issued_snapshot, lost_snapshot, expelled_snapshot, offline_snapshot, new_shares = e
        eligible_claims = frozenset(
            (c, key, from_epoch)
            for c in CUSTODIANS
            if (c, key, from_epoch) in issued_snapshot
            and (c, key, from_epoch) not in lost_snapshot
            and c not in expelled_snapshot
            and c not in offline_snapshot
        )
        if not (
            key == K0
            and to_epoch == from_epoch + 1
            and len({claim[0] for claim in contributor_shares}) >= K_OWN
            and contributor_shares <= eligible_claims
            and new_shares == shares_for(key, to_epoch, REPLACEMENT_ROSTER)
        ):
            return False
    return True


def inv_gate_ceremony_sound(st):
    for e in st.gate_log:
        pool, epoch, key, policy, signers, snapshot = e
        if not (
            signers <= GATE_OPERATORS & snapshot
            and len(signers) >= K_GATE
            and key == expected_gate_key(pool, epoch)
            and policy == expected_gate_policy(pool)
        ):
            return False
    return True


def inv_fresh_gate_ceremonies(st):
    return all(
        not (e[0] == LEGACY_POOL and e[1] == 1) or e[2] != G0
        for e in st.gate_log
    ) and all(
        e[0] != SUCCESSOR_POOL or e[2] not in {G0, G1}
        for e in st.gate_log
    )


def inv_owner_ceremony_sound(st):
    for e in st.owner_log:
        key, epoch, roster, signers, snapshot, new_shares = e
        if not (
            key in {KR, KS}
            and epoch == 0
            and roster == REPLACEMENT_ROSTER
            and signers <= roster & snapshot
            and len(signers) >= K_OWN
            and new_shares == shares_for(key, epoch, roster)
        ):
            return False
    return True


def inv_recovery_authorization_sound(st):
    for auth in st.recovery_auth_log:
        request, signed, signers, snapshot = auth
        if not (
            request == signed
            and request[0] == st.incident
            and request[0] != INCIDENT_NONE
            and request[1] == RECOVERY_DOMAIN_V1
            and request[2] == RECOVERY_POLICY_V1
            and request[3] == OLD_OUTPUTS
            and request[4] == MOVED_OUTPUTS
            and request[5] == KR
            and request[6] == "LEGACY_POLICY"
            and request[7] == G1
            and request[8] in st.owner_log
            and request[8][0] == request[5]
            and request[8][2] == REPLACEMENT_ROSTER
            and request[9] in st.gate_log
            and request[9][0] == LEGACY_POOL
            and request[9][1] == 1
            and request[9][2] == request[7]
            and request[3] <= st.delayed_outputs
            and request[11] == request[10] + RECOVERY_DELAY
            and signers <= RECOVERY_OPERATORS & snapshot
            and len(signers) >= K_RECOVERY
        ):
            return False
    return True


def inv_recovery_delay_honored(st):
    return all(
        event[1] != "RECOVERY"
        or all(event[4] >= auth[0][11] for auth in event[5])
        for event in st.migration_log
    )


def inv_recovery_branch_confinement(st):
    return all(
        event[1] != "RECOVERY" or event[2] in st.delayed_outputs
        for event in st.migration_log
    )


def inv_recovery_migration_bound(st):
    for event in st.migration_log:
        if event[1] != "RECOVERY":
            continue
        if not event[5]:
            return False
        if event[5] != st.recovery_auth_log:
            return False
        for auth in event[5]:
            request = auth[0]
            if not (
                event[2] in request[3]
                and event[3] in request[4]
                and owner_key(st, event[3]) == request[5]
                and policy_of(event[3]) == request[6]
                and request[7] == G1
            ):
                return False
    return True


def inv_owner_migration_sound(st):
    for event in st.migration_log:
        if event[1] != "OWNER":
            continue
        if not event[6]:
            return False
        if event[6] != st.owner_auth_log:
            return False
        for auth in event[6]:
            old_outputs, new_outputs, old_key, new_key, share_epoch, signers, snapshot, gate_key, owner_dkg, gate_dkg = auth
            eligible = frozenset(
                c
                for c in CUSTODIANS
                if (c, old_key, share_epoch) in st.issued
                and (c, old_key, share_epoch) not in st.lost
                and c not in st.expelled
                and c in snapshot
            )
            if not (
                old_outputs == OLD_OUTPUTS
                and new_outputs == MOVED_OUTPUTS
                and old_key == K0
                and new_key == KR
                and owner_dkg in st.owner_log
                and owner_dkg[0] == new_key
                and owner_dkg[2] == REPLACEMENT_ROSTER
                and gate_dkg in st.gate_log
                and gate_dkg[0] == LEGACY_POOL
                and gate_dkg[1] == 1
                and gate_dkg[2] == gate_key
                and len(signers) >= K_OWN
                and signers <= eligible
                and gate_key == G1
                and event[2] in old_outputs
                and event[3] in new_outputs
                and owner_key(st, event[2]) == old_key
                and owner_key(st, event[3]) == new_key
            ):
                return False
    return True


def inv_migration_consumes_old(st):
    return all(
        event[7]
        and event[2] in st.consumed
        and event[2] not in st.live
        and event[3] in st.live
        for event in st.migration_log
    )


def inv_migration_conservative(st):
    return all(
        event[2] == old(event[0])
        and event[3] == moved(event[0])
        and pool_of(event[3]) == LEGACY_POOL
        and owner_key(st, event[3]) == KR
        and value_of(event[2]) == value_of(event[3])
        and policy_of(event[2]) == policy_of(event[3])
        for event in st.migration_log
    )


def inv_fresh_owner_requires_full_migration(st):
    if st.legacy_phase == "Active" and st.current_legacy_key == KR:
        return (
            st.migrated == frozenset(UNITS)
            and OLD_OUTPUTS <= st.consumed
            and MOVED_OUTPUTS <= st.live
        )
    return True


def inv_active_gate_sound(st):
    if st.legacy_phase == "Active" and st.incident != INCIDENT_NONE:
        if active_gate(st, LEGACY_POOL) != G1 or not any(
            e[0] == LEGACY_POOL and e[1] == 1 and e[2] == G1
            for e in st.gate_log
        ):
            return False
    if st.successor_phase == "Active":
        if active_gate(st, SUCCESSOR_POOL) != GS or not any(
            e[0] == SUCCESSOR_POOL and e[2] == GS for e in st.gate_log
        ):
            return False
    return True


def inv_active_ownership_sound(st):
    if st.legacy_phase == "Active" and not (
        can_operate(st, st.current_legacy_key, owner_epoch(st, st.current_legacy_key))
        and not adversary_can(st, st.current_legacy_key)
    ):
        return False
    if st.successor_phase == "Active" and not (
        owner_recorded(st, KS)
        and can_operate(st, KS, 0)
        and not adversary_can(st, KS)
    ):
        return False
    return True


def inv_stranding_sound(st):
    return st.legacy_phase != "Stranded" or (
        bool(legacy_live(st)) and legacy_live(st) <= derived_stranded_outputs(st)
    )


def inv_no_recovery_without_branch(st):
    return RECOVERY in st.features or not st.recovery_auth_log


def inv_liability_admission_sound(st):
    return all(e[2] >= e[3] + 1 for e in st.liability_log)


def inv_liabilities_accounted(st):
    return all(map_get(st.liabilities, p) == expected_liability(st, p) for p in POOLS)


def inv_reservations_accounted(st):
    return st.reserved == (1, 0)


def inv_capitalization_sound(st):
    if not all(map_get(st.capital, p) == expected_capital(st, p) for p in POOLS):
        return False
    if FRESH_OUTPUTS <= st.created:
        return owner_recorded(st, KS) and any(
            e[0] == SUCCESSOR_POOL
            and e[1] == FRESH_OUTPUTS
            and e[2] == 3
            and e[3]
            for e in st.capital_log
        )
    return True


def inv_nullifier_history_preserved(st):
    return st.nullifier_history <= st.nullifiers


def inv_active_solvency(st):
    if st.legacy_phase == "Active":
        if st.scope == "GLOBAL":
            if total_active_backing(st) < total_obligation(st):
                return False
        elif backing_value(active_eligible(st, LEGACY_POOL)) < obligation(st, LEGACY_POOL):
            return False
    if st.successor_phase == "Active":
        if st.scope == "GLOBAL":
            if total_active_backing(st) < total_obligation(st):
                return False
        elif backing_value(active_eligible(st, SUCCESSOR_POOL)) < obligation(st, SUCCESSOR_POOL):
            return False
    return True


def inv_successor_sound(st):
    if st.successor_phase != "Active":
        return True
    return (
        SUCCESSOR in st.features
        and FRESH_OUTPUTS <= st.created
        and FRESH_OUTPUTS <= st.live
        and owner_recorded(st, KS)
        and gate_recorded(st, SUCCESSOR_POOL, 0)
        and map_get(st.capital, SUCCESSOR_POOL) == 3
        and (
            st.legacy_phase == "Active"
            or (OLD_OUTPUTS & st.live) <= st.quarantined
        )
    )


def inv_no_stale_authorization(st):
    return all(e[1] == e[2] for e in st.authorization_log)


INVARIANTS = (
    ("TypeOK", type_ok),
    ("OutputMetadataImmutable", inv_output_metadata_immutable),
    ("RecoveryPolicyImmutable", inv_recovery_policy_immutable),
    ("OutputConservation", inv_output_conservation),
    ("ShareIssuanceAccounted", inv_share_issuance_accounted),
    ("ShareHistoryMonotonic", inv_share_history_monotonic),
    ("MixedEpochIsNotThreshold", inv_mixed_epoch_not_threshold),
    ("ReshareSound", inv_reshare_sound),
    ("GateCeremonySound", inv_gate_ceremony_sound),
    ("FreshGateCeremonies", inv_fresh_gate_ceremonies),
    ("OwnerCeremonySound", inv_owner_ceremony_sound),
    ("RecoveryAuthorizationSound", inv_recovery_authorization_sound),
    ("RecoveryDelayHonored", inv_recovery_delay_honored),
    ("RecoveryBranchConfinement", inv_recovery_branch_confinement),
    ("RecoveryMigrationBound", inv_recovery_migration_bound),
    ("OwnerMigrationSound", inv_owner_migration_sound),
    ("MigrationConsumesOld", inv_migration_consumes_old),
    ("MigrationConservative", inv_migration_conservative),
    ("FreshOwnerRequiresFullMigration", inv_fresh_owner_requires_full_migration),
    ("ActiveGateSound", inv_active_gate_sound),
    ("ActiveOwnershipSound", inv_active_ownership_sound),
    ("StrandingSound", inv_stranding_sound),
    ("NoRecoveryWithoutBranch", inv_no_recovery_without_branch),
    ("LiabilityAdmissionSound", inv_liability_admission_sound),
    ("LiabilitiesAccounted", inv_liabilities_accounted),
    ("ReservationsAccounted", inv_reservations_accounted),
    ("CapitalizationSound", inv_capitalization_sound),
    ("NullifierHistoryPreserved", inv_nullifier_history_preserved),
    ("ActiveSolvency", inv_active_solvency),
    ("SuccessorSound", inv_successor_sound),
    ("NoStaleAuthorization", inv_no_stale_authorization),
)


def invariant_violations(st):
    return [name for name, predicate in INVARIANTS if not predicate(st)]


# ---------------------------------------------------------------------------
# Reachability contract: positive witnesses and explicit forbidden outcomes.


REQUIRED_WITNESSES = frozenset(
    {
        "preincident_reshare",
        "false_incident_keep_owner",
        "partial_loss_incident_reshare_active",
        "catastrophic_reshare_stranded",
        "mixed_epoch_not_unsafe",
        "epoch1_partial_loss_exact",
        "epoch1_catastrophic_loss_exact",
        "epoch1_threshold_compromise_exact",
        "threshold_compromise_unsafe",
        "threshold_honest_owner_migration_active",
        "catastrophic_recovery_active",
        "catastrophic_successor_active",
        "segregated_successor_liability_accepted",
        "recovery_and_successor_compose",
    }
)


def has_post_loss_reshare(st):
    lost_c1 = frozenset({("c1", K0, 0)})
    return any(lost_c1 <= event[5] for event in st.reshare_log)


def has_preincident_reshare(st):
    """Identify the unique e0->e1 reshare that occurred before any incident."""

    return any(
        event[0] == K0
        and event[1] == 0
        and event[2] == 1
        and event[4] == INITIAL_SHARES
        and not event[5]
        and not event[6]
        and not event[7]
        for event in st.reshare_log
    )


def witness_hits(st):
    hits = set()
    if (
        RESHARE in st.features
        and st.incident == INCIDENT_NONE
        and st.current_share_epoch == 1
        and st.current_legacy_key == K0
        and st.legacy_phase == "Active"
    ):
        hits.add("preincident_reshare")
    if (
        st.incident == "FALSE"
        and st.legacy_phase == "Active"
        and st.current_legacy_key == K0
        and active_gate(st, LEGACY_POOL) == G1
        and st.live == OLD_OUTPUTS
    ):
        hits.add("false_incident_keep_owner")
    if (
        RESHARE in st.features
        and st.incident == "PARTIAL_LOSS"
        and st.current_share_epoch == 1
        and st.current_legacy_key == K0
        and st.legacy_phase == "Active"
        and has_post_loss_reshare(st)
    ):
        hits.add("partial_loss_incident_reshare_active")
    if (
        st.features == frozenset({RESHARE})
        and st.incident == "CATASTROPHIC_LOSS"
        and st.legacy_phase == "Stranded"
    ):
        hits.add("catastrophic_reshare_stranded")
    if (
        st.incident == "MIXED_EPOCH"
        and ("c1", K0, 0) in st.known
        and ("c3", K0, 1) in st.known
        and not adversary_can(st, K0)
    ):
        hits.add("mixed_epoch_not_unsafe")
    if (
        st.incident == "PARTIAL_LOSS"
        and has_preincident_reshare(st)
        and st.lost == frozenset({("c3", K0, 1)})
    ):
        hits.add("epoch1_partial_loss_exact")
    if (
        st.incident == "CATASTROPHIC_LOSS"
        and has_preincident_reshare(st)
        and st.lost == shares_for(K0, 1, REPLACEMENT_ROSTER)
    ):
        hits.add("epoch1_catastrophic_loss_exact")
    if (
        st.incident == "THRESHOLD_COMPROMISE"
        and has_preincident_reshare(st)
        and st.known == shares_for(K0, 1, REPLACEMENT_ROSTER)
        and REPLACEMENT_ROSTER <= st.expelled
        and adversary_can(st, K0)
    ):
        hits.add("epoch1_threshold_compromise_exact")
    if st.incident == "THRESHOLD_COMPROMISE" and adversary_can(st, K0):
        hits.add("threshold_compromise_unsafe")
    if (
        st.incident == "THRESHOLD_COMPROMISE"
        and st.legacy_phase == "Active"
        and st.current_legacy_key == KR
        and st.migrated == frozenset(UNITS)
        and st.recovery_kind == "NONE"
    ):
        hits.add("threshold_honest_owner_migration_active")
    if (
        RECOVERY in st.features
        and st.incident == "CATASTROPHIC_LOSS"
        and st.legacy_phase == "Active"
        and st.current_legacy_key == KR
        and st.migrated == frozenset(UNITS)
    ):
        hits.add("catastrophic_recovery_active")
    if (
        SUCCESSOR in st.features
        and st.incident == "CATASTROPHIC_LOSS"
        and st.successor_phase == "Active"
        and st.legacy_phase != "Active"
        and map_get(st.liabilities, LEGACY_POOL) == 2
        and map_get(st.reserved, LEGACY_POOL) == 1
    ):
        hits.add("catastrophic_successor_active")
    if (
        SUCCESSOR in st.features
        and st.scope == "SEGREGATED"
        and st.incident == "CATASTROPHIC_LOSS"
        and st.successor_phase == "Active"
        and map_get(st.liabilities, SUCCESSOR_POOL) >= 1
    ):
        hits.add("segregated_successor_liability_accepted")
    if (
        {RECOVERY, SUCCESSOR} <= st.features
        and st.incident == "CATASTROPHIC_LOSS"
        and st.legacy_phase == "Active"
        and st.current_legacy_key == KR
        and st.successor_phase == "Active"
    ):
        hits.add("recovery_and_successor_compose")
    return hits


def forbidden_hits(st):
    hits = set()
    if st.incident == "MIXED_EPOCH" and adversary_can(st, K0):
        hits.add("mixed_epoch_treated_as_threshold")
    if has_preincident_reshare(st):
        if (
            st.incident == "PARTIAL_LOSS"
            and st.lost != frozenset({("c3", K0, 1)})
        ):
            hits.add("epoch1_partial_loss_misattributed")
        if (
            st.incident == "CATASTROPHIC_LOSS"
            and st.lost != shares_for(K0, 1, REPLACEMENT_ROSTER)
        ):
            hits.add("epoch1_catastrophic_loss_incomplete")
        if st.incident == "THRESHOLD_COMPROMISE" and not (
            st.known == shares_for(K0, 1, REPLACEMENT_ROSTER)
            and REPLACEMENT_ROSTER <= st.expelled
        ):
            hits.add("epoch1_compromise_misattributed")
    if (
        st.features == frozenset({RESHARE})
        and st.incident == "CATASTROPHIC_LOSS"
        and st.legacy_phase == "Active"
    ):
        hits.add("reshare_recovers_below_threshold")
    if (
        st.incident == "CATASTROPHIC_LOSS"
        and st.legacy_phase == "Active"
        and st.current_legacy_key == K0
    ):
        hits.add("catastrophic_loss_reuses_old_owner")
    if any(
        event[1] == "RECOVERY"
        and any(event[4] < auth[0][11] for auth in event[5])
        for event in st.migration_log
    ):
        hits.add("recovery_before_delay")
    if (
        st.legacy_phase == "Active"
        and st.current_legacy_key == KR
        and st.migrated != frozenset(UNITS)
    ):
        hits.add("partial_migration_activated")
    if st.successor_phase == "Active" and not inv_successor_sound(st):
        hits.add("successor_activated_without_facts")
    if not inv_active_solvency(st):
        hits.add("active_pool_insolvent")
    if not inv_liabilities_accounted(st):
        hits.add("liability_history_erased")
    if not inv_reservations_accounted(st):
        hits.add("reservation_erased")
    if not inv_nullifier_history_preserved(st):
        hits.add("nullifier_history_erased")
    if st.created & (
        EXTERNAL_OUTPUTS
        | WRONG_OWNER_OUTPUTS
        | WRONG_POLICY_OUTPUTS
        | WRONG_VALUE_OUTPUTS
    ):
        hits.add("bad_physical_recovery_output")
    if not inv_no_stale_authorization(st):
        hits.add("stale_gate_authorization")
    return hits


def trace_to(state, parents):
    trace = []
    cursor = state
    while parents is not None and parents.get(cursor) is not None:
        previous, action = parents[cursor]
        trace.append(action)
        cursor = previous
    return list(reversed(trace))


def parse_features(text):
    if text is None:
        return None
    if text in {"", "NONE", "-"}:
        return frozenset()
    values = frozenset(piece.strip().upper() for piece in text.split(",") if piece.strip())
    unknown = values - FEATURE_KINDS
    if unknown:
        raise ValueError("unknown feature(s): " + ", ".join(sorted(unknown)))
    return values


def strip_tla_comments(text):
    """Remove block and line comments before parsing a tiny config fragment."""

    text = re.sub(r"\(\*.*?\*\)", "", text, flags=re.DOTALL)
    return "\n".join(re.sub(r"\\\*.*$", "", line) for line in text.splitlines())


CFG_DIRECTIVE_RE = re.compile(
    r"^\s*(SPECIFICATION|ACTION_CONSTRAINT|CONSTRAINT|INVARIANT|PROPERTY|CHECK_DEADLOCK|CONSTANT)"
    r"\b(.*?)"
    r"(?=^\s*(?:SPECIFICATION|ACTION_CONSTRAINT|CONSTRAINT|INVARIANT|PROPERTY|CHECK_DEADLOCK|CONSTANT)\b|\Z)",
    flags=re.MULTILINE | re.DOTALL,
)


def _config_symbols(path, directive, bodies):
    symbols = []
    for body in bodies:
        symbols.extend(re.findall(r"\b[A-Za-z][A-Za-z0-9_]*\b", body))
    if len(symbols) != len(set(symbols)):
        raise ValueError(f"{path}: duplicate {directive} entry in {symbols!r}")
    return frozenset(symbols)


def parse_config(path):
    """Parse the cfg directives whose identity is part of the test contract.

    This is intentionally a small parser, not a complete TLC configuration
    grammar.  It recognizes every directive used by this suite and validates
    exact directive sets so a misspelled scenario constraint/property cannot
    silently turn a test into a different model.
    """

    source = strip_tla_comments(Path(path).read_text(encoding="utf-8"))
    bodies = {}
    for directive, body in CFG_DIRECTIVE_RE.findall(source):
        bodies.setdefault(directive, []).append(body.strip())

    specifications = _config_symbols(path, "SPECIFICATION", bodies.get("SPECIFICATION", []))
    if len(specifications) != 1:
        raise ValueError(
            f"{path}: expected exactly one SPECIFICATION, found {sorted(specifications)!r}"
        )

    deadlock_values = _config_symbols(
        path, "CHECK_DEADLOCK", bodies.get("CHECK_DEADLOCK", [])
    )
    if deadlock_values != frozenset({"FALSE"}):
        raise ValueError(
            f"{path}: CHECK_DEADLOCK must be exactly FALSE, found "
            f"{sorted(deadlock_values)!r}"
        )

    constant_source = "\n".join(bodies.get("CONSTANT", []))
    bug_matches = re.findall(r'\bBug\s*=\s*"([A-Z0-9_]+)"', constant_source)
    if len(bug_matches) != 1:
        raise ValueError(
            f"{path}: expected exactly one uncommented Bug assignment, "
            f"found {bug_matches!r}"
        )
    bug = bug_matches[0]
    if bug not in BUGS:
        raise ValueError(f"{path}: unknown Bug value {bug!r}")

    return {
        "bug": bug,
        "specification": next(iter(specifications)),
        "action_constraints": _config_symbols(
            path, "ACTION_CONSTRAINT", bodies.get("ACTION_CONSTRAINT", [])
        ),
        "constraints": _config_symbols(path, "CONSTRAINT", bodies.get("CONSTRAINT", [])),
        "invariants": _config_symbols(path, "INVARIANT", bodies.get("INVARIANT", [])),
        "properties": _config_symbols(path, "PROPERTY", bodies.get("PROPERTY", [])),
    }


def parse_config_bug(path):
    """Backward-compatible accessor for callers that need only ``Bug``."""

    return parse_config(path)["bug"]


def parse_expected_symbols(text):
    """Parse an exact comma-separated expected cfg symbol set."""

    if text is None:
        return None
    if text.upper() == "NONE" or not text.strip():
        return frozenset()
    if text.upper() == "ALL_SAFETY":
        return frozenset(name for name, _ in INVARIANTS)
    symbols = tuple(piece.strip() for piece in text.split(",") if piece.strip())
    if not symbols or any(
        re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", symbol) is None
        for symbol in symbols
    ):
        raise ValueError(f"invalid expected symbol set {text!r}")
    if len(symbols) != len(set(symbols)):
        raise ValueError(f"duplicate expected symbol in {text!r}")
    return frozenset(symbols)


def parse_tla_bug_kinds(path):
    """Extract ``BugKinds`` from the sibling TLA+ module for drift testing."""

    source = strip_tla_comments(Path(path).read_text(encoding="utf-8"))
    match = re.search(r"\bBugKinds\s*==\s*\{(.*?)\}", source, flags=re.DOTALL)
    if match is None:
        raise ValueError(f"{path}: BugKinds set not found")
    values = tuple(re.findall(r'"([A-Z0-9_]+)"', match.group(1)))
    if not values:
        raise ValueError(f"{path}: BugKinds set is empty")
    return values


def explore(
    bug="NONE",
    exhaustive=True,
    keep_parents=False,
    max_states=None,
    feature_filter=None,
    scope_filter=None,
):
    starts = list(initial_states(feature_filter, scope_filter))
    seen = set(starts)
    queue = deque(starts)
    parents = {state: None for state in starts} if keep_parents else None
    violations = {}
    witnesses = {}
    forbidden = {}
    action_hits = set()
    truncated = False

    while queue:
        state = queue.popleft()
        for name in invariant_violations(state):
            violations.setdefault(name, state)
        for name in witness_hits(state):
            witnesses.setdefault(name, state)
        for name in forbidden_hits(state):
            forbidden.setdefault(name, state)

        expected = EXPECTED.get(bug)
        if not exhaustive and expected is not None and expected in violations:
            break

        for action, nxt in successors(state, bug):
            action_hits.add(action.split("(", 1)[0])
            if nxt in seen:
                continue
            seen.add(nxt)
            if parents is not None:
                parents[nxt] = (state, action)
            if max_states is not None and len(seen) > max_states:
                truncated = True
                queue.clear()
                break
            queue.append(nxt)

    return {
        "states": len(seen),
        "violations": violations,
        "witnesses": witnesses,
        "forbidden": forbidden,
        "action_hits": action_hits,
        "parents": parents,
        "truncated": truncated,
    }


def result_for(
    bug,
    exhaustive,
    verbose,
    max_states,
    feature_filter=None,
    scope_filter=None,
):
    explored = explore(
        bug=bug,
        exhaustive=exhaustive,
        keep_parents=verbose,
        max_states=max_states,
        feature_filter=feature_filter,
        scope_filter=scope_filter,
    )
    expected = EXPECTED.get(bug)
    all_profiles = feature_filter is None and scope_filter is None
    if bug == "NONE":
        required = REQUIRED_WITNESSES if all_profiles else frozenset()
        passed = (
            not explored["truncated"]
            and not explored["violations"]
            and not explored["forbidden"]
            and required <= explored["witnesses"].keys()
        )
    else:
        passed = expected in explored["violations"]

    result = {
        "bug": bug,
        "states": explored["states"],
        "exhaustive": exhaustive,
        "truncated": explored["truncated"],
        "violations": sorted(explored["violations"]),
        "expected": expected,
        "witnesses": sorted(explored["witnesses"]),
        "missing_witnesses": sorted(
            (REQUIRED_WITNESSES if all_profiles else frozenset())
            - explored["witnesses"].keys()
        ),
        "forbidden": sorted(explored["forbidden"]),
        "actions": sorted(explored["action_hits"]),
        "passed": passed,
    }
    if verbose:
        if expected in explored["violations"]:
            result["counterexample"] = trace_to(
                explored["violations"][expected], explored["parents"]
            )
        if bug == "NONE":
            result["witness_traces"] = {
                name: trace_to(state, explored["parents"])
                for name, state in sorted(explored["witnesses"].items())
            }
            result["forbidden_traces"] = {
                name: trace_to(state, explored["parents"])
                for name, state in sorted(explored["forbidden"].items())
            }
    return result


def self_test_type_ok():
    state = next(initial_states())
    malformed = {
        "phase": replace(state, legacy_phase="Bogus"),
        "time": replace(state, now=MAX_TIME + 1),
        "boolean_time": replace(state, now=False),
        "feature": replace(state, features=frozenset({"MAGIC"})),
        "share": replace(state, issued=frozenset({("c1", K0, 99)})),
        "output": replace(state, live=frozenset({"imaginary"})),
        "liability": replace(state, liabilities=(-1, 0)),
        "boolean_liability": replace(state, liabilities=(False, 0)),
        "noncanonical_owner": replace(
            state, owner_overrides=frozenset({(old("u1"), K0)})
        ),
        "event": replace(state, gate_log=frozenset({("bad",)})),
    }
    accepted = [name for name, candidate in malformed.items() if type_ok(candidate)]
    if accepted:
        raise AssertionError("TypeOK accepted malformed state(s): " + ", ".join(accepted))
    if not type_ok(state):
        raise AssertionError("TypeOK rejected an initial state")
    initial_bad = invariant_violations(state)
    if initial_bad:
        raise AssertionError("initial state violates: " + ", ".join(initial_bad))
    tla_path = Path(__file__).with_name("ReserveRecoveryV2.tla")
    if tla_path.exists():
        tla_bugs = parse_tla_bug_kinds(tla_path)
        if frozenset(tla_bugs) != frozenset(BUGS) or len(tla_bugs) != len(BUGS):
            raise AssertionError(
                "Python BUGS differs from TLA BugKinds: "
                f"python={BUGS!r}, tla={tla_bugs!r}"
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bug", choices=BUGS, default="NONE")
    parser.add_argument("--all-bugs", action="store_true")
    parser.add_argument("--full-bugs", action="store_true")
    parser.add_argument("--features", help="exact comma-separated feature set; NONE means empty")
    parser.add_argument("--scope", choices=SCOPES)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--count-only", action="store_true")
    parser.add_argument("--max-states", type=int)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--validate-config")
    parser.add_argument("--expect-bug", choices=BUGS)
    parser.add_argument("--expect-specification")
    parser.add_argument("--expect-action-constraints")
    parser.add_argument("--expect-constraints")
    parser.add_argument("--expect-invariants")
    parser.add_argument("--expect-properties")
    args = parser.parse_args()

    self_test_type_ok()
    if args.validate_config:
        try:
            parsed = parse_config(args.validate_config)
            expected_sets = {
                "action_constraints": parse_expected_symbols(
                    args.expect_action_constraints
                ),
                "constraints": parse_expected_symbols(args.expect_constraints),
                "invariants": parse_expected_symbols(args.expect_invariants),
                "properties": parse_expected_symbols(args.expect_properties),
            }
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        if args.expect_bug is not None and parsed["bug"] != args.expect_bug:
            parser.error(
                f"{args.validate_config}: Bug is {parsed['bug']}, expected {args.expect_bug}"
            )
        if (
            args.expect_specification is not None
            and parsed["specification"] != args.expect_specification
        ):
            parser.error(
                f"{args.validate_config}: SPECIFICATION is "
                f"{parsed['specification']}, expected {args.expect_specification}"
            )
        for field, expected in expected_sets.items():
            if expected is not None and parsed[field] != expected:
                parser.error(
                    f"{args.validate_config}: {field} are "
                    f"{sorted(parsed[field])!r}, expected {sorted(expected)!r}"
                )
        print(json.dumps({
            key: sorted(value) if isinstance(value, frozenset) else value
            for key, value in parsed.items()
        }, sort_keys=True))
        return 0
    if args.self_test:
        print("TypeOK, initial invariants, and TLA BugKinds parity self-test PASS")
        return 0

    try:
        feature_filter = parse_features(args.features)
    except ValueError as exc:
        parser.error(str(exc))
    selected = BUGS if args.all_bugs else (args.bug,)
    results = []
    for bug in selected:
        exhaustive = bug == "NONE" or args.full_bugs
        result = result_for(
            bug,
            exhaustive,
            args.verbose,
            args.max_states,
            feature_filter,
            args.scope,
        )
        results.append(result)
        if not args.json and not args.count_only:
            detail = "clean" if not result["violations"] else "violates " + str(result["violations"])
            print(
                f"  {bug:<34} {result['states']:>9} states  "
                f"{'PASS' if result['passed'] else 'FAIL':<4}  {detail}"
            )
            if result["missing_witnesses"] and bug == "NONE":
                print("      missing witnesses: " + ", ".join(result["missing_witnesses"]))
            if result["forbidden"] and bug == "NONE":
                print("      forbidden reached: " + ", ".join(result["forbidden"]))
            if args.verbose and "counterexample" in result:
                print("      " + " -> ".join(result["counterexample"]))
            if args.verbose and bug == "NONE":
                for name, trace in result.get("witness_traces", {}).items():
                    print(f"      witness {name}: " + " -> ".join(trace))

    if args.count_only:
        if len(results) != 1:
            parser.error("--count-only requires one selected bug")
        print(results[0]["states"])
    elif args.json:
        print(json.dumps(results if args.all_bugs else results[0], sort_keys=True))

    return 0 if all(result["passed"] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
