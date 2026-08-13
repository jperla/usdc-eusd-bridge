#!/usr/bin/env python3
"""Independent finite-state reference model for Bridge Escrow V2.

This file is deliberately handwritten from ``BRIDGE_V2_TEST_PLAN.md``.  It
does not consume TLA+ states or TLC output.  The core model covers source-truth
noninterference, concrete direction-specific authorization artifacts, typed
source-event nullifiers, deterministic claim admission/adjudication, and
exact-once penalties.  Capacity arithmetic and generation lifecycle remain a
separate, explicitly NOT-RUN stage; core actions nevertheless emit the shared
``CapacityEvent`` envelope required by ``BRIDGE_V2_CAPACITY_INTERFACE.md``.

All protocol records below are ``NamedTuple`` values.  They are immutable,
hashable ordered tuples: signer slots are never silently collapsed to sets,
and malformed but well-typed artifact variants are ordinary baseline states.
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
import sys
from collections import deque
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable, NamedTuple


# ---------------------------------------------------------------------------
# Frozen tiny universe shared with the V2 TLA+ design.

E2M, M2E = "E2M", "M2E"
DIRECTIONS = (E2M, M2E)
V1, V2 = "V1", "V2"
VERSIONS = (V1, V2)
EPOCHS = (0, 1)
RELEASE_IDS = ("F1", "F2", "R1", "R2")
CLAIM_IDS = ("C1", "C2")
EVENTS = ("ETH_DEP", "MOB_RET")
SOURCE_STATES = ("UNKNOWN", "ABSENT", "FINAL")

OWNERS = ("o1", "o2")
GATES = ("g1", "g2", "g3")
ETH_SIGNERS = ("h1", "h2", "h3")
WARDENS = ("w1", "w2", "w3")
ACCOUNT_SIGNERS = ("a1", "a2", "a3")
CHALLENGERS = ("c1", "c2")
ALL_IDENTITIES = frozenset(OWNERS + GATES + ETH_SIGNERS + WARDENS + ACCOUNT_SIGNERS + CHALLENGERS)

K_OWN = K_FROST = K_ETH = K_WARDEN = K_ACCOUNT = 2
THRESHOLD = {
    "MLSAG": K_OWN,
    "FROST": K_FROST,
    "ETH_MULTI": K_ETH,
    "WARDEN": K_WARDEN,
    "ACCOUNT": K_ACCOUNT,
}

ROLE_ROSTERS = {
    ("MLSAG", 0): frozenset(OWNERS),
    ("MLSAG", 1): frozenset(OWNERS),  # ownership epoch is immutable here
    ("FROST", 0): frozenset(("g1", "g2", "g3")),
    ("FROST", 1): frozenset(("g2", "g3")),
    ("ETH_MULTI", 0): frozenset(("h1", "h2", "h3")),
    ("ETH_MULTI", 1): frozenset(("h2", "h3")),
    ("WARDEN", 0): frozenset(("w1", "w2", "w3")),
    ("WARDEN", 1): frozenset(("w2", "w3")),
    ("ACCOUNT", 0): frozenset(("a1", "a2", "a3")),
    ("ACCOUNT", 1): frozenset(("a2", "a3")),
}
CANONICAL_SLOTS = {
    ("MLSAG", 0): ("o1", "o2"),
    ("MLSAG", 1): ("o1", "o2"),
    ("FROST", 0): ("g1", "g2"),
    ("FROST", 1): ("g2", "g3"),
    ("ETH_MULTI", 0): ("h1", "h2"),
    ("ETH_MULTI", 1): ("h2", "h3"),
    ("WARDEN", 0): ("w1", "w2"),
    ("WARDEN", 1): ("w2", "w3"),
    ("ACCOUNT", 0): ("a1", "a2"),
    ("ACCOUNT", 1): ("a2", "a3"),
}

ROLE_KEYS = {
    ("MLSAG", 0): "K_OWN_0",
    ("MLSAG", 1): "K_OWN_0",
    ("FROST", 0): "K_GATE_0",
    ("FROST", 1): "K_GATE_1",
    ("ETH_MULTI", 0): "ETH_ESCROW_0",
    ("ETH_MULTI", 1): "ETH_ESCROW_1",
    ("WARDEN", 0): "K_WARDEN_0",
    ("WARDEN", 1): "K_WARDEN_1",
    ("ACCOUNT", 0): "K_ACCOUNT_0",
    ("ACCOUNT", 1): "K_ACCOUNT_1",
}

MANIFESTS = {(role, epoch): f"MANIFEST:{role}:{epoch}" for role in THRESHOLD for epoch in EPOCHS}
BOND_MANIFEST = {epoch: f"BOND_MANIFEST:{epoch}" for epoch in EPOCHS}
BOND_POSITION = {(epoch, signer): f"BOND:{epoch}:{signer}" for epoch in EPOCHS for signer in WARDENS + ACCOUNT_SIGNERS}
BOND_EXIT_TIME = {position: 4 for position in BOND_POSITION.values()}
CHALLENGE_BONDS = {"c1": "CHALLENGE_BOND:c1", "c2": "CHALLENGE_BOND:c2"}

EUSD_OUTPUTS = frozenset(("EU1", "EU2"))
USDC_OUTPUTS = frozenset(("US1", "US2"))
ALL_OUTPUTS = EUSD_OUTPUTS | USDC_OUTPUTS
OUTPUT_FOR_RELEASE = {"F1": "EU1", "F2": "EU2", "R1": "US1", "R2": "US2"}
ASSET_FOR_DIRECTION = {E2M: "eUSD", M2E: "USDC"}
MAX_TIME = 2
LIABILITY_WINDOW_END = 3

NONE = "<NONE>"
ABSENT = "<ABSENT>"
BRIDGE_ID = "EUSD_ETH_BRIDGE_V1"
POLICY_ID = "BRIDGE_POLICY_V1"
DOMAIN_SEPARATOR = "BRIDGE_SETTLEMENT_V1"
SCHEMA_VERSION = "SCHEMA_V1"


def direction_of(release_id: str) -> str:
    return E2M if release_id.startswith("F") else M2E


def event_of(release_id: str) -> str:
    return "ETH_DEP" if direction_of(release_id) == E2M else "MOB_RET"


def source_key(direction: str, event: str) -> tuple:
    return (direction, event)


def source_chain(direction: str) -> str:
    return "ETHEREUM" if direction == E2M else "MOBILECOIN"


def source_policy(direction: str) -> str:
    return "USDC_ESCROW" if direction == E2M else "EUSD_RETURN_POLICY"


def source_asset(direction: str) -> str:
    return "USDC" if direction == E2M else "eUSD"


def destination_asset(direction: str) -> str:
    return "eUSD" if direction == E2M else "USDC"


def recipient_for(release_id: str) -> str:
    # F1/F2 (and R1/R2) are distinct settlement attempts for one source event.
    # The canonical source assertion therefore retains one destination while
    # the destination transaction commitment/release ID may differ.
    return "RECIPIENT:MOBILECOIN" if direction_of(release_id) == E2M else "RECIPIENT:ETHEREUM"


# ---------------------------------------------------------------------------
# Immutable protocol records.  Field order is part of the model schema.


class SourceFact(NamedTuple):
    direction: str
    event: str
    checkpoint: str
    finality: str
    chain: str
    policy: str
    source_asset: str
    source_amount: int
    destination_asset: str
    destination_amount: int
    recipient: str


class SourceAssertion(NamedTuple):
    bridge_id: str
    direction: str
    event: str
    checkpoint: str
    finality: str
    chain: str
    policy: str
    source_asset: str
    source_amount: int
    destination_asset: str
    destination_amount: int
    recipient: str


class Request(NamedTuple):
    release_id: str
    direction: str
    event: str
    checkpoint: str
    amount: int
    recipient: str
    version: str
    epoch: int
    destination_tx: tuple
    source_key: tuple
    source_assertion: SourceAssertion
    nullifier: tuple
    digest: tuple


class Artifact(NamedTuple):
    role: str
    present: str
    sig_tag: tuple | str
    epoch: int | str
    digest: tuple | str
    s1: str
    s2: str
    manifest: str
    bond_manifest: str
    key_or_contract: str
    subject: tuple | str


class Bundle(NamedTuple):
    variant: str
    mlsag: Artifact
    frost: Artifact
    eth_multi: Artifact
    warden: Artifact
    account: Artifact


class Release(NamedTuple):
    request: Request
    bundle: Bundle
    consumed_output: str
    finalized_at: int


class NullifierConsumption(NamedTuple):
    nullifier: tuple
    release_id: str
    direction: str
    event: str


class Checkpoint(NamedTuple):
    checkpoint_id: str
    direction: str
    event: str
    fact_status: str
    fact: SourceFact | str
    commitment: tuple
    auth_tag: tuple


class Evidence(NamedTuple):
    evidence_id: str
    proof_id: tuple
    kind: str
    parse_tag: str
    auth_tag: tuple | str
    expires_at: int
    target1: str
    target2: str
    checkpoint: Checkpoint | str
    digest1: tuple | str
    digest2: tuple | str
    alt_warden: Artifact
    alt_account: Artifact


class FraudClaim(NamedTuple):
    claim_id: str
    challenger: str
    challenge_bond: str
    target1: str
    target2: str
    kind: str
    evidence_id: str
    proof_id: tuple
    offense: str
    auth_tag: tuple | str


class Verdict(NamedTuple):
    claim_id: str
    proof_id: tuple
    result: str
    culprits: frozenset


class Application(NamedTuple):
    claim_id: str
    proof_id: tuple
    result: str
    operator_bonds: frozenset
    challenger_bonds: frozenset
    restitution_units: int
    bounty_units: int
    pause_epoch: int | str
    expelled: frozenset


class CapacityEvent(NamedTuple):
    event_id: str
    kind: str
    logical_time: int
    generation: str
    direction: str
    asset: str
    amount: int
    release_id: str
    source_key: tuple | str
    value_position_ids: frozenset
    capacity_position_ids: frozenset
    failure_domains: frozenset
    approval_quorum: frozenset
    owner_manifest: str
    gate_manifest: str
    role_manifests: tuple
    bond_manifest: str
    capital_source_kind: str
    capital_source_ref: str
    phase_before: str
    phase_after: str


ABSENT_ARTIFACTS = {
    role: Artifact(role, "ABSENT", ABSENT, ABSENT, ABSENT, ABSENT, ABSENT, ABSENT, ABSENT, ABSENT, ABSENT)
    for role in THRESHOLD
}


@dataclass(frozen=True, slots=True)
class State:
    epoch: int
    now: int
    objective: tuple
    checkpoints: tuple
    work_status: str
    work_request: Request | None
    work_bundle: Bundle | None
    releases: tuple
    unspent_outputs: frozenset
    spent_outputs: frozenset
    nullifier_consumptions: tuple
    settlement_rejections: tuple
    claims: tuple
    evidence: tuple
    active_claim: str
    admissions: frozenset
    claim_rejections: tuple
    verdicts: tuple
    applications: tuple
    reserved_proofs: frozenset
    consumed_proofs: frozenset
    locked_operator_bonds: frozenset
    slashed_operator_bonds: frozenset
    locked_challenge_bonds: frozenset
    slashed_challenge_bonds: frozenset
    paused_epochs: frozenset
    pause_causes: frozenset
    expelled: frozenset
    fresh_gate_epochs: frozenset
    capacity_events: tuple
    halted: bool


def initial_state() -> State:
    initially_locked = set(BOND_POSITION.values())
    # a3 is a registered epoch-0 accountability identity whose bond position
    # exists but is not active/locked.  This makes an unbonded in-roster signer
    # a typed, baseline-publishable artifact rather than an out-of-domain hack.
    initially_locked.remove(BOND_POSITION[(0, "a3")])
    return State(
        epoch=0,
        now=0,
        objective=("UNKNOWN", "UNKNOWN"),
        checkpoints=(NONE, NONE),
        work_status="NONE",
        work_request=None,
        work_bundle=None,
        releases=(),
        unspent_outputs=ALL_OUTPUTS,
        spent_outputs=frozenset(),
        nullifier_consumptions=(),
        settlement_rejections=(),
        claims=(),
        evidence=(),
        active_claim=NONE,
        admissions=frozenset(),
        claim_rejections=(),
        verdicts=(),
        applications=(),
        reserved_proofs=frozenset(),
        consumed_proofs=frozenset(),
        locked_operator_bonds=frozenset(initially_locked),
        slashed_operator_bonds=frozenset(),
        locked_challenge_bonds=frozenset(CHALLENGE_BONDS.values()),
        slashed_challenge_bonds=frozenset(),
        paused_epochs=frozenset(),
        pause_causes=frozenset(),
        expelled=frozenset(),
        fresh_gate_epochs=frozenset((0,)),
        capacity_events=(),
        halted=False,
    )


# ---------------------------------------------------------------------------
# Canonical construction and verification helpers.


def canonical_fact(release_id: str) -> SourceFact:
    direction = direction_of(release_id)
    event = event_of(release_id)
    return SourceFact(
        direction,
        event,
        f"CHECKPOINT:{event}",
        "FINAL",
        source_chain(direction),
        source_policy(direction),
        source_asset(direction),
        1,
        destination_asset(direction),
        1,
        recipient_for(release_id),
    )


def canonical_assertion(release_id: str) -> SourceAssertion:
    fact = canonical_fact(release_id)
    return SourceAssertion(BRIDGE_ID, *fact)


def canonical_destination_tx(release_id: str) -> tuple:
    direction = direction_of(release_id)
    output = OUTPUT_FOR_RELEASE[release_id]
    if direction == E2M:
        return (
            "MOBILECOIN_TX",
            release_id,
            output,
            f"KEY_IMAGE:{output}",
            recipient_for(release_id),
            1,
            "CHANGE:0",
            "FEE:0",
            "TOMBSTONE:10",
        )
    return (
        "ETHEREUM_CALL",
        ROLE_KEYS[("ETH_MULTI", 0)],
        recipient_for(release_id),
        1,
        f"CALLDATA:{release_id}",
        "EXPIRY:10",
    )


def stable_nullifier(direction: str, event: str) -> tuple:
    return (
        "BRIDGE_SOURCE_EVENT_V1",
        BRIDGE_ID,
        direction,
        source_chain(direction),
        source_policy(direction),
        event,
    )


def settlement_digest(fields: tuple) -> tuple:
    """Injective structural digest atom for the finite model."""
    return ("BRIDGE_DIGEST", DOMAIN_SEPARATOR, SCHEMA_VERSION) + fields


def make_request(release_id: str, version: str, epoch: int, bug: str) -> Request:
    direction = direction_of(release_id)
    event = event_of(release_id)
    assertion = canonical_assertion(release_id)
    nullifier = stable_nullifier(direction, event)
    if bug == "VERSIONED_NULLIFIER":
        nullifier = nullifier + (version,)
    dest_tx = canonical_destination_tx(release_id)
    fields = (
        BRIDGE_ID,
        version,
        direction,
        assertion,
        nullifier,
        release_id,
        dest_tx,
        POLICY_ID,
        epoch,
        ROLE_KEYS[("MLSAG", 0)] if direction == E2M else ABSENT,
        ROLE_KEYS[("FROST", epoch)] if direction == E2M else ABSENT,
        tuple(MANIFESTS[(r, 0 if r == "MLSAG" else epoch)] for r in THRESHOLD),
        BOND_MANIFEST[epoch],
        "NO_REPLACEMENT",
    )
    digest = settlement_digest(fields)
    return Request(
        release_id,
        direction,
        event,
        assertion.checkpoint,
        assertion.destination_amount,
        assertion.recipient,
        version,
        epoch,
        dest_tx,
        source_key(direction, event),
        assertion,
        nullifier,
        digest,
    )


def expected_sig(role: str, epoch: int, digest: tuple, slots: tuple, key: str, subject: tuple | str) -> tuple:
    return ("SIG", role, epoch, key, digest, slots, subject)


def canonical_subject(role: str, req: Request) -> tuple | str:
    if role == "MLSAG":
        output = OUTPUT_FOR_RELEASE[req.release_id]
        return (output, f"KEY_IMAGE:{output}")
    if role == "FROST":
        return (ROLE_KEYS[(role, req.epoch)], POLICY_ID)
    if role == "ETH_MULTI":
        return (ROLE_KEYS[(role, req.epoch)], req.destination_tx)
    return (BRIDGE_ID, req.source_key)


def canonical_artifact(role: str, req: Request) -> Artifact:
    epoch = 0 if role == "MLSAG" else req.epoch
    slots = CANONICAL_SLOTS[(role, epoch)]
    key = ROLE_KEYS[(role, epoch)]
    subject = canonical_subject(role, req)
    bond = BOND_MANIFEST[epoch] if role in ("WARDEN", "ACCOUNT") else ABSENT
    return Artifact(
        role,
        "PRESENT",
        expected_sig(role, epoch, req.digest, slots, key, subject),
        epoch,
        req.digest,
        slots[0],
        slots[1],
        MANIFESTS[(role, epoch)],
        bond,
        key,
        subject,
    )


def canonical_bundle(req: Request) -> Bundle:
    if req.direction == E2M:
        return Bundle(
            "CANONICAL",
            canonical_artifact("MLSAG", req),
            canonical_artifact("FROST", req),
            ABSENT_ARTIFACTS["ETH_MULTI"],
            canonical_artifact("WARDEN", req),
            canonical_artifact("ACCOUNT", req),
        )
    return Bundle(
        "CANONICAL",
        ABSENT_ARTIFACTS["MLSAG"],
        ABSENT_ARTIFACTS["FROST"],
        canonical_artifact("ETH_MULTI", req),
        canonical_artifact("WARDEN", req),
        canonical_artifact("ACCOUNT", req),
    )


def bundle_replace(bundle: Bundle, role: str, artifact: Artifact, variant: str) -> Bundle:
    values = bundle._asdict()
    values[role.lower() if role != "ETH_MULTI" else "eth_multi"] = artifact
    values["variant"] = variant
    return Bundle(**values)


def malformed_bundles(req: Request) -> tuple[Bundle, ...]:
    """Single-fault, baseline-publishable bundle variants.

    Construction is permissive; admission rejects these in ``Bug=NONE``.
    Keeping each mutation independently representable avoids a combinatorial
    cross product while preserving every core falsifier schema.
    """
    base = canonical_bundle(req)
    variants: list[Bundle] = [base]
    roles = ("MLSAG", "FROST", "WARDEN", "ACCOUNT") if req.direction == E2M else ("ETH_MULTI", "WARDEN", "ACCOUNT")
    field_for = {"MLSAG": "mlsag", "FROST": "frost", "ETH_MULTI": "eth_multi", "WARDEN": "warden", "ACCOUNT": "account"}
    omit_name = {
        "MLSAG": "OMIT_MLSAG",
        "FROST": "OMIT_FROST",
        "ETH_MULTI": "OMIT_ETH_MULTISIG",
        "WARDEN": "OMIT_WARDEN_CERT",
        "ACCOUNT": "OMIT_ACCOUNTABILITY_CERT",
    }
    invalid_name = {"MLSAG": "INVALID_MLSAG", "FROST": "INVALID_FROST", "ETH_MULTI": "INVALID_ETH_MULTISIG"}
    under_name = {
        "MLSAG": "UNDER_THRESHOLD_OWNER",
        "FROST": "UNDER_THRESHOLD_FROST",
        "ETH_MULTI": "UNDER_THRESHOLD_ETH",
        "WARDEN": "UNDER_THRESHOLD_WARDEN",
        "ACCOUNT": "UNDER_THRESHOLD_ACCOUNT",
    }
    duplicate_name = {
        "MLSAG": "DUPLICATE_OWNER_SLOTS",
        "FROST": "DUPLICATE_FROST_SLOTS",
        "ETH_MULTI": "DUPLICATE_ETH_SLOTS",
        "WARDEN": "DUPLICATE_WARDEN_SLOTS",
        "ACCOUNT": "DUPLICATE_ACCOUNT_SLOTS",
    }
    stale_name = {
        "FROST": "STALE_FROST_EPOCH",
        "ETH_MULTI": "STALE_ETH_EPOCH",
        "WARDEN": "STALE_WARDEN_EPOCH",
        "ACCOUNT": "STALE_ACCOUNT_EPOCH",
    }
    digest_name = {
        "MLSAG": "MLSAG_DIGEST_MISMATCH",
        "FROST": "FROST_DIGEST_MISMATCH",
        "ETH_MULTI": "ETH_MULTISIG_DIGEST_MISMATCH",
        "WARDEN": "WARDEN_DIGEST_MISMATCH",
        "ACCOUNT": "ACCOUNT_DIGEST_MISMATCH",
    }

    for role in roles:
        field = field_for[role]
        art = getattr(base, field)
        variants.append(bundle_replace(base, role, ABSENT_ARTIFACTS[role], omit_name[role]))
        if role in invalid_name:
            variants.append(bundle_replace(base, role, art._replace(sig_tag=("BAD_SIG", role)), invalid_name[role]))
        one_slots = (art.s1, ABSENT)
        variants.append(
            bundle_replace(
                base,
                role,
                art._replace(s2=ABSENT, sig_tag=expected_sig(role, int(art.epoch), req.digest, one_slots, art.key_or_contract, art.subject)),
                under_name[role],
            )
        )
        duplicate_slots = (art.s1, art.s1)
        variants.append(
            bundle_replace(
                base,
                role,
                art._replace(s2=art.s1, sig_tag=expected_sig(role, int(art.epoch), req.digest, duplicate_slots, art.key_or_contract, art.subject)),
                duplicate_name[role],
            )
        )
        if role in stale_name:
            stale_epoch = 1 - req.epoch
            stale_slots = CANONICAL_SLOTS[(role, stale_epoch)]
            stale_key = ROLE_KEYS[(role, stale_epoch)]
            stale_subject = canonical_subject(role, req)
            if role in ("FROST", "ETH_MULTI"):
                stale_subject = (stale_key, POLICY_ID) if role == "FROST" else (stale_key, req.destination_tx)
            stale = art._replace(
                epoch=stale_epoch,
                s1=stale_slots[0],
                s2=stale_slots[1],
                manifest=MANIFESTS[(role, stale_epoch)],
                bond_manifest=BOND_MANIFEST[stale_epoch] if role in ("WARDEN", "ACCOUNT") else ABSENT,
                key_or_contract=stale_key,
                subject=stale_subject,
            )
            stale = stale._replace(sig_tag=expected_sig(role, stale_epoch, req.digest, stale_slots, stale_key, stale_subject))
            variants.append(bundle_replace(base, role, stale, stale_name[role]))
        wrong_digest = ("OTHER_DIGEST", req.release_id, role)
        slots = (art.s1, art.s2)
        digest_art = art._replace(
            digest=wrong_digest,
            sig_tag=expected_sig(role, int(art.epoch), wrong_digest, slots, art.key_or_contract, art.subject),
        )
        variants.append(bundle_replace(base, role, digest_art, digest_name[role]))

    # A signature by members of another exact roster remains a valid token for
    # those identities, but it cannot satisfy ACCOUNT role membership.
    account = base.account
    wrong_slots = CANONICAL_SLOTS[("WARDEN", req.epoch)]
    wrong_role = account._replace(
        s1=wrong_slots[0],
        s2=wrong_slots[1],
        sig_tag=expected_sig("ACCOUNT", req.epoch, req.digest, wrong_slots, account.key_or_contract, account.subject),
    )
    variants.append(bundle_replace(base, "ACCOUNT", wrong_role, "WRONG_ROLE_SIGNER"))

    wrong_bond = account._replace(bond_manifest=BOND_MANIFEST[1 - req.epoch])
    variants.append(bundle_replace(base, "ACCOUNT", wrong_bond, "WRONG_BOND_MANIFEST"))

    unbonded = account._replace(s2="a3")
    unbonded_slots = (unbonded.s1, unbonded.s2)
    unbonded = unbonded._replace(
        sig_tag=expected_sig("ACCOUNT", req.epoch, req.digest, unbonded_slots, unbonded.key_or_contract, unbonded.subject)
    )
    variants.append(bundle_replace(base, "ACCOUNT", unbonded, "UNBONDED_ACCOUNT_SIGNER"))

    variants.append(bundle_replace(base, "ACCOUNT", ABSENT_ARTIFACTS["ACCOUNT"], "FALSE_RELEASE_WITHOUT_ACCOUNTABILITY"))
    return tuple(variants)


def artifact_slots(artifact: Artifact) -> tuple[str, ...]:
    return tuple(slot for slot in (artifact.s1, artifact.s2) if slot != ABSENT)


def expected_artifact_epoch(role: str, req: Request) -> int:
    return 0 if role == "MLSAG" else req.epoch


def artifact_valid(artifact: Artifact, role: str, req: Request, state: State, *, require_bond: bool = True) -> bool:
    if artifact.present != "PRESENT" or artifact.role != role:
        return False
    epoch = expected_artifact_epoch(role, req)
    slots = artifact_slots(artifact)
    if artifact.epoch != epoch or artifact.digest != req.digest:
        return False
    if len(slots) < THRESHOLD[role] or len(set(slots)) != len(slots):
        return False
    if not set(slots) <= ROLE_ROSTERS[(role, epoch)]:
        return False
    if artifact.manifest != MANIFESTS[(role, epoch)]:
        return False
    if artifact.key_or_contract != ROLE_KEYS[(role, epoch)]:
        return False
    if artifact.subject != canonical_subject(role, req):
        return False
    if artifact.sig_tag != expected_sig(role, epoch, req.digest, slots, artifact.key_or_contract, artifact.subject):
        return False
    if role in ("WARDEN", "ACCOUNT"):
        if artifact.bond_manifest != BOND_MANIFEST[epoch]:
            return False
        if require_bond:
            for signer in slots:
                pos = BOND_POSITION[(epoch, signer)]
                if (pos not in state.locked_operator_bonds and pos not in state.slashed_operator_bonds) or BOND_EXIT_TIME[pos] < LIABILITY_WINDOW_END:
                    return False
    elif artifact.bond_manifest != ABSENT:
        return False
    return True


def required_roles(direction: str) -> tuple[str, ...]:
    return ("MLSAG", "FROST", "WARDEN", "ACCOUNT") if direction == E2M else ("ETH_MULTI", "WARDEN", "ACCOUNT")


def artifact_for(bundle: Bundle, role: str) -> Artifact:
    return {
        "MLSAG": bundle.mlsag,
        "FROST": bundle.frost,
        "ETH_MULTI": bundle.eth_multi,
        "WARDEN": bundle.warden,
        "ACCOUNT": bundle.account,
    }[role]


def bundle_valid(bundle: Bundle, req: Request, state: State) -> bool:
    if not all(artifact_valid(artifact_for(bundle, role), role, req, state) for role in required_roles(req.direction)):
        return False
    forbidden = ("ETH_MULTI",) if req.direction == E2M else ("MLSAG", "FROST")
    return all(artifact_for(bundle, role).present == "ABSENT" for role in forbidden)


ARTIFACT_BUGS = frozenset(
    {
        "FALSE_RELEASE_WITHOUT_ACCOUNTABILITY",
        "OMIT_MLSAG",
        "INVALID_MLSAG",
        "UNDER_THRESHOLD_OWNER",
        "OMIT_FROST",
        "INVALID_FROST",
        "UNDER_THRESHOLD_FROST",
        "OMIT_ETH_MULTISIG",
        "INVALID_ETH_MULTISIG",
        "UNDER_THRESHOLD_ETH",
        "OMIT_WARDEN_CERT",
        "UNDER_THRESHOLD_WARDEN",
        "OMIT_ACCOUNTABILITY_CERT",
        "UNDER_THRESHOLD_ACCOUNT",
        "WRONG_ROLE_SIGNER",
        "DUPLICATE_OWNER_SLOTS",
        "DUPLICATE_FROST_SLOTS",
        "DUPLICATE_ETH_SLOTS",
        "DUPLICATE_WARDEN_SLOTS",
        "DUPLICATE_ACCOUNT_SLOTS",
        "STALE_FROST_EPOCH",
        "STALE_ETH_EPOCH",
        "STALE_WARDEN_EPOCH",
        "STALE_ACCOUNT_EPOCH",
        "MLSAG_DIGEST_MISMATCH",
        "FROST_DIGEST_MISMATCH",
        "ETH_MULTISIG_DIGEST_MISMATCH",
        "WARDEN_DIGEST_MISMATCH",
        "ACCOUNT_DIGEST_MISMATCH",
        "WRONG_BOND_MANIFEST",
        "UNBONDED_ACCOUNT_SIGNER",
    }
)


def release_by_id(state: State, release_id: str) -> Release | None:
    return next((release for release in state.releases if release.request.release_id == release_id), None)


def objective_index(event: str) -> int:
    return EVENTS.index(event)


def objective_value(state: State, event: str):
    return state.objective[objective_index(event)]


def checkpoint_value(state: State, event: str):
    return state.checkpoints[objective_index(event)]


def exact_claimed_fact(assertion: SourceAssertion) -> SourceFact:
    return SourceFact(*assertion[1:])


def ground_truth_fault(state: State, release: Release) -> bool:
    objective = objective_value(state, release.request.event)
    if objective == "UNKNOWN":
        return False
    if objective == "ABSENT":
        return True
    return objective != exact_claimed_fact(release.request.source_assertion)


def auto_verifiable(version: str, direction: str, kind: str) -> bool:
    if kind == "EQUIVOCATION":
        return True
    if kind != "FALSE_SOURCE":
        return False
    return direction == E2M or (direction == M2E and version == V2)


def exact_liable_signers(release: Release) -> frozenset:
    return frozenset(artifact_slots(release.bundle.warden) + artifact_slots(release.bundle.account))


def authenticated_checkpoint(state: State, release: Release) -> Checkpoint | None:
    cp = checkpoint_value(state, release.request.event)
    if cp == NONE or not isinstance(cp, Checkpoint):
        return None
    expected_commitment = ("CHECKPOINT_COMMITMENT", cp.direction, cp.event, cp.fact_status, cp.fact)
    expected_auth = ("CHECKPOINT_AUTH", cp.checkpoint_id, expected_commitment)
    if cp.direction != release.request.direction or cp.event != release.request.event:
        return None
    if cp.commitment != expected_commitment or cp.auth_tag != expected_auth:
        return None
    return cp


def constructible_auto_proof(state: State, release: Release, bug: str) -> bool:
    if not auto_verifiable(release.request.version, release.request.direction, "FALSE_SOURCE"):
        return True
    if bug == "MISSING_AUTOPROOF_ETH" and release.request.direction == E2M:
        return False
    if bug == "MISSING_AUTOPROOF_MOB_V2" and release.request.direction == M2E and release.request.version == V2:
        return False
    cp = authenticated_checkpoint(state, release)
    if cp is None:
        return False
    if cp.fact_status == "ABSENT":
        return True
    if cp.fact_status == "FINAL" and isinstance(cp.fact, SourceFact):
        return cp.fact != exact_claimed_fact(release.request.source_assertion)
    return False


def capacity_event(kind: str, state: State, req: Request, bundle: Bundle, output: str) -> CapacityEvent:
    roles = required_roles(req.direction)
    quorum = frozenset(s for role in roles for s in artifact_slots(artifact_for(bundle, role)))
    return CapacityEvent(
        f"CAP:{kind}:{req.release_id}",
        kind,
        state.now,
        "GEN0",
        req.direction,
        ASSET_FOR_DIRECTION[req.direction],
        req.amount,
        req.release_id,
        req.source_key,
        frozenset((output,)),
        frozenset((f"CAPACITY:{req.direction}:{output}",)),
        frozenset(("CORE_SHARED_DOMAIN",)),
        quorum,
        MANIFESTS[("MLSAG", 0)] if req.direction == E2M else ABSENT,
        MANIFESTS[("FROST", req.epoch)] if req.direction == E2M else ABSENT,
        tuple(MANIFESTS[(role, expected_artifact_epoch(role, req))] for role in roles),
        BOND_MANIFEST[req.epoch],
        ABSENT,
        ABSENT,
        "ACTIVE",
        "ACTIVE",
    )


# ---------------------------------------------------------------------------
# Claim/evidence verifier.  Admission is separate from total adjudication.


def claim_auth(claim_id: str, challenger: str, evidence_id: str, proof_id: tuple) -> tuple:
    return ("CLAIM_AUTH", claim_id, challenger, evidence_id, proof_id)


def evidence_auth(evidence_id: str, proof_id: tuple) -> tuple:
    return ("EVIDENCE_AUTH", evidence_id, proof_id)


def evidence_map(state: State) -> dict[str, Evidence]:
    return {e.evidence_id: e for e in state.evidence}


def claim_map(state: State) -> dict[str, FraudClaim]:
    return {c.claim_id: c for c in state.claims}


def verdict_map(state: State) -> dict[str, Verdict]:
    return {v.claim_id: v for v in state.verdicts}


def proof_id_for_false_source(release: Release, cp: Checkpoint) -> tuple:
    return ("PROOF", "FALSE_SOURCE", release.request.source_key, cp.commitment)


def alt_release_id(release_id: str) -> str:
    return {"F1": "F2", "F2": "F1", "R1": "R2", "R2": "R1"}[release_id]


def make_alt_receipt(role: str, release: Release, alt_digest: tuple) -> Artifact:
    epoch = release.request.epoch
    if role == "WARDEN":
        slots = ("w1", "w3") if epoch == 0 else ("w2", "w3")
    else:
        slots = ("a1", "a3") if epoch == 0 else ("a2", "a3")
    key = ROLE_KEYS[(role, epoch)]
    subject = canonical_subject(role, release.request)
    return Artifact(
        role,
        "PRESENT",
        expected_sig(role, epoch, alt_digest, slots, key, subject),
        epoch,
        alt_digest,
        slots[0],
        slots[1],
        MANIFESTS[(role, epoch)],
        BOND_MANIFEST[epoch],
        key,
        subject,
    )


def make_evidence(state: State, claim_id: str, release: Release, variant: str) -> Evidence | None:
    suffix = f"{claim_id}:{release.request.release_id}:{variant}"
    if variant == "EQUIVOCATION":
        alt_digest = ("INCOMPATIBLE_DIGEST", release.request.source_key, alt_release_id(release.request.release_id), release.request.epoch)
        proof_id = ("PROOF", "EQUIVOCATION", release.request.source_key, release.request.epoch, tuple(sorted((repr(release.request.digest), repr(alt_digest)))))
        evidence_id = f"EV:{suffix}"
        evidence = Evidence(
            evidence_id,
            proof_id,
            "EQUIVOCATION",
            "WELL_FORMED",
            NONE,
            MAX_TIME,
            release.request.release_id,
            alt_release_id(release.request.release_id),
            NONE,
            release.request.digest,
            alt_digest,
            make_alt_receipt("WARDEN", release, alt_digest),
            make_alt_receipt("ACCOUNT", release, alt_digest),
        )
        return evidence._replace(auth_tag=evidence_auth(evidence_id, proof_id))

    cp = authenticated_checkpoint(state, release)
    if cp is None:
        return None
    proof_id = proof_id_for_false_source(release, cp)
    evidence_id = f"EV:{suffix}"
    parse_tag = "MALFORMED" if variant == "MALFORMED" else "WELL_FORMED"
    expiry = -1 if variant == "EXPIRED" else MAX_TIME
    evidence = Evidence(
        evidence_id,
        proof_id,
        "FALSE_SOURCE",
        parse_tag,
        NONE,
        expiry,
        release.request.release_id,
        NONE,
        cp,
        release.request.digest,
        NONE,
        ABSENT_ARTIFACTS["WARDEN"],
        ABSENT_ARTIFACTS["ACCOUNT"],
    )
    auth = ("BAD_AUTH", evidence_id) if variant == "UNAUTHENTICATED" else evidence_auth(evidence_id, proof_id)
    return evidence._replace(auth_tag=auth)


def make_claim(claim_id: str, evidence: Evidence, variant: str) -> FraudClaim:
    challenger = "c1" if claim_id == "C1" else "c2"
    claim = FraudClaim(
        claim_id,
        challenger,
        CHALLENGE_BONDS[challenger],
        evidence.target1,
        evidence.target2,
        evidence.kind,
        evidence.evidence_id,
        evidence.proof_id,
        evidence.kind,
        NONE,
    )
    # Evidence authentication and challenger authentication are independent.
    # The ordinary UNAUTHENTICATED variant corrupts the evidence token while
    # leaving the challenger's claim envelope valid.
    auth = ("BAD_CLAIM_AUTH", claim_id) if variant == "UNAUTHENTICATED_CLAIM" else claim_auth(claim_id, challenger, evidence.evidence_id, evidence.proof_id)
    return claim._replace(auth_tag=auth)


def evidence_well_formed(evidence: Evidence) -> bool:
    return (
        evidence.parse_tag == "WELL_FORMED"
        and evidence.kind in ("FALSE_SOURCE", "EQUIVOCATION")
        and evidence.target1 in RELEASE_IDS
        and (evidence.target2 == NONE or evidence.target2 in RELEASE_IDS)
        and isinstance(evidence.proof_id, tuple)
        and evidence.auth_tag == evidence_auth(evidence.evidence_id, evidence.proof_id)
    )


def admission_result(state: State, claim: FraudClaim, evidence: Evidence) -> tuple[str, str]:
    if claim.auth_tag != claim_auth(claim.claim_id, claim.challenger, claim.evidence_id, claim.proof_id):
        return ("REJECT", "UnauthenticatedClaim")
    if claim.challenger not in CHALLENGERS or claim.challenge_bond != CHALLENGE_BONDS.get(claim.challenger):
        return ("REJECT", "UnauthenticatedClaim")
    if claim.evidence_id != evidence.evidence_id or claim.proof_id != evidence.proof_id or claim.kind != evidence.kind:
        return ("REJECT", "Malformed")
    if not evidence_well_formed(evidence):
        return ("REJECT", "Malformed" if evidence.parse_tag != "WELL_FORMED" else "UnauthenticatedEvidence")
    if evidence.expires_at < state.now:
        return ("REJECT", "Expired")
    if evidence.proof_id in state.reserved_proofs or evidence.proof_id in state.consumed_proofs:
        return ("REJECT", "DuplicateProof")
    release = release_by_id(state, claim.target1)
    if release is None:
        return ("REJECT", "UnknownTarget")
    if not auto_verifiable(release.request.version, release.request.direction, evidence.kind):
        return ("REJECT", "Unsupported")
    return ("ADMIT", "Admitted")


def receipt_valid_for_digest(artifact: Artifact, role: str, release: Release, digest: tuple) -> bool:
    req = release.request._replace(digest=digest)
    return artifact_valid(artifact, role, req, _bond_permissive_state(release), require_bond=False)


def _bond_permissive_state(release: Release) -> State:
    # Artifact cryptography for evidence is evaluated against the immutable
    # manifest.  Historical coverage is checked separately against live state.
    return replace(initial_state(), epoch=release.request.epoch)


def verifier_result(state: State, claim: FraudClaim, evidence: Evidence, *, ignore_support: bool = False) -> tuple[str, frozenset]:
    """Pure total result on admitted evidence; never reads objective history."""
    release = release_by_id(state, claim.target1)
    if release is None:
        raise ValueError("verifier called on unadmitted target")
    if not ignore_support and not auto_verifiable(release.request.version, release.request.direction, evidence.kind):
        raise ValueError("verifier called on unsupported evidence")

    if evidence.kind == "FALSE_SOURCE":
        cp = evidence.checkpoint
        if not isinstance(cp, Checkpoint):
            raise ValueError("admitted false-source proof lacks checkpoint")
        claimed = exact_claimed_fact(release.request.source_assertion)
        operator_fault = cp.fact_status == "ABSENT" or (cp.fact_status == "FINAL" and cp.fact != claimed)
        return ("OperatorFault", exact_liable_signers(release)) if operator_fault else ("ChallengerFault", frozenset((claim.challenger,)))

    primary_w = frozenset(artifact_slots(release.bundle.warden))
    primary_a = frozenset(artifact_slots(release.bundle.account))
    if evidence.digest1 == release.request.digest and evidence.digest2 != evidence.digest1:
        alt_w = frozenset(artifact_slots(evidence.alt_warden))
        alt_a = frozenset(artifact_slots(evidence.alt_account))
        if receipt_valid_for_digest(evidence.alt_warden, "WARDEN", release, evidence.digest2) and receipt_valid_for_digest(evidence.alt_account, "ACCOUNT", release, evidence.digest2):
            return ("OperatorFault", (primary_w & alt_w) | (primary_a & alt_a))
    return ("ChallengerFault", frozenset((claim.challenger,)))


# ---------------------------------------------------------------------------
# Transition relation.


@dataclass(frozen=True, slots=True)
class Options:
    version: str = "ALL"
    profile: str = "ALL"
    bug: str = "NONE"


def allowed_release_ids(profile: str) -> tuple[str, ...]:
    if profile == "ALL":
        return RELEASE_IDS
    if profile == "E2M":
        return ("F1", "F2")
    if profile == "M2E":
        return ("R1", "R2")
    if profile in RELEASE_IDS:
        return (profile,)
    raise ValueError(f"unknown profile {profile!r}")


def allowed_versions(version: str) -> tuple[str, ...]:
    if version == "ALL":
        return VERSIONS
    if version in VERSIONS:
        return (version,)
    raise ValueError(f"unknown version {version!r}")


def append_unique(values: tuple, value) -> tuple:
    return values if value in values else values + (value,)


def release_path_checkpoint_ready(state: State, req: Request) -> bool:
    # Presence of an authenticated public checkpoint is a version capability
    # prerequisite, never a comparison to source truth.  Reverse V1 has no
    # objective checkpoint proof and deliberately skips this prerequisite.
    if not auto_verifiable(req.version, req.direction, "FALSE_SOURCE"):
        return True
    cp = checkpoint_value(state, req.event)
    return isinstance(cp, Checkpoint)


def action_successors(state: State, options: Options) -> list[tuple[str, State]]:
    if state.halted:
        return []
    out: list[tuple[str, State]] = []
    bug = options.bug

    # Environment-only objective history.  A fact is written once.  The guard
    # depends on observable request timing, never on its eventual fact value.
    relevant_events = tuple(sorted({event_of(r) for r in allowed_release_ids(options.profile)}))
    for event in relevant_events:
        idx = objective_index(event)
        event_in_pipeline = state.work_request is not None and state.work_request.event == event
        event_released = any(r.request.event == event for r in state.releases)
        if state.objective[idx] == "UNKNOWN" and not event_in_pipeline and not event_released:
            for status in ("ABSENT", "FINAL"):
                values = list(state.objective)
                if status == "ABSENT":
                    values[idx] = "ABSENT"
                else:
                    exemplar = "F1" if event == "ETH_DEP" else "R1"
                    values[idx] = canonical_fact(exemplar)
                out.append(("RecordObjectiveSourceFact", replace(state, objective=tuple(values))))

    # Allowlisted observable proof bridge.  This is the only action that copies
    # objective source history into authenticated public checkpoint material.
    for event in relevant_events:
        idx = objective_index(event)
        fact = state.objective[idx]
        if fact != "UNKNOWN" and state.checkpoints[idx] == NONE:
            direction = E2M if event == "ETH_DEP" else M2E
            status = "ABSENT" if fact == "ABSENT" else "FINAL"
            cp_fact = "ABSENT" if fact == "ABSENT" else fact
            commitment = ("CHECKPOINT_COMMITMENT", direction, event, status, cp_fact)
            checkpoint = Checkpoint(
                f"CHECKPOINT:{event}",
                direction,
                event,
                status,
                cp_fact,
                commitment,
                ("CHECKPOINT_AUTH", f"CHECKPOINT:{event}", commitment),
            )
            values = list(state.checkpoints)
            values[idx] = checkpoint
            out.append(("PublishVerifiableCheckpoint", replace(state, checkpoints=tuple(values))))

    # One active construction pipeline, with at most two finalized releases in
    # a trace.  Four fixed IDs still make same-event retries/version replay real.
    if state.work_status == "NONE" and len(state.releases) < 2 and state.active_claim == NONE:
        used = {release.request.release_id for release in state.releases}
        for release_id in allowed_release_ids(options.profile):
            if release_id in used:
                continue
            for version in allowed_versions(options.version):
                req = make_request(release_id, version, state.epoch, bug)
                out.append(("ConstructSourceAssertion", replace(state, work_status="REQUESTED", work_request=req)))

    if state.work_status == "REQUESTED" and state.work_request is not None:
        for bundle in malformed_bundles(state.work_request):
            out.append(("AssembleDirectionArtifacts", replace(state, work_status="ASSEMBLED", work_bundle=bundle)))

    if state.work_status == "ASSEMBLED" and state.work_request is not None and state.work_bundle is not None:
        req, bundle = state.work_request, state.work_bundle
        valid = bundle_valid(bundle, req, state)
        defect_accept = bug in ARTIFACT_BUGS and bundle.variant == bug
        truth_suppressed = bug == "TRUTH_IN_RELEASE_GUARD" and objective_value(state, req.event) != "UNKNOWN" and (
            objective_value(state, req.event) == "ABSENT"
            or objective_value(state, req.event) != exact_claimed_fact(req.source_assertion)
        )
        if (valid or defect_accept) and release_path_checkpoint_ready(state, req) and not truth_suppressed:
            event = capacity_event("AUTHORIZE_PENDING_RELEASE", state, req, bundle, OUTPUT_FOR_RELEASE[req.release_id])
            out.append(
                (
                    "SubmitDestinationRelease",
                    replace(state, work_status="SUBMITTED", capacity_events=append_unique(state.capacity_events, event)),
                )
            )
        if not valid and not defect_accept:
            rejection = (req.release_id, bundle.variant, "InvalidAuthorization")
            out.append(
                (
                    "RejectDestinationRelease",
                    replace(state, settlement_rejections=append_unique(state.settlement_rejections, rejection), halted=True),
                )
            )

    if state.work_status == "SUBMITTED" and state.work_request is not None and state.work_bundle is not None:
        req, bundle = state.work_request, state.work_bundle
        output = OUTPUT_FOR_RELEASE[req.release_id]
        owners = [n.release_id for n in state.nullifier_consumptions if n.nullifier == req.nullifier]
        reserve_ready = output in state.unspent_outputs
        nullifier_ready = not owners
        if reserve_ready and (nullifier_ready or bug == "REUSE_SOURCE_EVENT"):
            consumed_output = output
            unspent = state.unspent_outputs - {output}
            spent = state.spent_outputs | {output}
            if bug == "RELEASE_WITHOUT_RESERVE":
                consumed_output = NONE
                unspent = state.unspent_outputs
                spent = state.spent_outputs
            release = Release(req, bundle, consumed_output, state.now)
            nullifiers = state.nullifier_consumptions
            if bug != "OMIT_NULLIFIER_CONSUMPTION":
                nullifiers += (NullifierConsumption(req.nullifier, req.release_id, req.direction, req.event),)
            final_event = capacity_event("FINALIZE_RELEASE", state, req, bundle, output)
            out.append(
                (
                    "FinalizeDestinationRelease",
                    replace(
                        state,
                        work_status="NONE",
                        work_request=None,
                        work_bundle=None,
                        releases=state.releases + (release,),
                        unspent_outputs=unspent,
                        spent_outputs=spent,
                        nullifier_consumptions=nullifiers,
                        capacity_events=append_unique(state.capacity_events, final_event),
                    ),
                )
            )
        elif not nullifier_ready:
            kind = "IdempotentRebroadcast" if req.release_id in owners else "SourceEventAlreadyConsumed"
            rejection = (req.release_id, bundle.variant, kind)
            out.append(("RejectSettlementReplay", replace(state, settlement_rejections=append_unique(state.settlement_rejections, rejection), halted=True)))
        elif not reserve_ready:
            rejection = (req.release_id, bundle.variant, "InsufficientReserve")
            out.append(("RejectDestinationRelease", replace(state, settlement_rejections=append_unique(state.settlement_rejections, rejection), halted=True)))

    # Identical rebroadcast is an explicit typed rejection, never misconduct.
    for release in state.releases:
        rejection = (release.request.release_id, "CANONICAL", "IdempotentRebroadcast")
        if rejection not in state.settlement_rejections:
            out.append(("RejectIdenticalRebroadcast", replace(state, settlement_rejections=state.settlement_rejections + (rejection,), halted=True)))

    if bug == "POISON_NULLIFIER" and not state.nullifier_consumptions and not state.releases:
        n = stable_nullifier(E2M, "ETH_DEP")
        out.append(("PoisonNullifier", replace(state, nullifier_consumptions=(NullifierConsumption(n, "F1", E2M, "ETH_DEP"),))))

    # Evidence/claim construction is post-release and reads only public records.
    if state.releases and state.active_claim == NONE and len(state.claims) < 2 and state.work_status == "NONE":
        claim_id = next((cid for cid in CLAIM_IDS if cid not in {c.claim_id for c in state.claims}), None)
        if claim_id is not None:
            for release in state.releases:
                # C2 exists principally to prove ClaimId/proofId independence
                # and duplicate-proof rejection.  Repeating every C1 evidence
                # variant under C2 adds no semantic coverage and multiplies the
                # graph, so a later claim is restricted to the replay below.
                variants = [] if state.claims else ["CANONICAL", "MALFORMED", "UNAUTHENTICATED", "EXPIRED", "EQUIVOCATION"]
                for variant in variants:
                    evidence = make_evidence(state, claim_id, release, variant)
                    if evidence is None:
                        continue
                    claim = make_claim(claim_id, evidence, variant)
                    out.append(
                        (
                            "SubmitFraudClaim",
                            replace(
                                state,
                                claims=state.claims + (claim,),
                                evidence=state.evidence + (evidence,),
                                active_claim=claim_id,
                            ),
                        )
                    )
                # A second claim may deliberately reuse an already-reserved
                # proof while retaining its own independent ClaimId.
                if state.reserved_proofs:
                    proof = sorted(state.reserved_proofs, key=repr)[0]
                    prior = next((e for e in state.evidence if e.proof_id == proof), None)
                    if prior is not None:
                        evidence_id = f"EV:{claim_id}:{release.request.release_id}:DUPLICATE"
                        dup_e = prior._replace(evidence_id=evidence_id, auth_tag=evidence_auth(evidence_id, proof))
                        dup_c = make_claim(claim_id, dup_e, "DUPLICATE")
                        out.append(
                            (
                                "SubmitFraudClaim",
                                replace(state, claims=state.claims + (dup_c,), evidence=state.evidence + (dup_e,), active_claim=claim_id),
                            )
                        )

    if state.active_claim != NONE:
        claims = claim_map(state)
        evidences = evidence_map(state)
        claim = claims[state.active_claim]
        evidence = evidences[claim.evidence_id]
        result, reason = admission_result(state, claim, evidence)
        unsupported_bug = bug == "UNSUPPORTED_AUTO_SLASH" and reason == "Unsupported"
        if result == "ADMIT" or unsupported_bug:
            out.append(
                (
                    "AdmitClaim",
                    replace(
                        state,
                        admissions=state.admissions | {claim.claim_id},
                        reserved_proofs=state.reserved_proofs | {claim.proof_id},
                        active_claim=NONE,
                    ),
                )
            )
        else:
            rejection = (claim.claim_id, claim.proof_id, reason)
            out.append(
                (
                    "RejectClaim",
                    replace(
                        state,
                        claim_rejections=state.claim_rejections + (rejection,),
                        active_claim=NONE,
                        halted=bug != "REJECTED_CLAIM_EFFECT",
                    ),
                )
            )

    # Once admitted, a pure verifier is the sole baseline verdict source.
    for claim_id in state.admissions:
        if claim_id in {v.claim_id for v in state.verdicts}:
            continue
        claim = claim_map(state)[claim_id]
        evidence = evidence_map(state)[claim.evidence_id]
        release = release_by_id(state, claim.target1)
        ignore_support = bug == "UNSUPPORTED_AUTO_SLASH" and release is not None and not auto_verifiable(
            release.request.version, release.request.direction, evidence.kind
        )
        result, culprits = verifier_result(state, claim, evidence, ignore_support=ignore_support)
        if bug == "ARBITRARY_OPERATOR_VERDICT" and result == "ChallengerFault":
            result, culprits = "OperatorFault", exact_liable_signers(release)
        if bug == "INNOCENT_CULPRIT" and result == "OperatorFault":
            culprits = culprits | {"g3"}
        verdict = Verdict(claim_id, claim.proof_id, result, culprits)
        out.append(("RecordVerdict", replace(state, verdicts=state.verdicts + (verdict,), active_claim=NONE)))

    # Verdict application is exact-once in baseline and contains all effects.
    for verdict in state.verdicts:
        if verdict.proof_id in state.consumed_proofs:
            continue
        claim = claim_map(state)[verdict.claim_id]
        release = release_by_id(state, claim.target1)
        assert release is not None
        epoch = release.request.epoch
        if verdict.result == "OperatorFault":
            bonds = frozenset(BOND_POSITION[(epoch, signer)] for signer in verdict.culprits if (epoch, signer) in BOND_POSITION)
            app = Application(verdict.claim_id, verdict.proof_id, verdict.result, bonds, frozenset(), 1, 0, epoch, verdict.culprits)
            ce = CapacityEvent(
                f"CAP:APPLY_OPERATOR_FAULT:{repr(verdict.proof_id)}",
                "APPLY_OPERATOR_FAULT",
                state.now,
                "GEN0",
                release.request.direction,
                ASSET_FOR_DIRECTION[release.request.direction],
                release.request.amount,
                release.request.release_id,
                release.request.source_key,
                frozenset((release.consumed_output,)) if release.consumed_output != NONE else frozenset(),
                frozenset(),
                frozenset(("CORE_SHARED_DOMAIN",)),
                verdict.culprits,
                MANIFESTS[("MLSAG", 0)] if release.request.direction == E2M else ABSENT,
                MANIFESTS[("FROST", epoch)] if release.request.direction == E2M else ABSENT,
                tuple(),
                BOND_MANIFEST[epoch],
                ABSENT,
                ABSENT,
                "ACTIVE",
                "PAUSED",
            )
            out.append(
                (
                    "ApplyOperatorFault",
                    replace(
                        state,
                        applications=state.applications + (app,),
                        consumed_proofs=state.consumed_proofs | {verdict.proof_id},
                        locked_operator_bonds=state.locked_operator_bonds - bonds,
                        slashed_operator_bonds=state.slashed_operator_bonds | bonds,
                        paused_epochs=state.paused_epochs | {epoch},
                        pause_causes=state.pause_causes | {verdict.proof_id},
                        expelled=state.expelled | verdict.culprits,
                        capacity_events=append_unique(state.capacity_events, ce),
                    ),
                )
            )
        else:
            bond = CHALLENGE_BONDS[claim.challenger]
            challenger_bonds = frozenset((bond,))
            pause_epoch: int | str = ABSENT
            operator_bonds = frozenset()
            expelled = frozenset()
            paused = state.paused_epochs
            pause_causes = state.pause_causes
            slashed_ops = state.slashed_operator_bonds
            slashed_challengers = state.slashed_challenge_bonds | challenger_bonds
            locked_challengers = state.locked_challenge_bonds - challenger_bonds
            if bug == "FALSE_CHALLENGE_PAUSES":
                pause_epoch = epoch
                paused = paused | {epoch}
                pause_causes = pause_causes | {verdict.proof_id}
                operator_bonds = frozenset((BOND_POSITION[(epoch, artifact_slots(release.bundle.account)[0])],))
                slashed_ops = slashed_ops | operator_bonds
                expelled = frozenset((artifact_slots(release.bundle.account)[0],))
            if bug == "WRONG_CHALLENGER_SLASH":
                wrong = "c2" if claim.challenger == "c1" else "c1"
                challenger_bonds = frozenset((CHALLENGE_BONDS[wrong],))
                slashed_challengers = state.slashed_challenge_bonds | challenger_bonds
                locked_challengers = state.locked_challenge_bonds - challenger_bonds
            app = Application(verdict.claim_id, verdict.proof_id, verdict.result, operator_bonds, challenger_bonds, 0, 0, pause_epoch, expelled)
            out.append(
                (
                    "ApplyChallengerFault",
                    replace(
                        state,
                        applications=state.applications + (app,),
                        consumed_proofs=state.consumed_proofs | {verdict.proof_id},
                        locked_challenge_bonds=locked_challengers,
                        slashed_challenge_bonds=slashed_challengers,
                        slashed_operator_bonds=slashed_ops,
                        paused_epochs=paused,
                        pause_causes=pause_causes,
                        expelled=state.expelled | expelled,
                    ),
                )
            )

    if bug == "SLASH_WITHOUT_VERDICT" and state.releases and not state.applications:
        release = state.releases[0]
        signer = artifact_slots(release.bundle.account)[0]
        bond = BOND_POSITION[(release.request.epoch, signer)]
        proof = ("PROOF", "FABRICATED")
        app = Application("C1", proof, "OperatorFault", frozenset((bond,)), frozenset(), 1, 0, release.request.epoch, frozenset((signer,)))
        out.append(
            (
                "ApplyWithoutVerdict",
                replace(
                    state,
                    applications=(app,),
                    consumed_proofs=frozenset((proof,)),
                    locked_operator_bonds=state.locked_operator_bonds - {bond},
                    slashed_operator_bonds=state.slashed_operator_bonds | {bond},
                    paused_epochs=state.paused_epochs | {release.request.epoch},
                    pause_causes=state.pause_causes | {proof},
                    expelled=state.expelled | {signer},
                ),
            )
        )

    if bug == "DOUBLE_APPLY_PROOF" and state.applications:
        app = state.applications[0]
        if len([a for a in state.applications if a.proof_id == app.proof_id]) == 1:
            out.append(("DoubleApplyProof", replace(state, applications=state.applications + (app,))))

    if bug == "REJECTED_CLAIM_EFFECT" and state.claim_rejections and not state.applications:
        claim_id, proof, _ = state.claim_rejections[0]
        app = Application(claim_id, proof, "OperatorFault", frozenset(), frozenset(), 1, 0, state.epoch, frozenset())
        out.append(
            (
                "RejectedClaimEffect",
                replace(
                    state,
                    applications=(app,),
                    consumed_proofs=state.consumed_proofs | {proof},
                    paused_epochs=state.paused_epochs | {state.epoch},
                    pause_causes=state.pause_causes | {proof},
                ),
            )
        )

    if bug == "EARLY_BOND_EXIT" and state.releases:
        release = state.releases[0]
        signer = artifact_slots(release.bundle.account)[0]
        position = BOND_POSITION[(release.request.epoch, signer)]
        if position in state.locked_operator_bonds and position not in state.slashed_operator_bonds:
            out.append(("CompleteBondExit", replace(state, locked_operator_bonds=state.locked_operator_bonds - {position})))

    # Gate-epoch completion is containment, not ownership-key recovery.
    if state.epoch == 0 and 0 in state.paused_epochs:
        next_required = ROLE_ROSTERS[("FROST", 1)] | ROLE_ROSTERS[("WARDEN", 1)] | ROLE_ROSTERS[("ACCOUNT", 1)]
        if not (next_required & state.expelled):
            out.append(("CompleteFreshGateEpoch", replace(state, epoch=1, fresh_gate_epochs=state.fresh_gate_epochs | {1})))

    return out


# ---------------------------------------------------------------------------
# Named safety invariants and relational/transition audits.


def type_ok(state: State) -> bool:
    if state.epoch not in EPOCHS or type(state.epoch) is not int:
        return False
    if state.now not in range(MAX_TIME + 1) or type(state.now) is not int:
        return False
    if state.work_status not in ("NONE", "REQUESTED", "ASSEMBLED", "SUBMITTED") or type(state.halted) is not bool:
        return False
    if len(state.objective) != len(EVENTS) or len(state.checkpoints) != len(EVENTS):
        return False
    for fact in state.objective:
        if fact not in ("UNKNOWN", "ABSENT") and not isinstance(fact, SourceFact):
            return False
        if isinstance(fact, SourceFact) and (type(fact.source_amount) is not int or type(fact.destination_amount) is not int):
            return False
    if not state.unspent_outputs <= ALL_OUTPUTS or not state.spent_outputs <= ALL_OUTPUTS:
        return False
    if any(r.request.release_id not in RELEASE_IDS or r.request.version not in VERSIONS or r.request.direction not in DIRECTIONS for r in state.releases):
        return False
    if len({r.request.release_id for r in state.releases}) != len(state.releases):
        return False
    if any(c.claim_id not in CLAIM_IDS or c.challenger not in CHALLENGERS for c in state.claims):
        return False
    if len({c.claim_id for c in state.claims}) != len(state.claims):
        return False
    if len({e.evidence_id for e in state.evidence}) != len(state.evidence):
        return False
    if state.active_claim != NONE and state.active_claim not in {c.claim_id for c in state.claims}:
        return False
    if any(type(e.expires_at) is not int for e in state.evidence):
        return False
    if any(type(a.restitution_units) is not int or type(a.bounty_units) is not int for a in state.applications):
        return False
    if not state.expelled <= ALL_IDENTITIES:
        return False
    return True


def no_policy_bypass(state: State) -> bool:
    for release in state.releases:
        req, bundle = release.request, release.bundle
        if any(artifact_for(bundle, role).present != "PRESENT" for role in required_roles(req.direction)):
            return False
        forbidden = ("ETH_MULTI",) if req.direction == E2M else ("MLSAG", "FROST")
        if any(artifact_for(bundle, role).present != "ABSENT" for role in forbidden):
            return False
    return True


def role_sound(state: State, role: str) -> bool:
    return all(
        artifact_valid(
            artifact_for(r.bundle, role),
            role,
            r.request,
            state,
            require_bond=role in ("WARDEN", "ACCOUNT"),
        )
        for r in state.releases
        if role in required_roles(r.request.direction)
    )


def signer_slots_distinct(state: State) -> bool:
    for release in state.releases:
        for role in required_roles(release.request.direction):
            slots = artifact_slots(artifact_for(release.bundle, role))
            if len(slots) != len(set(slots)) or ABSENT in slots:
                return False
    return True


def role_thresholds_independent(state: State) -> bool:
    for release in state.releases:
        for role in required_roles(release.request.direction):
            art = artifact_for(release.bundle, role)
            epoch = expected_artifact_epoch(role, release.request)
            if len(set(artifact_slots(art)) & ROLE_ROSTERS[(role, epoch)]) < THRESHOLD[role]:
                return False
    return True


def release_digest_bound(state: State) -> bool:
    return all(
        artifact_for(r.bundle, role).digest == r.request.digest
        for r in state.releases
        for role in required_roles(r.request.direction)
    )


def release_epoch_sound(state: State) -> bool:
    return all(
        artifact_for(r.bundle, role).epoch == expected_artifact_epoch(role, r.request)
        for r in state.releases
        for role in required_roles(r.request.direction)
    )


def historical_bond_binding(state: State) -> bool:
    for release in state.releases:
        epoch = release.request.epoch
        for role in ("WARDEN", "ACCOUNT"):
            artifact = artifact_for(release.bundle, role)
            if artifact.bond_manifest != BOND_MANIFEST[epoch]:
                return False
            for signer in artifact_slots(artifact):
                if (epoch, signer) not in BOND_POSITION:
                    return False
                position = BOND_POSITION[(epoch, signer)]
                if position not in state.locked_operator_bonds and position not in state.slashed_operator_bonds:
                    return False
                if BOND_EXIT_TIME[position] < LIABILITY_WINDOW_END:
                    return False
    return True


def escrow_output_partition(state: State) -> bool:
    return state.unspent_outputs | state.spent_outputs == ALL_OUTPUTS and not (state.unspent_outputs & state.spent_outputs)


def release_value_conserved(state: State) -> bool:
    for release in state.releases:
        expected = OUTPUT_FOR_RELEASE[release.request.release_id]
        if release.consumed_output != expected or expected not in state.spent_outputs:
            return False
        if release.request.amount != 1 or destination_asset(release.request.direction) != ASSET_FOR_DIRECTION[release.request.direction]:
            return False
    return True


def nullifier_bijection(state: State) -> bool:
    release_ids = {r.request.release_id for r in state.releases}
    owners = {(n.nullifier, n.release_id) for n in state.nullifier_consumptions}
    expected = {(r.request.nullifier, r.request.release_id) for r in state.releases}
    if owners != expected or {n.release_id for n in state.nullifier_consumptions} != release_ids:
        return False
    by_nullifier: dict[tuple, set[str]] = {}
    for n in state.nullifier_consumptions:
        by_nullifier.setdefault(n.nullifier, set()).add(n.release_id)
    return all(len(ids) == 1 for ids in by_nullifier.values())


def stable_source_nullifier(state: State) -> bool:
    requests = [r.request for r in state.releases]
    if state.work_request is not None:
        requests.append(state.work_request)
    return all(req.nullifier == stable_nullifier(req.direction, req.event) for req in requests)


def unmatched_has_accountability(state: State) -> bool:
    for release in state.releases:
        if ground_truth_fault(state, release):
            if not artifact_valid(release.bundle.warden, "WARDEN", release.request, state, require_bond=False):
                return False
            if not artifact_valid(release.bundle.account, "ACCOUNT", release.request, state, require_bond=False):
                return False
            if len(exact_liable_signers(release)) < K_WARDEN + K_ACCOUNT:
                return False
            epoch = release.request.epoch
            for signer in exact_liable_signers(release):
                if (epoch, signer) not in BOND_POSITION:
                    return False
                position = BOND_POSITION[(epoch, signer)]
                if position not in state.locked_operator_bonds and position not in state.slashed_operator_bonds:
                    return False
    return True


def unmatched_has_automatic_proof(state: State, bug: str) -> bool:
    return all(not ground_truth_fault(state, release) or constructible_auto_proof(state, release, bug) for release in state.releases)


def claim_evidence_immutable(state: State) -> bool:
    evidences = evidence_map(state)
    return all(c.evidence_id in evidences and c.proof_id == evidences[c.evidence_id].proof_id and c.kind == evidences[c.evidence_id].kind for c in state.claims)


def rejection_sound(state: State) -> bool:
    claims = claim_map(state)
    evidences = evidence_map(state)
    for claim_id, proof_id, reason in state.claim_rejections:
        if claim_id not in claims or claims[claim_id].proof_id != proof_id:
            return False
        expected = admission_result(replace(state, reserved_proofs=state.reserved_proofs - {proof_id}), claims[claim_id], evidences[claims[claim_id].evidence_id])
        # Duplicate proof is evaluated against the actual reservation set.
        if reason == "DuplicateProof":
            expected = admission_result(state, claims[claim_id], evidences[claims[claim_id].evidence_id])
        if expected[0] != "REJECT" or expected[1] != reason:
            return False
        if claim_id in state.admissions:
            return False
    return True


def verdict_deterministic(state: State) -> bool:
    claims, evidences = claim_map(state), evidence_map(state)
    for verdict in state.verdicts:
        claim = claims.get(verdict.claim_id)
        if claim is None:
            return False
        release = release_by_id(state, claim.target1)
        if release is None or not auto_verifiable(release.request.version, release.request.direction, evidences[claim.evidence_id].kind):
            return False
        if (verdict.result, verdict.culprits) != verifier_result(state, claim, evidences[claim.evidence_id]):
            return False
    return True


def verdict_sound(state: State) -> bool:
    claims = claim_map(state)
    for verdict in state.verdicts:
        if verdict.result == "ChallengerFault" and verdict.culprits != frozenset((claims[verdict.claim_id].challenger,)):
            return False
    for app in state.applications:
        verdict = next((v for v in state.verdicts if v.claim_id == app.claim_id and v.proof_id == app.proof_id), None)
        if verdict is not None and verdict.result == "ChallengerFault":
            challenger = claims[verdict.claim_id].challenger
            if app.challenger_bonds != frozenset((CHALLENGE_BONDS[challenger],)) or app.operator_bonds:
                return False
    return True


def culprit_set_exact(state: State) -> bool:
    claims, evidences = claim_map(state), evidence_map(state)
    for verdict in state.verdicts:
        if verdict.result != "OperatorFault":
            continue
        claim = claims[verdict.claim_id]
        release = release_by_id(state, claim.target1)
        if release is None:
            return False
        evidence = evidences[claim.evidence_id]
        supported = auto_verifiable(release.request.version, release.request.direction, evidence.kind)
        expected = verifier_result(state, claim, evidence, ignore_support=not supported)[1]
        if verdict.culprits != expected:
            return False
    return True


def slash_requires_verdict(state: State) -> bool:
    verdicts = {(v.claim_id, v.proof_id, v.result) for v in state.verdicts}
    return all((a.claim_id, a.proof_id, a.result) in verdicts for a in state.applications)


def slash_exact_once(state: State) -> bool:
    proof_ids = [a.proof_id for a in state.applications]
    return len(proof_ids) == len(set(proof_ids)) and set(proof_ids) == set(state.consumed_proofs)


def no_rejected_claim_effect(state: State) -> bool:
    for claim_id, proof, reason in state.claim_rejections:
        if any(a.claim_id == claim_id and a.proof_id == proof for a in state.applications):
            return False
        # A duplicate submission can refer to a proof whose legitimate first
        # application already caused effects.  Those effects are not caused by
        # the rejected ClaimId.  Every other rejected proof must be inert.
        if reason != "DuplicateProof" and (proof in state.consumed_proofs or proof in state.pause_causes):
            return False
    return True


def no_unsupported_automatic_slash(state: State) -> bool:
    claims = claim_map(state)
    for verdict in state.verdicts:
        claim = claims[verdict.claim_id]
        release = release_by_id(state, claim.target1)
        if release and release.request.direction == M2E and release.request.version == V1 and claim.kind == "FALSE_SOURCE":
            if verdict.result == "OperatorFault":
                return False
    return True


def challenger_fault_does_not_pause(state: State) -> bool:
    for app in state.applications:
        if app.result == "ChallengerFault" and (app.pause_epoch != ABSENT or app.operator_bonds or app.expelled or app.proof_id in state.pause_causes):
            return False
    return True


def operator_fault_containment(state: State) -> bool:
    verdicts = verdict_map(state)
    for app in state.applications:
        if app.result != "OperatorFault":
            continue
        verdict = verdicts.get(app.claim_id)
        if verdict is None:
            return False
        claim = claim_map(state)[app.claim_id]
        release = release_by_id(state, claim.target1)
        if release is None:
            return False
        epoch = release.request.epoch
        expected_bonds = frozenset(BOND_POSITION[(epoch, s)] for s in verdict.culprits if (epoch, s) in BOND_POSITION)
        if app.operator_bonds != expected_bonds or app.restitution_units != 1 or app.pause_epoch != epoch or app.expelled != verdict.culprits:
            return False
        if epoch not in state.paused_epochs or app.proof_id not in state.pause_causes or not verdict.culprits <= state.expelled:
            return False
        if not expected_bonds <= state.slashed_operator_bonds:
            return False
    return True


INVARIANTS = {
    "TypeOK": type_ok,
    "NoPolicyBypass": no_policy_bypass,
    "MlsagArtifactSound": lambda s: role_sound(s, "MLSAG"),
    "FrostArtifactSound": lambda s: role_sound(s, "FROST"),
    "EthereumMultisigArtifactSound": lambda s: role_sound(s, "ETH_MULTI"),
    "WardenCertificateSound": lambda s: role_sound(s, "WARDEN"),
    "AccountabilityCertificateSound": lambda s: role_sound(s, "ACCOUNT"),
    "SignerSlotsDistinct": signer_slots_distinct,
    "RoleThresholdsIndependent": role_thresholds_independent,
    "ReleaseDigestBound": release_digest_bound,
    "ReleaseEpochSound": release_epoch_sound,
    "HistoricalBondBinding": historical_bond_binding,
    "EscrowOutputPartition": escrow_output_partition,
    "ReleaseValueConserved": release_value_conserved,
    "NullifierBijection": nullifier_bijection,
    "StableSourceNullifier": stable_source_nullifier,
    "UnmatchedReleaseHasAccountability": unmatched_has_accountability,
    "ClaimEvidenceImmutable": claim_evidence_immutable,
    "RejectionSound": rejection_sound,
    "VerdictDeterministic": verdict_deterministic,
    "VerdictSound": verdict_sound,
    "CulpritSetExact": culprit_set_exact,
    "SlashRequiresVerdict": slash_requires_verdict,
    "SlashExactOnce": slash_exact_once,
    "NoRejectedClaimEffect": no_rejected_claim_effect,
    "NoUnsupportedAutomaticSlash": no_unsupported_automatic_slash,
    "ChallengerFaultDoesNotPause": challenger_fault_does_not_pause,
    "OperatorFaultContainment": operator_fault_containment,
}


BUG_EXPECTED = {
    "TRUTH_IN_RELEASE_GUARD": ("TruthNoninterference", "FalseSourceReleaseRepresentable"),
    "FALSE_RELEASE_WITHOUT_ACCOUNTABILITY": ("UnmatchedReleaseHasAccountability",),
    "MISSING_AUTOPROOF_ETH": ("UnmatchedReleaseHasAutomaticProof",),
    "MISSING_AUTOPROOF_MOB_V2": ("UnmatchedReleaseHasAutomaticProof",),
    "OMIT_MLSAG": ("NoPolicyBypass",),
    "INVALID_MLSAG": ("MlsagArtifactSound",),
    "UNDER_THRESHOLD_OWNER": ("MlsagArtifactSound",),
    "OMIT_FROST": ("NoPolicyBypass",),
    "INVALID_FROST": ("FrostArtifactSound",),
    "UNDER_THRESHOLD_FROST": ("FrostArtifactSound",),
    "OMIT_ETH_MULTISIG": ("NoPolicyBypass",),
    "INVALID_ETH_MULTISIG": ("EthereumMultisigArtifactSound",),
    "UNDER_THRESHOLD_ETH": ("EthereumMultisigArtifactSound",),
    "OMIT_WARDEN_CERT": ("NoPolicyBypass",),
    "UNDER_THRESHOLD_WARDEN": ("WardenCertificateSound",),
    "OMIT_ACCOUNTABILITY_CERT": ("NoPolicyBypass",),
    "UNDER_THRESHOLD_ACCOUNT": ("AccountabilityCertificateSound",),
    "WRONG_ROLE_SIGNER": ("RoleThresholdsIndependent",),
    "DUPLICATE_OWNER_SLOTS": ("SignerSlotsDistinct",),
    "DUPLICATE_FROST_SLOTS": ("SignerSlotsDistinct",),
    "DUPLICATE_ETH_SLOTS": ("SignerSlotsDistinct",),
    "DUPLICATE_WARDEN_SLOTS": ("SignerSlotsDistinct",),
    "DUPLICATE_ACCOUNT_SLOTS": ("SignerSlotsDistinct",),
    "STALE_FROST_EPOCH": ("ReleaseEpochSound",),
    "STALE_ETH_EPOCH": ("ReleaseEpochSound",),
    "STALE_WARDEN_EPOCH": ("ReleaseEpochSound",),
    "STALE_ACCOUNT_EPOCH": ("ReleaseEpochSound",),
    "MLSAG_DIGEST_MISMATCH": ("ReleaseDigestBound",),
    "FROST_DIGEST_MISMATCH": ("ReleaseDigestBound",),
    "ETH_MULTISIG_DIGEST_MISMATCH": ("ReleaseDigestBound",),
    "WARDEN_DIGEST_MISMATCH": ("ReleaseDigestBound",),
    "ACCOUNT_DIGEST_MISMATCH": ("ReleaseDigestBound",),
    "WRONG_BOND_MANIFEST": ("HistoricalBondBinding",),
    "UNBONDED_ACCOUNT_SIGNER": ("AccountabilityCertificateSound",),
    "RELEASE_WITHOUT_RESERVE": ("ReleaseValueConserved",),
    "OMIT_NULLIFIER_CONSUMPTION": ("NullifierBijection",),
    "POISON_NULLIFIER": ("NullifierBijection",),
    "REUSE_SOURCE_EVENT": ("NullifierBijection",),
    "VERSIONED_NULLIFIER": ("StableSourceNullifier",),
    "ARBITRARY_OPERATOR_VERDICT": ("VerdictDeterministic",),
    "INNOCENT_CULPRIT": ("CulpritSetExact",),
    "SLASH_WITHOUT_VERDICT": ("SlashRequiresVerdict",),
    "DOUBLE_APPLY_PROOF": ("SlashExactOnce",),
    "REJECTED_CLAIM_EFFECT": ("NoRejectedClaimEffect",),
    "UNSUPPORTED_AUTO_SLASH": ("NoUnsupportedAutomaticSlash",),
    "FALSE_CHALLENGE_PAUSES": ("ChallengerFaultDoesNotPause",),
    "WRONG_CHALLENGER_SLASH": ("VerdictSound",),
    "EARLY_BOND_EXIT": ("HistoricalBondBinding",),
}

CAPACITY_NOT_RUN_BUGS = (
    "RESERVE_CAP_BYPASS",
    "OMIT_PENDING_EXPOSURE",
    "UNDERCOUNT_CROSS_DIRECTION",
    "UNDERCOUNT_CROSS_GENERATION",
    "DOUBLE_COUNT_OVERLAP_BOND",
    "UNFUNDED_SUCCESSOR",
    "FUND_BEFORE_OWNER_AUTHORITY_READY",
    "INELIGIBLE_BACKING",
)


def invariant_failures(state: State, bug: str) -> set[str]:
    failures = {name for name, pred in INVARIANTS.items() if not pred(state)}
    if not unmatched_has_automatic_proof(state, bug):
        failures.add("UnmatchedReleaseHasAutomaticProof")
    return failures


def observable_state(state: State) -> State:
    return replace(state, objective=("<GHOST>", "<GHOST>"))


RELEASE_PATH_ACTIONS = frozenset(
    {
        "ConstructSourceAssertion",
        "AssembleDirectionArtifacts",
        "SubmitDestinationRelease",
        "FinalizeDestinationRelease",
        "RejectDestinationRelease",
        "RejectSettlementReplay",
    }
)


def projected_release_edges(state: State, options: Options) -> frozenset:
    return frozenset((name, observable_state(successor)) for name, successor in action_successors(state, options) if name in RELEASE_PATH_ACTIONS)


def truth_noninterference(states: Iterable[State], options: Options, max_checks: int | None = None) -> tuple[bool, int]:
    checks = 0
    checked_observables: set[State] = set()
    for state in states:
        # Only states with a request/artifact/release-acceptance edge can
        # distinguish the hyperproperty.  Deduplicate ghost-equivalent states.
        if state.work_status == "NONE":
            continue
        observable = observable_state(state)
        if observable in checked_observables:
            continue
        checked_observables.add(observable)
        # Compare every known truth assignment while preserving all observable
        # fields.  UNKNOWN is excluded from this twin because it changes only
        # the environment action's future availability, not a release action.
        variants = []
        for eth_status, mob_status in itertools.product(("ABSENT", "FINAL"), repeat=2):
            objective = []
            for event, status in zip(EVENTS, (eth_status, mob_status)):
                exemplar = "F1" if event == "ETH_DEP" else "R1"
                objective.append("ABSENT" if status == "ABSENT" else canonical_fact(exemplar))
            variants.append(replace(state, objective=tuple(objective)))
        reference = projected_release_edges(variants[0], options)
        for twin in variants[1:]:
            checks += 1
            if projected_release_edges(twin, options) != reference:
                return False, checks
            if max_checks is not None and checks >= max_checks:
                return True, checks
    return True, checks


def objective_history_independent(state: State, successor: State, action: str) -> bool:
    changed = state.objective != successor.objective
    return not changed or action == "RecordObjectiveSourceFact"


# ---------------------------------------------------------------------------
# Reachability witnesses and BFS.


def witness_names(state: State) -> set[str]:
    names: set[str] = set()
    for release in state.releases:
        req = release.request
        prefix = f"{req.direction}_{req.version}"
        if objective_value(state, req.event) != "UNKNOWN":
            if ground_truth_fault(state, release):
                names.add(f"FALSE_RELEASE:{prefix}")
            else:
                names.add(f"HONEST_RELEASE:{prefix}")
        if bundle_valid(release.bundle, req, state):
            names.add(f"ROLE_INDEPENDENCE:{req.direction}")
    for _, _, reason in state.claim_rejections:
        names.add(f"REJECTION:{reason}")
    claims = claim_map(state)
    for verdict in state.verdicts:
        claim = claims[verdict.claim_id]
        release = release_by_id(state, claim.target1)
        if release:
            names.add(f"VERDICT:{verdict.result}:{claim.kind}:{release.request.direction}:{release.request.version}")
    for app in state.applications:
        if app.result == "OperatorFault":
            names.add("OPERATOR_PENALTY_APPLIED")
        else:
            names.add("CHALLENGER_PENALTY_APPLIED")
    for _, _, reason in state.settlement_rejections:
        names.add(f"SETTLEMENT_REJECTION:{reason}")
    if any(len({n.release_id for n in state.nullifier_consumptions if n.nullifier == nullifier}) > 1 for nullifier in {n.nullifier for n in state.nullifier_consumptions}):
        names.add("DUPLICATE_NULLIFIER_RELEASE")
    return names


def required_witnesses(options: Options) -> set[str]:
    required: set[str] = set()
    for direction in DIRECTIONS:
        if not any(direction_of(r) == direction for r in allowed_release_ids(options.profile)):
            continue
        for version in allowed_versions(options.version):
            required.add(f"HONEST_RELEASE:{direction}_{version}")
            required.add(f"FALSE_RELEASE:{direction}_{version}")
            required.add(f"ROLE_INDEPENDENCE:{direction}")
    # Claims require the corresponding direction to be in the selected profile.
    if any(direction_of(r) == E2M for r in allowed_release_ids(options.profile)):
        for version in allowed_versions(options.version):
            required.add(f"VERDICT:OperatorFault:FALSE_SOURCE:E2M:{version}")
    if any(direction_of(r) == M2E for r in allowed_release_ids(options.profile)) and V2 in allowed_versions(options.version):
        required.add("VERDICT:OperatorFault:FALSE_SOURCE:M2E:V2")
    if any(direction_of(r) == M2E for r in allowed_release_ids(options.profile)) and V1 in allowed_versions(options.version):
        required.add("REJECTION:Unsupported")
    required |= {
        "REJECTION:Malformed",
        "REJECTION:UnauthenticatedEvidence",
        "REJECTION:Expired",
        "SETTLEMENT_REJECTION:IdempotentRebroadcast",
    }
    return required


FORBIDDEN_BASELINE = {
    "VERDICT:OperatorFault:FALSE_SOURCE:M2E:V1",
    "DUPLICATE_NULLIFIER_RELEASE",
}


@dataclass(slots=True)
class Exploration:
    states: int
    transitions: int
    failures: dict[str, State]
    witnesses: set[str]
    objective_audit_ok: bool
    all_states: list[State] | None


def explore(options: Options, *, retain_states: bool = True, stop_on_target: bool = False) -> Exploration:
    init = initial_state()
    queue = deque((init,))
    seen = {init}
    failures: dict[str, State] = {}
    witnesses: set[str] = set()
    transitions = 0
    objective_ok = True
    target = set(BUG_EXPECTED.get(options.bug, ()))

    while queue:
        state = queue.popleft()
        witnesses |= witness_names(state)
        for name in invariant_failures(state, options.bug):
            failures.setdefault(name, state)
        if stop_on_target and target and target <= set(failures):
            break
        for action, successor in action_successors(state, options):
            transitions += 1
            if not objective_history_independent(state, successor, action):
                objective_ok = False
                failures.setdefault("ObjectiveHistoryIndependent", successor)
            if successor not in seen:
                seen.add(successor)
                queue.append(successor)

    return Exploration(len(seen), transitions, failures, witnesses, objective_ok, list(seen) if retain_states else None)


# ---------------------------------------------------------------------------
# Independent self-tests.


def assert_raises_bool_int() -> None:
    bad = replace(initial_state(), now=True)
    assert not type_ok(bad), "bool must not be accepted as an integer"


def run_self_tests() -> dict[str, str]:
    results: dict[str, str] = {}

    req1 = make_request("F1", V1, 0, "NONE")
    req2 = make_request("F1", V2, 0, "NONE")
    assert req1.digest != req2.digest
    assert req1.nullifier == req2.nullifier
    assert stable_nullifier(E2M, "ETH_DEP") == stable_nullifier(E2M, "ETH_DEP")
    results["canonical_digest_and_stable_nullifier"] = "PASS"

    base = initial_state()
    bundle = canonical_bundle(req1)
    assert bundle_valid(bundle, req1, base)
    duplicate = next(b for b in malformed_bundles(req1) if b.variant == "DUPLICATE_OWNER_SLOTS")
    assert duplicate.mlsag.s1 == duplicate.mlsag.s2
    assert not bundle_valid(duplicate, req1, base)
    results["ordered_duplicate_slots"] = "PASS"

    wrong = next(b for b in malformed_bundles(req1) if b.variant == "WRONG_ROLE_SIGNER")
    assert set(artifact_slots(wrong.account)) <= ROLE_ROSTERS[("WARDEN", 0)]
    assert not set(artifact_slots(wrong.account)) <= ROLE_ROSTERS[("ACCOUNT", 0)]
    assert not bundle_valid(wrong, req1, base)
    results["role_separation"] = "PASS"

    unique_bonds = {BOND_POSITION[(0, signer)] for signer in ("w1", "a1", "a1")}
    assert len(unique_bonds) == 2
    unique_values = set(("EU1", "EU1", "EU2"))
    assert len(unique_values) == 2
    results["bond_and_value_deduplication"] = "PASS"

    # Build a concrete false-source proof without consulting ghost truth in the
    # verifier, and establish deterministic repeated evaluation.
    state = initial_state()
    fact_state = replace(state, objective=("ABSENT", "UNKNOWN"))
    cp_state = next(s for a, s in action_successors(fact_state, Options(profile="F1", version=V1)) if a == "PublishVerifiableCheckpoint")
    req = make_request("F1", V1, 0, "NONE")
    release = Release(req, canonical_bundle(req), "EU1", 0)
    state = replace(
        cp_state,
        releases=(release,),
        unspent_outputs=ALL_OUTPUTS - {"EU1"},
        spent_outputs=frozenset(("EU1",)),
        nullifier_consumptions=(NullifierConsumption(req.nullifier, "F1", E2M, "ETH_DEP"),),
    )
    evidence = make_evidence(state, "C1", release, "CANONICAL")
    assert evidence is not None
    claim = make_claim("C1", evidence, "CANONICAL")
    state = replace(state, claims=(claim,), evidence=(evidence,))
    first = verifier_result(state, claim, evidence)
    second = verifier_result(state, claim, evidence)
    assert first == second and first[0] == "OperatorFault"
    results["deterministic_evidence_verifier"] = "PASS"

    app = Application("C1", evidence.proof_id, first[0], frozenset(), frozenset(), 1, 0, 0, first[1])
    once = replace(state, applications=(app,), consumed_proofs=frozenset((evidence.proof_id,)))
    twice = replace(once, applications=(app, app))
    assert slash_exact_once(once) and not slash_exact_once(twice)
    results["exact_proof_application"] = "PASS"

    assert_raises_bool_int()
    results["noncanonical_bool_as_int"] = "PASS"

    # Local twin-state oracle on pipeline states.  The defect must be detected.
    pipeline = replace(cp_state, work_status="ASSEMBLED", work_request=req, work_bundle=canonical_bundle(req))
    ok, checks = truth_noninterference((pipeline,), Options(profile="F1", version=V1))
    assert ok and checks > 0
    broken, _ = truth_noninterference((pipeline,), Options(profile="F1", version=V1, bug="TRUTH_IN_RELEASE_GUARD"))
    assert not broken
    results["truth_noninterference_oracle"] = "PASS"

    # Core event envelope must not carry objective history.
    ce = capacity_event("FINALIZE_RELEASE", state, req, canonical_bundle(req), "EU1")
    assert "ABSENT" not in repr(ce) or ce.capital_source_kind == ABSENT
    assert "SourceFact" not in repr(ce) and "GroundTruth" not in repr(ce)
    results["capacity_event_ghost_exclusion"] = "PASS"

    return results


# ---------------------------------------------------------------------------
# Strict config/CLI handling.


CFG_ASSIGNMENT = re.compile(r"^\s*(Version|Profile|Bug)\s*=\s*(?:\"([^\"]+)\"|([A-Za-z0-9_]+))\s*$")


def parse_config(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("\\*", 1)[0].split("#", 1)[0].strip()
        if not line:
            continue
        match = CFG_ASSIGNMENT.match(line)
        if not match:
            # TLA+ runner directives are recognized but not interpreted here.
            if re.match(r"^(SPECIFICATION|CONSTRAINT|ACTION_CONSTRAINT|INVARIANT|PROPERTY|CHECK_DEADLOCK)\b", line):
                continue
            raise ValueError(f"noncanonical or unknown config line: {raw!r}")
        key, quoted, atom = match.groups()
        if key in values:
            raise ValueError(f"duplicate config assignment: {key}")
        value = quoted if quoted is not None else atom
        if value in ("TRUE", "FALSE"):
            raise ValueError(f"Boolean is not a canonical {key} selector")
        values[key] = value
    missing = {"Version", "Profile", "Bug"} - set(values)
    if missing:
        raise ValueError(f"missing config assignments: {sorted(missing)}")
    return values


def validate_options(options: Options) -> None:
    allowed_versions(options.version)
    allowed_release_ids(options.profile)
    if options.bug != "NONE" and options.bug not in BUG_EXPECTED:
        if options.bug in CAPACITY_NOT_RUN_BUGS:
            raise ValueError(f"{options.bug} belongs to the NOT-RUN capacity/generation stage")
        raise ValueError(f"unknown core bug selector {options.bug!r}")


def result_payload(options: Options, result: Exploration, noninterference_ok: bool, twin_checks: int) -> dict:
    required = required_witnesses(options) if options.bug == "NONE" else set()
    missing = sorted(required - result.witnesses)
    forbidden = sorted(FORBIDDEN_BASELINE & result.witnesses) if options.bug == "NONE" else []
    expected = set(BUG_EXPECTED.get(options.bug, ()))
    observed = set(result.failures)
    if options.bug == "TRUTH_IN_RELEASE_GUARD":
        if not noninterference_ok:
            observed.add("TruthNoninterference")
        if not any(w.startswith("FALSE_RELEASE:") for w in result.witnesses):
            observed.add("FalseSourceReleaseRepresentable")
    baseline_ok = not result.failures and result.objective_audit_ok and noninterference_ok and not missing and not forbidden
    defect_ok = options.bug != "NONE" and expected <= observed
    return {
        "status": "PASS" if (baseline_ok if options.bug == "NONE" else defect_ok) else "FAIL",
        "stage": "CORE_AUTHORIZATION_ACCOUNTABILITY_NULLIFIER",
        "capacity_generation_stage": "NOT_RUN",
        "version": options.version,
        "profile": options.profile,
        "bug": options.bug,
        "states": result.states,
        "transitions": result.transitions,
        "invariant_failures": sorted(result.failures),
        "expected_failure": sorted(expected),
        "observed_named_failures": sorted(observed),
        "required_witnesses_missing": missing,
        "forbidden_witnesses_reached": forbidden,
        "witnesses": sorted(result.witnesses),
        "objective_history_independent": result.objective_audit_ok,
        "truth_noninterference": noninterference_ok,
        "truth_twin_checks": twin_checks,
        "core_bug_manifest_count": len(BUG_EXPECTED),
        "capacity_not_run_bugs": list(CAPACITY_NOT_RUN_BUGS),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="ALL", choices=("ALL",) + VERSIONS)
    parser.add_argument("--profile", default="ALL", choices=("ALL", "E2M", "M2E") + RELEASE_IDS)
    parser.add_argument("--bug", default="NONE")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--validate-config", action="store_true")
    parser.add_argument("--count-only", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--stop-on-target", action="store_true", help="stop defect search once every designated failure is reached")
    args = parser.parse_args(argv)

    version, profile, bug = args.version, args.profile, args.bug
    if args.config:
        cfg = parse_config(args.config)
        version, profile, bug = cfg["Version"], cfg["Profile"], cfg["Bug"]
    options = Options(version, profile, bug)
    validate_options(options)

    if args.validate_config:
        print(json.dumps({"status": "PASS", "version": version, "profile": profile, "bug": bug}, sort_keys=True))
        return 0

    if args.self_test:
        tests = run_self_tests()
        print(json.dumps({"status": "PASS", "self_tests": tests, "core_bug_manifest_count": len(BUG_EXPECTED)}, indent=2, sort_keys=True))
        return 0

    retain = not args.count_only
    result = explore(options, retain_states=retain, stop_on_target=args.stop_on_target)
    if args.count_only:
        print(result.states)
        return 0

    states = result.all_states or []
    noninterference_ok, twin_checks = truth_noninterference(states, options)
    payload = result_payload(options, result, noninterference_ok, twin_checks)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Core reachable states: {payload['states']}")
        print(f"Core transitions: {payload['transitions']}")
        print(f"Truth noninterference: {'PASS' if noninterference_ok else 'FAIL'} ({twin_checks} twin comparisons)")
        print(f"Result: {payload['status']}")
        print("Capacity/generation stage: NOT RUN")
        if payload["invariant_failures"]:
            print("Invariant failures: " + ", ".join(payload["invariant_failures"]))
        if payload["required_witnesses_missing"]:
            print("Missing witnesses: " + ", ".join(payload["required_witnesses_missing"]))
    return 0 if payload["status"] == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        raise SystemExit(2)
