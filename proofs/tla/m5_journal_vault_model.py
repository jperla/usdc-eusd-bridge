"""Bounded executable model of the M5 journal/vault integration handshake.

This is a symbolic retained-identity and state-projection reference model, not
an implementation of storage, canonical bytes, authentication, cryptography,
an HSM, or MobileCoin consensus.  The explorer enumerates every reachable
state in the one-child bound and checks safety invariants at each edge.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
from enum import Enum, IntEnum
from typing import Iterable, NamedTuple


class Identity(str, Enum):
    NONE = "none"
    EXACT = "exact"
    CHANGED = "changed"
    CALLER = "caller"


class VaultState(IntEnum):
    EMPTY = 0
    COMMITTED = 1
    SEALED = 2
    RELEASED = 3


class JournalStage(IntEnum):
    BASE_AUTHORITY = 0
    PRODUCE_REQUEST = 1
    SEALED_RECEIPT = 2
    RELEASE_CERTIFICATE = 3
    OUTBOX = 4
    DELIVERY = 5


class Ack(str, Enum):
    NONE = "none"
    NONCE_COMMIT_STATEMENT = "nonce_commit_statement"
    COMMITMENT = "commitment"
    OPERATION_AUTHORIZATION = "operation_authorization"
    PRODUCE_REQUEST = "produce_request"
    SEALED_RESPONSE = "sealed_response"
    SEALED_RECEIPT = "sealed_receipt"
    RELEASE_CERTIFICATE = "release_certificate"
    RELEASE_PERSISTENCE = "release_persistence"
    RESPONSE_RETURN = "response_return"
    OUTBOX = "outbox"
    PUBLISH = "publish"
    DELIVERY = "delivery"


@dataclass(frozen=True)
class Defects:
    """Independent, deliberately unsafe transition gates."""

    skip_commit_authorization: bool = False
    certificate_before_receipt_anchor: bool = False
    raw_before_release: bool = False
    return_before_release: bool = False
    changed_request_rebind: bool = False
    caller_byte_injection: bool = False
    seal_before_j1_anchor: bool = False
    persist_j2_before_seal: bool = False
    release_before_j3_anchor: bool = False
    outbox_before_j3_anchor: bool = False
    changed_certificate_persistence: bool = False
    changed_delivery_persistence: bool = False
    ignore_anchor_ahead_mismatch: bool = False


@dataclass(frozen=True)
class State:
    # Jc: exact authenticated pre-commit plan/statement has distinct DB and
    # monotone operation-authority-anchor observations.
    nonce_commit_statement: Identity = Identity.NONE
    nonce_commit_statement_anchored: bool = False

    commitment_observed: bool = False
    vault: VaultState = VaultState.EMPTY

    # J0: the commitment-dependent operation-wide round-two authorization is
    # necessarily after C and separately anchored before J1.
    operation_authorization: Identity = Identity.NONE
    operation_authorization_anchored: bool = False

    # Journal mutations J1, J2, J3, O, and D have distinct DB and authority
    # anchor heads.  A live method may briefly have db_stage = anchor_stage + 1.
    db_stage: JournalStage = JournalStage.BASE_AUTHORITY
    anchor_stage: JournalStage = JournalStage.BASE_AUTHORITY

    # The current DB row is intentionally distinct from the last anchored J1
    # identity so the changed-request mutant cannot erase its prior evidence.
    request: Identity = Identity.NONE
    anchored_request: Identity = Identity.NONE
    request_bindings: frozenset[Identity] = frozenset()
    changed_rebind_pending: bool = False

    # `receipt` is the symbolic vault-retained identity; `journal_receipt` is
    # the independently persisted J2 row identity.
    receipt: Identity = Identity.NONE
    journal_receipt: Identity = Identity.NONE
    certificate: Identity = Identity.NONE
    # Vault retention, opaque response return, and publisher observation are
    # three distinct boundaries.  These are identities, never response bytes.
    released_response: Identity = Identity.NONE
    returned_response: Identity = Identity.NONE
    outbox_response: Identity = Identity.NONE
    published_response: Identity = Identity.NONE
    delivery_record: Identity = Identity.NONE
    raw_observed: bool = False

    crashed: bool = False
    ack_lost: Ack = Ack.NONE
    anchor_ahead_mismatch: bool = False
    fail_closed: bool = False

    @property
    def pending_anchor(self) -> bool:
        return (
            (
                self.nonce_commit_statement is not Identity.NONE
                and not self.nonce_commit_statement_anchored
            )
            or (
                self.operation_authorization is not Identity.NONE
                and not self.operation_authorization_anchored
            )
            or self.changed_rebind_pending
            or self.db_stage > self.anchor_stage
        )

    @property
    def delivered(self) -> bool:
        return self.anchor_stage >= JournalStage.DELIVERY


INITIAL_STATE = State()


class Transition(NamedTuple):
    action: str
    state: State


class Violation(NamedTuple):
    invariant: str
    detail: str


@dataclass(frozen=True)
class Counterexample:
    violations: tuple[Violation, ...]
    trace: tuple[str, ...]
    state: State

    @property
    def violation(self) -> Violation:
        """Compatibility accessor for the first invariant in model order."""

        return self.violations[0]


@dataclass(frozen=True)
class Exploration:
    states: frozenset[State]
    edges: int
    successful_states: int


def _milestone(state: State) -> Ack:
    if state.anchor_stage >= JournalStage.DELIVERY:
        return Ack.DELIVERY
    if state.raw_observed:
        return Ack.PUBLISH
    if state.anchor_stage >= JournalStage.OUTBOX:
        return Ack.OUTBOX
    if state.returned_response is not Identity.NONE:
        return Ack.RESPONSE_RETURN
    if state.vault is VaultState.RELEASED:
        return Ack.RELEASE_PERSISTENCE
    if state.anchor_stage >= JournalStage.RELEASE_CERTIFICATE:
        return Ack.RELEASE_CERTIFICATE
    if state.anchor_stage >= JournalStage.SEALED_RECEIPT:
        return Ack.SEALED_RECEIPT
    if state.vault is VaultState.SEALED:
        return Ack.SEALED_RESPONSE
    if state.anchor_stage >= JournalStage.PRODUCE_REQUEST:
        return Ack.PRODUCE_REQUEST
    if state.operation_authorization_anchored:
        return Ack.OPERATION_AUTHORIZATION
    if state.commitment_observed:
        return Ack.COMMITMENT
    if state.nonce_commit_statement_anchored:
        return Ack.NONCE_COMMIT_STATEMENT
    return Ack.NONE


def _replace(state: State, action: str, **changes: object) -> Transition:
    return Transition(action, replace(state, **changes))


def transitions(state: State, defects: Defects = Defects()) -> tuple[Transition, ...]:
    """Return all bounded actions, including rejected changed-value stutters."""

    if state.fail_closed:
        return ()

    if state.crashed:
        if state.pending_anchor:
            return (
                _replace(
                    state,
                    "restart_detects_db_anchor_disagreement",
                    crashed=False,
                    fail_closed=True,
                ),
            )
        return (_replace(state, "restart_from_durable_state", crashed=False),)

    actions: list[Transition] = [_replace(state, "crash", crashed=True)]

    # The anchor-ahead flag is an explicit symbolic mismatch oracle.  Honest
    # detection records it and terminates; the mutant leaves it live.
    actions.append(
        _replace(
            state,
            "detect_anchor_ahead_disagreement",
            anchor_ahead_mismatch=True,
            fail_closed=True,
        )
    )
    if defects.ignore_anchor_ahead_mismatch:
        actions.append(
            _replace(
                state,
                "ignore_anchor_ahead_disagreement",
                anchor_ahead_mismatch=True,
            )
        )
    # Vault-checkpoint disagreement remains a direct detection oracle because
    # this model has no vault roots or authenticated historical proofs.
    actions.append(
        _replace(
            state,
            "detect_vault_checkpoint_disagreement",
            fail_closed=True,
        )
    )

    if state.ack_lost is not Ack.NONE:
        actions.append(_replace(state, "retry_exact_after_lost_ack", ack_lost=Ack.NONE))
        # A changed retry is rejected and leaves the durable identity intact.
        actions.append(Transition("reject_changed_retry_after_lost_ack", state))
        return tuple(actions)

    milestone = _milestone(state)
    if milestone is not Ack.NONE and not state.pending_anchor:
        actions.append(_replace(state, "lose_return_ack", ack_lost=milestone))

    # Phase A: persist and authority-anchor the exact authenticated plan before
    # the commitment may cross the vault boundary.
    if state.nonce_commit_statement is Identity.NONE:
        actions.append(
            _replace(
                state,
                "persist_exact_nonce_commit_statement_db",
                nonce_commit_statement=Identity.EXACT,
            )
        )
        actions.append(Transition("reject_changed_nonce_commit_statement", state))
        if defects.skip_commit_authorization:
            actions.append(
                _replace(
                    state,
                    "observe_commitment_without_authorization",
                    commitment_observed=True,
                    vault=VaultState.COMMITTED,
                )
            )
        return tuple(actions)

    if not state.nonce_commit_statement_anchored:
        actions.append(
            _replace(
                state,
                "anchor_exact_nonce_commit_statement",
                nonce_commit_statement_anchored=True,
            )
        )
        if defects.skip_commit_authorization and not state.commitment_observed:
            actions.append(
                _replace(
                    state,
                    "observe_commitment_before_authorization_anchor",
                    commitment_observed=True,
                    vault=VaultState.COMMITTED,
                )
            )
        return tuple(actions)

    if not state.commitment_observed:
        actions.append(
            _replace(
                state,
                "observe_exact_fully_bound_commitment",
                commitment_observed=True,
                vault=VaultState.COMMITTED,
            )
        )
        return tuple(actions)

    # J0 follows the observed complete commitment set: persist the exact
    # operation-wide round-two statement vector, then anchor it.  J1 cannot be
    # reconstructed or accepted before this historical proof exists.
    if state.operation_authorization is Identity.NONE:
        actions.append(
            _replace(
                state,
                "persist_exact_operation_authorization_db",
                operation_authorization=Identity.EXACT,
            )
        )
        actions.append(Transition("reject_changed_operation_authorization", state))
        return tuple(actions)

    if not state.operation_authorization_anchored:
        actions.append(
            _replace(
                state,
                "anchor_exact_operation_authorization",
                operation_authorization_anchored=True,
            )
        )
        return tuple(actions)

    # A deliberately defective coordinator may try to rewrite the already
    # anchored semantic slot.  The rebind itself also has a DB/anchor window.
    if state.changed_rebind_pending:
        actions.append(
            _replace(
                state,
                "anchor_changed_request_rebind",
                anchored_request=Identity.CHANGED,
                request_bindings=state.request_bindings | {Identity.CHANGED},
                changed_rebind_pending=False,
            )
        )
        return tuple(actions)

    # Journal J1: exact produce request DB commit and authority anchor.
    if state.db_stage is JournalStage.BASE_AUTHORITY:
        actions.append(
            _replace(
                state,
                "persist_exact_produce_request_db",
                db_stage=JournalStage.PRODUCE_REQUEST,
                request=Identity.EXACT,
            )
        )
        actions.append(Transition("reject_changed_produce_request", state))
        return tuple(actions)

    if state.anchor_stage is JournalStage.BASE_AUTHORITY:
        if defects.seal_before_j1_anchor:
            actions.append(
                _replace(
                    state,
                    "vault_seal_before_j1_anchor",
                    vault=VaultState.SEALED,
                    receipt=Identity.EXACT,
                )
            )
        actions.append(
            _replace(
                state,
                "anchor_exact_produce_request",
                anchor_stage=JournalStage.PRODUCE_REQUEST,
                anchored_request=Identity.EXACT,
                request_bindings=frozenset({Identity.EXACT}),
            )
        )
        return tuple(actions)

    if (
        defects.changed_request_rebind
        and state.db_stage is JournalStage.PRODUCE_REQUEST
        and state.anchor_stage is JournalStage.PRODUCE_REQUEST
        and state.request is Identity.EXACT
        and state.vault is VaultState.COMMITTED
    ):
        actions.append(
            _replace(
                state,
                "persist_changed_request_rebind_db",
                request=Identity.CHANGED,
                changed_rebind_pending=True,
            )
        )

    # Vault S: exact retry is deterministic; a changed request is rejected.
    if state.vault is VaultState.COMMITTED:
        actions.append(
            _replace(
                state,
                "vault_seal_exact_response",
                vault=VaultState.SEALED,
                receipt=Identity.EXACT,
            )
        )
        actions.append(Transition("reject_changed_request_at_vault", state))
        if defects.persist_j2_before_seal:
            actions.append(
                _replace(
                    state,
                    "persist_j2_before_vault_seal_db",
                    db_stage=JournalStage.SEALED_RECEIPT,
                    journal_receipt=Identity.EXACT,
                )
            )
        return tuple(actions)

    # Journal J2: persist exact receipt, then anchor it.
    if state.db_stage is JournalStage.PRODUCE_REQUEST:
        actions.append(
            _replace(
                state,
                "persist_exact_sealed_receipt_db",
                db_stage=JournalStage.SEALED_RECEIPT,
                journal_receipt=Identity.EXACT,
            )
        )
        actions.append(Transition("reject_changed_sealed_receipt", state))
        return tuple(actions)

    if state.anchor_stage is JournalStage.PRODUCE_REQUEST:
        if defects.certificate_before_receipt_anchor:
            actions.append(
                _replace(
                    state,
                    "issue_certificate_before_receipt_anchor_db",
                    db_stage=JournalStage.RELEASE_CERTIFICATE,
                    certificate=Identity.EXACT,
                )
            )
        actions.append(
            _replace(
                state,
                "anchor_exact_sealed_receipt",
                anchor_stage=JournalStage.SEALED_RECEIPT,
            )
        )
        return tuple(actions)

    # Journal J3: the certificate references J2, never its own state root.
    if state.db_stage is JournalStage.SEALED_RECEIPT:
        actions.append(
            _replace(
                state,
                "persist_exact_release_certificate_db",
                db_stage=JournalStage.RELEASE_CERTIFICATE,
                certificate=Identity.EXACT,
            )
        )
        actions.append(Transition("reject_changed_release_certificate", state))
        if defects.changed_certificate_persistence:
            actions.append(
                _replace(
                    state,
                    "persist_changed_release_certificate_db",
                    db_stage=JournalStage.RELEASE_CERTIFICATE,
                    certificate=Identity.CHANGED,
                )
            )
        return tuple(actions)

    if state.anchor_stage is JournalStage.SEALED_RECEIPT:
        if defects.release_before_j3_anchor:
            actions.append(
                _replace(
                    state,
                    "vault_persist_release_before_j3_anchor",
                    vault=VaultState.RELEASED,
                    released_response=Identity.EXACT,
                )
            )
        if defects.outbox_before_j3_anchor:
            actions.append(
                _replace(
                    state,
                    "persist_outbox_before_j3_anchor_db",
                    db_stage=JournalStage.OUTBOX,
                    outbox_response=Identity.EXACT,
                )
            )
        actions.append(
            _replace(
                state,
                "anchor_exact_release_certificate",
                anchor_stage=JournalStage.RELEASE_CERTIFICATE,
            )
        )
        return tuple(actions)

    # The early-raw mutant bypasses the release-persistence gate but does not
    # alter any stored response identity.
    if (
        defects.raw_before_release
        and state.vault is VaultState.SEALED
        and state.anchor_stage >= JournalStage.RELEASE_CERTIFICATE
        and not state.raw_observed
    ):
        actions.append(
            _replace(
                state,
                "observe_raw_response_before_vault_release",
                raw_observed=True,
                published_response=Identity.EXACT,
            )
        )

    if (
        defects.return_before_release
        and state.vault is VaultState.SEALED
        and state.anchor_stage >= JournalStage.RELEASE_CERTIFICATE
        and state.returned_response is Identity.NONE
    ):
        actions.append(
            _replace(
                state,
                "return_response_before_release_persistence",
                returned_response=Identity.EXACT,
            )
        )

    # Vault R persistence is distinct from returning the opaque response
    # capability.  A crash may occur between these two actions.
    if state.vault is VaultState.SEALED:
        actions.append(
            _replace(
                state,
                "vault_persist_exact_release",
                vault=VaultState.RELEASED,
                released_response=Identity.EXACT,
            )
        )
        actions.append(Transition("reject_changed_certificate_at_vault", state))
        return tuple(actions)

    if state.returned_response is Identity.NONE:
        actions.append(
            _replace(
                state,
                "return_exact_released_response",
                returned_response=Identity.EXACT,
            )
        )
        actions.append(Transition("reject_changed_response_return", state))
        return tuple(actions)

    # Journal O: opaque exact response-capability enqueue.  The mutant
    # represents the forbidden emit_round2-style caller byte slice.
    if state.db_stage is JournalStage.RELEASE_CERTIFICATE:
        actions.append(
            _replace(
                state,
                "enqueue_exact_typed_response_db",
                db_stage=JournalStage.OUTBOX,
                outbox_response=Identity.EXACT,
            )
        )
        actions.append(Transition("reject_changed_typed_response", state))
        if defects.caller_byte_injection:
            actions.append(
                _replace(
                    state,
                    "enqueue_caller_chosen_bytes_db",
                    db_stage=JournalStage.OUTBOX,
                    outbox_response=Identity.CALLER,
                )
            )
        return tuple(actions)

    if state.anchor_stage is JournalStage.RELEASE_CERTIFICATE:
        actions.append(
            _replace(
                state,
                "anchor_exact_outbox",
                anchor_stage=JournalStage.OUTBOX,
            )
        )
        return tuple(actions)

    # Publisher P obtains bytes only from the already anchored exact outbox.
    if not state.raw_observed:
        actions.append(
            _replace(
                state,
                "append_once_publish_exact_response",
                raw_observed=True,
                published_response=state.outbox_response,
            )
        )
        return tuple(actions)

    # Journal D: delivery DB commit and authority anchor remain distinct.
    if state.db_stage is JournalStage.OUTBOX:
        actions.append(
            _replace(
                state,
                "persist_delivery_marker_db",
                db_stage=JournalStage.DELIVERY,
                delivery_record=Identity.EXACT,
            )
        )
        if defects.changed_delivery_persistence:
            actions.append(
                _replace(
                    state,
                    "persist_changed_delivery_marker_db",
                    db_stage=JournalStage.DELIVERY,
                    delivery_record=Identity.CHANGED,
                )
            )
        return tuple(actions)

    if state.anchor_stage is JournalStage.OUTBOX:
        actions.append(
            _replace(
                state,
                "anchor_delivery_marker",
                anchor_stage=JournalStage.DELIVERY,
            )
        )
        return tuple(actions)

    # Fully delivered exact retries and crashes are represented by the generic
    # lost-ack and crash transitions above.
    return tuple(actions)


def invariant_violations(state: State) -> tuple[Violation, ...]:
    violations: list[Violation] = []

    if state.commitment_observed and not (
        state.nonce_commit_statement is Identity.EXACT
        and state.nonce_commit_statement_anchored
    ):
        violations.append(
            Violation(
                "CommitmentRequiresAnchoredAuthorization",
                "commitment crossed the boundary before the exact authenticated "
                "plan authorization was authority-anchored",
            )
        )

    if state.db_stage >= JournalStage.PRODUCE_REQUEST and not (
        state.operation_authorization is Identity.EXACT
        and state.operation_authorization_anchored
    ):
        violations.append(
            Violation(
                "ProduceRequestRequiresOperationAuthorization",
                "J1 exists before the exact commitment-dependent J0 proof is anchored",
            )
        )

    if state.operation_authorization is not Identity.NONE and not (
        state.commitment_observed
        and state.nonce_commit_statement is Identity.EXACT
        and state.nonce_commit_statement_anchored
    ):
        violations.append(
            Violation(
                "OperationAuthorizationRequiresCommitment",
                "commitment-dependent J0 exists before exact Jc and C",
            )
        )

    if (
        state.db_stage >= JournalStage.PRODUCE_REQUEST
        and state.request is not Identity.EXACT
    ):
        violations.append(
            Violation(
                "J1DatabaseRequiresExactRequest",
                "the J1-or-later DB projection does not retain the exact request",
            )
        )

    if state.anchor_stage >= JournalStage.PRODUCE_REQUEST and not (
        state.anchored_request is Identity.EXACT
        and Identity.EXACT in state.request_bindings
    ):
        violations.append(
            Violation(
                "AnchoredJ1RequiresExactRequest",
                "the J1-or-later anchor does not retain the exact request identity",
            )
        )

    if state.vault >= VaultState.SEALED and not (
        state.anchor_stage >= JournalStage.PRODUCE_REQUEST
        and state.request is Identity.EXACT
        and state.anchored_request is Identity.EXACT
        and Identity.EXACT in state.request_bindings
    ):
        violations.append(
            Violation(
                "SealedRequiresAnchoredExactJ1",
                "vault sealing occurred before exact J1 persistence and anchoring",
            )
        )

    if state.db_stage >= JournalStage.SEALED_RECEIPT and not (
        state.vault >= VaultState.SEALED
        and state.receipt is Identity.EXACT
        and state.journal_receipt is Identity.EXACT
    ):
        violations.append(
            Violation(
                "J2RequiresSealedExactReceipt",
                "J2-or-later exists without the sealed exact vault and journal receipt",
            )
        )

    if (
        not state.request_bindings.issubset({Identity.EXACT})
        or len(state.request_bindings) > 1
        or state.anchored_request not in {Identity.NONE, Identity.EXACT}
    ):
        violations.append(
            Violation(
                "SingleExactRequestBinding",
                "one semantic nonce slot retained or selected a changed request",
            )
        )

    if state.certificate is not Identity.NONE and not (
        state.journal_receipt is Identity.EXACT
        and state.anchor_stage >= JournalStage.SEALED_RECEIPT
    ):
        violations.append(
            Violation(
                "CertificateRequiresAnchoredReceipt",
                "certificate exists before the exact receipt checkpoint is anchored",
            )
        )

    if (
        state.db_stage >= JournalStage.RELEASE_CERTIFICATE
        and state.certificate is not Identity.EXACT
    ):
        violations.append(
            Violation(
                "J3DatabaseRequiresExactCertificate",
                "the J3-or-later DB projection does not retain the exact certificate",
            )
        )

    if state.vault is VaultState.RELEASED and not (
        state.certificate is Identity.EXACT
        and state.released_response is Identity.EXACT
        and state.anchor_stage >= JournalStage.RELEASE_CERTIFICATE
    ):
        violations.append(
            Violation(
                "ReleasedRequiresAnchoredExactJ3",
                "durable release occurred without anchored J3 and exact identities",
            )
        )

    if state.returned_response is not Identity.NONE and not (
        state.returned_response is Identity.EXACT
        and state.vault is VaultState.RELEASED
        and state.released_response is Identity.EXACT
        and state.anchor_stage >= JournalStage.RELEASE_CERTIFICATE
    ):
        violations.append(
            Violation(
                "ResponseReturnRequiresPersistedRelease",
                "a response identity crossed the vault boundary before exact release",
            )
        )

    if (
        state.db_stage >= JournalStage.OUTBOX
        or state.outbox_response is not Identity.NONE
    ) and state.anchor_stage < JournalStage.RELEASE_CERTIFICATE:
        violations.append(
            Violation(
                "OutboxRequiresAnchoredJ3",
                "outbox state exists before the exact J3 checkpoint is anchored",
            )
        )

    if state.db_stage >= JournalStage.OUTBOX and not (
        state.outbox_response is Identity.EXACT
        and state.returned_response is Identity.EXACT
        and state.vault is VaultState.RELEASED
        and state.released_response is Identity.EXACT
        and state.certificate is Identity.EXACT
    ):
        violations.append(
            Violation(
                "OutboxDatabaseRequiresExactReturnedResponse",
                "O-or-later does not retain the exact response returned by the vault",
            )
        )

    if state.raw_observed and not (
        state.vault is VaultState.RELEASED
        and state.released_response is Identity.EXACT
        and state.returned_response is Identity.EXACT
        and state.anchor_stage >= JournalStage.RELEASE_CERTIFICATE
    ):
        violations.append(
            Violation(
                "RawObservationRequiresPersistedRelease",
                "raw response became observable before the exact release persisted",
            )
        )

    if state.published_response is not Identity.NONE and not (
        state.published_response is Identity.EXACT
        and state.outbox_response is Identity.EXACT
        and state.anchor_stage >= JournalStage.OUTBOX
    ):
        violations.append(
            Violation(
                "PublisherRequiresAnchoredExactOutbox",
                "publisher observed a response without the anchored exact outbox",
            )
        )

    if state.db_stage >= JournalStage.DELIVERY and not (
        state.delivery_record is Identity.EXACT
        and state.raw_observed
        and state.published_response is Identity.EXACT
        and state.outbox_response is Identity.EXACT
        and state.anchor_stage >= JournalStage.OUTBOX
    ):
        violations.append(
            Violation(
                "DeliveryDatabaseRequiresExactPublication",
                "D does not retain the exact anchored publication identity",
            )
        )

    if state.delivered and not (
        state.delivery_record is Identity.EXACT
        and state.raw_observed
        and state.published_response is Identity.EXACT
        and state.anchor_stage >= JournalStage.OUTBOX
    ):
        violations.append(
            Violation(
                "DeliveryRequiresExactPublication",
                "delivery was anchored without exact append-once publication",
            )
        )

    if state.anchor_ahead_mismatch and not state.fail_closed:
        violations.append(
            Violation(
                "AnchorAheadMismatchMustFailClosed",
                "an explicit anchor-ahead mismatch remained live",
            )
        )

    if not state.fail_closed:
        if state.anchor_stage > state.db_stage:
            violations.append(
                Violation(
                    "AnchorNeverLeadsDatabase",
                    "authority anchor is ahead of the authenticated DB projection",
                )
            )
        if int(state.db_stage) - int(state.anchor_stage) > 1:
            violations.append(
                Violation(
                    "AtMostOneLiveUnanchoredMutation",
                    "a second DB mutation occurred before anchoring the first",
                )
            )

    return tuple(violations)


def _trace_to(
    state: State,
    predecessor: dict[State, tuple[State, str]],
) -> tuple[str, ...]:
    reversed_trace: list[str] = []
    cursor = state
    while cursor in predecessor:
        prior, action = predecessor[cursor]
        reversed_trace.append(action)
        cursor = prior
    return tuple(reversed(reversed_trace))


def explore(defects: Defects = Defects()) -> Exploration:
    """Exhaust the reachable bound and raise on the first safety violation."""

    queue = deque([INITIAL_STATE])
    seen = {INITIAL_STATE}
    edges = 0
    successful_states = 0

    while queue:
        state = queue.popleft()
        violations = invariant_violations(state)
        if violations:
            raise AssertionError(f"unsafe model state: {violations!r}\n{state!r}")
        if state.delivered and not state.fail_closed:
            successful_states += 1
        for transition in transitions(state, defects):
            edges += 1
            successor = transition.state
            violations = invariant_violations(successor)
            if violations:
                raise AssertionError(
                    f"unsafe transition {transition.action}: {violations!r}\n"
                    f"{successor!r}"
                )
            if successor not in seen:
                seen.add(successor)
                queue.append(successor)

    return Exploration(frozenset(seen), edges, successful_states)


def find_counterexample(defects: Defects) -> Counterexample | None:
    """Breadth-first search for the shortest invariant witness."""

    queue = deque([INITIAL_STATE])
    seen = {INITIAL_STATE}
    predecessor: dict[State, tuple[State, str]] = {}

    while queue:
        state = queue.popleft()
        for transition in transitions(state, defects):
            successor = transition.state
            if successor not in seen:
                predecessor[successor] = (state, transition.action)
            violations = invariant_violations(successor)
            if violations:
                trace = _trace_to(successor, predecessor)
                return Counterexample(violations, trace, successor)
            if successor not in seen:
                seen.add(successor)
                queue.append(successor)
    return None


def actions_from(state: State, defects: Defects = Defects()) -> set[str]:
    return {transition.action for transition in transitions(state, defects)}


def state_after(
    actions: Iterable[str],
    defects: Defects = Defects(),
    start: State = INITIAL_STATE,
) -> State:
    """Apply an unambiguous named trace, useful for focused unit tests."""

    state = start
    for expected_action in actions:
        matches = [
            transition
            for transition in transitions(state, defects)
            if transition.action == expected_action
        ]
        if len(matches) != 1:
            available = sorted(actions_from(state, defects))
            raise AssertionError(
                f"expected one {expected_action!r}, found {len(matches)}; "
                f"available={available!r}"
            )
        state = matches[0].state
    return state


HONEST_SUCCESS_TRACE = (
    "persist_exact_nonce_commit_statement_db",
    "anchor_exact_nonce_commit_statement",
    "observe_exact_fully_bound_commitment",
    "persist_exact_operation_authorization_db",
    "anchor_exact_operation_authorization",
    "persist_exact_produce_request_db",
    "anchor_exact_produce_request",
    "vault_seal_exact_response",
    "persist_exact_sealed_receipt_db",
    "anchor_exact_sealed_receipt",
    "persist_exact_release_certificate_db",
    "anchor_exact_release_certificate",
    "vault_persist_exact_release",
    "return_exact_released_response",
    "enqueue_exact_typed_response_db",
    "anchor_exact_outbox",
    "append_once_publish_exact_response",
    "persist_delivery_marker_db",
    "anchor_delivery_marker",
)
