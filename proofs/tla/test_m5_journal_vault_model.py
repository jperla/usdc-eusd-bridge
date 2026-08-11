import unittest
from dataclasses import replace

from m5_journal_vault_model import (
    Ack,
    Defects,
    HONEST_SUCCESS_TRACE,
    INITIAL_STATE,
    Identity,
    JournalStage,
    VaultState,
    actions_from,
    explore,
    find_counterexample,
    invariant_violations,
    state_after,
    transitions,
)


class HonestModelTests(unittest.TestCase):
    def test_exhaustive_honest_model_is_safe(self) -> None:
        result = explore()
        # Freeze the bound.  Edges include explicit rejected-value stutters,
        # crash/restart, lost-ack/retry, and fail-closed detection branches.
        self.assertEqual(len(result.states), 128)
        self.assertEqual(result.edges, 192)
        self.assertEqual(result.successful_states, 4)

    def test_complete_happens_before_trace_reaches_delivery(self) -> None:
        state = state_after(HONEST_SUCCESS_TRACE)
        self.assertTrue(state.delivered)
        self.assertEqual(state.vault, VaultState.RELEASED)
        self.assertEqual(state.published_response, Identity.EXACT)
        self.assertFalse(invariant_violations(state))

    def test_commitment_gate_has_distinct_db_and_anchor_steps(self) -> None:
        db_only = state_after(("persist_exact_nonce_commit_statement_db",))
        self.assertFalse(db_only.nonce_commit_statement_anchored)
        self.assertNotIn("observe_exact_fully_bound_commitment", actions_from(db_only))
        anchored = state_after(
            (
                "persist_exact_nonce_commit_statement_db",
                "anchor_exact_nonce_commit_statement",
            )
        )
        self.assertIn("observe_exact_fully_bound_commitment", actions_from(anchored))

    def test_j0_follows_commitment_and_precedes_j1(self) -> None:
        commitment = state_after(HONEST_SUCCESS_TRACE[:3])
        self.assertIn(
            "persist_exact_operation_authorization_db",
            actions_from(commitment),
        )
        j0_db_only = state_after(HONEST_SUCCESS_TRACE[:4])
        self.assertNotIn("persist_exact_produce_request_db", actions_from(j0_db_only))
        j0_anchored = state_after(HONEST_SUCCESS_TRACE[:5])
        self.assertIn("persist_exact_produce_request_db", actions_from(j0_anchored))

    def test_each_journal_write_has_a_distinct_unanchored_state(self) -> None:
        state = INITIAL_STATE
        for action in HONEST_SUCCESS_TRACE:
            state = state_after(
                HONEST_SUCCESS_TRACE[: HONEST_SUCCESS_TRACE.index(action) + 1]
            )
            if action.startswith("persist_") or action.startswith("enqueue_"):
                if action not in {
                    "persist_exact_nonce_commit_statement_db",
                    "persist_exact_operation_authorization_db",
                }:
                    self.assertGreater(state.db_stage, state.anchor_stage)

    def test_changed_objects_are_rejected_without_mutation(self) -> None:
        phases = (
            ((), "reject_changed_nonce_commit_statement"),
            (
                HONEST_SUCCESS_TRACE[:3],
                "reject_changed_operation_authorization",
            ),
            (
                HONEST_SUCCESS_TRACE[:5],
                "reject_changed_produce_request",
            ),
            (
                HONEST_SUCCESS_TRACE[:7],
                "reject_changed_request_at_vault",
            ),
            (
                HONEST_SUCCESS_TRACE[:8],
                "reject_changed_sealed_receipt",
            ),
            (
                HONEST_SUCCESS_TRACE[:10],
                "reject_changed_release_certificate",
            ),
            (
                HONEST_SUCCESS_TRACE[:12],
                "reject_changed_certificate_at_vault",
            ),
            (
                HONEST_SUCCESS_TRACE[:13],
                "reject_changed_response_return",
            ),
            (
                HONEST_SUCCESS_TRACE[:14],
                "reject_changed_typed_response",
            ),
        )
        for prefix, rejection in phases:
            with self.subTest(rejection=rejection):
                state = state_after(prefix)
                matches = [
                    transition
                    for transition in transitions(state)
                    if transition.action == rejection
                ]
                self.assertEqual(len(matches), 1)
                self.assertEqual(matches[0].state, state)

    def test_lost_ack_exact_retry_preserves_all_identities(self) -> None:
        state = state_after(HONEST_SUCCESS_TRACE[:16])
        lose_ack = next(
            transition
            for transition in transitions(state)
            if transition.action == "lose_return_ack"
        ).state
        self.assertEqual(lose_ack.ack_lost, Ack.OUTBOX)
        changed = next(
            transition
            for transition in transitions(lose_ack)
            if transition.action == "reject_changed_retry_after_lost_ack"
        ).state
        self.assertEqual(changed, lose_ack)
        retried = next(
            transition
            for transition in transitions(lose_ack)
            if transition.action == "retry_exact_after_lost_ack"
        ).state
        self.assertEqual(retried, state)

    def test_restart_of_stable_orphan_sealed_state_converges(self) -> None:
        sealed = state_after(HONEST_SUCCESS_TRACE[:8])
        crashed = replace(sealed, crashed=True)
        restarted = next(iter(transitions(crashed))).state
        self.assertEqual(restarted, sealed)
        recovered = state_after(HONEST_SUCCESS_TRACE[8:], start=restarted)
        self.assertTrue(recovered.delivered)

    def test_crash_after_release_persistence_before_return_converges(self) -> None:
        released = state_after(HONEST_SUCCESS_TRACE[:13])
        self.assertEqual(released.vault, VaultState.RELEASED)
        self.assertEqual(released.returned_response, Identity.NONE)
        self.assertFalse(released.raw_observed)
        crashed = replace(released, crashed=True)
        restarted = next(iter(transitions(crashed))).state
        self.assertEqual(restarted, released)
        self.assertEqual(restarted.released_response, Identity.EXACT)
        returned = state_after(
            ("return_exact_released_response",),
            start=restarted,
        )
        self.assertEqual(returned.returned_response, Identity.EXACT)
        self.assertFalse(returned.raw_observed)
        recovered = state_after(HONEST_SUCCESS_TRACE[13:], start=restarted)
        self.assertTrue(recovered.delivered)

    def test_release_return_and_publisher_observation_are_distinct(self) -> None:
        persisted = state_after(HONEST_SUCCESS_TRACE[:13])
        returned = state_after(HONEST_SUCCESS_TRACE[:14])
        published = state_after(HONEST_SUCCESS_TRACE[:17])
        self.assertEqual(persisted.returned_response, Identity.NONE)
        self.assertEqual(returned.returned_response, Identity.EXACT)
        self.assertFalse(returned.raw_observed)
        self.assertEqual(returned.outbox_response, Identity.NONE)
        self.assertTrue(published.raw_observed)
        self.assertEqual(published.published_response, Identity.EXACT)

    def test_crash_with_db_ahead_of_anchor_fails_closed(self) -> None:
        db_ahead = state_after(HONEST_SUCCESS_TRACE[:9])
        self.assertEqual(db_ahead.db_stage, JournalStage.SEALED_RECEIPT)
        self.assertEqual(db_ahead.anchor_stage, JournalStage.PRODUCE_REQUEST)
        crashed = replace(db_ahead, crashed=True)
        restarted = next(iter(transitions(crashed))).state
        self.assertTrue(restarted.fail_closed)
        self.assertEqual(transitions(restarted), ())

    def test_detected_anchor_or_vault_disagreement_has_no_repair_edge(self) -> None:
        for action in (
            "detect_anchor_ahead_disagreement",
            "detect_vault_checkpoint_disagreement",
        ):
            with self.subTest(action=action):
                failed = next(
                    transition.state
                    for transition in transitions(INITIAL_STATE)
                    if transition.action == action
                )
                self.assertTrue(failed.fail_closed)
                if action == "detect_anchor_ahead_disagreement":
                    self.assertTrue(failed.anchor_ahead_mismatch)
                self.assertEqual(transitions(failed), ())

    def test_honest_api_has_no_caller_byte_transition(self) -> None:
        state = state_after(HONEST_SUCCESS_TRACE[:14])
        self.assertNotIn("enqueue_caller_chosen_bytes_db", actions_from(state))


class MutantWitnessTests(unittest.TestCase):
    CASES = (
        (
            Defects(skip_commit_authorization=True),
            frozenset({"CommitmentRequiresAnchoredAuthorization"}),
            ("observe_commitment_without_authorization",),
        ),
        (
            Defects(certificate_before_receipt_anchor=True),
            frozenset(
                {
                    "CertificateRequiresAnchoredReceipt",
                    "AtMostOneLiveUnanchoredMutation",
                }
            ),
            HONEST_SUCCESS_TRACE[:9] + ("issue_certificate_before_receipt_anchor_db",),
        ),
        (
            Defects(raw_before_release=True),
            frozenset(
                {
                    "RawObservationRequiresPersistedRelease",
                    "PublisherRequiresAnchoredExactOutbox",
                }
            ),
            HONEST_SUCCESS_TRACE[:12] + ("observe_raw_response_before_vault_release",),
        ),
        (
            Defects(return_before_release=True),
            frozenset({"ResponseReturnRequiresPersistedRelease"}),
            HONEST_SUCCESS_TRACE[:12] + ("return_response_before_release_persistence",),
        ),
        (
            Defects(changed_request_rebind=True),
            frozenset({"J1DatabaseRequiresExactRequest"}),
            HONEST_SUCCESS_TRACE[:7] + ("persist_changed_request_rebind_db",),
        ),
        (
            Defects(caller_byte_injection=True),
            frozenset({"OutboxDatabaseRequiresExactReturnedResponse"}),
            HONEST_SUCCESS_TRACE[:14] + ("enqueue_caller_chosen_bytes_db",),
        ),
        (
            Defects(seal_before_j1_anchor=True),
            frozenset({"SealedRequiresAnchoredExactJ1"}),
            HONEST_SUCCESS_TRACE[:6] + ("vault_seal_before_j1_anchor",),
        ),
        (
            Defects(persist_j2_before_seal=True),
            frozenset({"J2RequiresSealedExactReceipt"}),
            HONEST_SUCCESS_TRACE[:7] + ("persist_j2_before_vault_seal_db",),
        ),
        (
            Defects(release_before_j3_anchor=True),
            frozenset({"ReleasedRequiresAnchoredExactJ3"}),
            HONEST_SUCCESS_TRACE[:11] + ("vault_persist_release_before_j3_anchor",),
        ),
        (
            Defects(outbox_before_j3_anchor=True),
            frozenset(
                {
                    "OutboxRequiresAnchoredJ3",
                    "OutboxDatabaseRequiresExactReturnedResponse",
                    "AtMostOneLiveUnanchoredMutation",
                }
            ),
            HONEST_SUCCESS_TRACE[:11] + ("persist_outbox_before_j3_anchor_db",),
        ),
        (
            Defects(changed_certificate_persistence=True),
            frozenset({"J3DatabaseRequiresExactCertificate"}),
            HONEST_SUCCESS_TRACE[:10] + ("persist_changed_release_certificate_db",),
        ),
        (
            Defects(changed_delivery_persistence=True),
            frozenset({"DeliveryDatabaseRequiresExactPublication"}),
            HONEST_SUCCESS_TRACE[:17] + ("persist_changed_delivery_marker_db",),
        ),
        (
            Defects(ignore_anchor_ahead_mismatch=True),
            frozenset({"AnchorAheadMismatchMustFailClosed"}),
            ("ignore_anchor_ahead_disagreement",),
        ),
    )

    def test_each_deliberate_defect_has_a_shortest_counterexample(self) -> None:
        for defects, expected_invariants, expected_trace in self.CASES:
            with self.subTest(invariants=sorted(expected_invariants)):
                witness = find_counterexample(defects)
                self.assertIsNotNone(witness)
                assert witness is not None
                actual_invariants = frozenset(
                    violation.invariant for violation in witness.violations
                )
                self.assertEqual(actual_invariants, expected_invariants)
                self.assertEqual(witness.trace, expected_trace)

    def test_changed_request_db_retains_prior_anchored_identity(self) -> None:
        witness = find_counterexample(Defects(changed_request_rebind=True))
        assert witness is not None
        self.assertEqual(witness.state.request, Identity.CHANGED)
        self.assertEqual(witness.state.anchored_request, Identity.EXACT)
        self.assertEqual(witness.state.request_bindings, {Identity.EXACT})
        self.assertTrue(witness.state.changed_rebind_pending)


if __name__ == "__main__":
    unittest.main()
