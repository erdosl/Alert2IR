from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import unittest
from uuid import uuid4

from alert2ir.application import (
    ExecutionAttemptState,
    OrchestrationResult,
    ProcessingState,
)
from alert2ir.backends import InvestigationResult
from alert2ir.core import DecisionOutcome, EvidenceReference, Severity
from alert2ir.persistence import InMemoryProcessingRepository
from tests.test_durable_processing import (
    LifecycleBackend,
    MutableClock,
    NOW,
    accept_only,
    make_alert,
    plan_only,
)


class InMemoryDurableRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = MutableClock()
        self.repository = InMemoryProcessingRepository(self.clock)
        self.backend = LifecycleBackend()

    def test_idempotent_acceptance_uses_scope_and_key_uniqueness(self) -> None:
        first = accept_only(self.repository, key="Key")
        version = first.fingerprint_version
        digest = first.request_fingerprint
        replay = self.repository.accept_processing(
            uuid4(), first.alert, "synthetic", "Key", version, digest
        )
        self.assertFalse(replay.created)
        self.assertEqual(replay.record.processing_id, first.processing_id)
        self.assertEqual(len(self.repository._records), 1)

    def test_plan_and_attempt_one_are_created_atomically_once(self) -> None:
        accepted = accept_only(self.repository)
        first = plan_only(self.repository, self.backend, accepted)
        second = plan_only(self.repository, self.backend, accepted)
        self.assertIsNotNone(first)
        self.assertIsNone(second)
        self.assertEqual(first.record.state, ProcessingState.PLANNED)
        self.assertEqual(first.attempt.attempt_number, 1)
        self.assertEqual(len(self.repository._attempts), 1)

    def test_concurrent_execution_claim_has_one_winner(self) -> None:
        planned = plan_only(
            self.repository, self.backend, accept_only(self.repository)
        )
        with ThreadPoolExecutor(max_workers=8) as executor:
            claims = list(
                executor.map(
                    lambda _: self.repository.claim_attempt_for_submission(
                        planned.attempt.attempt_id
                    ),
                    range(8),
                )
            )
        winners = [claim for claim in claims if claim is not None]
        self.assertEqual(len(winners), 1)
        self.assertEqual(winners[0].state, ExecutionAttemptState.SUBMITTING)
        self.assertEqual(
            self.repository.get(planned.record.processing_id).state,
            ProcessingState.SUBMITTING,
        )

    def test_expected_state_cas_prevents_reentry(self) -> None:
        planned = plan_only(
            self.repository, self.backend, accept_only(self.repository)
        )
        claimed = self.repository.claim_attempt_for_submission(planned.attempt.attempt_id)
        submitted = self.repository.mark_attempt_submitted(
            claimed.attempt_id, "operation"
        )
        self.assertIsNone(
            self.repository.claim_attempt_for_submission(planned.attempt.attempt_id)
        )
        self.assertIsNone(
            self.repository.mark_attempt_submitted(claimed.attempt_id, "other")
        )
        self.assertEqual(submitted.external_operation_id, "operation")

    def test_completion_stores_attempt_and_public_result_atomically(self) -> None:
        planned = plan_only(
            self.repository, self.backend, accept_only(self.repository)
        )
        claimed = self.repository.claim_attempt_for_submission(planned.attempt.attempt_id)
        self.repository.mark_attempt_submitted(claimed.attempt_id, "operation")
        result = OrchestrationResult(
            planned.record.decision,
            planned.record.incident,
            planned.record.investigation_request,
            InvestigationResult(
                self.backend.name,
                ("process.list",),
                (EvidenceReference("result", None),),
            ),
        )
        completed = self.repository.complete_processing(claimed.attempt_id, result)
        self.assertEqual(completed.state, ProcessingState.COMPLETED)
        self.assertEqual(completed.result, result)
        self.assertEqual(
            self.repository.get_attempt(claimed.attempt_id).state,
            ExecutionAttemptState.COMPLETED,
        )
        self.assertIsNone(self.repository.complete_processing(claimed.attempt_id, result))

    def test_terminal_failure_is_atomic_and_cannot_reenter_active_execution(self) -> None:
        planned = plan_only(
            self.repository, self.backend, accept_only(self.repository)
        )
        failed = self.repository.fail_processing(
            planned.record.processing_id,
            frozenset({ProcessingState.PLANNED}),
            "backend_submission_failed",
            "definitive failure",
            planned.attempt.attempt_id,
        )
        self.assertEqual(failed.state, ProcessingState.FAILED)
        self.assertEqual(
            self.repository.get_attempt(planned.attempt.attempt_id).state,
            ExecutionAttemptState.FAILED,
        )
        self.assertIsNone(
            self.repository.claim_attempt_for_submission(planned.attempt.attempt_id)
        )

    def test_timeout_observation_keeps_known_operation_submitted(self) -> None:
        planned = plan_only(
            self.repository, self.backend, accept_only(self.repository)
        )
        claimed = self.repository.claim_attempt_for_submission(planned.attempt.attempt_id)
        self.repository.mark_attempt_submitted(claimed.attempt_id, "operation")
        self.repository.record_poll(
            claimed.attempt_id,
            "timeout",
            "backend_timeout",
            "known operation poll timed out",
        )
        record = self.repository.get(planned.record.processing_id)
        attempt = self.repository.get_attempt(claimed.attempt_id)
        self.assertEqual(record.state, ProcessingState.SUBMITTED)
        self.assertEqual(attempt.state, ExecutionAttemptState.SUBMITTED)
        self.assertEqual(attempt.external_operation_id, "operation")

    def test_reconcilable_query_is_ordered_bounded_and_stale_aware(self) -> None:
        accepted = accept_only(self.repository, make_alert(Severity.LOW), "accepted")
        planned = plan_only(
            self.repository,
            self.backend,
            accept_only(self.repository, key="submitting"),
        )
        self.repository.claim_attempt_for_submission(planned.attempt.attempt_id)
        early = self.repository.find_reconcilable(
            limit=10,
            stale_submitting_before=NOW - timedelta(seconds=1),
        )
        self.assertEqual([item.processing_id for item in early], [accepted.processing_id])
        late = self.repository.find_reconcilable(
            limit=1,
            stale_submitting_before=NOW,
        )
        self.assertEqual(len(late), 1)


if __name__ == "__main__":
    unittest.main()
