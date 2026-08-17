from datetime import datetime, timezone
import unittest
from uuid import UUID

from alert2ir.application import (
    ExecutionAttempt,
    ExecutionAttemptState,
    OrchestrationResult,
    ProcessingRecord,
    ProcessingState,
)
from alert2ir.application.persistence import (
    ALLOWED_PROCESSING_TRANSITIONS,
    processing_transition_allowed,
)
from alert2ir.core import (
    CanonicalAlert,
    Decision,
    DecisionOutcome,
    DetectionIdentity,
    Severity,
    SourceProvenance,
)


NOW = datetime(2026, 8, 17, tzinfo=timezone.utc)
PROCESSING_ID = UUID("10000000-0000-4000-8000-000000000001")
ATTEMPT_ID = UUID("20000000-0000-4000-8000-000000000001")
OPERATION_KEY = UUID("30000000-0000-4000-8000-000000000001")


def no_action_values():
    alert = CanonicalAlert(
        DetectionIdentity("rule"),
        NOW,
        SourceProvenance("source"),
        (),
        Severity.LOW,
        (),
    )
    decision = Decision(
        DecisionOutcome.NO_ACTION,
        "policy",
        ("reason",),
        alert.source,
    )
    return alert, OrchestrationResult(decision, None, None, None)


class ProcessingTransitionTests(unittest.TestCase):
    def test_every_declared_allowed_transition(self) -> None:
        expected = {
            ("accepted", "planned"),
            ("accepted", "completed"),
            ("accepted", "failed"),
            ("planned", "submitting"),
            ("planned", "failed"),
            ("submitting", "submitted"),
            ("submitting", "failed"),
            ("submitting", "recovery_required"),
            ("submitted", "submitted"),
            ("submitted", "completed"),
            ("submitted", "failed"),
            ("submitted", "recovery_required"),
            ("recovery_required", "submitted"),
            ("recovery_required", "failed"),
        }
        actual = {
            (source.value, target.value)
            for source, targets in ALLOWED_PROCESSING_TRANSITIONS.items()
            for target in targets
        }
        self.assertEqual(actual, expected)
        for source, target in expected:
            self.assertTrue(
                processing_transition_allowed(
                    ProcessingState(source), ProcessingState(target)
                )
            )

    def test_every_other_transition_is_forbidden(self) -> None:
        for source in ProcessingState:
            for target in ProcessingState:
                expected = target in ALLOWED_PROCESSING_TRANSITIONS[source]
                self.assertEqual(
                    processing_transition_allowed(source, target),
                    expected,
                    (source, target),
                )
        self.assertEqual(ALLOWED_PROCESSING_TRANSITIONS[ProcessingState.COMPLETED], set())
        self.assertEqual(ALLOWED_PROCESSING_TRANSITIONS[ProcessingState.FAILED], set())


class DurableRecordInvariantTests(unittest.TestCase):
    def test_accepted_requires_coherent_identity_and_fingerprint(self) -> None:
        alert, _ = no_action_values()
        record = ProcessingRecord(
            PROCESSING_ID,
            NOW,
            NOW,
            alert,
            ProcessingState.ACCEPTED,
            "source",
            "Key",
            1,
            b"x" * 32,
        )
        self.assertEqual(record.state, ProcessingState.ACCEPTED)
        self.assertEqual(record.fingerprint_version, 1)
        with self.assertRaisesRegex(ValueError, "exactly 32"):
            ProcessingRecord(
                PROCESSING_ID,
                NOW,
                NOW,
                alert,
                ProcessingState.ACCEPTED,
                "source",
                "Key",
                1,
                b"short",
            )
        with self.assertRaisesRegex(ValueError, "unsupported request fingerprint"):
            ProcessingRecord(
                PROCESSING_ID,
                NOW,
                NOW,
                alert,
                ProcessingState.ACCEPTED,
                "source",
                "Key",
                2,
                b"x" * 32,
            )

    def test_completed_state_cannot_exist_without_terminal_result(self) -> None:
        alert, result = no_action_values()
        with self.assertRaisesRegex(ValueError, "requires result"):
            ProcessingRecord(
                PROCESSING_ID,
                NOW,
                NOW,
                alert,
                ProcessingState.COMPLETED,
                completed_at=NOW,
            )
        record = ProcessingRecord(
            PROCESSING_ID,
            NOW,
            NOW,
            alert,
            ProcessingState.COMPLETED,
            completed_result=result,
            completed_at=NOW,
        )
        self.assertIs(record.result, result)

    def test_failed_state_requires_bounded_error_and_is_terminal(self) -> None:
        alert, _ = no_action_values()
        with self.assertRaisesRegex(ValueError, "requires failed_at"):
            ProcessingRecord(
                PROCESSING_ID,
                NOW,
                NOW,
                alert,
                ProcessingState.FAILED,
            )
        with self.assertRaisesRegex(ValueError, "1-256"):
            ProcessingRecord(
                PROCESSING_ID,
                NOW,
                NOW,
                alert,
                ProcessingState.FAILED,
                failed_at=NOW,
                error_category="x",
                error_detail="s" * 257,
            )

    def test_attempt_state_field_coherence(self) -> None:
        base = dict(
            attempt_id=ATTEMPT_ID,
            processing_id=PROCESSING_ID,
            attempt_number=1,
            operation_key=OPERATION_KEY,
            backend="mock",
            created_at=NOW,
        )
        ExecutionAttempt(state=ExecutionAttemptState.PLANNED, **base)
        with self.assertRaisesRegex(ValueError, "requires only a start time"):
            ExecutionAttempt(state=ExecutionAttemptState.SUBMITTING, **base)
        submitted = ExecutionAttempt(
            state=ExecutionAttemptState.SUBMITTED,
            started_at=NOW,
            submitted_at=NOW,
            external_operation_id="operation",
            **base,
        )
        self.assertEqual(submitted.external_operation_id, "operation")
        with self.assertRaisesRegex(ValueError, "missing required fields"):
            ExecutionAttempt(
                state=ExecutionAttemptState.COMPLETED,
                started_at=NOW,
                completed_at=NOW,
                **base,
            )


if __name__ == "__main__":
    unittest.main()
