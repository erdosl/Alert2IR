from datetime import datetime, timezone
import unittest
from uuid import UUID

from alert2ir.application import (
    IdempotencyConflictError,
    PersistenceUnavailableError,
    ProcessingState,
)
from alert2ir.core import Severity
from alert2ir.persistence import InMemoryProcessingRepository
from tests.test_durable_processing import LifecycleBackend, make_alert, make_processor


NOW = datetime(2026, 8, 17, tzinfo=timezone.utc)


class PersistentAlertProcessorTests(unittest.TestCase):
    def test_processing_id_is_allocated_before_acceptance_and_retained(self) -> None:
        expected = UUID("a05a2510-96aa-46d7-a183-51564784dc5f")
        repository = InMemoryProcessingRepository(lambda: NOW)
        processor = make_processor(repository, LifecycleBackend())
        processor._processing_id_factory = lambda: expected
        outcome = processor.process(make_alert(Severity.LOW), "Key")
        self.assertEqual(outcome.record.processing_id, expected)
        self.assertEqual(repository.get(expected), outcome.record)
        self.assertEqual(outcome.record.state, ProcessingState.COMPLETED)

    def test_acceptance_failure_prevents_all_backend_work(self) -> None:
        class FailingRepository:
            def accept_processing(self, *args, **kwargs):
                raise RuntimeError("database unavailable")

        backend = LifecycleBackend()
        processor = make_processor(FailingRepository(), backend)
        with self.assertRaises(PersistenceUnavailableError):
            processor.process(make_alert(), "Key")
        self.assertEqual(backend.submit_calls, 0)

    def test_fingerprint_conflict_does_not_change_original(self) -> None:
        repository = InMemoryProcessingRepository(lambda: NOW)
        backend = LifecycleBackend()
        processor = make_processor(repository, backend)
        original = processor.process(make_alert(Severity.LOW), "Key").record
        with self.assertRaises(IdempotencyConflictError):
            processor.process(
                make_alert(Severity.LOW, identifier="different"),
                "Key",
            )
        self.assertEqual(repository.get(original.processing_id), original)
        self.assertEqual(len(repository._records), 1)

    def test_replay_never_creates_a_second_attempt(self) -> None:
        repository = InMemoryProcessingRepository(lambda: NOW)
        backend = LifecycleBackend()
        processor = make_processor(repository, backend)
        first = processor.process(make_alert(), "Key")
        for _ in range(5):
            replay = processor.process(make_alert(), "Key")
            self.assertEqual(replay.record.processing_id, first.record.processing_id)
        self.assertEqual(len(repository._attempts), 1)
        self.assertEqual(backend.submit_calls, 1)


if __name__ == "__main__":
    unittest.main()
