from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Lock
import unittest
from uuid import UUID, uuid4

from alert2ir.application import (
    AlertOrchestrator,
    ExecutionAttemptState,
    IdempotencyConflictError,
    PersistenceUnavailableError,
    PersistentAlertProcessor,
    ProcessingState,
)
from alert2ir.application.fingerprinting import fingerprint_canonical_alert
from alert2ir.backends import (
    BackendRouter,
    BackendSubmissionRejectedError,
    BackendSubmissionUnknownError,
    InvestigationResult,
    OperationState,
    OperationStatus,
    SubmittedOperation,
)
from alert2ir.core import (
    BaselineSeverityPolicy,
    CanonicalAlert,
    DetectionIdentity,
    Entity,
    EvidenceReference,
    Incident,
    InvestigationRequest,
    Severity,
    SourceProvenance,
)
from alert2ir.persistence import InMemoryProcessingRepository


NOW = datetime(2026, 8, 17, 12, tzinfo=timezone.utc)


class MutableClock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class SequenceMonotonic:
    def __init__(self, *values: float) -> None:
        self._values = iter(values)
        self._last = values[-1]

    def __call__(self) -> float:
        try:
            self._last = next(self._values)
        except StopIteration:
            pass
        return self._last


class LifecycleBackend:
    name = "mock"
    capabilities = frozenset({"process.list"})

    def __init__(
        self,
        *,
        statuses: list[OperationStatus] | None = None,
        submit_error: Exception | None = None,
        poll_error: Exception | None = None,
        collect_error: Exception | None = None,
        on_submit=None,
        on_poll=None,
    ) -> None:
        self.statuses = statuses or [
            OperationStatus(OperationState.SUCCEEDED, "finished")
        ]
        self.submit_error = submit_error
        self.poll_error = poll_error
        self.collect_error = collect_error
        self.on_submit = on_submit
        self.on_poll = on_poll
        self.submit_calls = 0
        self.poll_calls: list[str] = []
        self.collect_calls: list[str] = []
        self.operation_keys = []
        self.submit_timeouts: list[float | None] = []
        self.poll_timeouts: list[float | None] = []
        self._lock = Lock()

    def submit(self, request, operation_key, *, timeout_seconds=None):
        with self._lock:
            self.submit_calls += 1
            self.operation_keys.append(operation_key)
            self.submit_timeouts.append(timeout_seconds)
        if self.on_submit is not None:
            self.on_submit(request, operation_key)
        if self.submit_error is not None:
            raise self.submit_error
        return SubmittedOperation("operation-1")

    def poll(self, request, external_operation_id, *, timeout_seconds=None):
        self.poll_calls.append(external_operation_id)
        self.poll_timeouts.append(timeout_seconds)
        if self.on_poll is not None:
            self.on_poll(request, external_operation_id)
        if self.poll_error is not None:
            raise self.poll_error
        return self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]

    def collect_result(self, request, external_operation_id):
        self.collect_calls.append(external_operation_id)
        if self.collect_error is not None:
            raise self.collect_error
        return InvestigationResult(
            self.name,
            request.required_capabilities,
            (EvidenceReference("result", "fake"),),
        )


def make_alert(
    severity: Severity = Severity.HIGH,
    *,
    identifier: str = "rule-42",
) -> CanonicalAlert:
    return CanonicalAlert(
        DetectionIdentity(identifier, "Synthetic activity"),
        NOW,
        SourceProvenance("synthetic", "alert-1"),
        (Entity("host", "workstation-7"),),
        severity,
        (EvidenceReference("record-1", None),),
    )


def make_request(incident: Incident) -> InvestigationRequest:
    return InvestigationRequest(
        incident,
        "collect process inventory",
        ("process.list",),
        incident.alert.entities,
    )


def make_processor(
    repository,
    backend,
    *,
    wall_clock=lambda: NOW,
    monotonic=None,
):
    orchestrator = AlertOrchestrator(
        BaselineSeverityPolicy(),
        BackendRouter((backend,)),
        make_request,
    )
    return PersistentAlertProcessor(
        orchestrator,
        repository,
        wall_clock=wall_clock,
        monotonic=monotonic,
    )


def accept_only(repository, alert=None, key="Key"):
    alert = alert or make_alert()
    version, digest = fingerprint_canonical_alert(alert)
    return repository.accept_processing(
        uuid4(), alert, alert.source.source, key, version, digest
    ).record


def plan_only(repository, backend, record):
    orchestrator = AlertOrchestrator(
        BaselineSeverityPolicy(), BackendRouter((backend,)), make_request
    )
    plan = orchestrator.plan(record.alert)
    return repository.store_plan(
        record.processing_id,
        plan.decision,
        plan.incident,
        plan.investigation_request,
        backend.name,
        uuid4(),
        uuid4(),
    )


class DurableExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = MutableClock()
        self.repository = InMemoryProcessingRepository(self.clock)

    def test_durable_identity_and_request_exist_before_submit(self) -> None:
        observed = {}

        def on_submit(_request, _operation_key):
            record = self.repository.get_by_idempotency("synthetic", "Key")
            observed["record"] = record

        backend = LifecycleBackend(on_submit=on_submit)
        outcome = make_processor(self.repository, backend).process(make_alert(), "Key")

        durable = observed["record"]
        self.assertEqual(durable.processing_id, outcome.record.processing_id)
        self.assertEqual(durable.alert, make_alert())
        self.assertEqual(durable.idempotency_scope, "synthetic")
        self.assertEqual(durable.idempotency_key, "Key")
        self.assertEqual(len(durable.request_fingerprint), 32)
        self.assertEqual(durable.state, ProcessingState.SUBMITTING)

    def test_operation_id_is_durable_before_first_poll(self) -> None:
        backend = LifecycleBackend()

        def on_poll(_request, external_id):
            attempt = self.repository.get_attempt_for_processing(
                processing_id
            )
            self.assertEqual(attempt.state, ExecutionAttemptState.SUBMITTED)
            self.assertEqual(attempt.external_operation_id, external_id)

        backend.on_poll = on_poll
        processor = make_processor(self.repository, backend)
        original_submit = backend.submit

        def submit(request, operation_key):
            nonlocal processing_id
            result = original_submit(request, operation_key)
            processing_id = self.repository.get_by_idempotency(
                "synthetic", "Key"
            ).processing_id
            return result

        processing_id = UUID(int=0)
        backend.submit = submit
        outcome = processor.process(make_alert(), "Key")
        self.assertEqual(outcome.record.state, ProcessingState.COMPLETED)

    def test_completed_replay_and_lost_ack_do_not_submit_again(self) -> None:
        backend = LifecycleBackend()
        processor = make_processor(self.repository, backend)
        first = processor.process(make_alert(), "Key")
        replay = processor.process(make_alert(), "Key")
        self.assertEqual(first.record.processing_id, replay.record.processing_id)
        self.assertEqual(first.record.result, replay.record.result)
        self.assertTrue(replay.replayed)
        self.assertEqual(backend.submit_calls, 1)

    def test_active_replay_does_not_submit_or_poll_again(self) -> None:
        backend = LifecycleBackend(
            statuses=[OperationStatus(OperationState.NONTERMINAL, "running")]
        )
        processor = make_processor(self.repository, backend)
        first = processor.process(make_alert(), "Key")
        replay = processor.process(make_alert(), "Key")
        self.assertEqual(first.record.state, ProcessingState.SUBMITTED)
        self.assertEqual(replay.record.processing_id, first.record.processing_id)
        self.assertEqual(backend.submit_calls, 1)
        self.assertEqual(backend.poll_calls, ["operation-1"])

    def test_same_key_different_fingerprint_conflicts_without_attempt(self) -> None:
        backend = LifecycleBackend()
        processor = make_processor(self.repository, backend)
        processor.process(make_alert(Severity.LOW), "Key")
        with self.assertRaises(IdempotencyConflictError):
            processor.process(make_alert(Severity.LOW, identifier="other"), "Key")
        self.assertEqual(backend.submit_calls, 0)

    def test_concurrent_duplicates_create_one_processing_and_one_submission(self) -> None:
        backend = LifecycleBackend()
        processor = make_processor(self.repository, backend)
        with ThreadPoolExecutor(max_workers=8) as executor:
            outcomes = list(
                executor.map(lambda _: processor.process(make_alert(), "Key"), range(8))
            )
        self.assertEqual(len({item.record.processing_id for item in outcomes}), 1)
        self.assertEqual(backend.submit_calls, 1)
        record = outcomes[0].record
        self.assertEqual(
            self.repository.get_attempt_for_processing(record.processing_id).attempt_number,
            1,
        )

    def test_definitive_submission_rejection_is_durable_and_replayed(self) -> None:
        backend = LifecycleBackend(
            submit_error=BackendSubmissionRejectedError("definitive")
        )
        processor = make_processor(self.repository, backend)
        first = processor.process(make_alert(), "Key")
        replay = processor.process(make_alert(), "Key")
        self.assertEqual(first.record.state, ProcessingState.FAILED)
        self.assertEqual(first.record.error_category, "backend_submission_failed")
        self.assertEqual(replay.record, first.record)
        self.assertEqual(backend.submit_calls, 1)

    def test_unknown_submission_becomes_recovery_required_and_never_resubmits(self) -> None:
        backend = LifecycleBackend(
            submit_error=BackendSubmissionUnknownError("response lost")
        )
        processor = make_processor(self.repository, backend)
        first = processor.process(make_alert(), "Key")
        replay = processor.process(make_alert(), "Key")
        report = processor.reconcile_once()
        self.assertEqual(first.record.state, ProcessingState.RECOVERY_REQUIRED)
        self.assertEqual(first.record.error_category, "backend_submission_unknown")
        self.assertEqual(replay.record.state, ProcessingState.RECOVERY_REQUIRED)
        self.assertEqual(backend.submit_calls, 1)
        self.assertEqual(report.examined, 0)

    def test_operation_id_persistence_failure_requires_recovery_without_resubmit(self) -> None:
        class OperationIdFailureRepository(InMemoryProcessingRepository):
            def mark_attempt_submitted(self, attempt_id, external_operation_id):
                raise RuntimeError("synthetic commit failure")

        repository = OperationIdFailureRepository(self.clock)
        backend = LifecycleBackend()
        processor = make_processor(repository, backend)
        with self.assertRaises(PersistenceUnavailableError):
            processor.process(make_alert(), "Key")
        durable = repository.get_by_idempotency("synthetic", "Key")
        self.assertEqual(durable.state, ProcessingState.RECOVERY_REQUIRED)
        self.assertEqual(durable.error_category, "backend_submission_unknown")

        replay = processor.process(make_alert(), "Key")
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.record.state, ProcessingState.RECOVERY_REQUIRED)
        self.assertEqual(backend.submit_calls, 1)

    def test_known_operation_timeout_remains_submitted(self) -> None:
        backend = LifecycleBackend(poll_error=TimeoutError("deadline"))
        outcome = make_processor(self.repository, backend).process(make_alert(), "Key")
        attempt = self.repository.get_attempt_for_processing(
            outcome.record.processing_id
        )
        self.assertEqual(outcome.record.state, ProcessingState.SUBMITTED)
        self.assertEqual(outcome.record.error_category, "backend_timeout")
        self.assertEqual(attempt.external_operation_id, "operation-1")
        self.assertEqual(backend.submit_calls, 1)

    def test_terminal_remote_failure_is_durable(self) -> None:
        backend = LifecycleBackend(
            statuses=[OperationStatus(OperationState.FAILED, "error")]
        )
        outcome = make_processor(self.repository, backend).process(make_alert(), "Key")
        self.assertEqual(outcome.record.state, ProcessingState.FAILED)
        self.assertEqual(outcome.record.error_category, "backend_execution_failed")
        self.assertEqual(backend.collect_calls, [])

    def test_malformed_status_and_result_collection_are_conservative(self) -> None:
        class MalformedBackend(LifecycleBackend):
            def poll(self, request, external_operation_id, *, timeout_seconds=None):
                self.poll_calls.append(external_operation_id)
                self.poll_timeouts.append(timeout_seconds)
                return object()

        for backend in (
            MalformedBackend(),
            LifecycleBackend(collect_error=RuntimeError("malformed result")),
        ):
            with self.subTest(backend=type(backend).__name__):
                repository = InMemoryProcessingRepository(self.clock)
                outcome = make_processor(repository, backend).process(make_alert(), "Key")
                self.assertEqual(outcome.record.state, ProcessingState.RECOVERY_REQUIRED)
                self.assertEqual(outcome.record.error_category, "backend_protocol_error")
                self.assertEqual(backend.submit_calls, 1)


class ReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = MutableClock()
        self.repository = InMemoryProcessingRepository(self.clock)

    def test_accepted_and_planned_restart_resume_once(self) -> None:
        for initial in ("accepted", "planned"):
            with self.subTest(initial=initial):
                repository = InMemoryProcessingRepository(self.clock)
                backend = LifecycleBackend()
                record = accept_only(repository)
                if initial == "planned":
                    record = plan_only(repository, backend, record).record
                report = make_processor(repository, backend).reconcile_once()
                durable = repository.get(record.processing_id)
                self.assertEqual(durable.state, ProcessingState.COMPLETED)
                self.assertEqual(backend.submit_calls, 1)
                self.assertEqual(report.examined, 1)

    def test_stale_submitting_without_discovery_requires_recovery(self) -> None:
        backend = LifecycleBackend()
        record = accept_only(self.repository)
        planned = plan_only(self.repository, backend, record)
        self.repository.claim_attempt_for_submission(planned.attempt.attempt_id)
        self.clock.value = NOW + timedelta(minutes=10)
        processor = make_processor(
            self.repository,
            backend,
            wall_clock=self.clock,
        )
        report = processor.reconcile_once(stale_after=timedelta(minutes=5))
        durable = self.repository.get(record.processing_id)
        self.assertEqual(durable.state, ProcessingState.RECOVERY_REQUIRED)
        self.assertEqual(backend.submit_calls, 0)
        self.assertEqual(report.advanced, 1)

    def test_submitted_operation_survives_new_processor_without_resubmission(self) -> None:
        first_backend = LifecycleBackend(
            statuses=[OperationStatus(OperationState.NONTERMINAL, "running")]
        )
        first = make_processor(self.repository, first_backend).process(
            make_alert(), "Key"
        )
        self.assertEqual(first.record.state, ProcessingState.SUBMITTED)

        restarted_backend = LifecycleBackend()
        report = make_processor(self.repository, restarted_backend).reconcile_once()
        durable = self.repository.get(first.record.processing_id)
        self.assertEqual(durable.state, ProcessingState.COMPLETED)
        self.assertEqual(restarted_backend.submit_calls, 0)
        self.assertEqual(restarted_backend.poll_calls, ["operation-1"])
        self.assertEqual(restarted_backend.collect_calls, ["operation-1"])
        self.assertEqual(report.advanced, 1)

    def test_exhausted_reconciliation_budget_starts_no_work(self) -> None:
        backend = LifecycleBackend()
        record = accept_only(self.repository)
        processor = make_processor(
            self.repository,
            backend,
            monotonic=SequenceMonotonic(0.0, 1.0),
        )

        report = processor.reconcile_once(max_seconds=0.5)

        self.assertEqual(report.examined, 0)
        self.assertTrue(report.time_limit_reached)
        self.assertEqual(
            self.repository.get(record.processing_id).state,
            ProcessingState.ACCEPTED,
        )
        self.assertEqual(backend.submit_calls, 0)
        self.assertEqual(backend.poll_calls, [])

    def test_reconciliation_remaining_budget_reaches_submit_and_poll(self) -> None:
        backend = LifecycleBackend(
            statuses=[OperationStatus(OperationState.NONTERMINAL, "running")]
        )
        record = accept_only(self.repository)
        plan_only(self.repository, backend, record)
        processor = make_processor(
            self.repository,
            backend,
            monotonic=SequenceMonotonic(0.0, 0.1, 0.2, 0.3, 0.4, 0.5),
        )

        report = processor.reconcile_once(max_seconds=1.0)

        durable = self.repository.get(record.processing_id)
        self.assertEqual(durable.state, ProcessingState.SUBMITTED)
        self.assertEqual(report.examined, 1)
        self.assertEqual(backend.submit_timeouts, [0.7])
        self.assertEqual(backend.poll_timeouts, [0.6])

    def test_reconciliation_budget_poll_timeout_remains_submitted(self) -> None:
        first_backend = LifecycleBackend(
            statuses=[OperationStatus(OperationState.NONTERMINAL, "running")]
        )
        first = make_processor(self.repository, first_backend).process(
            make_alert(), "Key"
        )
        restarted_backend = LifecycleBackend(poll_error=TimeoutError("deadline"))
        processor = make_processor(
            self.repository,
            restarted_backend,
            monotonic=SequenceMonotonic(0.0, 0.1, 0.2, 0.3),
        )

        report = processor.reconcile_once(max_seconds=0.5)

        durable = self.repository.get(first.record.processing_id)
        self.assertEqual(durable.state, ProcessingState.SUBMITTED)
        self.assertEqual(durable.error_category, "backend_timeout")
        self.assertEqual(restarted_backend.submit_calls, 0)
        self.assertEqual(restarted_backend.poll_calls, ["operation-1"])
        self.assertEqual(restarted_backend.poll_timeouts, [0.3])
        self.assertEqual(report.failed, 0)

    def test_reconciliation_limit_is_enforced(self) -> None:
        backend = LifecycleBackend()
        for index in range(3):
            accept_only(self.repository, key=f"Key-{index}")
        report = make_processor(self.repository, backend).reconcile_once(limit=2)
        self.assertEqual(report.examined, 2)
        remaining = self.repository.find_reconcilable(
            limit=10,
            stale_submitting_before=NOW,
        )
        self.assertEqual(len(remaining), 1)


if __name__ == "__main__":
    unittest.main()
