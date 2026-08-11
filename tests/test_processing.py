from datetime import datetime, timezone
import unittest
from uuid import UUID

from alert2ir.application import AlertOrchestrator, PersistentAlertProcessor
from alert2ir.backends import (
    BackendRouter,
    InvestigationResult,
    MockBackend,
    UnsupportedCapabilitiesError,
)
from alert2ir.core import (
    BaselineSeverityPolicy,
    CanonicalAlert,
    DecisionOutcome,
    DetectionIdentity,
    Entity,
    EvidenceReference,
    Incident,
    InvestigationRequest,
    Severity,
    SourceProvenance,
)
from alert2ir.persistence import InMemoryProcessingRepository


PROCESSING_ID_A = UUID("a05a2510-96aa-46d7-a183-51564784dc5f")
PROCESSING_ID_B = UUID("9cda1940-d1fc-4c17-802e-a0a3059a268d")
CREATED_AT = datetime(2026, 8, 11, 16, 0, tzinfo=timezone.utc)


def make_alert(severity: Severity) -> CanonicalAlert:
    return CanonicalAlert(
        detection=DetectionIdentity("rule-42", "Synthetic suspicious activity"),
        detected_at=datetime(2026, 8, 11, 9, 30, tzinfo=timezone.utc),
        source=SourceProvenance("synthetic", "alert-9001"),
        entities=(Entity("host", "workstation-7"),),
        severity=severity,
        evidence=(EvidenceReference("record-100", "synthetic-record"),),
    )


def make_request(incident: Incident) -> InvestigationRequest:
    return InvestigationRequest(
        incident=incident,
        desired_outcome="collect process inventory",
        required_capabilities=("process.list",),
        targets=incident.alert.entities,
    )


def make_orchestrator(backend=None) -> AlertOrchestrator:
    selected_backend = backend or MockBackend(
        "mock", frozenset({"process.list"})
    )
    return AlertOrchestrator(
        policy=BaselineSeverityPolicy(),
        router=BackendRouter((selected_backend,)),
        request_factory=make_request,
    )


class RecordingIdFactory:
    def __init__(self, values: tuple[UUID, ...], events=None) -> None:
        self._values = iter(values)
        self.calls = 0
        self.events = events

    def __call__(self) -> UUID:
        self.calls += 1
        if self.events is not None:
            self.events.append("uuid")
        return next(self._values)


class RecordingRepository:
    def __init__(self, events=None, error=None) -> None:
        self.events = events
        self.error = error
        self.calls = []

    def save(self, processing_id, alert, result):
        self.calls.append((processing_id, alert, result))
        if self.events is not None:
            self.events.append("save")
        if self.error is not None:
            raise self.error
        raise AssertionError("success is not expected from this test repository")

    def get(self, processing_id):
        raise AssertionError("get is not expected")


class PersistentAlertProcessorTests(unittest.TestCase):
    def test_no_action_success_is_persisted_with_complete_alert(self) -> None:
        alert = make_alert(Severity.LOW)
        repository = InMemoryProcessingRepository(lambda: CREATED_AT)
        processor = PersistentAlertProcessor(
            make_orchestrator(), repository, lambda: PROCESSING_ID_A
        )

        record = processor.process(alert)

        self.assertEqual(record.processing_id, PROCESSING_ID_A)
        self.assertEqual(record.created_at, CREATED_AT)
        self.assertEqual(record.alert, alert)
        self.assertEqual(record.result.decision.outcome, DecisionOutcome.NO_ACTION)
        self.assertEqual(repository.get(PROCESSING_ID_A), record)
        self.assertEqual(repository._records, {PROCESSING_ID_A: record})

    def test_investigate_success_persists_complete_result(self) -> None:
        alert = make_alert(Severity.HIGH)
        repository = InMemoryProcessingRepository(lambda: CREATED_AT)
        processor = PersistentAlertProcessor(
            make_orchestrator(), repository, lambda: PROCESSING_ID_A
        )

        record = processor.process(alert)

        self.assertEqual(record.result.decision.outcome, DecisionOutcome.INVESTIGATE)
        self.assertEqual(record.result.incident.alert, alert)
        self.assertEqual(
            record.result.investigation_request.required_capabilities,
            ("process.list",),
        )
        self.assertEqual(record.result.investigation_result.backend, "mock")
        self.assertEqual(
            record.result.investigation_result.evidence,
            (EvidenceReference("mock:process.list", "mock-result"),),
        )
        self.assertEqual(repository.get(PROCESSING_ID_A), record)
        self.assertEqual(repository._records, {PROCESSING_ID_A: record})

    def test_unsupported_routing_prevents_id_and_save(self) -> None:
        id_factory = RecordingIdFactory((PROCESSING_ID_A,))
        repository = RecordingRepository()
        orchestrator = AlertOrchestrator(
            policy=BaselineSeverityPolicy(),
            router=BackendRouter(()),
            request_factory=make_request,
        )
        processor = PersistentAlertProcessor(orchestrator, repository, id_factory)

        with self.assertRaises(UnsupportedCapabilitiesError):
            processor.process(make_alert(Severity.HIGH))

        self.assertEqual(id_factory.calls, 0)
        self.assertEqual(repository.calls, [])

    def test_backend_failure_prevents_id_and_save(self) -> None:
        backend_error = RuntimeError("distinctive backend failure")

        class FailingBackend:
            name = "failing"
            capabilities = frozenset({"process.list"})

            def investigate(self, request):
                raise backend_error

        id_factory = RecordingIdFactory((PROCESSING_ID_A,))
        repository = RecordingRepository()
        processor = PersistentAlertProcessor(
            make_orchestrator(FailingBackend()), repository, id_factory
        )

        with self.assertRaises(RuntimeError) as raised:
            processor.process(make_alert(Severity.HIGH))

        self.assertIs(raised.exception, backend_error)
        self.assertEqual(id_factory.calls, 0)
        self.assertEqual(repository.calls, [])

    def test_persistence_failure_propagates_after_ordered_completion(self) -> None:
        events = []
        persistence_error = RuntimeError("distinctive persistence failure")

        class RecordingBackend:
            name = "recording"
            capabilities = frozenset({"process.list"})

            def investigate(self, request):
                events.append("backend_complete")
                return InvestigationResult(
                    backend=self.name,
                    completed_capabilities=request.required_capabilities,
                    evidence=(),
                )

        id_factory = RecordingIdFactory((PROCESSING_ID_A,), events)
        repository = RecordingRepository(events, persistence_error)
        processor = PersistentAlertProcessor(
            make_orchestrator(RecordingBackend()), repository, id_factory
        )

        with self.assertRaises(RuntimeError) as raised:
            processor.process(make_alert(Severity.HIGH))

        self.assertIs(raised.exception, persistence_error)
        self.assertEqual(events, ["backend_complete", "uuid", "save"])
        self.assertEqual(id_factory.calls, 1)
        self.assertEqual(len(repository.calls), 1)

    def test_repeated_successes_receive_distinct_processing_ids(self) -> None:
        alert = make_alert(Severity.LOW)
        repository = InMemoryProcessingRepository(lambda: CREATED_AT)
        id_factory = RecordingIdFactory((PROCESSING_ID_A, PROCESSING_ID_B))
        processor = PersistentAlertProcessor(
            make_orchestrator(), repository, id_factory
        )

        first = processor.process(alert)
        second = processor.process(alert)

        self.assertNotEqual(first.processing_id, second.processing_id)
        self.assertEqual(repository.get(PROCESSING_ID_A), first)
        self.assertEqual(repository.get(PROCESSING_ID_B), second)
        self.assertEqual(id_factory.calls, 2)


if __name__ == "__main__":
    unittest.main()
