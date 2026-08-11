from datetime import datetime, timezone
import unittest
from uuid import UUID

from alert2ir.application import (
    AlertOrchestrator,
    OrchestrationResult,
    ProcessingRecord,
    ProcessingRepository,
)
from alert2ir.backends import BackendRouter, MockBackend
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


PROCESSING_ID = UUID("d21c6356-09b6-4ed7-a6e1-97a9fc93f264")
CREATED_AT = datetime(2026, 8, 11, 12, 0, tzinfo=timezone.utc)


def make_alert(severity: Severity, identifier: str = "rule-42") -> CanonicalAlert:
    return CanonicalAlert(
        detection=DetectionIdentity(identifier, "Synthetic suspicious activity"),
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


def make_orchestrator() -> AlertOrchestrator:
    return AlertOrchestrator(
        policy=BaselineSeverityPolicy(),
        router=BackendRouter(
            (MockBackend("mock", frozenset({"process.list"})),)
        ),
        request_factory=make_request,
    )


class ProcessingRecordTests(unittest.TestCase):
    def test_naive_created_at_is_rejected(self) -> None:
        alert = make_alert(Severity.LOW)
        result = make_orchestrator().process(alert)

        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            ProcessingRecord(
                processing_id=PROCESSING_ID,
                created_at=datetime(2026, 8, 11, 12, 0),
                alert=alert,
                result=result,
            )

    def test_different_complete_alert_with_same_source_is_rejected(self) -> None:
        processed_alert = make_alert(Severity.HIGH, identifier="rule-42")
        supplied_alert = make_alert(Severity.HIGH, identifier="rule-99")
        self.assertEqual(processed_alert.source, supplied_alert.source)
        result = make_orchestrator().process(processed_alert)

        with self.assertRaisesRegex(ValueError, "incident alert must match"):
            ProcessingRecord(
                processing_id=PROCESSING_ID,
                created_at=CREATED_AT,
                alert=supplied_alert,
                result=result,
            )


class InMemoryProcessingRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository: ProcessingRepository = InMemoryProcessingRepository(
            lambda: CREATED_AT
        )
        self.orchestrator = make_orchestrator()

    def test_low_flow_retains_separate_complete_alert_and_storage_metadata(self) -> None:
        alert = make_alert(Severity.LOW)
        result = self.orchestrator.process(alert)

        saved = self.repository.save(PROCESSING_ID, alert, result)
        retrieved = self.repository.get(PROCESSING_ID)

        self.assertEqual(saved.processing_id, PROCESSING_ID)
        self.assertEqual(saved.created_at, CREATED_AT)
        self.assertEqual(saved.alert, alert)
        self.assertIsNone(saved.result.incident)
        self.assertEqual(retrieved, saved)
        self.assertEqual(retrieved.alert, alert)

    def test_high_flow_retains_complete_request_and_result_graph(self) -> None:
        alert = make_alert(Severity.HIGH)
        result = self.orchestrator.process(alert)

        saved = self.repository.save(PROCESSING_ID, alert, result)

        self.assertEqual(self.repository.get(PROCESSING_ID), saved)
        self.assertEqual(saved.result, result)
        self.assertEqual(saved.result.incident.alert, alert)
        self.assertEqual(saved.result.investigation_request, result.investigation_request)
        self.assertEqual(saved.result.investigation_result, result.investigation_result)

    def test_unknown_processing_id_returns_none(self) -> None:
        self.assertIsNone(
            self.repository.get(UUID("64a776fa-88c9-4149-9960-15bbb363381c"))
        )

    def test_existing_processing_id_is_not_overwritten(self) -> None:
        original_alert = make_alert(Severity.LOW)
        original_result = self.orchestrator.process(original_alert)
        original = self.repository.save(
            PROCESSING_ID,
            original_alert,
            original_result,
        )
        replacement_alert = make_alert(Severity.HIGH)
        replacement_result = self.orchestrator.process(replacement_alert)

        with self.assertRaisesRegex(ValueError, "already exists"):
            self.repository.save(
                PROCESSING_ID,
                replacement_alert,
                replacement_result,
            )

        self.assertEqual(self.repository.get(PROCESSING_ID), original)


if __name__ == "__main__":
    unittest.main()
