from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import subprocess
import sys
import unittest
from uuid import uuid4

import psycopg

from alert2ir.application import OrchestrationResult, ProcessingRepository
from alert2ir.backends import InvestigationResult
from alert2ir.core import (
    CanonicalAlert,
    Decision,
    DecisionOutcome,
    DetectionIdentity,
    Entity,
    EvidenceReference,
    Incident,
    InvestigationRequest,
    Severity,
    SourceProvenance,
)
from alert2ir.persistence import PostgresProcessingRepository


DATABASE_URL_ENV = "ALERT2IR_TEST_DATABASE_URL"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def make_alert(identifier: str, severity: Severity) -> CanonicalAlert:
    return CanonicalAlert(
        detection=DetectionIdentity(identifier, "Ordered synthetic activity"),
        detected_at=datetime(
            2026,
            8,
            11,
            15,
            30,
            tzinfo=timezone(timedelta(hours=5, minutes=30)),
        ),
        source=SourceProvenance("synthetic", "alert-9001"),
        entities=(
            Entity("host", "workstation-7"),
            Entity("user", "alice"),
        ),
        severity=severity,
        evidence=(
            EvidenceReference("record-100", "synthetic-record"),
            EvidenceReference("record-101", None),
        ),
    )


def make_no_action(alert: CanonicalAlert) -> OrchestrationResult:
    return OrchestrationResult(
        decision=Decision(
            outcome=DecisionOutcome.NO_ACTION,
            policy_id="ordered-policy-v1",
            reasons=("first reason", "second reason"),
            source=alert.source,
        ),
        incident=None,
        investigation_request=None,
        investigation_result=None,
    )


def make_investigate(alert: CanonicalAlert) -> OrchestrationResult:
    decision = Decision(
        outcome=DecisionOutcome.INVESTIGATE,
        policy_id="ordered-policy-v1",
        reasons=("first reason", "second reason"),
        source=alert.source,
    )
    incident = Incident(alert=alert, decision=decision)
    request = InvestigationRequest(
        incident=incident,
        desired_outcome="collect ordered evidence",
        required_capabilities=("process.list", "network.connections"),
        targets=(alert.entities[1], alert.entities[0]),
    )
    backend_result = InvestigationResult(
        backend="mock",
        completed_capabilities=("network.connections", "process.list"),
        evidence=(
            EvidenceReference("result-200", None),
            EvidenceReference("result-201", "synthetic-result"),
        ),
    )
    return OrchestrationResult(
        decision=decision,
        incident=incident,
        investigation_request=request,
        investigation_result=backend_result,
    )


@unittest.skipUnless(
    os.environ.get(DATABASE_URL_ENV),
    f"{DATABASE_URL_ENV} is required for PostgreSQL repository integration tests",
)
class PostgresProcessingRepositoryIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.database_url = os.environ[DATABASE_URL_ENV]
        environment = os.environ.copy()
        environment["ALERT2IR_DATABASE_URL"] = cls.database_url
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=REPOSITORY_ROOT,
            env=environment,
            check=True,
        )

    def setUp(self) -> None:
        self.repository: ProcessingRepository = PostgresProcessingRepository(
            self.database_url
        )

    def test_low_no_action_round_trip_and_null_database_shape(self) -> None:
        processing_id = uuid4()
        alert = make_alert("rule-low", Severity.LOW)
        result = make_no_action(alert)

        saved = self.repository.save(processing_id, alert, result)
        retrieved = self.repository.get(processing_id)

        self.assertEqual(saved.processing_id, processing_id)
        self.assertIsNotNone(saved.created_at.tzinfo)
        self.assertIsNotNone(saved.created_at.utcoffset())
        self.assertEqual(retrieved, saved)
        self.assertEqual(retrieved.alert, alert)
        self.assertIsNone(retrieved.result.incident)
        with psycopg.connect(self.database_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT request_desired_outcome, request_capabilities,
                           request_targets, result_backend,
                           result_completed_capabilities, result_evidence
                    FROM processing_records WHERE id = %s
                    """,
                    (processing_id,),
                )
                self.assertEqual(cursor.fetchone(), (None,) * 6)

    def test_high_investigate_round_trip_and_exact_database_shape(self) -> None:
        processing_id = uuid4()
        alert = make_alert("rule-high", Severity.HIGH)
        result = make_investigate(alert)

        self.repository.save(processing_id, alert, result)
        retrieved = self.repository.get(processing_id)

        self.assertEqual(retrieved.alert.detection, alert.detection)
        self.assertEqual(retrieved.alert.source, alert.source)
        self.assertEqual(retrieved.alert.entities, alert.entities)
        self.assertEqual(retrieved.alert.evidence, alert.evidence)
        self.assertEqual(retrieved.result, result)
        self.assertEqual(retrieved.result.incident.alert, retrieved.alert)
        self.assertEqual(
            retrieved.result.decision.reasons,
            ("first reason", "second reason"),
        )
        self.assertEqual(
            retrieved.result.investigation_request.required_capabilities,
            ("process.list", "network.connections"),
        )
        self.assertEqual(
            retrieved.result.investigation_request.targets,
            (alert.entities[1], alert.entities[0]),
        )
        self.assertEqual(
            retrieved.result.investigation_result.completed_capabilities,
            ("network.connections", "process.list"),
        )
        self.assertEqual(
            retrieved.result.investigation_result.evidence,
            (
                EvidenceReference("result-200", None),
                EvidenceReference("result-201", "synthetic-result"),
            ),
        )
        self.assertIsNotNone(retrieved.alert.detected_at.tzinfo)
        self.assertIsNotNone(retrieved.alert.detected_at.utcoffset())
        self.assertEqual(retrieved.alert.detected_at, alert.detected_at)

        with psycopg.connect(self.database_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT snapshot_version, entities, alert_evidence,
                           decision_reasons, request_capabilities,
                           request_targets, result_completed_capabilities,
                           result_evidence
                    FROM processing_records WHERE id = %s
                    """,
                    (processing_id,),
                )
                self.assertEqual(
                    cursor.fetchone(),
                    (
                        1,
                        [
                            {"kind": "host", "value": "workstation-7"},
                            {"kind": "user", "value": "alice"},
                        ],
                        [
                            {
                                "kind": "synthetic-record",
                                "reference": "record-100",
                            },
                            {"kind": None, "reference": "record-101"},
                        ],
                        ["first reason", "second reason"],
                        ["process.list", "network.connections"],
                        [
                            {"kind": "user", "value": "alice"},
                            {"kind": "host", "value": "workstation-7"},
                        ],
                        ["network.connections", "process.list"],
                        [
                            {"kind": None, "reference": "result-200"},
                            {
                                "kind": "synthetic-result",
                                "reference": "result-201",
                            },
                        ],
                    ),
                )

    def test_unknown_id_returns_none(self) -> None:
        self.repository.check_readiness()
        self.assertIsNone(self.repository.get(uuid4()))

    def test_duplicate_id_is_rejected_and_original_is_unchanged(self) -> None:
        processing_id = uuid4()
        original_alert = make_alert("rule-original", Severity.LOW)
        original = self.repository.save(
            processing_id, original_alert, make_no_action(original_alert)
        )
        replacement_alert = make_alert("rule-replacement", Severity.HIGH)

        with self.assertRaises(psycopg.errors.UniqueViolation):
            self.repository.save(
                processing_id,
                replacement_alert,
                make_investigate(replacement_alert),
            )

        self.assertEqual(self.repository.get(processing_id), original)

    def test_mismatched_alert_rolls_back_before_commit(self) -> None:
        processing_id = uuid4()
        processed_alert = make_alert("rule-A", Severity.HIGH)
        supplied_alert = make_alert("rule-B", Severity.HIGH)
        self.assertEqual(processed_alert.source, supplied_alert.source)

        with self.assertRaisesRegex(ValueError, "incident alert must match"):
            self.repository.save(
                processing_id,
                supplied_alert,
                make_investigate(processed_alert),
            )

        self.assertIsNone(self.repository.get(processing_id))


if __name__ == "__main__":
    unittest.main()
