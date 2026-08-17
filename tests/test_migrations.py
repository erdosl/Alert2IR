import os
from pathlib import Path
import subprocess
import sys
import unittest
from uuid import uuid4

import psycopg
from psycopg.types.json import Jsonb

from alert2ir.persistence import PostgresProcessingRepository


DATABASE_URL_ENV = "ALERT2IR_TEST_DATABASE_URL"
REVISION = "0002_durable_execution"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    os.environ.get(DATABASE_URL_ENV),
    f"{DATABASE_URL_ENV} is required for PostgreSQL migration integration tests",
)
class MigrationIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.database_url = os.environ[DATABASE_URL_ENV]
        cls.environment = os.environ.copy()
        cls.environment["ALERT2IR_DATABASE_URL"] = cls.database_url

    def upgrade(self, revision: str) -> None:
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", revision],
            cwd=REPOSITORY_ROOT,
            env=self.environment,
            check=True,
        )

    def test_legacy_rows_are_preserved_by_forward_migration(self) -> None:
        self.upgrade("0001_processing_records")
        no_action_id = uuid4()
        investigate_id = uuid4()
        common = dict(
            detection_identifier="legacy-rule",
            detected_at="2026-08-11T09:30:00+00:00",
            source="legacy-source",
            severity="high",
            entities=Jsonb([{"kind": "host", "value": "legacy-host"}]),
            alert_evidence=Jsonb(
                [{"reference": "legacy-record", "kind": None}]
            ),
            policy_id="legacy-policy",
            decision_reasons=Jsonb(["legacy reason"]),
        )
        insert = """
            INSERT INTO processing_records (
                id, detection_identifier, detected_at, source, severity,
                entities, alert_evidence, decision_outcome, policy_id,
                decision_reasons, request_desired_outcome,
                request_capabilities, request_targets, result_backend,
                result_completed_capabilities, result_evidence
            ) VALUES (
                %(id)s, %(detection_identifier)s, %(detected_at)s, %(source)s,
                %(severity)s, %(entities)s, %(alert_evidence)s,
                %(decision_outcome)s, %(policy_id)s, %(decision_reasons)s,
                %(request_desired_outcome)s, %(request_capabilities)s,
                %(request_targets)s, %(result_backend)s,
                %(result_completed_capabilities)s, %(result_evidence)s
            ) RETURNING created_at
        """
        with psycopg.connect(self.database_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    insert,
                    {
                        **common,
                        "id": no_action_id,
                        "decision_outcome": "no_action",
                        "request_desired_outcome": None,
                        "request_capabilities": None,
                        "request_targets": None,
                        "result_backend": None,
                        "result_completed_capabilities": None,
                        "result_evidence": None,
                    },
                )
                no_action_created = cursor.fetchone()[0]
                cursor.execute(
                    insert,
                    {
                        **common,
                        "id": investigate_id,
                        "decision_outcome": "investigate",
                        "request_desired_outcome": "collect process inventory",
                        "request_capabilities": Jsonb(["process.list"]),
                        "request_targets": Jsonb(
                            [{"kind": "host", "value": "legacy-host"}]
                        ),
                        "result_backend": "velociraptor",
                        "result_completed_capabilities": Jsonb(["process.list"]),
                        "result_evidence": Jsonb(
                            [{"reference": "F.LEGACY", "kind": "collection"}]
                        ),
                    },
                )
                investigate_created = cursor.fetchone()[0]

        self.upgrade("head")
        self.upgrade("head")

        with psycopg.connect(self.database_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT version_num FROM alembic_version")
                self.assertEqual(cursor.fetchone(), (REVISION,))
                cursor.execute(
                    """
                    SELECT id, state, created_at, updated_at, completed_at,
                           idempotency_scope, idempotency_key,
                           fingerprint_version, request_fingerprint
                    FROM processing_records
                    WHERE id IN (%s, %s)
                    ORDER BY id
                    """,
                    (no_action_id, investigate_id),
                )
                rows = {row[0]: row for row in cursor.fetchall()}
                cursor.execute("SELECT count(*) FROM execution_attempts")
                self.assertEqual(cursor.fetchone(), (0,))
                cursor.execute(
                    "SELECT to_regclass('public.execution_attempts')"
                )
                self.assertEqual(cursor.fetchone(), ("execution_attempts",))
                cursor.execute(
                    """
                    SELECT conname FROM pg_constraint
                    WHERE conrelid IN (
                        'processing_records'::regclass,
                        'execution_attempts'::regclass
                    )
                    """
                )
                constraints = {row[0] for row in cursor.fetchall()}
                self.assertTrue(
                    {
                        "uq_processing_records_idempotency",
                        "ck_processing_records_fingerprint",
                        "ck_processing_records_lifecycle_coherence",
                        "uq_execution_attempts_number",
                        "ck_execution_attempts_lifecycle_coherence",
                    }
                    <= constraints
                )
                cursor.execute(
                    """
                    SELECT indexname FROM pg_indexes
                    WHERE tablename IN ('processing_records', 'execution_attempts')
                    """
                )
                indexes = {row[0] for row in cursor.fetchall()}
                self.assertTrue(
                    {
                        "ix_processing_records_state_updated",
                        "uq_execution_attempts_active_processing",
                        "ix_execution_attempts_state_polled",
                        "ix_execution_attempts_backend_external",
                    }
                    <= indexes
                )

        for processing_id, created_at in (
            (no_action_id, no_action_created),
            (investigate_id, investigate_created),
        ):
            row = rows[processing_id]
            self.assertEqual(row[1], "completed")
            self.assertEqual(row[2], created_at)
            self.assertEqual(row[3], created_at)
            self.assertEqual(row[4], created_at)
            self.assertEqual(row[5:], (None, None, None, None))

        repository = PostgresProcessingRepository(self.database_url)
        no_action = repository.get(no_action_id)
        investigate = repository.get(investigate_id)
        self.assertEqual(no_action.processing_id, no_action_id)
        self.assertEqual(no_action.result.decision.outcome.value, "no_action")
        self.assertEqual(investigate.processing_id, investigate_id)
        self.assertEqual(investigate.result.investigation_result.backend, "velociraptor")
        self.assertEqual(
            investigate.result.investigation_result.evidence[0].reference,
            "F.LEGACY",
        )


if __name__ == "__main__":
    unittest.main()
