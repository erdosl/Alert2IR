import os
from pathlib import Path
import subprocess
import sys
import unittest
from uuid import uuid4

import psycopg
from psycopg.types.json import Jsonb


DATABASE_URL_ENV = "ALERT2IR_TEST_DATABASE_URL"
REVISION = "0001_processing_records"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    os.environ.get(DATABASE_URL_ENV),
    f"{DATABASE_URL_ENV} is required for PostgreSQL migration integration tests",
)
class MigrationIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.database_url = os.environ[DATABASE_URL_ENV]

    def run_upgrade(self) -> None:
        environment = os.environ.copy()
        environment["ALERT2IR_DATABASE_URL"] = self.database_url
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=REPOSITORY_ROOT,
            env=environment,
            check=True,
        )

    def test_baseline_migration_and_constraints(self) -> None:
        self.run_upgrade()

        with psycopg.connect(self.database_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT version_num FROM alembic_version")
                self.assertEqual(cursor.fetchone(), (REVISION,))
                cursor.execute("SELECT to_regclass('public.processing_records')")
                self.assertEqual(cursor.fetchone(), ("processing_records",))

        self.run_upgrade()

        common_values = {
            "detection_identifier": "rule-42",
            "detected_at": "2026-08-11T09:30:00+00:00",
            "source": "synthetic",
            "severity": "high",
            "entities": Jsonb([]),
            "alert_evidence": Jsonb([]),
            "policy_id": "baseline-severity-v1",
            "decision_reasons": Jsonb(["requires investigation"]),
        }
        insert_sql = """
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
            )
        """

        no_action = {
            **common_values,
            "id": uuid4(),
            "decision_outcome": "no_action",
            "request_desired_outcome": None,
            "request_capabilities": None,
            "request_targets": None,
            "result_backend": None,
            "result_completed_capabilities": None,
            "result_evidence": None,
        }
        investigate = {
            **common_values,
            "id": uuid4(),
            "decision_outcome": "investigate",
            "request_desired_outcome": "collect process inventory",
            "request_capabilities": Jsonb(["process.list"]),
            "request_targets": Jsonb([]),
            "result_backend": "mock",
            "result_completed_capabilities": Jsonb(["process.list"]),
            "result_evidence": Jsonb([]),
        }
        partial_investigate = {
            **investigate,
            "id": uuid4(),
            "result_backend": None,
        }

        with psycopg.connect(self.database_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute(insert_sql, no_action)
                cursor.execute(insert_sql, investigate)

        with self.assertRaises(psycopg.errors.CheckViolation):
            with psycopg.connect(self.database_url) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(insert_sql, partial_investigate)


if __name__ == "__main__":
    unittest.main()
