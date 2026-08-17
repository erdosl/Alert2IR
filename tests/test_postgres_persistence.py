from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import subprocess
import sys
import unittest
from uuid import uuid4

import psycopg
from psycopg.types.json import Jsonb

from alert2ir.application import IdempotencyConflictError, ProcessingState
from alert2ir.application.fingerprinting import fingerprint_canonical_alert
from alert2ir.backends import OperationState, OperationStatus
from alert2ir.core import Severity
from alert2ir.persistence import PostgresProcessingRepository
from tests.test_durable_processing import (
    LifecycleBackend,
    accept_only,
    make_alert,
    make_processor,
    plan_only,
)


DATABASE_URL_ENV = "ALERT2IR_TEST_DATABASE_URL"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    os.environ.get(DATABASE_URL_ENV),
    f"{DATABASE_URL_ENV} is required for PostgreSQL repository integration tests",
)
class PostgresDurableRepositoryIntegrationTests(unittest.TestCase):
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
        self.repository = PostgresProcessingRepository(self.database_url)
        with psycopg.connect(self.database_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    DELETE FROM execution_attempts
                    WHERE processing_id IN (
                        SELECT id FROM processing_records
                        WHERE idempotency_key IS NOT NULL
                    )
                    """
                )
                cursor.execute(
                    "DELETE FROM processing_records WHERE idempotency_key IS NOT NULL"
                )

    def test_acceptance_and_no_action_completion_round_trip(self) -> None:
        alert = make_alert(Severity.LOW, identifier=f"rule-{uuid4()}")
        version, digest = fingerprint_canonical_alert(alert)
        processing_id = uuid4()
        key = str(uuid4())
        accepted = self.repository.accept_processing(
            processing_id,
            alert,
            alert.source.source,
            key,
            version,
            digest,
        )
        replay = self.repository.accept_processing(
            uuid4(), alert, alert.source.source, key, version, digest
        )
        self.assertTrue(accepted.created)
        self.assertFalse(replay.created)
        self.assertEqual(replay.record.processing_id, processing_id)
        self.assertEqual(self.repository.get(processing_id), accepted.record)

        processor = make_processor(self.repository, LifecycleBackend())
        completed = processor.process(alert, key)
        # An existing accepted replay is intentionally passive; reconciliation
        # resumes deterministic planning and no-action completion.
        self.assertEqual(completed.record.state, ProcessingState.ACCEPTED)
        processor.reconcile_once()
        durable = self.repository.get(processing_id)
        self.assertEqual(durable.state, ProcessingState.COMPLETED)
        self.assertEqual(durable.result.decision.outcome.value, "no_action")

    def test_concurrent_identical_acceptance_converges_on_one_id(self) -> None:
        alert = make_alert(identifier=f"rule-{uuid4()}")
        version, digest = fingerprint_canonical_alert(alert)
        key = str(uuid4())

        def accept(_):
            return self.repository.accept_processing(
                uuid4(), alert, alert.source.source, key, version, digest
            )

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(accept, range(8)))
        self.assertEqual(sum(item.created for item in results), 1)
        self.assertEqual(len({item.record.processing_id for item in results}), 1)

    def test_concurrent_different_payloads_yield_one_conflict(self) -> None:
        backend = LifecycleBackend()
        processor = make_processor(self.repository, backend)
        key = str(uuid4())
        alerts = (
            make_alert(Severity.LOW, identifier=f"first-{uuid4()}"),
            make_alert(Severity.LOW, identifier=f"second-{uuid4()}"),
        )

        def process(alert):
            try:
                return ("accepted", processor.process(alert, key).record.processing_id)
            except IdempotencyConflictError:
                return ("conflict", None)

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(process, alerts))
        self.assertEqual(sorted(item[0] for item in results), ["accepted", "conflict"])
        with psycopg.connect(self.database_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT count(*) FROM processing_records
                    WHERE idempotency_scope = 'synthetic' AND idempotency_key = %s
                    """,
                    (key,),
                )
                self.assertEqual(cursor.fetchone(), (1,))

    def test_concurrent_claim_has_one_winner_and_one_active_attempt(self) -> None:
        alert = make_alert(identifier=f"rule-{uuid4()}")
        version, digest = fingerprint_canonical_alert(alert)
        accepted = self.repository.accept_processing(
            uuid4(), alert, "synthetic", str(uuid4()), version, digest
        ).record
        backend = LifecycleBackend()
        planned = plan_only(self.repository, backend, accepted)

        with ThreadPoolExecutor(max_workers=8) as executor:
            claims = list(
                executor.map(
                    lambda _: self.repository.claim_attempt_for_submission(
                        planned.attempt.attempt_id
                    ),
                    range(8),
                )
            )
        self.assertEqual(len([item for item in claims if item is not None]), 1)
        with psycopg.connect(self.database_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT count(*) FROM execution_attempts WHERE processing_id = %s",
                    (accepted.processing_id,),
                )
                self.assertEqual(cursor.fetchone(), (1,))

    def test_concurrent_duplicate_processing_submits_backend_once(self) -> None:
        backend = LifecycleBackend()
        processor = make_processor(self.repository, backend)
        alert = make_alert(identifier=f"rule-{uuid4()}")
        key = str(uuid4())
        with ThreadPoolExecutor(max_workers=4) as executor:
            outcomes = list(
                executor.map(lambda _: processor.process(alert, key), range(4))
            )
        self.assertEqual(len({item.record.processing_id for item in outcomes}), 1)
        self.assertEqual(backend.submit_calls, 1)
        processing_id = outcomes[0].record.processing_id
        with psycopg.connect(self.database_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT count(*) FROM execution_attempts WHERE processing_id = %s",
                    (processing_id,),
                )
                self.assertEqual(cursor.fetchone(), (1,))

    def test_same_key_changed_body_conflicts_without_new_attempt(self) -> None:
        backend = LifecycleBackend()
        processor = make_processor(self.repository, backend)
        key = str(uuid4())
        first = processor.process(
            make_alert(Severity.LOW, identifier=f"rule-{uuid4()}"), key
        )
        changed = make_alert(Severity.HIGH, identifier="different")
        with self.assertRaises(IdempotencyConflictError):
            processor.process(changed, key)
        with psycopg.connect(self.database_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT count(*) FROM execution_attempts WHERE processing_id = %s",
                    (first.record.processing_id,),
                )
                self.assertEqual(cursor.fetchone(), (0,))

    def test_known_operation_resumes_through_new_repository_instance(self) -> None:
        key = str(uuid4())
        first_backend = LifecycleBackend(
            statuses=[OperationStatus(OperationState.NONTERMINAL, "running")]
        )
        first = make_processor(self.repository, first_backend).process(
            make_alert(identifier=f"rule-{uuid4()}"), key
        )
        self.assertEqual(first.record.state, ProcessingState.SUBMITTED)

        restarted_repository = PostgresProcessingRepository(self.database_url)
        restarted_backend = LifecycleBackend()
        report = make_processor(
            restarted_repository, restarted_backend
        ).reconcile_once()
        durable = restarted_repository.get(first.record.processing_id)
        self.assertEqual(durable.state, ProcessingState.COMPLETED)
        self.assertEqual(restarted_backend.submit_calls, 0)
        self.assertEqual(restarted_backend.poll_calls, ["operation-1"])
        self.assertEqual(report.advanced, 1)

    def test_legacy_null_key_rows_coexist_and_have_no_attempts(self) -> None:
        ids = (uuid4(), uuid4())
        insert = """
            INSERT INTO processing_records (
                id, detection_identifier, detected_at, source, severity,
                entities, alert_evidence, state, updated_at, completed_at,
                decision_outcome, policy_id, decision_reasons
            ) VALUES (
                %s, %s, CURRENT_TIMESTAMP, 'legacy-source', 'low',
                %s, %s, 'completed', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
                'no_action', 'legacy-policy', %s
            )
        """
        with psycopg.connect(self.database_url) as connection:
            with connection.cursor() as cursor:
                for processing_id in ids:
                    cursor.execute(
                        insert,
                        (
                            processing_id,
                            f"legacy-{processing_id}",
                            Jsonb([]),
                            Jsonb([]),
                            Jsonb(["legacy reason"]),
                        ),
                    )
        for processing_id in ids:
            record = self.repository.get(processing_id)
            self.assertEqual(record.state, ProcessingState.COMPLETED)
            self.assertIsNone(record.idempotency_key)
            self.assertIsNone(record.request_fingerprint)
            self.assertIsNone(
                self.repository.get_attempt_for_processing(processing_id)
            )


if __name__ == "__main__":
    unittest.main()
