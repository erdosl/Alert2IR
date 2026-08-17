from datetime import datetime, timezone
import io
import json
import unittest
from uuid import UUID

import httpx2
from opentelemetry import trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

from alert2ir.api import create_app
from alert2ir.application import AlertOrchestrator, PersistentAlertProcessor
from alert2ir.backends import BackendRouter
from alert2ir.core import BaselineSeverityPolicy, Incident, InvestigationRequest
from alert2ir.observability import (
    ApplicationObservability,
    current_attempt_id,
    current_error_category,
    current_processing_id,
    current_request_id,
    make_event_logger,
    reconciliation_context,
    request_context,
    set_attempt_id,
    set_error_category,
    set_processing_id,
)
from alert2ir.persistence import InMemoryProcessingRepository
from tests.test_api import CountingBackend, make_payload


NOW = datetime(2026, 8, 17, tzinfo=timezone.utc)
PROCESSING_ID = UUID("aaaaaaaa-0000-4000-8000-000000000001")


class TelemetryHarness:
    def __init__(self) -> None:
        self.stream = io.StringIO()
        self.reader = InMemoryMetricReader()
        self.meter_provider = MeterProvider(metric_readers=(self.reader,))
        self.observability = ApplicationObservability(
            tracer_provider=trace.NoOpTracerProvider(),
            meter_provider=self.meter_provider,
            event_logger=make_event_logger(
                stream=self.stream,
                name=f"durable-observability-{id(self)}",
            ),
        )

    def events(self):
        return [json.loads(line) for line in self.stream.getvalue().splitlines()]

    def metrics(self):
        data = self.reader.get_metrics_data()
        values = []
        if data is None:
            return values
        for resource in data.resource_metrics:
            for scope in resource.scope_metrics:
                for metric in scope.metrics:
                    for point in metric.data.data_points:
                        values.append((metric.name, dict(point.attributes)))
        return values

    def close(self):
        self.meter_provider.shutdown()


def make_app(harness, *, backend=None, repository=None):
    backend = backend or CountingBackend()

    def request_factory(incident: Incident) -> InvestigationRequest:
        return InvestigationRequest(
            incident,
            "collect process inventory",
            ("process.list",),
            incident.alert.entities,
        )

    orchestrator = AlertOrchestrator(
        BaselineSeverityPolicy(),
        BackendRouter((backend,)),
        request_factory,
        harness.observability,
    )
    processor = PersistentAlertProcessor(
        orchestrator,
        repository or InMemoryProcessingRepository(lambda: NOW),
        lambda: PROCESSING_ID,
        harness.observability,
    )
    return create_app(processor, harness.observability), processor


class DurableObservabilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_new_bounded_metrics_are_emitted_without_identity_labels(self) -> None:
        harness = TelemetryHarness()
        self.addCleanup(harness.close)
        app, _ = make_app(harness)
        transport = httpx2.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx2.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await client.post(
                "/v1/alerts",
                json=make_payload(),
                headers={"Idempotency-Key": "HIGHLY-SENSITIVE-KEY"},
            )
        self.assertEqual(response.status_code, 200)
        metrics = harness.metrics()
        names = {name for name, _ in metrics}
        self.assertTrue(
            {
                "alert2ir.processing.transitions",
                "alert2ir.idempotency.requests",
                "alert2ir.backend.submissions",
            }
            <= names
        )
        prohibited = {
            "idempotency_key",
            "processing_id",
            "attempt_id",
            "external_operation_id",
            "fingerprint",
            "trace_id",
        }
        durable_metric_names = {
            "alert2ir.processing.transitions",
            "alert2ir.idempotency.requests",
            "alert2ir.backend.submissions",
            "alert2ir.reconciliation.operations",
            "alert2ir.processing.stale",
            "alert2ir.processing.recovery_required",
        }
        for name, attributes in metrics:
            self.assertTrue(prohibited.isdisjoint(attributes))
            if name in durable_metric_names:
                self.assertTrue(
                    set(attributes)
                    <= {
                        "state",
                        "to_state",
                        "outcome",
                        "backend",
                        "error_category",
                    }
                )
        telemetry = harness.stream.getvalue()
        self.assertNotIn("HIGHLY-SENSITIVE-KEY", telemetry)
        self.assertNotIn("request_fingerprint", telemetry)

    async def test_replay_metric_and_fresh_request_correlation(self) -> None:
        harness = TelemetryHarness()
        self.addCleanup(harness.close)
        app, _ = make_app(harness)
        transport = httpx2.ASGITransport(app=app, raise_app_exceptions=False)
        headers = {"Idempotency-Key": "Key"}
        async with httpx2.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            first = await client.post("/v1/alerts", json=make_payload(), headers=headers)
            replay = await client.post("/v1/alerts", json=make_payload(), headers=headers)
        self.assertNotEqual(first.headers["X-Request-ID"], replay.headers["X-Request-ID"])
        outcomes = [
            attributes["outcome"]
            for name, attributes in harness.metrics()
            if name == "alert2ir.idempotency.requests"
        ]
        self.assertIn("accepted", outcomes)
        self.assertIn("replayed", outcomes)

    async def test_sensitive_persistence_failure_is_sanitized(self) -> None:
        class FailingRepository:
            def accept_processing(self, *args, **kwargs):
                raise RuntimeError("DATABASE_SECRET_VALUE")

        harness = TelemetryHarness()
        self.addCleanup(harness.close)
        app, _ = make_app(harness, repository=FailingRepository())
        transport = httpx2.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx2.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await client.post(
                "/v1/alerts",
                json=make_payload(),
                headers={"Idempotency-Key": "SECRET-KEY"},
            )
        self.assertEqual(response.status_code, 503)
        combined = response.text + harness.stream.getvalue()
        self.assertNotIn("DATABASE_SECRET_VALUE", combined)
        self.assertNotIn("SECRET-KEY", combined)

    async def test_recovery_required_uses_bounded_dimensions(self) -> None:
        from alert2ir.backends import BackendSubmissionUnknownError

        harness = TelemetryHarness()
        self.addCleanup(harness.close)
        backend = CountingBackend(
            submit_error=BackendSubmissionUnknownError("REMOTE_SECRET")
        )
        app, _ = make_app(harness, backend=backend)
        transport = httpx2.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx2.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await client.post(
                "/v1/alerts",
                json=make_payload(),
                headers={"Idempotency-Key": "Key"},
            )
        self.assertEqual(response.json()["state"], "recovery_required")
        recovery = [
            attributes
            for name, attributes in harness.metrics()
            if name == "alert2ir.processing.recovery_required"
        ]
        self.assertEqual(
            recovery,
            [
                {
                    "backend": "mock",
                    "error_category": "backend_submission_unknown",
                }
            ],
        )
        self.assertNotIn("REMOTE_SECRET", harness.stream.getvalue())

    async def test_terminal_failure_telemetry_uses_the_durable_error_category(self) -> None:
        from alert2ir.backends import OperationState

        harness = TelemetryHarness()
        self.addCleanup(harness.close)
        app, _ = make_app(
            harness,
            backend=CountingBackend(status=OperationState.FAILED),
        )
        transport = httpx2.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx2.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await client.post(
                "/v1/alerts",
                json=make_payload(),
                headers={"Idempotency-Key": "Key"},
            )
        self.assertEqual(response.status_code, 500)
        finished = [
            event
            for event in harness.events()
            if event["event"] == "request.finished"
        ]
        self.assertEqual(
            finished[-1]["error_category"],
            "backend_execution_failed",
        )
        self.assertEqual(finished[-1]["processing_id"], str(PROCESSING_ID))
        processing = [
            attributes
            for name, attributes in harness.metrics()
            if name == "alert2ir.processing"
        ]
        self.assertIn(
            {
                "decision": "investigate",
                "outcome": "error",
                "error_category": "backend_execution_failed",
            },
            processing,
        )


class ContextLifecycleTests(unittest.TestCase):
    def test_request_and_reconciliation_contexts_reset_every_identity(self) -> None:
        self.assertIsNone(current_request_id())
        self.assertIsNone(current_processing_id())
        self.assertIsNone(current_attempt_id())
        with request_context("request-1"):
            set_processing_id("processing-http")
            set_attempt_id("attempt-http")
            set_error_category("backend_timeout")
            with reconciliation_context("processing-work", "attempt-work"):
                self.assertIsNone(current_request_id())
                self.assertEqual(current_processing_id(), "processing-work")
                self.assertEqual(current_attempt_id(), "attempt-work")
                self.assertIsNone(current_error_category())
            self.assertEqual(current_request_id(), "request-1")
            self.assertEqual(current_processing_id(), "processing-http")
            self.assertEqual(current_attempt_id(), "attempt-http")
            self.assertEqual(current_error_category(), "backend_timeout")
        self.assertIsNone(current_request_id())
        self.assertIsNone(current_processing_id())
        self.assertIsNone(current_attempt_id())
        self.assertIsNone(current_error_category())


if __name__ == "__main__":
    unittest.main()
