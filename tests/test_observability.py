from datetime import datetime, timezone
from io import StringIO
import json
import os
import unittest
from unittest.mock import patch
from uuid import UUID

import httpx2
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    InMemoryMetricReader,
    MetricExporter,
    MetricExportResult,
    PeriodicExportingMetricReader,
)
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace.export import (
    SimpleSpanProcessor,
    SpanExportResult,
    SpanExporter,
)
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from alert2ir.api import create_app
from alert2ir.application import AlertOrchestrator, PersistentAlertProcessor
from alert2ir.backends import BackendRouter, MockBackend, VelociraptorBackend
from alert2ir.core import BaselineSeverityPolicy, Incident, InvestigationRequest
from alert2ir.observability import (
    ApplicationObservability,
    SanitizingSpanProcessor,
    configure_observability,
    current_error_category,
    current_processing_id,
    current_request_id,
    make_event_logger,
    metric_views,
    request_context,
)
from alert2ir.persistence import InMemoryProcessingRepository


PROCESSING_ID = UUID("799b290e-2048-4d23-9b20-fc8680582f8d")
CREATED_AT = datetime(2026, 8, 16, 12, 0, tzinfo=timezone.utc)
SENTINELS = (
    "SUPER_SECRET_TOKEN_1942",
    "PASSWORD_SENTINEL_2881",
    "PRIVATE_KEY_SENTINEL_3773",
)


def make_payload(severity: str = "high", *, sensitive: bool = False):
    suffix = SENTINELS[0] if sensitive else "synthetic"
    return {
        "detection": {
            "identifier": f"rule-{suffix}",
            "name": f"detection-{SENTINELS[1] if sensitive else 'safe'}",
        },
        "detected_at": "2026-08-16T10:30:00+00:00",
        "source": {
            "source": "synthetic",
            "source_alert_id": SENTINELS[2] if sensitive else "alert-1",
        },
        "entities": [{"kind": "host", "value": f"host-{suffix}"}],
        "severity": severity,
        "evidence": [{"reference": f"record-{suffix}", "kind": "record"}],
    }


class TelemetryHarness:
    def __init__(
        self,
        *,
        span_exporter: SpanExporter | None = None,
        metric_reader=None,
    ) -> None:
        self.stream = StringIO()
        self.span_exporter = span_exporter or InMemorySpanExporter()
        self.metric_reader = metric_reader or InMemoryMetricReader()
        resource = Resource({"service.name": "alert2ir"})
        self.tracer_provider = TracerProvider(resource=resource)
        self.tracer_provider.add_span_processor(
            SanitizingSpanProcessor(SimpleSpanProcessor(self.span_exporter))
        )
        self.meter_provider = MeterProvider(
            resource=resource,
            metric_readers=(self.metric_reader,),
            views=metric_views(),
        )
        self.observability = ApplicationObservability(
            tracer_provider=self.tracer_provider,
            meter_provider=self.meter_provider,
            event_logger=make_event_logger(
                stream=self.stream,
                name=f"alert2ir.events.test.{id(self)}",
            ),
        )

    def events(self) -> list[dict[str, object]]:
        return [
            json.loads(line)
            for line in self.stream.getvalue().splitlines()
            if line
        ]

    def spans(self):
        getter = getattr(self.span_exporter, "get_finished_spans", None)
        return tuple(getter()) if getter is not None else ()

    def all_metrics(self):
        metrics_data = self.metric_reader.get_metrics_data()
        if metrics_data is None:
            return {}
        return {
            metric.name: metric
            for resource_metric in metrics_data.resource_metrics
            for scope_metric in resource_metric.scope_metrics
            for metric in scope_metric.metrics
        }

    def application_metrics(self):
        return {
            name: metric
            for name, metric in self.all_metrics().items()
            if name.startswith("alert2ir.")
        }

    def close(self) -> None:
        self.tracer_provider.shutdown()
        self.meter_provider.shutdown()


def make_app(harness: TelemetryHarness, *, repository=None, backends=None):
    configured_backends = (
        (MockBackend("mock", frozenset({"process.list"})),)
        if backends is None
        else backends
    )

    def request_factory(incident: Incident) -> InvestigationRequest:
        return InvestigationRequest(
            incident=incident,
            desired_outcome="collect process inventory",
            required_capabilities=("process.list",),
            targets=incident.alert.entities,
        )

    orchestrator = AlertOrchestrator(
        policy=BaselineSeverityPolicy(),
        router=BackendRouter(configured_backends),
        request_factory=request_factory,
        observability=harness.observability,
    )
    processor = PersistentAlertProcessor(
        orchestrator,
        repository or InMemoryProcessingRepository(lambda: CREATED_AT),
        lambda: PROCESSING_ID,
        harness.observability,
    )
    return create_app(processor, harness.observability)


async def request(app, payload, *, headers=None):
    transport = httpx2.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx2.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as client:
        return await client.post("/v1/alerts", json=payload, headers=headers)


class ObservabilitySuccessTests(unittest.IsolatedAsyncioTestCase):
    async def test_health_and_readiness_are_excluded_from_tracing(self) -> None:
        harness = TelemetryHarness()
        self.addCleanup(harness.close)
        app = make_app(harness)
        transport = httpx2.ASGITransport(app=app, raise_app_exceptions=False)

        async with httpx2.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            health = await client.get("/healthz")
            readiness = await client.get("/readyz")

        self.assertEqual(health.json(), {"status": "ok"})
        self.assertEqual(readiness.json(), {"status": "ready"})
        self.assertEqual(harness.spans(), ())
        self.assertEqual(harness.events(), [])

    async def test_investigation_trace_events_metrics_and_correlation(self) -> None:
        harness = TelemetryHarness()
        self.addCleanup(harness.close)

        response = await request(make_app(harness), make_payload("high"))

        self.assertEqual(response.status_code, 200)
        request_id = UUID(response.headers["X-Request-ID"])
        events = harness.events()
        self.assertEqual(
            [event["event"] for event in events],
            [
                "alert.processing.started",
                "backend.execution.started",
                "backend.execution.finished",
                "persistence.finished",
                "alert.processing.finished",
                "request.finished",
            ],
        )
        for event in events:
            self.assertEqual(event["schema_version"], "1")
            datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
            self.assertEqual(UUID(str(event["request_id"])), request_id)
            self.assertRegex(str(event["trace_id"]), r"^[0-9a-f]{32}$")
            self.assertRegex(str(event["span_id"]), r"^[0-9a-f]{16}$")
            self.assertNotIn(None, event.values())
        self.assertEqual(events[-1]["http_route"], "/v1/alerts")
        self.assertEqual(events[-1]["http_status"], 200)
        self.assertIsInstance(events[-1]["duration_ms"], (int, float))

        spans = {span.name: span for span in harness.spans()}
        server = spans["POST /v1/alerts"]
        processing = spans["alert2ir.process"]
        backend = spans["backend.investigate"]
        persistence = spans["persistence.save"]
        self.assertEqual(processing.parent.span_id, server.context.span_id)
        self.assertEqual(backend.parent.span_id, processing.context.span_id)
        self.assertEqual(persistence.parent.span_id, processing.context.span_id)
        self.assertEqual(backend.attributes["alert2ir.backend"], "mock")
        self.assertNotIn("alert2ir.target", backend.attributes)
        self.assertEqual(persistence.attributes["db.system.name"], "postgresql")
        self.assertNotIn("db.statement", persistence.attributes)
        self.assertEqual(dict(server.resource.attributes), {"service.name": "alert2ir"})
        self.assertEqual(
            set(server.attributes),
            {"http.method", "http.route", "http.status_code"},
        )
        self.assertNotIn("net.peer.ip", server.attributes)
        self.assertNotIn("http.url", server.attributes)
        self.assertNotIn("http.user_agent", server.attributes)

        metrics = harness.application_metrics()
        self.assertEqual(
            set(metrics),
            {
                "alert2ir.processing",
                "alert2ir.processing.duration",
                "alert2ir.backend.executions",
                "alert2ir.backend.duration",
                "alert2ir.persistence.operations",
                "alert2ir.persistence.duration",
            },
        )
        self.assertEqual(set(harness.all_metrics()), set(metrics))
        for name in (
            "alert2ir.processing",
            "alert2ir.backend.executions",
            "alert2ir.persistence.operations",
        ):
            points = metrics[name].data.data_points
            self.assertEqual(len(points), 1)
            self.assertEqual(points[0].value, 1)
        self.assertEqual(
            set(metrics["alert2ir.backend.executions"].data.data_points[0].attributes),
            {"backend", "capability", "outcome"},
        )
        self.assertEqual(
            tuple(
                metrics["alert2ir.processing.duration"]
                .data.data_points[0]
                .explicit_bounds
            ),
            (
                0.01,
                0.025,
                0.05,
                0.1,
                0.25,
                0.5,
                1.0,
                2.5,
                5.0,
                10.0,
                30.0,
                60.0,
                120.0,
            ),
        )

    async def test_no_action_has_no_backend_telemetry(self) -> None:
        harness = TelemetryHarness()
        self.addCleanup(harness.close)

        response = await request(make_app(harness), make_payload("low"))

        self.assertEqual(response.status_code, 200)
        names = {span.name for span in harness.spans()}
        self.assertNotIn("backend.investigate", names)
        self.assertNotIn(
            "backend.execution.started",
            {event["event"] for event in harness.events()},
        )
        self.assertNotIn("alert2ir.backend.executions", harness.application_metrics())

    async def test_velociraptor_operation_span_is_low_cardinality(self) -> None:
        class CollectionClient:
            def collect(self, *, client_id, artifact, timeout_seconds):
                return "F.OPAQUE-REFERENCE"

        harness = TelemetryHarness()
        self.addCleanup(harness.close)
        backend = VelociraptorBackend(
            client=CollectionClient(),
            host_client_ids={"host-synthetic": "C.SYNTHETIC"},
            collection_timeout_seconds=5,
            observability=harness.observability,
        )

        response = await request(
            make_app(harness, backends=(backend,)),
            make_payload("high"),
        )

        self.assertEqual(response.status_code, 200)
        spans = {span.name: span for span in harness.spans()}
        operation = spans["velociraptor.collect"]
        backend_span = spans["backend.investigate"]
        self.assertEqual(operation.parent.span_id, backend_span.context.span_id)
        self.assertNotIn("F.OPAQUE-REFERENCE", repr(operation.attributes))

    async def test_request_context_is_reset_and_caller_id_is_not_reused(self) -> None:
        harness = TelemetryHarness()
        self.addCleanup(harness.close)
        app = make_app(harness)

        first = await request(
            app,
            make_payload("low"),
            headers={"X-Request-ID": "caller-id"},
        )
        second = await request(app, make_payload("low"))

        self.assertNotEqual(first.headers["X-Request-ID"], "caller-id")
        self.assertNotEqual(
            first.headers["X-Request-ID"], second.headers["X-Request-ID"]
        )
        self.assertNotIn("caller-id", json.dumps(harness.events()))
        self.assertIsNone(current_request_id())
        self.assertIsNone(current_processing_id())
        self.assertIsNone(current_error_category())

    async def test_validation_and_routing_failures_use_bounded_categories(self) -> None:
        validation_harness = TelemetryHarness()
        self.addCleanup(validation_harness.close)
        invalid = make_payload("low")
        del invalid["detection"]

        validation_response = await request(
            make_app(validation_harness),
            invalid,
        )

        self.assertEqual(validation_response.status_code, 422)
        self.assertEqual(
            validation_harness.events()[-1]["error_category"],
            "input_validation",
        )
        self.assertEqual(validation_harness.application_metrics(), {})

        routing_harness = TelemetryHarness()
        self.addCleanup(routing_harness.close)
        routing_response = await request(
            make_app(routing_harness, backends=()),
            make_payload("high"),
        )

        self.assertEqual(routing_response.status_code, 409)
        self.assertEqual(
            routing_harness.events()[-1]["error_category"],
            "routing_unsupported",
        )
        self.assertNotIn(
            "alert2ir.backend.executions",
            routing_harness.application_metrics(),
        )
        self.assertEqual(
            routing_harness.application_metrics()[
                "alert2ir.processing"
            ].data.data_points[0].value,
            1,
        )


class SensitiveFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_persistence_failure_is_sanitized_everywhere(self) -> None:
        class FailingRepository:
            def save(self, processing_id, alert, result):
                raise RuntimeError(f"database failed {SENTINELS[0]}")

            def get(self, processing_id):
                raise AssertionError("not used")

        harness = TelemetryHarness()
        self.addCleanup(harness.close)
        response = await request(
            make_app(harness, repository=FailingRepository()),
            make_payload("low", sensitive=True),
        )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json(), {"detail": "Internal Server Error"})
        self.assertIn("X-Request-ID", response.headers)
        event_text = json.dumps(harness.events())
        span_text = repr(
            [
                (span.name, span.attributes, span.events, span.status.description)
                for span in harness.spans()
            ]
        )
        metric_attributes = [
            dict(point.attributes)
            for metric in harness.application_metrics().values()
            for point in metric.data.data_points
        ]
        for sentinel in SENTINELS:
            self.assertNotIn(sentinel, response.text)
            self.assertNotIn(sentinel, event_text)
            self.assertNotIn(sentinel, span_text)
            self.assertNotIn(sentinel, repr(metric_attributes))
        for span in harness.spans():
            if span.name in {"alert2ir.process", "persistence.save"}:
                self.assertEqual(span.events, ())
        persistence_event = next(
            event
            for event in harness.events()
            if event["event"] == "persistence.finished"
        )
        self.assertEqual(persistence_event["processing_id"], str(PROCESSING_ID))
        self.assertEqual(
            persistence_event["error_category"], "persistence_internal"
        )
        prohibited_keys = {
            "request_id",
            "trace_id",
            "span_id",
            "processing_id",
            "operation_reference",
            "hostname",
            "source_alert_id",
        }
        self.assertFalse(
            prohibited_keys.intersection(
                key for attributes in metric_attributes for key in attributes
            )
        )
        metrics = harness.application_metrics()
        self.assertEqual(
            metrics["alert2ir.processing"].data.data_points[0].value,
            1,
        )
        self.assertEqual(
            metrics["alert2ir.persistence.operations"].data.data_points[0].value,
            1,
        )
        self.assertNotIn("alert2ir.backend.executions", metrics)

    async def test_backend_failure_is_sanitized_and_recorded_once(self) -> None:
        class FailingBackend:
            name = "mock"
            capabilities = frozenset({"process.list"})

            def investigate(self, request):
                raise RuntimeError(f"backend failed {SENTINELS[0]}")

        harness = TelemetryHarness()
        self.addCleanup(harness.close)

        response = await request(
            make_app(harness, backends=(FailingBackend(),)),
            make_payload("high", sensitive=True),
        )

        self.assertEqual(response.status_code, 500)
        telemetry_text = (
            json.dumps(harness.events())
            + repr(
                [
                    (span.name, span.attributes, span.events, span.status.description)
                    for span in harness.spans()
                ]
            )
            + repr(
                [
                    dict(point.attributes)
                    for metric in harness.application_metrics().values()
                    for point in metric.data.data_points
                ]
            )
        )
        for sentinel in SENTINELS:
            self.assertNotIn(sentinel, response.text)
            self.assertNotIn(sentinel, telemetry_text)
        metrics = harness.application_metrics()
        self.assertEqual(
            metrics["alert2ir.processing"].data.data_points[0].value,
            1,
        )
        self.assertEqual(
            metrics["alert2ir.backend.executions"].data.data_points[0].value,
            1,
        )
        self.assertNotIn("alert2ir.persistence.operations", metrics)
        self.assertEqual(
            next(
                event
                for event in harness.events()
                if event["event"] == "backend.execution.finished"
            )["error_category"],
            "backend_execution",
        )

    async def test_backend_timeout_uses_shared_bounded_category(self) -> None:
        class TimeoutBackend:
            name = "mock"
            capabilities = frozenset({"process.list"})

            def investigate(self, request):
                raise TimeoutError(SENTINELS[0])

        harness = TelemetryHarness()
        self.addCleanup(harness.close)
        response = await request(
            make_app(harness, backends=(TimeoutBackend(),)),
            make_payload("high"),
        )

        self.assertEqual(response.status_code, 500)
        finished = next(
            event
            for event in harness.events()
            if event["event"] == "backend.execution.finished"
        )
        self.assertEqual(finished["outcome"], "timeout")
        self.assertEqual(finished["error_category"], "backend_timeout")
        point = harness.application_metrics()[
            "alert2ir.backend.executions"
        ].data.data_points[0]
        self.assertEqual(point.attributes["outcome"], "timeout")
        self.assertEqual(point.attributes["error_category"], "backend_timeout")

    async def test_unexpected_route_failure_has_generic_safe_boundary(self) -> None:
        harness = TelemetryHarness()
        self.addCleanup(harness.close)

        class ExplodingProcessor:
            observability = harness.observability

            def process(self, alert):
                raise RuntimeError(f"unexpected {SENTINELS[0]}")

        response = await request(
            create_app(ExplodingProcessor(), harness.observability),
            make_payload("low", sensitive=True),
        )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json(), {"detail": "Internal Server Error"})
        UUID(response.headers["X-Request-ID"])
        self.assertEqual(harness.events()[-1]["error_category"], "internal_error")
        self.assertNotIn(SENTINELS[0], response.text)
        self.assertNotIn(SENTINELS[0], json.dumps(harness.events()))

    async def test_operation_reference_is_only_in_the_safe_submission_event(self) -> None:
        harness = TelemetryHarness()
        self.addCleanup(harness.close)
        reference = "F.OPAQUE-SUBMISSION"

        class SubmittingClient:
            def collect(self, *, client_id, artifact, timeout_seconds):
                harness.observability.backend_operation_submitted(reference)
                return reference

        backend = VelociraptorBackend(
            client=SubmittingClient(),
            host_client_ids={"host-synthetic": "C.SYNTHETIC"},
            collection_timeout_seconds=5,
            observability=harness.observability,
        )

        response = await request(
            make_app(harness, backends=(backend,)),
            make_payload("high"),
        )

        self.assertEqual(response.status_code, 200)
        submitted = next(
            event
            for event in harness.events()
            if event["event"] == "backend.operation.submitted"
        )
        self.assertEqual(submitted["operation_reference"], reference)
        self.assertEqual(submitted["operation_reference_kind"], "flow_id")
        self.assertNotIn(
            reference,
            repr([span.attributes for span in harness.spans()]),
        )
        self.assertNotIn(
            reference,
            repr(
                [
                    dict(point.attributes)
                    for metric in harness.application_metrics().values()
                    for point in metric.data.data_points
                ]
            ),
        )


class ExportIsolationTests(unittest.IsolatedAsyncioTestCase):
    def test_exporters_are_not_constructed_without_explicit_endpoint(self) -> None:
        for endpoint in (None, "", " \t "):
            with self.subTest(endpoint=endpoint), patch.dict(
                os.environ,
                {},
                clear=False,
            ), patch(
                "alert2ir.observability.OTLPSpanExporter"
            ) as span_exporter, patch(
                "alert2ir.observability.OTLPMetricExporter"
            ) as metric_exporter:
                if endpoint is None:
                    os.environ.pop("OTEL_EXPORTER_OTLP_ENDPOINT", None)
                else:
                    os.environ["OTEL_EXPORTER_OTLP_ENDPOINT"] = endpoint
                configured = configure_observability()

            span_exporter.assert_not_called()
            metric_exporter.assert_not_called()
            configured.tracer_provider.shutdown()
            configured.meter_provider.shutdown()

    async def test_failing_trace_export_does_not_change_request(self) -> None:
        class FailingSpanExporter(SpanExporter):
            def __init__(self):
                self.calls = 0

            def export(self, spans):
                self.calls += 1
                return SpanExportResult.FAILURE

            def shutdown(self):
                return None

        exporter = FailingSpanExporter()
        harness = TelemetryHarness(span_exporter=exporter)
        self.addCleanup(harness.close)

        response = await request(make_app(harness), make_payload("low"))

        self.assertEqual(response.status_code, 200)
        self.assertGreater(exporter.calls, 0)
        self.assertIn("request.finished", {e["event"] for e in harness.events()})

    async def test_failing_metric_export_does_not_change_request(self) -> None:
        class FailingMetricExporter(MetricExporter):
            def __init__(self):
                super().__init__()
                self.calls = 0

            def export(self, metrics_data, timeout_millis=10000, **kwargs):
                self.calls += 1
                return MetricExportResult.FAILURE

            def force_flush(self, timeout_millis=10000):
                return True

            def shutdown(self, timeout_millis=30000, **kwargs):
                return None

        exporter = FailingMetricExporter()
        reader = PeriodicExportingMetricReader(
            exporter,
            export_interval_millis=60000,
        )
        harness = TelemetryHarness(metric_reader=reader)
        self.addCleanup(harness.close)

        response = await request(make_app(harness), make_payload("low"))
        reader.collect()

        self.assertEqual(response.status_code, 200)
        self.assertGreater(exporter.calls, 0)


class ContextPrimitiveTests(unittest.TestCase):
    def test_nested_context_resets_all_values(self) -> None:
        self.assertIsNone(current_request_id())
        with request_context("request-a"):
            self.assertEqual(current_request_id(), "request-a")
        self.assertIsNone(current_request_id())
        self.assertIsNone(current_processing_id())
        self.assertIsNone(current_error_category())


if __name__ == "__main__":
    unittest.main()
