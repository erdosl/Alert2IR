"""Application-owned, vendor-neutral observability primitives."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import json
import logging
import os
import sys
import time
from typing import Any, TextIO
from uuid import uuid4

import psycopg
from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
    OTLPMetricExporter,
)
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.metrics.view import (
    ExplicitBucketHistogramAggregation,
    View,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Span, Status, StatusCode


_REQUEST_ID: ContextVar[str | None] = ContextVar(
    "alert2ir_request_id", default=None
)
_PROCESSING_ID: ContextVar[str | None] = ContextVar(
    "alert2ir_processing_id", default=None
)
_ERROR_CATEGORY: ContextVar[str | None] = ContextVar(
    "alert2ir_error_category", default=None
)

_EVENT_FIELDS = frozenset(
    {
        "backend",
        "capabilities",
        "capability",
        "decision",
        "duration_ms",
        "error_category",
        "failure_stage",
        "http_method",
        "http_route",
        "http_status",
        "operation_reference",
        "operation_reference_kind",
        "outcome",
        "persistence",
        "processing_id",
        "request_id",
        "target_count",
    }
)
_BACKENDS = frozenset({"mock", "velociraptor"})
_CAPABILITIES = frozenset({"process.list"})
_DECISIONS = frozenset({"investigate", "no_action", "unknown"})
_OUTCOMES = frozenset({"success", "timeout", "error"})
_SAFE_SPAN_ATTRIBUTES = frozenset(
    {
        "alert2ir.backend",
        "alert2ir.capability",
        "alert2ir.decision",
        "alert2ir.error.category",
        "alert2ir.outcome",
        "alert2ir.target_count",
        "db.operation.name",
        "db.system.name",
        "http.method",
        "http.request.method",
        "http.response.status_code",
        "http.route",
        "http.status_code",
    }
)

_PROCESSING_BUCKETS = (
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
)
_PERSISTENCE_BUCKETS = (
    0.005,
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
)


def bounded_backend(value: str) -> str:
    """Return a controlled backend metric/log value."""

    return value if value in _BACKENDS else "other"


def bounded_capability(values: tuple[str, ...]) -> str:
    """Return one controlled capability value for one backend execution."""

    if len(values) == 1 and values[0] in _CAPABILITIES:
        return values[0]
    return "other"


def outcome_for_error(category: str) -> str:
    return "timeout" if category.endswith("_timeout") else "error"


def classify_error(error: BaseException, *, stage: str) -> str:
    """Map concrete failures into the shared bounded telemetry vocabulary."""

    # Imports remain local so backend modules can depend on this module without a
    # module-initialization cycle.
    from alert2ir.backends.router import (
        AmbiguousBackendError,
        UnsupportedCapabilitiesError,
    )
    from alert2ir.backends.velociraptor import (
        VelociraptorCollectionError,
        VelociraptorTargetError,
    )

    if isinstance(error, UnsupportedCapabilitiesError):
        return "routing_unsupported"
    if isinstance(error, AmbiguousBackendError):
        return "routing_ambiguous"
    if isinstance(error, VelociraptorTargetError):
        return "backend_target"
    if isinstance(error, TimeoutError):
        return "backend_timeout" if stage == "backend" else "persistence_timeout"
    if isinstance(error, VelociraptorCollectionError):
        if error.args == ("Velociraptor collection exceeded its local deadline",):
            return "backend_timeout"
        return "backend_execution"
    if stage == "backend":
        return "backend_execution"
    if stage == "persistence":
        if isinstance(error, psycopg.errors.UniqueViolation):
            return "persistence_constraint"
        if isinstance(error, psycopg.errors.QueryCanceled):
            return "persistence_timeout"
        if isinstance(error, (psycopg.OperationalError, psycopg.InterfaceError)):
            return "persistence_unavailable"
        if isinstance(error, ValueError):
            return "persistence_mapping"
        return "persistence_internal"
    return "internal_error"


@contextmanager
def request_context(request_id: str) -> Iterator[None]:
    """Set and reliably reset request-scoped correlation values."""

    request_token = _REQUEST_ID.set(request_id)
    processing_token = _PROCESSING_ID.set(None)
    error_token = _ERROR_CATEGORY.set(None)
    try:
        yield
    finally:
        _ERROR_CATEGORY.reset(error_token)
        _PROCESSING_ID.reset(processing_token)
        _REQUEST_ID.reset(request_token)


def current_request_id() -> str | None:
    return _REQUEST_ID.get()


def current_processing_id() -> str | None:
    return _PROCESSING_ID.get()


def current_error_category() -> str | None:
    return _ERROR_CATEGORY.get()


def set_processing_id(value: str) -> None:
    _PROCESSING_ID.set(value)


def set_error_category(value: str) -> None:
    _ERROR_CATEGORY.set(value)


class JsonEventLogger:
    """Write one controlled JSON object for each application event."""

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def emit(self, event: str, *, level: int = logging.INFO, **fields: Any) -> None:
        unknown = set(fields) - _EVENT_FIELDS
        if unknown:
            raise ValueError(f"unsupported observability fields: {sorted(unknown)!r}")

        payload: dict[str, Any] = {
            "schema_version": "1",
            "timestamp": datetime.now(timezone.utc).isoformat(
                timespec="milliseconds"
            ).replace("+00:00", "Z"),
            "level": logging.getLevelName(level),
            "event": event,
        }
        request_id = current_request_id()
        processing_id = current_processing_id()
        if request_id is not None:
            payload["request_id"] = request_id
        if processing_id is not None:
            payload["processing_id"] = processing_id

        span_context = trace.get_current_span().get_span_context()
        if span_context.is_valid:
            payload["trace_id"] = f"{span_context.trace_id:032x}"
            payload["span_id"] = f"{span_context.span_id:016x}"

        payload.update(
            {key: value for key, value in fields.items() if value is not None}
        )
        self._logger.log(
            level,
            json.dumps(payload, separators=(",", ":"), sort_keys=True),
        )


class _SanitizedReadableSpan:
    """Read-only exported-span view containing only reviewed safe telemetry."""

    def __init__(self, span: ReadableSpan) -> None:
        self.name = span.name
        self.context = span.context
        self.parent = span.parent
        self.resource = span.resource
        self.kind = span.kind
        self.start_time = span.start_time
        self.end_time = span.end_time
        self.instrumentation_scope = span.instrumentation_scope
        self.attributes = {
            key: value
            for key, value in span.attributes.items()
            if key in _SAFE_SPAN_ATTRIBUTES
        }
        self.events = ()
        self.links = ()
        self.status = (
            Status(StatusCode.ERROR)
            if span.status.status_code == StatusCode.ERROR
            else span.status
        )
        self.dropped_attributes = 0
        self.dropped_events = 0
        self.dropped_links = 0

    def get_span_context(self):
        return self.context


class SanitizingSpanProcessor(SpanProcessor):
    """Apply the Alert2IR span allowlist before delegating to an exporter."""

    def __init__(self, delegate: SpanProcessor) -> None:
        self._delegate = delegate

    def on_start(self, span: Span, parent_context=None) -> None:
        self._delegate.on_start(span, parent_context)

    def on_end(self, span: ReadableSpan) -> None:
        self._delegate.on_end(_SanitizedReadableSpan(span))  # type: ignore[arg-type]

    def shutdown(self) -> None:
        self._delegate.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self._delegate.force_flush(timeout_millis)


def make_event_logger(
    *,
    stream: TextIO | None = None,
    name: str = "alert2ir.events",
) -> JsonEventLogger:
    """Create an isolated standard-library logger for newline-delimited JSON."""

    logger = logging.getLogger(name)
    logger.handlers.clear()
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return JsonEventLogger(logger)


class ApplicationObservability:
    """Small application-facing facade over structured events and OTel APIs."""

    def __init__(
        self,
        *,
        tracer_provider: trace.TracerProvider,
        meter_provider: metrics.MeterProvider,
        event_logger: JsonEventLogger,
    ) -> None:
        self.tracer_provider = tracer_provider
        self.meter_provider = meter_provider
        self.events = event_logger
        self.tracer = tracer_provider.get_tracer("alert2ir", "1")
        meter = meter_provider.get_meter("alert2ir", "1")
        self._processing = meter.create_counter(
            "alert2ir.processing",
            unit="1",
            description="Alert processing attempts",
        )
        self._processing_duration = meter.create_histogram(
            "alert2ir.processing.duration",
            unit="s",
            description="Alert processing duration",
        )
        self._backend = meter.create_counter(
            "alert2ir.backend.executions",
            unit="1",
            description="Investigation backend executions",
        )
        self._backend_duration = meter.create_histogram(
            "alert2ir.backend.duration",
            unit="s",
            description="Investigation backend duration",
        )
        self._persistence = meter.create_counter(
            "alert2ir.persistence.operations",
            unit="1",
            description="Persistence operations",
        )
        self._persistence_duration = meter.create_histogram(
            "alert2ir.persistence.duration",
            unit="s",
            description="Persistence duration",
        )

    @staticmethod
    def monotonic() -> float:
        return time.perf_counter()

    @contextmanager
    def span(
        self,
        name: str,
        attributes: Mapping[str, str | int] | None = None,
    ) -> Iterator[Span]:
        with self.tracer.start_as_current_span(
            name,
            attributes=attributes,
            record_exception=False,
            set_status_on_exception=False,
        ) as span:
            yield span

    @staticmethod
    def finish_span(
        span: Span,
        *,
        outcome: str,
        error_category: str | None = None,
    ) -> None:
        span.set_attribute("alert2ir.outcome", outcome)
        if error_category is not None:
            span.set_attribute("alert2ir.error.category", error_category)
            span.set_status(Status(StatusCode.ERROR))

    @staticmethod
    def _metric_attributes(
        base: Mapping[str, str], error_category: str | None
    ) -> dict[str, str]:
        attributes = dict(base)
        if error_category is not None:
            attributes["error_category"] = error_category
        return attributes

    def record_processing(
        self,
        *,
        duration_seconds: float,
        decision: str,
        outcome: str,
        error_category: str | None = None,
    ) -> None:
        attributes = self._metric_attributes(
            {
                "decision": decision if decision in _DECISIONS else "unknown",
                "outcome": outcome if outcome in _OUTCOMES else "error",
            },
            error_category,
        )
        self._processing.add(1, attributes)
        self._processing_duration.record(duration_seconds, attributes)

    def record_backend(
        self,
        *,
        duration_seconds: float,
        backend: str,
        capability: str,
        outcome: str,
        error_category: str | None = None,
    ) -> None:
        attributes = self._metric_attributes(
            {
                "backend": bounded_backend(backend),
                "capability": capability if capability in _CAPABILITIES else "other",
                "outcome": outcome if outcome in _OUTCOMES else "error",
            },
            error_category,
        )
        self._backend.add(1, attributes)
        self._backend_duration.record(duration_seconds, attributes)

    def record_persistence(
        self,
        *,
        duration_seconds: float,
        outcome: str,
        error_category: str | None = None,
    ) -> None:
        attributes = self._metric_attributes(
            {
                "operation": "save",
                "outcome": outcome if outcome in _OUTCOMES else "error",
            },
            error_category,
        )
        self._persistence.add(1, attributes)
        self._persistence_duration.record(duration_seconds, attributes)

    def backend_operation_submitted(self, reference: str) -> None:
        self.events.emit(
            "backend.operation.submitted",
            backend="velociraptor",
            operation_reference_kind="flow_id",
            operation_reference=reference,
        )


def metric_views() -> tuple[View, ...]:
    return (
        View(
            instrument_name="alert2ir.processing.duration",
            aggregation=ExplicitBucketHistogramAggregation(_PROCESSING_BUCKETS),
        ),
        View(
            instrument_name="alert2ir.backend.duration",
            aggregation=ExplicitBucketHistogramAggregation(_PROCESSING_BUCKETS),
        ),
        View(
            instrument_name="alert2ir.persistence.duration",
            aggregation=ExplicitBucketHistogramAggregation(_PERSISTENCE_BUCKETS),
        ),
    )


def no_op_observability() -> ApplicationObservability:
    """Return isolated no-export telemetry for direct unit/domain construction."""

    logger = logging.getLogger(f"alert2ir.events.noop.{uuid4().hex}")
    logger.addHandler(logging.NullHandler())
    logger.propagate = False
    return ApplicationObservability(
        tracer_provider=trace.NoOpTracerProvider(),
        meter_provider=metrics.NoOpMeterProvider(),
        event_logger=JsonEventLogger(logger),
    )


def configure_observability() -> ApplicationObservability:
    """Configure in-process instrumentation and optional explicit OTLP export."""

    event_logger = make_event_logger()
    resource = Resource({"service.name": "alert2ir"})
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    if not endpoint:
        return ApplicationObservability(
            tracer_provider=TracerProvider(resource=resource),
            meter_provider=MeterProvider(
                resource=resource,
                views=metric_views(),
            ),
            event_logger=event_logger,
        )

    protocol = os.environ.get("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
    if protocol != "grpc":
        raise RuntimeError("Alert2IR OTLP export requires the 'grpc' protocol")

    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(
        SanitizingSpanProcessor(
            BatchSpanProcessor(
                OTLPSpanExporter(endpoint=endpoint, timeout=3.0),
                max_queue_size=512,
                schedule_delay_millis=5000,
                max_export_batch_size=256,
                export_timeout_millis=3000,
            )
        )
    )
    metric_reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(endpoint=endpoint, timeout=3.0),
        export_interval_millis=10000,
        export_timeout_millis=3000,
    )
    meter_provider = MeterProvider(
        resource=resource,
        metric_readers=(metric_reader,),
        views=metric_views(),
    )
    return ApplicationObservability(
        tracer_provider=tracer_provider,
        meter_provider=meter_provider,
        event_logger=event_logger,
    )
