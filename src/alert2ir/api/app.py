"""FastAPI application factory for the canonical Alert2IR boundary."""

from uuid import uuid4

from fastapi import FastAPI, Request
from opentelemetry import metrics
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from fastapi.responses import JSONResponse

from alert2ir.api.schemas import (
    AlertProcessingResponse,
    ApiErrorResponse,
    CanonicalAlertRequest,
)
from alert2ir.application import PersistentAlertProcessor
from alert2ir.backends import AmbiguousBackendError, UnsupportedCapabilitiesError
from alert2ir.observability import (
    ApplicationObservability,
    current_error_category,
    current_processing_id,
    no_op_observability,
    request_context,
    set_error_category,
)


def _error_response(status_code: int, error: ApiErrorResponse) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=error.model_dump(mode="json"))


def create_app(
    processor: PersistentAlertProcessor,
    observability: ApplicationObservability | None = None,
) -> FastAPI:
    configured_observability = observability or getattr(
        processor,
        "observability",
        None,
    )
    if configured_observability is None:
        configured_observability = no_op_observability()
    app = FastAPI()

    @app.middleware("http")
    async def correlate_request(request: Request, call_next):
        request_id = str(uuid4())
        started = configured_observability.monotonic()
        with request_context(request_id):
            try:
                response = await call_next(request)
            except Exception:
                set_error_category("internal_error")
                response = JSONResponse(
                    status_code=500,
                    content={"detail": "Internal Server Error"},
                )

            if request.method == "POST" and request.url.path == "/v1/alerts":
                category = current_error_category()
                if response.status_code == 422:
                    category = "input_validation"
                elif response.status_code >= 500 and category is None:
                    category = "internal_error"
                elif response.status_code == 409 and category is None:
                    category = "routing_unsupported"
                outcome = "success" if response.status_code < 400 else "error"
                duration = configured_observability.monotonic() - started
                configured_observability.events.emit(
                    "request.finished",
                    http_method="POST",
                    http_route="/v1/alerts",
                    http_status=response.status_code,
                    outcome=outcome,
                    error_category=category,
                    processing_id=current_processing_id(),
                    duration_ms=round(duration * 1000, 3),
                )
            response.headers["X-Request-ID"] = request_id
            return response

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post(
        "/v1/alerts",
        response_model=AlertProcessingResponse,
        responses={
            409: {"model": ApiErrorResponse},
            500: {
                "description": (
                    "Internal processing failure, including ambiguous backend "
                    "routing or persistence failure."
                )
            },
        },
    )
    async def process_alert(
        alert_request: CanonicalAlertRequest,
    ) -> AlertProcessingResponse | JSONResponse:
        try:
            record = processor.process(alert_request.to_domain())
        except UnsupportedCapabilitiesError as error:
            set_error_category("routing_unsupported")
            return _error_response(
                409,
                ApiErrorResponse(
                    code="unsupported_capabilities",
                    message=str(error),
                    requested_capabilities=error.requested_capabilities,
                    eligible_backends=None,
                ),
            )
        except AmbiguousBackendError as error:
            set_error_category("routing_ambiguous")
            return _error_response(
                500,
                ApiErrorResponse(
                    code="ambiguous_backend",
                    message=str(error),
                    requested_capabilities=error.requested_capabilities,
                    eligible_backends=error.eligible_backends,
                ),
            )

        return AlertProcessingResponse.from_application(record)

    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=configured_observability.tracer_provider,
        # Framework HTTP metrics carry host/server attributes that are outside
        # the bounded WS12 application metric contract. Custom metrics below
        # retain the reviewed decision/backend/persistence dimensions only.
        meter_provider=metrics.NoOpMeterProvider(),
        excluded_urls=".*/healthz",
        http_capture_headers_server_request=[],
        http_capture_headers_server_response=[],
        http_capture_headers_sanitize_fields=[".*"],
        exclude_spans=["receive", "send"],
    )
    return app
