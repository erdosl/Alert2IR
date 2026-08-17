"""FastAPI boundary for durable, idempotent alert processing."""

import asyncio
from contextlib import asynccontextmanager

from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from opentelemetry import metrics
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from alert2ir.api.schemas import (
    AlertProcessingResponse,
    ApiErrorResponse,
    CanonicalAlertRequest,
)
from alert2ir.application import (
    IdempotencyConflictError,
    PersistenceUnavailableError,
    PersistentAlertProcessor,
    ProcessingState,
)
from alert2ir.backends import AmbiguousBackendError, UnsupportedCapabilitiesError
from alert2ir.observability import (
    ApplicationObservability,
    current_error_category,
    current_processing_id,
    no_op_observability,
    request_context,
    set_error_category,
    set_processing_id,
)


_DURABLE_CLIENT_FAILURES = {
    "unsupported_capability": (
        409,
        "no configured backend supports the required capability",
    ),
}


def _error_response(
    status_code: int,
    error: ApiErrorResponse,
    *,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=error.model_dump(mode="json", exclude_none=True),
        headers=headers,
    )


def _idempotency_key(request: Request) -> tuple[str | None, JSONResponse | None]:
    values = request.headers.getlist("idempotency-key")
    if not values:
        return None, _error_response(
            400,
            ApiErrorResponse(
                code="idempotency_key_required",
                message="Idempotency-Key header is required",
            ),
        )
    value = values[0]
    if (
        len(values) != 1
        or not 1 <= len(value) <= 128
        or any(not 0x21 <= ord(character) <= 0x7E for character in value)
    ):
        return None, _error_response(
            400,
            ApiErrorResponse(
                code="invalid_idempotency_key",
                message=(
                    "Idempotency-Key must contain 1-128 visible ASCII characters"
                ),
            ),
        )
    return value, None


def _set_request_correlation(
    request: Request,
    *,
    processing_id: UUID | str | None = None,
    error_category: str | None = None,
) -> None:
    """Share endpoint correlation with the outer ASGI middleware task."""

    if processing_id is not None:
        value = str(processing_id)
        set_processing_id(value)
        request.state.alert2ir_processing_id = value
    if error_category is not None:
        set_error_category(error_category)
        request.state.alert2ir_error_category = current_error_category()


def _public_processing_response(record, *, replayed: bool) -> JSONResponse:
    public = AlertProcessingResponse.from_application(record)
    headers = {"Location": public.status_url}
    if replayed:
        headers["Idempotency-Replayed"] = "true"

    if record.state is ProcessingState.COMPLETED:
        status_code = 200
    elif record.state is ProcessingState.FAILED:
        durable_client_failure = _DURABLE_CLIENT_FAILURES.get(
            record.error_category
        )
        if durable_client_failure is not None:
            status_code, message = durable_client_failure
            return _error_response(
                status_code,
                ApiErrorResponse(
                    code=record.error_category,
                    message=message,
                    processing_id=record.processing_id,
                    state=record.state,
                    status_url=public.status_url,
                ),
                headers=headers,
            )
        status_code = 500
    else:
        status_code = 202
    return JSONResponse(
        status_code=status_code,
        content=public.model_dump(mode="json"),
        headers=headers,
    )


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

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        task = asyncio.create_task(asyncio.to_thread(processor.reconcile_once))

        def consume_result(completed: asyncio.Task) -> None:
            try:
                completed.result()
            except (Exception, asyncio.CancelledError):
                # Startup reconciliation is deliberately failure-isolated from
                # liveness and readiness; its bounded metrics carry the outcome.
                return

        task.add_done_callback(consume_result)
        yield
        if not task.done():
            task.cancel()

    app = FastAPI(lifespan=lifespan)

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
                category = getattr(
                    request.state,
                    "alert2ir_error_category",
                    current_error_category(),
                )
                if response.status_code == 422:
                    category = "validation_error"
                elif response.status_code >= 500 and category is None:
                    category = "internal_error"
                outcome = "success" if response.status_code < 400 else "error"
                duration = configured_observability.monotonic() - started
                configured_observability.events.emit(
                    "request.finished",
                    http_method="POST",
                    http_route="/v1/alerts",
                    http_status=response.status_code,
                    outcome=outcome,
                    error_category=category,
                    processing_id=getattr(
                        request.state,
                        "alert2ir_processing_id",
                        current_processing_id(),
                    ),
                    duration_ms=round(duration * 1000, 3),
                )
            response.headers["X-Request-ID"] = request_id
            return response

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get(
        "/readyz",
        response_model=None,
        responses={503: {"description": "Persistence is not ready."}},
    )
    def readyz() -> dict[str, str] | JSONResponse:
        try:
            processor.check_readiness()
        except Exception:
            return JSONResponse(status_code=503, content={"status": "not_ready"})
        return {"status": "ready"}

    @app.get(
        "/v1/processings/{processing_id}",
        response_model=AlertProcessingResponse,
        responses={404: {"model": ApiErrorResponse}},
    )
    def get_processing(processing_id: UUID) -> AlertProcessingResponse | JSONResponse:
        try:
            record = processor.get(processing_id)
        except Exception:
            set_error_category("persistence_failed")
            return _error_response(
                503,
                ApiErrorResponse(
                    code="persistence_failed",
                    message="processing status is temporarily unavailable",
                ),
            )
        if record is None:
            return _error_response(
                404,
                ApiErrorResponse(
                    code="processing_not_found",
                    message="processing was not found",
                ),
            )
        return AlertProcessingResponse.from_application(record)

    @app.post(
        "/v1/alerts",
        response_model=AlertProcessingResponse,
        openapi_extra={
            "parameters": [
                {
                    "name": "Idempotency-Key",
                    "in": "header",
                    "required": True,
                    "schema": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 128,
                        "pattern": r"^[!-~]+$",
                    },
                    "description": (
                        "Opaque case-sensitive caller retry identity; visible ASCII only."
                    ),
                }
            ]
        },
        responses={
            202: {"model": AlertProcessingResponse},
            400: {"model": ApiErrorResponse},
            409: {"model": ApiErrorResponse},
            503: {"model": ApiErrorResponse},
            500: {"description": "Durable terminal or internal failure."},
        },
    )
    def process_alert(
        alert_request: CanonicalAlertRequest,
        request: Request,
    ) -> JSONResponse:
        key, key_error = _idempotency_key(request)
        if key_error is not None:
            configured_observability.record_idempotency("error")
            _set_request_correlation(
                request,
                error_category=(
                    "idempotency_key_required"
                    if not request.headers.getlist("idempotency-key")
                    else "invalid_idempotency_key"
                ),
            )
            return key_error
        assert key is not None
        try:
            outcome = processor.process(alert_request.to_domain(), key)
        except IdempotencyConflictError as error:
            _set_request_correlation(
                request,
                processing_id=error.processing_id,
                error_category="idempotency_conflict",
            )
            return _error_response(
                409,
                ApiErrorResponse(
                    code="idempotency_conflict",
                    message="idempotency key is already bound to another request",
                ),
            )
        except PersistenceUnavailableError:
            _set_request_correlation(
                request,
                error_category="persistence_failed",
            )
            return _error_response(
                503,
                ApiErrorResponse(
                    code="persistence_failed",
                    message="durable processing is temporarily unavailable",
                ),
            )
        except UnsupportedCapabilitiesError as error:
            processing_id = getattr(error, "processing_id", None)
            _set_request_correlation(
                request,
                processing_id=processing_id,
                error_category="unsupported_capability",
            )
            status_url = (
                None
                if processing_id is None
                else f"/v1/processings/{processing_id}"
            )
            return _error_response(
                409,
                ApiErrorResponse(
                    code="unsupported_capability",
                    message="no configured backend supports the required capability",
                    requested_capabilities=error.requested_capabilities,
                    processing_id=processing_id,
                    state=getattr(error, "processing_state", None),
                    status_url=status_url,
                ),
                headers=None if status_url is None else {"Location": status_url},
            )
        except AmbiguousBackendError as error:
            processing_id = getattr(error, "processing_id", None)
            _set_request_correlation(
                request,
                processing_id=processing_id,
                error_category="backend_selection_error",
            )
            status_url = (
                None
                if processing_id is None
                else f"/v1/processings/{processing_id}"
            )
            return _error_response(
                500,
                ApiErrorResponse(
                    code="backend_selection_error",
                    message="backend selection was ambiguous",
                    requested_capabilities=error.requested_capabilities,
                    eligible_backends=error.eligible_backends,
                    processing_id=processing_id,
                    state=getattr(error, "processing_state", None),
                    status_url=status_url,
                ),
                headers=None if status_url is None else {"Location": status_url},
            )
        _set_request_correlation(
            request,
            processing_id=outcome.record.processing_id,
            error_category=outcome.record.error_category,
        )
        return _public_processing_response(
            outcome.record,
            replayed=outcome.replayed,
        )

    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=configured_observability.tracer_provider,
        meter_provider=metrics.NoOpMeterProvider(),
        excluded_urls=".*/healthz,.*/readyz",
        http_capture_headers_server_request=[],
        http_capture_headers_server_response=[],
        http_capture_headers_sanitize_fields=[".*"],
        exclude_spans=["receive", "send"],
    )
    return app
