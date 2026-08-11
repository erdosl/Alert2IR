"""FastAPI application factory for the canonical Alert2IR boundary."""

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from alert2ir.api.schemas import (
    AlertProcessingResponse,
    ApiErrorResponse,
    CanonicalAlertRequest,
)
from alert2ir.application import PersistentAlertProcessor
from alert2ir.backends import AmbiguousBackendError, UnsupportedCapabilitiesError


def _error_response(status_code: int, error: ApiErrorResponse) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=error.model_dump(mode="json"))


def create_app(processor: PersistentAlertProcessor) -> FastAPI:
    app = FastAPI()

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
        request: CanonicalAlertRequest,
    ) -> AlertProcessingResponse | JSONResponse:
        try:
            record = processor.process(request.to_domain())
        except UnsupportedCapabilitiesError as error:
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

    return app
