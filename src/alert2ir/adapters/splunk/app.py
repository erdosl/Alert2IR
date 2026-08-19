"""Authenticated network boundary for bounded Splunk finding delivery."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
import json
from typing import Protocol

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from alert2ir.adapters.splunk.auth import (
    AuthenticationError,
    verify_signature,
    validate_shared_secret,
)
from alert2ir.adapters.splunk.client import (
    Alert2IRDeliveryResult,
    DeliveryClassification,
)
from alert2ir.adapters.splunk.mapping import canonicalize
from alert2ir.adapters.splunk.models import SplunkFinding
from alert2ir.core.models import CanonicalAlert


MAX_REQUEST_BODY_BYTES = 65_536


class AlertSubmitter(Protocol):
    async def submit_alert(
        self,
        alert: CanonicalAlert,
        *,
        idempotency_key: str,
    ) -> Alert2IRDeliveryResult:
        ...


def _system_clock() -> datetime:
    return datetime.now(timezone.utc)


def _error(status_code: int, error: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": error})


async def _bounded_body(request: Request) -> bytes | None:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_REQUEST_BODY_BYTES:
            return None
        body.extend(chunk)
    return bytes(body)


def _single_header(request: Request, name: str) -> str | None:
    values = request.headers.getlist(name)
    return values[0] if len(values) == 1 else None


def _is_json(request: Request) -> bool:
    values = request.headers.getlist("content-type")
    if len(values) != 1:
        return False
    return values[0].partition(";")[0].strip().lower() == "application/json"


def _reject_nonstandard_json_constant(_value: str) -> None:
    raise ValueError("non-standard JSON constant")


def _adapter_status(result: Alert2IRDeliveryResult) -> int:
    if result.classification is DeliveryClassification.COMPLETED:
        return 200
    if result.classification is DeliveryClassification.ACCEPTED:
        return 202
    if result.classification is DeliveryClassification.PERMANENT_FAILURE:
        if result.upstream_status in {400, 409, 422}:
            return result.upstream_status
        return 502
    if result.classification is DeliveryClassification.DURABLE_FAILURE:
        return 500
    if result.error_code == "upstream_timeout":
        return 504
    if result.upstream_status == 503:
        return 503
    return 502


def create_splunk_adapter_app(
    *,
    shared_secret: bytes,
    alert2ir_client: AlertSubmitter,
    clock: Callable[[], datetime] = _system_clock,
) -> FastAPI:
    """Construct a stateless source gateway from explicit dependencies."""

    configured_secret = validate_shared_secret(shared_secret)
    app = FastAPI()

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post(
        "/v1/splunk/findings",
        response_model=Alert2IRDeliveryResult,
        responses={
            400: {"description": "Authenticated malformed JSON."},
            401: {"description": "Authentication failed."},
            413: {"description": "Request body is too large."},
            415: {"description": "Unsupported media type."},
            422: {"description": "Authenticated invalid Splunk finding."},
            502: {"model": Alert2IRDeliveryResult},
            503: {"model": Alert2IRDeliveryResult},
            504: {"model": Alert2IRDeliveryResult},
        },
    )
    async def submit_finding(request: Request) -> JSONResponse:
        raw_body = await _bounded_body(request)
        if raw_body is None:
            return _error(413, "request_too_large")

        timestamp = _single_header(request, "x-alert2ir-timestamp")
        signature = _single_header(request, "x-alert2ir-signature")
        try:
            verify_signature(
                shared_secret=configured_secret,
                timestamp_header=timestamp,
                signature_header=signature,
                raw_body=raw_body,
                now=clock(),
            )
        except AuthenticationError:
            return _error(401, "authentication_failed")

        if not _is_json(request):
            return _error(415, "unsupported_media_type")
        try:
            decoded = json.loads(
                raw_body,
                parse_constant=_reject_nonstandard_json_constant,
            )
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return _error(400, "invalid_json")

        try:
            finding = SplunkFinding.model_validate(decoded)
            canonicalized = canonicalize(finding)
        except (ValidationError, ValueError, TypeError):
            return _error(422, "invalid_splunk_finding")

        # The HMAC window bounds wire replay. The finding key independently
        # gives Alert2IR stable logical duplicate suppression.
        result = await alert2ir_client.submit_alert(
            canonicalized.alert,
            idempotency_key=canonicalized.idempotency_key,
        )
        return JSONResponse(
            status_code=_adapter_status(result),
            content=result.model_dump(mode="json", exclude_none=True),
        )

    return app
