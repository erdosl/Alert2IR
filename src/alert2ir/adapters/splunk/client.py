"""One-shot private HTTP delivery of already-canonical Alert2IR alerts."""

from __future__ import annotations

from enum import StrEnum
import math
import re
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

import httpx2
from pydantic import BaseModel, ConfigDict, Field

from alert2ir.api.schemas import CanonicalAlertRequest
from alert2ir.core.models import CanonicalAlert


DEFAULT_REQUEST_TIMEOUT_SECONDS = 5.0
MAXIMUM_UPSTREAM_RESPONSE_BYTES = 65_536
MAXIMUM_STATUS_URL_LENGTH = 2_048

_SAFE_ERROR_CODE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_PROCESSING_STATES = frozenset(
    {
        "accepted",
        "planned",
        "submitting",
        "submitted",
        "completed",
        "failed",
        "recovery_required",
    }
)


class DeliveryClassification(StrEnum):
    COMPLETED = "completed"
    ACCEPTED = "accepted"
    PERMANENT_FAILURE = "permanent_failure"
    DURABLE_FAILURE = "durable_failure"
    TRANSIENT_FAILURE = "transient_failure"


class Alert2IRDeliveryResult(BaseModel):
    """Bounded information needed by a future Splunk sender."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    classification: DeliveryClassification
    upstream_status: int | None = Field(default=None, ge=100, le=599)
    processing_id: UUID | None = None
    state: Literal[
        "accepted",
        "planned",
        "submitting",
        "submitted",
        "completed",
        "failed",
        "recovery_required",
    ] | None = None
    status_url: str | None = Field(
        default=None,
        max_length=MAXIMUM_STATUS_URL_LENGTH,
    )
    replayed: bool = False
    decision_outcome: Literal["no_action", "investigate"] | None = None
    error_code: str | None = Field(
        default=None,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_]{0,63}$",
    )
    retryable: bool
    acceptance_unknown: bool


def _bounded_json_object(response: httpx2.Response) -> dict[str, object]:
    if len(response.content) > MAXIMUM_UPSTREAM_RESPONSE_BYTES:
        return {}
    try:
        value = response.json()
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _processing_id(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(UUID(value))
    except ValueError:
        return None


def _bounded_visible(value: object, maximum: int) -> str | None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or not value.isprintable()
    ):
        return None
    return value


def _status_url(response: httpx2.Response, body: dict[str, object]) -> str | None:
    from_body = _bounded_visible(body.get("status_url"), MAXIMUM_STATUS_URL_LENGTH)
    if from_body is not None:
        return from_body
    locations = response.headers.get_list("Location")
    if len(locations) != 1:
        return None
    return _bounded_visible(locations[0], MAXIMUM_STATUS_URL_LENGTH)


def _state(body: dict[str, object]) -> str | None:
    value = body.get("state")
    return value if isinstance(value, str) and value in _PROCESSING_STATES else None


def _decision_outcome(
    body: dict[str, object],
) -> Literal["no_action", "investigate"] | None:
    decision = body.get("decision")
    if not isinstance(decision, dict):
        return None
    outcome = decision.get("outcome")
    if outcome in {"no_action", "investigate"}:
        return outcome
    return None


def _error_code(body: dict[str, object]) -> str | None:
    for field_name in ("code", "error_category"):
        value = body.get(field_name)
        if isinstance(value, str) and _SAFE_ERROR_CODE_PATTERN.fullmatch(value):
            return value
    return None


def _replayed(response: httpx2.Response) -> bool:
    values = response.headers.get_list("Idempotency-Replayed")
    return len(values) == 1 and values[0].lower() == "true"


def _response_fields(response: httpx2.Response) -> dict[str, object]:
    body = _bounded_json_object(response)
    return {
        "upstream_status": response.status_code,
        "processing_id": _processing_id(body.get("processing_id")),
        "state": _state(body),
        "status_url": _status_url(response, body),
        "replayed": _replayed(response),
        "decision_outcome": _decision_outcome(body),
        "error_code": _error_code(body),
    }


def _classify_response(response: httpx2.Response) -> Alert2IRDeliveryResult:
    fields = _response_fields(response)
    status = response.status_code
    if status == 200:
        return Alert2IRDeliveryResult(
            classification=DeliveryClassification.COMPLETED,
            retryable=False,
            acceptance_unknown=False,
            **fields,
        )
    if status == 202:
        return Alert2IRDeliveryResult(
            classification=DeliveryClassification.ACCEPTED,
            retryable=False,
            acceptance_unknown=False,
            **fields,
        )
    if status in {400, 409, 422}:
        return Alert2IRDeliveryResult(
            classification=DeliveryClassification.PERMANENT_FAILURE,
            retryable=False,
            acceptance_unknown=False,
            **fields,
        )
    if status == 500:
        durable = (
            fields["processing_id"] is not None
            or fields["status_url"] is not None
        )
        if durable:
            return Alert2IRDeliveryResult(
                classification=DeliveryClassification.DURABLE_FAILURE,
                retryable=False,
                acceptance_unknown=False,
                **fields,
            )
        fields["error_code"] = "upstream_internal_failure"
        return Alert2IRDeliveryResult(
            classification=DeliveryClassification.TRANSIENT_FAILURE,
            retryable=True,
            acceptance_unknown=True,
            **fields,
        )
    if status == 503:
        if fields["error_code"] is None:
            fields["error_code"] = "upstream_unavailable"
        return Alert2IRDeliveryResult(
            classification=DeliveryClassification.TRANSIENT_FAILURE,
            retryable=True,
            acceptance_unknown=False,
            **fields,
        )
    fields["error_code"] = "unexpected_upstream_status"
    return Alert2IRDeliveryResult(
        classification=DeliveryClassification.TRANSIENT_FAILURE,
        retryable=True,
        acceptance_unknown=True,
        **fields,
    )


class Alert2IRClient:
    """Send one canonical alert once; never retry and never poll."""

    def __init__(
        self,
        *,
        base_url: str,
        timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("base URL must be an HTTP(S) origin")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout must be finite and greater than zero")

        self._client = httpx2.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=httpx2.Timeout(float(timeout_seconds)),
            transport=transport,
            follow_redirects=False,
            trust_env=False,
        )

    async def submit_alert(
        self,
        alert: CanonicalAlert,
        *,
        idempotency_key: str,
    ) -> Alert2IRDeliveryResult:
        if (
            not isinstance(idempotency_key, str)
            or not 1 <= len(idempotency_key) <= 128
            or any(
                not 0x21 <= ord(character) <= 0x7E
                for character in idempotency_key
            )
        ):
            raise ValueError("idempotency key must be 1-128 visible ASCII characters")

        payload = CanonicalAlertRequest.from_domain(alert).model_dump(mode="json")
        try:
            response = await self._client.post(
                "/v1/alerts",
                json=payload,
                headers={"Idempotency-Key": idempotency_key},
            )
        except httpx2.TimeoutException:
            return Alert2IRDeliveryResult(
                classification=DeliveryClassification.TRANSIENT_FAILURE,
                error_code="upstream_timeout",
                retryable=True,
                acceptance_unknown=True,
            )
        except httpx2.ConnectError:
            return Alert2IRDeliveryResult(
                classification=DeliveryClassification.TRANSIENT_FAILURE,
                error_code="upstream_connection_failed",
                retryable=True,
                acceptance_unknown=False,
            )
        except httpx2.RequestError:
            return Alert2IRDeliveryResult(
                classification=DeliveryClassification.TRANSIENT_FAILURE,
                error_code="upstream_transport_failure",
                retryable=True,
                acceptance_unknown=True,
            )
        return _classify_response(response)

    async def aclose(self) -> None:
        await self._client.aclose()
