#!/usr/bin/env python3
"""Standalone Splunk custom alert action for Alert2IR finding delivery.

This file intentionally uses only the Python standard library.  It is packaged
for Splunk's embedded Python runtime and must not import the Alert2IR application
package, which is not present on the Splunk host.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
import gzip
from hashlib import sha256
import hmac
import http.client
import io
import json
import math
from pathlib import Path
import re
import socket
import sys
import time
from typing import Callable, Dict, Mapping, Optional, Sequence
import urllib.error
import urllib.parse
import urllib.request
from uuid import UUID


FINDING_SCHEMA = "alert2ir.splunk-finding.v1"
SIGNING_CONTEXT = b"alert2ir-splunk-v1\n"
SIGNATURE_VERSION = "v1"
WINDOWS_SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

MINIMUM_SECRET_BYTES = 32
MAXIMUM_SECRET_BYTES = 4_096
MAXIMUM_INVOCATION_BYTES = 65_536
MAX_COMPRESSED_RESULTS_BYTES = 65_536
MAX_DECOMPRESSED_RESULTS_BYTES = 65_536
MAXIMUM_FINDING_BODY_BYTES = 65_536
MAXIMUM_ADAPTER_RESPONSE_BYTES = 65_536
MAXIMUM_URL_LENGTH = 2_048
MAXIMUM_PATH_LENGTH = 4_096
HTTP_TIMEOUT_SECONDS = 5.0
MAXIMUM_ATTEMPTS = 3
RETRY_DELAYS_SECONDS = (1.0, 2.0)

RULE_TITLE_MAX_LENGTH = 256
HOSTNAME_MAX_LENGTH = 255
SOURCE_MAX_LENGTH = 512
SOURCETYPE_MAX_LENGTH = 128
PROCESS_GUID_MAX_LENGTH = 128
IMAGE_MAX_LENGTH = 1_024
EVENT_CODE_MAXIMUM = 65_535
RECORD_ID_MAXIMUM = 2**63 - 1
MINIMUM_UNIX_EPOCH = Decimal("-62135596800")
MAXIMUM_UNIX_EPOCH_EXCLUSIVE = Decimal("253402300800")

EXPECTED_RESULT_FIELDS = (
    "_time",
    "Computer",
    "host",
    "source",
    "sourcetype",
    "EventCode",
    "RecordID",
    "ProcessGuid",
    "Image",
    "ParentImage",
    "TargetFilename",
)
SPLUNK_MULTIVALUE_RESULT_FIELDS = tuple(
    "__mv_" + field for field in EXPECTED_RESULT_FIELDS
)
SIGMA_LEVELS = frozenset(("informational", "low", "medium", "high", "critical"))

_TIMESTAMP_PATTERN = re.compile(r"(?:0|[1-9][0-9]{0,11})\Z")
_NUMERIC_EVENT_TIME_PATTERN = re.compile(
    r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)\Z"
)
_RFC3339_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z"
)
_HOSTNAME_PATTERN = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\Z")
_SAFE_ERROR_CODE_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class ActionError(Exception):
    """Base class for sanitized custom-action failures."""


class ActionInputError(ActionError):
    """The invocation or projected result row is invalid."""


class ActionConfigurationError(ActionError):
    """Reviewed action configuration or secret material is invalid."""


class ConnectionFailure(ActionError):
    """The adapter could not be reached for one attempt."""


class RequestTimeout(ActionError):
    """The adapter request timed out with unknown acceptance."""


def _require_string(
    value: object,
    *,
    name: str,
    maximum: int,
    configuration_value: bool = False,
) -> str:
    error_type = ActionConfigurationError if configuration_value else ActionInputError
    if (
        not isinstance(value, str)
        or not value
        or not value.strip()
        or len(value) > maximum
        or not value.isprintable()
    ):
        raise error_type("{} is invalid".format(name))
    return value


def _canonical_uuid(value: object) -> str:
    text = _require_string(
        value,
        name="rule_id",
        maximum=36,
        configuration_value=True,
    )
    try:
        return str(UUID(text))
    except (ValueError, AttributeError) as error:
        raise ActionConfigurationError("rule_id must be a UUID") from error


def _validate_adapter_url(value: object) -> str:
    url = _require_string(
        value,
        name="adapter_url",
        maximum=MAXIMUM_URL_LENGTH,
        configuration_value=True,
    )
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme not in ("http", "https")
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/v1/splunk/findings"
    ):
        raise ActionConfigurationError(
            "adapter_url must be an HTTP(S) /v1/splunk/findings URL"
        )
    return url


@dataclass(frozen=True)
class ActionConfiguration:
    """Reviewed per-saved-search values plus local sender configuration."""

    adapter_url: str
    secret_file: str
    rule_id: str
    rule_title: str
    sigma_level: str
    channel: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "adapter_url", _validate_adapter_url(self.adapter_url))
        object.__setattr__(self, "rule_id", _canonical_uuid(self.rule_id))
        _require_string(
            self.secret_file,
            name="secret_file",
            maximum=MAXIMUM_PATH_LENGTH,
            configuration_value=True,
        )
        if "\x00" in self.secret_file or not Path(self.secret_file).is_absolute():
            raise ActionConfigurationError("secret_file must be an absolute path")
        _require_string(
            self.rule_title,
            name="rule_title",
            maximum=RULE_TITLE_MAX_LENGTH,
            configuration_value=True,
        )
        if self.sigma_level not in SIGMA_LEVELS:
            raise ActionConfigurationError("sigma_level is unsupported")
        if self.channel != WINDOWS_SYSMON_CHANNEL:
            raise ActionConfigurationError("channel is unsupported")


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes
    headers: Mapping[str, str]


@dataclass(frozen=True)
class AdapterDisposition:
    category: str
    retryable: bool
    success: bool
    status: Optional[int]
    processing_id: Optional[str] = None
    replayed: bool = False
    error_code: Optional[str] = None


@dataclass(frozen=True)
class DeliveryOutcome:
    success: bool
    attempts: int
    category: str
    status: Optional[int]
    processing_id: Optional[str] = None
    replayed: bool = False
    error_code: Optional[str] = None


def _reject_nonstandard_json_constant(_value: str) -> None:
    raise ValueError("non-standard JSON constant")


def parse_invocation(raw_payload: bytes) -> dict:
    """Decode one bounded JSON custom-action payload from stdin bytes."""

    if not isinstance(raw_payload, bytes):
        raise ActionInputError("invocation must be bytes")
    if len(raw_payload) > MAXIMUM_INVOCATION_BYTES:
        raise ActionInputError("invocation is too large")
    try:
        value = json.loads(
            raw_payload,
            parse_constant=_reject_nonstandard_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ActionInputError("invocation is not valid JSON") from error
    if not isinstance(value, dict):
        raise ActionInputError("invocation must be a JSON object")
    return value


def results_file_from_invocation(invocation: Mapping[str, object]) -> Path:
    value = _require_string(
        invocation.get("results_file"),
        name="results file",
        maximum=MAXIMUM_PATH_LENGTH,
    )
    if "\x00" in value:
        raise ActionInputError("results file path is invalid")
    return Path(value)


def parse_configuration(invocation: Mapping[str, object]) -> ActionConfiguration:
    value = invocation.get("configuration")
    if not isinstance(value, dict):
        raise ActionConfigurationError("configuration is required")
    required = (
        "adapter_url",
        "secret_file",
        "rule_id",
        "rule_title",
        "sigma_level",
        "channel",
    )
    missing = [name for name in required if name not in value]
    if missing:
        raise ActionConfigurationError("required configuration is missing")
    try:
        return ActionConfiguration(**{name: value[name] for name in required})
    except TypeError as error:
        raise ActionConfigurationError("configuration values are invalid") from error


def read_single_result(path: Path) -> Dict[str, str]:
    """Read exactly one row from Splunk's bounded gzip CSV result artifact."""

    try:
        if not path.is_file():
            raise ActionInputError("results file does not exist")
        if path.stat().st_size > MAX_COMPRESSED_RESULTS_BYTES:
            raise ActionInputError("results file is too large")
        with path.open("rb") as compressed:
            with gzip.GzipFile(fileobj=compressed, mode="rb") as archive:
                payload = archive.read(MAX_DECOMPRESSED_RESULTS_BYTES + 1)
    except ActionInputError:
        raise
    except (OSError, EOFError) as error:
        raise ActionInputError("results file is unreadable") from error

    if len(payload) > MAX_DECOMPRESSED_RESULTS_BYTES:
        raise ActionInputError("results file is too large")
    try:
        text = payload.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
        fieldnames = tuple(reader.fieldnames or ())
        supported_field_sets = (
            EXPECTED_RESULT_FIELDS,
            EXPECTED_RESULT_FIELDS + SPLUNK_MULTIVALUE_RESULT_FIELDS,
        )
        if fieldnames not in supported_field_sets:
            raise ActionInputError("results file has unexpected projected fields")
        first = next(reader, None)
        second = next(reader, None)
    except (UnicodeDecodeError, csv.Error) as error:
        raise ActionInputError("results file contains malformed CSV") from error

    if first is None or second is not None:
        raise ActionInputError("results file must contain exactly one result row")
    if None in first or any(not isinstance(value, str) for value in first.values()):
        raise ActionInputError("results file contains malformed CSV")
    return {field: first[field] for field in EXPECTED_RESULT_FIELDS}


def _normalize_hostname_for_comparison(value: str) -> str:
    normalized = value.strip()
    if normalized.endswith("."):
        normalized = normalized[:-1]
    if (
        not normalized
        or len(normalized) > HOSTNAME_MAX_LENGTH
        or not normalized.isascii()
        or _HOSTNAME_PATTERN.fullmatch(normalized) is None
    ):
        raise ActionInputError("hostname is invalid")
    return normalized.lower()


def _validate_hostnames(computer: Optional[str], host: Optional[str]) -> None:
    normalized_computer = (
        None if computer is None else _normalize_hostname_for_comparison(computer)
    )
    normalized_host = None if host is None else _normalize_hostname_for_comparison(host)
    if normalized_computer is None and normalized_host is None:
        raise ActionInputError("Computer or host is required")
    if (
        normalized_computer is not None
        and normalized_host is not None
        and normalized_computer != normalized_host
    ):
        raise ActionInputError("Computer and host disagree")


def _validate_event_time(value: object) -> str:
    text = _require_string(value, name="_time", maximum=64)
    if _NUMERIC_EVENT_TIME_PATTERN.fullmatch(text) is not None:
        try:
            numeric = Decimal(text)
        except InvalidOperation as error:
            raise ActionInputError("_time is invalid") from error
        if not numeric.is_finite():
            raise ActionInputError("_time is invalid")
        if not MINIMUM_UNIX_EPOCH <= numeric < MAXIMUM_UNIX_EPOCH_EXCLUSIVE:
            raise ActionInputError("_time is outside the supported range")
        return text
    if _RFC3339_PATTERN.fullmatch(text) is None:
        raise ActionInputError("_time is invalid")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise ActionInputError("_time is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ActionInputError("_time is invalid")
    return text


def _decimal_integer(value: object, name: str, maximum: int) -> str:
    text = _require_string(value, name=name, maximum=32)
    if re.fullmatch(r"[0-9]+", text) is None:
        raise ActionInputError("{} must be a decimal integer".format(name))
    parsed = int(text)
    if parsed < 1 or parsed > maximum:
        raise ActionInputError("{} is outside the supported range".format(name))
    return str(parsed)


def _optional_result_value(
    row: Mapping[str, str],
    name: str,
    maximum: int,
) -> Optional[str]:
    value = row.get(name, "")
    if value == "":
        return None
    return _require_string(value, name=name, maximum=maximum)


def build_finding(
    row: Mapping[str, str],
    config: ActionConfiguration,
) -> dict:
    """Construct the exact finding envelope without carrying runtime metadata."""

    computer = _optional_result_value(row, "Computer", HOSTNAME_MAX_LENGTH)
    host = _optional_result_value(row, "host", HOSTNAME_MAX_LENGTH)
    _validate_hostnames(computer, host)

    event: Dict[str, object] = {
        "detected_at": _validate_event_time(row.get("_time")),
        "channel": config.channel,
        "event_code": _decimal_integer(
            row.get("EventCode"),
            "EventCode",
            EVENT_CODE_MAXIMUM,
        ),
        "record_id": _decimal_integer(
            row.get("RecordID"),
            "RecordID",
            RECORD_ID_MAXIMUM,
        ),
    }
    required_host_values = (("computer", computer), ("host", host))
    event.update({name: value for name, value in required_host_values if value is not None})

    optional_values = (
        ("source", _optional_result_value(row, "source", SOURCE_MAX_LENGTH)),
        (
            "sourcetype",
            _optional_result_value(row, "sourcetype", SOURCETYPE_MAX_LENGTH),
        ),
        (
            "process_guid",
            _optional_result_value(row, "ProcessGuid", PROCESS_GUID_MAX_LENGTH),
        ),
        ("image", _optional_result_value(row, "Image", IMAGE_MAX_LENGTH)),
        (
            "parent_image",
            _optional_result_value(row, "ParentImage", IMAGE_MAX_LENGTH),
        ),
        (
            "target_filename",
            _optional_result_value(row, "TargetFilename", IMAGE_MAX_LENGTH),
        ),
    )
    event.update({name: value for name, value in optional_values if value is not None})

    return {
        "schema": FINDING_SCHEMA,
        "detection": {
            "rule_id": config.rule_id,
            "rule_title": config.rule_title,
            "sigma_level": config.sigma_level,
        },
        "event": event,
    }


def serialize_finding(finding: Mapping[str, object]) -> bytes:
    try:
        body = json.dumps(
            finding,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ActionInputError("finding cannot be serialized") from error
    if len(body) > MAXIMUM_FINDING_BODY_BYTES:
        raise ActionInputError("finding body is too large")
    return body


def _validate_secret(secret: bytes) -> bytes:
    if not isinstance(secret, bytes):
        raise ActionConfigurationError("secret must be bytes")
    if not MINIMUM_SECRET_BYTES <= len(secret) <= MAXIMUM_SECRET_BYTES:
        raise ActionConfigurationError("secret must be at least 32 bytes")
    return secret


def load_secret(path: Path) -> bytes:
    try:
        if not path.is_file() or path.stat().st_size > MAXIMUM_SECRET_BYTES + 2:
            raise ActionConfigurationError("secret file is invalid")
        with path.open("rb") as source:
            secret = source.read(MAXIMUM_SECRET_BYTES + 3)
    except ActionConfigurationError:
        raise
    except OSError as error:
        raise ActionConfigurationError("secret file is unreadable") from error
    if secret.endswith(b"\r\n"):
        secret = secret[:-2]
    elif secret.endswith(b"\n"):
        secret = secret[:-1]
    return _validate_secret(secret)


def signature_header(secret: bytes, timestamp: str, body: bytes) -> str:
    """Return the exact version-1 HMAC header value."""

    _validate_secret(secret)
    if not isinstance(timestamp, str) or _TIMESTAMP_PATTERN.fullmatch(timestamp) is None:
        raise ActionConfigurationError("authentication timestamp is invalid")
    if not isinstance(body, bytes):
        raise ActionInputError("finding body must be bytes")
    signing_input = SIGNING_CONTEXT + timestamp.encode("ascii") + b"\n" + body
    return SIGNATURE_VERSION + "=" + hmac.new(secret, signing_input, sha256).hexdigest()


def _bounded_response_object(response: HttpResponse) -> Optional[dict]:
    if not isinstance(response.body, bytes) or len(response.body) > MAXIMUM_ADAPTER_RESPONSE_BYTES:
        return None
    try:
        value = json.loads(
            response.body,
            parse_constant=_reject_nonstandard_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _bounded_processing_id(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    try:
        return str(UUID(value))
    except ValueError:
        return None


def _bounded_error_code(value: object) -> Optional[str]:
    if isinstance(value, str) and _SAFE_ERROR_CODE_PATTERN.fullmatch(value):
        return value
    return None


def _fallback_disposition(status: int) -> AdapterDisposition:
    if status in (200, 202):
        return AdapterDisposition(
            category="success",
            retryable=False,
            success=True,
            status=status,
        )
    if 300 <= status <= 499:
        return AdapterDisposition(
            category="permanent_failure",
            retryable=False,
            success=False,
            status=status,
            error_code="unexpected_adapter_response",
        )
    return AdapterDisposition(
        category="transient_failure",
        retryable=True,
        success=False,
        status=status,
        error_code="unexpected_adapter_response",
    )


def classify_adapter_response(response: HttpResponse) -> AdapterDisposition:
    """Classify only the bounded gateway response vocabulary."""

    if (
        isinstance(response.status, bool)
        or not isinstance(response.status, int)
        or not 100 <= response.status <= 599
    ):
        raise ActionInputError("adapter HTTP status is invalid")
    body = _bounded_response_object(response)
    if body is None:
        return _fallback_disposition(response.status)

    classification = body.get("classification")
    retryable = body.get("retryable")
    contracts = {
        "completed": ((200,), False, "success", True),
        "accepted": ((202,), False, "success", True),
        "permanent_failure": ((400, 409, 422), False, "permanent_failure", False),
        "durable_failure": ((500,), False, "durable_failure", False),
        "transient_failure": ((502, 503, 504), True, "transient_failure", False),
    }
    contract = contracts.get(classification)
    if contract is None:
        return _fallback_disposition(response.status)
    statuses, expected_retryable, category, success = contract
    if response.status not in statuses or retryable is not expected_retryable:
        return _fallback_disposition(response.status)
    return AdapterDisposition(
        category=category,
        retryable=expected_retryable,
        success=success,
        status=response.status,
        processing_id=_bounded_processing_id(body.get("processing_id")),
        replayed=body.get("replayed") is True,
        error_code=_bounded_error_code(body.get("error_code")),
    )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _read_http_body(response) -> bytes:
    body = response.read(MAXIMUM_ADAPTER_RESPONSE_BYTES + 1)
    return body if len(body) <= MAXIMUM_ADAPTER_RESPONSE_BYTES else b""


def http_post_once(
    url: str,
    body: bytes,
    headers: Dict[str, str],
    timeout_seconds: float,
) -> HttpResponse:
    """Perform one POST without redirects, proxies, retry, or polling."""

    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
    )
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            return HttpResponse(
                status=int(response.status),
                body=_read_http_body(response),
                headers={str(key): str(value) for key, value in response.headers.items()},
            )
    except urllib.error.HTTPError as error:
        try:
            try:
                response_body = _read_http_body(error)
            except (socket.timeout, TimeoutError) as timeout_error:
                raise RequestTimeout("adapter request timed out") from timeout_error
            except OSError as connection_error:
                raise ConnectionFailure("adapter connection failed") from connection_error
        finally:
            error.close()
        return HttpResponse(
            status=int(error.code),
            body=response_body,
            headers={
                str(key): str(value)
                for key, value in (error.headers.items() if error.headers else ())
            },
        )
    except (socket.timeout, TimeoutError) as error:
        raise RequestTimeout("adapter request timed out") from error
    except urllib.error.URLError as error:
        if isinstance(error.reason, (socket.timeout, TimeoutError)):
            raise RequestTimeout("adapter request timed out") from error
        raise ConnectionFailure("adapter connection failed") from error
    except http.client.HTTPException as error:
        raise ConnectionFailure("adapter connection failed") from error
    except OSError as error:
        raise ConnectionFailure("adapter connection failed") from error


def _timestamp_from_clock(value: object) -> str:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ActionConfigurationError("clock returned an invalid timestamp")
    timestamp = str(int(value))
    if _TIMESTAMP_PATTERN.fullmatch(timestamp) is None:
        raise ActionConfigurationError("clock returned an invalid timestamp")
    return timestamp


def _transient_exception_disposition(error: ActionError) -> AdapterDisposition:
    code = "adapter_timeout" if isinstance(error, RequestTimeout) else "adapter_connection_failed"
    return AdapterDisposition(
        category="transient_failure",
        retryable=True,
        success=False,
        status=None,
        error_code=code,
    )


def deliver(
    *,
    body: bytes,
    config: ActionConfiguration,
    secret: bytes,
    transport: Callable[[str, bytes, Dict[str, str], float], HttpResponse] = http_post_once,
    clock: Callable[[], float] = time.time,
    sleeper: Callable[[float], None] = time.sleep,
) -> DeliveryOutcome:
    """Deliver one stable body with at most three total HTTP attempts."""

    if not isinstance(body, bytes) or len(body) > MAXIMUM_FINDING_BODY_BYTES:
        raise ActionInputError("finding body is invalid")
    _validate_secret(secret)

    for attempt in range(1, MAXIMUM_ATTEMPTS + 1):
        timestamp = _timestamp_from_clock(clock())
        headers = {
            "Content-Type": "application/json",
            "X-Alert2IR-Timestamp": timestamp,
            "X-Alert2IR-Signature": signature_header(secret, timestamp, body),
        }
        try:
            response = transport(
                config.adapter_url,
                body,
                headers,
                HTTP_TIMEOUT_SECONDS,
            )
            disposition = classify_adapter_response(response)
        except (ConnectionFailure, RequestTimeout) as error:
            disposition = _transient_exception_disposition(error)

        if disposition.success or not disposition.retryable or attempt == MAXIMUM_ATTEMPTS:
            return DeliveryOutcome(
                success=disposition.success,
                attempts=attempt,
                category=disposition.category,
                status=disposition.status,
                processing_id=disposition.processing_id,
                replayed=disposition.replayed,
                error_code=disposition.error_code,
            )
        sleeper(RETRY_DELAYS_SECONDS[attempt - 1])

    raise AssertionError("bounded attempt loop did not return")


def execute_invocation(
    invocation: Mapping[str, object],
    *,
    transport: Callable[[str, bytes, Dict[str, str], float], HttpResponse] = http_post_once,
    clock: Callable[[], float] = time.time,
    sleeper: Callable[[float], None] = time.sleep,
) -> DeliveryOutcome:
    """Validate local inputs once, freeze the body, and perform bounded delivery."""

    config = parse_configuration(invocation)
    results_path = results_file_from_invocation(invocation)
    row = read_single_result(results_path)
    finding = build_finding(row, config)
    body = serialize_finding(finding)
    secret = load_secret(Path(config.secret_file))
    return deliver(
        body=body,
        config=config,
        secret=secret,
        transport=transport,
        clock=clock,
        sleeper=sleeper,
    )


def _read_bounded_stdin(stream) -> bytes:
    value = stream.read(MAXIMUM_INVOCATION_BYTES + 1)
    if not isinstance(value, bytes):
        raise ActionInputError("stdin must provide bytes")
    if len(value) > MAXIMUM_INVOCATION_BYTES:
        raise ActionInputError("invocation is too large")
    return value


def _safe_outcome_log(outcome: DeliveryOutcome) -> None:
    fields = [
        "outcome={}".format(outcome.category),
        "attempts={}".format(outcome.attempts),
        "status={}".format(outcome.status if outcome.status is not None else "none"),
        "replayed={}".format(str(outcome.replayed).lower()),
    ]
    if outcome.processing_id is not None:
        fields.append("processing_id={}".format(outcome.processing_id))
    if outcome.error_code is not None:
        fields.append("error_category={}".format(outcome.error_code))
    sys.stderr.write("alert2ir_delivery " + " ".join(fields) + "\n")


def main(argv: Optional[Sequence[str]] = None, stdin=None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    source = sys.stdin.buffer if stdin is None else stdin
    if arguments != ["--execute"]:
        sys.stderr.write("alert2ir_delivery error_category=invalid_execution_mode\n")
        return 1
    try:
        payload = parse_invocation(_read_bounded_stdin(source))
        outcome = execute_invocation(payload)
    except ActionError as error:
        sys.stderr.write(
            "alert2ir_delivery error_category={}\n".format(type(error).__name__)
        )
        return 1
    _safe_outcome_log(outcome)
    return 0 if outcome.success else 1


if __name__ == "__main__":
    sys.exit(main())
