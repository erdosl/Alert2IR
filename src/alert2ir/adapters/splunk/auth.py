"""Lab-scoped HMAC authentication for the Splunk source gateway."""

from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import hmac
import re


AUTHENTICATION_VERSION = "v1"
SIGNING_CONTEXT = b"alert2ir-splunk-v1\n"
DEFAULT_ALLOWED_SKEW_SECONDS = 300
MINIMUM_SHARED_SECRET_BYTES = 32

_TIMESTAMP_PATTERN = re.compile(r"(?:0|[1-9][0-9]{0,11})\Z")
_SIGNATURE_PATTERN = re.compile(r"v1=([0-9a-f]{64})\Z")


class AuthenticationError(ValueError):
    """An intentionally non-specific request-authentication failure."""

    def __init__(self) -> None:
        super().__init__("authentication failed")


def validate_shared_secret(shared_secret: bytes) -> bytes:
    """Validate construction-time secret material without transforming it."""

    if not isinstance(shared_secret, bytes):
        raise ValueError("shared secret must be bytes")
    if len(shared_secret) < MINIMUM_SHARED_SECRET_BYTES:
        raise ValueError("shared secret must be at least 32 bytes")
    return shared_secret


def _parse_timestamp(value: str | None) -> int:
    if value is None or _TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise AuthenticationError
    return int(value)


def signing_input(timestamp: str, raw_body: bytes) -> bytes:
    """Build the exact version-1 bytes covered by HMAC."""

    _parse_timestamp(timestamp)
    if not isinstance(raw_body, bytes):
        raise ValueError("raw body must be bytes")
    return SIGNING_CONTEXT + timestamp.encode("ascii") + b"\n" + raw_body


def compute_signature(
    shared_secret: bytes,
    timestamp: str,
    raw_body: bytes,
) -> str:
    """Compute the lowercase hexadecimal version-1 HMAC digest."""

    validate_shared_secret(shared_secret)
    return hmac.new(
        shared_secret,
        signing_input(timestamp, raw_body),
        sha256,
    ).hexdigest()


def verify_signature(
    *,
    shared_secret: bytes,
    timestamp_header: str | None,
    signature_header: str | None,
    raw_body: bytes,
    now: datetime,
    allowed_skew_seconds: int = DEFAULT_ALLOWED_SKEW_SECONDS,
) -> None:
    """Verify format, replay window, and HMAC without parsing the body."""

    if (
        isinstance(allowed_skew_seconds, bool)
        or not isinstance(allowed_skew_seconds, int)
        or allowed_skew_seconds < 0
    ):
        raise ValueError("allowed skew must be a non-negative integer")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("authentication clock must be timezone-aware")

    timestamp = _parse_timestamp(timestamp_header)
    if signature_header is None:
        raise AuthenticationError
    match = _SIGNATURE_PATTERN.fullmatch(signature_header)
    if match is None:
        raise AuthenticationError

    now_epoch = int(now.timestamp())
    if abs(now_epoch - timestamp) > allowed_skew_seconds:
        raise AuthenticationError

    expected = compute_signature(
        shared_secret,
        timestamp_header,
        raw_body,
    )
    if not hmac.compare_digest(expected, match.group(1)):
        raise AuthenticationError
