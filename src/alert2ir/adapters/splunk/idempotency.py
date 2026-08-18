"""Deterministic logical identity for normalized Splunk findings."""

from __future__ import annotations

from datetime import timezone
from hashlib import sha256
import json

from alert2ir.adapters.splunk.models import NormalizedSplunkFinding


FINDING_IDENTITY_SCHEMA = "alert2ir.splunk-finding-id.v1"
IDEMPOTENCY_KEY_PREFIX = "splunk-v1-"


def _utc_timestamp(value: NormalizedSplunkFinding) -> str:
    if (
        value.detected_at.tzinfo is None
        or value.detected_at.utcoffset() is None
    ):
        raise ValueError("normalized detected_at must be timezone-aware")
    return (
        value.detected_at.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def finding_identity_document(
    finding: NormalizedSplunkFinding,
) -> dict[str, object]:
    """Return the exact logical finding identity document for version 1."""

    return {
        "schema": FINDING_IDENTITY_SCHEMA,
        "detection_id": finding.rule_id,
        "event": {
            "channel": finding.channel,
            "computer": finding.computer,
            "detected_at": _utc_timestamp(finding),
            "event_code": finding.event_code,
            "record_id": finding.record_id,
        },
    }


def finding_identity_bytes(finding: NormalizedSplunkFinding) -> bytes:
    """Serialize identity without input member ordering or whitespace effects."""

    return json.dumps(
        finding_identity_document(finding),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def finding_identity_digest(finding: NormalizedSplunkFinding) -> str:
    """Return the lowercase SHA-256 hexadecimal logical identity."""

    return sha256(finding_identity_bytes(finding)).hexdigest()


def idempotency_key(finding: NormalizedSplunkFinding) -> str:
    """Return the API-safe stable key shared with source_alert_id."""

    return f"{IDEMPOTENCY_KEY_PREFIX}{finding_identity_digest(finding)}"
