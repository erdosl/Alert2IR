"""Versioned canonical alert fingerprints for idempotent acceptance."""

from __future__ import annotations

from datetime import timezone
from hashlib import sha256
import json

from alert2ir.core.models import CanonicalAlert


FINGERPRINT_VERSION = 1
FINGERPRINT_SCHEMA = "alert2ir.canonical-alert-fingerprint.v1"


def canonical_fingerprint_document(alert: CanonicalAlert) -> dict[str, object]:
    """Return the exact v1 semantic document before deterministic encoding."""

    detected_at = (
        alert.detected_at.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    return {
        "schema": FINGERPRINT_SCHEMA,
        "detection": {
            "identifier": alert.detection.identifier,
            "name": alert.detection.name,
        },
        "detected_at": detected_at,
        "source": {
            "source": alert.source.source,
            "source_alert_id": alert.source.source_alert_id,
        },
        "entities": [
            {"kind": entity.kind, "value": entity.value}
            for entity in alert.entities
        ],
        "severity": alert.severity.value,
        "evidence": [
            {"reference": evidence.reference, "kind": evidence.kind}
            for evidence in alert.evidence
        ],
    }


def canonical_fingerprint_bytes(alert: CanonicalAlert) -> bytes:
    """Serialize the v1 document without input JSON ordering or whitespace effects."""

    return json.dumps(
        canonical_fingerprint_document(alert),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def fingerprint_canonical_alert(alert: CanonicalAlert) -> tuple[int, bytes]:
    return FINGERPRINT_VERSION, sha256(canonical_fingerprint_bytes(alert)).digest()
