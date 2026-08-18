"""Pure Splunk finding normalization and canonical alert construction."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_FLOOR
import re
from urllib.parse import quote

from alert2ir.adapters.splunk.idempotency import idempotency_key
from alert2ir.adapters.splunk.models import (
    CanonicalizedSplunkFinding,
    EVIDENCE_REFERENCE_MAX_LENGTH,
    HOSTNAME_MAX_LENGTH,
    NormalizedSplunkFinding,
    SigmaLevel,
    SplunkFinding,
    TimestampInput,
)
from alert2ir.core.models import (
    CanonicalAlert,
    DetectionIdentity,
    Entity,
    EvidenceReference,
    Severity,
    SourceProvenance,
)


CANONICAL_SOURCE = "splunk"
SIGMA_LEVEL_MAPPING_SCHEMA = "alert2ir.splunk.sigma-level.v1"

_HOSTNAME_PATTERN = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\Z")
_NUMERIC_TIMESTAMP_PATTERN = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)\Z")
_RFC3339_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z"
)
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MINIMUM_UNIX_EPOCH = Decimal("-62135596800")
_MAXIMUM_UNIX_EPOCH_EXCLUSIVE = Decimal("253402300800")

_SEVERITY_BY_SIGMA_LEVEL = {
    SigmaLevel.INFORMATIONAL: Severity.LOW,
    SigmaLevel.LOW: Severity.LOW,
    SigmaLevel.MEDIUM: Severity.MEDIUM,
    SigmaLevel.HIGH: Severity.HIGH,
    SigmaLevel.CRITICAL: Severity.CRITICAL,
}


def _normalize_one_hostname(value: str) -> str:
    normalized = value.strip()
    if normalized.endswith("."):
        normalized = normalized[:-1]
    if not normalized:
        raise ValueError("hostname must be non-empty")
    if len(normalized) > HOSTNAME_MAX_LENGTH:
        raise ValueError("hostname exceeds the supported length")
    if not normalized.isascii():
        raise ValueError("hostname must contain only ASCII characters")
    if _HOSTNAME_PATTERN.fullmatch(normalized) is None:
        raise ValueError("hostname contains unsupported characters")
    return normalized.lower()


def normalize_hostname(computer: str | None, host: str | None) -> str:
    """Normalize Computer/host and reject contradictory endpoint identity."""

    normalized_computer = (
        None if computer is None else _normalize_one_hostname(computer)
    )
    normalized_host = None if host is None else _normalize_one_hostname(host)
    if normalized_computer is not None and normalized_host is not None:
        if normalized_computer != normalized_host:
            raise ValueError("Computer and host disagree after normalization")
    if normalized_computer is not None:
        return normalized_computer
    if normalized_host is not None:
        return normalized_host
    raise ValueError("Computer or host is required")


def _normalize_epoch(value: int | float | str) -> datetime:
    try:
        decimal_value = Decimal(str(value))
    except InvalidOperation as error:
        raise ValueError("Unix epoch must be numeric") from error
    if not decimal_value.is_finite():
        raise ValueError("Unix epoch must be finite")
    if not (
        _MINIMUM_UNIX_EPOCH
        <= decimal_value
        < _MAXIMUM_UNIX_EPOCH_EXCLUSIVE
    ):
        raise ValueError("Unix epoch is outside the supported datetime range")
    # Canonical datetime precision is microseconds. Flooring makes numeric
    # epochs agree with Python's RFC3339 fractional-second truncation.
    microseconds = int(
        (decimal_value * Decimal(1_000_000)).to_integral_value(
            rounding=ROUND_FLOOR
        )
    )
    return _UNIX_EPOCH + timedelta(microseconds=microseconds)


def normalize_timestamp(value: TimestampInput) -> datetime:
    """Normalize a supported Splunk timestamp to a timezone-aware UTC value."""

    if isinstance(value, bool):
        raise ValueError("boolean is not a supported timestamp")
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("detected_at must be timezone-aware")
        return value.astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        return _normalize_epoch(value)
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("timestamp must be RFC3339 or a Unix epoch")
    if _NUMERIC_TIMESTAMP_PATTERN.fullmatch(value) is not None:
        return _normalize_epoch(value)
    if _RFC3339_PATTERN.fullmatch(value) is None:
        raise ValueError("timestamp must be RFC3339 with an explicit timezone")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("timestamp is malformed") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("detected_at must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def normalize_sigma_severity(level: SigmaLevel) -> Severity:
    """Apply the closed, reviewed Sigma-level mapping version 1."""

    try:
        return _SEVERITY_BY_SIGMA_LEVEL[level]
    except KeyError as error:
        raise ValueError(f"unsupported Sigma level: {level!r}") from error


def normalize_splunk_finding(finding: SplunkFinding) -> NormalizedSplunkFinding:
    """Normalize a validated source finding without external state."""

    return NormalizedSplunkFinding(
        rule_id=finding.detection.rule_id,
        rule_title=finding.detection.rule_title,
        sigma_level=finding.detection.sigma_level,
        detected_at=normalize_timestamp(finding.event.detected_at),
        computer=normalize_hostname(finding.event.computer, finding.event.host),
        channel=finding.event.channel,
        event_code=finding.event.event_code,
        record_id=finding.event.record_id,
        source=finding.event.source,
        sourcetype=finding.event.sourcetype,
        process_guid=finding.event.process_guid,
        image=finding.event.image,
        parent_image=finding.event.parent_image,
        target_filename=finding.event.target_filename,
    )


def _evidence(reference: str, kind: str) -> EvidenceReference:
    if len(reference) > EVIDENCE_REFERENCE_MAX_LENGTH:
        raise ValueError(f"{kind} evidence exceeds the supported length")
    return EvidenceReference(reference=reference, kind=kind)


def build_evidence(
    finding: NormalizedSplunkFinding,
    severity: Severity,
) -> tuple[EvidenceReference, ...]:
    """Construct the fixed-order, bounded canonical evidence set."""

    items = [
        _evidence(
            f"{SIGMA_LEVEL_MAPPING_SCHEMA}:"
            f"{finding.sigma_level.value}->{severity.value}",
            "normalization-policy",
        ),
        _evidence(
            "windows-event://"
            f"{quote(finding.computer, safe='-._~')}/"
            f"{quote(finding.channel, safe='-._~')}/"
            f"{finding.record_id}?event_code={finding.event_code}",
            "source-event",
        ),
    ]
    optional_evidence = (
        (finding.process_guid, "process-guid"),
        (finding.image, "process-image"),
        (finding.parent_image, "parent-process-image"),
        (finding.target_filename, "target-file"),
    )
    items.extend(
        _evidence(reference, kind)
        for reference, kind in optional_evidence
        if reference is not None
    )
    return tuple(items)


def _to_canonical_alert(
    finding: NormalizedSplunkFinding,
    key: str,
) -> CanonicalAlert:
    severity = normalize_sigma_severity(finding.sigma_level)
    return CanonicalAlert(
        detection=DetectionIdentity(
            identifier=finding.rule_id,
            name=finding.rule_title,
        ),
        detected_at=finding.detected_at,
        source=SourceProvenance(
            source=CANONICAL_SOURCE,
            source_alert_id=key,
        ),
        entities=(Entity(kind="host", value=finding.computer),),
        severity=severity,
        evidence=build_evidence(finding, severity),
    )


def canonicalize(finding: SplunkFinding) -> CanonicalizedSplunkFinding:
    """Return the canonical alert and stable delivery identity as one value."""

    normalized = normalize_splunk_finding(finding)
    key = idempotency_key(normalized)
    return CanonicalizedSplunkFinding(
        alert=_to_canonical_alert(normalized, key),
        idempotency_key=key,
    )


def to_canonical_alert(finding: SplunkFinding) -> CanonicalAlert:
    """Map a validated Splunk finding into the existing canonical domain."""

    return canonicalize(finding).alert
