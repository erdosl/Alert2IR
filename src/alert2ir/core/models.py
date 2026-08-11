"""Canonical, vendor-neutral alert domain models."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


def _require_non_empty(value: str, field_name: str) -> None:
    if not value.strip():
        raise ValueError(f"{field_name} must be non-empty")


def _require_optional_non_empty(value: str | None, field_name: str) -> None:
    if value is not None:
        _require_non_empty(value, field_name)


class Severity(StrEnum):
    """Initial normalized alert severity vocabulary."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class DetectionIdentity:
    identifier: str
    name: str | None = None

    def __post_init__(self) -> None:
        _require_non_empty(self.identifier, "identifier")
        _require_optional_non_empty(self.name, "name")


@dataclass(frozen=True, slots=True)
class SourceProvenance:
    source: str
    source_alert_id: str | None = None

    def __post_init__(self) -> None:
        _require_non_empty(self.source, "source")
        _require_optional_non_empty(self.source_alert_id, "source_alert_id")


@dataclass(frozen=True, slots=True)
class Entity:
    kind: str
    value: str

    def __post_init__(self) -> None:
        _require_non_empty(self.kind, "kind")
        _require_non_empty(self.value, "value")


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    reference: str
    kind: str | None = None

    def __post_init__(self) -> None:
        _require_non_empty(self.reference, "reference")
        _require_optional_non_empty(self.kind, "kind")


@dataclass(frozen=True, slots=True)
class CanonicalAlert:
    detection: DetectionIdentity
    detected_at: datetime
    source: SourceProvenance
    entities: tuple[Entity, ...]
    severity: Severity
    evidence: tuple[EvidenceReference, ...]

    def __post_init__(self) -> None:
        if self.detected_at.tzinfo is None or self.detected_at.utcoffset() is None:
            raise ValueError("detected_at must be timezone-aware")
