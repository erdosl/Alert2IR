"""Application-facing contract for completed processing persistence."""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from alert2ir.application.orchestrator import OrchestrationResult
from alert2ir.core.models import CanonicalAlert


@dataclass(frozen=True, slots=True)
class ProcessingRecord:
    """One immutable, completed alert-processing aggregate."""

    processing_id: UUID
    created_at: datetime
    alert: CanonicalAlert
    result: OrchestrationResult

    def __post_init__(self) -> None:
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        if self.result.decision.source != self.alert.source:
            raise ValueError("result decision source must match alert source")
        if self.result.incident is not None and self.result.incident.alert != self.alert:
            raise ValueError("result incident alert must match alert")


class ProcessingRepository(Protocol):
    """Store and retrieve completed processing aggregates by storage identity."""

    def check_readiness(self) -> None:
        """Raise when persistence connectivity or its required schema is absent."""
        ...

    def save(
        self,
        processing_id: UUID,
        alert: CanonicalAlert,
        result: OrchestrationResult,
    ) -> ProcessingRecord:
        ...

    def get(self, processing_id: UUID) -> ProcessingRecord | None:
        ...
