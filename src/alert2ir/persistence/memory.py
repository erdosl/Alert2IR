"""Deterministic in-memory completed-processing repository."""

from collections.abc import Callable
from datetime import datetime
from uuid import UUID

from alert2ir.application import OrchestrationResult, ProcessingRecord
from alert2ir.core import CanonicalAlert


class InMemoryProcessingRepository:
    def __init__(self, clock: Callable[[], datetime]) -> None:
        self._clock = clock
        self._records: dict[UUID, ProcessingRecord] = {}

    def check_readiness(self) -> None:
        """The in-memory repository has no external readiness dependency."""

    def save(
        self,
        processing_id: UUID,
        alert: CanonicalAlert,
        result: OrchestrationResult,
    ) -> ProcessingRecord:
        if processing_id in self._records:
            raise ValueError(f"processing ID already exists: {processing_id}")

        record = ProcessingRecord(
            processing_id=processing_id,
            created_at=self._clock(),
            alert=alert,
            result=result,
        )
        self._records[processing_id] = record
        return record

    def get(self, processing_id: UUID) -> ProcessingRecord | None:
        return self._records.get(processing_id)
