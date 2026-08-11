"""Persistence-aware completed alert processing use case."""

from collections.abc import Callable
from uuid import UUID, uuid4

from alert2ir.application.orchestrator import AlertOrchestrator
from alert2ir.application.persistence import ProcessingRecord, ProcessingRepository
from alert2ir.core.models import CanonicalAlert


class PersistentAlertProcessor:
    """Orchestrate an alert, then persist its completed aggregate."""

    def __init__(
        self,
        orchestrator: AlertOrchestrator,
        repository: ProcessingRepository,
        processing_id_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._orchestrator = orchestrator
        self._repository = repository
        self._processing_id_factory = processing_id_factory

    def process(self, alert: CanonicalAlert) -> ProcessingRecord:
        result = self._orchestrator.process(alert)
        processing_id = self._processing_id_factory()
        return self._repository.save(processing_id, alert, result)
