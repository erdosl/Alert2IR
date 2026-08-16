"""Persistence-aware completed alert processing use case."""

from collections.abc import Callable
from uuid import UUID, uuid4

from alert2ir.application.orchestrator import AlertOrchestrator
from alert2ir.application.persistence import ProcessingRecord, ProcessingRepository
from alert2ir.core.models import CanonicalAlert
from alert2ir.observability import (
    ApplicationObservability,
    bounded_backend,
    classify_error,
    current_error_category,
    no_op_observability,
    outcome_for_error,
    set_error_category,
    set_processing_id,
)


class PersistentAlertProcessor:
    """Orchestrate an alert, then persist its completed aggregate."""

    def __init__(
        self,
        orchestrator: AlertOrchestrator,
        repository: ProcessingRepository,
        processing_id_factory: Callable[[], UUID] = uuid4,
        observability: ApplicationObservability | None = None,
    ) -> None:
        self._orchestrator = orchestrator
        self._repository = repository
        self._processing_id_factory = processing_id_factory
        self.observability = observability or no_op_observability()

    def check_readiness(self) -> None:
        """Verify that the configured persistence contract is ready."""

        self._repository.check_readiness()

    def process(self, alert: CanonicalAlert) -> ProcessingRecord:
        started = self.observability.monotonic()
        decision = "unknown"
        self.observability.events.emit("alert.processing.started")
        with self.observability.span("alert2ir.process") as processing_span:
            try:
                result = self._orchestrator.process(alert)
                decision = result.decision.outcome.value
                processing_span.set_attribute("alert2ir.decision", decision)
                processing_id = self._processing_id_factory()
                set_processing_id(str(processing_id))

                persistence_started = self.observability.monotonic()
                with self.observability.span(
                    "persistence.save",
                    {
                        "db.system.name": "postgresql",
                        "db.operation.name": "INSERT",
                    },
                ) as persistence_span:
                    try:
                        record = self._repository.save(
                            processing_id,
                            alert,
                            result,
                        )
                    except Exception as error:
                        category = classify_error(error, stage="persistence")
                        outcome = outcome_for_error(category)
                        persistence_duration = (
                            self.observability.monotonic() - persistence_started
                        )
                        set_error_category(category)
                        self.observability.finish_span(
                            persistence_span,
                            outcome=outcome,
                            error_category=category,
                        )
                        self.observability.record_persistence(
                            duration_seconds=persistence_duration,
                            outcome=outcome,
                            error_category=category,
                        )
                        self.observability.events.emit(
                            "persistence.finished",
                            outcome=outcome,
                            error_category=category,
                            duration_ms=round(persistence_duration * 1000, 3),
                        )
                        raise
                    else:
                        persistence_duration = (
                            self.observability.monotonic() - persistence_started
                        )
                        self.observability.finish_span(
                            persistence_span,
                            outcome="success",
                        )
                        self.observability.record_persistence(
                            duration_seconds=persistence_duration,
                            outcome="success",
                        )
                        self.observability.events.emit(
                            "persistence.finished",
                            outcome="success",
                            duration_ms=round(persistence_duration * 1000, 3),
                        )
            except Exception as error:
                category = current_error_category() or classify_error(
                    error,
                    stage="processing",
                )
                set_error_category(category)
                outcome = outcome_for_error(category)
                duration = self.observability.monotonic() - started
                if category.startswith("routing_"):
                    failure_stage = "routing"
                elif category.startswith("backend_"):
                    failure_stage = "backend"
                elif category.startswith("persistence_"):
                    failure_stage = "persistence"
                else:
                    failure_stage = "processing"
                self.observability.finish_span(
                    processing_span,
                    outcome=outcome,
                    error_category=category,
                )
                self.observability.record_processing(
                    duration_seconds=duration,
                    decision=decision,
                    outcome=outcome,
                    error_category=category,
                )
                self.observability.events.emit(
                    "alert.processing.finished",
                    decision=decision,
                    outcome=outcome,
                    failure_stage=failure_stage,
                    error_category=category,
                    duration_ms=round(duration * 1000, 3),
                )
                raise
            else:
                duration = self.observability.monotonic() - started
                self.observability.finish_span(processing_span, outcome="success")
                self.observability.record_processing(
                    duration_seconds=duration,
                    decision=decision,
                    outcome="success",
                )
                backend = None
                if result.investigation_result is not None:
                    backend = bounded_backend(result.investigation_result.backend)
                self.observability.events.emit(
                    "alert.processing.finished",
                    decision=decision,
                    outcome="success",
                    backend=backend,
                    duration_ms=round(duration * 1000, 3),
                )
                return record
