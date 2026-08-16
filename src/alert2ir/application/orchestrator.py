"""In-memory alert orchestration use case."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from alert2ir.backends.base import InvestigationResult
from alert2ir.backends.router import BackendRouter
from alert2ir.core.models import CanonicalAlert
from alert2ir.core.workflow import (
    Decision,
    DecisionOutcome,
    Incident,
    InvestigationRequest,
)
from alert2ir.observability import (
    ApplicationObservability,
    bounded_backend,
    bounded_capability,
    classify_error,
    no_op_observability,
    outcome_for_error,
    set_error_category,
)


class DecisionPolicy(Protocol):
    def decide(self, alert: CanonicalAlert) -> Decision:
        ...


@dataclass(frozen=True, slots=True)
class OrchestrationResult:
    decision: Decision
    incident: Incident | None
    investigation_request: InvestigationRequest | None
    investigation_result: InvestigationResult | None

    def __post_init__(self) -> None:
        if self.decision.outcome is DecisionOutcome.NO_ACTION:
            if any(
                value is not None
                for value in (
                    self.incident,
                    self.investigation_request,
                    self.investigation_result,
                )
            ):
                raise ValueError("no_action result cannot contain investigation values")
            return

        if self.decision.outcome is DecisionOutcome.INVESTIGATE:
            if self.incident is None:
                raise ValueError("investigate result requires an incident")
            if self.investigation_request is None:
                raise ValueError("investigate result requires an investigation request")
            if self.investigation_result is None:
                raise ValueError("investigate result requires an investigation result")
            if self.incident.decision != self.decision:
                raise ValueError("incident decision must match orchestration decision")
            if self.investigation_request.incident != self.incident:
                raise ValueError("investigation request incident must match incident")
            return

        raise ValueError(f"unsupported decision outcome: {self.decision.outcome!r}")


@dataclass(frozen=True, slots=True)
class AlertOrchestrator:
    policy: DecisionPolicy
    router: BackendRouter
    request_factory: Callable[[Incident], InvestigationRequest]
    observability: ApplicationObservability = field(
        default_factory=no_op_observability,
        compare=False,
        repr=False,
    )

    def process(self, alert: CanonicalAlert) -> OrchestrationResult:
        decision = self.policy.decide(alert)
        if decision.source != alert.source:
            raise ValueError("decision source must match alert source")

        if decision.outcome is DecisionOutcome.NO_ACTION:
            return OrchestrationResult(
                decision=decision,
                incident=None,
                investigation_request=None,
                investigation_result=None,
            )

        if decision.outcome is DecisionOutcome.INVESTIGATE:
            incident = Incident(alert=alert, decision=decision)
            request = self.request_factory(incident)
            if request.incident != incident:
                raise ValueError("investigation request incident must match incident")
            backend = self.router.select(request)
            backend_name = bounded_backend(backend.name)
            capability = bounded_capability(request.required_capabilities)
            started = self.observability.monotonic()
            self.observability.events.emit(
                "backend.execution.started",
                backend=backend_name,
                capability=capability,
                target_count=len(request.targets),
            )
            with self.observability.span(
                "backend.investigate",
                {
                    "alert2ir.backend": backend_name,
                    "alert2ir.capability": capability,
                    "alert2ir.target_count": len(request.targets),
                },
            ) as span:
                try:
                    result = backend.investigate(request)
                except Exception as error:
                    category = classify_error(error, stage="backend")
                    outcome = outcome_for_error(category)
                    duration = self.observability.monotonic() - started
                    set_error_category(category)
                    self.observability.finish_span(
                        span,
                        outcome=outcome,
                        error_category=category,
                    )
                    self.observability.record_backend(
                        duration_seconds=duration,
                        backend=backend_name,
                        capability=capability,
                        outcome=outcome,
                        error_category=category,
                    )
                    self.observability.events.emit(
                        "backend.execution.finished",
                        backend=backend_name,
                        capability=capability,
                        outcome=outcome,
                        error_category=category,
                        duration_ms=round(duration * 1000, 3),
                    )
                    raise
                else:
                    duration = self.observability.monotonic() - started
                    self.observability.finish_span(span, outcome="success")
                    self.observability.record_backend(
                        duration_seconds=duration,
                        backend=backend_name,
                        capability=capability,
                        outcome="success",
                    )
                    self.observability.events.emit(
                        "backend.execution.finished",
                        backend=backend_name,
                        capability=capability,
                        outcome="success",
                        duration_ms=round(duration * 1000, 3),
                    )
            return OrchestrationResult(
                decision=decision,
                incident=incident,
                investigation_request=request,
                investigation_result=result,
            )

        raise ValueError(f"unsupported decision outcome: {decision.outcome!r}")
