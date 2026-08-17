"""Deterministic policy and investigation planning without external effects."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from alert2ir.backends.base import InvestigationBackend, InvestigationResult
from alert2ir.backends.router import BackendRouter
from alert2ir.core.models import CanonicalAlert
from alert2ir.core.workflow import (
    Decision,
    DecisionOutcome,
    Incident,
    InvestigationRequest,
)
from alert2ir.observability import ApplicationObservability, no_op_observability


class DecisionPolicy(Protocol):
    def decide(self, alert: CanonicalAlert) -> Decision: ...


@dataclass(frozen=True, slots=True)
class OrchestrationResult:
    """Terminal public logical outcome retained for API compatibility."""

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
            if any(
                value is None
                for value in (
                    self.incident,
                    self.investigation_request,
                    self.investigation_result,
                )
            ):
                raise ValueError("investigate result requires the complete result graph")
            if self.incident is not None and self.incident.decision != self.decision:
                raise ValueError("incident decision must match orchestration decision")
            if (
                self.investigation_request is not None
                and self.investigation_request.incident != self.incident
            ):
                raise ValueError("investigation request incident must match incident")
            return
        raise ValueError(f"unsupported decision outcome: {self.decision.outcome!r}")


@dataclass(frozen=True, slots=True)
class PlanningResult:
    """Pure deterministic plan; backend methods have not been called."""

    decision: Decision
    incident: Incident | None
    investigation_request: InvestigationRequest | None
    backend: InvestigationBackend | None = field(compare=False, repr=False)

    def __post_init__(self) -> None:
        if self.decision.outcome is DecisionOutcome.NO_ACTION:
            if any(
                value is not None
                for value in (
                    self.incident,
                    self.investigation_request,
                    self.backend,
                )
            ):
                raise ValueError("no_action plan cannot contain investigation values")
            return
        if self.decision.outcome is DecisionOutcome.INVESTIGATE:
            if any(
                value is None
                for value in (
                    self.incident,
                    self.investigation_request,
                    self.backend,
                )
            ):
                raise ValueError("investigate plan requires request and backend")
            if self.incident is not None and self.incident.decision != self.decision:
                raise ValueError("incident decision must match plan decision")
            if (
                self.investigation_request is not None
                and self.investigation_request.incident != self.incident
            ):
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

    def plan(self, alert: CanonicalAlert) -> PlanningResult:
        decision = self.policy.decide(alert)
        if decision.source != alert.source:
            raise ValueError("decision source must match alert source")

        if decision.outcome is DecisionOutcome.NO_ACTION:
            return PlanningResult(decision, None, None, None)
        if decision.outcome is DecisionOutcome.INVESTIGATE:
            incident = Incident(alert=alert, decision=decision)
            request = self.request_factory(incident)
            if request.incident != incident:
                raise ValueError("investigation request incident must match incident")
            backend = self.router.select(request)
            return PlanningResult(decision, incident, request, backend)
        raise ValueError(f"unsupported decision outcome: {decision.outcome!r}")

    def backend_for_name(self, name: str) -> InvestigationBackend | None:
        return self.router.get(name)
