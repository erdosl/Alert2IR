"""In-memory alert orchestration use case."""

from collections.abc import Callable
from dataclasses import dataclass
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
            result = backend.investigate(request)
            return OrchestrationResult(
                decision=decision,
                incident=incident,
                investigation_request=request,
                investigation_result=result,
            )

        raise ValueError(f"unsupported decision outcome: {decision.outcome!r}")
