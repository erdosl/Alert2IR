"""Decision, incident, and investigation request domain models."""

from dataclasses import dataclass
from enum import StrEnum

from alert2ir.core.models import CanonicalAlert, Entity, Severity, SourceProvenance


def _require_non_empty(value: str, field_name: str) -> None:
    if not value.strip():
        raise ValueError(f"{field_name} must be non-empty")


class DecisionOutcome(StrEnum):
    INVESTIGATE = "investigate"
    NO_ACTION = "no_action"


@dataclass(frozen=True, slots=True)
class Decision:
    outcome: DecisionOutcome
    policy_id: str
    reasons: tuple[str, ...]
    source: SourceProvenance

    def __post_init__(self) -> None:
        _require_non_empty(self.policy_id, "policy_id")
        if not self.reasons:
            raise ValueError("reasons must contain at least one item")
        for reason in self.reasons:
            _require_non_empty(reason, "reason")


class BaselineSeverityPolicy:
    POLICY_ID = "baseline-severity-v1"

    _OUTCOME_BY_SEVERITY = {
        Severity.LOW: DecisionOutcome.NO_ACTION,
        Severity.MEDIUM: DecisionOutcome.NO_ACTION,
        Severity.HIGH: DecisionOutcome.INVESTIGATE,
        Severity.CRITICAL: DecisionOutcome.INVESTIGATE,
    }

    def decide(self, alert: CanonicalAlert) -> Decision:
        try:
            outcome = self._OUTCOME_BY_SEVERITY[alert.severity]
        except KeyError as exc:
            raise ValueError(
                f"unsupported normalized severity: {alert.severity!r}"
            ) from exc

        if outcome is DecisionOutcome.INVESTIGATE:
            reason = f"normalized severity '{alert.severity.value}' requires investigation"
        else:
            reason = (
                f"normalized severity '{alert.severity.value}' does not require investigation"
            )

        return Decision(
            outcome=outcome,
            policy_id=self.POLICY_ID,
            reasons=(reason,),
            source=alert.source,
        )


@dataclass(frozen=True, slots=True)
class Incident:
    alert: CanonicalAlert
    decision: Decision

    def __post_init__(self) -> None:
        if self.decision.outcome is not DecisionOutcome.INVESTIGATE:
            raise ValueError("incident requires an investigate decision")
        if self.decision.source != self.alert.source:
            raise ValueError("decision source must match alert source")


@dataclass(frozen=True, slots=True)
class InvestigationRequest:
    incident: Incident
    desired_outcome: str
    required_capabilities: tuple[str, ...]
    targets: tuple[Entity, ...]

    def __post_init__(self) -> None:
        _require_non_empty(self.desired_outcome, "desired_outcome")
        if not self.required_capabilities:
            raise ValueError("required_capabilities must contain at least one item")
        for capability in self.required_capabilities:
            _require_non_empty(capability, "capability")
