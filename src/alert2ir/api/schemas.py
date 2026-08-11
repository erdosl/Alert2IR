"""Typed JSON schemas for the canonical Alert2IR API boundary."""

from datetime import datetime
from typing import Annotated, Self
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, field_validator

from alert2ir.application import ProcessingRecord
from alert2ir.backends.base import InvestigationResult
from alert2ir.core.models import (
    CanonicalAlert,
    DetectionIdentity,
    Entity,
    EvidenceReference,
    Severity,
    SourceProvenance,
)
from alert2ir.core.workflow import Decision, DecisionOutcome, Incident, InvestigationRequest


def _validate_non_empty(value: str) -> str:
    if not value.strip():
        raise ValueError("value must be non-empty")
    return value


NonEmptyString = Annotated[str, AfterValidator(_validate_non_empty)]


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DetectionIdentityRequest(ApiModel):
    identifier: NonEmptyString
    name: NonEmptyString | None = None

    def to_domain(self) -> DetectionIdentity:
        return DetectionIdentity(identifier=self.identifier, name=self.name)

    @classmethod
    def from_domain(cls, value: DetectionIdentity) -> Self:
        return cls(identifier=value.identifier, name=value.name)


class SourceProvenanceRequest(ApiModel):
    source: NonEmptyString
    source_alert_id: NonEmptyString | None = None

    def to_domain(self) -> SourceProvenance:
        return SourceProvenance(
            source=self.source,
            source_alert_id=self.source_alert_id,
        )

    @classmethod
    def from_domain(cls, value: SourceProvenance) -> Self:
        return cls(source=value.source, source_alert_id=value.source_alert_id)


class EntityRequest(ApiModel):
    kind: NonEmptyString
    value: NonEmptyString

    def to_domain(self) -> Entity:
        return Entity(kind=self.kind, value=self.value)

    @classmethod
    def from_domain(cls, value: Entity) -> Self:
        return cls(kind=value.kind, value=value.value)


class EvidenceReferenceRequest(ApiModel):
    reference: NonEmptyString
    kind: NonEmptyString | None = None

    def to_domain(self) -> EvidenceReference:
        return EvidenceReference(reference=self.reference, kind=self.kind)

    @classmethod
    def from_domain(cls, value: EvidenceReference) -> Self:
        return cls(reference=value.reference, kind=value.kind)


class CanonicalAlertRequest(ApiModel):
    detection: DetectionIdentityRequest
    detected_at: datetime
    source: SourceProvenanceRequest
    entities: tuple[EntityRequest, ...]
    severity: Severity
    evidence: tuple[EvidenceReferenceRequest, ...]

    @field_validator("detected_at")
    @classmethod
    def validate_detected_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("detected_at must be timezone-aware")
        return value

    def to_domain(self) -> CanonicalAlert:
        return CanonicalAlert(
            detection=self.detection.to_domain(),
            detected_at=self.detected_at,
            source=self.source.to_domain(),
            entities=tuple(entity.to_domain() for entity in self.entities),
            severity=self.severity,
            evidence=tuple(item.to_domain() for item in self.evidence),
        )

    @classmethod
    def from_domain(cls, value: CanonicalAlert) -> Self:
        return cls(
            detection=DetectionIdentityRequest.from_domain(value.detection),
            detected_at=value.detected_at,
            source=SourceProvenanceRequest.from_domain(value.source),
            entities=tuple(EntityRequest.from_domain(item) for item in value.entities),
            severity=value.severity,
            evidence=tuple(
                EvidenceReferenceRequest.from_domain(item) for item in value.evidence
            ),
        )


class DecisionResponse(ApiModel):
    outcome: DecisionOutcome
    policy_id: str
    reasons: tuple[str, ...]
    source: SourceProvenanceRequest

    @classmethod
    def from_domain(cls, value: Decision) -> Self:
        return cls(
            outcome=value.outcome,
            policy_id=value.policy_id,
            reasons=value.reasons,
            source=SourceProvenanceRequest.from_domain(value.source),
        )


class IncidentResponse(ApiModel):
    alert: CanonicalAlertRequest
    decision: DecisionResponse

    @classmethod
    def from_domain(cls, value: Incident) -> Self:
        return cls(
            alert=CanonicalAlertRequest.from_domain(value.alert),
            decision=DecisionResponse.from_domain(value.decision),
        )


class InvestigationRequestResponse(ApiModel):
    desired_outcome: str
    required_capabilities: tuple[str, ...]
    targets: tuple[EntityRequest, ...]

    @classmethod
    def from_domain(cls, value: InvestigationRequest) -> Self:
        return cls(
            desired_outcome=value.desired_outcome,
            required_capabilities=value.required_capabilities,
            targets=tuple(EntityRequest.from_domain(item) for item in value.targets),
        )


class InvestigationResultResponse(ApiModel):
    backend: str
    completed_capabilities: tuple[str, ...]
    evidence: tuple[EvidenceReferenceRequest, ...]

    @classmethod
    def from_domain(cls, value: InvestigationResult) -> Self:
        return cls(
            backend=value.backend,
            completed_capabilities=value.completed_capabilities,
            evidence=tuple(
                EvidenceReferenceRequest.from_domain(item) for item in value.evidence
            ),
        )


class AlertProcessingResponse(ApiModel):
    processing_id: UUID
    decision: DecisionResponse
    incident: IncidentResponse | None
    investigation_request: InvestigationRequestResponse | None
    investigation_result: InvestigationResultResponse | None

    @classmethod
    def from_application(cls, record: ProcessingRecord) -> Self:
        value = record.result
        return cls(
            processing_id=record.processing_id,
            decision=DecisionResponse.from_domain(value.decision),
            incident=(
                IncidentResponse.from_domain(value.incident)
                if value.incident is not None
                else None
            ),
            investigation_request=(
                InvestigationRequestResponse.from_domain(value.investigation_request)
                if value.investigation_request is not None
                else None
            ),
            investigation_result=(
                InvestigationResultResponse.from_domain(value.investigation_result)
                if value.investigation_result is not None
                else None
            ),
        )


class ApiErrorResponse(ApiModel):
    code: str
    message: str
    requested_capabilities: tuple[str, ...] | None
    eligible_backends: tuple[str, ...] | None
