"""PostgreSQL persistence for completed processing aggregates."""

from collections.abc import Mapping
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from alert2ir.application import OrchestrationResult, ProcessingRecord
from alert2ir.backends import InvestigationResult
from alert2ir.core import (
    CanonicalAlert,
    Decision,
    DecisionOutcome,
    DetectionIdentity,
    Entity,
    EvidenceReference,
    Incident,
    InvestigationRequest,
    Severity,
    SourceProvenance,
)


SNAPSHOT_VERSION = 1
SCHEMA_REVISION = "0001_processing_records"
_READINESS_CONNECT_TIMEOUT_SECONDS = 3
_READINESS_STATEMENT_TIMEOUT_MILLISECONDS = 2000

_INSERT_SQL = """
    INSERT INTO processing_records (
        id, snapshot_version, detection_identifier, detection_name, detected_at,
        source, source_alert_id, severity, entities, alert_evidence,
        decision_outcome, policy_id, decision_reasons, request_desired_outcome,
        request_capabilities, request_targets, result_backend,
        result_completed_capabilities, result_evidence
    ) VALUES (
        %(id)s, %(snapshot_version)s, %(detection_identifier)s,
        %(detection_name)s, %(detected_at)s, %(source)s, %(source_alert_id)s,
        %(severity)s, %(entities)s, %(alert_evidence)s, %(decision_outcome)s,
        %(policy_id)s, %(decision_reasons)s, %(request_desired_outcome)s,
        %(request_capabilities)s, %(request_targets)s, %(result_backend)s,
        %(result_completed_capabilities)s, %(result_evidence)s
    )
    RETURNING created_at
"""

_SELECT_SQL = """
    SELECT
        id, created_at, snapshot_version, detection_identifier, detection_name,
        detected_at, source, source_alert_id, severity, entities, alert_evidence,
        decision_outcome, policy_id, decision_reasons, request_desired_outcome,
        request_capabilities, request_targets, result_backend,
        result_completed_capabilities, result_evidence
    FROM processing_records
    WHERE id = %s
"""


def _encode_entities(values: tuple[Entity, ...]) -> list[dict[str, str]]:
    return [{"kind": value.kind, "value": value.value} for value in values]


def _encode_evidence(
    values: tuple[EvidenceReference, ...],
) -> list[dict[str, str | None]]:
    return [
        {"reference": value.reference, "kind": value.kind}
        for value in values
    ]


def _require_array(value: Any, field_name: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"snapshot v1 {field_name} must be a JSON array")
    return value


def _require_object(
    value: Any,
    field_name: str,
    expected_keys: set[str],
) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ValueError(
            f"snapshot v1 {field_name} must be an object with keys "
            f"{sorted(expected_keys)!r}"
        )
    return value


def _decode_entities(value: Any, field_name: str) -> tuple[Entity, ...]:
    decoded = []
    for item in _require_array(value, field_name):
        item = _require_object(item, field_name, {"kind", "value"})
        decoded.append(Entity(kind=item["kind"], value=item["value"]))
    return tuple(decoded)


def _decode_evidence(value: Any, field_name: str) -> tuple[EvidenceReference, ...]:
    decoded = []
    for item in _require_array(value, field_name):
        item = _require_object(item, field_name, {"reference", "kind"})
        decoded.append(
            EvidenceReference(reference=item["reference"], kind=item["kind"])
        )
    return tuple(decoded)


def _decode_strings(value: Any, field_name: str) -> tuple[str, ...]:
    values = _require_array(value, field_name)
    if any(not isinstance(item, str) for item in values):
        raise ValueError(f"snapshot v1 {field_name} must contain only strings")
    return tuple(values)


def _serialize_values(
    processing_id: UUID,
    alert: CanonicalAlert,
    result: OrchestrationResult,
) -> dict[str, Any]:
    values: dict[str, Any] = {
        "id": processing_id,
        "snapshot_version": SNAPSHOT_VERSION,
        "detection_identifier": alert.detection.identifier,
        "detection_name": alert.detection.name,
        "detected_at": alert.detected_at,
        "source": alert.source.source,
        "source_alert_id": alert.source.source_alert_id,
        "severity": alert.severity.value,
        "entities": Jsonb(_encode_entities(alert.entities)),
        "alert_evidence": Jsonb(_encode_evidence(alert.evidence)),
        "decision_outcome": result.decision.outcome.value,
        "policy_id": result.decision.policy_id,
        "decision_reasons": Jsonb(list(result.decision.reasons)),
        "request_desired_outcome": None,
        "request_capabilities": None,
        "request_targets": None,
        "result_backend": None,
        "result_completed_capabilities": None,
        "result_evidence": None,
    }
    if result.decision.outcome is DecisionOutcome.INVESTIGATE:
        request = result.investigation_request
        investigation_result = result.investigation_result
        if request is None or investigation_result is None:
            raise ValueError("investigate result is missing request or backend result")
        values.update(
            request_desired_outcome=request.desired_outcome,
            request_capabilities=Jsonb(list(request.required_capabilities)),
            request_targets=Jsonb(_encode_entities(request.targets)),
            result_backend=investigation_result.backend,
            result_completed_capabilities=Jsonb(
                list(investigation_result.completed_capabilities)
            ),
            result_evidence=Jsonb(_encode_evidence(investigation_result.evidence)),
        )
    return values


def _deserialize_row(row: Mapping[str, Any]) -> ProcessingRecord:
    version = row["snapshot_version"]
    if version != SNAPSHOT_VERSION:
        raise ValueError(f"unsupported processing snapshot version: {version!r}")

    source = SourceProvenance(
        source=row["source"],
        source_alert_id=row["source_alert_id"],
    )
    alert = CanonicalAlert(
        detection=DetectionIdentity(
            identifier=row["detection_identifier"],
            name=row["detection_name"],
        ),
        detected_at=row["detected_at"],
        source=source,
        entities=_decode_entities(row["entities"], "entities"),
        severity=Severity(row["severity"]),
        evidence=_decode_evidence(row["alert_evidence"], "alert_evidence"),
    )
    decision = Decision(
        outcome=DecisionOutcome(row["decision_outcome"]),
        policy_id=row["policy_id"],
        reasons=_decode_strings(row["decision_reasons"], "decision_reasons"),
        source=alert.source,
    )

    if decision.outcome is DecisionOutcome.NO_ACTION:
        result = OrchestrationResult(
            decision=decision,
            incident=None,
            investigation_request=None,
            investigation_result=None,
        )
    else:
        incident = Incident(alert=alert, decision=decision)
        request = InvestigationRequest(
            incident=incident,
            desired_outcome=row["request_desired_outcome"],
            required_capabilities=_decode_strings(
                row["request_capabilities"], "request_capabilities"
            ),
            targets=_decode_entities(row["request_targets"], "request_targets"),
        )
        investigation_result = InvestigationResult(
            backend=row["result_backend"],
            completed_capabilities=_decode_strings(
                row["result_completed_capabilities"],
                "result_completed_capabilities",
            ),
            evidence=_decode_evidence(row["result_evidence"], "result_evidence"),
        )
        result = OrchestrationResult(
            decision=decision,
            incident=incident,
            investigation_request=request,
            investigation_result=investigation_result,
        )

    return ProcessingRecord(
        processing_id=row["id"],
        created_at=row["created_at"],
        alert=alert,
        result=result,
    )


class PostgresProcessingRepository:
    """Store snapshot-v1 processing records with one connection per operation."""

    def __init__(self, database_url: str) -> None:
        if not database_url.strip():
            raise ValueError("database_url must be non-empty")
        self._database_url = database_url

    def check_readiness(self) -> None:
        """Verify bounded connectivity and the exact required migration revision."""

        with psycopg.connect(
            self._database_url,
            connect_timeout=_READINESS_CONNECT_TIMEOUT_SECONDS,
            options=(
                "-c statement_timeout="
                f"{_READINESS_STATEMENT_TIMEOUT_MILLISECONDS}"
            ),
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                if cursor.fetchone() != (1,):
                    raise RuntimeError("PostgreSQL connectivity check failed")
                cursor.execute("SELECT version_num FROM alembic_version")
                revisions = cursor.fetchall()
        if revisions != [(SCHEMA_REVISION,)]:
            raise RuntimeError("Alert2IR schema is not at the required revision")

    def save(
        self,
        processing_id: UUID,
        alert: CanonicalAlert,
        result: OrchestrationResult,
    ) -> ProcessingRecord:
        values = _serialize_values(processing_id, alert, result)
        with psycopg.connect(self._database_url) as connection:
            with connection.cursor() as cursor:
                cursor.execute(_INSERT_SQL, values)
                created_at = cursor.fetchone()[0]
                record = ProcessingRecord(
                    processing_id=processing_id,
                    created_at=created_at,
                    alert=alert,
                    result=result,
                )
        return record

    def get(self, processing_id: UUID) -> ProcessingRecord | None:
        with psycopg.connect(self._database_url, row_factory=dict_row) as connection:
            with connection.cursor() as cursor:
                cursor.execute(_SELECT_SQL, (processing_id,))
                row = cursor.fetchone()
        if row is None:
            return None
        return _deserialize_row(row)
