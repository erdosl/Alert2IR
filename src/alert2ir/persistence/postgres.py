"""PostgreSQL durable processing and execution-attempt repository."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from alert2ir.application import (
    ExecutionAttempt,
    ExecutionAttemptState,
    OrchestrationResult,
    PlannedProcessing,
    ProcessingAcceptance,
    ProcessingRecord,
    ProcessingState,
)
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
SCHEMA_REVISION = "0002_durable_execution"
_READINESS_CONNECT_TIMEOUT_SECONDS = 3
_READINESS_STATEMENT_TIMEOUT_MILLISECONDS = 2000
_LIFECYCLE_CONNECT_TIMEOUT_SECONDS = 3
_LIFECYCLE_STATEMENT_TIMEOUT_MILLISECONDS = 5000

_PROCESSING_COLUMNS = """
    id, created_at, updated_at, snapshot_version,
    detection_identifier, detection_name, detected_at,
    source, source_alert_id, severity, entities, alert_evidence,
    idempotency_scope, idempotency_key, fingerprint_version,
    request_fingerprint, state, selected_backend,
    decision_outcome, policy_id, decision_reasons,
    request_desired_outcome, request_capabilities, request_targets,
    result_backend, result_completed_capabilities, result_evidence,
    completed_at, failed_at, error_category, error_detail
"""

_ATTEMPT_COLUMNS = """
    attempt_id, processing_id, attempt_number, operation_key, backend, state,
    external_operation_id, created_at, started_at, submitted_at,
    last_polled_at, completed_at, failed_at, last_remote_state,
    error_category, error_detail
"""

_INSERT_ACCEPT_SQL = f"""
    INSERT INTO processing_records (
        id, snapshot_version, detection_identifier, detection_name, detected_at,
        source, source_alert_id, severity, entities, alert_evidence,
        idempotency_scope, idempotency_key, fingerprint_version,
        request_fingerprint, state
    ) VALUES (
        %(id)s, %(snapshot_version)s, %(detection_identifier)s,
        %(detection_name)s, %(detected_at)s, %(source)s, %(source_alert_id)s,
        %(severity)s, %(entities)s, %(alert_evidence)s,
        %(idempotency_scope)s, %(idempotency_key)s, %(fingerprint_version)s,
        %(request_fingerprint)s, 'accepted'
    )
    ON CONFLICT (idempotency_scope, idempotency_key) DO NOTHING
    RETURNING {_PROCESSING_COLUMNS}
"""

_SELECT_PROCESSING_SQL = f"""
    SELECT {_PROCESSING_COLUMNS}
    FROM processing_records
    WHERE id = %s
"""

_SELECT_IDEMPOTENCY_SQL = f"""
    SELECT {_PROCESSING_COLUMNS}
    FROM processing_records
    WHERE idempotency_scope = %s AND idempotency_key = %s
"""

_SELECT_ATTEMPT_SQL = f"""
    SELECT {_ATTEMPT_COLUMNS}
    FROM execution_attempts
    WHERE attempt_id = %s
"""

_SELECT_PROCESSING_ATTEMPT_SQL = f"""
    SELECT {_ATTEMPT_COLUMNS}
    FROM execution_attempts
    WHERE processing_id = %s
    ORDER BY attempt_number DESC
    LIMIT 1
"""


def _encode_entities(values: tuple[Entity, ...]) -> list[dict[str, str]]:
    return [{"kind": value.kind, "value": value.value} for value in values]


def _encode_evidence(
    values: tuple[EvidenceReference, ...],
) -> list[dict[str, str | None]]:
    return [{"reference": value.reference, "kind": value.kind} for value in values]


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
        decoded.append(EvidenceReference(reference=item["reference"], kind=item["kind"]))
    return tuple(decoded)


def _decode_strings(value: Any, field_name: str) -> tuple[str, ...]:
    values = _require_array(value, field_name)
    if any(not isinstance(item, str) for item in values):
        raise ValueError(f"snapshot v1 {field_name} must contain only strings")
    return tuple(values)


def _canonical_values(
    processing_id: UUID,
    alert: CanonicalAlert,
    *,
    idempotency_scope: str,
    idempotency_key: str,
    fingerprint_version: int,
    request_fingerprint: bytes,
) -> dict[str, Any]:
    return {
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
        "idempotency_scope": idempotency_scope,
        "idempotency_key": idempotency_key,
        "fingerprint_version": fingerprint_version,
        "request_fingerprint": request_fingerprint,
    }


def _decision_values(decision: Decision) -> dict[str, Any]:
    return {
        "decision_outcome": decision.outcome.value,
        "policy_id": decision.policy_id,
        "decision_reasons": Jsonb(list(decision.reasons)),
    }


def _request_values(request: InvestigationRequest) -> dict[str, Any]:
    return {
        "request_desired_outcome": request.desired_outcome,
        "request_capabilities": Jsonb(list(request.required_capabilities)),
        "request_targets": Jsonb(_encode_entities(request.targets)),
    }


def _result_values(result: InvestigationResult) -> dict[str, Any]:
    return {
        "result_backend": result.backend,
        "result_completed_capabilities": Jsonb(
            list(result.completed_capabilities)
        ),
        "result_evidence": Jsonb(_encode_evidence(result.evidence)),
    }


def _deserialize_processing(row: Mapping[str, Any]) -> ProcessingRecord:
    version = row["snapshot_version"]
    if version != SNAPSHOT_VERSION:
        raise ValueError(f"unsupported processing snapshot version: {version!r}")

    source = SourceProvenance(row["source"], row["source_alert_id"])
    alert = CanonicalAlert(
        detection=DetectionIdentity(
            row["detection_identifier"], row["detection_name"]
        ),
        detected_at=row["detected_at"],
        source=source,
        entities=_decode_entities(row["entities"], "entities"),
        severity=Severity(row["severity"]),
        evidence=_decode_evidence(row["alert_evidence"], "alert_evidence"),
    )

    decision = None
    incident = None
    request = None
    if row["decision_outcome"] is not None:
        decision = Decision(
            outcome=DecisionOutcome(row["decision_outcome"]),
            policy_id=row["policy_id"],
            reasons=_decode_strings(row["decision_reasons"], "decision_reasons"),
            source=source,
        )
        if decision.outcome is DecisionOutcome.INVESTIGATE and row[
            "request_desired_outcome"
        ] is not None:
            incident = Incident(alert=alert, decision=decision)
            request = InvestigationRequest(
                incident=incident,
                desired_outcome=row["request_desired_outcome"],
                required_capabilities=_decode_strings(
                    row["request_capabilities"], "request_capabilities"
                ),
                targets=_decode_entities(row["request_targets"], "request_targets"),
            )

    completed_result = None
    if ProcessingState(row["state"]) is ProcessingState.COMPLETED:
        if decision is None:
            raise ValueError("completed processing is missing its decision")
        if decision.outcome is DecisionOutcome.NO_ACTION:
            completed_result = OrchestrationResult(decision, None, None, None)
        else:
            if incident is None or request is None:
                raise ValueError("completed investigation is missing its request")
            investigation_result = InvestigationResult(
                backend=row["result_backend"],
                completed_capabilities=_decode_strings(
                    row["result_completed_capabilities"],
                    "result_completed_capabilities",
                ),
                evidence=_decode_evidence(row["result_evidence"], "result_evidence"),
            )
            completed_result = OrchestrationResult(
                decision, incident, request, investigation_result
            )

    return ProcessingRecord(
        processing_id=row["id"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        alert=alert,
        state=ProcessingState(row["state"]),
        idempotency_scope=row["idempotency_scope"],
        idempotency_key=row["idempotency_key"],
        fingerprint_version=row["fingerprint_version"],
        request_fingerprint=row["request_fingerprint"],
        planned_decision=decision if completed_result is None else None,
        planned_incident=incident if completed_result is None else None,
        planned_request=request if completed_result is None else None,
        selected_backend=row["selected_backend"],
        completed_result=completed_result,
        completed_at=row["completed_at"],
        failed_at=row["failed_at"],
        error_category=row["error_category"],
        error_detail=row["error_detail"],
    )


def _deserialize_row(row: Mapping[str, Any]) -> ProcessingRecord:
    """Retain the historical mapping helper name used by focused tests."""

    return _deserialize_processing(row)


def _deserialize_attempt(row: Mapping[str, Any]) -> ExecutionAttempt:
    return ExecutionAttempt(
        attempt_id=row["attempt_id"],
        processing_id=row["processing_id"],
        attempt_number=row["attempt_number"],
        operation_key=row["operation_key"],
        backend=row["backend"],
        state=ExecutionAttemptState(row["state"]),
        external_operation_id=row["external_operation_id"],
        created_at=row["created_at"],
        started_at=row["started_at"],
        submitted_at=row["submitted_at"],
        last_polled_at=row["last_polled_at"],
        completed_at=row["completed_at"],
        failed_at=row["failed_at"],
        last_remote_state=row["last_remote_state"],
        error_category=row["error_category"],
        error_detail=row["error_detail"],
    )


def _validate_error(error_category: str, error_detail: str) -> None:
    for name, value in (
        ("error_category", error_category),
        ("error_detail", error_detail),
    ):
        if not value or len(value) > 256:
            raise ValueError(f"{name} must contain 1-256 characters")


class PostgresProcessingRepository:
    """Use one short PostgreSQL transaction for each lifecycle operation."""

    def __init__(self, database_url: str) -> None:
        if not database_url.strip():
            raise ValueError("database_url must be non-empty")
        self._database_url = database_url

    def _connect(self):
        """Open one bounded lifecycle transaction using dictionary rows."""

        return psycopg.connect(
            self._database_url,
            row_factory=dict_row,
            connect_timeout=_LIFECYCLE_CONNECT_TIMEOUT_SECONDS,
            options=(
                "-c statement_timeout="
                f"{_LIFECYCLE_STATEMENT_TIMEOUT_MILLISECONDS}"
            ),
        )

    def check_readiness(self) -> None:
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

    def accept_processing(
        self,
        processing_id: UUID,
        alert: CanonicalAlert,
        idempotency_scope: str,
        idempotency_key: str,
        fingerprint_version: int,
        request_fingerprint: bytes,
    ) -> ProcessingAcceptance:
        values = _canonical_values(
            processing_id,
            alert,
            idempotency_scope=idempotency_scope,
            idempotency_key=idempotency_key,
            fingerprint_version=fingerprint_version,
            request_fingerprint=request_fingerprint,
        )
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(_INSERT_ACCEPT_SQL, values)
                row = cursor.fetchone()
                created = row is not None
                if row is None:
                    cursor.execute(
                        _SELECT_IDEMPOTENCY_SQL,
                        (idempotency_scope, idempotency_key),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        raise RuntimeError("idempotency conflict row could not be read")
        return ProcessingAcceptance(_deserialize_processing(row), created)

    def get(self, processing_id: UUID) -> ProcessingRecord | None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(_SELECT_PROCESSING_SQL, (processing_id,))
                row = cursor.fetchone()
        return None if row is None else _deserialize_processing(row)

    def get_by_idempotency(
        self, idempotency_scope: str, idempotency_key: str
    ) -> ProcessingRecord | None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    _SELECT_IDEMPOTENCY_SQL,
                    (idempotency_scope, idempotency_key),
                )
                row = cursor.fetchone()
        return None if row is None else _deserialize_processing(row)

    def store_no_action_result(
        self, processing_id: UUID, result: OrchestrationResult
    ) -> ProcessingRecord | None:
        if result.decision.outcome is not DecisionOutcome.NO_ACTION:
            raise ValueError("no-action completion requires a no_action result")
        values = {"id": processing_id, **_decision_values(result.decision)}
        sql = f"""
            UPDATE processing_records
            SET state = 'completed', updated_at = CURRENT_TIMESTAMP,
                completed_at = CURRENT_TIMESTAMP,
                decision_outcome = %(decision_outcome)s,
                policy_id = %(policy_id)s,
                decision_reasons = %(decision_reasons)s
            WHERE id = %(id)s AND state = 'accepted'
            RETURNING {_PROCESSING_COLUMNS}
        """
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(sql, values)
                row = cursor.fetchone()
        return None if row is None else _deserialize_processing(row)

    def store_plan(
        self,
        processing_id: UUID,
        decision: Decision,
        incident: Incident,
        request: InvestigationRequest,
        selected_backend: str,
        attempt_id: UUID,
        operation_key: UUID,
    ) -> PlannedProcessing | None:
        if decision.outcome is not DecisionOutcome.INVESTIGATE:
            raise ValueError("execution plan requires an investigate decision")
        if incident.alert.source != decision.source or request.incident != incident:
            raise ValueError("plan graph is inconsistent")
        values = {
            "id": processing_id,
            "selected_backend": selected_backend,
            "attempt_id": attempt_id,
            "operation_key": operation_key,
            **_decision_values(decision),
            **_request_values(request),
        }
        update_sql = """
            UPDATE processing_records
            SET state = 'planned', updated_at = CURRENT_TIMESTAMP,
                selected_backend = %(selected_backend)s,
                decision_outcome = %(decision_outcome)s,
                policy_id = %(policy_id)s,
                decision_reasons = %(decision_reasons)s,
                request_desired_outcome = %(request_desired_outcome)s,
                request_capabilities = %(request_capabilities)s,
                request_targets = %(request_targets)s
            WHERE id = %(id)s AND state = 'accepted'
            RETURNING id
        """
        insert_attempt = f"""
            INSERT INTO execution_attempts (
                attempt_id, processing_id, attempt_number, operation_key,
                backend, state
            ) VALUES (
                %(attempt_id)s, %(id)s, 1, %(operation_key)s,
                %(selected_backend)s, 'planned'
            )
            RETURNING {_ATTEMPT_COLUMNS}
        """
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(update_sql, values)
                if cursor.fetchone() is None:
                    return None
                cursor.execute(insert_attempt, values)
                attempt_row = cursor.fetchone()
                cursor.execute(_SELECT_PROCESSING_SQL, (processing_id,))
                processing_row = cursor.fetchone()
        if attempt_row is None or processing_row is None:
            raise RuntimeError("stored plan could not be read")
        return PlannedProcessing(
            _deserialize_processing(processing_row),
            _deserialize_attempt(attempt_row),
        )

    def get_attempt(self, attempt_id: UUID) -> ExecutionAttempt | None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(_SELECT_ATTEMPT_SQL, (attempt_id,))
                row = cursor.fetchone()
        return None if row is None else _deserialize_attempt(row)

    def get_attempt_for_processing(
        self, processing_id: UUID
    ) -> ExecutionAttempt | None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(_SELECT_PROCESSING_ATTEMPT_SQL, (processing_id,))
                row = cursor.fetchone()
        return None if row is None else _deserialize_attempt(row)

    def claim_attempt_for_submission(
        self, attempt_id: UUID
    ) -> ExecutionAttempt | None:
        attempt_sql = f"""
            UPDATE execution_attempts
            SET state = 'submitting', started_at = CURRENT_TIMESTAMP
            WHERE attempt_id = %s AND state = 'planned'
            RETURNING {_ATTEMPT_COLUMNS}
        """
        processing_sql = """
            UPDATE processing_records
            SET state = 'submitting', updated_at = CURRENT_TIMESTAMP
            WHERE id = %s AND state = 'planned'
            RETURNING id
        """
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(attempt_sql, (attempt_id,))
                row = cursor.fetchone()
                if row is None:
                    return None
                cursor.execute(processing_sql, (row["processing_id"],))
                if cursor.fetchone() is None:
                    raise RuntimeError("processing and attempt claim states diverged")
        return _deserialize_attempt(row)

    def mark_attempt_submitted(
        self, attempt_id: UUID, external_operation_id: str
    ) -> ExecutionAttempt | None:
        attempt_sql = f"""
            UPDATE execution_attempts
            SET state = 'submitted', external_operation_id = %s,
                submitted_at = CURRENT_TIMESTAMP
            WHERE attempt_id = %s AND state = 'submitting'
            RETURNING {_ATTEMPT_COLUMNS}
        """
        processing_sql = """
            UPDATE processing_records
            SET state = 'submitted', updated_at = CURRENT_TIMESTAMP
            WHERE id = %s AND state = 'submitting'
            RETURNING id
        """
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(attempt_sql, (external_operation_id, attempt_id))
                row = cursor.fetchone()
                if row is None:
                    return None
                cursor.execute(processing_sql, (row["processing_id"],))
                if cursor.fetchone() is None:
                    raise RuntimeError("processing and submitted attempt states diverged")
        return _deserialize_attempt(row)

    def record_poll(
        self,
        attempt_id: UUID,
        remote_state: str,
        error_category: str | None = None,
        error_detail: str | None = None,
    ) -> ExecutionAttempt | None:
        if error_category is not None or error_detail is not None:
            if error_category is None or error_detail is None:
                raise ValueError("poll error category and detail must be present together")
            _validate_error(error_category, error_detail)
        sql = f"""
            UPDATE execution_attempts
            SET last_polled_at = CURRENT_TIMESTAMP,
                last_remote_state = %(remote_state)s,
                error_category = %(error_category)s,
                error_detail = %(error_detail)s
            WHERE attempt_id = %(attempt_id)s AND state = 'submitted'
            RETURNING {_ATTEMPT_COLUMNS}
        """
        processing_sql = """
            UPDATE processing_records
            SET updated_at = CURRENT_TIMESTAMP,
                error_category = %s, error_detail = %s
            WHERE id = %s AND state = 'submitted'
            RETURNING id
        """
        values = {
            "attempt_id": attempt_id,
            "remote_state": remote_state,
            "error_category": error_category,
            "error_detail": error_detail,
        }
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(sql, values)
                row = cursor.fetchone()
                if row is None:
                    return None
                cursor.execute(
                    processing_sql,
                    (error_category, error_detail, row["processing_id"]),
                )
                if cursor.fetchone() is None:
                    raise RuntimeError("processing and polled attempt states diverged")
        return _deserialize_attempt(row)

    def complete_processing(
        self,
        attempt_id: UUID,
        result: OrchestrationResult,
    ) -> ProcessingRecord | None:
        if (
            result.decision.outcome is not DecisionOutcome.INVESTIGATE
            or result.investigation_result is None
        ):
            raise ValueError("attempt completion requires an investigate result")
        result_values = {
            "attempt_id": attempt_id,
            **_result_values(result.investigation_result),
        }
        attempt_sql = """
            UPDATE execution_attempts
            SET state = 'completed', completed_at = CURRENT_TIMESTAMP,
                last_polled_at = CURRENT_TIMESTAMP,
                last_remote_state = 'succeeded',
                error_category = NULL, error_detail = NULL
            WHERE attempt_id = %(attempt_id)s AND state = 'submitted'
            RETURNING processing_id
        """
        processing_sql = f"""
            UPDATE processing_records
            SET state = 'completed', updated_at = CURRENT_TIMESTAMP,
                completed_at = CURRENT_TIMESTAMP,
                result_backend = %(result_backend)s,
                result_completed_capabilities = %(result_completed_capabilities)s,
                result_evidence = %(result_evidence)s,
                error_category = NULL, error_detail = NULL
            WHERE id = %(processing_id)s AND state = 'submitted'
            RETURNING {_PROCESSING_COLUMNS}
        """
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(attempt_sql, result_values)
                attempt_row = cursor.fetchone()
                if attempt_row is None:
                    return None
                values = {**result_values, "processing_id": attempt_row["processing_id"]}
                cursor.execute(processing_sql, values)
                row = cursor.fetchone()
                if row is None:
                    raise RuntimeError("processing and completed attempt states diverged")
        completed = _deserialize_processing(row)
        if completed.completed_result != result:
            raise ValueError("terminal result does not match the durable processing plan")
        return completed

    def fail_processing(
        self,
        processing_id: UUID,
        expected_states: frozenset[ProcessingState],
        error_category: str,
        error_detail: str,
        attempt_id: UUID | None = None,
    ) -> ProcessingRecord | None:
        _validate_error(error_category, error_detail)
        if not expected_states:
            raise ValueError("expected processing states cannot be empty")
        processing_sql = f"""
            UPDATE processing_records
            SET state = 'failed', updated_at = CURRENT_TIMESTAMP,
                failed_at = CURRENT_TIMESTAMP,
                error_category = %(error_category)s,
                error_detail = %(error_detail)s
            WHERE id = %(processing_id)s AND state = ANY(%(states)s)
            RETURNING {_PROCESSING_COLUMNS}
        """
        attempt_sql = """
            UPDATE execution_attempts
            SET state = 'failed', failed_at = CURRENT_TIMESTAMP,
                error_category = %(error_category)s,
                error_detail = %(error_detail)s
            WHERE attempt_id = %(attempt_id)s
              AND processing_id = %(processing_id)s
              AND state IN ('planned', 'submitting', 'submitted', 'recovery_required')
            RETURNING attempt_id
        """
        values = {
            "processing_id": processing_id,
            "states": [state.value for state in expected_states],
            "attempt_id": attempt_id,
            "error_category": error_category,
            "error_detail": error_detail,
        }
        with self._connect() as connection:
            with connection.cursor() as cursor:
                if attempt_id is not None:
                    cursor.execute(attempt_sql, values)
                    if cursor.fetchone() is None:
                        return None
                cursor.execute(processing_sql, values)
                row = cursor.fetchone()
                if row is None and attempt_id is not None:
                    raise RuntimeError("processing and failed attempt states diverged")
        return None if row is None else _deserialize_processing(row)

    def mark_recovery_required(
        self,
        attempt_id: UUID,
        expected_states: frozenset[ExecutionAttemptState],
        error_category: str,
        error_detail: str,
    ) -> ProcessingRecord | None:
        _validate_error(error_category, error_detail)
        allowed = {
            ExecutionAttemptState.SUBMITTING,
            ExecutionAttemptState.SUBMITTED,
        }
        if not expected_states or not expected_states <= allowed:
            raise ValueError("invalid recovery-required expected states")
        attempt_sql = """
            UPDATE execution_attempts
            SET state = 'recovery_required',
                error_category = %(error_category)s,
                error_detail = %(error_detail)s
            WHERE attempt_id = %(attempt_id)s AND state = ANY(%(states)s)
            RETURNING processing_id, state
        """
        processing_sql = f"""
            UPDATE processing_records
            SET state = 'recovery_required', updated_at = CURRENT_TIMESTAMP,
                error_category = %(error_category)s,
                error_detail = %(error_detail)s
            WHERE id = %(processing_id)s AND state = ANY(%(processing_states)s)
            RETURNING {_PROCESSING_COLUMNS}
        """
        values = {
            "attempt_id": attempt_id,
            "states": [state.value for state in expected_states],
            "processing_states": [
                ProcessingState(state.value).value for state in expected_states
            ],
            "error_category": error_category,
            "error_detail": error_detail,
        }
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(attempt_sql, values)
                attempt_row = cursor.fetchone()
                if attempt_row is None:
                    return None
                values["processing_id"] = attempt_row["processing_id"]
                cursor.execute(processing_sql, values)
                row = cursor.fetchone()
                if row is None:
                    raise RuntimeError("processing and recovery attempt states diverged")
        return _deserialize_processing(row)

    def find_reconcilable(
        self,
        *,
        limit: int,
        stale_submitting_before: datetime,
    ) -> tuple[ProcessingRecord, ...]:
        if limit < 1:
            raise ValueError("reconciliation limit must be positive")
        sql = f"""
            SELECT {_PROCESSING_COLUMNS.replace('id,', 'p.id,', 1)}
            FROM processing_records AS p
            LEFT JOIN execution_attempts AS a ON a.processing_id = p.id
            WHERE p.state IN ('accepted', 'planned', 'submitted')
               OR (
                    p.state = 'submitting'
                    AND a.state = 'submitting'
                    AND a.started_at <= %s
               )
            ORDER BY p.updated_at, p.id
            LIMIT %s
        """
        # Every unqualified name after p.id is unique to processing_records today.
        # Explicit qualification is retained for the columns shared with attempts.
        sql = sql.replace(" created_at, updated_at,", " p.created_at, p.updated_at,")
        sql = sql.replace(" state, selected_backend,", " p.state, selected_backend,")
        sql = sql.replace(" completed_at, failed_at, error_category, error_detail", " p.completed_at, p.failed_at, p.error_category, p.error_detail")
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(sql, (stale_submitting_before, limit))
                rows = cursor.fetchall()
        return tuple(_deserialize_processing(row) for row in rows)
