"""Thread-safe deterministic in-memory durable-lifecycle repository."""

from collections.abc import Callable
from dataclasses import replace
from datetime import datetime
from threading import RLock
from uuid import UUID

from alert2ir.application.orchestrator import OrchestrationResult
from alert2ir.application.persistence import (
    ExecutionAttempt,
    ExecutionAttemptState,
    PlannedProcessing,
    ProcessingAcceptance,
    ProcessingRecord,
    ProcessingState,
)
from alert2ir.core.models import CanonicalAlert
from alert2ir.core.workflow import Decision, DecisionOutcome, Incident, InvestigationRequest


class InMemoryProcessingRepository:
    def __init__(self, clock: Callable[[], datetime]) -> None:
        self._clock = clock
        self._records: dict[UUID, ProcessingRecord] = {}
        self._idempotency: dict[tuple[str, str], UUID] = {}
        self._attempts: dict[UUID, ExecutionAttempt] = {}
        self._attempt_by_processing: dict[UUID, UUID] = {}
        self._operation_keys: set[UUID] = set()
        self._lock = RLock()

    def check_readiness(self) -> None:
        """The in-memory repository has no external readiness dependency."""

    def accept_processing(
        self,
        processing_id: UUID,
        alert: CanonicalAlert,
        idempotency_scope: str,
        idempotency_key: str,
        fingerprint_version: int,
        request_fingerprint: bytes,
    ) -> ProcessingAcceptance:
        if idempotency_scope != alert.source.source:
            raise ValueError("idempotency scope must equal canonical source")
        if (
            not 1 <= len(idempotency_key) <= 128
            or any(
                not 0x21 <= ord(character) <= 0x7E
                for character in idempotency_key
            )
        ):
            raise ValueError("idempotency key must be visible ASCII")
        identity = (idempotency_scope, idempotency_key)
        with self._lock:
            existing_id = self._idempotency.get(identity)
            if existing_id is not None:
                return ProcessingAcceptance(self._records[existing_id], False)
            if processing_id in self._records:
                raise ValueError(f"processing ID already exists: {processing_id}")
            now = self._clock()
            record = ProcessingRecord(
                processing_id=processing_id,
                created_at=now,
                updated_at=now,
                alert=alert,
                state=ProcessingState.ACCEPTED,
                idempotency_scope=idempotency_scope,
                idempotency_key=idempotency_key,
                fingerprint_version=fingerprint_version,
                request_fingerprint=request_fingerprint,
            )
            self._records[processing_id] = record
            self._idempotency[identity] = processing_id
            return ProcessingAcceptance(record, True)

    def get(self, processing_id: UUID) -> ProcessingRecord | None:
        with self._lock:
            return self._records.get(processing_id)

    def get_by_idempotency(
        self, idempotency_scope: str, idempotency_key: str
    ) -> ProcessingRecord | None:
        with self._lock:
            processing_id = self._idempotency.get(
                (idempotency_scope, idempotency_key)
            )
            return None if processing_id is None else self._records[processing_id]

    def store_no_action_result(
        self, processing_id: UUID, result: OrchestrationResult
    ) -> ProcessingRecord | None:
        if result.decision.outcome is not DecisionOutcome.NO_ACTION:
            raise ValueError("no-action completion requires a no_action result")
        with self._lock:
            current = self._records.get(processing_id)
            if current is None or current.state is not ProcessingState.ACCEPTED:
                return None
            now = self._clock()
            updated = replace(
                current,
                state=ProcessingState.COMPLETED,
                updated_at=now,
                completed_result=result,
                completed_at=now,
            )
            self._records[processing_id] = updated
            return updated

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
        with self._lock:
            current = self._records.get(processing_id)
            if current is None or current.state is not ProcessingState.ACCEPTED:
                return None
            if processing_id in self._attempt_by_processing:
                return None
            if attempt_id in self._attempts or operation_key in self._operation_keys:
                raise ValueError("attempt or operation key already exists")
            now = self._clock()
            record = replace(
                current,
                state=ProcessingState.PLANNED,
                updated_at=now,
                planned_decision=decision,
                planned_incident=incident,
                planned_request=request,
                selected_backend=selected_backend,
            )
            attempt = ExecutionAttempt(
                attempt_id=attempt_id,
                processing_id=processing_id,
                attempt_number=1,
                operation_key=operation_key,
                backend=selected_backend,
                state=ExecutionAttemptState.PLANNED,
                created_at=now,
            )
            self._records[processing_id] = record
            self._attempts[attempt_id] = attempt
            self._attempt_by_processing[processing_id] = attempt_id
            self._operation_keys.add(operation_key)
            return PlannedProcessing(record, attempt)

    def get_attempt(self, attempt_id: UUID) -> ExecutionAttempt | None:
        with self._lock:
            return self._attempts.get(attempt_id)

    def get_attempt_for_processing(
        self, processing_id: UUID
    ) -> ExecutionAttempt | None:
        with self._lock:
            attempt_id = self._attempt_by_processing.get(processing_id)
            return None if attempt_id is None else self._attempts[attempt_id]

    def claim_attempt_for_submission(
        self, attempt_id: UUID
    ) -> ExecutionAttempt | None:
        with self._lock:
            attempt = self._attempts.get(attempt_id)
            if attempt is None or attempt.state is not ExecutionAttemptState.PLANNED:
                return None
            record = self._records[attempt.processing_id]
            if record.state is not ProcessingState.PLANNED:
                return None
            now = self._clock()
            claimed = replace(
                attempt,
                state=ExecutionAttemptState.SUBMITTING,
                started_at=now,
            )
            self._attempts[attempt_id] = claimed
            self._records[record.processing_id] = replace(
                record,
                state=ProcessingState.SUBMITTING,
                updated_at=now,
            )
            return claimed

    def mark_attempt_submitted(
        self, attempt_id: UUID, external_operation_id: str
    ) -> ExecutionAttempt | None:
        with self._lock:
            attempt = self._attempts.get(attempt_id)
            if attempt is None or attempt.state is not ExecutionAttemptState.SUBMITTING:
                return None
            record = self._records[attempt.processing_id]
            if record.state is not ProcessingState.SUBMITTING:
                return None
            now = self._clock()
            submitted = replace(
                attempt,
                state=ExecutionAttemptState.SUBMITTED,
                external_operation_id=external_operation_id,
                submitted_at=now,
            )
            self._attempts[attempt_id] = submitted
            self._records[record.processing_id] = replace(
                record,
                state=ProcessingState.SUBMITTED,
                updated_at=now,
            )
            return submitted

    def record_poll(
        self,
        attempt_id: UUID,
        remote_state: str,
        error_category: str | None = None,
        error_detail: str | None = None,
    ) -> ExecutionAttempt | None:
        with self._lock:
            attempt = self._attempts.get(attempt_id)
            if attempt is None or attempt.state is not ExecutionAttemptState.SUBMITTED:
                return None
            record = self._records[attempt.processing_id]
            if record.state is not ProcessingState.SUBMITTED:
                return None
            now = self._clock()
            polled = replace(
                attempt,
                last_polled_at=now,
                last_remote_state=remote_state,
                error_category=error_category,
                error_detail=error_detail,
            )
            self._attempts[attempt_id] = polled
            self._records[record.processing_id] = replace(
                record,
                updated_at=now,
                error_category=error_category,
                error_detail=error_detail,
            )
            return polled

    def complete_processing(
        self,
        attempt_id: UUID,
        result: OrchestrationResult,
    ) -> ProcessingRecord | None:
        if result.decision.outcome is not DecisionOutcome.INVESTIGATE:
            raise ValueError("attempt completion requires an investigate result")
        with self._lock:
            attempt = self._attempts.get(attempt_id)
            if attempt is None or attempt.state is not ExecutionAttemptState.SUBMITTED:
                return None
            record = self._records[attempt.processing_id]
            if record.state is not ProcessingState.SUBMITTED:
                return None
            now = self._clock()
            completed_attempt = replace(
                attempt,
                state=ExecutionAttemptState.COMPLETED,
                completed_at=now,
                last_polled_at=now,
                last_remote_state="succeeded",
                error_category=None,
                error_detail=None,
            )
            completed_record = replace(
                record,
                state=ProcessingState.COMPLETED,
                updated_at=now,
                completed_at=now,
                completed_result=result,
                error_category=None,
                error_detail=None,
            )
            self._attempts[attempt_id] = completed_attempt
            self._records[record.processing_id] = completed_record
            return completed_record

    def fail_processing(
        self,
        processing_id: UUID,
        expected_states: frozenset[ProcessingState],
        error_category: str,
        error_detail: str,
        attempt_id: UUID | None = None,
    ) -> ProcessingRecord | None:
        with self._lock:
            record = self._records.get(processing_id)
            if record is None or record.state not in expected_states:
                return None
            attempt = None
            if attempt_id is not None:
                attempt = self._attempts.get(attempt_id)
                if attempt is None or attempt.processing_id != processing_id:
                    return None
                if attempt.state not in {
                    ExecutionAttemptState.PLANNED,
                    ExecutionAttemptState.SUBMITTING,
                    ExecutionAttemptState.SUBMITTED,
                    ExecutionAttemptState.RECOVERY_REQUIRED,
                }:
                    return None
            now = self._clock()
            failed_record = replace(
                record,
                state=ProcessingState.FAILED,
                updated_at=now,
                failed_at=now,
                error_category=error_category,
                error_detail=error_detail,
            )
            self._records[processing_id] = failed_record
            if attempt is not None:
                self._attempts[attempt_id] = replace(
                    attempt,
                    state=ExecutionAttemptState.FAILED,
                    failed_at=now,
                    error_category=error_category,
                    error_detail=error_detail,
                )
            return failed_record

    def mark_recovery_required(
        self,
        attempt_id: UUID,
        expected_states: frozenset[ExecutionAttemptState],
        error_category: str,
        error_detail: str,
    ) -> ProcessingRecord | None:
        with self._lock:
            attempt = self._attempts.get(attempt_id)
            if attempt is None or attempt.state not in expected_states:
                return None
            record = self._records[attempt.processing_id]
            expected_processing = {
                ExecutionAttemptState.SUBMITTING: ProcessingState.SUBMITTING,
                ExecutionAttemptState.SUBMITTED: ProcessingState.SUBMITTED,
            }.get(attempt.state)
            if record.state is not expected_processing:
                return None
            now = self._clock()
            self._attempts[attempt_id] = replace(
                attempt,
                state=ExecutionAttemptState.RECOVERY_REQUIRED,
                error_category=error_category,
                error_detail=error_detail,
            )
            recovery = replace(
                record,
                state=ProcessingState.RECOVERY_REQUIRED,
                updated_at=now,
                error_category=error_category,
                error_detail=error_detail,
            )
            self._records[record.processing_id] = recovery
            return recovery

    def find_reconcilable(
        self,
        *,
        limit: int,
        stale_submitting_before: datetime,
    ) -> tuple[ProcessingRecord, ...]:
        if limit < 1:
            raise ValueError("reconciliation limit must be positive")
        with self._lock:
            values: list[ProcessingRecord] = []
            for record in self._records.values():
                if record.state in {
                    ProcessingState.ACCEPTED,
                    ProcessingState.PLANNED,
                    ProcessingState.SUBMITTED,
                }:
                    values.append(record)
                elif record.state is ProcessingState.SUBMITTING:
                    attempt = self.get_attempt_for_processing(record.processing_id)
                    if (
                        attempt is not None
                        and attempt.started_at is not None
                        and attempt.started_at <= stale_submitting_before
                    ):
                        values.append(record)
            values.sort(key=lambda item: (item.updated_at, str(item.processing_id)))
            return tuple(values[:limit])
