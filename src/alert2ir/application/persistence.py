"""Durable processing and execution-attempt persistence contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from alert2ir.application.orchestrator import OrchestrationResult
from alert2ir.core.models import CanonicalAlert
from alert2ir.core.workflow import Decision, Incident, InvestigationRequest


class ProcessingState(StrEnum):
    ACCEPTED = "accepted"
    PLANNED = "planned"
    SUBMITTING = "submitting"
    SUBMITTED = "submitted"
    COMPLETED = "completed"
    FAILED = "failed"
    RECOVERY_REQUIRED = "recovery_required"


class ExecutionAttemptState(StrEnum):
    PLANNED = "planned"
    SUBMITTING = "submitting"
    SUBMITTED = "submitted"
    COMPLETED = "completed"
    FAILED = "failed"
    RECOVERY_REQUIRED = "recovery_required"


TERMINAL_PROCESSING_STATES = frozenset(
    {ProcessingState.COMPLETED, ProcessingState.FAILED}
)
ACTIVE_ATTEMPT_STATES = frozenset(
    {
        ExecutionAttemptState.PLANNED,
        ExecutionAttemptState.SUBMITTING,
        ExecutionAttemptState.SUBMITTED,
        ExecutionAttemptState.RECOVERY_REQUIRED,
    }
)


ALLOWED_PROCESSING_TRANSITIONS: dict[ProcessingState, frozenset[ProcessingState]] = {
    ProcessingState.ACCEPTED: frozenset(
        {
            ProcessingState.PLANNED,
            ProcessingState.COMPLETED,
            ProcessingState.FAILED,
        }
    ),
    ProcessingState.PLANNED: frozenset(
        {ProcessingState.SUBMITTING, ProcessingState.FAILED}
    ),
    ProcessingState.SUBMITTING: frozenset(
        {
            ProcessingState.SUBMITTED,
            ProcessingState.FAILED,
            ProcessingState.RECOVERY_REQUIRED,
        }
    ),
    ProcessingState.SUBMITTED: frozenset(
        {
            ProcessingState.SUBMITTED,
            ProcessingState.COMPLETED,
            ProcessingState.FAILED,
            ProcessingState.RECOVERY_REQUIRED,
        }
    ),
    ProcessingState.COMPLETED: frozenset(),
    ProcessingState.FAILED: frozenset(),
    ProcessingState.RECOVERY_REQUIRED: frozenset(
        {ProcessingState.SUBMITTED, ProcessingState.FAILED}
    ),
}


def processing_transition_allowed(
    from_state: ProcessingState,
    to_state: ProcessingState,
) -> bool:
    return to_state in ALLOWED_PROCESSING_TRANSITIONS[from_state]


def _require_aware(value: datetime | None, field_name: str) -> None:
    if value is not None and (
        value.tzinfo is None or value.utcoffset() is None
    ):
        raise ValueError(f"{field_name} must be timezone-aware")


def _require_bounded_error(value: str | None, field_name: str) -> None:
    if value is not None and (not value or len(value) > 256):
        raise ValueError(f"{field_name} must contain 1-256 characters")


@dataclass(frozen=True, slots=True)
class ProcessingRecord:
    """One durable logical processing at any lifecycle phase."""

    processing_id: UUID
    created_at: datetime
    updated_at: datetime
    alert: CanonicalAlert
    state: ProcessingState
    idempotency_scope: str | None = None
    idempotency_key: str | None = None
    fingerprint_version: int | None = None
    request_fingerprint: bytes | None = None
    planned_decision: Decision | None = None
    planned_incident: Incident | None = None
    planned_request: InvestigationRequest | None = None
    selected_backend: str | None = None
    completed_result: OrchestrationResult | None = None
    completed_at: datetime | None = None
    failed_at: datetime | None = None
    error_category: str | None = None
    error_detail: str | None = None

    def __post_init__(self) -> None:
        for name in ("created_at", "updated_at", "completed_at", "failed_at"):
            _require_aware(getattr(self, name), name)
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        if (self.idempotency_scope is None) != (self.idempotency_key is None):
            raise ValueError("idempotency scope and key must be present together")
        fingerprint_values = (self.fingerprint_version, self.request_fingerprint)
        if any(value is None for value in fingerprint_values) != all(
            value is None for value in fingerprint_values
        ):
            raise ValueError("fingerprint version and digest must be present together")
        if self.idempotency_key is None:
            if self.request_fingerprint is not None:
                raise ValueError("legacy processing cannot contain a fingerprint")
        elif self.request_fingerprint is None:
            raise ValueError("idempotent processing requires a fingerprint")
        if self.request_fingerprint is not None and len(self.request_fingerprint) != 32:
            raise ValueError("request fingerprint must contain exactly 32 bytes")
        if self.fingerprint_version is not None and self.fingerprint_version != 1:
            raise ValueError("unsupported request fingerprint version")
        _require_bounded_error(self.error_category, "error_category")
        _require_bounded_error(self.error_detail, "error_detail")
        if (self.error_category is None) != (self.error_detail is None):
            raise ValueError("error category and detail must be present together")

        planned_values = (
            self.planned_decision,
            self.planned_incident,
            self.planned_request,
            self.selected_backend,
        )
        if self.state is ProcessingState.ACCEPTED:
            if any(value is not None for value in planned_values):
                raise ValueError("accepted processing cannot contain a plan")
            if self.completed_result is not None:
                raise ValueError("accepted processing cannot contain a result")
        elif self.state in {
            ProcessingState.PLANNED,
            ProcessingState.SUBMITTING,
            ProcessingState.SUBMITTED,
            ProcessingState.RECOVERY_REQUIRED,
        }:
            if any(value is None for value in planned_values):
                raise ValueError(f"{self.state.value} processing requires a complete plan")
            if self.completed_result is not None:
                raise ValueError(f"{self.state.value} processing cannot contain a result")
        elif self.state is ProcessingState.COMPLETED:
            if self.completed_result is None or self.completed_at is None:
                raise ValueError("completed processing requires result and completed_at")
            if self.failed_at is not None:
                raise ValueError("completed processing cannot contain failed_at")
        elif self.state is ProcessingState.FAILED:
            if self.failed_at is None or self.error_category is None:
                raise ValueError("failed processing requires failed_at and error_category")
            if self.completed_result is not None or self.completed_at is not None:
                raise ValueError("failed processing cannot contain a completed result")

        if self.planned_decision is not None:
            if self.planned_decision.source != self.alert.source:
                raise ValueError("planned decision source must match alert source")
            if self.planned_incident is not None and self.planned_incident.alert != self.alert:
                raise ValueError("planned incident alert must match alert")
        if self.completed_result is not None:
            if self.completed_result.decision.source != self.alert.source:
                raise ValueError("result decision source must match alert source")
            if (
                self.completed_result.incident is not None
                and self.completed_result.incident.alert != self.alert
            ):
                raise ValueError("result incident alert must match alert")

    @property
    def result(self) -> OrchestrationResult | None:
        """Compatibility/public shorthand for the terminal logical result."""

        return self.completed_result

    @property
    def decision(self) -> Decision | None:
        if self.completed_result is not None:
            return self.completed_result.decision
        return self.planned_decision

    @property
    def incident(self) -> Incident | None:
        if self.completed_result is not None:
            return self.completed_result.incident
        return self.planned_incident

    @property
    def investigation_request(self) -> InvestigationRequest | None:
        if self.completed_result is not None:
            return self.completed_result.investigation_request
        return self.planned_request


@dataclass(frozen=True, slots=True)
class ExecutionAttempt:
    attempt_id: UUID
    processing_id: UUID
    attempt_number: int
    operation_key: UUID
    backend: str
    state: ExecutionAttemptState
    created_at: datetime
    started_at: datetime | None = None
    submitted_at: datetime | None = None
    last_polled_at: datetime | None = None
    completed_at: datetime | None = None
    failed_at: datetime | None = None
    external_operation_id: str | None = None
    last_remote_state: str | None = None
    error_category: str | None = None
    error_detail: str | None = None

    def __post_init__(self) -> None:
        if self.attempt_number < 1:
            raise ValueError("attempt_number must be positive")
        if not self.backend.strip():
            raise ValueError("backend must be non-empty")
        for name in (
            "created_at",
            "started_at",
            "submitted_at",
            "last_polled_at",
            "completed_at",
            "failed_at",
        ):
            _require_aware(getattr(self, name), name)
        _require_bounded_error(self.last_remote_state, "last_remote_state")
        _require_bounded_error(self.error_category, "error_category")
        _require_bounded_error(self.error_detail, "error_detail")
        if (self.error_category is None) != (self.error_detail is None):
            raise ValueError("error category and detail must be present together")
        if self.external_operation_id is not None and (
            not self.external_operation_id.strip()
            or len(self.external_operation_id) > 512
        ):
            raise ValueError("external_operation_id must contain 1-512 characters")

        if self.state is ExecutionAttemptState.PLANNED:
            if any(
                value is not None
                for value in (
                    self.started_at,
                    self.submitted_at,
                    self.external_operation_id,
                    self.completed_at,
                    self.failed_at,
                )
            ):
                raise ValueError("planned attempt contains execution fields")
        elif self.state is ExecutionAttemptState.SUBMITTING:
            if self.started_at is None or self.external_operation_id is not None:
                raise ValueError("submitting attempt requires only a start time")
        elif self.state is ExecutionAttemptState.SUBMITTED:
            if any(
                value is None
                for value in (
                    self.started_at,
                    self.submitted_at,
                    self.external_operation_id,
                )
            ):
                raise ValueError("submitted attempt requires durable operation identity")
            if self.completed_at is not None or self.failed_at is not None:
                raise ValueError("submitted attempt cannot contain terminal timestamps")
        elif self.state is ExecutionAttemptState.COMPLETED:
            if any(
                value is None
                for value in (
                    self.started_at,
                    self.submitted_at,
                    self.external_operation_id,
                    self.completed_at,
                )
            ):
                raise ValueError("completed attempt is missing required fields")
            if self.failed_at is not None:
                raise ValueError("completed attempt cannot contain failed_at")
        elif self.state is ExecutionAttemptState.FAILED:
            if self.failed_at is None or self.error_category is None:
                raise ValueError("failed attempt requires failure metadata")
            if self.completed_at is not None:
                raise ValueError("failed attempt cannot contain completed_at")
        elif self.state is ExecutionAttemptState.RECOVERY_REQUIRED:
            if self.started_at is None or self.error_category is None:
                raise ValueError("recovery-required attempt requires recovery metadata")
            if self.completed_at is not None or self.failed_at is not None:
                raise ValueError("recovery-required attempt is nonterminal")


@dataclass(frozen=True, slots=True)
class ProcessingAcceptance:
    record: ProcessingRecord
    created: bool


@dataclass(frozen=True, slots=True)
class PlannedProcessing:
    record: ProcessingRecord
    attempt: ExecutionAttempt


class ProcessingRepository(Protocol):
    """Explicit, state-safe durable lifecycle operations."""

    def check_readiness(self) -> None: ...

    def accept_processing(
        self,
        processing_id: UUID,
        alert: CanonicalAlert,
        idempotency_scope: str,
        idempotency_key: str,
        fingerprint_version: int,
        request_fingerprint: bytes,
    ) -> ProcessingAcceptance: ...

    def get(self, processing_id: UUID) -> ProcessingRecord | None: ...

    def get_by_idempotency(
        self, idempotency_scope: str, idempotency_key: str
    ) -> ProcessingRecord | None: ...

    def store_no_action_result(
        self, processing_id: UUID, result: OrchestrationResult
    ) -> ProcessingRecord | None: ...

    def store_plan(
        self,
        processing_id: UUID,
        decision: Decision,
        incident: Incident,
        request: InvestigationRequest,
        selected_backend: str,
        attempt_id: UUID,
        operation_key: UUID,
    ) -> PlannedProcessing | None: ...

    def get_attempt(self, attempt_id: UUID) -> ExecutionAttempt | None: ...

    def get_attempt_for_processing(
        self, processing_id: UUID
    ) -> ExecutionAttempt | None: ...

    def claim_attempt_for_submission(
        self, attempt_id: UUID
    ) -> ExecutionAttempt | None: ...

    def mark_attempt_submitted(
        self, attempt_id: UUID, external_operation_id: str
    ) -> ExecutionAttempt | None: ...

    def record_poll(
        self,
        attempt_id: UUID,
        remote_state: str,
        error_category: str | None = None,
        error_detail: str | None = None,
    ) -> ExecutionAttempt | None: ...

    def complete_processing(
        self,
        attempt_id: UUID,
        result: OrchestrationResult,
    ) -> ProcessingRecord | None: ...

    def fail_processing(
        self,
        processing_id: UUID,
        expected_states: frozenset[ProcessingState],
        error_category: str,
        error_detail: str,
        attempt_id: UUID | None = None,
    ) -> ProcessingRecord | None: ...

    def mark_recovery_required(
        self,
        attempt_id: UUID,
        expected_states: frozenset[ExecutionAttemptState],
        error_category: str,
        error_detail: str,
    ) -> ProcessingRecord | None: ...

    def find_reconcilable(
        self,
        *,
        limit: int,
        stale_submitting_before: datetime,
    ) -> tuple[ProcessingRecord, ...]: ...
