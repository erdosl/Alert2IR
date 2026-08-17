"""Durable, idempotent alert processing and bounded reconciliation."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from alert2ir.application.fingerprinting import fingerprint_canonical_alert
from alert2ir.application.orchestrator import AlertOrchestrator, OrchestrationResult
from alert2ir.application.persistence import (
    ExecutionAttempt,
    ExecutionAttemptState,
    ProcessingRecord,
    ProcessingRepository,
    ProcessingState,
)
from alert2ir.backends.base import (
    BackendSubmissionRejectedError,
    OperationState,
    OperationStatus,
    SubmittedOperation,
)
from alert2ir.backends.router import (
    AmbiguousBackendError,
    UnsupportedCapabilitiesError,
)
from alert2ir.core.models import CanonicalAlert
from alert2ir.core.workflow import DecisionOutcome
from alert2ir.observability import (
    ApplicationObservability,
    bounded_backend,
    bounded_capability,
    current_error_category,
    current_processing_id,
    no_op_observability,
    reconciliation_context,
    set_attempt_id,
    set_error_category,
    set_processing_id,
)


_SUBMITTING_STALE_AFTER = timedelta(minutes=5)
_RECONCILIATION_LIMIT = 25
_RECONCILIATION_TIME_LIMIT_SECONDS = 10.0


class IdempotencyConflictError(Exception):
    """One scoped key is already bound to a different canonical request."""

    def __init__(self, processing_id: UUID) -> None:
        self.processing_id = processing_id
        super().__init__("idempotency key is already bound to another request")


class PersistenceUnavailableError(Exception):
    """A required durable lifecycle operation could not be completed."""


@dataclass(frozen=True, slots=True)
class ProcessingOutcome:
    record: ProcessingRecord
    replayed: bool


@dataclass(frozen=True, slots=True)
class ReconciliationReport:
    examined: int
    advanced: int
    failed: int
    time_limit_reached: bool


class PersistentAlertProcessor:
    """Commit acceptance before planning, submission, polling, or collection."""

    def __init__(
        self,
        orchestrator: AlertOrchestrator,
        repository: ProcessingRepository,
        processing_id_factory: Callable[[], UUID] = uuid4,
        observability: ApplicationObservability | None = None,
        attempt_id_factory: Callable[[], UUID] = uuid4,
        operation_key_factory: Callable[[], UUID] = uuid4,
        wall_clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        self._orchestrator = orchestrator
        self._repository = repository
        self._processing_id_factory = processing_id_factory
        self._attempt_id_factory = attempt_id_factory
        self._operation_key_factory = operation_key_factory
        self._wall_clock = wall_clock or (lambda: datetime.now(timezone.utc))
        self.observability = observability or no_op_observability()
        self._monotonic = monotonic or self.observability.monotonic

    def check_readiness(self) -> None:
        self._repository.check_readiness()

    def get(self, processing_id: UUID) -> ProcessingRecord | None:
        return self._repository.get(processing_id)

    def process(
        self,
        alert: CanonicalAlert,
        idempotency_key: str,
    ) -> ProcessingOutcome:
        """Accept once, then run the synchronous fast path only for the creator."""

        previous_processing_id = current_processing_id()
        previous_error_category = current_error_category()
        started = self.observability.monotonic()
        try:
            outcome = self._process(alert, idempotency_key)
        except Exception:
            category = current_error_category() or "internal_error"
            self.observability.record_processing(
                duration_seconds=self.observability.monotonic() - started,
                decision="unknown",
                outcome="error",
                error_category=category,
            )
            raise
        else:
            decision = outcome.record.decision
            durable_error = outcome.record.error_category
            processing_failed = outcome.record.state in {
                ProcessingState.FAILED,
                ProcessingState.RECOVERY_REQUIRED,
            }
            self.observability.record_processing(
                duration_seconds=self.observability.monotonic() - started,
                decision="unknown" if decision is None else decision.outcome.value,
                outcome="error" if processing_failed else "success",
                error_category=durable_error if processing_failed else None,
            )
            return outcome
        finally:
            set_attempt_id(None)
            set_processing_id(previous_processing_id)
            set_error_category(previous_error_category)

    def _process(
        self,
        alert: CanonicalAlert,
        idempotency_key: str,
    ) -> ProcessingOutcome:
        """Internal implementation with correlation cleanup owned by ``process``."""

        fingerprint_version, digest = fingerprint_canonical_alert(alert)
        processing_id = self._processing_id_factory()
        persistence_started = self.observability.monotonic()
        try:
            acceptance = self._repository.accept_processing(
                processing_id=processing_id,
                alert=alert,
                idempotency_scope=alert.source.source,
                idempotency_key=idempotency_key,
                fingerprint_version=fingerprint_version,
                request_fingerprint=digest,
            )
        except Exception as error:
            self.observability.record_persistence(
                duration_seconds=self.observability.monotonic() - persistence_started,
                outcome="error",
                error_category="persistence_failed",
            )
            set_error_category("persistence_failed")
            raise PersistenceUnavailableError(
                "durable processing acceptance failed"
            ) from error
        self.observability.record_persistence(
            duration_seconds=self.observability.monotonic() - persistence_started,
            outcome="success",
        )

        record = acceptance.record
        set_processing_id(str(record.processing_id))
        if (
            record.fingerprint_version != fingerprint_version
            or record.request_fingerprint != digest
        ):
            self.observability.record_idempotency("conflict")
            set_error_category("idempotency_conflict")
            raise IdempotencyConflictError(record.processing_id)
        if not acceptance.created:
            self.observability.record_idempotency("replayed")
            return ProcessingOutcome(record, replayed=True)

        self.observability.record_idempotency("accepted")
        self.observability.record_transition(state="unknown", to_state="accepted")
        return ProcessingOutcome(self._advance_accepted(record), replayed=False)

    def _reread(self, processing_id: UUID) -> ProcessingRecord:
        record = self._repository.get(processing_id)
        if record is None:
            raise PersistenceUnavailableError("durable processing could not be read")
        return record

    def _advance_accepted(
        self,
        record: ProcessingRecord,
        *,
        reconciliation_deadline: float | None = None,
    ) -> ProcessingRecord:
        try:
            plan = self._orchestrator.plan(record.alert)
        except UnsupportedCapabilitiesError as error:
            failed = self._fail_without_attempt(
                record,
                "unsupported_capability",
                "no configured backend supports the required capability",
            )
            error.processing_id = record.processing_id
            error.processing_state = (
                failed.state if failed is not None else ProcessingState.ACCEPTED
            )
            raise
        except AmbiguousBackendError as error:
            failed = self._fail_without_attempt(
                record,
                "backend_selection_error",
                "backend selection was ambiguous",
            )
            error.processing_id = record.processing_id
            error.processing_state = (
                failed.state if failed is not None else ProcessingState.ACCEPTED
            )
            raise
        except Exception as error:
            failed = self._fail_without_attempt(
                record,
                "backend_selection_error",
                "processing planning failed",
            )
            if failed is None:
                return self._reread(record.processing_id)
            raise RuntimeError("processing planning failed") from error

        if plan.decision.outcome is DecisionOutcome.NO_ACTION:
            result = OrchestrationResult(plan.decision, None, None, None)
            try:
                completed = self._repository.store_no_action_result(
                    record.processing_id,
                    result,
                )
            except Exception as error:
                raise PersistenceUnavailableError(
                    "no-action completion could not be persisted"
                ) from error
            durable = completed or self._reread(record.processing_id)
            if durable.state is ProcessingState.COMPLETED:
                self.observability.record_transition(
                    state="accepted", to_state="completed"
                )
            return durable

        if (
            plan.incident is None
            or plan.investigation_request is None
            or plan.backend is None
        ):
            raise RuntimeError("investigation plan is incomplete")
        try:
            planned = self._repository.store_plan(
                processing_id=record.processing_id,
                decision=plan.decision,
                incident=plan.incident,
                request=plan.investigation_request,
                selected_backend=plan.backend.name,
                attempt_id=self._attempt_id_factory(),
                operation_key=self._operation_key_factory(),
            )
        except Exception as error:
            raise PersistenceUnavailableError(
                "execution plan could not be persisted"
            ) from error
        if planned is None:
            return self._reread(record.processing_id)
        self.observability.record_transition(state="accepted", to_state="planned")
        return self._submit(
            planned.record,
            planned.attempt,
            reconciliation_deadline=reconciliation_deadline,
        )

    def _fail_without_attempt(
        self,
        record: ProcessingRecord,
        category: str,
        detail: str,
    ) -> ProcessingRecord | None:
        try:
            failed = self._repository.fail_processing(
                record.processing_id,
                frozenset({ProcessingState.ACCEPTED}),
                category,
                detail,
            )
            if failed is not None:
                set_error_category(category)
                self.observability.record_transition(
                    state=record.state.value,
                    to_state="failed",
                    outcome="error",
                    error_category=category,
                )
            return failed
        except Exception as error:
            raise PersistenceUnavailableError(
                "planning failure could not be persisted"
            ) from error

    def _submit(
        self,
        record: ProcessingRecord,
        attempt: ExecutionAttempt,
        *,
        reconciliation_deadline: float | None = None,
    ) -> ProcessingRecord:
        request = record.investigation_request
        backend_name = record.selected_backend
        if request is None or backend_name is None:
            raise RuntimeError("planned processing is missing execution data")
        backend = self._orchestrator.backend_for_name(backend_name)
        if backend is None:
            failed = self._repository.fail_processing(
                record.processing_id,
                frozenset({ProcessingState.PLANNED}),
                "backend_selection_error",
                "persisted backend is not configured",
                attempt.attempt_id,
            )
            return failed or self._reread(record.processing_id)

        operation_timeout = self._remaining_reconciliation_seconds(
            reconciliation_deadline
        )
        if operation_timeout is not None and operation_timeout <= 0:
            return record

        try:
            claimed = self._repository.claim_attempt_for_submission(
                attempt.attempt_id
            )
        except Exception as error:
            raise PersistenceUnavailableError(
                "execution attempt claim could not be persisted"
            ) from error
        if claimed is None:
            return self._reread(record.processing_id)
        set_attempt_id(str(claimed.attempt_id))
        self.observability.record_transition(state="planned", to_state="submitting")

        operation_timeout = self._remaining_reconciliation_seconds(
            reconciliation_deadline
        )
        if operation_timeout is not None and operation_timeout <= 0:
            recovery = self._repository.mark_recovery_required(
                claimed.attempt_id,
                frozenset({ExecutionAttemptState.SUBMITTING}),
                "recovery_required",
                "reconciliation deadline expired before backend submission",
            )
            durable = recovery or self._reread(record.processing_id)
            if durable.state is ProcessingState.RECOVERY_REQUIRED:
                self.observability.record_recovery_required(
                    backend=backend_name,
                    error_category="recovery_required",
                )
            return durable

        try:
            submitted = self._backend_submit(
                backend,
                request,
                claimed.operation_key,
                timeout_seconds=operation_timeout,
            )
            if not isinstance(submitted, SubmittedOperation):
                raise TypeError("backend returned an invalid submission response")
        except BackendSubmissionRejectedError:
            self.observability.record_submission(
                backend=backend_name,
                outcome="error",
                error_category="backend_submission_failed",
            )
            failed = self._repository.fail_processing(
                record.processing_id,
                frozenset({ProcessingState.SUBMITTING}),
                "backend_submission_failed",
                "backend definitively rejected submission",
                claimed.attempt_id,
            )
            durable = failed or self._reread(record.processing_id)
            if durable.state is ProcessingState.FAILED:
                self.observability.record_transition(
                    state="submitting",
                    to_state="failed",
                    outcome="error",
                    error_category="backend_submission_failed",
                )
            return durable
        except Exception:
            self.observability.record_submission(
                backend=backend_name,
                outcome="error",
                error_category="backend_submission_unknown",
            )
            recovery = self._repository.mark_recovery_required(
                claimed.attempt_id,
                frozenset({ExecutionAttemptState.SUBMITTING}),
                "backend_submission_unknown",
                "backend submission outcome is unknown",
            )
            durable = recovery or self._reread(record.processing_id)
            if durable.state is ProcessingState.RECOVERY_REQUIRED:
                self.observability.record_transition(
                    state="submitting",
                    to_state="recovery_required",
                    outcome="error",
                    error_category="backend_submission_unknown",
                )
                self.observability.record_recovery_required(
                    backend=backend_name,
                    error_category="backend_submission_unknown",
                )
            return durable

        self.observability.record_submission(backend=backend_name, outcome="success")

        try:
            durable_attempt = self._repository.mark_attempt_submitted(
                claimed.attempt_id,
                submitted.external_operation_id,
            )
        except Exception as error:
            try:
                self._repository.mark_recovery_required(
                    claimed.attempt_id,
                    frozenset({ExecutionAttemptState.SUBMITTING}),
                    "backend_submission_unknown",
                    "external operation identity could not be persisted",
                )
            except Exception:
                pass
            raise PersistenceUnavailableError(
                "external operation identity could not be persisted"
            ) from error
        if durable_attempt is None:
            return self._reread(record.processing_id)
        self.observability.record_transition(state="submitting", to_state="submitted")
        durable_record = self._reread(record.processing_id)
        return self._poll_submitted(
            durable_record,
            durable_attempt,
            reconciliation_deadline=reconciliation_deadline,
        )

    def _backend_submit(
        self,
        backend,
        request,
        operation_key,
        *,
        timeout_seconds: float | None = None,
    ) -> SubmittedOperation:
        started = self.observability.monotonic()
        capability = bounded_capability(request.required_capabilities)
        with self.observability.span(
            "backend.submit",
            {"alert2ir.backend": bounded_backend(backend.name)},
        ) as span:
            try:
                if timeout_seconds is None:
                    result = backend.submit(request, operation_key)
                else:
                    result = backend.submit(
                        request,
                        operation_key,
                        timeout_seconds=timeout_seconds,
                    )
            except BackendSubmissionRejectedError:
                self.observability.finish_span(
                    span,
                    outcome="error",
                    error_category="backend_submission_failed",
                )
                self.observability.record_backend(
                    duration_seconds=self.observability.monotonic() - started,
                    backend=backend.name,
                    capability=capability,
                    outcome="error",
                    error_category="backend_submission_failed",
                )
                raise
            except Exception:
                self.observability.finish_span(
                    span,
                    outcome="error",
                    error_category="backend_submission_unknown",
                )
                self.observability.record_backend(
                    duration_seconds=self.observability.monotonic() - started,
                    backend=backend.name,
                    capability=capability,
                    outcome="error",
                    error_category="backend_submission_unknown",
                )
                raise
            self.observability.finish_span(span, outcome="success")
            self.observability.record_backend(
                duration_seconds=self.observability.monotonic() - started,
                backend=backend.name,
                capability=capability,
                outcome="success",
            )
            return result

    def _backend_poll(
        self,
        backend,
        request,
        external_operation_id,
        *,
        timeout_seconds: float | None = None,
    ) -> OperationStatus:
        with self.observability.span(
            "backend.poll",
            {"alert2ir.backend": bounded_backend(backend.name)},
        ) as span:
            try:
                if timeout_seconds is None:
                    status = backend.poll(request, external_operation_id)
                else:
                    status = backend.poll(
                        request,
                        external_operation_id,
                        timeout_seconds=timeout_seconds,
                    )
            except TimeoutError:
                self.observability.finish_span(
                    span,
                    outcome="timeout",
                    error_category="backend_timeout",
                )
                raise
            except Exception:
                self.observability.finish_span(
                    span,
                    outcome="error",
                    error_category="backend_protocol_error",
                )
                raise
            self.observability.finish_span(span, outcome="success")
            return status

    def _backend_collect(self, backend, request, external_operation_id):
        with self.observability.span(
            "backend.collect_result",
            {"alert2ir.backend": bounded_backend(backend.name)},
        ) as span:
            try:
                result = backend.collect_result(request, external_operation_id)
            except Exception:
                self.observability.finish_span(
                    span,
                    outcome="error",
                    error_category="backend_protocol_error",
                )
                raise
            self.observability.finish_span(span, outcome="success")
            return result

    def _poll_submitted(
        self,
        record: ProcessingRecord,
        attempt: ExecutionAttempt,
        *,
        reconciliation_deadline: float | None = None,
    ) -> ProcessingRecord:
        request = record.investigation_request
        backend_name = record.selected_backend
        external_operation_id = attempt.external_operation_id
        if request is None or backend_name is None or external_operation_id is None:
            recovery = self._repository.mark_recovery_required(
                attempt.attempt_id,
                frozenset({ExecutionAttemptState.SUBMITTED}),
                "recovery_required",
                "submitted execution metadata is incomplete",
            )
            durable = recovery or self._reread(record.processing_id)
            if durable.state is ProcessingState.RECOVERY_REQUIRED:
                self.observability.record_recovery_required(
                    backend=backend_name or "other",
                    error_category="recovery_required",
                )
            return durable
        backend = self._orchestrator.backend_for_name(backend_name)
        if backend is None:
            recovery = self._repository.mark_recovery_required(
                attempt.attempt_id,
                frozenset({ExecutionAttemptState.SUBMITTED}),
                "recovery_required",
                "persisted backend is not configured",
            )
            durable = recovery or self._reread(record.processing_id)
            if durable.state is ProcessingState.RECOVERY_REQUIRED:
                self.observability.record_recovery_required(
                    backend=backend_name,
                    error_category="recovery_required",
                )
            return durable

        poll_timeout = self._remaining_reconciliation_seconds(
            reconciliation_deadline
        )
        if poll_timeout is not None and poll_timeout <= 0:
            return record

        try:
            status = self._backend_poll(
                backend,
                request,
                external_operation_id,
                timeout_seconds=poll_timeout,
            )
            if not isinstance(status, OperationStatus):
                raise TypeError("backend returned an invalid operation status")
        except TimeoutError:
            self._repository.record_poll(
                attempt.attempt_id,
                "timeout",
                "backend_timeout",
                "known backend operation poll timed out",
            )
            return self._reread(record.processing_id)
        except Exception:
            recovery = self._repository.mark_recovery_required(
                attempt.attempt_id,
                frozenset({ExecutionAttemptState.SUBMITTED}),
                "backend_protocol_error",
                "known backend operation status was not safely interpretable",
            )
            durable = recovery or self._reread(record.processing_id)
            if durable.state is ProcessingState.RECOVERY_REQUIRED:
                self.observability.record_recovery_required(
                    backend=backend_name,
                    error_category="backend_protocol_error",
                )
            return durable

        if status.state is OperationState.NONTERMINAL:
            self._repository.record_poll(attempt.attempt_id, status.remote_state)
            return self._reread(record.processing_id)
        if status.state is OperationState.FAILED:
            self._repository.record_poll(attempt.attempt_id, status.remote_state)
            failed = self._repository.fail_processing(
                record.processing_id,
                frozenset({ProcessingState.SUBMITTED}),
                "backend_execution_failed",
                "known backend operation reached terminal failure",
                attempt.attempt_id,
            )
            durable = failed or self._reread(record.processing_id)
            if durable.state is ProcessingState.FAILED:
                self.observability.record_transition(
                    state="submitted",
                    to_state="failed",
                    outcome="error",
                    error_category="backend_execution_failed",
                )
            return durable
        if status.state is not OperationState.SUCCEEDED:
            recovery = self._repository.mark_recovery_required(
                attempt.attempt_id,
                frozenset({ExecutionAttemptState.SUBMITTED}),
                "backend_protocol_error",
                "known backend operation returned an unknown status",
            )
            durable = recovery or self._reread(record.processing_id)
            if durable.state is ProcessingState.RECOVERY_REQUIRED:
                self.observability.record_recovery_required(
                    backend=backend_name,
                    error_category="backend_protocol_error",
                )
            return durable

        self._repository.record_poll(attempt.attempt_id, status.remote_state)
        collection_budget = self._remaining_reconciliation_seconds(
            reconciliation_deadline
        )
        if collection_budget is not None and collection_budget <= 0:
            return self._reread(record.processing_id)
        try:
            investigation_result = self._backend_collect(
                backend,
                request,
                external_operation_id,
            )
            if investigation_result.backend != backend_name:
                raise ValueError("backend result identity does not match its plan")
            decision = record.decision
            incident = record.incident
            if decision is None or incident is None:
                raise ValueError("durable processing plan is incomplete")
            result = OrchestrationResult(
                decision,
                incident,
                request,
                investigation_result,
            )
        except Exception:
            recovery = self._repository.mark_recovery_required(
                attempt.attempt_id,
                frozenset({ExecutionAttemptState.SUBMITTED}),
                "backend_protocol_error",
                "backend result could not be collected safely",
            )
            durable = recovery or self._reread(record.processing_id)
            if durable.state is ProcessingState.RECOVERY_REQUIRED:
                self.observability.record_recovery_required(
                    backend=backend_name,
                    error_category="backend_protocol_error",
                )
            return durable
        completed = self._repository.complete_processing(attempt.attempt_id, result)
        durable = completed or self._reread(record.processing_id)
        if durable.state is ProcessingState.COMPLETED:
            self.observability.record_transition(
                state="submitted", to_state="completed"
            )
        return durable

    def _remaining_reconciliation_seconds(
        self,
        deadline: float | None,
    ) -> float | None:
        if deadline is None:
            return None
        return deadline - self._monotonic()

    def reconcile_once(
        self,
        *,
        limit: int = _RECONCILIATION_LIMIT,
        max_seconds: float = _RECONCILIATION_TIME_LIMIT_SECONDS,
        stale_after: timedelta = _SUBMITTING_STALE_AFTER,
    ) -> ReconciliationReport:
        """Run one bounded, failure-isolated pass over incomplete durable work."""

        if limit < 1 or max_seconds <= 0:
            raise ValueError("reconciliation bounds must be positive")
        started = self._monotonic()
        deadline = started + max_seconds
        stale_before = self._wall_clock() - stale_after
        records = self._repository.find_reconcilable(
            limit=limit,
            stale_submitting_before=stale_before,
        )
        examined = advanced = failures = 0
        time_limit_reached = False
        for record in records:
            remaining = self._remaining_reconciliation_seconds(deadline)
            if remaining is not None and remaining <= 0:
                time_limit_reached = True
                break
            examined += 1
            attempt_for_context = self._repository.get_attempt_for_processing(
                record.processing_id
            )
            with reconciliation_context(
                str(record.processing_id),
                None
                if attempt_for_context is None
                else str(attempt_for_context.attempt_id),
            ):
                try:
                    before = record.state
                    if record.state is ProcessingState.ACCEPTED:
                        after = self._advance_accepted(
                            record,
                            reconciliation_deadline=deadline,
                        )
                    elif record.state is ProcessingState.PLANNED:
                        attempt = self._repository.get_attempt_for_processing(
                            record.processing_id
                        )
                        after = (
                            record
                            if attempt is None
                            else self._submit(
                                record,
                                attempt,
                                reconciliation_deadline=deadline,
                            )
                        )
                    elif record.state is ProcessingState.SUBMITTING:
                        self.observability.record_stale("submitting")
                        attempt = self._repository.get_attempt_for_processing(
                            record.processing_id
                        )
                        if attempt is None:
                            after = record
                        else:
                            after = self._repository.mark_recovery_required(
                                attempt.attempt_id,
                                frozenset({ExecutionAttemptState.SUBMITTING}),
                                "backend_submission_unknown",
                                "stale submission has no discoverable operation",
                            ) or self._reread(record.processing_id)
                            if after.state is ProcessingState.RECOVERY_REQUIRED:
                                self.observability.record_recovery_required(
                                    backend=record.selected_backend or "other",
                                    error_category="backend_submission_unknown",
                                )
                    elif record.state is ProcessingState.SUBMITTED:
                        attempt = self._repository.get_attempt_for_processing(
                            record.processing_id
                        )
                        after = (
                            record
                            if attempt is None
                            else self._poll_submitted(
                                record,
                                attempt,
                                reconciliation_deadline=deadline,
                            )
                        )
                    else:
                        after = record
                    if after.state is not before:
                        advanced += 1
                    self.observability.record_reconciliation(
                        state=before.value,
                        outcome="success",
                    )
                except Exception:
                    failures += 1
                    self.observability.record_reconciliation(
                        state=record.state.value,
                        outcome="error",
                        error_category="internal_error",
                    )
            remaining = self._remaining_reconciliation_seconds(deadline)
            if remaining is not None and remaining <= 0:
                time_limit_reached = True
                break
        return ReconciliationReport(
            examined=examined,
            advanced=advanced,
            failed=failures,
            time_limit_reached=time_limit_reached,
        )
