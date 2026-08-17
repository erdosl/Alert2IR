"""Vendor-neutral investigation backend lifecycle contracts."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from alert2ir.core.models import EvidenceReference
from alert2ir.core.workflow import InvestigationRequest


def _require_non_empty(value: str, field_name: str) -> None:
    if not value.strip():
        raise ValueError(f"{field_name} must be non-empty")


class OperationState(StrEnum):
    NONTERMINAL = "nonterminal"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class SubmittedOperation:
    external_operation_id: str

    def __post_init__(self) -> None:
        _require_non_empty(self.external_operation_id, "external_operation_id")
        if len(self.external_operation_id) > 512:
            raise ValueError("external_operation_id must not exceed 512 characters")


@dataclass(frozen=True, slots=True)
class OperationStatus:
    state: OperationState
    remote_state: str

    def __post_init__(self) -> None:
        _require_non_empty(self.remote_state, "remote_state")
        if len(self.remote_state) > 256:
            raise ValueError("remote_state must not exceed 256 characters")


@dataclass(frozen=True, slots=True)
class InvestigationResult:
    backend: str
    completed_capabilities: tuple[str, ...]
    evidence: tuple[EvidenceReference, ...]

    def __post_init__(self) -> None:
        _require_non_empty(self.backend, "backend")
        for capability in self.completed_capabilities:
            _require_non_empty(capability, "completed capability")


class BackendSubmissionRejectedError(Exception):
    """Submission definitively failed before a remote operation was created."""


class BackendSubmissionUnknownError(Exception):
    """The submission crossed an uncertain remote side-effect boundary."""


class BackendExecutionError(Exception):
    """A known remote operation reached terminal failure."""


class BackendProtocolError(Exception):
    """A backend response cannot be interpreted safely."""


class InvestigationBackend(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def capabilities(self) -> frozenset[str]: ...

    def submit(
        self,
        request: InvestigationRequest,
        operation_key: UUID,
        *,
        timeout_seconds: float | None = None,
    ) -> SubmittedOperation:
        """Create one operation within an optional caller-supplied time budget."""
        ...

    def poll(
        self,
        request: InvestigationRequest,
        external_operation_id: str,
        *,
        timeout_seconds: float | None = None,
    ) -> OperationStatus:
        """Inspect one known operation within an optional time budget."""
        ...

    def collect_result(
        self,
        request: InvestigationRequest,
        external_operation_id: str,
    ) -> InvestigationResult:
        """Build a vendor-neutral result for one known successful operation."""
        ...
