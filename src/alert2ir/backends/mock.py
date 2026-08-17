"""Deterministic investigation backend for local and integration tests."""

from dataclasses import dataclass
from uuid import UUID

from alert2ir.backends.base import (
    InvestigationResult,
    OperationState,
    OperationStatus,
    SubmittedOperation,
    _require_non_empty,
)
from alert2ir.backends.router import UnsupportedCapabilitiesError
from alert2ir.core.models import EvidenceReference
from alert2ir.core.workflow import InvestigationRequest


@dataclass(frozen=True, slots=True)
class MockBackend:
    name: str
    capabilities: frozenset[str]

    def __post_init__(self) -> None:
        _require_non_empty(self.name, "name")
        for capability in self.capabilities:
            _require_non_empty(capability, "capability")

    def _require_supported(self, request: InvestigationRequest) -> None:
        if not set(request.required_capabilities) <= self.capabilities:
            raise UnsupportedCapabilitiesError(request.required_capabilities)

    def submit(
        self,
        request: InvestigationRequest,
        operation_key: UUID,
        *,
        timeout_seconds: float | None = None,
    ) -> SubmittedOperation:
        del timeout_seconds
        self._require_supported(request)
        return SubmittedOperation(external_operation_id=f"mock:{operation_key}")

    def poll(
        self,
        request: InvestigationRequest,
        external_operation_id: str,
        *,
        timeout_seconds: float | None = None,
    ) -> OperationStatus:
        del timeout_seconds
        self._require_supported(request)
        _require_non_empty(external_operation_id, "external_operation_id")
        return OperationStatus(OperationState.SUCCEEDED, "completed")

    def collect_result(
        self,
        request: InvestigationRequest,
        external_operation_id: str,
    ) -> InvestigationResult:
        self._require_supported(request)
        _require_non_empty(external_operation_id, "external_operation_id")
        return InvestigationResult(
            backend=self.name,
            completed_capabilities=request.required_capabilities,
            evidence=tuple(
                EvidenceReference(
                    reference=f"mock:{capability}",
                    kind="mock-result",
                )
                for capability in request.required_capabilities
            ),
        )

    def investigate(self, request: InvestigationRequest) -> InvestigationResult:
        """Legacy deterministic helper outside the durable application path."""

        return self.collect_result(request, "mock:legacy")
