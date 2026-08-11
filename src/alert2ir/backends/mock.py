"""Deterministic investigation backend for local and integration tests."""

from dataclasses import dataclass

from alert2ir.backends.base import InvestigationResult, _require_non_empty
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

    def investigate(self, request: InvestigationRequest) -> InvestigationResult:
        if not set(request.required_capabilities) <= self.capabilities:
            raise UnsupportedCapabilitiesError(request.required_capabilities)

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
