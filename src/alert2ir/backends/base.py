"""Vendor-neutral investigation backend contracts."""

from dataclasses import dataclass
from typing import Protocol

from alert2ir.core.models import EvidenceReference
from alert2ir.core.workflow import InvestigationRequest


def _require_non_empty(value: str, field_name: str) -> None:
    if not value.strip():
        raise ValueError(f"{field_name} must be non-empty")


@dataclass(frozen=True, slots=True)
class InvestigationResult:
    backend: str
    completed_capabilities: tuple[str, ...]
    evidence: tuple[EvidenceReference, ...]

    def __post_init__(self) -> None:
        _require_non_empty(self.backend, "backend")
        for capability in self.completed_capabilities:
            _require_non_empty(capability, "completed capability")


class InvestigationBackend(Protocol):
    @property
    def name(self) -> str:
        ...

    @property
    def capabilities(self) -> frozenset[str]:
        ...

    def investigate(self, request: InvestigationRequest) -> InvestigationResult:
        ...
