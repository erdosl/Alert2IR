"""Capability-based investigation backend selection."""

from dataclasses import dataclass

from alert2ir.backends.base import InvestigationBackend
from alert2ir.core.workflow import InvestigationRequest


class UnsupportedCapabilitiesError(Exception):
    def __init__(self, requested_capabilities: tuple[str, ...]) -> None:
        self.requested_capabilities = requested_capabilities
        super().__init__(
            "no configured backend supports all requested capabilities: "
            f"{requested_capabilities!r}"
        )


class AmbiguousBackendError(Exception):
    def __init__(
        self,
        requested_capabilities: tuple[str, ...],
        eligible_backends: tuple[str, ...],
    ) -> None:
        self.requested_capabilities = requested_capabilities
        self.eligible_backends = eligible_backends
        super().__init__(
            "multiple backends support all requested capabilities and no selection "
            f"policy is defined: {eligible_backends!r}"
        )


@dataclass(frozen=True, slots=True)
class BackendRouter:
    backends: tuple[InvestigationBackend, ...]

    def select(self, request: InvestigationRequest) -> InvestigationBackend:
        required = set(request.required_capabilities)
        eligible = tuple(
            backend for backend in self.backends if required <= backend.capabilities
        )

        if not eligible:
            raise UnsupportedCapabilitiesError(request.required_capabilities)
        if len(eligible) > 1:
            raise AmbiguousBackendError(
                request.required_capabilities,
                tuple(backend.name for backend in eligible),
            )
        return eligible[0]

    def get(self, name: str) -> InvestigationBackend | None:
        """Resolve a previously persisted backend selection exactly by name."""

        matches = tuple(backend for backend in self.backends if backend.name == name)
        if len(matches) == 1:
            return matches[0]
        return None
