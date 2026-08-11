"""Vendor-neutral investigation backend contracts and implementations."""

from alert2ir.backends.base import InvestigationBackend, InvestigationResult
from alert2ir.backends.mock import MockBackend
from alert2ir.backends.router import (
    AmbiguousBackendError,
    BackendRouter,
    UnsupportedCapabilitiesError,
)

__all__ = [
    "AmbiguousBackendError",
    "BackendRouter",
    "InvestigationBackend",
    "InvestigationResult",
    "MockBackend",
    "UnsupportedCapabilitiesError",
]
