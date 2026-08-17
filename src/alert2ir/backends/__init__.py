"""Vendor-neutral investigation backend contracts and implementations."""

from alert2ir.backends.base import (
    BackendExecutionError,
    BackendProtocolError,
    BackendSubmissionRejectedError,
    BackendSubmissionUnknownError,
    InvestigationBackend,
    InvestigationResult,
    OperationState,
    OperationStatus,
    SubmittedOperation,
)
from alert2ir.backends.mock import MockBackend
from alert2ir.backends.router import (
    AmbiguousBackendError,
    BackendRouter,
    UnsupportedCapabilitiesError,
)
from alert2ir.backends.velociraptor import (
    PyVelociraptorCollectionClient,
    VelociraptorBackend,
    VelociraptorCollectionClient,
    VelociraptorCollectionError,
    VelociraptorConfigurationError,
    VelociraptorSubmissionUnknownError,
    VelociraptorTargetError,
)

__all__ = [
    "AmbiguousBackendError",
    "BackendRouter",
    "BackendExecutionError",
    "BackendProtocolError",
    "BackendSubmissionRejectedError",
    "BackendSubmissionUnknownError",
    "InvestigationBackend",
    "InvestigationResult",
    "OperationState",
    "OperationStatus",
    "SubmittedOperation",
    "MockBackend",
    "PyVelociraptorCollectionClient",
    "UnsupportedCapabilitiesError",
    "VelociraptorBackend",
    "VelociraptorCollectionClient",
    "VelociraptorCollectionError",
    "VelociraptorConfigurationError",
    "VelociraptorSubmissionUnknownError",
    "VelociraptorTargetError",
]
