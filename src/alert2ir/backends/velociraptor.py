"""Narrow Velociraptor investigation backend contract."""

from collections.abc import Mapping
from dataclasses import dataclass
from math import isfinite
from types import MappingProxyType
from typing import Protocol

from alert2ir.backends.base import InvestigationResult
from alert2ir.backends.router import UnsupportedCapabilitiesError
from alert2ir.core.models import EvidenceReference
from alert2ir.core.workflow import InvestigationRequest


_PROCESS_LIST_ARTIFACT = "Windows.System.Pslist"
_PROCESS_LIST_CAPABILITY = "process.list"


class VelociraptorConfigurationError(ValueError):
    """Raised when backend construction receives invalid configuration."""


class VelociraptorTargetError(Exception):
    """Raised when a request cannot resolve one supported host target."""


class VelociraptorCollectionError(Exception):
    """Raised when collection execution or its return contract fails."""


class VelociraptorCollectionClient(Protocol):
    """Product-specific seam for one completed, retrievable collection."""

    def collect(
        self,
        *,
        client_id: str,
        artifact: str,
        timeout_seconds: float,
    ) -> str:
        """Return a nonblank opaque reference after results are retrievable."""
        ...


@dataclass(frozen=True, slots=True)
class VelociraptorBackend:
    client: VelociraptorCollectionClient
    host_client_ids: Mapping[str, str]
    collection_timeout_seconds: float

    def __post_init__(self) -> None:
        timeout = self.collection_timeout_seconds
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise VelociraptorConfigurationError(
                "collection timeout must be a finite positive number"
            )
        if not isfinite(timeout) or timeout <= 0:
            raise VelociraptorConfigurationError(
                "collection timeout must be a finite positive number"
            )

        host_client_ids = dict(self.host_client_ids)
        for host, client_id in host_client_ids.items():
            if not isinstance(host, str) or not host.strip():
                raise VelociraptorConfigurationError(
                    "host-to-client mapping contains a blank or invalid host value"
                )
            if not isinstance(client_id, str) or not client_id.strip():
                raise VelociraptorConfigurationError(
                    "host-to-client mapping contains a blank or invalid client ID"
                )

        object.__setattr__(
            self,
            "host_client_ids",
            MappingProxyType(host_client_ids),
        )

    @property
    def name(self) -> str:
        return "velociraptor"

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({_PROCESS_LIST_CAPABILITY})

    def investigate(self, request: InvestigationRequest) -> InvestigationResult:
        if not set(request.required_capabilities) <= self.capabilities:
            raise UnsupportedCapabilitiesError(request.required_capabilities)

        if len(request.targets) != 1:
            raise VelociraptorTargetError(
                "Velociraptor process collection requires exactly one target"
            )

        target = request.targets[0]
        if target.kind != "host":
            raise VelociraptorTargetError(
                "Velociraptor process collection requires a host target"
            )

        try:
            client_id = self.host_client_ids[target.value]
        except KeyError as exc:
            raise VelociraptorTargetError(
                "host target has no configured Velociraptor client mapping"
            ) from exc

        collection_reference = self.client.collect(
            client_id=client_id,
            artifact=_PROCESS_LIST_ARTIFACT,
            timeout_seconds=self.collection_timeout_seconds,
        )
        if (
            not isinstance(collection_reference, str)
            or not collection_reference.strip()
        ):
            raise VelociraptorCollectionError(
                "collection client returned a blank or invalid collection reference"
            )

        return InvestigationResult(
            backend=self.name,
            completed_capabilities=request.required_capabilities,
            evidence=(
                EvidenceReference(
                    reference=collection_reference,
                    kind="collection",
                ),
            ),
        )
