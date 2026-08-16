"""Narrow Velociraptor investigation backend contract and API client."""

import json
import os
import time
from collections.abc import Mapping
from dataclasses import dataclass
from math import isfinite
from numbers import Real
from pathlib import Path
from types import MappingProxyType
from typing import Protocol

import grpc
import pyvelociraptor
from pyvelociraptor import api_pb2, api_pb2_grpc

from alert2ir.backends.base import InvestigationResult
from alert2ir.backends.router import UnsupportedCapabilitiesError
from alert2ir.core.models import EvidenceReference
from alert2ir.core.workflow import InvestigationRequest
from alert2ir.observability import (
    ApplicationObservability,
    classify_error,
    no_op_observability,
    outcome_for_error,
)


_PROCESS_LIST_ARTIFACT = "Windows.System.Pslist"
_PROCESS_LIST_CAPABILITY = "process.list"
_POLL_INTERVAL_SECONDS = 1.0
_NONTERMINAL_FLOW_STATES = frozenset(
    {
        "UNSET",
        "RUNNING",
        "WAITING",
        "IN_PROGRESS",
        "UNRESPONSIVE",
    }
)
_TERMINAL_SUCCESS_FLOW_STATES = frozenset({"FINISHED"})
_TERMINAL_FAILURE_FLOW_STATES = frozenset({"ERROR"})
_REQUIRED_API_CONFIG_FIELDS = (
    "api_connection_string",
    "ca_certificate",
    "client_private_key",
    "client_cert",
)
_TARGET_NAME_OVERRIDE = "VelociraptorServer"


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


def _vql_string_literal(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise VelociraptorCollectionError(
            "collection request contains a blank or invalid string value"
        )
    return json.dumps(value, ensure_ascii=True)


class PyVelociraptorCollectionClient:
    """Certificate-authenticated client for one synchronous collection."""

    def __init__(
        self,
        api_config_path: str | Path,
        observability: ApplicationObservability | None = None,
    ) -> None:
        try:
            path = Path(api_config_path)
        except (TypeError, ValueError):
            raise VelociraptorConfigurationError(
                "Velociraptor API configuration path is invalid"
            ) from None

        try:
            if not path.is_file() or not os.access(path, os.R_OK):
                raise VelociraptorConfigurationError(
                    "Velociraptor API configuration path is not a readable regular file"
                )
            with path.open("rb") as config_file:
                encrypted_key = b"ENCRYPTED" in config_file.read()
        except VelociraptorConfigurationError:
            raise
        except OSError:
            raise VelociraptorConfigurationError(
                "Velociraptor API configuration path is not a readable regular file"
            ) from None

        if encrypted_key:
            raise VelociraptorConfigurationError(
                "encrypted Velociraptor API private keys are not supported"
            )

        try:
            configuration = pyvelociraptor.LoadConfigFile(str(path))
        except Exception:
            raise VelociraptorConfigurationError(
                "Velociraptor API configuration could not be loaded"
            ) from None

        if not isinstance(configuration, Mapping):
            raise VelociraptorConfigurationError(
                "Velociraptor API configuration is invalid"
            )

        for field in _REQUIRED_API_CONFIG_FIELDS:
            value = configuration.get(field)
            if not isinstance(value, str) or not value.strip():
                raise VelociraptorConfigurationError(
                    "Velociraptor API configuration field "
                    f"{field!r} is missing or blank"
                )

        self._api_config_path = path
        self._api_connection_string = configuration[
            "api_connection_string"
        ].strip()
        self._ca_certificate = configuration["ca_certificate"]
        self._client_private_key = configuration["client_private_key"]
        self._client_cert = configuration["client_cert"]
        self._observability = observability or no_op_observability()

    @staticmethod
    def _validate_timeout(timeout_seconds: float) -> float:
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, Real):
            raise VelociraptorConfigurationError(
                "collection timeout must be a finite positive number"
            )
        timeout = float(timeout_seconds)
        if not isfinite(timeout) or timeout <= 0:
            raise VelociraptorConfigurationError(
                "collection timeout must be a finite positive number"
            )
        return timeout

    @staticmethod
    def _validate_artifacts(value: object, expected_artifact: str) -> bool:
        return isinstance(value, list) and value == [expected_artifact]

    def _run_query(
        self,
        stub: api_pb2_grpc.APIStub,
        vql: str,
        *,
        timeout_seconds: float,
    ) -> list[dict[str, object]]:
        request = api_pb2.VQLCollectorArgs(
            max_wait=1,
            max_row=100,
            Query=[api_pb2.VQLRequest(Name="Alert2IR", VQL=vql)],
        )
        rows: list[dict[str, object]] = []

        try:
            for response in stub.Query(request, timeout=timeout_seconds):
                if not response.Response:
                    continue
                try:
                    batch = json.loads(response.Response)
                except (json.JSONDecodeError, TypeError, UnicodeDecodeError):
                    raise VelociraptorCollectionError(
                        "Velociraptor API query returned malformed JSON"
                    ) from None
                if not isinstance(batch, list) or any(
                    not isinstance(row, dict) for row in batch
                ):
                    raise VelociraptorCollectionError(
                        "Velociraptor API query returned an invalid result structure"
                    )
                rows.extend(batch)
        except VelociraptorCollectionError:
            raise
        except grpc.RpcError:
            raise VelociraptorCollectionError(
                "Velociraptor API query failed"
            ) from None
        except Exception:
            raise VelociraptorCollectionError(
                "Velociraptor API query failed"
            ) from None

        return rows

    @staticmethod
    def _deadline_remaining(deadline: float) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise VelociraptorCollectionError(
                "Velociraptor collection exceeded its local deadline"
            )
        return remaining

    def _wait_for_next_poll(self, deadline: float) -> None:
        remaining = self._deadline_remaining(deadline)
        time.sleep(min(_POLL_INTERVAL_SECONDS, remaining))

    def collect(
        self,
        *,
        client_id: str,
        artifact: str,
        timeout_seconds: float,
    ) -> str:
        timeout = self._validate_timeout(timeout_seconds)
        client_literal = _vql_string_literal(client_id)
        artifact_literal = _vql_string_literal(artifact)
        timeout_literal = json.dumps(timeout, allow_nan=False)
        scheduling_vql = f"""\
LET collection <= collect_client(
    client_id={client_literal},
    artifacts=[{artifact_literal}],
    timeout={timeout_literal})

SELECT
    collection.flow_id AS flow_id,
    collection.request.client_id AS client_id,
    collection.request.artifacts AS artifacts
FROM scope()
"""

        channel = None
        try:
            try:
                credentials = grpc.ssl_channel_credentials(
                    root_certificates=self._ca_certificate.encode("utf-8"),
                    private_key=self._client_private_key.encode("utf-8"),
                    certificate_chain=self._client_cert.encode("utf-8"),
                )
                channel = grpc.secure_channel(
                    self._api_connection_string,
                    credentials,
                    options=(("grpc.ssl_target_name_override", _TARGET_NAME_OVERRIDE),),
                )
                stub = api_pb2_grpc.APIStub(channel)
            except Exception:
                raise VelociraptorCollectionError(
                    "Velociraptor secure API channel could not be created"
                ) from None

            scheduling_rows = self._run_query(
                stub,
                scheduling_vql,
                timeout_seconds=timeout,
            )
            if len(scheduling_rows) != 1:
                raise VelociraptorCollectionError(
                    "Velociraptor collection scheduling returned an "
                    "unexpected row count"
                )

            scheduling_row = scheduling_rows[0]
            flow_id = scheduling_row.get("flow_id")
            if (
                not isinstance(flow_id, str)
                or not flow_id.strip()
                or not flow_id.startswith("F.")
            ):
                raise VelociraptorCollectionError(
                    "Velociraptor collection scheduling returned an invalid flow ID"
                )
            self._observability.backend_operation_submitted(flow_id)
            if scheduling_row.get("client_id") != client_id:
                raise VelociraptorCollectionError(
                    "Velociraptor collection scheduling returned an unexpected client"
                )
            if not self._validate_artifacts(
                scheduling_row.get("artifacts"), artifact
            ):
                raise VelociraptorCollectionError(
                    "Velociraptor collection scheduling returned unexpected artifacts"
                )

            flow_literal = _vql_string_literal(flow_id)
            polling_vql = f"""\
SELECT
    session_id,
    state,
    request.client_id AS client_id,
    request.artifacts AS artifacts,
    status
FROM flows(
    client_id={client_literal},
    flow_id={flow_literal})
"""
            deadline = time.monotonic() + timeout

            while True:
                remaining = self._deadline_remaining(deadline)
                polling_rows = self._run_query(
                    stub,
                    polling_vql,
                    timeout_seconds=remaining,
                )
                if not polling_rows:
                    self._wait_for_next_poll(deadline)
                    continue
                if len(polling_rows) != 1:
                    raise VelociraptorCollectionError(
                        "Velociraptor flow lookup returned an unexpected row count"
                    )

                polling_row = polling_rows[0]
                if polling_row.get("session_id") != flow_id:
                    raise VelociraptorCollectionError(
                        "Velociraptor flow lookup returned an unexpected flow"
                    )
                if polling_row.get("client_id") != client_id:
                    raise VelociraptorCollectionError(
                        "Velociraptor flow lookup returned an unexpected client"
                    )
                if not self._validate_artifacts(
                    polling_row.get("artifacts"), artifact
                ):
                    raise VelociraptorCollectionError(
                        "Velociraptor flow lookup returned unexpected artifacts"
                    )

                state = polling_row.get("state")
                if not isinstance(state, str):
                    raise VelociraptorCollectionError(
                        "Velociraptor flow returned a malformed or unknown state"
                    )
                if state in _TERMINAL_SUCCESS_FLOW_STATES:
                    return flow_id
                if state in _NONTERMINAL_FLOW_STATES:
                    self._wait_for_next_poll(deadline)
                    continue
                if state in _TERMINAL_FAILURE_FLOW_STATES:
                    raise VelociraptorCollectionError(
                        f"Velociraptor flow entered terminal {state} state"
                    )
                raise VelociraptorCollectionError(
                    "Velociraptor flow returned a malformed or unknown state"
                )
        finally:
            if channel is not None:
                channel.close()


@dataclass(frozen=True, slots=True)
class VelociraptorBackend:
    client: VelociraptorCollectionClient
    host_client_ids: Mapping[str, str]
    collection_timeout_seconds: float
    observability: ApplicationObservability | None = None

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
        if self.observability is None:
            object.__setattr__(self, "observability", no_op_observability())

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

        observability = self.observability
        if observability is None:  # Defensive for static type narrowing.
            observability = no_op_observability()
        with observability.span("velociraptor.collect") as span:
            try:
                collection_reference = self.client.collect(
                    client_id=client_id,
                    artifact=_PROCESS_LIST_ARTIFACT,
                    timeout_seconds=self.collection_timeout_seconds,
                )
            except Exception as error:
                category = classify_error(error, stage="backend")
                observability.finish_span(
                    span,
                    outcome=outcome_for_error(category),
                    error_category=category,
                )
                raise
            else:
                observability.finish_span(span, outcome="success")
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
