import logging
import os

from alert2ir.api import create_app
from alert2ir.application import AlertOrchestrator, PersistentAlertProcessor
from alert2ir.backends import (
    BackendRouter,
    MockBackend,
    PyVelociraptorCollectionClient,
    VelociraptorBackend,
)
from alert2ir.core import BaselineSeverityPolicy, Incident, InvestigationRequest
from alert2ir.persistence import PostgresProcessingRepository
from alert2ir.observability import ApplicationObservability, configure_observability


_BACKEND_SETTING = "ALERT2IR_BACKEND"
_VELOCIRAPTOR_API_CONFIG_PATH_SETTING = (
    "ALERT2IR_VELOCIRAPTOR_API_CONFIG_PATH"
)
_VELOCIRAPTOR_HOST_SETTING = "ALERT2IR_VELOCIRAPTOR_HOST"
_VELOCIRAPTOR_CLIENT_ID_SETTING = "ALERT2IR_VELOCIRAPTOR_CLIENT_ID"
_VELOCIRAPTOR_APPLICATION_SETTINGS = (
    _VELOCIRAPTOR_API_CONFIG_PATH_SETTING,
    _VELOCIRAPTOR_HOST_SETTING,
    _VELOCIRAPTOR_CLIENT_ID_SETTING,
)
_VELOCIRAPTOR_COLLECTION_TIMEOUT_SECONDS = 60.0


def _require_database_url() -> str:
    database_url = os.environ.get("ALERT2IR_DATABASE_URL")
    if database_url is None or not database_url.strip():
        raise RuntimeError("ALERT2IR_DATABASE_URL must be set and non-empty")
    return database_url


def _require_exact_nonempty_setting(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value or value != value.strip():
        raise RuntimeError(
            f"{name} must be set to a non-empty value without leading or "
            "trailing whitespace"
        )
    return value


def _make_backend_router(observability: ApplicationObservability) -> BackendRouter:
    if _BACKEND_SETTING not in os.environ:
        backend_name = "mock"
    else:
        backend_name = os.environ[_BACKEND_SETTING]

    if backend_name not in {"mock", "velociraptor"}:
        raise RuntimeError(
            "ALERT2IR_BACKEND must be exactly 'mock' or 'velociraptor'"
        )

    configured_velociraptor_settings = tuple(
        name for name in _VELOCIRAPTOR_APPLICATION_SETTINGS if name in os.environ
    )

    if backend_name == "mock":
        if configured_velociraptor_settings:
            raise RuntimeError(
                "Velociraptor application settings require "
                "ALERT2IR_BACKEND='velociraptor'"
            )
        return BackendRouter(
            backends=(
                MockBackend(
                    name="mock",
                    capabilities=frozenset({"process.list"}),
                ),
            )
        )

    api_config_path = _require_exact_nonempty_setting(
        _VELOCIRAPTOR_API_CONFIG_PATH_SETTING
    )
    host = _require_exact_nonempty_setting(_VELOCIRAPTOR_HOST_SETTING)
    client_id = _require_exact_nonempty_setting(_VELOCIRAPTOR_CLIENT_ID_SETTING)
    client = PyVelociraptorCollectionClient(
        api_config_path=api_config_path,
        observability=observability,
    )
    backend = VelociraptorBackend(
        client=client,
        host_client_ids={host: client_id},
        collection_timeout_seconds=_VELOCIRAPTOR_COLLECTION_TIMEOUT_SECONDS,
        observability=observability,
    )
    return BackendRouter(backends=(backend,))


def _make_process_inventory_request(incident: Incident) -> InvestigationRequest:
    return InvestigationRequest(
        incident=incident,
        desired_outcome="collect process inventory",
        required_capabilities=("process.list",),
        targets=incident.alert.entities,
    )


observability = configure_observability()
orchestrator = AlertOrchestrator(
    policy=BaselineSeverityPolicy(),
    router=_make_backend_router(observability),
    request_factory=_make_process_inventory_request,
    observability=observability,
)

processor = PersistentAlertProcessor(
    orchestrator=orchestrator,
    repository=PostgresProcessingRepository(_require_database_url()),
    observability=observability,
)
app = create_app(processor, observability)

# Application-owned request completion events replace the ordinary access line;
# Uvicorn lifecycle and error logging remain enabled.
logging.getLogger("uvicorn.access").disabled = True
configured_backend = orchestrator.router.backends[0]
observability.events.emit(
    "service.started",
    backend=configured_backend.name,
    capabilities=sorted(configured_backend.capabilities),
    persistence="postgresql",
)
