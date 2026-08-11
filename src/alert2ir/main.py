import os

from alert2ir.api import create_app
from alert2ir.application import AlertOrchestrator, PersistentAlertProcessor
from alert2ir.backends import BackendRouter, MockBackend
from alert2ir.core import BaselineSeverityPolicy, Incident, InvestigationRequest
from alert2ir.persistence import PostgresProcessingRepository


def _require_database_url() -> str:
    database_url = os.environ.get("ALERT2IR_DATABASE_URL")
    if database_url is None or not database_url.strip():
        raise RuntimeError("ALERT2IR_DATABASE_URL must be set and non-empty")
    return database_url


def _make_ws04_investigation_request(incident: Incident) -> InvestigationRequest:
    return InvestigationRequest(
        incident=incident,
        desired_outcome="collect process inventory",
        required_capabilities=("process.list",),
        targets=incident.alert.entities,
    )


orchestrator = AlertOrchestrator(
    policy=BaselineSeverityPolicy(),
    router=BackendRouter(
        (MockBackend(name="mock", capabilities=frozenset({"process.list"})),)
    ),
    request_factory=_make_ws04_investigation_request,
)

app = create_app(
    PersistentAlertProcessor(
        orchestrator=orchestrator,
        repository=PostgresProcessingRepository(_require_database_url()),
    )
)
