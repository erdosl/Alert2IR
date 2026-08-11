from alert2ir.api import create_app
from alert2ir.application import AlertOrchestrator
from alert2ir.backends import BackendRouter, MockBackend
from alert2ir.core import BaselineSeverityPolicy, Incident, InvestigationRequest


def _make_ws04_investigation_request(incident: Incident) -> InvestigationRequest:
    return InvestigationRequest(
        incident=incident,
        desired_outcome="collect process inventory",
        required_capabilities=("process.list",),
        targets=incident.alert.entities,
    )


app = create_app(
    AlertOrchestrator(
        policy=BaselineSeverityPolicy(),
        router=BackendRouter(
            (MockBackend(name="mock", capabilities=frozenset({"process.list"})),)
        ),
        request_factory=_make_ws04_investigation_request,
    )
)
