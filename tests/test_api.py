from copy import deepcopy
import unittest

import httpx2

from alert2ir.api import create_app
from alert2ir.application import AlertOrchestrator
from alert2ir.backends import BackendRouter, MockBackend
from alert2ir.core import BaselineSeverityPolicy, Incident, InvestigationRequest


def make_payload(severity: str = "high") -> dict[str, object]:
    return {
        "detection": {
            "identifier": "rule-42",
            "name": "Synthetic suspicious activity",
        },
        "detected_at": "2026-08-11T09:30:00+00:00",
        "source": {"source": "synthetic", "source_alert_id": "alert-9001"},
        "entities": [{"kind": "host", "value": "workstation-7"}],
        "severity": severity,
        "evidence": [{"reference": "record-100", "kind": "synthetic-record"}],
    }


def make_request(
    incident: Incident,
    capabilities: tuple[str, ...] = ("process.list",),
) -> InvestigationRequest:
    return InvestigationRequest(
        incident=incident,
        desired_outcome="collect process inventory",
        required_capabilities=capabilities,
        targets=incident.alert.entities,
    )


def make_client(
    backends: tuple[MockBackend, ...] | None = None,
    capabilities: tuple[str, ...] = ("process.list",),
) -> httpx2.AsyncClient:
    configured_backends = backends or (
        MockBackend("mock", frozenset({"process.list"})),
    )

    def request_factory(incident: Incident) -> InvestigationRequest:
        return make_request(incident, capabilities)

    orchestrator = AlertOrchestrator(
        policy=BaselineSeverityPolicy(),
        router=BackendRouter(configured_backends),
        request_factory=request_factory,
    )
    transport = httpx2.ASGITransport(app=create_app(orchestrator))
    return httpx2.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    )


class ApiEndpointTests(unittest.IsolatedAsyncioTestCase):
    async def test_health_endpoint_is_unchanged(self) -> None:
        async with make_client() as client:
            response = await client.get("/healthz")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    async def test_typed_investigate_flow(self) -> None:
        async with make_client() as client:
            response = await client.post("/v1/alerts", json=make_payload("high"))

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["decision"]["outcome"], "investigate")
        self.assertEqual(body["decision"]["policy_id"], "baseline-severity-v1")
        self.assertEqual(
            body["decision"]["source"],
            {"source": "synthetic", "source_alert_id": "alert-9001"},
        )
        self.assertEqual(body["incident"]["alert"]["detection"]["identifier"], "rule-42")
        self.assertEqual(body["incident"]["decision"], body["decision"])
        self.assertEqual(
            body["investigation_request"],
            {
                "desired_outcome": "collect process inventory",
                "required_capabilities": ["process.list"],
                "targets": [{"kind": "host", "value": "workstation-7"}],
            },
        )
        self.assertEqual(
            body["investigation_result"],
            {
                "backend": "mock",
                "completed_capabilities": ["process.list"],
                "evidence": [
                    {"reference": "mock:process.list", "kind": "mock-result"}
                ],
            },
        )

    async def test_typed_no_action_flow(self) -> None:
        async with make_client() as client:
            response = await client.post("/v1/alerts", json=make_payload("low"))

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["decision"]["outcome"], "no_action")
        self.assertIsNone(body["incident"])
        self.assertIsNone(body["investigation_request"])
        self.assertIsNone(body["investigation_result"])

    async def test_source_specific_extra_field_is_rejected(self) -> None:
        payload = make_payload()
        payload["source_only_debug_field"] = "must not cross boundary"

        async with make_client() as client:
            response = await client.post("/v1/alerts", json=payload)

        self.assertEqual(response.status_code, 422)

    async def test_naive_timestamp_is_rejected(self) -> None:
        payload = make_payload("low")
        payload["detected_at"] = "2026-08-11T09:30:00"

        async with make_client() as client:
            response = await client.post("/v1/alerts", json=payload)

        self.assertEqual(response.status_code, 422)

    async def test_timezone_aware_timestamp_is_accepted(self) -> None:
        async with make_client() as client:
            response = await client.post("/v1/alerts", json=make_payload("low"))

        self.assertEqual(response.status_code, 200)

    async def test_representative_whitespace_strings_are_rejected(self) -> None:
        for path in (("detection", "identifier"), ("source", "source")):
            with self.subTest(path=path):
                payload = deepcopy(make_payload())
                nested = payload[path[0]]
                nested[path[1]] = " \t"

                async with make_client() as client:
                    response = await client.post("/v1/alerts", json=payload)

                self.assertEqual(response.status_code, 422)

    async def test_unsupported_capabilities_map_to_conflict(self) -> None:
        async with make_client(capabilities=("file.hash",)) as client:
            response = await client.post(
                "/v1/alerts",
                json=make_payload(),
            )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.json(),
            {
                "code": "unsupported_capabilities",
                "message": "no configured backend supports all requested capabilities: ('file.hash',)",
                "requested_capabilities": ["file.hash"],
                "eligible_backends": None,
            },
        )

    async def test_ambiguous_routing_maps_to_internal_error(self) -> None:
        backends = (
            MockBackend("mock-a", frozenset({"process.list"})),
            MockBackend("mock-b", frozenset({"process.list"})),
        )

        async with make_client(backends=backends) as client:
            response = await client.post(
                "/v1/alerts",
                json=make_payload(),
            )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json(),
            {
                "code": "ambiguous_backend",
                "message": "multiple backends support all requested capabilities and no selection policy is defined: ('mock-a', 'mock-b')",
                "requested_capabilities": ["process.list"],
                "eligible_backends": ["mock-a", "mock-b"],
            },
        )

    async def test_openapi_documents_typed_boundary_and_errors(self) -> None:
        async with make_client() as client:
            response = await client.get("/openapi.json")
        document = response.json()

        self.assertIn("/healthz", document["paths"])
        self.assertIn("/v1/alerts", document["paths"])
        operation = document["paths"]["/v1/alerts"]["post"]
        request_schema = operation["requestBody"]["content"]["application/json"]["schema"]
        self.assertTrue(request_schema)
        self.assertTrue(operation["responses"]["200"]["content"]["application/json"]["schema"])
        self.assertIn("409", operation["responses"])
        self.assertIn("500", operation["responses"])
        canonical_schema = document["components"]["schemas"]["CanonicalAlertRequest"]
        self.assertEqual(
            set(canonical_schema["properties"]),
            {"detection", "detected_at", "source", "entities", "severity", "evidence"},
        )


if __name__ == "__main__":
    unittest.main()
