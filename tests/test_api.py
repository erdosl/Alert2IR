from copy import deepcopy
from datetime import datetime, timezone
from threading import Lock
import unittest
from uuid import UUID, uuid4

import httpx2

from alert2ir.api import create_app
from alert2ir.application import AlertOrchestrator, PersistentAlertProcessor
from alert2ir.backends import (
    BackendRouter,
    BackendSubmissionUnknownError,
    InvestigationResult,
    OperationState,
    OperationStatus,
    SubmittedOperation,
    VelociraptorBackend,
)
from alert2ir.core import BaselineSeverityPolicy, EvidenceReference, Incident, InvestigationRequest
from alert2ir.persistence import InMemoryProcessingRepository


PROCESSING_ID = UUID("5afaf9ce-3df8-43d3-bac8-1b875211dcc4")
CREATED_AT = datetime(2026, 8, 17, 19, 0, tzinfo=timezone.utc)


def make_payload(severity: str = "high") -> dict[str, object]:
    return {
        "detection": {
            "identifier": "rule-42",
            "name": "Synthetic suspicious activity",
        },
        "detected_at": "2026-08-17T09:30:00+00:00",
        "source": {"source": "synthetic", "source_alert_id": "alert-9001"},
        "entities": [{"kind": "host", "value": "workstation-7"}],
        "severity": severity,
        "evidence": [{"reference": "record-100", "kind": "synthetic-record"}],
    }


class CountingBackend:
    name = "mock"
    capabilities = frozenset({"process.list"})

    def __init__(self, status=OperationState.SUCCEEDED, submit_error=None):
        self.status = status
        self.submit_error = submit_error
        self.submissions = 0
        self.polls = 0
        self._lock = Lock()

    def submit(self, request, operation_key):
        with self._lock:
            self.submissions += 1
        if self.submit_error is not None:
            raise self.submit_error
        return SubmittedOperation("operation-1")

    def poll(self, request, external_operation_id):
        self.polls += 1
        return OperationStatus(self.status, self.status.value)

    def collect_result(self, request, external_operation_id):
        return InvestigationResult(
            self.name,
            request.required_capabilities,
            (EvidenceReference("mock:process.list", "mock-result"),),
        )


def make_request(
    incident: Incident,
    capabilities: tuple[str, ...] = ("process.list",),
) -> InvestigationRequest:
    return InvestigationRequest(
        incident,
        "collect process inventory",
        capabilities,
        incident.alert.entities,
    )


def make_application(
    *,
    backend=None,
    repository=None,
    capabilities=("process.list",),
    processing_id_factory=lambda: PROCESSING_ID,
):
    backend = backend or CountingBackend()
    repository = repository or InMemoryProcessingRepository(lambda: CREATED_AT)
    orchestrator = AlertOrchestrator(
        BaselineSeverityPolicy(),
        BackendRouter((backend,)),
        lambda incident: make_request(incident, capabilities),
    )
    processor = PersistentAlertProcessor(
        orchestrator,
        repository,
        processing_id_factory,
    )
    return create_app(processor), repository, backend


def make_client(app):
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://testserver",
    )


class DurableApiTests(unittest.IsolatedAsyncioTestCase):
    def assert_request_id(self, response) -> UUID:
        parsed = UUID(response.headers["X-Request-ID"])
        self.assertEqual(str(parsed), response.headers["X-Request-ID"])
        return parsed

    async def test_health_and_readiness_contracts(self) -> None:
        app, _, _ = make_application()
        async with make_client(app) as client:
            health = await client.get("/healthz")
            readiness = await client.get("/readyz")
        self.assertEqual(health.json(), {"status": "ok"})
        self.assertEqual(readiness.json(), {"status": "ready"})

    async def test_missing_and_invalid_idempotency_keys(self) -> None:
        invalid = ["", "contains space", "\x7f", "x" * 129]
        app, repository, backend = make_application()
        async with make_client(app) as client:
            missing = await client.post("/v1/alerts", json=make_payload())
            responses = [
                await client.post(
                    "/v1/alerts",
                    json=make_payload(),
                    headers={"Idempotency-Key": value},
                )
                for value in invalid
            ]
            duplicate = await client.post(
                "/v1/alerts",
                json=make_payload(),
                headers=[("Idempotency-Key", "one"), ("Idempotency-Key", "two")],
            )
        self.assertEqual(missing.status_code, 400)
        self.assertEqual(missing.json()["code"], "idempotency_key_required")
        for response in (*responses, duplicate):
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json()["code"], "invalid_idempotency_key")
        self.assertEqual(repository._records, {})
        self.assertEqual(backend.submissions, 0)

    async def test_completed_processing_and_replay_headers(self) -> None:
        app, _, backend = make_application()
        async with make_client(app) as client:
            first = await client.post(
                "/v1/alerts",
                json=make_payload(),
                headers={"Idempotency-Key": "Case-Sensitive-Key"},
            )
            replay = await client.post(
                "/v1/alerts",
                json=make_payload(),
                headers={"Idempotency-Key": "Case-Sensitive-Key"},
            )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(first.json()["processing_id"], str(PROCESSING_ID))
        self.assertEqual(replay.json(), first.json())
        self.assertNotIn("Idempotency-Replayed", first.headers)
        self.assertEqual(replay.headers["Idempotency-Replayed"], "true")
        self.assertEqual(
            replay.headers["Location"], f"/v1/processings/{PROCESSING_ID}"
        )
        self.assertNotEqual(self.assert_request_id(first), self.assert_request_id(replay))
        self.assertEqual(backend.submissions, 1)
        self.assertEqual(
            first.json()["investigation_result"]["evidence"][0]["reference"],
            "mock:process.list",
        )

    async def test_active_replay_is_202_without_duplicate_backend_action(self) -> None:
        backend = CountingBackend(OperationState.NONTERMINAL)
        app, _, _ = make_application(backend=backend)
        headers = {"Idempotency-Key": "active"}
        async with make_client(app) as client:
            first = await client.post(
                "/v1/alerts", json=make_payload(), headers=headers
            )
            replay = await client.post(
                "/v1/alerts", json=make_payload(), headers=headers
            )
        self.assertEqual(first.status_code, 202)
        self.assertEqual(first.json()["state"], "submitted")
        self.assertEqual(replay.status_code, 202)
        self.assertEqual(replay.headers["Idempotency-Replayed"], "true")
        self.assertEqual(backend.submissions, 1)
        self.assertEqual(backend.polls, 1)

    async def test_recovery_required_is_202_and_never_resubmitted(self) -> None:
        backend = CountingBackend(
            submit_error=BackendSubmissionUnknownError("response lost")
        )
        app, _, _ = make_application(backend=backend)
        headers = {"Idempotency-Key": "uncertain"}
        async with make_client(app) as client:
            first = await client.post("/v1/alerts", json=make_payload(), headers=headers)
            replay = await client.post("/v1/alerts", json=make_payload(), headers=headers)
        self.assertEqual(first.status_code, 202)
        self.assertEqual(first.json()["state"], "recovery_required")
        self.assertEqual(replay.json()["state"], "recovery_required")
        self.assertEqual(backend.submissions, 1)

    async def test_terminal_backend_failure_is_durable_and_replayed(self) -> None:
        backend = CountingBackend(OperationState.FAILED)
        app, _, _ = make_application(backend=backend)
        headers = {"Idempotency-Key": "terminal-failure"}
        async with make_client(app) as client:
            first = await client.post("/v1/alerts", json=make_payload(), headers=headers)
            replay = await client.post("/v1/alerts", json=make_payload(), headers=headers)
        self.assertEqual(first.status_code, 500)
        self.assertEqual(first.json()["state"], "failed")
        self.assertEqual(first.json()["error_category"], "backend_execution_failed")
        self.assertEqual(replay.status_code, 500)
        self.assertEqual(replay.json(), first.json())
        self.assertEqual(replay.headers["Idempotency-Replayed"], "true")
        self.assertNotEqual(
            self.assert_request_id(first),
            self.assert_request_id(replay),
        )
        self.assertEqual(backend.submissions, 1)

    async def test_unsupported_failure_replay_preserves_public_semantics(self) -> None:
        app, repository, backend = make_application(capabilities=("unsupported",))
        headers = {"Idempotency-Key": "unsupported-replay"}
        changed = make_payload("critical")
        async with make_client(app) as client:
            first = await client.post("/v1/alerts", json=make_payload(), headers=headers)
            replay = await client.post("/v1/alerts", json=make_payload(), headers=headers)
            conflict = await client.post("/v1/alerts", json=changed, headers=headers)

        self.assertEqual(first.status_code, 409)
        self.assertEqual(replay.status_code, 409)
        self.assertEqual(first.json()["code"], "unsupported_capability")
        self.assertEqual(replay.json()["code"], "unsupported_capability")
        self.assertEqual(first.json()["processing_id"], replay.json()["processing_id"])
        self.assertEqual(first.json()["state"], "failed")
        self.assertEqual(replay.json()["state"], "failed")
        self.assertNotIn("Idempotency-Replayed", first.headers)
        self.assertEqual(replay.headers["Idempotency-Replayed"], "true")
        self.assertEqual(first.headers["Location"], replay.headers["Location"])
        self.assertNotEqual(self.assert_request_id(first), self.assert_request_id(replay))
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["code"], "idempotency_conflict")
        self.assertEqual(len(repository._records), 1)
        processing_id = UUID(first.json()["processing_id"])
        durable = repository.get(processing_id)
        self.assertEqual(durable.error_category, "unsupported_capability")
        self.assertIsNone(repository.get_attempt_for_processing(processing_id))
        self.assertEqual(backend.submissions, 0)

    async def test_velociraptor_flow_id_is_internal_to_post_and_get(self) -> None:
        flow_id = "F.SECRET-OPERATION-ID"

        class FakeVelociraptorClient:
            def __init__(self) -> None:
                self.schedule_calls = []
                self.poll_calls = []

            def schedule(self, **values):
                self.schedule_calls.append(values)
                return flow_id

            def poll_flow(self, **values):
                self.poll_calls.append(values)
                return OperationStatus(OperationState.SUCCEEDED, "FINISHED")

        client_backend = FakeVelociraptorClient()
        backend = VelociraptorBackend(
            client_backend,
            {"workstation-7": "C.TEST"},
            5.0,
        )
        app, repository, _ = make_application(backend=backend)
        async with make_client(app) as client:
            post = await client.post(
                "/v1/alerts",
                json=make_payload(),
                headers={"Idempotency-Key": "private-flow"},
            )
            status = await client.get(post.headers["Location"])

        self.assertEqual(post.status_code, 200)
        self.assertEqual(status.status_code, 200)
        self.assertNotIn(flow_id, post.text)
        self.assertNotIn(flow_id, status.text)
        self.assertEqual(post.json()["investigation_result"]["evidence"], [])
        self.assertEqual(status.json()["investigation_result"]["evidence"], [])
        processing_id = UUID(post.json()["processing_id"])
        attempt = repository.get_attempt_for_processing(processing_id)
        self.assertEqual(attempt.external_operation_id, flow_id)
        self.assertEqual(len(client_backend.schedule_calls), 1)
        self.assertEqual(client_backend.poll_calls[0]["flow_id"], flow_id)

    async def test_same_scoped_key_with_changed_payload_conflicts(self) -> None:
        app, repository, backend = make_application()
        headers = {"Idempotency-Key": "conflict"}
        changed = deepcopy(make_payload())
        changed["severity"] = "critical"
        async with make_client(app) as client:
            first = await client.post("/v1/alerts", json=make_payload(), headers=headers)
            conflict = await client.post("/v1/alerts", json=changed, headers=headers)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["code"], "idempotency_conflict")
        self.assertEqual(len(repository._records), 1)
        self.assertEqual(backend.submissions, 1)

    async def test_scope_is_exact_source_and_key_is_case_sensitive(self) -> None:
        app, repository, _ = make_application(processing_id_factory=uuid4)
        first = make_payload("low")
        other_source = deepcopy(first)
        other_source["source"]["source"] = "other"
        async with make_client(app) as client:
            responses = [
                await client.post(
                    "/v1/alerts",
                    json=body,
                    headers={"Idempotency-Key": key},
                )
                for body, key in (
                    (first, "Key"),
                    (first, "key"),
                    (other_source, "Key"),
                )
            ]
        self.assertTrue(all(response.status_code == 200 for response in responses))
        self.assertEqual(len(repository._records), 3)

    async def test_persistence_failure_before_acceptance_is_503_and_skips_backend(self) -> None:
        class UnavailableRepository:
            def check_readiness(self):
                raise RuntimeError("unavailable")

            def accept_processing(self, *args, **kwargs):
                raise RuntimeError("unavailable")

        backend = CountingBackend()
        app, _, _ = make_application(repository=UnavailableRepository(), backend=backend)
        async with make_client(app) as client:
            response = await client.post(
                "/v1/alerts",
                json=make_payload(),
                headers={"Idempotency-Key": "Key"},
            )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["code"], "persistence_failed")
        self.assertEqual(backend.submissions, 0)

    async def test_get_returns_bounded_public_status_without_internal_metadata(self) -> None:
        app, _, _ = make_application()
        async with make_client(app) as client:
            post = await client.post(
                "/v1/alerts",
                json=make_payload(),
                headers={"Idempotency-Key": "SECRET-IDEMPOTENCY-VALUE"},
            )
            status = await client.get(post.headers["Location"])
            missing = await client.get(f"/v1/processings/{uuid4()}")
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json()["processing_id"], post.json()["processing_id"])
        serialized = status.text.lower()
        for prohibited in (
            "idempotency",
            "fingerprint",
            "operation_key",
            "external_operation",
            "secret-idempotency-value",
        ):
            self.assertNotIn(prohibited, serialized)
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.json()["code"], "processing_not_found")

    async def test_get_of_submitted_processing_never_submits_or_polls(self) -> None:
        backend = CountingBackend(OperationState.NONTERMINAL)
        app, _, _ = make_application(backend=backend)
        async with make_client(app) as client:
            post = await client.post(
                "/v1/alerts",
                json=make_payload(),
                headers={"Idempotency-Key": "active-get"},
            )
            status = await client.get(post.headers["Location"])
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.json()["state"], "submitted")
        self.assertEqual(backend.submissions, 1)
        self.assertEqual(backend.polls, 1)

    async def test_no_action_keeps_existing_logical_result_shape(self) -> None:
        app, _, backend = make_application()
        async with make_client(app) as client:
            response = await client.post(
                "/v1/alerts",
                json=make_payload("low"),
                headers={"Idempotency-Key": "no-action"},
            )
        body = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["state"], "completed")
        self.assertEqual(body["decision"]["outcome"], "no_action")
        self.assertIsNone(body["incident"])
        self.assertIsNone(body["investigation_request"])
        self.assertIsNone(body["investigation_result"])
        self.assertEqual(backend.submissions, 0)

    async def test_validation_and_routing_remain_typed(self) -> None:
        payload = make_payload()
        payload["unexpected"] = "value"
        app, _, _ = make_application(capabilities=("unsupported",))
        async with make_client(app) as client:
            validation = await client.post(
                "/v1/alerts",
                json=payload,
                headers={"Idempotency-Key": "validation"},
            )
            routing = await client.post(
                "/v1/alerts",
                json=make_payload(),
                headers={"Idempotency-Key": "routing"},
            )
        self.assertEqual(validation.status_code, 422)
        self.assertEqual(routing.status_code, 409)
        self.assertEqual(routing.json()["code"], "unsupported_capability")

    async def test_openapi_documents_status_resource_and_idempotent_responses(self) -> None:
        app, _, _ = make_application()
        async with make_client(app) as client:
            document = (await client.get("/openapi.json")).json()
        self.assertIn("/v1/processings/{processing_id}", document["paths"])
        responses = document["paths"]["/v1/alerts"]["post"]["responses"]
        for status in ("200", "202", "400", "409", "503"):
            self.assertIn(status, responses)
        parameters = document["paths"]["/v1/alerts"]["post"]["parameters"]
        self.assertEqual(parameters[0]["name"], "Idempotency-Key")
        self.assertTrue(parameters[0]["required"])


if __name__ == "__main__":
    unittest.main()
