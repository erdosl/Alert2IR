import unittest
from uuid import uuid4

from alert2ir.application import (
    AlertOrchestrator,
    PersistentAlertProcessor,
    ProcessingState,
)
from alert2ir.backends import (
    BackendRouter,
    OperationState,
    OperationStatus,
    VelociraptorBackend,
    VelociraptorSubmissionUnknownError,
)
from alert2ir.backends.velociraptor import PyVelociraptorCollectionClient
from alert2ir.core import BaselineSeverityPolicy, InvestigationRequest
from alert2ir.observability import no_op_observability
from alert2ir.persistence import InMemoryProcessingRepository
from tests.test_velociraptor_backend import make_request


FLOW_ID = "F.SECRET-OPERATION-ID"


class FakeLifecycleClient:
    def __init__(self, status=OperationState.SUCCEEDED):
        self.status = status
        self.schedule_calls = []
        self.poll_calls = []

    def schedule(self, **values):
        self.schedule_calls.append(values)
        return FLOW_ID

    def poll_flow(self, **values):
        self.poll_calls.append(values)
        return OperationStatus(self.status, self.status.value.upper())

    def collect(self, **values):
        raise AssertionError("durable backend must not use combined collection")


def backend(client):
    return VelociraptorBackend(
        client=client,
        host_client_ids={"workstation-7": "C.1234"},
        collection_timeout_seconds=5.0,
    )


def bare_client(query_once):
    client = object.__new__(PyVelociraptorCollectionClient)
    client._observability = no_op_observability()
    client._query_once = query_once
    return client


class VelociraptorSplitLifecycleTests(unittest.TestCase):
    def test_schedule_returns_flow_id_without_polling(self) -> None:
        queries = []

        def query(vql, *, timeout_seconds):
            queries.append(vql)
            return [
                {
                    "flow_id": "F.1234",
                    "client_id": "C.1234",
                    "artifacts": ["Windows.System.Pslist"],
                }
            ]

        client = bare_client(query)
        flow_id = client.schedule(
            client_id="C.1234",
            artifact="Windows.System.Pslist",
            timeout_seconds=5,
        )
        self.assertEqual(flow_id, "F.1234")
        self.assertEqual(len(queries), 1)
        self.assertIn("collect_client", queries[0])
        self.assertNotIn("FROM flows", queries[0])

    def test_exact_flow_poll_contains_no_scheduling_operation(self) -> None:
        queries = []

        def query(vql, *, timeout_seconds):
            queries.append(vql)
            return [
                {
                    "session_id": "F.1234",
                    "state": "RUNNING",
                    "client_id": "C.1234",
                    "artifacts": ["Windows.System.Pslist"],
                }
            ]

        status = bare_client(query).poll_flow(
            client_id="C.1234",
            artifact="Windows.System.Pslist",
            flow_id="F.1234",
            timeout_seconds=5,
        )
        self.assertEqual(status.state, OperationState.NONTERMINAL)
        self.assertEqual(queries, [queries[0]])
        self.assertIn("FROM flows", queries[0])
        self.assertIn('flow_id="F.1234"', queries[0])
        self.assertNotIn("collect_client", queries[0])

    def test_persisted_flow_can_be_polled_by_new_backend_instance(self) -> None:
        first_client = FakeLifecycleClient()
        submitted = backend(first_client).submit(make_request(), uuid4())
        restarted_client = FakeLifecycleClient(OperationState.NONTERMINAL)
        status = backend(restarted_client).poll(
            make_request(), submitted.external_operation_id
        )
        self.assertEqual(status.state, OperationState.NONTERMINAL)
        self.assertEqual(restarted_client.schedule_calls, [])
        self.assertEqual(
            restarted_client.poll_calls[0]["flow_id"],
            submitted.external_operation_id,
        )

    def test_restart_reconciliation_polls_exact_persisted_flow(self) -> None:
        request = make_request()
        repository = InMemoryProcessingRepository(
            lambda: request.incident.alert.detected_at
        )

        def request_factory(incident):
            return InvestigationRequest(
                incident,
                request.desired_outcome,
                request.required_capabilities,
                request.targets,
            )

        first_client = FakeLifecycleClient(OperationState.NONTERMINAL)
        first_processor = PersistentAlertProcessor(
            AlertOrchestrator(
                BaselineSeverityPolicy(),
                BackendRouter((backend(first_client),)),
                request_factory,
            ),
            repository,
        )
        first = first_processor.process(request.incident.alert, "restart-flow")
        self.assertEqual(first.record.state, ProcessingState.SUBMITTED)
        attempt = repository.get_attempt_for_processing(first.record.processing_id)
        self.assertEqual(attempt.external_operation_id, FLOW_ID)

        restarted_client = FakeLifecycleClient(OperationState.SUCCEEDED)
        restarted_processor = PersistentAlertProcessor(
            AlertOrchestrator(
                BaselineSeverityPolicy(),
                BackendRouter((backend(restarted_client),)),
                request_factory,
            ),
            repository,
        )
        report = restarted_processor.reconcile_once()

        self.assertEqual(report.advanced, 1)
        self.assertEqual(restarted_client.schedule_calls, [])
        self.assertEqual(restarted_client.poll_calls[0]["flow_id"], FLOW_ID)
        self.assertEqual(
            repository.get(first.record.processing_id).state,
            ProcessingState.COMPLETED,
        )

    def test_terminal_states_are_normalized_without_public_flow_evidence(self) -> None:
        request = make_request()
        for remote, expected in (
            (OperationState.SUCCEEDED, OperationState.SUCCEEDED),
            (OperationState.FAILED, OperationState.FAILED),
        ):
            with self.subTest(remote=remote):
                configured = backend(FakeLifecycleClient(remote))
                self.assertEqual(configured.poll(request, "F.1234").state, expected)
        result = backend(FakeLifecycleClient()).collect_result(request, "F.1234")
        self.assertEqual(result.backend, "velociraptor")
        self.assertEqual(result.evidence, ())

    def test_backend_caps_submit_and_poll_timeouts_to_caller_budget(self) -> None:
        client = FakeLifecycleClient(OperationState.NONTERMINAL)
        configured = backend(client)

        submitted = configured.submit(
            make_request(),
            uuid4(),
            timeout_seconds=0.4,
        )
        configured.poll(
            make_request(),
            submitted.external_operation_id,
            timeout_seconds=0.2,
        )

        self.assertEqual(client.schedule_calls[0]["timeout_seconds"], 0.4)
        self.assertEqual(client.poll_calls[0]["timeout_seconds"], 0.2)

    def test_unknown_scheduling_response_is_explicit_uncertainty(self) -> None:
        client = bare_client(lambda vql, timeout_seconds: [])
        with self.assertRaises(VelociraptorSubmissionUnknownError):
            client.schedule(
                client_id="C.1234",
                artifact="Windows.System.Pslist",
                timeout_seconds=5,
            )

    def test_poll_timeout_does_not_call_schedule(self) -> None:
        class TimeoutClient(FakeLifecycleClient):
            def poll_flow(self, **values):
                self.poll_calls.append(values)
                raise TimeoutError("deadline")

        client = TimeoutClient()
        with self.assertRaises(TimeoutError):
            backend(client).poll(make_request(), "F.1234")
        self.assertEqual(client.schedule_calls, [])
        self.assertEqual(len(client.poll_calls), 1)

    def test_result_collection_never_calls_client_submission_or_polling(self) -> None:
        client = FakeLifecycleClient()
        result = backend(client).collect_result(make_request(), "F.1234")
        self.assertEqual(result.evidence, ())
        self.assertEqual(client.schedule_calls, [])
        self.assertEqual(client.poll_calls, [])


if __name__ == "__main__":
    unittest.main()
