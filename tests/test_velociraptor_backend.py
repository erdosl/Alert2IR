import json
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import grpc

import alert2ir.backends.velociraptor as velociraptor_module

from alert2ir.backends import (
    PyVelociraptorCollectionClient,
    UnsupportedCapabilitiesError,
    VelociraptorBackend,
    VelociraptorCollectionError,
    VelociraptorConfigurationError,
    VelociraptorTargetError,
)


_TEST_API_CONFIG = {
    "api_connection_string": "api.invalid:8001",
    "ca_certificate": "CA_CREDENTIAL_MARKER",
    "client_private_key": "PRIVATE_KEY_CREDENTIAL_MARKER",
    "client_cert": "CLIENT_CERT_CREDENTIAL_MARKER",
}


class FakeResponse:
    def __init__(self, response: object = "", log: object = "") -> None:
        self.Response = response
        self.log = log


class FakeQueryStub:
    def __init__(
        self,
        responses: list[FakeResponse] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.responses = responses or []
        self.error = error
        self.calls: list[tuple[object, float]] = []

    def Query(self, request: object, *, timeout: float):
        self.calls.append((request, timeout))
        if self.error is not None:
            raise self.error
        return iter(self.responses)


class FakeRpcError(grpc.RpcError):
    def __init__(self, message: str) -> None:
        self.message = message

    def __str__(self) -> str:
        return self.message


class FakeClock:
    def __init__(self) -> None:
        self.current = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.current

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.current += seconds


def scheduling_row(
    *,
    client_id: str = "C.TESTCLIENT",
    artifact: str = "Windows.Test.Artifact",
    flow_id: str = "F.TESTFLOW",
) -> dict[str, object]:
    return {
        "flow_id": flow_id,
        "client_id": client_id,
        "artifacts": [artifact],
    }


def flow_row(
    *,
    client_id: str = "C.TESTCLIENT",
    artifact: str = "Windows.Test.Artifact",
    flow_id: str = "F.TESTFLOW",
    state: object = "FINISHED",
) -> dict[str, object]:
    return {
        "session_id": flow_id,
        "state": state,
        "client_id": client_id,
        "artifacts": [artifact],
        "status": "",
    }
from alert2ir.core import (
    BaselineSeverityPolicy,
    CanonicalAlert,
    DetectionIdentity,
    Entity,
    EvidenceReference,
    Incident,
    InvestigationRequest,
    Severity,
    SourceProvenance,
)


class RecordingCollectionClient:
    def __init__(
        self,
        collection_reference: str = "F.CA780123",
        error: VelociraptorCollectionError | None = None,
    ) -> None:
        self.collection_reference = collection_reference
        self.error = error
        self.calls: list[tuple[str, str, float]] = []

    def collect(
        self,
        *,
        client_id: str,
        artifact: str,
        timeout_seconds: float,
    ) -> str:
        self.calls.append((client_id, artifact, timeout_seconds))
        if self.error is not None:
            raise self.error
        return self.collection_reference


def make_request(
    *,
    required_capabilities: tuple[str, ...] = ("process.list",),
    targets: tuple[Entity, ...] = (Entity("host", "workstation-7"),),
    desired_outcome: str = "collect process inventory",
) -> InvestigationRequest:
    alert = CanonicalAlert(
        detection=DetectionIdentity("rule-42", "Synthetic suspicious activity"),
        detected_at=datetime(2026, 8, 13, 9, 30, tzinfo=timezone.utc),
        source=SourceProvenance("synthetic", "alert-9001"),
        entities=(Entity("host", "workstation-7"),),
        severity=Severity.HIGH,
        evidence=(),
    )
    incident = Incident(alert, BaselineSeverityPolicy().decide(alert))
    return InvestigationRequest(
        incident=incident,
        desired_outcome=desired_outcome,
        required_capabilities=required_capabilities,
        targets=targets,
    )


def make_backend(
    client: RecordingCollectionClient | None = None,
) -> VelociraptorBackend:
    return VelociraptorBackend(
        client=client or RecordingCollectionClient(),
        host_client_ids={"workstation-7": "C.1234567890abcdef"},
        collection_timeout_seconds=12.5,
    )


class VelociraptorBackendDeclarationTests(unittest.TestCase):
    def test_name_and_capabilities_are_exact(self) -> None:
        backend = make_backend()

        self.assertEqual(backend.name, "velociraptor")
        self.assertEqual(backend.capabilities, frozenset({"process.list"}))


class VelociraptorBackendExecutionTests(unittest.TestCase):
    def test_process_list_collects_once_and_returns_existing_result_shape(self) -> None:
        client = RecordingCollectionClient("F.OPAQUE-COLLECTION")
        backend = make_backend(client)
        request = make_request(
            desired_outcome="describe something unrelated to artifact selection"
        )

        result = backend.investigate(request)

        self.assertEqual(
            client.calls,
            [("C.1234567890abcdef", "Windows.System.Pslist", 12.5)],
        )
        self.assertEqual(result.backend, "velociraptor")
        self.assertEqual(result.completed_capabilities, ("process.list",))
        self.assertEqual(
            result.evidence,
            (EvidenceReference("F.OPAQUE-COLLECTION", "collection"),),
        )

    def test_unsupported_direct_execution_uses_existing_convention(self) -> None:
        request = make_request(required_capabilities=("file.hash",))

        with self.assertRaises(UnsupportedCapabilitiesError) as raised:
            make_backend().investigate(request)

        self.assertEqual(raised.exception.requested_capabilities, ("file.hash",))

    def test_blank_collection_reference_fails_explicitly(self) -> None:
        for collection_reference in ("", " \t"):
            with self.subTest(collection_reference=collection_reference):
                client = RecordingCollectionClient(collection_reference)
                with self.assertRaises(VelociraptorCollectionError):
                    make_backend(client).investigate(make_request())
                self.assertEqual(len(client.calls), 1)

    def test_collection_execution_error_propagates_without_success_result(self) -> None:
        expected = VelociraptorCollectionError("collection failed")
        client = RecordingCollectionClient(error=expected)

        with self.assertRaises(VelociraptorCollectionError) as raised:
            make_backend(client).investigate(make_request())

        self.assertIs(raised.exception, expected)
        self.assertEqual(len(client.calls), 1)


class VelociraptorBackendTargetTests(unittest.TestCase):
    def test_no_targets_fails_explicitly(self) -> None:
        with self.assertRaises(VelociraptorTargetError):
            make_backend().investigate(make_request(targets=()))

    def test_multiple_targets_fail_explicitly(self) -> None:
        targets = (
            Entity("host", "workstation-7"),
            Entity("host", "workstation-8"),
        )

        with self.assertRaises(VelociraptorTargetError):
            make_backend().investigate(make_request(targets=targets))

    def test_non_host_target_fails_explicitly(self) -> None:
        with self.assertRaises(VelociraptorTargetError):
            make_backend().investigate(
                make_request(targets=(Entity("user", "analyst"),))
            )

    def test_unmapped_host_fails_explicitly(self) -> None:
        with self.assertRaises(VelociraptorTargetError):
            make_backend().investigate(
                make_request(targets=(Entity("host", "workstation-8"),))
            )


class VelociraptorBackendConfigurationTests(unittest.TestCase):
    def test_zero_timeout_is_rejected(self) -> None:
        with self.assertRaises(VelociraptorConfigurationError):
            VelociraptorBackend(RecordingCollectionClient(), {}, 0)

    def test_negative_timeout_is_rejected(self) -> None:
        with self.assertRaises(VelociraptorConfigurationError):
            VelociraptorBackend(RecordingCollectionClient(), {}, -1)

    def test_non_finite_timeout_is_rejected(self) -> None:
        for timeout in (float("inf"), float("-inf"), float("nan")):
            with self.subTest(timeout=timeout), self.assertRaises(
                VelociraptorConfigurationError
            ):
                VelociraptorBackend(RecordingCollectionClient(), {}, timeout)

    def test_blank_mapped_client_id_is_rejected(self) -> None:
        for client_id in ("", " \n"):
            with self.subTest(client_id=client_id), self.assertRaises(
                VelociraptorConfigurationError
            ):
                VelociraptorBackend(
                    RecordingCollectionClient(),
                    {"workstation-7": client_id},
                    1,
                )

    def test_input_mapping_mutation_cannot_change_constructed_backend(self) -> None:
        host_client_ids = {"workstation-7": "C.ORIGINAL"}
        client = RecordingCollectionClient()
        backend = VelociraptorBackend(client, host_client_ids, 3)
        host_client_ids["workstation-7"] = "C.MUTATED"

        backend.investigate(make_request())

        self.assertEqual(
            client.calls,
            [("C.ORIGINAL", "Windows.System.Pslist", 3)],
        )


class ConcreteClientTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.api_config_path = Path(self.temporary_directory.name) / "api.yaml"
        self.api_config_path.write_text("# synthetic test configuration\n")

    def make_client(
        self,
        configuration: dict[str, object] | None = None,
        observability=None,
    ) -> PyVelociraptorCollectionClient:
        loaded_configuration = (
            dict(_TEST_API_CONFIG) if configuration is None else configuration
        )
        with patch.object(
            velociraptor_module.pyvelociraptor,
            "LoadConfigFile",
            return_value=loaded_configuration,
        ) as load_config:
            client = PyVelociraptorCollectionClient(
                self.api_config_path,
                observability=observability,
            )

        load_config.assert_called_once_with(str(self.api_config_path))
        return client

    def patch_channel(self):
        credentials = object()
        channel = MagicMock(name="secure_channel")
        stub = object()
        ssl_credentials = self.enterContext(
            patch.object(
                velociraptor_module.grpc,
                "ssl_channel_credentials",
                return_value=credentials,
            )
        )
        secure_channel = self.enterContext(
            patch.object(
                velociraptor_module.grpc,
                "secure_channel",
                return_value=channel,
            )
        )
        stub_constructor = self.enterContext(
            patch.object(
                velociraptor_module.api_pb2_grpc,
                "APIStub",
                return_value=stub,
            )
        )
        return (
            credentials,
            channel,
            stub,
            ssl_credentials,
            secure_channel,
            stub_constructor,
        )

    @staticmethod
    def scheduling_query_count(query_mock: MagicMock) -> int:
        return sum(
            "collect_client(" in call.args[1]
            for call in query_mock.call_args_list
        )


class PyVelociraptorConfigurationTests(ConcreteClientTestCase):
    def test_absent_config_path_is_rejected_before_loading(self) -> None:
        missing_path = Path(self.temporary_directory.name) / "missing.yaml"

        with patch.object(
            velociraptor_module.pyvelociraptor,
            "LoadConfigFile",
        ) as load_config, self.assertRaises(VelociraptorConfigurationError):
            PyVelociraptorCollectionClient(missing_path)

        load_config.assert_not_called()

    def test_non_regular_config_path_is_rejected_before_loading(self) -> None:
        with patch.object(
            velociraptor_module.pyvelociraptor,
            "LoadConfigFile",
        ) as load_config, self.assertRaises(VelociraptorConfigurationError):
            PyVelociraptorCollectionClient(Path(self.temporary_directory.name))

        load_config.assert_not_called()

    def test_loader_failure_is_sanitized(self) -> None:
        secret_marker = _TEST_API_CONFIG["client_private_key"]
        with patch.object(
            velociraptor_module.pyvelociraptor,
            "LoadConfigFile",
            side_effect=ValueError(f"failed while reading {secret_marker}"),
        ) as load_config, self.assertRaises(
            VelociraptorConfigurationError
        ) as raised:
            PyVelociraptorCollectionClient(self.api_config_path)

        load_config.assert_called_once_with(str(self.api_config_path))
        self.assertNotIn(str(secret_marker), str(raised.exception))

    def test_missing_or_blank_required_config_fields_are_rejected(self) -> None:
        for field in _TEST_API_CONFIG:
            for replacement in (None, "", " \t"):
                with self.subTest(field=field, replacement=replacement):
                    configuration = dict(_TEST_API_CONFIG)
                    if replacement is None:
                        del configuration[field]
                    else:
                        configuration[field] = replacement

                    with patch.object(
                        velociraptor_module.pyvelociraptor,
                        "LoadConfigFile",
                        return_value=configuration,
                    ), self.assertRaises(VelociraptorConfigurationError):
                        PyVelociraptorCollectionClient(self.api_config_path)

    def test_encrypted_key_is_rejected_without_loading_or_prompting(self) -> None:
        self.api_config_path.write_text("client_private_key: ENCRYPTED\n")

        with patch.object(
            velociraptor_module.pyvelociraptor,
            "LoadConfigFile",
        ) as load_config, self.assertRaises(VelociraptorConfigurationError):
            PyVelociraptorCollectionClient(self.api_config_path)

        load_config.assert_not_called()

    def test_invalid_direct_timeout_is_rejected_before_channel_creation(self) -> None:
        client = self.make_client()
        invalid_timeouts = (
            0,
            -1,
            float("inf"),
            float("-inf"),
            float("nan"),
            True,
            "1",
            None,
        )

        with patch.object(
            velociraptor_module.grpc,
            "secure_channel",
        ) as secure_channel:
            for timeout in invalid_timeouts:
                with self.subTest(timeout=timeout), self.assertRaises(
                    VelociraptorConfigurationError
                ):
                    client.collect(
                        client_id="C.TESTCLIENT",
                        artifact="Windows.Test.Artifact",
                        timeout_seconds=timeout,  # type: ignore[arg-type]
                    )

        secure_channel.assert_not_called()


class PyVelociraptorCollectionTests(ConcreteClientTestCase):
    def test_operation_reference_is_emitted_before_terminal_poll(self) -> None:
        observed = []
        observability = MagicMock()
        observability.backend_operation_submitted.side_effect = (
            lambda reference: observed.append(("submitted", reference))
        )
        client = self.make_client(observability=observability)
        self.patch_channel()

        def query_side_effect(stub, vql, *, timeout_seconds):
            if "collect_client(" in vql:
                observed.append(("schedule", None))
                return [scheduling_row(flow_id="F.SUBMITTED")]
            observed.append(("poll", None))
            return [flow_row(flow_id="F.SUBMITTED")]

        self.enterContext(
            patch.object(client, "_run_query", side_effect=query_side_effect)
        )

        result = client.collect(
            client_id="C.TESTCLIENT",
            artifact="Windows.Test.Artifact",
            timeout_seconds=5,
        )

        self.assertEqual(result, "F.SUBMITTED")
        self.assertEqual(
            observed,
            [
                ("schedule", None),
                ("submitted", "F.SUBMITTED"),
                ("poll", None),
            ],
        )

    def test_scheduling_vql_channel_and_immediate_finished_contract(self) -> None:
        client = self.make_client()
        client_id = 'C.test"quoted\\client'
        artifact = 'Windows.Test."quoted\\artifact'
        flow_id = 'F.test"quoted\\flow'
        (
            credentials,
            channel,
            stub,
            ssl_credentials,
            secure_channel,
            stub_constructor,
        ) = self.patch_channel()
        query = self.enterContext(
            patch.object(
                client,
                "_run_query",
                side_effect=[
                    [
                        scheduling_row(
                            client_id=client_id,
                            artifact=artifact,
                            flow_id=flow_id,
                        )
                    ],
                    [
                        flow_row(
                            client_id=client_id,
                            artifact=artifact,
                            flow_id=flow_id,
                        )
                    ],
                ],
            )
        )

        returned_flow_id = client.collect(
            client_id=client_id,
            artifact=artifact,
            timeout_seconds=12.5,
        )

        self.assertEqual(returned_flow_id, flow_id)
        self.assertEqual(query.call_count, 2)
        self.assertEqual(self.scheduling_query_count(query), 1)
        scheduling_vql = query.call_args_list[0].args[1]
        polling_vql = query.call_args_list[1].args[1]
        self.assertIn(f"client_id={json.dumps(client_id)}", scheduling_vql)
        self.assertIn(f"artifacts=[{json.dumps(artifact)}]", scheduling_vql)
        self.assertIn("timeout=12.5)", scheduling_vql)
        self.assertIn("collection.flow_id AS flow_id", scheduling_vql)
        self.assertIn(f"client_id={json.dumps(client_id)}", polling_vql)
        self.assertIn(f"flow_id={json.dumps(flow_id)}", polling_vql)
        for prohibited_argument in (
            "env=",
            "spec=",
            "urgent=",
            "ops_per_sec=",
            "cpu_limit=",
            "iops_limit=",
            "max_rows=",
            "max_bytes=",
        ):
            self.assertNotIn(prohibited_argument, scheduling_vql)
        self.assertEqual(query.call_args_list[0].kwargs["timeout_seconds"], 12.5)
        self.assertGreater(query.call_args_list[1].kwargs["timeout_seconds"], 0)
        self.assertLessEqual(
            query.call_args_list[1].kwargs["timeout_seconds"], 12.5
        )
        ssl_credentials.assert_called_once_with(
            root_certificates=_TEST_API_CONFIG["ca_certificate"].encode("utf-8"),
            private_key=_TEST_API_CONFIG["client_private_key"].encode("utf-8"),
            certificate_chain=_TEST_API_CONFIG["client_cert"].encode("utf-8"),
        )
        secure_channel.assert_called_once_with(
            _TEST_API_CONFIG["api_connection_string"],
            credentials,
            options=(("grpc.ssl_target_name_override", "VelociraptorServer"),),
        )
        stub_constructor.assert_called_once_with(channel)
        self.assertIs(query.call_args_list[0].args[0], stub)
        self.assertIs(query.call_args_list[1].args[0], stub)
        channel.close.assert_called_once_with()

    def test_scheduling_requires_exactly_one_row(self) -> None:
        for rows in ([], [scheduling_row(), scheduling_row()]):
            with self.subTest(rows=rows):
                client = self.make_client()
                self.patch_channel()
                query = self.enterContext(
                    patch.object(client, "_run_query", return_value=rows)
                )

                with self.assertRaises(VelociraptorCollectionError):
                    client.collect(
                        client_id="C.TESTCLIENT",
                        artifact="Windows.Test.Artifact",
                        timeout_seconds=5,
                    )

                self.assertEqual(query.call_count, 1)
                self.assertEqual(self.scheduling_query_count(query), 1)

    def test_scheduling_rejects_invalid_flow_ids_without_rescheduling(self) -> None:
        for flow_id in (None, "", " \t", "collection-1", "F"):
            with self.subTest(flow_id=flow_id):
                client = self.make_client()
                self.patch_channel()
                row = scheduling_row()
                row["flow_id"] = flow_id
                query = self.enterContext(
                    patch.object(client, "_run_query", return_value=[row])
                )

                with self.assertRaises(VelociraptorCollectionError):
                    client.collect(
                        client_id="C.TESTCLIENT",
                        artifact="Windows.Test.Artifact",
                        timeout_seconds=5,
                    )

                self.assertEqual(query.call_count, 1)
                self.assertEqual(self.scheduling_query_count(query), 1)

    def test_scheduling_rejects_returned_client_mismatch(self) -> None:
        client = self.make_client()
        self.patch_channel()
        query = self.enterContext(
            patch.object(
                client,
                "_run_query",
                return_value=[scheduling_row(client_id="C.OTHER")],
            )
        )

        with self.assertRaises(VelociraptorCollectionError):
            client.collect(
                client_id="C.TESTCLIENT",
                artifact="Windows.Test.Artifact",
                timeout_seconds=5,
            )

        self.assertEqual(query.call_count, 1)
        self.assertEqual(self.scheduling_query_count(query), 1)

    def test_scheduling_rejects_returned_artifact_mismatch(self) -> None:
        for artifacts in (
            [],
            ["Windows.Other.Artifact"],
            ["Windows.Test.Artifact", "Windows.Other.Artifact"],
            "Windows.Test.Artifact",
        ):
            with self.subTest(artifacts=artifacts):
                client = self.make_client()
                self.patch_channel()
                row = scheduling_row()
                row["artifacts"] = artifacts
                query = self.enterContext(
                    patch.object(client, "_run_query", return_value=[row])
                )

                with self.assertRaises(VelociraptorCollectionError):
                    client.collect(
                        client_id="C.TESTCLIENT",
                        artifact="Windows.Test.Artifact",
                        timeout_seconds=5,
                    )

                self.assertEqual(query.call_count, 1)
                self.assertEqual(self.scheduling_query_count(query), 1)

    def test_zero_row_poll_then_finished_is_transient_without_real_sleep(self) -> None:
        client = self.make_client()
        self.patch_channel()
        query = self.enterContext(
            patch.object(
                client,
                "_run_query",
                side_effect=[
                    [scheduling_row()],
                    [],
                    [flow_row()],
                ],
            )
        )
        sleep = self.enterContext(patch.object(velociraptor_module.time, "sleep"))

        result = client.collect(
            client_id="C.TESTCLIENT",
            artifact="Windows.Test.Artifact",
            timeout_seconds=5,
        )

        self.assertEqual(result, "F.TESTFLOW")
        self.assertEqual(query.call_count, 3)
        self.assertEqual(self.scheduling_query_count(query), 1)
        sleep.assert_called_once()

    def test_each_v0772_nonterminal_state_polls_same_flow_until_finished(
        self,
    ) -> None:
        nonterminal_states = (
            "UNSET",
            "RUNNING",
            "WAITING",
            "IN_PROGRESS",
            "UNRESPONSIVE",
        )

        for state in nonterminal_states:
            with self.subTest(state=state):
                client = self.make_client()
                self.patch_channel()
                query = self.enterContext(
                    patch.object(
                        client,
                        "_run_query",
                        side_effect=[
                            [scheduling_row()],
                            [flow_row(state=state)],
                            [flow_row(state="FINISHED")],
                        ],
                    )
                )
                sleep = self.enterContext(
                    patch.object(velociraptor_module.time, "sleep")
                )

                result = client.collect(
                    client_id="C.TESTCLIENT",
                    artifact="Windows.Test.Artifact",
                    timeout_seconds=5,
                )

                self.assertEqual(result, "F.TESTFLOW")
                self.assertEqual(query.call_count, 3)
                self.assertEqual(self.scheduling_query_count(query), 1)
                self.assertEqual(
                    query.call_args_list[1].args[1],
                    query.call_args_list[2].args[1],
                )
                self.assertIn(
                    'flow_id="F.TESTFLOW"',
                    query.call_args_list[2].args[1],
                )
                sleep.assert_called_once()

    def test_waiting_then_finished_regresses_first_live_e2e_failure(self) -> None:
        client = self.make_client()
        self.patch_channel()
        query = self.enterContext(
            patch.object(
                client,
                "_run_query",
                side_effect=[
                    [scheduling_row()],
                    [flow_row(state="WAITING")],
                    [flow_row(state="FINISHED")],
                ],
            )
        )
        sleep = self.enterContext(patch.object(velociraptor_module.time, "sleep"))

        result = client.collect(
            client_id="C.TESTCLIENT",
            artifact="Windows.Test.Artifact",
            timeout_seconds=5,
        )

        self.assertEqual(result, "F.TESTFLOW")
        self.assertEqual(query.call_count, 3)
        self.assertEqual(self.scheduling_query_count(query), 1)
        self.assertEqual(
            query.call_args_list[1].args[1],
            query.call_args_list[2].args[1],
        )
        sleep.assert_called_once()

    def test_remote_error_state_does_not_reschedule(self) -> None:
        client = self.make_client()
        _, channel, *_ = self.patch_channel()
        query = self.enterContext(
            patch.object(
                client,
                "_run_query",
                side_effect=[
                    [scheduling_row()],
                    [flow_row(state="ERROR")],
                ],
            )
        )

        with self.assertRaises(VelociraptorCollectionError):
            client.collect(
                client_id="C.TESTCLIENT",
                artifact="Windows.Test.Artifact",
                timeout_seconds=5,
            )

        self.assertEqual(self.scheduling_query_count(query), 1)
        channel.close.assert_called_once_with()

    def test_malformed_or_unknown_flow_state_is_rejected(self) -> None:
        for state in (
            None,
            "",
            " ",
            "finished",
            "COMPLETE",
            "FAILED",
            7,
            [],
            {},
        ):
            with self.subTest(state=state):
                client = self.make_client()
                self.patch_channel()
                query = self.enterContext(
                    patch.object(
                        client,
                        "_run_query",
                        side_effect=[
                            [scheduling_row()],
                            [flow_row(state=state)],
                        ],
                    )
                )

                with self.assertRaises(VelociraptorCollectionError):
                    client.collect(
                        client_id="C.TESTCLIENT",
                        artifact="Windows.Test.Artifact",
                        timeout_seconds=5,
                    )

                self.assertEqual(self.scheduling_query_count(query), 1)

    def test_polling_rejects_flow_client_and_artifact_mismatches(self) -> None:
        mismatches = (
            {"session_id": "F.OTHER"},
            {"client_id": "C.OTHER"},
            {"artifacts": ["Windows.Other.Artifact"]},
            {"artifacts": ["Windows.Test.Artifact", "Windows.Other.Artifact"]},
        )
        for mismatch in mismatches:
            with self.subTest(mismatch=mismatch):
                client = self.make_client()
                self.patch_channel()
                row = flow_row()
                row.update(mismatch)
                query = self.enterContext(
                    patch.object(
                        client,
                        "_run_query",
                        side_effect=[[scheduling_row()], [row]],
                    )
                )

                with self.assertRaises(VelociraptorCollectionError):
                    client.collect(
                        client_id="C.TESTCLIENT",
                        artifact="Windows.Test.Artifact",
                        timeout_seconds=5,
                    )

                self.assertEqual(self.scheduling_query_count(query), 1)

    def test_polling_rejects_multiple_rows(self) -> None:
        client = self.make_client()
        self.patch_channel()
        query = self.enterContext(
            patch.object(
                client,
                "_run_query",
                side_effect=[[scheduling_row()], [flow_row(), flow_row()]],
            )
        )

        with self.assertRaises(VelociraptorCollectionError):
            client.collect(
                client_id="C.TESTCLIENT",
                artifact="Windows.Test.Artifact",
                timeout_seconds=5,
            )

        self.assertEqual(self.scheduling_query_count(query), 1)

    def test_local_deadline_timeout_does_not_schedule_again(self) -> None:
        client = self.make_client()
        _, channel, *_ = self.patch_channel()
        query = self.enterContext(
            patch.object(
                client,
                "_run_query",
                side_effect=[[scheduling_row()], []],
            )
        )
        clock = FakeClock()
        self.enterContext(
            patch.object(velociraptor_module.time, "monotonic", clock.monotonic)
        )
        self.enterContext(patch.object(velociraptor_module.time, "sleep", clock.sleep))

        with self.assertRaises(VelociraptorCollectionError):
            client.collect(
                client_id="C.TESTCLIENT",
                artifact="Windows.Test.Artifact",
                timeout_seconds=0.5,
            )

        self.assertEqual(query.call_count, 2)
        self.assertEqual(self.scheduling_query_count(query), 1)
        self.assertEqual(clock.sleeps, [0.5])
        channel.close.assert_called_once_with()

    def test_nonterminal_state_remains_bounded_by_local_deadline(self) -> None:
        client = self.make_client()
        _, channel, *_ = self.patch_channel()
        query = self.enterContext(
            patch.object(
                client,
                "_run_query",
                side_effect=[
                    [scheduling_row()],
                    [flow_row(state="UNRESPONSIVE")],
                ],
            )
        )
        clock = FakeClock()
        self.enterContext(
            patch.object(velociraptor_module.time, "monotonic", clock.monotonic)
        )
        self.enterContext(patch.object(velociraptor_module.time, "sleep", clock.sleep))

        with self.assertRaises(VelociraptorCollectionError):
            client.collect(
                client_id="C.TESTCLIENT",
                artifact="Windows.Test.Artifact",
                timeout_seconds=0.5,
            )

        self.assertEqual(query.call_count, 2)
        self.assertEqual(self.scheduling_query_count(query), 1)
        self.assertEqual(clock.sleeps, [0.5])
        channel.close.assert_called_once_with()

    def test_finished_flow_with_zero_result_rows_is_accepted(self) -> None:
        client = self.make_client()
        self.patch_channel()
        finished = flow_row()
        finished["total_collected_rows"] = 0
        self.enterContext(
            patch.object(
                client,
                "_run_query",
                side_effect=[[scheduling_row()], [finished]],
            )
        )

        result = client.collect(
            client_id="C.TESTCLIENT",
            artifact="Windows.Test.Artifact",
            timeout_seconds=5,
        )

        self.assertEqual(result, "F.TESTFLOW")

    def test_blank_direct_client_or_artifact_is_rejected_without_channel(self) -> None:
        client = self.make_client()
        with patch.object(
            velociraptor_module.grpc,
            "secure_channel",
        ) as secure_channel:
            for client_id, artifact in (
                ("", "Windows.Test.Artifact"),
                ("C.TESTCLIENT", " \t"),
            ):
                with self.subTest(
                    client_id=client_id, artifact=artifact
                ), self.assertRaises(VelociraptorCollectionError):
                    client.collect(
                        client_id=client_id,
                        artifact=artifact,
                        timeout_seconds=5,
                    )

        secure_channel.assert_not_called()

    def test_channel_creation_failure_is_sanitized(self) -> None:
        client = self.make_client()
        secret_marker = _TEST_API_CONFIG["client_private_key"]
        with patch.object(
            velociraptor_module.grpc,
            "ssl_channel_credentials",
            side_effect=RuntimeError(f"bad credential {secret_marker}"),
        ), self.assertRaises(VelociraptorCollectionError) as raised:
            client.collect(
                client_id="C.TESTCLIENT",
                artifact="Windows.Test.Artifact",
                timeout_seconds=5,
            )

        self.assertNotIn(str(secret_marker), str(raised.exception))


class PyVelociraptorQueryTests(ConcreteClientTestCase):
    def test_query_uses_one_bounded_request_and_accumulates_json_batches(self) -> None:
        client = self.make_client()
        stub = FakeQueryStub(
            [
                FakeResponse('[{"first": 1}]'),
                FakeResponse(),
                FakeResponse('[{"second": 2}]'),
            ]
        )

        rows = client._run_query(
            stub,  # type: ignore[arg-type]
            "SELECT * FROM scope()",
            timeout_seconds=3.25,
        )

        self.assertEqual(rows, [{"first": 1}, {"second": 2}])
        self.assertEqual(len(stub.calls), 1)
        request, timeout = stub.calls[0]
        self.assertEqual(timeout, 3.25)
        self.assertEqual(request.max_wait, 1)
        self.assertEqual(request.max_row, 100)
        self.assertEqual(len(request.Query), 1)
        self.assertEqual(request.Query[0].Name, "Alert2IR")
        self.assertEqual(request.Query[0].VQL, "SELECT * FROM scope()")

    def test_malformed_json_and_result_structures_are_rejected(self) -> None:
        malformed_payloads: tuple[object, ...] = (
            "{",
            '{"not": "a list"}',
            "[1]",
            '["not an object"]',
            7,
        )
        client = self.make_client()

        for payload in malformed_payloads:
            with self.subTest(payload=payload), self.assertRaises(
                VelociraptorCollectionError
            ):
                client._run_query(
                    FakeQueryStub([FakeResponse(payload)]),  # type: ignore[arg-type]
                    "SELECT * FROM scope()",
                    timeout_seconds=2,
                )

    def test_grpc_and_api_errors_are_sanitized(self) -> None:
        client = self.make_client()
        secret_marker = _TEST_API_CONFIG["client_private_key"]
        errors = (
            FakeRpcError(f"gRPC exposed {secret_marker}"),
            RuntimeError(f"API exposed {secret_marker}"),
        )

        for error in errors:
            with self.subTest(error=type(error).__name__), self.assertRaises(
                VelociraptorCollectionError
            ) as raised:
                client._run_query(
                    FakeQueryStub(error=error),  # type: ignore[arg-type]
                    "SELECT * FROM scope()",
                    timeout_seconds=2,
                )
            self.assertNotIn(str(secret_marker), str(raised.exception))

    def test_log_only_response_is_ignored_and_returns_no_rows(self) -> None:
        client = self.make_client()

        rows = client._run_query(
            FakeQueryStub(
                [FakeResponse(log="query progress")]
            ),  # type: ignore[arg-type]
            "SELECT * FROM scope()",
            timeout_seconds=2,
        )

        self.assertEqual(rows, [])

    def test_benign_log_before_valid_json_returns_valid_rows(self) -> None:
        client = self.make_client()

        rows = client._run_query(
            FakeQueryStub(
                [
                    FakeResponse(log="query progress"),
                    FakeResponse('[{"row": 1}]'),
                ]
            ),  # type: ignore[arg-type]
            "SELECT * FROM scope()",
            timeout_seconds=2,
        )

        self.assertEqual(rows, [{"row": 1}])

    def test_valid_json_before_log_only_response_returns_valid_rows(self) -> None:
        client = self.make_client()

        rows = client._run_query(
            FakeQueryStub(
                [
                    FakeResponse('[{"row": 1}]'),
                    FakeResponse(log="query complete"),
                ]
            ),  # type: ignore[arg-type]
            "SELECT * FROM scope()",
            timeout_seconds=2,
        )

        self.assertEqual(rows, [{"row": 1}])

    def test_query_log_credential_content_is_not_disclosed_by_error(self) -> None:
        client = self.make_client()
        secret_marker = _TEST_API_CONFIG["client_private_key"]
        stdout = StringIO()
        stderr = StringIO()

        with redirect_stdout(stdout), redirect_stderr(stderr), self.assertRaises(
            VelociraptorCollectionError
        ) as raised:
            client._run_query(
                FakeQueryStub(
                    [
                        FakeResponse(log=f"query detail {secret_marker}"),
                        FakeResponse("{"),
                    ]
                ),  # type: ignore[arg-type]
                "SELECT * FROM scope()",
                timeout_seconds=2,
            )

        self.assertNotIn(str(secret_marker), str(raised.exception))
        self.assertEqual(
            str(raised.exception),
            "Velociraptor API query returned malformed JSON",
        )
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
