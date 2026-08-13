from datetime import datetime, timezone
import unittest

from alert2ir.backends import (
    UnsupportedCapabilitiesError,
    VelociraptorBackend,
    VelociraptorCollectionError,
    VelociraptorConfigurationError,
    VelociraptorTargetError,
)
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


if __name__ == "__main__":
    unittest.main()
