from datetime import datetime, timezone
import unittest

from alert2ir.backends import (
    AmbiguousBackendError,
    BackendRouter,
    InvestigationResult,
    MockBackend,
    UnsupportedCapabilitiesError,
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


def make_request(
    required_capabilities: tuple[str, ...] = ("process.list",),
) -> InvestigationRequest:
    alert = CanonicalAlert(
        detection=DetectionIdentity("rule-42", "Synthetic suspicious activity"),
        detected_at=datetime(2026, 8, 11, 9, 30, tzinfo=timezone.utc),
        source=SourceProvenance("synthetic", "alert-9001"),
        entities=(Entity("host", "workstation-7"),),
        severity=Severity.HIGH,
        evidence=(),
    )
    incident = Incident(alert, BaselineSeverityPolicy().decide(alert))
    return InvestigationRequest(
        incident=incident,
        desired_outcome="collect investigation evidence",
        required_capabilities=required_capabilities,
        targets=(Entity("host", "workstation-7"),),
    )


class InvestigationResultTests(unittest.TestCase):
    def test_empty_completed_capabilities_and_evidence_are_valid(self) -> None:
        result = InvestigationResult(
            backend="mock",
            completed_capabilities=(),
            evidence=(),
        )

        self.assertEqual(result.completed_capabilities, ())
        self.assertEqual(result.evidence, ())

    def test_backend_must_be_non_empty(self) -> None:
        for backend in ("", " \t"):
            with self.subTest(backend=backend), self.assertRaises(ValueError):
                InvestigationResult(backend, (), ())

    def test_each_completed_capability_must_be_non_empty(self) -> None:
        for capability in ("", " \n"):
            with self.subTest(capability=capability), self.assertRaises(ValueError):
                InvestigationResult("mock", (capability,), ())


class MockBackendContractTests(unittest.TestCase):
    def test_backend_retains_name_and_advertised_capabilities(self) -> None:
        capabilities = frozenset({"process.list"})
        backend = MockBackend(name="mock", capabilities=capabilities)

        self.assertEqual(backend.name, "mock")
        self.assertEqual(backend.capabilities, capabilities)

    def test_backend_name_must_be_non_empty(self) -> None:
        for name in ("", " \t"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                MockBackend(name=name, capabilities=frozenset())

    def test_each_advertised_capability_must_be_non_empty(self) -> None:
        for capability in ("", " \n"):
            with self.subTest(capability=capability), self.assertRaises(ValueError):
                MockBackend("mock", frozenset({capability}))

    def test_empty_capability_set_is_valid(self) -> None:
        backend = MockBackend("mock", frozenset())

        self.assertEqual(backend.capabilities, frozenset())


class BackendRouterTests(unittest.TestCase):
    def test_selects_only_backend_supporting_request(self) -> None:
        process_backend = MockBackend("process-mock", frozenset({"process.list"}))
        file_backend = MockBackend("file-mock", frozenset({"file.hash"}))
        router = BackendRouter((file_backend, process_backend))

        self.assertIs(router.select(make_request()), process_backend)

    def test_selects_backend_supporting_complete_multi_capability_set(self) -> None:
        partial_backend = MockBackend("partial", frozenset({"process.list"}))
        complete_backend = MockBackend(
            "complete",
            frozenset({"process.list", "file.hash"}),
        )
        router = BackendRouter((partial_backend, complete_backend))

        selected = router.select(make_request(("process.list", "file.hash")))

        self.assertIs(selected, complete_backend)

    def test_no_eligible_backend_is_explicitly_unsupported(self) -> None:
        request = make_request(("process.list",))
        router = BackendRouter((MockBackend("file", frozenset({"file.hash"})),))

        with self.assertRaises(UnsupportedCapabilitiesError) as raised:
            router.select(request)

        self.assertEqual(raised.exception.requested_capabilities, ("process.list",))

    def test_empty_router_is_explicitly_unsupported(self) -> None:
        with self.assertRaises(UnsupportedCapabilitiesError):
            BackendRouter(()).select(make_request())

    def test_capabilities_split_across_backends_do_not_satisfy_request(self) -> None:
        router = BackendRouter(
            (
                MockBackend("process", frozenset({"process.list"})),
                MockBackend("file", frozenset({"file.hash"})),
            )
        )
        request = make_request(("process.list", "file.hash"))

        with self.assertRaises(UnsupportedCapabilitiesError):
            router.select(request)

    def test_multiple_eligible_backends_are_ambiguous(self) -> None:
        request = make_request()
        router = BackendRouter(
            (
                MockBackend("mock-a", frozenset({"process.list"})),
                MockBackend("mock-b", frozenset({"process.list"})),
            )
        )

        with self.assertRaises(AmbiguousBackendError) as raised:
            router.select(request)

        self.assertEqual(raised.exception.requested_capabilities, ("process.list",))
        self.assertEqual(raised.exception.eligible_backends, ("mock-a", "mock-b"))


class MockBackendExecutionTests(unittest.TestCase):
    def test_unsupported_direct_execution_fails_explicitly(self) -> None:
        backend = MockBackend("mock", frozenset({"file.hash"}))

        with self.assertRaises(UnsupportedCapabilitiesError) as raised:
            backend.investigate(make_request())

        self.assertEqual(raised.exception.requested_capabilities, ("process.list",))

    def test_supported_execution_is_deterministic(self) -> None:
        backend = MockBackend("mock", frozenset({"process.list"}))
        request = make_request()
        expected = InvestigationResult(
            backend="mock",
            completed_capabilities=("process.list",),
            evidence=(
                EvidenceReference(
                    reference="mock:process.list",
                    kind="mock-result",
                ),
            ),
        )

        self.assertEqual(backend.investigate(request), expected)
        self.assertEqual(backend.investigate(request), backend.investigate(request))

    def test_multi_capability_execution_preserves_request_order(self) -> None:
        backend = MockBackend(
            "mock",
            frozenset({"process.list", "file.hash"}),
        )
        request = make_request(("file.hash", "process.list"))
        result = backend.investigate(request)

        self.assertEqual(result.completed_capabilities, ("file.hash", "process.list"))
        self.assertEqual(
            result.evidence,
            (
                EvidenceReference("mock:file.hash", "mock-result"),
                EvidenceReference("mock:process.list", "mock-result"),
            ),
        )


if __name__ == "__main__":
    unittest.main()
