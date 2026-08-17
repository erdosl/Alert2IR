from datetime import datetime, timezone
from typing import cast
import unittest

from alert2ir.application import AlertOrchestrator, OrchestrationResult
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
    Decision,
    DecisionOutcome,
    DetectionIdentity,
    Entity,
    EvidenceReference,
    Incident,
    InvestigationRequest,
    Severity,
    SourceProvenance,
)


def make_alert(severity: Severity) -> CanonicalAlert:
    return CanonicalAlert(
        detection=DetectionIdentity("rule-42", "Synthetic suspicious activity"),
        detected_at=datetime(2026, 8, 11, 9, 30, tzinfo=timezone.utc),
        source=SourceProvenance("synthetic", "alert-9001"),
        entities=(Entity("host", "workstation-7"),),
        severity=severity,
        evidence=(),
    )


def make_process_request(incident: Incident) -> InvestigationRequest:
    return InvestigationRequest(
        incident=incident,
        desired_outcome="collect process inventory",
        required_capabilities=("process.list",),
        targets=incident.alert.entities,
    )


class AlertOrchestratorTests(unittest.TestCase):
    def test_no_action_skips_all_investigation_work(self) -> None:
        def fail_if_called(incident: Incident) -> InvestigationRequest:
            raise AssertionError(f"request factory called unexpectedly for {incident!r}")

        orchestrator = AlertOrchestrator(
            policy=BaselineSeverityPolicy(),
            router=BackendRouter(()),
            request_factory=fail_if_called,
        )

        result = orchestrator.plan(make_alert(Severity.LOW))

        self.assertEqual(result.decision.outcome, DecisionOutcome.NO_ACTION)
        self.assertIsNone(result.incident)
        self.assertIsNone(result.investigation_request)
        self.assertIsNone(result.backend)

    def test_no_action_with_mismatched_policy_provenance_fails_early(self) -> None:
        class MismatchedPolicy:
            def decide(self, alert: CanonicalAlert) -> Decision:
                return Decision(
                    outcome=DecisionOutcome.NO_ACTION,
                    policy_id="mismatched-policy",
                    reasons=("no action",),
                    source=SourceProvenance("other-source", "other-alert"),
                )

        def fail_if_called(incident: Incident) -> InvestigationRequest:
            raise AssertionError(f"request factory called unexpectedly for {incident!r}")

        orchestrator = AlertOrchestrator(
            policy=MismatchedPolicy(),
            router=BackendRouter(backends=()),
            request_factory=fail_if_called,
        )

        with self.assertRaisesRegex(
            ValueError,
            "decision source must match alert source",
        ):
            orchestrator.plan(make_alert(Severity.LOW))

    def test_supported_investigation_produces_complete_chain(self) -> None:
        alert = make_alert(Severity.HIGH)
        orchestrator = AlertOrchestrator(
            policy=BaselineSeverityPolicy(),
            router=BackendRouter(
                (MockBackend("mock", frozenset({"process.list"})),)
            ),
            request_factory=make_process_request,
        )

        result = orchestrator.plan(alert)

        self.assertEqual(result.decision.outcome, DecisionOutcome.INVESTIGATE)
        self.assertEqual(result.incident, Incident(alert, result.decision))
        self.assertEqual(result.investigation_request.incident, result.incident)
        self.assertEqual(
            result.investigation_request.desired_outcome,
            "collect process inventory",
        )
        self.assertEqual(
            result.investigation_request.required_capabilities,
            ("process.list",),
        )
        self.assertEqual(result.investigation_request.targets, alert.entities)
        self.assertEqual(result.backend.name, "mock")

    def test_repeated_processing_is_equal(self) -> None:
        alert = make_alert(Severity.HIGH)
        orchestrator = AlertOrchestrator(
            policy=BaselineSeverityPolicy(),
            router=BackendRouter(
                (MockBackend("mock", frozenset({"process.list"})),)
            ),
            request_factory=make_process_request,
        )

        self.assertEqual(orchestrator.plan(alert), orchestrator.plan(alert))

    def test_unsupported_capabilities_propagate(self) -> None:
        orchestrator = AlertOrchestrator(
            policy=BaselineSeverityPolicy(),
            router=BackendRouter((MockBackend("mock", frozenset()),)),
            request_factory=make_process_request,
        )

        with self.assertRaises(UnsupportedCapabilitiesError):
            orchestrator.plan(make_alert(Severity.HIGH))

    def test_ambiguous_backends_propagate(self) -> None:
        orchestrator = AlertOrchestrator(
            policy=BaselineSeverityPolicy(),
            router=BackendRouter(
                (
                    MockBackend("mock-a", frozenset({"process.list"})),
                    MockBackend("mock-b", frozenset({"process.list"})),
                )
            ),
            request_factory=make_process_request,
        )

        with self.assertRaises(AmbiguousBackendError):
            orchestrator.plan(make_alert(Severity.HIGH))

    def test_mismatched_factory_request_fails_before_routing(self) -> None:
        other_alert = CanonicalAlert(
            detection=DetectionIdentity("rule-99", "Other synthetic activity"),
            detected_at=datetime(2026, 8, 11, 10, 0, tzinfo=timezone.utc),
            source=SourceProvenance("synthetic", "alert-9002"),
            entities=(Entity("host", "workstation-8"),),
            severity=Severity.HIGH,
            evidence=(),
        )
        other_decision = BaselineSeverityPolicy().decide(other_alert)
        other_incident = Incident(other_alert, other_decision)

        def make_mismatched_request(incident: Incident) -> InvestigationRequest:
            return InvestigationRequest(
                incident=other_incident,
                desired_outcome="collect process inventory",
                required_capabilities=("process.list",),
                targets=other_incident.alert.entities,
            )

        orchestrator = AlertOrchestrator(
            policy=BaselineSeverityPolicy(),
            router=BackendRouter(backends=()),
            request_factory=make_mismatched_request,
        )

        with self.assertRaisesRegex(
            ValueError,
            "investigation request incident must match incident",
        ):
            orchestrator.plan(make_alert(Severity.HIGH))

    def test_unrecognized_decision_outcome_fails_explicitly(self) -> None:
        class FuturePolicy:
            def decide(self, alert: CanonicalAlert) -> Decision:
                return Decision(
                    outcome=cast(DecisionOutcome, "future"),
                    policy_id="future-policy",
                    reasons=("future outcome",),
                    source=alert.source,
                )

        orchestrator = AlertOrchestrator(
            policy=FuturePolicy(),
            router=BackendRouter(()),
            request_factory=make_process_request,
        )

        with self.assertRaisesRegex(ValueError, "unsupported decision outcome"):
            orchestrator.plan(make_alert(Severity.HIGH))


class OrchestrationResultInvariantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.alert = make_alert(Severity.HIGH)
        self.decision = BaselineSeverityPolicy().decide(self.alert)
        self.incident = Incident(self.alert, self.decision)
        self.request = make_process_request(self.incident)
        self.backend_result = InvestigationResult(
            backend="mock",
            completed_capabilities=("process.list",),
            evidence=(EvidenceReference("mock:process.list", "mock-result"),),
        )

    def test_no_action_rejects_each_investigation_value(self) -> None:
        alert = make_alert(Severity.LOW)
        decision = BaselineSeverityPolicy().decide(alert)
        values = (
            (self.incident, None, None),
            (None, self.request, None),
            (None, None, self.backend_result),
        )

        for incident, request, result in values:
            with self.subTest(values=(incident, request, result)), self.assertRaises(
                ValueError
            ):
                OrchestrationResult(decision, incident, request, result)

    def test_investigate_rejects_missing_incident(self) -> None:
        with self.assertRaisesRegex(ValueError, "complete result graph"):
            OrchestrationResult(
                self.decision,
                None,
                self.request,
                self.backend_result,
            )

    def test_investigate_rejects_mismatched_incident_decision(self) -> None:
        other_decision = Decision(
            outcome=DecisionOutcome.INVESTIGATE,
            policy_id="other-policy",
            reasons=("other reason",),
            source=self.alert.source,
        )
        other_incident = Incident(self.alert, other_decision)
        other_request = make_process_request(other_incident)

        with self.assertRaisesRegex(ValueError, "decision must match"):
            OrchestrationResult(
                self.decision,
                other_incident,
                other_request,
                self.backend_result,
            )

    def test_investigate_rejects_mismatched_request_incident(self) -> None:
        other_alert = CanonicalAlert(
            detection=DetectionIdentity("rule-99"),
            detected_at=self.alert.detected_at,
            source=self.alert.source,
            entities=self.alert.entities,
            severity=Severity.CRITICAL,
            evidence=(),
        )
        other_decision = BaselineSeverityPolicy().decide(other_alert)
        other_incident = Incident(other_alert, other_decision)
        other_request = make_process_request(other_incident)

        with self.assertRaisesRegex(ValueError, "request incident must match"):
            OrchestrationResult(
                self.decision,
                self.incident,
                other_request,
                self.backend_result,
            )


if __name__ == "__main__":
    unittest.main()
