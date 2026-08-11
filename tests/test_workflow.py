from datetime import datetime, timezone
import unittest

from alert2ir.core import (
    BaselineSeverityPolicy,
    CanonicalAlert,
    Decision,
    DecisionOutcome,
    DetectionIdentity,
    Entity,
    Incident,
    InvestigationRequest,
    Severity,
    SourceProvenance,
)


def make_alert(
    severity: Severity,
    source: SourceProvenance | None = None,
) -> CanonicalAlert:
    return CanonicalAlert(
        detection=DetectionIdentity("rule-42", "Synthetic suspicious activity"),
        detected_at=datetime(2026, 8, 11, 9, 30, tzinfo=timezone.utc),
        source=source or SourceProvenance("synthetic", "alert-9001"),
        entities=(Entity("host", "workstation-7"),),
        severity=severity,
        evidence=(),
    )


class BaselineSeverityPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = BaselineSeverityPolicy()

    def test_severity_outcomes_are_explainable_and_retain_provenance(self) -> None:
        expected = {
            Severity.LOW: (
                DecisionOutcome.NO_ACTION,
                "normalized severity 'low' does not require investigation",
            ),
            Severity.MEDIUM: (
                DecisionOutcome.NO_ACTION,
                "normalized severity 'medium' does not require investigation",
            ),
            Severity.HIGH: (
                DecisionOutcome.INVESTIGATE,
                "normalized severity 'high' requires investigation",
            ),
            Severity.CRITICAL: (
                DecisionOutcome.INVESTIGATE,
                "normalized severity 'critical' requires investigation",
            ),
        }
        self.assertEqual(set(expected), set(Severity))

        for severity, (outcome, reason) in expected.items():
            with self.subTest(severity=severity):
                alert = make_alert(severity)
                decision = self.policy.decide(alert)

                self.assertEqual(decision.outcome, outcome)
                self.assertEqual(decision.policy_id, "baseline-severity-v1")
                self.assertEqual(decision.reasons, (reason,))
                self.assertEqual(decision.source, alert.source)

    def test_repeated_evaluation_is_equal(self) -> None:
        alert = make_alert(Severity.HIGH)

        self.assertEqual(self.policy.decide(alert), self.policy.decide(alert))


class DecisionInvariantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = SourceProvenance("synthetic", "alert-9001")

    def test_policy_id_must_be_non_empty(self) -> None:
        for policy_id in ("", " \t"):
            with self.subTest(policy_id=policy_id), self.assertRaises(ValueError):
                Decision(
                    outcome=DecisionOutcome.INVESTIGATE,
                    policy_id=policy_id,
                    reasons=("requires investigation",),
                    source=self.source,
                )

    def test_reasons_must_not_be_empty(self) -> None:
        with self.assertRaises(ValueError):
            Decision(
                outcome=DecisionOutcome.INVESTIGATE,
                policy_id="baseline-severity-v1",
                reasons=(),
                source=self.source,
            )

    def test_each_reason_must_be_non_empty(self) -> None:
        for reason in ("", " \n"):
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                Decision(
                    outcome=DecisionOutcome.INVESTIGATE,
                    policy_id="baseline-severity-v1",
                    reasons=(reason,),
                    source=self.source,
                )


class IncidentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = BaselineSeverityPolicy()

    def test_investigate_decision_forms_incident(self) -> None:
        alert = make_alert(Severity.HIGH)
        decision = self.policy.decide(alert)

        self.assertEqual(Incident(alert=alert, decision=decision), Incident(alert, decision))

    def test_no_action_decision_is_rejected(self) -> None:
        alert = make_alert(Severity.LOW)

        with self.assertRaisesRegex(ValueError, "investigate decision"):
            Incident(alert=alert, decision=self.policy.decide(alert))

    def test_mismatched_source_provenance_is_rejected(self) -> None:
        alert = make_alert(Severity.HIGH)
        decision = Decision(
            outcome=DecisionOutcome.INVESTIGATE,
            policy_id="baseline-severity-v1",
            reasons=("normalized severity 'high' requires investigation",),
            source=SourceProvenance("other-source", "other-alert"),
        )

        with self.assertRaisesRegex(ValueError, "source must match"):
            Incident(alert=alert, decision=decision)


class InvestigationRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        alert = make_alert(Severity.HIGH)
        self.incident = Incident(alert, BaselineSeverityPolicy().decide(alert))
        self.target = Entity("host", "workstation-7")

    def test_request_preserves_vendor_neutral_values(self) -> None:
        request = InvestigationRequest(
            incident=self.incident,
            desired_outcome="collect process inventory",
            required_capabilities=("process.list",),
            targets=(self.target,),
        )

        self.assertEqual(request.incident, self.incident)
        self.assertEqual(request.desired_outcome, "collect process inventory")
        self.assertEqual(request.required_capabilities, ("process.list",))
        self.assertEqual(request.targets, (self.target,))

    def test_desired_outcome_must_be_non_empty(self) -> None:
        for desired_outcome in ("", " \t"):
            with self.subTest(desired_outcome=desired_outcome), self.assertRaises(ValueError):
                InvestigationRequest(
                    incident=self.incident,
                    desired_outcome=desired_outcome,
                    required_capabilities=("process.list",),
                    targets=(),
                )

    def test_empty_targets_are_valid(self) -> None:
        request = InvestigationRequest(
            incident=self.incident,
            desired_outcome="collect process inventory",
            required_capabilities=("process.list",),
            targets=(),
        )

        self.assertEqual(request.targets, ())

    def test_required_capabilities_must_not_be_empty(self) -> None:
        with self.assertRaises(ValueError):
            InvestigationRequest(
                incident=self.incident,
                desired_outcome="collect process inventory",
                required_capabilities=(),
                targets=(),
            )

    def test_each_capability_must_be_non_empty(self) -> None:
        for capability in ("", " \n"):
            with self.subTest(capability=capability), self.assertRaises(ValueError):
                InvestigationRequest(
                    incident=self.incident,
                    desired_outcome="collect process inventory",
                    required_capabilities=(capability,),
                    targets=(),
                )


if __name__ == "__main__":
    unittest.main()
