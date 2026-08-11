from dataclasses import dataclass, fields
from datetime import datetime
import unittest

from alert2ir.adapters import SourceAdapter
from alert2ir.core import (
    CanonicalAlert,
    DetectionIdentity,
    Entity,
    EvidenceReference,
    Severity,
    SourceProvenance,
)


@dataclass(frozen=True, slots=True)
class SyntheticPayload:
    rule_key: str
    rule_title: str
    fired_at: str
    priority: int
    objects: tuple[tuple[str, str], ...]
    artifacts: tuple[str, ...]
    source_record_key: str
    source_only_debug_field: str


class SyntheticAdapter:
    _severity_by_priority = {
        1: Severity.LOW,
        2: Severity.MEDIUM,
        3: Severity.HIGH,
        4: Severity.CRITICAL,
    }

    def normalize(self, payload: SyntheticPayload) -> CanonicalAlert:
        return CanonicalAlert(
            detection=DetectionIdentity(
                identifier=payload.rule_key,
                name=payload.rule_title,
            ),
            detected_at=datetime.fromisoformat(payload.fired_at),
            source=SourceProvenance(
                source="synthetic",
                source_alert_id=payload.source_record_key,
            ),
            entities=tuple(Entity(kind=kind, value=value) for kind, value in payload.objects),
            severity=self._severity_by_priority[payload.priority],
            evidence=tuple(
                EvidenceReference(reference=artifact, kind="synthetic-artifact")
                for artifact in payload.artifacts
            ),
        )


class NormalizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = SyntheticPayload(
            rule_key="rule-42",
            rule_title="Synthetic suspicious activity",
            fired_at="2026-08-11T09:30:00+00:00",
            priority=3,
            objects=(("host", "workstation-7"), ("user", "analyst")),
            artifacts=("record-100", "record-101"),
            source_record_key="alert-9001",
            source_only_debug_field="must not cross the boundary",
        )
        self.adapter: SourceAdapter[SyntheticPayload] = SyntheticAdapter()

    def test_complete_payload_maps_to_expected_canonical_alert(self) -> None:
        expected = CanonicalAlert(
            detection=DetectionIdentity(
                identifier="rule-42",
                name="Synthetic suspicious activity",
            ),
            detected_at=datetime.fromisoformat("2026-08-11T09:30:00+00:00"),
            source=SourceProvenance(
                source="synthetic",
                source_alert_id="alert-9001",
            ),
            entities=(
                Entity(kind="host", value="workstation-7"),
                Entity(kind="user", value="analyst"),
            ),
            severity=Severity.HIGH,
            evidence=(
                EvidenceReference(reference="record-100", kind="synthetic-artifact"),
                EvidenceReference(reference="record-101", kind="synthetic-artifact"),
            ),
        )

        self.assertEqual(self.adapter.normalize(self.payload), expected)

    def test_source_specific_fields_and_debug_value_do_not_leak(self) -> None:
        alert = self.adapter.normalize(self.payload)
        canonical_field_names = {field.name for field in fields(alert)}

        self.assertTrue(
            {
                "rule_key",
                "priority",
                "objects",
                "artifacts",
                "source_only_debug_field",
            }.isdisjoint(canonical_field_names)
        )
        self.assertFalse(hasattr(alert, "metadata"))
        self.assertFalse(hasattr(alert, "vendor_extensions"))
        self.assertFalse(hasattr(alert, "source_only_debug_field"))

    def test_each_synthetic_priority_maps_to_normalized_severity(self) -> None:
        expected = {
            1: Severity.LOW,
            2: Severity.MEDIUM,
            3: Severity.HIGH,
            4: Severity.CRITICAL,
        }

        for priority, severity in expected.items():
            with self.subTest(priority=priority):
                payload = SyntheticPayload(
                    rule_key=self.payload.rule_key,
                    rule_title=self.payload.rule_title,
                    fired_at=self.payload.fired_at,
                    priority=priority,
                    objects=self.payload.objects,
                    artifacts=self.payload.artifacts,
                    source_record_key=self.payload.source_record_key,
                    source_only_debug_field=self.payload.source_only_debug_field,
                )
                self.assertEqual(self.adapter.normalize(payload).severity, severity)

    def test_normalization_retains_provenance_entities_and_evidence(self) -> None:
        alert = self.adapter.normalize(self.payload)

        self.assertEqual(alert.source, SourceProvenance("synthetic", "alert-9001"))
        self.assertEqual(
            alert.entities,
            (
                Entity("host", "workstation-7"),
                Entity("user", "analyst"),
            ),
        )
        self.assertEqual(
            alert.evidence,
            (
                EvidenceReference("record-100", "synthetic-artifact"),
                EvidenceReference("record-101", "synthetic-artifact"),
            ),
        )

    def test_naive_detected_at_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            CanonicalAlert(
                detection=DetectionIdentity("rule-42"),
                detected_at=datetime(2026, 8, 11, 9, 30),
                source=SourceProvenance("synthetic"),
                entities=(),
                severity=Severity.LOW,
                evidence=(),
            )

    def test_required_and_optional_strings_reject_whitespace(self) -> None:
        invalid_factories = (
            lambda: DetectionIdentity(" "),
            lambda: DetectionIdentity("rule-42", name="\t"),
            lambda: SourceProvenance(""),
            lambda: SourceProvenance("synthetic", source_alert_id="\n"),
            lambda: Entity(" ", "value"),
            lambda: Entity("host", " "),
            lambda: EvidenceReference(""),
            lambda: EvidenceReference("record-100", kind=" "),
        )

        for factory in invalid_factories:
            with self.subTest(factory=factory), self.assertRaises(ValueError):
                factory()

    def test_repeated_normalization_is_equal(self) -> None:
        self.assertEqual(
            self.adapter.normalize(self.payload),
            self.adapter.normalize(self.payload),
        )


if __name__ == "__main__":
    unittest.main()
