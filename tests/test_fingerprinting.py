from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import unittest

from alert2ir.application.fingerprinting import (
    FINGERPRINT_SCHEMA,
    FINGERPRINT_VERSION,
    canonical_fingerprint_bytes,
    canonical_fingerprint_document,
    fingerprint_canonical_alert,
)
from alert2ir.api.schemas import CanonicalAlertRequest


def payload() -> dict[str, object]:
    return {
        "detection": {"identifier": "Rule-42", "name": "Suspicious Activity"},
        "detected_at": "2026-08-17T12:34:56.123456+00:00",
        "source": {"source": "Synthetic", "source_alert_id": "Alert-9"},
        "entities": [
            {"kind": "host", "value": "Workstation-7"},
            {"kind": "user", "value": "Alice"},
            {"kind": "user", "value": "Alice"},
        ],
        "severity": "high",
        "evidence": [
            {"reference": "Record-1", "kind": "event"},
            {"reference": "Record-1", "kind": None},
        ],
    }


def alert(value: dict[str, object] | None = None):
    return CanonicalAlertRequest.model_validate(value or payload()).to_domain()


class CanonicalFingerprintTests(unittest.TestCase):
    def digest(self, value: dict[str, object] | None = None) -> bytes:
        version, digest = fingerprint_canonical_alert(alert(value))
        self.assertEqual(version, FINGERPRINT_VERSION)
        self.assertEqual(len(digest), 32)
        return digest

    def test_exact_semantic_replay_is_stable(self) -> None:
        self.assertEqual(self.digest(), self.digest(deepcopy(payload())))

    def test_input_json_member_order_and_whitespace_do_not_matter(self) -> None:
        original = payload()
        reordered = json.loads(json.dumps(original, indent=8, sort_keys=True))
        self.assertEqual(self.digest(original), self.digest(reordered))

    def test_equivalent_timezone_instants_normalize_identically(self) -> None:
        shifted = deepcopy(payload())
        shifted["detected_at"] = "2026-08-17T08:34:56.123456-04:00"
        self.assertEqual(self.digest(), self.digest(shifted))

    def test_timestamp_is_utc_with_fixed_six_digit_fraction(self) -> None:
        value = deepcopy(payload())
        value["detected_at"] = "2026-08-17T14:34:56+02:00"
        document = canonical_fingerprint_document(alert(value))
        self.assertEqual(document["detected_at"], "2026-08-17T12:34:56.000000Z")

    def test_schema_and_optional_nulls_are_explicit(self) -> None:
        value = deepcopy(payload())
        value["detection"]["name"] = None
        value["source"]["source_alert_id"] = None
        document = canonical_fingerprint_document(alert(value))
        self.assertEqual(document["schema"], FINGERPRINT_SCHEMA)
        self.assertIsNone(document["detection"]["name"])
        self.assertIsNone(document["source"]["source_alert_id"])
        self.assertIsNone(document["evidence"][1]["kind"])
        self.assertIn(b'"name":null', canonical_fingerprint_bytes(alert(value)))

    def test_entity_order_evidence_order_and_duplicates_are_semantic(self) -> None:
        for field in ("entities", "evidence"):
            with self.subTest(field=field):
                changed = deepcopy(payload())
                changed[field] = list(reversed(changed[field]))
                self.assertNotEqual(self.digest(), self.digest(changed))
        without_duplicate = deepcopy(payload())
        without_duplicate["entities"] = without_duplicate["entities"][:-1]
        self.assertNotEqual(self.digest(), self.digest(without_duplicate))

        duplicated_evidence = deepcopy(payload())
        duplicated_evidence["evidence"].append(
            deepcopy(duplicated_evidence["evidence"][0])
        )
        self.assertNotEqual(self.digest(), self.digest(duplicated_evidence))

    def test_case_is_preserved(self) -> None:
        changed = deepcopy(payload())
        changed["source"]["source"] = "synthetic"
        self.assertNotEqual(self.digest(), self.digest(changed))

    def test_validated_strings_are_not_trimmed_or_unicode_normalized(self) -> None:
        leading_space = deepcopy(payload())
        leading_space["detection"]["name"] = " Suspicious Activity"
        self.assertNotEqual(self.digest(), self.digest(leading_space))

        composed = deepcopy(payload())
        decomposed = deepcopy(payload())
        composed["detection"]["name"] = "Caf\N{LATIN SMALL LETTER E WITH ACUTE}"
        decomposed["detection"]["name"] = "Cafe\N{COMBINING ACUTE ACCENT}"
        self.assertNotEqual(self.digest(composed), self.digest(decomposed))

    def test_each_semantic_field_change_changes_digest(self) -> None:
        mutations = {
            "severity": lambda value: value.__setitem__("severity", "critical"),
            "detection name": lambda value: value["detection"].__setitem__(
                "name", "Other"
            ),
            "source alert ID": lambda value: value["source"].__setitem__(
                "source_alert_id", "Alert-10"
            ),
            "entity": lambda value: value["entities"][0].__setitem__(
                "value", "Workstation-8"
            ),
            "evidence": lambda value: value["evidence"][0].__setitem__(
                "reference", "Record-2"
            ),
        }
        baseline = self.digest()
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                changed = deepcopy(payload())
                mutation(changed)
                self.assertNotEqual(baseline, self.digest(changed))

    def test_canonical_domain_timezone_values_are_equivalent(self) -> None:
        first = alert()
        second = type(first)(
            detection=first.detection,
            detected_at=first.detected_at.astimezone(
                timezone(timedelta(hours=5, minutes=30))
            ),
            source=first.source,
            entities=first.entities,
            severity=first.severity,
            evidence=first.evidence,
        )
        self.assertEqual(
            fingerprint_canonical_alert(first),
            fingerprint_canonical_alert(second),
        )


if __name__ == "__main__":
    unittest.main()
