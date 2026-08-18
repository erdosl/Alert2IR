from copy import deepcopy
from datetime import datetime, timedelta, timezone
import inspect
import json
from pathlib import Path
import unittest

from pydantic import ValidationError

from alert2ir.adapters.splunk import (
    CHANNEL_MAX_LENGTH,
    EVIDENCE_REFERENCE_MAX_LENGTH,
    FINDING_IDENTITY_SCHEMA,
    HOSTNAME_MAX_LENGTH,
    IMAGE_MAX_LENGTH,
    PARENT_IMAGE_MAX_LENGTH,
    PROCESS_GUID_MAX_LENGTH,
    RULE_TITLE_MAX_LENGTH,
    SIGMA_LEVEL_MAPPING_SCHEMA,
    SOURCE_MAX_LENGTH,
    SOURCETYPE_MAX_LENGTH,
    SPLUNK_FINDING_SCHEMA,
    TARGET_FILENAME_MAX_LENGTH,
    SplunkFinding,
    SigmaLevel,
    canonicalize,
    finding_identity_bytes,
    finding_identity_document,
    idempotency_key,
    normalize_hostname,
    normalize_sigma_severity,
    normalize_splunk_finding,
    normalize_timestamp,
)
from alert2ir.core import (
    CanonicalAlert,
    DetectionIdentity,
    Entity,
    EvidenceReference,
    Severity,
    SourceProvenance,
)


FIXTURE_DIRECTORY = Path(__file__).parent / "fixtures" / "splunk"
EXPECTED_PROCESS_KEY = (
    "splunk-v1-"
    "6137f60f0a881510b2397bea604e3cb3c97c4846279aa0293de9643440da74a0"
)


def fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURE_DIRECTORY / name).read_text(encoding="utf-8"))


def parse(name: str = "process_creation.json") -> SplunkFinding:
    return SplunkFinding.model_validate(fixture(name))


def canonical_key(payload: dict[str, object]) -> str:
    normalized = normalize_splunk_finding(SplunkFinding.model_validate(payload))
    return idempotency_key(normalized)


class SplunkFindingModelTests(unittest.TestCase):
    def test_realistic_event_one_and_event_eleven_fixtures_are_valid(self) -> None:
        event_one = parse("process_creation.json")
        event_eleven = parse("file_creation.json")

        self.assertEqual(event_one.event.event_code, 1)
        self.assertEqual(event_one.event.record_id, 1300570)
        self.assertEqual(event_eleven.event.event_code, 11)
        self.assertEqual(event_eleven.event.record_id, 1757566)

    def test_minimal_fixture_is_valid(self) -> None:
        value = parse("minimal.json")
        self.assertEqual(value.schema_version, SPLUNK_FINDING_SCHEMA)
        self.assertIsNone(value.event.computer)
        self.assertEqual(value.event.host, "win11-02")

    def test_malformed_event_object_is_rejected(self) -> None:
        payload = fixture("minimal.json")
        payload["event"] = ["not", "an", "event"]
        with self.assertRaises(ValidationError):
            SplunkFinding.model_validate(payload)

    def test_unknown_outer_and_detection_fields_are_rejected(self) -> None:
        mutations = (
            lambda value: value.__setitem__("unexpected", True),
            lambda value: value["detection"].__setitem__("saved_search", "ignored"),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                payload = fixture("minimal.json")
                mutation(payload)
                with self.assertRaises(ValidationError):
                    SplunkFinding.model_validate(payload)

    def test_unknown_event_fields_are_deliberately_ignored(self) -> None:
        finding = parse("process_creation.json")
        event_fields = finding.event.model_dump()

        self.assertNotIn("CommandLine", event_fields)
        self.assertNotIn("User", event_fields)
        self.assertNotIn("_raw", event_fields)
        self.assertFalse(hasattr(finding.event, "session_key"))

    def test_unsupported_schema_version_is_rejected(self) -> None:
        payload = fixture("minimal.json")
        payload["schema"] = "alert2ir.splunk-finding.v2"
        with self.assertRaises(ValidationError):
            SplunkFinding.model_validate(payload)

    def test_rule_id_is_required_valid_and_canonicalized(self) -> None:
        missing = fixture("minimal.json")
        del missing["detection"]["rule_id"]
        invalid = fixture("minimal.json")
        invalid["detection"]["rule_id"] = "not-a-uuid"
        uppercase = fixture("minimal.json")
        uppercase["detection"]["rule_id"] = (
            "83F9F33F-69B6-45CA-8E70-681FEA55A255"
        )

        for payload in (missing, invalid):
            with self.subTest(payload=payload), self.assertRaises(ValidationError):
                SplunkFinding.model_validate(payload)
        self.assertEqual(
            SplunkFinding.model_validate(uppercase).detection.rule_id,
            "83f9f33f-69b6-45ca-8e70-681fea55a255",
        )

    def test_required_detection_metadata_is_enforced(self) -> None:
        for field_name in ("rule_title", "sigma_level"):
            with self.subTest(field_name=field_name):
                payload = fixture("minimal.json")
                del payload["detection"][field_name]
                with self.assertRaises(ValidationError):
                    SplunkFinding.model_validate(payload)

    def test_unsupported_sigma_level_is_rejected(self) -> None:
        payload = fixture("minimal.json")
        payload["detection"]["sigma_level"] = "severe"
        with self.assertRaises(ValidationError):
            SplunkFinding.model_validate(payload)

    def test_event_result_cannot_override_reviewed_sigma_level(self) -> None:
        payload = fixture("process_creation.json")
        payload["event"]["sigma_level"] = "critical"
        finding = SplunkFinding.model_validate(payload)
        self.assertEqual(finding.detection.sigma_level, SigmaLevel.LOW)
        self.assertEqual(canonicalize(finding).alert.severity, Severity.LOW)

    def test_required_event_values_are_enforced(self) -> None:
        for field_name in ("_time", "channel", "EventCode", "RecordID"):
            with self.subTest(field_name=field_name):
                payload = fixture("minimal.json")
                del payload["event"][field_name]
                with self.assertRaises(ValidationError):
                    SplunkFinding.model_validate(payload)

        no_host = fixture("minimal.json")
        del no_host["event"]["host"]
        with self.assertRaises(ValidationError):
            SplunkFinding.model_validate(no_host)

    def test_event_code_and_record_id_reject_malformed_values(self) -> None:
        for field_name, invalid_values in {
            "EventCode": (True, 1.5, "1.0", "event-one", 0, 65536),
            "RecordID": (False, 3.4, "12x", -1, 0, 2**63),
        }.items():
            for invalid_value in invalid_values:
                with self.subTest(field_name=field_name, invalid_value=invalid_value):
                    payload = fixture("minimal.json")
                    payload["event"][field_name] = invalid_value
                    with self.assertRaises(ValidationError):
                        SplunkFinding.model_validate(payload)

    def test_channel_rejects_ambiguous_machine_values(self) -> None:
        for value in (
            " Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-Sysmon/Operational ",
            "Microsoft-Windows-Sysmon/Operational\n",
            "München-Windows/Operational",
        ):
            with self.subTest(value=value):
                payload = fixture("minimal.json")
                payload["event"]["channel"] = value
                with self.assertRaises(ValidationError):
                    SplunkFinding.model_validate(payload)

    def test_bounded_values_reject_overlong_input(self) -> None:
        cases = (
            ("detection", "rule_title", RULE_TITLE_MAX_LENGTH),
            ("event", "host", HOSTNAME_MAX_LENGTH),
            ("event", "channel", CHANNEL_MAX_LENGTH),
            ("event", "source", SOURCE_MAX_LENGTH),
            ("event", "sourcetype", SOURCETYPE_MAX_LENGTH),
            ("event", "ProcessGuid", PROCESS_GUID_MAX_LENGTH),
            ("event", "Image", IMAGE_MAX_LENGTH),
            ("event", "ParentImage", PARENT_IMAGE_MAX_LENGTH),
            ("event", "TargetFilename", TARGET_FILENAME_MAX_LENGTH),
        )
        for section, field_name, maximum in cases:
            with self.subTest(section=section, field_name=field_name):
                payload = fixture("minimal.json")
                payload[section][field_name] = "x" * (maximum + 1)
                with self.assertRaises(ValidationError):
                    SplunkFinding.model_validate(payload)

    def test_path_bounds_accept_the_exact_maximum(self) -> None:
        for field_name, maximum in (
            ("Image", IMAGE_MAX_LENGTH),
            ("ParentImage", PARENT_IMAGE_MAX_LENGTH),
            ("TargetFilename", TARGET_FILENAME_MAX_LENGTH),
        ):
            with self.subTest(field_name=field_name):
                payload = fixture("minimal.json")
                payload["event"][field_name] = "x" * maximum
                self.assertEqual(
                    len(
                        getattr(
                            SplunkFinding.model_validate(payload).event,
                            {
                                "Image": "image",
                                "ParentImage": "parent_image",
                                "TargetFilename": "target_filename",
                            }[field_name],
                        )
                    ),
                    maximum,
                )


class SplunkNormalizationTests(unittest.TestCase):
    def test_hostname_normalization_rules(self) -> None:
        cases = {
            ("WIN11-02", None): "win11-02",
            (" win11-02. ", None): "win11-02",
            (None, " WIN11-02 "): "win11-02",
            ("WIN11-02", "win11-02."): "win11-02",
            ("WIN11-02.CORP.EXAMPLE.", None): "win11-02.corp.example",
        }
        for inputs, expected in cases.items():
            with self.subTest(inputs=inputs):
                self.assertEqual(normalize_hostname(*inputs), expected)

    def test_computer_is_preferred_and_host_is_fallback(self) -> None:
        self.assertEqual(normalize_hostname("WIN11-02", None), "win11-02")
        self.assertEqual(normalize_hostname(None, "WIN11-03"), "win11-03")

    def test_conflicting_computer_and_host_are_rejected(self) -> None:
        finding = parse("conflicting_host.json")
        with self.assertRaisesRegex(ValueError, "disagree"):
            normalize_splunk_finding(finding)

    def test_invalid_hostnames_are_rejected_without_discovery_or_rewriting(self) -> None:
        for computer, host in (
            (None, None),
            (" ", None),
            ("höst", None),
            ("bad host", None),
            ("bad/name", None),
            (".", None),
        ):
            with self.subTest(computer=computer, host=host), self.assertRaises(
                ValueError
            ):
                normalize_hostname(computer, host)

    def test_timestamp_formats_normalize_to_utc(self) -> None:
        expected = datetime(2026, 8, 12, 20, 26, 12, 705000, tzinfo=timezone.utc)
        values = (
            1786566372.705,
            "1786566372.705",
            "2026-08-12T20:26:12.705Z",
            "2026-08-12T16:26:12.705-04:00",
            datetime(
                2026,
                8,
                12,
                22,
                26,
                12,
                705000,
                tzinfo=timezone(timedelta(hours=2)),
            ),
        )
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(normalize_timestamp(value), expected)

    def test_submicrosecond_timestamp_forms_normalize_identically(self) -> None:
        expected = datetime(
            2026,
            8,
            12,
            20,
            26,
            12,
            705922,
            tzinfo=timezone.utc,
        )
        self.assertEqual(normalize_timestamp("1786566372.7059226"), expected)
        self.assertEqual(
            normalize_timestamp("2026-08-12T20:26:12.7059226Z"),
            expected,
        )

    def test_timestamp_rejects_naive_malformed_and_nonfinite_values(self) -> None:
        invalid = (
            datetime(2026, 8, 12, 20, 26, 12),
            "2026-08-12T20:26:12.705",
            "not-a-time",
            "NaN",
            float("nan"),
            float("inf"),
            float("-inf"),
            10**1000,
            True,
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_timestamp(value)

    def test_exact_sigma_severity_mapping(self) -> None:
        expected = {
            SigmaLevel.INFORMATIONAL: Severity.LOW,
            SigmaLevel.LOW: Severity.LOW,
            SigmaLevel.MEDIUM: Severity.MEDIUM,
            SigmaLevel.HIGH: Severity.HIGH,
            SigmaLevel.CRITICAL: Severity.CRITICAL,
        }
        for source, target in expected.items():
            with self.subTest(source=source):
                self.assertEqual(normalize_sigma_severity(source), target)

    def test_severity_normalization_has_no_override_input(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(normalize_sigma_severity).parameters),
            ("level",),
        )

    def test_normalized_finding_contains_canonical_event_values(self) -> None:
        normalized = normalize_splunk_finding(parse())
        self.assertEqual(normalized.rule_id, "78441abe-99b0-4e6e-bd85-d52748e59d0e")
        self.assertEqual(normalized.computer, "win11-02")
        self.assertEqual(normalized.detected_at.tzinfo, timezone.utc)
        self.assertEqual(normalized.event_code, 1)
        self.assertEqual(normalized.record_id, 1300570)


class SplunkCanonicalMappingTests(unittest.TestCase):
    def test_complete_process_fixture_maps_to_exact_canonical_alert(self) -> None:
        actual = canonicalize(parse())
        expected = CanonicalAlert(
            detection=DetectionIdentity(
                "78441abe-99b0-4e6e-bd85-d52748e59d0e",
                "Process Discovery via Tasklist",
            ),
            detected_at=datetime(
                2026, 8, 12, 20, 26, 12, 705000, tzinfo=timezone.utc
            ),
            source=SourceProvenance("splunk", EXPECTED_PROCESS_KEY),
            entities=(Entity("host", "win11-02"),),
            severity=Severity.LOW,
            evidence=(
                EvidenceReference(
                    f"{SIGMA_LEVEL_MAPPING_SCHEMA}:low->low",
                    "normalization-policy",
                ),
                EvidenceReference(
                    "windows-event://win11-02/"
                    "Microsoft-Windows-Sysmon%2FOperational/1300570?event_code=1",
                    "source-event",
                ),
                EvidenceReference(
                    "{11111111-2222-3333-4444-555555555555}",
                    "process-guid",
                ),
                EvidenceReference(
                    "C:\\Windows\\System32\\tasklist.exe",
                    "process-image",
                ),
                EvidenceReference(
                    "C:\\Windows\\System32\\cmd.exe",
                    "parent-process-image",
                ),
            ),
        )
        self.assertEqual(actual.alert, expected)
        self.assertEqual(actual.idempotency_key, EXPECTED_PROCESS_KEY)

    def test_source_and_single_host_entity_are_fixed(self) -> None:
        alert = canonicalize(parse()).alert
        self.assertEqual(alert.source.source, "splunk")
        self.assertEqual(alert.entities, (Entity("host", "win11-02"),))
        self.assertEqual(len(alert.entities), 1)

        changed = fixture("process_creation.json")
        changed["event"]["source"] = "caller-controlled-value"
        remapped = canonicalize(SplunkFinding.model_validate(changed)).alert
        self.assertEqual(remapped.source.source, "splunk")

    def test_process_values_never_become_entities(self) -> None:
        alert = canonicalize(parse()).alert
        self.assertEqual({entity.kind for entity in alert.entities}, {"host"})

    def test_optional_evidence_is_omitted_and_required_evidence_remains(self) -> None:
        alert = canonicalize(parse("minimal.json")).alert
        self.assertEqual(
            tuple(item.kind for item in alert.evidence),
            ("normalization-policy", "source-event"),
        )

    def test_event_eleven_evidence_uses_fixed_order(self) -> None:
        alert = canonicalize(parse("file_creation.json")).alert
        self.assertEqual(
            alert.evidence[0].reference,
            f"{SIGMA_LEVEL_MAPPING_SCHEMA}:informational->low",
        )
        self.assertEqual(
            tuple(item.kind for item in alert.evidence),
            (
                "normalization-policy",
                "source-event",
                "process-guid",
                "process-image",
                "target-file",
            ),
        )

    def test_all_optional_evidence_uses_one_fixed_order(self) -> None:
        payload = fixture("process_creation.json")
        payload["event"]["TargetFilename"] = "C:\\Windows\\Temp\\target.bin"
        alert = canonicalize(SplunkFinding.model_validate(payload)).alert
        self.assertEqual(
            tuple(item.kind for item in alert.evidence),
            (
                "normalization-policy",
                "source-event",
                "process-guid",
                "process-image",
                "parent-process-image",
                "target-file",
            ),
        )

    def test_evidence_is_deterministic_and_bounded(self) -> None:
        first = canonicalize(parse()).alert.evidence
        second = canonicalize(parse()).alert.evidence
        self.assertEqual(first, second)
        self.assertEqual(first[0].kind, "normalization-policy")
        self.assertEqual(first[1].kind, "source-event")
        self.assertTrue(
            all(
                len(item.reference) <= EVIDENCE_REFERENCE_MAX_LENGTH
                for item in first
            )
        )

    def test_ignored_sensitive_and_unbounded_splunk_fields_do_not_cross(self) -> None:
        result = canonicalize(parse())
        references = "\n".join(item.reference for item in result.alert.evidence)
        prohibited_markers = (
            "/FO CSV",
            "LAB\\analyst",
            "1234",
            "5678",
            "<Event>",
            "scheduler__sanitized",
            "splunk.invalid",
            "sanitized-placeholder",
        )
        for marker in prohibited_markers:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, references)

    def test_canonicalization_is_structurally_deterministic(self) -> None:
        finding = parse()
        self.assertEqual(canonicalize(finding), canonicalize(finding))


class SplunkFindingIdentityTests(unittest.TestCase):
    def test_identity_document_and_bytes_are_frozen(self) -> None:
        normalized = normalize_splunk_finding(parse())
        expected_document = {
            "schema": FINDING_IDENTITY_SCHEMA,
            "detection_id": "78441abe-99b0-4e6e-bd85-d52748e59d0e",
            "event": {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "computer": "win11-02",
                "detected_at": "2026-08-12T20:26:12.705000Z",
                "event_code": 1,
                "record_id": 1300570,
            },
        }
        expected_bytes = (
            b'{"detection_id":"78441abe-99b0-4e6e-bd85-d52748e59d0e",'
            b'"event":{"channel":"Microsoft-Windows-Sysmon/Operational",'
            b'"computer":"win11-02",'
            b'"detected_at":"2026-08-12T20:26:12.705000Z",'
            b'"event_code":1,"record_id":1300570},'
            b'"schema":"alert2ir.splunk-finding-id.v1"}'
        )
        self.assertEqual(finding_identity_document(normalized), expected_document)
        self.assertEqual(finding_identity_bytes(normalized), expected_bytes)

    def test_exact_key_shape_and_value_are_frozen(self) -> None:
        normalized = normalize_splunk_finding(parse())
        key = idempotency_key(normalized)
        self.assertEqual(key, EXPECTED_PROCESS_KEY)
        self.assertTrue(key.startswith("splunk-v1-"))
        self.assertEqual(len(key), 74)
        self.assertLessEqual(len(key), 128)
        self.assertTrue(key.isascii())
        self.assertTrue(key.isprintable())

    def test_same_logical_finding_always_has_the_same_key(self) -> None:
        payload = fixture("process_creation.json")
        self.assertEqual(canonical_key(payload), canonical_key(deepcopy(payload)))

    def test_each_identity_field_changes_the_key(self) -> None:
        mutations = {
            "rule UUID": lambda value: value["detection"].__setitem__(
                "rule_id", "83f9f33f-69b6-45ca-8e70-681fea55a255"
            ),
            "hostname": lambda value: (
                value["event"].__setitem__("Computer", "win11-03"),
                value["event"].__setitem__("host", "WIN11-03."),
            ),
            "channel": lambda value: value["event"].__setitem__(
                "channel", "Microsoft-Windows-Security-Auditing"
            ),
            "EventCode": lambda value: value["event"].__setitem__("EventCode", "11"),
            "RecordID": lambda value: value["event"].__setitem__(
                "RecordID", "1300571"
            ),
            "timestamp": lambda value: value["event"].__setitem__(
                "_time", "2026-08-12T20:26:12.706Z"
            ),
        }
        baseline = canonical_key(fixture("process_creation.json"))
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                changed = fixture("process_creation.json")
                mutation(changed)
                self.assertNotEqual(canonical_key(changed), baseline)

    def test_representation_only_fields_do_not_change_the_key(self) -> None:
        mutations = {
            "rule title": lambda value: value["detection"].__setitem__(
                "rule_title", "Reviewed Renamed Detection"
            ),
            "severity": lambda value: value["detection"].__setitem__(
                "sigma_level", "critical"
            ),
            "Image": lambda value: value["event"].__setitem__(
                "Image", "C:\\Other\\image.exe"
            ),
            "ParentImage": lambda value: value["event"].__setitem__(
                "ParentImage", "C:\\Other\\parent.exe"
            ),
            "ProcessGuid": lambda value: value["event"].__setitem__(
                "ProcessGuid", "{ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb}"
            ),
            "TargetFilename": lambda value: value["event"].__setitem__(
                "TargetFilename", "C:\\Other\\target.bin"
            ),
            "Splunk source": lambda value: value["event"].__setitem__(
                "source", "other-source"
            ),
            "Splunk sourcetype": lambda value: value["event"].__setitem__(
                "sourcetype", "other-sourcetype"
            ),
        }
        baseline = canonical_key(fixture("process_creation.json"))
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                changed = fixture("process_creation.json")
                mutation(changed)
                self.assertEqual(canonical_key(changed), baseline)

    def test_equivalent_host_and_timezone_representations_keep_the_key(self) -> None:
        changed = fixture("process_creation.json")
        changed["event"]["Computer"] = " win11-02. "
        changed["event"]["host"] = "WIN11-02"
        changed["event"]["_time"] = "2026-08-12T16:26:12.705-04:00"
        self.assertEqual(canonical_key(changed), EXPECTED_PROCESS_KEY)

    def test_json_member_order_does_not_change_the_key(self) -> None:
        payload = fixture("process_creation.json")
        reordered = {
            key: value
            for key, value in reversed(tuple(payload.items()))
        }
        reordered["detection"] = {
            key: value
            for key, value in reversed(tuple(payload["detection"].items()))
        }
        reordered["event"] = {
            key: value for key, value in reversed(tuple(payload["event"].items()))
        }
        self.assertEqual(canonical_key(reordered), EXPECTED_PROCESS_KEY)

    def test_source_alert_id_is_the_same_finding_identity(self) -> None:
        result = canonicalize(parse())
        self.assertEqual(result.alert.source.source_alert_id, result.idempotency_key)


if __name__ == "__main__":
    unittest.main()
