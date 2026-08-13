"""Repository contracts for sanitized WS08 detection-validation evidence.

These standard-library tests inspect durable repository evidence only. They do
not require Sigma packages, contact Splunk, or execute detections.
"""

from datetime import datetime, timezone
from decimal import Decimal
from hashlib import sha1, sha256
import json
from pathlib import Path
import re
import subprocess
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIRECTORY = REPOSITORY_ROOT / "validation" / "detection"
WS07_DIRECTORY = REPOSITORY_ROOT / "validation" / "attack-simulation"
PIPELINE_PATH = "config/sigma/pipelines/alert2ir-splunk-xml-sysmon.yml"
PIPELINE_SHA256 = (
    "49b5511d9418c44844f0f4cbf5ce3802f1e9982b76ec932b771d0c8da2f68ac3"
)
CANONICAL_COMMIT = "19ad59060ccca96fc3205f39f26831da67fd8ba3"
VALIDATION_REPOSITORY_HEAD = "9312f681919a3d05f05e85cb52d8981e61a80584"
SCHEMA = "alert2ir-detection-validation-v1"
SOURCE = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
SOURCETYPE = "XmlWinEventLog"
PROJECTION = (
    "| table _time RecordID EventID EventCode host source sourcetype "
    "Computer Image ParentImage CommandLine"
)

TOP_LEVEL_FIELDS = set(
    "schema rule translation execution ground_truth matches".split()
)
RULE_FIELDS = {"id", "path", "sha256", "git_blob", "canonical_commit"}
TRANSLATION_FIELDS = set(
    "sigma_specification sigma_cli_version pysigma_version "
    "splunk_backend_package splunk_backend_version backend format "
    "pipeline_path pipeline_sha256 generated_spl generated_spl_sha256".split()
)
EXECUTION_FIELDS = set(
    "validation_repository_head splunk_version splunk_build "
    "sysmon_addon_version index source sourcetype host validation_window "
    "executed_spl executed_spl_sha256 result_count".split()
)
VALIDATION_WINDOW_FIELDS = set(
    "earliest_epoch latest_epoch start_utc end_utc".split()
)
GROUND_TRUTH_FIELDS = set(
    "ws07_run_id expected_event_code expected_record_id "
    "expected_time_created splunk_time splunk_minus_ws07_seconds "
    "expected_present validation_status".split()
)
MATCH_REQUIRED_FIELDS = set(
    "record_id time host event_code image parent_image command_line_summary "
    "relationship".split()
)
MATCH_OPTIONAL_FIELDS = {"computer", "matched_switch"}

TOOLCHAIN = {
    "sigma_specification": "2.1.0",
    "sigma_cli_version": "3.1.0",
    "pysigma_version": "1.5.0",
    "splunk_backend_package": "pysigma-backend-splunk",
    "splunk_backend_version": "2.1.0",
    "backend": "splunk",
    "format": "default",
}
EXECUTION_PLATFORM = {
    "splunk_version": "10.4.1",
    "splunk_build": "5a009d941268",
    "sysmon_addon_version": "5.0.1",
    "index": "main",
    "source": SOURCE,
    "sourcetype": SOURCETYPE,
    "host": "win11-02",
}
WS07_RUN_IDS = {
    "45e78645-170d-4f2c-b158-32fdc89bec8d",
    "2c752432-9aa7-4a4d-bdb5-4ffacd2698b7",
    "34b43f09-1023-4c5c-8609-03c410bb28a3",
}

# Only facts specific to the approved WS08 validation slice live here.
CASES = {
    "t1057-process-discovery-tasklist.json": {
        "rule_path": "detections/sigma/windows/process-discovery-tasklist.yml",
        "status": "pass",
        "result_count": 1,
        "primary_record_id": 1300570,
        "generated_hash": "613fcae58d409dcefd3d4d22a68ba8d057720b8d617c47be43348e00a6612892",
        "executed_hash": "a0ff9de03e3d8a4a6e490af7cd9486e416ceaeaf94e2bedb950a7a783f97d5dc",
        "generated_terms": ('Image="*\\\\tasklist.exe"',),
    },
    "t1059-001-powershell-encoded-command.json": {
        "rule_path": "detections/sigma/windows/powershell-encoded-command.yml",
        "status": "pass",
        "result_count": 1,
        "primary_record_id": 1300904,
        "matched_switch": "-e",
        "generated_hash": "03131a7c10c552507e64c4c2c81e228d6a303f8e03df22f86799b63546676725",
        "executed_hash": "8770d070a4321e2f542d575809ce190365d7e9a0dd55ea854cccf93fd59c47b6",
        "generated_terms": (
            'Image="*\\\\powershell.exe"',
            'CommandLine IN ("*-e *", "*-enc *", "*-encodedcommand*")',
        ),
    },
    "t1059-003-cmd-temp-file-write-display.json": {
        "rule_path": "detections/sigma/windows/cmd-temp-file-write-display.yml",
        "status": "pass_with_additional_matches",
        "result_count": 2,
        "primary_record_id": 1301448,
        "additional_record_id": 1301440,
        "generated_hash": "dbb2bf19acd7f859d93144030fb975e5269b57cc75861bcbd06467cd49aaada2",
        "executed_hash": "8f22ebd2ceedb8196be80d920b650544875308b40255402be6054c4947c52485",
        "generated_terms": (
            'Image="*\\\\cmd.exe"',
            'CommandLine="*echo*"',
            'CommandLine="*type*"',
            'CommandLine="*\\\\Windows\\\\Temp\\\\*"',
        ),
    },
}


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as source_file:
        return json.load(source_file, parse_float=Decimal)


def sha256_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def git_blob_id(value: bytes) -> str:
    header = f"blob {len(value)}\0".encode("ascii")
    return sha1(header + value).hexdigest()


def timestamp_as_epoch_decimal(value: str) -> Decimal:
    whole, fractional = value.removesuffix("Z").split(".", maxsplit=1)
    base = datetime.fromisoformat(whole).replace(tzinfo=timezone.utc)
    return Decimal(int(base.timestamp())) + Decimal(f"0.{fractional}")


def committed_bytes(path: str) -> bytes:
    return subprocess.run(
        ["git", "show", f"{CANONICAL_COMMIT}:{path}"],
        cwd=REPOSITORY_ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout


def sysmon_process_event(ws07_record: dict) -> dict:
    events = [
        event
        for event in ws07_record["telemetry_observations"]
        if event["state"] == "observed"
        and event["channel"] == "Microsoft-Windows-Sysmon/Operational"
        and event["event_id"] == 1
    ]
    if len(events) != 1:
        raise AssertionError("WS07 record must have one observed Sysmon event 1")
    return events[0]


def nested_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, nested in value.items():
            yield key
            yield from nested_strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from nested_strings(nested)


class DetectionValidationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.paths = sorted(EVIDENCE_DIRECTORY.glob("*.json"))
        cls.texts = {
            path.name: path.read_text(encoding="utf-8") for path in cls.paths
        }
        cls.records = {path.name: load_json(path) for path in cls.paths}
        cls.ws07_records = {
            run_id: load_json(WS07_DIRECTORY / f"{run_id}.json")
            for run_id in WS07_RUN_IDS
        }

        powershell = cls.ws07_records[
            "2c752432-9aa7-4a4d-bdb5-4ffacd2698b7"
        ]
        file_write = cls.ws07_records[
            "34b43f09-1023-4c5c-8609-03c410bb28a3"
        ]
        cls.powershell_payload = powershell["execution"]["inputs"][
            "obfuscated_code"
        ]
        cls.file_target = file_write["execution"]["inputs"][
            "file_contents_path"
        ]
        cls.file_message = file_write["execution"]["inputs"]["message"]

    def test_exact_evidence_set(self) -> None:
        self.assertEqual(set(self.records), set(CASES))
        self.assertEqual(len(self.records), 3)

    def test_json_schema_and_objects_are_closed(self) -> None:
        for filename, record in self.records.items():
            with self.subTest(filename=filename):
                self.assertEqual(set(record), TOP_LEVEL_FIELDS)
                self.assertEqual(record["schema"], SCHEMA)
                self.assertEqual(set(record["rule"]), RULE_FIELDS)
                self.assertEqual(set(record["translation"]), TRANSLATION_FIELDS)
                self.assertEqual(set(record["execution"]), EXECUTION_FIELDS)
                self.assertEqual(
                    set(record["execution"]["validation_window"]),
                    VALIDATION_WINDOW_FIELDS,
                )
                self.assertEqual(set(record["ground_truth"]), GROUND_TRUTH_FIELDS)
                self.assertIsInstance(record["matches"], list)
                for match in record["matches"]:
                    self.assertTrue(MATCH_REQUIRED_FIELDS.issubset(match))
                    self.assertFalse(
                        set(match) - MATCH_REQUIRED_FIELDS - MATCH_OPTIONAL_FIELDS
                    )

    def test_rule_content_and_chronology_are_canonical(self) -> None:
        for filename, case in CASES.items():
            with self.subTest(filename=filename):
                record = self.records[filename]
                rule = record["rule"]
                self.assertEqual(rule["path"], case["rule_path"])

                rule_bytes = (REPOSITORY_ROOT / rule["path"]).read_bytes()
                self.assertEqual(rule_bytes, committed_bytes(rule["path"]))
                self.assertEqual(rule["sha256"], sha256_bytes(rule_bytes))
                self.assertEqual(rule["git_blob"], git_blob_id(rule_bytes))

                yaml_id = re.search(rb"(?m)^id: ([0-9a-f-]+)\r?$", rule_bytes)
                self.assertIsNotNone(yaml_id)
                self.assertEqual(rule["id"], yaml_id.group(1).decode("ascii"))
                self.assertEqual(rule["canonical_commit"], CANONICAL_COMMIT)
                validation_head = record["execution"][
                    "validation_repository_head"
                ]
                self.assertEqual(validation_head, VALIDATION_REPOSITORY_HEAD)
                self.assertNotEqual(rule["canonical_commit"], validation_head)

    def test_pipeline_and_translation_toolchain_identity(self) -> None:
        pipeline_bytes = (REPOSITORY_ROOT / PIPELINE_PATH).read_bytes()
        self.assertEqual(sha256_bytes(pipeline_bytes), PIPELINE_SHA256)
        for filename, record in self.records.items():
            with self.subTest(filename=filename):
                translation = record["translation"]
                self.assertEqual(
                    {key: translation[key] for key in TOOLCHAIN}, TOOLCHAIN
                )
                self.assertEqual(translation["pipeline_path"], PIPELINE_PATH)
                self.assertEqual(translation["pipeline_sha256"], PIPELINE_SHA256)

    def test_execution_platform_and_one_second_windows(self) -> None:
        for filename, record in self.records.items():
            with self.subTest(filename=filename):
                execution = record["execution"]
                self.assertEqual(
                    {key: execution[key] for key in EXECUTION_PLATFORM},
                    EXECUTION_PLATFORM,
                )
                window = execution["validation_window"]
                self.assertEqual(
                    window["latest_epoch"] - window["earliest_epoch"], 1
                )
                self.assertEqual(
                    datetime.fromtimestamp(
                        window["earliest_epoch"], timezone.utc
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    window["start_utc"],
                )
                self.assertEqual(
                    datetime.fromtimestamp(
                        window["latest_epoch"], timezone.utc
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    window["end_utc"],
                )

    def test_generated_and_executed_spl_are_bounded_and_approved(self) -> None:
        common_generated_terms = (
            f'source="{SOURCE}"',
            f'sourcetype="{SOURCETYPE}"',
            "EventCode=1",
        )
        for filename, case in CASES.items():
            with self.subTest(filename=filename):
                record = self.records[filename]
                translation = record["translation"]
                execution = record["execution"]
                generated = translation["generated_spl"]
                window = execution["validation_window"]

                self.assertTrue(generated.endswith("\n"))
                self.assertFalse(generated.endswith("\n\n"))
                self.assertEqual(sha256_text(generated), case["generated_hash"])
                self.assertEqual(
                    translation["generated_spl_sha256"], case["generated_hash"]
                )
                for term in common_generated_terms + case["generated_terms"]:
                    self.assertIn(term, generated)
                self.assertNotIn("index=main", generated)
                self.assertNotIn("host=win11-02", generated)
                self.assertNotRegex(generated, r"\bRecordID\s*=")

                expected_executed = (
                    f"index=main earliest={window['earliest_epoch']} "
                    f"latest={window['latest_epoch']} "
                    f"{generated.removesuffix(chr(10))} {PROJECTION}"
                )
                executed = execution["executed_spl"]
                self.assertEqual(executed, expected_executed)
                self.assertEqual(sha256_text(executed), case["executed_hash"])
                self.assertEqual(
                    execution["executed_spl_sha256"], case["executed_hash"]
                )
                self.assertNotRegex(executed, r"\bRecordID\s*=")
                for run_id in WS07_RUN_IDS:
                    self.assertNotIn(run_id, executed)

    def test_ground_truth_is_derived_from_ws07_and_timing_is_exact(self) -> None:
        evidence_run_ids = {
            record["ground_truth"]["ws07_run_id"]
            for record in self.records.values()
        }
        self.assertEqual(evidence_run_ids, WS07_RUN_IDS)

        for filename, record in self.records.items():
            with self.subTest(filename=filename):
                ground_truth = record["ground_truth"]
                run_id = ground_truth["ws07_run_id"]
                ws07_record = self.ws07_records[run_id]
                self.assertEqual(ws07_record["run_id"], run_id)

                rule_bytes = (REPOSITORY_ROOT / record["rule"]["path"]).read_bytes()
                technique = re.search(
                    rb"(?m)^  - attack\.(t[0-9.]+)\r?$", rule_bytes
                )
                self.assertIsNotNone(technique)
                self.assertEqual(
                    technique.group(1).decode("ascii").upper(),
                    ws07_record["source_provenance"]["technique_id"],
                )

                ws07_event = sysmon_process_event(ws07_record)
                self.assertEqual(
                    ground_truth["expected_event_code"], ws07_event["event_id"]
                )
                self.assertEqual(
                    ground_truth["expected_record_id"], ws07_event["record_id"]
                )
                self.assertEqual(
                    ground_truth["expected_time_created"],
                    ws07_event["timestamp_utc"],
                )
                difference = (
                    timestamp_as_epoch_decimal(ground_truth["splunk_time"])
                    - timestamp_as_epoch_decimal(
                        ground_truth["expected_time_created"]
                    )
                )
                self.assertEqual(
                    ground_truth["splunk_minus_ws07_seconds"], difference
                )

                event_epoch = timestamp_as_epoch_decimal(
                    ground_truth["expected_time_created"]
                )
                window = record["execution"]["validation_window"]
                self.assertGreaterEqual(event_epoch, window["earliest_epoch"])
                self.assertLess(event_epoch, window["latest_epoch"])

    def test_result_and_match_summary_contracts(self) -> None:
        for filename, case in CASES.items():
            with self.subTest(filename=filename):
                record = self.records[filename]
                ground_truth = record["ground_truth"]
                self.assertIs(ground_truth["expected_present"], True)
                self.assertEqual(ground_truth["validation_status"], case["status"])
                self.assertEqual(
                    record["execution"]["result_count"], case["result_count"]
                )
                self.assertEqual(len(record["matches"]), case["result_count"])

                matches = {
                    match["record_id"]: match for match in record["matches"]
                }
                self.assertEqual(len(matches), len(record["matches"]))
                expected_ids = {case["primary_record_id"]}
                if "additional_record_id" in case:
                    expected_ids.add(case["additional_record_id"])
                self.assertEqual(set(matches), expected_ids)
                for match in matches.values():
                    self.assertEqual(match["host"], EXECUTION_PLATFORM["host"])
                    self.assertEqual(match["event_code"], 1)
                    self.assertTrue(match["command_line_summary"].strip())

                primary = matches[case["primary_record_id"]]
                self.assertEqual(primary["relationship"], "expected_primary")
                self.assertEqual(
                    primary["record_id"], ground_truth["expected_record_id"]
                )
                self.assertEqual(
                    primary["event_code"], ground_truth["expected_event_code"]
                )
                self.assertEqual(primary["time"], ground_truth["splunk_time"])

                if filename.startswith("t1059-001"):
                    self.assertEqual(
                        primary["matched_switch"], case["matched_switch"]
                    )
                    self.assertIn(
                        "<Base64 payload redacted>",
                        primary["command_line_summary"],
                    )
                    self.assertNotIn(
                        self.powershell_payload, primary["command_line_summary"]
                    )
                if "additional_record_id" in case:
                    wrapper = matches[case["additional_record_id"]]
                    self.assertEqual(wrapper["relationship"], "related_wrapper")
                    self.assertNotIn(1301449, matches)
                    self.assertNotIn(1301589, matches)

    def test_evidence_is_sanitized_against_ws07_values(self) -> None:
        sensitive_values = {
            "Authorization:",
            "Bearer",
            "ALERT2IR_SPLUNK_TOKEN",
            self.powershell_payload,
            self.file_target,
            self.file_message,
            "<Event xmlns=",
        }
        for filename, text in self.texts.items():
            lowered = text.lower()
            decoded = "\n".join(nested_strings(self.records[filename])).lower()
            with self.subTest(filename=filename, value="_raw"):
                self.assertNotRegex(lowered, r'"_raw"\s*:')
            for sensitive in sensitive_values:
                with self.subTest(filename=filename, value=sensitive):
                    self.assertNotIn(sensitive.lower(), decoded)


if __name__ == "__main__":
    unittest.main()
