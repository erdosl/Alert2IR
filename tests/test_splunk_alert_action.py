"""Contracts for the standalone Splunk custom alert-action sender.

The deployable script is loaded directly from the Splunk app so these tests do
not accidentally make the Splunk host depend on the Alert2IR Python package.
"""

from __future__ import annotations

from configparser import ConfigParser
from contextlib import redirect_stderr
from datetime import datetime, timezone
import gzip
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

import httpx2

from alert2ir.adapters.splunk import (
    Alert2IRDeliveryResult,
    DeliveryClassification,
    SplunkFinding,
    canonicalize,
    create_splunk_adapter_app,
    verify_signature,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPOSITORY_ROOT / "integrations" / "splunk" / "alert2ir_delivery"
SCRIPT_PATH = APP_ROOT / "bin" / "alert2ir_delivery.py"
FIXTURE_PATH = (
    REPOSITORY_ROOT
    / "tests"
    / "fixtures"
    / "splunk"
    / "investigation_validation.csv"
)
SAVED_SEARCH_PATH = APP_ROOT / "default" / "savedsearches.conf"
ALERT_ACTIONS_PATH = APP_ROOT / "default" / "alert_actions.conf"
VALIDATION_RULE_PATH = (
    REPOSITORY_ROOT
    / "detections"
    / "sigma"
    / "validation"
    / "windows"
    / "investigation-delivery-marker.yml"
)

RULE_ID = "ad3f9191-7d59-4b6f-8442-e99df9d74c1d"
RULE_TITLE = "Alert2IR Investigation Delivery Validation Marker"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"
ADAPTER_URL = "http://adapter.invalid:8091/v1/splunk/findings"
SECRET = b"0123456789abcdef0123456789abcdef"
NOW_EPOCH = 1_787_056_496
NOW = datetime.fromtimestamp(NOW_EPOCH, timezone.utc)
EXPECTED_VALIDATION_KEY = (
    "splunk-v1-"
    "66823112eaa986827dc1f36169bf9e6218dd23da0e6e1267080e5b2e92b48b93"
)
EXPECTED_FIELDS = (
    "_time",
    "Computer",
    "host",
    "source",
    "sourcetype",
    "EventCode",
    "RecordID",
    "ProcessGuid",
    "Image",
    "ParentImage",
    "TargetFilename",
)
GENERATED_VALIDATION_SPL = (
    'source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" '
    'sourcetype="XmlWinEventLog" EventCode=1 Image="*\\\\cmd.exe" '
    'CommandLine="*Alert2IR-INVESTIGATE-*"'
)


def load_sender_module():
    spec = importlib.util.spec_from_file_location(
        "alert2ir_delivery_standalone",
        SCRIPT_PATH,
    )
    if spec is None or spec.loader is None:
        raise AssertionError("unable to load standalone sender")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


sender = load_sender_module()


def fixture_row() -> dict[str, str]:
    with FIXTURE_PATH.open(encoding="utf-8", newline="") as fixture:
        import csv

        rows = list(csv.DictReader(fixture))
    if len(rows) != 1:
        raise AssertionError("validation fixture must contain exactly one row")
    return rows[0]


def configuration(secret_file: str = "/protected/alert2ir.secret") -> dict[str, str]:
    return {
        "adapter_url": ADAPTER_URL,
        "secret_file": secret_file,
        "rule_id": RULE_ID,
        "rule_title": RULE_TITLE,
        "sigma_level": "high",
        "channel": CHANNEL,
    }


def invocation(results_file: str, secret_file: str) -> dict[str, object]:
    return {
        "server_uri": "https://splunk.invalid:8089",
        "session_key": "must-never-cross-the-boundary",
        "sid": "scheduler__must-not-cross",
        "search_name": RULE_TITLE,
        "results_link": "https://splunk.invalid/results/must-not-cross",
        "results_file": results_file,
        "configuration": configuration(secret_file),
    }


def gzip_csv(path: Path, rows: list[dict[str, str]], fields=EXPECTED_FIELDS) -> None:
    import csv

    with gzip.open(path, "wt", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def response(
    status: int,
    classification: str,
    *,
    replayed: bool = False,
) -> object:
    body: dict[str, object] = {
        "classification": classification,
        "upstream_status": 200 if status in {200, 202} else status,
        "replayed": replayed,
        "retryable": classification == "transient_failure",
        "acceptance_unknown": status in {502, 504},
    }
    if classification in {"completed", "accepted", "durable_failure"}:
        body["processing_id"] = "5afaf9ce-3df8-43d3-bac8-1b875211dcc4"
    if classification == "completed":
        body.update({"state": "completed", "decision_outcome": "investigate"})
    elif classification == "accepted":
        body["state"] = "accepted"
    return sender.HttpResponse(
        status=status,
        body=json.dumps(body, separators=(",", ":")).encode("utf-8"),
        headers={},
    )


class FakeTransport:
    def __init__(self, outcomes: list[object]) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[dict[str, object]] = []

    def __call__(
        self,
        url: str,
        body: bytes,
        headers: dict[str, str],
        timeout_seconds: float,
    ) -> object:
        self.calls.append(
            {
                "url": url,
                "body": body,
                "headers": dict(headers),
                "timeout_seconds": timeout_seconds,
            }
        )
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class SplunkResultFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def test_exactly_one_gzip_csv_result_is_accepted(self) -> None:
        path = self.directory / "results.csv.gz"
        gzip_csv(path, [fixture_row()])
        self.assertEqual(sender.read_single_result(path), fixture_row())

    def test_splunk_multivalue_companion_columns_are_dropped(self) -> None:
        path = self.directory / "results.csv.gz"
        fields = (*EXPECTED_FIELDS, *("__mv_" + field for field in EXPECTED_FIELDS))
        gzip_csv(path, [fixture_row()], fields=fields)

        self.assertEqual(sender.read_single_result(path), fixture_row())

    def test_missing_results_file_is_rejected(self) -> None:
        with self.assertRaisesRegex(sender.ActionInputError, "results file"):
            sender.read_single_result(self.directory / "missing.csv.gz")

    def test_zero_and_multiple_result_rows_are_rejected(self) -> None:
        for name, rows in (
            ("zero", []),
            ("multiple", [fixture_row(), fixture_row()]),
        ):
            with self.subTest(name=name):
                path = self.directory / f"{name}.csv.gz"
                gzip_csv(path, rows)
                with self.assertRaisesRegex(sender.ActionInputError, "exactly one"):
                    sender.read_single_result(path)

    def test_malformed_csv_is_rejected(self) -> None:
        path = self.directory / "malformed.csv.gz"
        with gzip.open(path, "wb") as target:
            target.write(b'_time,Computer\n"unterminated')
        with self.assertRaises(sender.ActionInputError):
            sender.read_single_result(path)

    def test_missing_or_unknown_projected_column_is_rejected(self) -> None:
        row = fixture_row()
        for fields in (
            tuple(field for field in EXPECTED_FIELDS if field != "RecordID"),
            (*EXPECTED_FIELDS, "_raw"),
        ):
            with self.subTest(fields=fields):
                path = self.directory / f"fields-{len(fields)}.csv.gz"
                gzip_csv(path, [row], fields=fields)
                with self.assertRaisesRegex(sender.ActionInputError, "projected fields"):
                    sender.read_single_result(path)

    def test_compressed_and_decompressed_limits_are_enforced(self) -> None:
        compressed = self.directory / "compressed.csv.gz"
        compressed.write_bytes(b"x" * (sender.MAX_COMPRESSED_RESULTS_BYTES + 1))
        with self.assertRaisesRegex(sender.ActionInputError, "too large"):
            sender.read_single_result(compressed)

        expanded = self.directory / "expanded.csv.gz"
        with gzip.open(expanded, "wb") as target:
            target.write(b"x" * (sender.MAX_DECOMPRESSED_RESULTS_BYTES + 1))
        with self.assertRaisesRegex(sender.ActionInputError, "too large"):
            sender.read_single_result(expanded)


class SplunkActionInputTests(unittest.TestCase):
    def test_json_invocation_and_reviewed_configuration_are_accepted(self) -> None:
        payload = invocation("/tmp/results.csv.gz", "/protected/secret")
        parsed = sender.parse_invocation(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        config = sender.parse_configuration(parsed)
        self.assertEqual(config.adapter_url, ADAPTER_URL)
        self.assertEqual(config.rule_id, RULE_ID)
        self.assertEqual(config.rule_title, RULE_TITLE)
        self.assertEqual(config.sigma_level, "high")
        self.assertEqual(config.channel, CHANNEL)
        self.assertEqual(sender.results_file_from_invocation(parsed), Path("/tmp/results.csv.gz"))

    def test_missing_results_file_and_malformed_invocation_are_rejected(self) -> None:
        with self.assertRaises(sender.ActionInputError):
            sender.parse_invocation(b"not json")
        payload = invocation("/tmp/results.csv.gz", "/protected/secret")
        del payload["results_file"]
        with self.assertRaises(sender.ActionInputError):
            sender.results_file_from_invocation(payload)

    def test_reviewed_metadata_is_required_and_validated(self) -> None:
        cases = {
            "missing rule id": ("rule_id", None),
            "invalid rule id": ("rule_id", "not-a-uuid"),
            "missing title": ("rule_title", None),
            "blank title": ("rule_title", " "),
            "missing level": ("sigma_level", None),
            "unsupported level": ("sigma_level", "severe"),
        }
        for name, (field, replacement) in cases.items():
            with self.subTest(name=name):
                payload = invocation("/tmp/results.csv.gz", "/protected/secret")
                config = payload["configuration"]
                assert isinstance(config, dict)
                if replacement is None:
                    del config[field]
                else:
                    config[field] = replacement
                with self.assertRaises(sender.ActionConfigurationError):
                    sender.parse_configuration(payload)

    def test_adapter_url_and_channel_are_narrow(self) -> None:
        for field, value in (
            ("adapter_url", "http://adapter.invalid/v1/alerts"),
            ("adapter_url", "http://user:password@adapter.invalid/v1/splunk/findings"),
            ("adapter_url", "http://adapter.invalid/v1/splunk/findings?secret=no"),
            ("channel", "Security"),
        ):
            with self.subTest(field=field, value=value):
                payload = invocation("/tmp/results.csv.gz", "/protected/secret")
                config = payload["configuration"]
                assert isinstance(config, dict)
                config[field] = value
                with self.assertRaises(sender.ActionConfigurationError):
                    sender.parse_configuration(payload)

    def test_secret_file_path_must_be_absolute(self) -> None:
        payload = invocation("/tmp/results.csv.gz", "relative.secret")
        with self.assertRaises(sender.ActionConfigurationError):
            sender.parse_configuration(payload)

    def test_event_validation_fails_before_transport(self) -> None:
        invalid = {
            "event time": ("_time", "2026-08-18 12:34:56"),
            "event time range": ("_time", "999999999999"),
            "event code": ("EventCode", "one"),
            "record id": ("RecordID", "0"),
            "hostname": ("Computer", "not a host!"),
        }
        config = sender.parse_configuration(
            invocation("/tmp/results.csv.gz", "/protected/secret")
        )
        for name, (field, value) in invalid.items():
            with self.subTest(name=name):
                row = fixture_row()
                row[field] = value
                with self.assertRaises(sender.ActionInputError):
                    sender.build_finding(row, config)

    def test_result_columns_cannot_override_reviewed_metadata(self) -> None:
        row = fixture_row()
        row.update(
            {
                "rule_id": "00000000-0000-0000-0000-000000000000",
                "rule_title": "event-controlled title",
                "sigma_level": "low",
            }
        )
        config = sender.parse_configuration(
            invocation("/tmp/results.csv.gz", "/protected/secret")
        )
        finding = sender.build_finding(row, config)
        self.assertEqual(
            finding["detection"],
            {"rule_id": RULE_ID, "rule_title": RULE_TITLE, "sigma_level": "high"},
        )


class SplunkFindingEnvelopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = sender.parse_configuration(
            invocation("/tmp/results.csv.gz", "/protected/secret")
        )

    def test_validation_row_produces_exact_phase_one_envelope(self) -> None:
        finding = sender.build_finding(fixture_row(), self.config)
        self.assertEqual(
            finding,
            {
                "schema": "alert2ir.splunk-finding.v1",
                "detection": {
                    "rule_id": RULE_ID,
                    "rule_title": RULE_TITLE,
                    "sigma_level": "high",
                },
                "event": {
                    "detected_at": "2026-08-18T12:34:56.123456Z",
                    "computer": "WIN11-02",
                    "host": "win11-02",
                    "channel": CHANNEL,
                    "source": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                    "sourcetype": "XmlWinEventLog",
                    "event_code": "1",
                    "record_id": "1800001",
                    "process_guid": "{22222222-3333-4444-5555-666666666666}",
                    "image": r"C:\Windows\System32\cmd.exe",
                    "parent_image": r"C:\Windows\explorer.exe",
                },
            },
        )

        accepted = SplunkFinding.model_validate(finding)
        canonical = canonicalize(accepted)
        self.assertEqual(canonical.alert.severity.value, "high")
        self.assertEqual(
            [(entity.kind, entity.value) for entity in canonical.alert.entities],
            [("host", "win11-02")],
        )
        self.assertEqual(canonical.idempotency_key, EXPECTED_VALIDATION_KEY)

    def test_empty_optional_values_are_omitted(self) -> None:
        row = fixture_row()
        for field in ("source", "sourcetype", "ProcessGuid", "Image", "ParentImage", "TargetFilename"):
            row[field] = ""
        finding = sender.build_finding(row, self.config)
        self.assertTrue(
            {
                "source",
                "sourcetype",
                "process_guid",
                "image",
                "parent_image",
                "target_filename",
            }.isdisjoint(finding["event"])
        )

    def test_serialization_is_exact_deterministic_json(self) -> None:
        finding = sender.build_finding(fixture_row(), self.config)
        first = sender.serialize_finding(finding)
        reordered = {"event": finding["event"], "detection": finding["detection"], "schema": finding["schema"]}
        second = sender.serialize_finding(reordered)
        self.assertEqual(first, second)
        self.assertNotIn(b"\n", first)
        self.assertEqual(json.loads(first), finding)

    def test_unnecessary_runtime_and_event_values_do_not_cross_boundary(self) -> None:
        row = fixture_row()
        row.update(
            {
                "CommandLine": "sensitive command",
                "User": "sensitive user",
                "ProcessId": "1234",
                "ParentProcessId": "5678",
                "_raw": "raw xml",
                "sid": "sid",
                "results_link": "url",
                "session_key": "session",
            }
        )
        body = sender.serialize_finding(sender.build_finding(row, self.config))
        for prohibited in (
            b"CommandLine",
            b"sensitive command",
            b"User",
            b"ProcessId",
            b"_raw",
            b"sid",
            b"results_link",
            b"session_key",
            b"Idempotency-Key",
        ):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, body)


class SplunkSenderAuthenticationTests(unittest.TestCase):
    def test_sender_hmac_vector_exactly_matches_phase_two(self) -> None:
        body = b'{"a":1}'
        signature = sender.signature_header(SECRET, "1786566372", body)
        self.assertEqual(
            signature,
            "v1=c4e03a5591f52c251b1fd38728070921e5e54303714d5dda90529eef1624c179",
        )
        verify_signature(
            shared_secret=SECRET,
            timestamp_header="1786566372",
            signature_header=signature,
            raw_body=body,
            now=datetime.fromtimestamp(1_786_566_372, timezone.utc),
        )

    def test_signature_changes_with_body_timestamp_or_secret(self) -> None:
        baseline = sender.signature_header(SECRET, "1786566372", b'{"a":1}')
        self.assertEqual(baseline, sender.signature_header(SECRET, "1786566372", b'{"a":1}'))
        self.assertNotEqual(baseline, sender.signature_header(SECRET, "1786566372", b'{"a":2}'))
        self.assertNotEqual(baseline, sender.signature_header(SECRET, "1786566373", b'{"a":1}'))
        self.assertNotEqual(baseline, sender.signature_header(b"z" * 32, "1786566372", b'{"a":1}'))

    def test_secret_file_accepts_minimum_and_one_terminal_newline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            path.write_bytes(b"x" * 32 + b"\n")
            self.assertEqual(sender.load_secret(path), b"x" * 32)
            path.write_bytes(b"x" * 31)
            with self.assertRaisesRegex(sender.ActionConfigurationError, "32 bytes"):
                sender.load_secret(path)


class SplunkSenderResponseTests(unittest.TestCase):
    def test_phase_two_response_classifications_are_explicit(self) -> None:
        contracts = (
            (response(200, "completed"), "success", False),
            (response(202, "accepted"), "success", False),
            (response(400, "permanent_failure"), "permanent_failure", False),
            (response(409, "permanent_failure"), "permanent_failure", False),
            (response(422, "permanent_failure"), "permanent_failure", False),
            (response(500, "durable_failure"), "durable_failure", False),
            (response(502, "transient_failure"), "transient_failure", True),
            (response(503, "transient_failure"), "transient_failure", True),
            (response(504, "transient_failure"), "transient_failure", True),
        )
        for raw_response, category, retryable in contracts:
            with self.subTest(status=raw_response.status):
                disposition = sender.classify_adapter_response(raw_response)
                self.assertEqual(disposition.category, category)
                self.assertEqual(disposition.retryable, retryable)

    def test_malformed_response_falls_back_conservatively(self) -> None:
        cases = (
            (200, "success", False),
            (202, "success", False),
            (400, "permanent_failure", False),
            (409, "permanent_failure", False),
            (422, "permanent_failure", False),
            (500, "transient_failure", True),
            (502, "transient_failure", True),
            (503, "transient_failure", True),
            (504, "transient_failure", True),
        )
        for status, category, retryable in cases:
            with self.subTest(status=status):
                disposition = sender.classify_adapter_response(
                    sender.HttpResponse(status=status, body=b"not json", headers={})
                )
                self.assertEqual(disposition.category, category)
                self.assertEqual(disposition.retryable, retryable)


class SplunkSenderRetryTests(unittest.TestCase):
    def setUp(self) -> None:
        config = configuration()
        self.config = sender.ActionConfiguration(**config)
        self.body = b'{"schema":"alert2ir.splunk-finding.v1"}'

    def deliver(self, outcomes: list[object], timestamps=None):
        transport = FakeTransport(outcomes)
        sleeps: list[float] = []
        values = iter(timestamps or [NOW_EPOCH, NOW_EPOCH + 1, NOW_EPOCH + 3])
        result = sender.deliver(
            body=self.body,
            config=self.config,
            secret=SECRET,
            transport=transport,
            clock=lambda: next(values),
            sleeper=sleeps.append,
        )
        return result, transport, sleeps

    def test_success_and_permanent_results_never_retry(self) -> None:
        for status, classification in (
            (200, "completed"),
            (202, "accepted"),
            (400, "permanent_failure"),
            (409, "permanent_failure"),
            (422, "permanent_failure"),
            (500, "durable_failure"),
        ):
            with self.subTest(status=status):
                result, transport, sleeps = self.deliver([response(status, classification)])
                self.assertEqual(result.attempts, 1)
                self.assertEqual(len(transport.calls), 1)
                self.assertEqual(sleeps, [])
                self.assertEqual(result.success, status in {200, 202})

    def test_transient_statuses_retry_then_succeed(self) -> None:
        for status in (502, 503, 504):
            with self.subTest(status=status):
                result, transport, sleeps = self.deliver(
                    [response(status, "transient_failure"), response(200, "completed")]
                )
                self.assertTrue(result.success)
                self.assertEqual(result.attempts, 2)
                self.assertEqual(len(transport.calls), 2)
                self.assertEqual(sleeps, [1.0])

    def test_connection_and_timeout_retry_then_succeed(self) -> None:
        for failure in (
            sender.ConnectionFailure("connection failed"),
            sender.RequestTimeout("request timed out"),
        ):
            with self.subTest(failure=type(failure).__name__):
                result, transport, sleeps = self.deliver(
                    [failure, response(202, "accepted")]
                )
                self.assertTrue(result.success)
                self.assertEqual(len(transport.calls), 2)
                self.assertEqual(sleeps, [1.0])

    def test_three_transient_failures_stop_without_a_fourth_attempt(self) -> None:
        result, transport, sleeps = self.deliver(
            [
                response(503, "transient_failure"),
                response(503, "transient_failure"),
                response(503, "transient_failure"),
            ]
        )
        self.assertFalse(result.success)
        self.assertEqual(result.attempts, 3)
        self.assertEqual(len(transport.calls), 3)
        self.assertEqual(sleeps, [1.0, 2.0])

    def test_body_is_stable_and_authentication_refreshes_across_retries(self) -> None:
        result, transport, _ = self.deliver(
            [
                response(503, "transient_failure"),
                response(503, "transient_failure"),
                response(202, "accepted", replayed=True),
            ]
        )
        self.assertTrue(result.success)
        self.assertTrue(result.replayed)
        self.assertEqual([call["body"] for call in transport.calls], [self.body] * 3)
        timestamps = [
            call["headers"]["X-Alert2IR-Timestamp"] for call in transport.calls
        ]
        signatures = [
            call["headers"]["X-Alert2IR-Signature"] for call in transport.calls
        ]
        self.assertEqual(timestamps, [str(NOW_EPOCH), str(NOW_EPOCH + 1), str(NOW_EPOCH + 3)])
        self.assertEqual(len(set(signatures)), 3)
        for call in transport.calls:
            self.assertEqual(call["url"], ADAPTER_URL)
            self.assertEqual(call["headers"]["Content-Type"], "application/json")
            self.assertNotIn("Idempotency-Key", call["headers"])


class SplunkSenderExecutionTests(unittest.TestCase):
    def test_valid_invocation_reads_once_and_delivers_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            results = root / "results.csv.gz"
            secret = root / "secret"
            gzip_csv(results, [fixture_row()])
            secret.write_bytes(SECRET + b"\n")
            transport = FakeTransport([response(200, "completed")])
            outcome = sender.execute_invocation(
                invocation(str(results), str(secret)),
                transport=transport,
                clock=lambda: NOW_EPOCH,
                sleeper=lambda _delay: None,
            )
        self.assertTrue(outcome.success)
        self.assertEqual(len(transport.calls), 1)
        body = transport.calls[0]["body"]
        finding = SplunkFinding.model_validate_json(body)
        self.assertEqual(canonicalize(finding).idempotency_key, EXPECTED_VALIDATION_KEY)

    def test_local_failures_never_call_http(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            results = root / "results.csv.gz"
            secret = root / "secret"
            secret.write_bytes(SECRET)
            invalid_rows = ([], [fixture_row(), fixture_row()])
            for index, rows in enumerate(invalid_rows):
                with self.subTest(rows=len(rows)):
                    gzip_csv(results, list(rows))
                    transport = FakeTransport([])
                    with self.assertRaises(sender.ActionError):
                        sender.execute_invocation(
                            invocation(str(results), str(secret)),
                            transport=transport,
                            clock=lambda: NOW_EPOCH,
                            sleeper=lambda _delay: None,
                        )
                    self.assertEqual(transport.calls, [], index)

    def test_invalid_row_configuration_and_secret_never_call_http(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            results = root / "results.csv.gz"
            secret = root / "secret"
            secret.write_bytes(SECRET)

            cases: list[tuple[str, dict[str, str], dict[str, str], bytes]] = []
            for field, value in (
                ("_time", "invalid"),
                ("EventCode", "one"),
                ("RecordID", "zero"),
            ):
                row = fixture_row()
                row[field] = value
                cases.append((field, row, configuration(str(secret)), SECRET))
            bad_config = configuration(str(secret))
            bad_config["rule_id"] = "not-a-uuid"
            cases.append(("rule_id", fixture_row(), bad_config, SECRET))
            cases.append(("secret", fixture_row(), configuration(str(secret)), b"short"))

            for name, row, action_config, secret_bytes in cases:
                with self.subTest(name=name):
                    gzip_csv(results, [row])
                    secret.write_bytes(secret_bytes)
                    payload = invocation(str(results), str(secret))
                    payload["configuration"] = action_config
                    transport = FakeTransport([])
                    with self.assertRaises(sender.ActionError):
                        sender.execute_invocation(
                            payload,
                            transport=transport,
                            clock=lambda: NOW_EPOCH,
                            sleeper=lambda _delay: None,
                        )
                    self.assertEqual(transport.calls, [])

    def test_main_exit_code_is_zero_only_for_success(self) -> None:
        payload = json.dumps({"synthetic": True}).encode("utf-8")
        original = sender.execute_invocation
        try:
            for success, expected in ((True, 0), (False, 1)):
                with self.subTest(success=success):
                    sender.execute_invocation = lambda _value, success=success: sender.DeliveryOutcome(
                        success=success,
                        attempts=1,
                        category="success" if success else "permanent_failure",
                        status=200 if success else 422,
                    )
                    with redirect_stderr(io.StringIO()):
                        self.assertEqual(
                            sender.main(["--execute"], stdin=io.BytesIO(payload)),
                            expected,
                        )
        finally:
            sender.execute_invocation = original

    def test_main_rejects_non_execute_mode(self) -> None:
        with redirect_stderr(io.StringIO()):
            self.assertEqual(sender.main([], stdin=io.BytesIO(b"{}")), 1)


class RecordingAlert2IRClient:
    def __init__(self) -> None:
        self.calls: list[tuple[object, str]] = []

    async def submit_alert(self, alert, *, idempotency_key: str) -> Alert2IRDeliveryResult:
        self.calls.append((alert, idempotency_key))
        return Alert2IRDeliveryResult(
            classification=DeliveryClassification.COMPLETED,
            upstream_status=200,
            processing_id="5afaf9ce-3df8-43d3-bac8-1b875211dcc4",
            state="completed",
            replayed=False,
            decision_outcome="investigate",
            retryable=False,
            acceptance_unknown=False,
        )


class SplunkCrossPhaseTests(unittest.IsolatedAsyncioTestCase):
    async def test_sender_to_authenticated_gateway_to_phase_one(self) -> None:
        config = sender.ActionConfiguration(**configuration())
        body = sender.serialize_finding(sender.build_finding(fixture_row(), config))
        timestamp = str(NOW_EPOCH)
        phase_two_client = RecordingAlert2IRClient()
        app = create_splunk_adapter_app(
            shared_secret=SECRET,
            alert2ir_client=phase_two_client,
            clock=lambda: NOW,
        )
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url="http://adapter.invalid",
        ) as caller:
            response_value = await caller.post(
                "/v1/splunk/findings",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Alert2IR-Timestamp": timestamp,
                    "X-Alert2IR-Signature": sender.signature_header(
                        SECRET,
                        timestamp,
                        body,
                    ),
                },
            )

        self.assertEqual(response_value.status_code, 200)
        self.assertEqual(len(phase_two_client.calls), 1)
        alert, key = phase_two_client.calls[0]
        self.assertEqual(alert.severity.value, "high")
        self.assertEqual(
            [(entity.kind, entity.value) for entity in alert.entities],
            [("host", "win11-02")],
        )
        self.assertEqual(key, EXPECTED_VALIDATION_KEY)


def parse_conf(path: Path) -> ConfigParser:
    parser = ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    with path.open(encoding="utf-8") as source:
        parser.read_file(source)
    return parser


class SplunkAppConfigurationTests(unittest.TestCase):
    def test_custom_action_registration_is_minimal_and_python_compatible(self) -> None:
        config = parse_conf(ALERT_ACTIONS_PATH)["alert2ir_delivery"]
        self.assertEqual(config["is_custom"], "1")
        self.assertEqual(config["payload_format"], "json")
        self.assertEqual(config["forceCsvResults"], "true")
        self.assertEqual(config["alert.execute.cmd"], "alert2ir_delivery.py")
        self.assertEqual(config["alert.execute.cmd.arg.1"], "--execute")
        self.assertEqual(config["python.required"], "3.9,3.13")
        self.assertEqual(
            {
                key for key in config if key.startswith("param.")
            },
            {
                "param.adapter_url",
                "param.secret_file",
                "param.rule_id",
                "param.rule_title",
                "param.sigma_level",
                "param.channel",
            },
        )

    def test_saved_search_is_disabled_per_result_and_reviewed(self) -> None:
        searches = parse_conf(SAVED_SEARCH_PATH)
        self.assertEqual(searches.sections(), [RULE_TITLE])
        search = searches[RULE_TITLE]
        self.assertEqual(search["disabled"], "true")
        self.assertEqual(search["enableSched"], "0")
        self.assertEqual(search["cron_schedule"], "* * * * *")
        self.assertEqual(search["dispatch.earliest_time"], "-2m@m")
        self.assertEqual(search["dispatch.latest_time"], "-1m@m")
        self.assertEqual(search["alert.digest_mode"], "false")
        self.assertEqual(search["alert.suppress"], "false")
        self.assertEqual(search["action.alert2ir_delivery"], "1")
        self.assertEqual(search["action.alert2ir_delivery.param.rule_id"], RULE_ID)
        self.assertEqual(search["action.alert2ir_delivery.param.rule_title"], RULE_TITLE)
        self.assertEqual(search["action.alert2ir_delivery.param.sigma_level"], "high")
        self.assertEqual(search["action.alert2ir_delivery.param.channel"], CHANNEL)
        self.assertEqual(search["action.alert2ir_delivery.param.adapter_url"], "")
        self.assertEqual(search["action.alert2ir_delivery.param.secret_file"], "")

    def test_saved_search_uses_derived_predicate_and_exact_projection(self) -> None:
        search = parse_conf(SAVED_SEARCH_PATH)[RULE_TITLE]["search"]
        prefix = "index=main "
        projection = " | table " + " ".join(EXPECTED_FIELDS)
        self.assertFalse(search.startswith("search "))
        self.assertTrue(search.startswith(prefix))
        self.assertTrue(search.endswith(projection))
        self.assertEqual(search[len(prefix) : -len(projection)], GENERATED_VALIDATION_SPL)

    def test_saved_search_contains_no_secret_or_forbidden_override(self) -> None:
        text = SAVED_SEARCH_PATH.read_text(encoding="utf-8").lower()
        for prohibited in (
            "idempotency-key",
            "canonical_source",
            "severity_override",
            "session_key",
            "shared_secret",
        ):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, text)
        search = parse_conf(SAVED_SEARCH_PATH)[RULE_TITLE]
        self.assertEqual(search["action.alert2ir_delivery.param.adapter_url"], "")
        self.assertEqual(search["action.alert2ir_delivery.param.secret_file"], "")

    def test_validation_sigma_rule_is_explicitly_safe_and_non_production(self) -> None:
        text = VALIDATION_RULE_PATH.read_text(encoding="utf-8")
        for expected in (
            "id: " + RULE_ID,
            "status: test",
            "level: high",
            "Image|endswith: '\\cmd.exe'",
            "CommandLine|contains: 'Alert2IR-INVESTIGATE-'",
            "not production detection content",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main()
