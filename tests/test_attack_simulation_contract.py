"""Repository contracts for WS07 scenarios and future ground-truth records.

These tests validate Alert2IR's pinned JSON contract with the Python standard
library. They do not parse Atomic YAML, execute an Atomic test, validate a
detection, or substitute for later endpoint execution and cleanup evidence.
"""

import base64
from copy import deepcopy
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import unittest
from uuid import UUID


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCENARIO_MANIFEST = (
    REPOSITORY_ROOT / "config" / "attack-simulation" / "scenarios.json"
)

ATOMIC_REPOSITORY = "https://github.com/redcanaryco/atomic-red-team"
ATOMIC_COMMIT = "1ba1dd8d9ce6f74700f7aec2e60de5632f667f03"
COMMAND_PROMPT_EXECUTABLE = r"C:\Windows\System32\cmd.exe"
FILE_SCENARIO_ID = "alert2ir.ws07.windows.cmd-file-write.v1"
FILE_PATH_TEMPLATE = r"C:\Windows\Temp\Alert2IR-WS07-${run_id}.bin"
FILE_MESSAGE_TEMPLATE = "Alert2IR WS07 ground truth ${run_id}"
POWERSHELL_DECODED_SCRIPT = (
    "& (gcm ('ie{0}' -f 'x')) "
    '("Wr"+"it"+"e-H"+"ost \'H"+"el"+"lo, fr"+"om P"+"ow"+"erS"+"h"+'
    '"ell!\'")'
)
EXPECTED_WS07_CANARY_RECORDS = {
    "45e78645-170d-4f2c-b158-32fdc89bec8d.json",
    "2c752432-9aa7-4a4d-bdb5-4ffacd2698b7.json",
    "34b43f09-1023-4c5c-8609-03c410bb28a3.json",
}

APPROVED_ENDPOINTS = {
    ("win11-02", "WIN11-02", "192.168.56.62", "Ethernet"),
    ("win11-01", "WIN11-01", "192.168.56.60", "Ethernet"),
}

EXPECTED_SCENARIOS = {
    "alert2ir.ws07.windows.process-discovery-tasklist.v1": {
        "technique_id": "T1057",
        "atomic_guid": "c5806a4f-62b8-4900-980b-c7ec004e9908",
        "atomic_test_name": "Process Discovery - tasklist",
        "definition_path": "atomics/T1057/T1057.yaml",
        "definition_sha256": (
            "dc79938deab7d7f04c7cc35f5031f21a1af4cfe8fa85b17ccdb8191a2384bff5"
        ),
        "executor": "command_prompt",
        "executable": COMMAND_PROMPT_EXECUTABLE,
        "elevation_required": False,
    },
    "alert2ir.ws07.windows.powershell-command.v1": {
        "technique_id": "T1059.001",
        "atomic_guid": "a538de64-1c74-46ed-aa60-b995ed302598",
        "atomic_test_name": "PowerShell Command Execution",
        "definition_path": "atomics/T1059.001/T1059.001.yaml",
        "definition_sha256": (
            "9b02ed22b78f97873617aa4b9d4dcca3eb9e7ca8d5ed72a21e90baf7e8935fb7"
        ),
        "executor": "command_prompt",
        "executable": COMMAND_PROMPT_EXECUTABLE,
        "elevation_required": False,
    },
    "alert2ir.ws07.windows.cmd-file-write.v1": {
        "technique_id": "T1059.003",
        "atomic_guid": "127b4afe-2346-4192-815c-69042bec570e",
        "atomic_test_name": "Writes text to a file and displays it.",
        "definition_path": "atomics/T1059.003/T1059.003.yaml",
        "definition_sha256": (
            "5318d81746f483458ea2f906f64223a2a4e9506fded9df509f53986391ad572c"
        ),
        "executor": "command_prompt",
        "executable": COMMAND_PROMPT_EXECUTABLE,
        "elevation_required": False,
    },
}

SAFETY_FLAGS = {
    "requires_network",
    "downloads",
    "credentials",
    "external_target",
    "reboot_required",
    "logoff_required",
    "security_control_change",
    "service_change",
    "account_change",
    "firewall_change",
    "scheduled_task_change",
    "registry_change",
}

FORBIDDEN_WS08_WS09_FIELDS = {
    "splunk",
    "spl",
    "splunk_search",
    "sourcetype",
    "splunk_detection",
    "detection",
    "sigma",
    "sigma_rule",
    "canonical_alert",
    "alert2ir_canonical_alert",
    "alert2ir_decision",
    "decision",
    "incident",
    "investigation",
    "velociraptor",
}

TELEMETRY_OBSERVATION_STATES = {
    "observed",
    "missing_expected",
    "not_available",
    "unexpected",
}


def load_manifest() -> dict:
    """Load the repository-owned scenario contract as JSON."""
    with SCENARIO_MANIFEST.open(encoding="utf-8") as manifest_file:
        return json.load(manifest_file)


def mapping_keys(value: object):
    """Yield mapping keys recursively from the narrow JSON-like contracts."""
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from mapping_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from mapping_keys(child)


def reject_forbidden_fields(value: object) -> None:
    """Reject WS08/WS09 concerns when they appear as contract field names."""
    forbidden = {
        key
        for key in mapping_keys(value)
        if key.lower().replace("-", "_") in FORBIDDEN_WS08_WS09_FIELDS
    }
    if forbidden:
        raise ValueError(f"forbidden WS08/WS09 fields: {sorted(forbidden)}")


def require_exact_fields(
    value: object,
    required: set[str],
    context: str,
    optional: set[str] | None = None,
) -> dict:
    """Require the fixed v1 fields, with only explicitly optional fields allowed."""
    if not isinstance(value, dict):
        raise ValueError(f"{context} must be an object")
    optional = optional or set()
    missing = required - value.keys()
    if missing:
        raise ValueError(f"{context} is missing fields: {sorted(missing)}")
    unexpected = value.keys() - required - optional
    if unexpected:
        raise ValueError(f"{context} has unexpected fields: {sorted(unexpected)}")
    return value


def require_utc(value: object, context: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{context} must be a UTC timestamp string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ValueError(f"{context} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{context} must be timezone-aware UTC")
    return parsed


def resolve_scenario(scenario: dict, run_id: str) -> tuple[dict, str, str | None]:
    """Resolve the current literal templates for ground-truth contract checks."""
    try:
        canonical_run_id = str(UUID(run_id))
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("run_id must be a UUID before scenario resolution") from error
    if canonical_run_id != run_id:
        raise ValueError("run_id must use canonical UUID text before resolution")

    inputs = {}
    for name, value in scenario["inputs"].items():
        if not isinstance(value, str):
            raise ValueError("scenario input templates must be strings")
        resolved_input = value.replace("${run_id}", run_id)
        if "#{" in resolved_input or "${" in resolved_input:
            raise ValueError("scenario contains an unresolved input placeholder")
        inputs[name] = resolved_input

    def resolve_template(template: str | None) -> str | None:
        if template is None:
            return None
        resolved = template
        for name, value in inputs.items():
            resolved = resolved.replace(f"#{{{name}}}", value)
        if "#{" in resolved or "${" in resolved:
            raise ValueError("scenario contains an unresolved execution template")
        return resolved

    command = resolve_template(scenario["executor"]["command_template"])
    cleanup = resolve_template(scenario["executor"]["cleanup_command_template"])

    if scenario["scenario_id"] == FILE_SCENARIO_ID:
        expected_path = rf"C:\Windows\Temp\Alert2IR-WS07-{run_id}.bin"
        expected_message = f"Alert2IR WS07 ground truth {run_id}"
        if inputs != {
            "file_contents_path": expected_path,
            "message": expected_message,
        }:
            raise ValueError("file scenario inputs must resolve to the approved v1 target")
        expected_command = (
            f'echo "{expected_message}" > "{expected_path}" & type "{expected_path}"'
        )
        expected_cleanup = f'del "{expected_path}" >nul 2>&1'
        if command != expected_command:
            raise ValueError("file scenario command must target the approved v1 file")
        if cleanup != expected_cleanup:
            raise ValueError("file scenario cleanup must target the approved v1 file")

    return inputs, command, cleanup


def validate_ground_truth_record(record: object, manifest: dict) -> None:
    """Validate only the documented WS07 ground-truth version 1 contract."""
    reject_forbidden_fields(record)
    record = require_exact_fields(
        record,
        {
            "schema_version",
            "run_id",
            "scenario_id",
            "alert2ir_commit",
            "operator_role",
            "endpoint",
            "source_provenance",
            "execution",
            "prerequisite",
            "clock_evidence",
            "preflight",
            "cleanup",
            "post_state_verification",
            "telemetry_window",
            "telemetry_observations",
            "deviations",
        },
        "ground-truth record",
    )
    if record["schema_version"] != 1:
        raise ValueError("ground-truth schema_version must be 1")

    try:
        run_id = UUID(record["run_id"])
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("run_id must be a UUID") from error
    if str(run_id) != record["run_id"]:
        raise ValueError("run_id must use canonical UUID text")

    scenarios = {
        scenario["scenario_id"]: scenario for scenario in manifest["scenarios"]
    }
    if record["scenario_id"] not in scenarios:
        raise ValueError("scenario_id must reference the committed manifest")
    scenario = scenarios[record["scenario_id"]]

    if not isinstance(record["alert2ir_commit"], str) or re.fullmatch(
        r"[0-9a-f]{40}", record["alert2ir_commit"]
    ) is None:
        raise ValueError("alert2ir_commit must be a 40-character lowercase hex SHA")
    if record["operator_role"] != "lab-admin":
        raise ValueError("operator_role must be lab-admin for WS07 v1")

    endpoint = require_exact_fields(
        record["endpoint"],
        {"inventory_name", "computer_name", "host_only_ipv4", "interface"},
        "endpoint",
    )
    for field in ("inventory_name", "computer_name", "interface"):
        if not isinstance(endpoint[field], str) or not endpoint[field].strip():
            raise ValueError(f"endpoint.{field} must be non-empty")
    try:
        ipaddress.IPv4Address(endpoint["host_only_ipv4"])
    except (ipaddress.AddressValueError, TypeError) as error:
        raise ValueError("endpoint.host_only_ipv4 must be an IPv4 address") from error
    endpoint_identity = (
        endpoint["inventory_name"],
        endpoint["computer_name"],
        endpoint["host_only_ipv4"],
        endpoint["interface"],
    )
    if endpoint_identity not in APPROVED_ENDPOINTS:
        raise ValueError("endpoint must match an approved WS07 Windows identity")

    provenance = require_exact_fields(
        record["source_provenance"],
        {
            "technique_id",
            "atomic_guid",
            "atomic_commit",
            "definition_path",
            "definition_sha256",
        },
        "source_provenance",
    )
    expected_provenance = {
        "technique_id": scenario["technique_id"],
        "atomic_guid": scenario["atomic_guid"],
        "atomic_commit": manifest["atomic_source"]["commit"],
        "definition_path": scenario["definition"]["path"],
        "definition_sha256": scenario["definition"]["sha256"],
    }
    if {key: provenance[key] for key in expected_provenance} != expected_provenance:
        raise ValueError("source_provenance must match the selected scenario")

    execution = require_exact_fields(
        record["execution"],
        {
            "executable",
            "executor",
            "actual_elevated",
            "inputs",
            "command",
            "start_utc",
            "end_utc",
            "exit_code",
            "result",
        },
        "execution",
    )
    if execution["executor"] != scenario["executor"]["name"]:
        raise ValueError("execution.executor must match the selected scenario")
    if execution["executable"] != scenario["executor"]["executable"]:
        raise ValueError("execution.executable must match the selected scenario")
    if not isinstance(execution["actual_elevated"], bool):
        raise ValueError("execution.actual_elevated must be boolean")
    expected_inputs, expected_command, expected_cleanup = resolve_scenario(
        scenario, record["run_id"]
    )
    if execution["inputs"] != expected_inputs:
        raise ValueError("execution.inputs must exactly resolve the selected scenario")
    if execution["command"] != expected_command:
        raise ValueError("execution.command must exactly resolve the selected scenario")
    for field in ("executable", "command"):
        if not isinstance(execution[field], str) or not execution[field].strip():
            raise ValueError(f"execution.{field} must be non-empty")
    if execution["exit_code"] is not None and not isinstance(execution["exit_code"], int):
        raise ValueError("execution.exit_code must be an integer or null")
    if execution["result"] not in {"succeeded", "failed", "blocked"}:
        raise ValueError("execution.result is invalid")
    execution_start = require_utc(execution["start_utc"], "execution.start_utc")
    execution_end = require_utc(execution["end_utc"], "execution.end_utc")
    if execution_end < execution_start:
        raise ValueError("execution end precedes start")

    prerequisite = require_exact_fields(
        record["prerequisite"], {"status", "details"}, "prerequisite"
    )
    if scenario["prerequisites"] != {
        "required": False,
        "acquisition_allowed": False,
    }:
        raise ValueError("WS07 ground-truth v1 supports only no-prerequisite scenarios")
    if prerequisite["status"] != "not_required":
        raise ValueError("prerequisite.status must be not_required")
    if not isinstance(prerequisite["details"], str) or not prerequisite[
        "details"
    ].strip():
        raise ValueError("prerequisite.details must be non-empty text")

    clock = require_exact_fields(
        record["clock_evidence"],
        {"dev01_before_utc", "endpoint_utc", "dev01_after_utc"},
        "clock_evidence",
    )
    before = require_utc(clock["dev01_before_utc"], "clock_evidence.dev01_before_utc")
    require_utc(clock["endpoint_utc"], "clock_evidence.endpoint_utc")
    after = require_utc(clock["dev01_after_utc"], "clock_evidence.dev01_after_utc")
    if after < before:
        raise ValueError("clock evidence dev01 timestamps are reversed")

    preflight = require_exact_fields(
        record["preflight"], {"status", "checks"}, "preflight"
    )
    if preflight["status"] not in {"passed", "failed", "stopped"}:
        raise ValueError("preflight.status is invalid")
    if not isinstance(preflight["checks"], list) or not all(
        isinstance(check, str) and check.strip() for check in preflight["checks"]
    ):
        raise ValueError("preflight.checks must be a list of non-empty strings")

    cleanup = require_exact_fields(
        record["cleanup"],
        {"required", "command", "result", "independently_verified"},
        "cleanup",
    )
    if not isinstance(cleanup["required"], bool) or cleanup["required"] != scenario[
        "cleanup"
    ]["required"]:
        raise ValueError("cleanup.required must match the selected scenario")
    if not isinstance(cleanup["independently_verified"], bool):
        raise ValueError("cleanup.independently_verified must be boolean")
    if cleanup["required"]:
        if cleanup["command"] != expected_cleanup:
            raise ValueError("required cleanup must record the exact resolved command")
        if cleanup["result"] == "succeeded":
            if cleanup["independently_verified"] is not True:
                raise ValueError("successful cleanup must be independently verified")
        elif cleanup["result"] == "failed":
            if cleanup["independently_verified"] is not False:
                raise ValueError("failed cleanup cannot be independently verified")
        else:
            raise ValueError("required cleanup result is invalid")
    elif cleanup != {
        "required": False,
        "command": None,
        "result": "not_required",
        "independently_verified": False,
    }:
        raise ValueError("non-required cleanup must use the fixed v1 representation")

    post_state = require_exact_fields(
        record["post_state_verification"], {"status", "details"}, "post_state"
    )
    if post_state["status"] not in {"verified", "failed", "not_applicable"}:
        raise ValueError("post-state verification status is invalid")
    if not isinstance(post_state["details"], str) or not post_state[
        "details"
    ].strip():
        raise ValueError("post-state verification details must be non-empty text")
    if cleanup["required"]:
        expected_post_state = (
            "verified" if cleanup["result"] == "succeeded" else "failed"
        )
        if post_state["status"] != expected_post_state:
            raise ValueError("post-state status contradicts required cleanup result")
    elif post_state["status"] != "not_applicable":
        raise ValueError("post-state must be not_applicable without cleanup")

    telemetry_window = require_exact_fields(
        record["telemetry_window"], {"start_utc", "end_utc"}, "telemetry_window"
    )
    window_start = require_utc(
        telemetry_window["start_utc"], "telemetry_window.start_utc"
    )
    window_end = require_utc(telemetry_window["end_utc"], "telemetry_window.end_utc")
    if window_end < window_start:
        raise ValueError("telemetry window end precedes start")

    observations = record["telemetry_observations"]
    if not isinstance(observations, list):
        raise ValueError("telemetry_observations must be a list")
    allowed_reference_fields = {
        "state",
        "channel",
        "event_id",
        "record_id",
        "timestamp_utc",
    }
    for observation in observations:
        observation = require_exact_fields(
            observation,
            {"state", "channel", "event_id"},
            "telemetry observation",
            {"record_id", "timestamp_utc"},
        )
        if set(observation) - allowed_reference_fields:
            raise ValueError("telemetry observation contains unsanitized fields")
        if observation["state"] not in TELEMETRY_OBSERVATION_STATES:
            raise ValueError("telemetry observation state is invalid")
        if not isinstance(observation["channel"], str) or not observation[
            "channel"
        ].strip():
            raise ValueError("telemetry observation channel must be non-empty")
        if observation.get("event_id") is not None and type(
            observation["event_id"]
        ) is not int:
            raise ValueError("telemetry event_id must be an integer or null")
        if observation.get("record_id") is not None and (
            type(observation["record_id"]) is not int
            or observation["record_id"] <= 0
        ):
            raise ValueError("telemetry record_id must be an integer or null")
        if observation.get("timestamp_utc") is not None:
            require_utc(
                observation["timestamp_utc"], "telemetry observation timestamp_utc"
            )
        if observation["state"] == "observed":
            if (
                type(observation.get("record_id")) is not int
                or observation["record_id"] <= 0
            ):
                raise ValueError("observed telemetry requires record_id")
            if "timestamp_utc" not in observation:
                raise ValueError("observed telemetry requires timestamp_utc")

    accounted_expectations = {
        (observation["channel"], observation["event_id"])
        for observation in observations
        if observation["state"] in {
            "observed",
            "missing_expected",
            "not_available",
        }
    }
    for expectation in scenario["expected_telemetry"]:
        identity = (expectation["channel"], expectation["event_id"])
        if identity not in accounted_expectations:
            raise ValueError(
                "every scenario telemetry expectation requires a run observation"
            )

    if not isinstance(record["deviations"], list) or not all(
        isinstance(deviation, str) and deviation.strip()
        for deviation in record["deviations"]
    ):
        raise ValueError("deviations must be a list of non-empty strings")


def valid_ground_truth_record(manifest: dict, scenario_index: int = 0) -> dict:
    """Return synthetic test data; this is never written as execution evidence."""
    scenario = manifest["scenarios"][scenario_index]
    run_id = "12345678-1234-4234-9234-123456789abc"
    inputs, command, cleanup_command = resolve_scenario(scenario, run_id)
    cleanup_required = scenario["cleanup"]["required"]
    telemetry_observations = []
    for index, expectation in enumerate(scenario["expected_telemetry"], start=1):
        telemetry_observations.append(
            {
                "state": "observed",
                "channel": expectation["channel"],
                "event_id": expectation["event_id"],
                "record_id": 12344 + index,
                "timestamp_utc": "2026-08-12T10:00:00Z",
            }
        )
    return {
        "schema_version": 1,
        "run_id": run_id,
        "scenario_id": scenario["scenario_id"],
        "alert2ir_commit": "a" * 40,
        "operator_role": "lab-admin",
        "endpoint": {
            "inventory_name": "win11-02",
            "computer_name": "WIN11-02",
            "host_only_ipv4": "192.168.56.62",
            "interface": "Ethernet",
        },
        "source_provenance": {
            "technique_id": scenario["technique_id"],
            "atomic_guid": scenario["atomic_guid"],
            "atomic_commit": manifest["atomic_source"]["commit"],
            "definition_path": scenario["definition"]["path"],
            "definition_sha256": scenario["definition"]["sha256"],
        },
        "execution": {
            "executable": scenario["executor"]["executable"],
            "executor": scenario["executor"]["name"],
            "actual_elevated": True,
            "inputs": inputs,
            "command": command,
            "start_utc": "2026-08-12T10:00:00Z",
            "end_utc": "2026-08-12T10:00:01Z",
            "exit_code": 0,
            "result": "succeeded",
        },
        "prerequisite": {"status": "not_required", "details": "None declared."},
        "clock_evidence": {
            "dev01_before_utc": "2026-08-12T09:59:58Z",
            "endpoint_utc": "2026-08-12T09:59:59Z",
            "dev01_after_utc": "2026-08-12T10:00:00Z",
        },
        "preflight": {"status": "passed", "checks": ["identity"]},
        "cleanup": {
            "required": cleanup_required,
            "command": cleanup_command,
            "result": "succeeded" if cleanup_required else "not_required",
            "independently_verified": cleanup_required,
        },
        "post_state_verification": {
            "status": "verified" if cleanup_required else "not_applicable",
            "details": (
                "The target is absent."
                if cleanup_required
                else "No cleanup or post-state verification is required."
            ),
        },
        "telemetry_window": {
            "start_utc": "2026-08-12T09:59:55Z",
            "end_utc": "2026-08-12T10:00:06Z",
        },
        "telemetry_observations": telemetry_observations,
        "deviations": [],
    }


class AttackSimulationScenarioContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_manifest()
        cls.scenarios = {
            scenario["scenario_id"]: scenario
            for scenario in cls.manifest["scenarios"]
        }

    def test_manifest_schema_and_atomic_source_are_frozen(self) -> None:
        self.assertEqual(self.manifest["schema_version"], 1)
        self.assertEqual(
            self.manifest["atomic_source"],
            {"repository": ATOMIC_REPOSITORY, "commit": ATOMIC_COMMIT},
        )

    def test_only_the_three_approved_unique_scenarios_exist(self) -> None:
        scenario_ids = [
            scenario["scenario_id"] for scenario in self.manifest["scenarios"]
        ]
        self.assertEqual(len(scenario_ids), len(set(scenario_ids)))
        self.assertEqual(set(scenario_ids), set(EXPECTED_SCENARIOS))

    def test_atomic_guids_are_unique_valid_uuids(self) -> None:
        guids = [scenario["atomic_guid"] for scenario in self.scenarios.values()]
        self.assertEqual(len(guids), len(set(guids)))
        for guid in guids:
            with self.subTest(guid=guid):
                self.assertEqual(str(UUID(guid)), guid)

    def test_frozen_atomic_provenance_matches_each_scenario(self) -> None:
        for scenario_id, expected in EXPECTED_SCENARIOS.items():
            with self.subTest(scenario_id=scenario_id):
                scenario = self.scenarios[scenario_id]
                self.assertEqual(scenario["technique_id"], expected["technique_id"])
                self.assertEqual(scenario["atomic_guid"], expected["atomic_guid"])
                self.assertEqual(
                    scenario["atomic_test_name"], expected["atomic_test_name"]
                )
                self.assertEqual(
                    scenario["definition"],
                    {
                        "path": expected["definition_path"],
                        "sha256": expected["definition_sha256"],
                    },
                )
                self.assertRegex(scenario["definition"]["sha256"], r"^[0-9a-f]{64}$")

    def test_platform_executor_and_elevation_match_pinned_tests(self) -> None:
        for scenario_id, expected in EXPECTED_SCENARIOS.items():
            with self.subTest(scenario_id=scenario_id):
                scenario = self.scenarios[scenario_id]
                self.assertEqual(scenario["platform"], "windows")
                self.assertEqual(scenario["executor"]["name"], expected["executor"])
                self.assertEqual(
                    scenario["executor"]["executable"], expected["executable"]
                )
                self.assertIs(
                    scenario["executor"]["elevation_required"],
                    expected["elevation_required"],
                )

    def test_all_green_safety_flags_are_explicit_and_false(self) -> None:
        for scenario in self.scenarios.values():
            with self.subTest(scenario_id=scenario["scenario_id"]):
                self.assertEqual(set(scenario["safety"]), SAFETY_FLAGS)
                self.assertTrue(
                    all(value is False for value in scenario["safety"].values())
                )

    def test_no_scenario_requires_or_allows_prerequisite_acquisition(self) -> None:
        for scenario in self.scenarios.values():
            with self.subTest(scenario_id=scenario["scenario_id"]):
                self.assertEqual(
                    scenario["prerequisites"],
                    {"required": False, "acquisition_allowed": False},
                )

    def test_tasklist_contract_is_exact_and_has_no_cleanup(self) -> None:
        scenario = self.scenarios[
            "alert2ir.ws07.windows.process-discovery-tasklist.v1"
        ]
        self.assertEqual(scenario["inputs"], {})
        self.assertEqual(scenario["executor"]["command_template"], "tasklist")
        self.assertIsNone(scenario["executor"]["cleanup_command_template"])
        self.assertFalse(scenario["cleanup"]["required"])
        self.assertFalse(scenario["effects"]["persistent_host_effect"])

    def test_powershell_contract_preserves_exact_benign_encoded_command(self) -> None:
        scenario = self.scenarios[
            "alert2ir.ws07.windows.powershell-command.v1"
        ]
        self.assertEqual(
            scenario["executor"]["command_template"],
            "powershell.exe -e  #{obfuscated_code}",
        )
        self.assertEqual(
            scenario["inputs"]["obfuscated_code"],
            "JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkAIAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcASAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIAIgArACIAbwBtACAAUAAiACsAIgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwAbAAhACcAIgApAA==",
        )
        decoded = base64.b64decode(
            scenario["inputs"]["obfuscated_code"], validate=True
        ).decode("utf-16le")
        self.assertEqual(decoded, POWERSHELL_DECODED_SCRIPT)
        command = scenario["executor"]["command_template"].lower()
        self.assertNotIn("executionpolicy", command)
        self.assertNotIn("bypass", command)
        self.assertIsNone(scenario["executor"]["cleanup_command_template"])
        self.assertFalse(scenario["cleanup"]["required"])

    def test_file_scenario_is_run_unique_temp_scoped_and_same_path_cleanup(self) -> None:
        scenario = self.scenarios[
            "alert2ir.ws07.windows.cmd-file-write.v1"
        ]
        target = scenario["inputs"]["file_contents_path"]
        self.assertEqual(target, FILE_PATH_TEMPLATE)
        self.assertTrue(target.startswith("C:\\Windows\\Temp\\"))
        self.assertIn("${run_id}", target)
        self.assertNotIn("*", target)
        self.assertNotIn("..", target)
        self.assertEqual(scenario["inputs"]["message"], FILE_MESSAGE_TEMPLATE)
        self.assertEqual(
            scenario["executor"]["command_template"],
            'echo "#{message}" > "#{file_contents_path}" & type "#{file_contents_path}"',
        )
        self.assertEqual(
            scenario["executor"]["cleanup_command_template"],
            'del "#{file_contents_path}" >nul 2>&1',
        )
        self.assertIn(
            "#{file_contents_path}", scenario["executor"]["command_template"]
        )
        self.assertIn(
            "#{file_contents_path}",
            scenario["executor"]["cleanup_command_template"],
        )
        self.assertEqual(
            scenario["pre_state"],
            ["The resolved file_contents_path must not exist."],
        )
        self.assertEqual(scenario["post_cleanup"], scenario["pre_state"])
        self.assertTrue(scenario["cleanup"]["required"])

    def test_file_resolution_rejects_paths_and_placeholders_outside_v1(self) -> None:
        scenario = self.scenarios[FILE_SCENARIO_ID]
        run_id = "12345678-1234-4234-9234-123456789abc"
        inputs, command, cleanup = resolve_scenario(scenario, run_id)
        resolved_path = (
            r"C:\Windows\Temp\Alert2IR-WS07-"
            "12345678-1234-4234-9234-123456789abc.bin"
        )
        self.assertEqual(inputs["file_contents_path"], resolved_path)
        self.assertIn(f'\"{resolved_path}\"', command)
        self.assertEqual(cleanup, f'del "{resolved_path}" >nul 2>&1')

        mutations = {
            "wildcard": r"C:\Windows\Temp\*.bin",
            "traversal": r"C:\Windows\Temp\..\outside.bin",
            "different parent": r"C:\Temp\Alert2IR-WS07-${run_id}.bin",
            "unresolved dollar": r"C:\Windows\Temp\${other}.bin",
            "unresolved atomic": r"C:\Windows\Temp\#{other}.bin",
        }
        for label, path in mutations.items():
            with self.subTest(label=label):
                candidate = deepcopy(scenario)
                candidate["inputs"]["file_contents_path"] = path
                with self.assertRaises(ValueError):
                    resolve_scenario(candidate, run_id)

        candidate = deepcopy(scenario)
        candidate["executor"]["cleanup_command_template"] = (
            'del "C:\\Windows\\Temp\\different.bin" >nul 2>&1'
        )
        with self.assertRaisesRegex(ValueError, "cleanup"):
            resolve_scenario(candidate, run_id)

    def test_expected_local_telemetry_is_detection_neutral(self) -> None:
        tasklist = self.scenarios[
            "alert2ir.ws07.windows.process-discovery-tasklist.v1"
        ]
        powershell = self.scenarios[
            "alert2ir.ws07.windows.powershell-command.v1"
        ]
        file_write = self.scenarios[
            "alert2ir.ws07.windows.cmd-file-write.v1"
        ]

        self.assertEqual(
            tasklist["expected_telemetry"],
            [
                {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": 1,
                    "category": "process_creation",
                    "expectation": "expected",
                }
            ],
        )
        self.assertEqual(
            powershell["expected_telemetry"][0],
            {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "category": "process_creation",
                "expectation": "expected",
            },
        )
        self.assertEqual(
            powershell["expected_telemetry"][1],
            {
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "event_id": None,
                "category": "powershell_operational_activity",
                "expectation": "non_guaranteed",
                "reason": (
                    "Comprehensive Script Block Logging is not established on "
                    "the endpoints."
                ),
            },
        )
        self.assertEqual(
            file_write["expected_telemetry"],
            [
                {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": 1,
                    "category": "process_creation",
                    "expectation": "expected",
                },
                {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": 11,
                    "category": "file_create",
                    "expectation": "expected",
                },
                {
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "event_id": 26,
                    "category": "file_delete_detected",
                    "expectation": "expected",
                },
            ],
        )
        for scenario in self.scenarios.values():
            for expectation in scenario["expected_telemetry"]:
                self.assertNotEqual(expectation.get("event_id"), 4688)

    def test_scenario_fields_exclude_ws08_and_ws09_concerns(self) -> None:
        reject_forbidden_fields(self.manifest)


class GroundTruthRecordContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_manifest()

    def setUp(self) -> None:
        self.record = valid_ground_truth_record(self.manifest)

    def test_repository_ground_truth_records_satisfy_contract(self) -> None:
        record_directory = REPOSITORY_ROOT / "validation" / "attack-simulation"
        record_paths = sorted(record_directory.glob("*.json"))
        actual_record_names = {record_path.name for record_path in record_paths}
        self.assertTrue(EXPECTED_WS07_CANARY_RECORDS <= actual_record_names)
        for record_path in record_paths:
            with self.subTest(record=record_path.name):
                with record_path.open(encoding="utf-8") as record_file:
                    record = json.load(record_file)
                validate_ground_truth_record(record, self.manifest)
                self.assertEqual(record_path.stem, record["run_id"])

    def test_valid_record_and_elevated_actual_context_are_accepted(self) -> None:
        scenario = self.manifest["scenarios"][0]
        self.assertFalse(scenario["executor"]["elevation_required"])
        self.assertTrue(self.record["execution"]["actual_elevated"])
        validate_ground_truth_record(self.record, self.manifest)

    def test_invalid_run_uuid_is_rejected(self) -> None:
        for invalid in (
            "not-a-uuid",
            "12345678-1234-4234-9234-123456789ABC",
        ):
            with self.subTest(invalid=invalid):
                record = deepcopy(self.record)
                record["run_id"] = invalid
                with self.assertRaisesRegex(ValueError, "run_id"):
                    validate_ground_truth_record(record, self.manifest)

    def test_unknown_scenario_id_is_rejected(self) -> None:
        self.record["scenario_id"] = "alert2ir.ws07.windows.unknown.v1"
        with self.assertRaisesRegex(ValueError, "scenario_id"):
            validate_ground_truth_record(self.record, self.manifest)

    def test_alert2ir_commit_must_be_full_lowercase_hex(self) -> None:
        for invalid in ("a" * 39, "A" * 40, "not-a-git-sha"):
            with self.subTest(invalid=invalid):
                record = deepcopy(self.record)
                record["alert2ir_commit"] = invalid
                with self.assertRaisesRegex(ValueError, "alert2ir_commit"):
                    validate_ground_truth_record(record, self.manifest)

    def test_execution_clock_and_telemetry_timestamps_must_be_utc(self) -> None:
        timestamp_locations = (
            ("execution", "start_utc"),
            ("clock_evidence", "endpoint_utc"),
            ("telemetry_window", "end_utc"),
        )
        for section, field in timestamp_locations:
            with self.subTest(section=section, field=field):
                record = deepcopy(self.record)
                record[section][field] = "2026-08-12T11:00:00+01:00"
                with self.assertRaisesRegex(ValueError, "UTC"):
                    validate_ground_truth_record(record, self.manifest)

    def test_actual_elevation_must_be_boolean(self) -> None:
        self.record["execution"]["actual_elevated"] = "true"
        with self.assertRaisesRegex(ValueError, "actual_elevated"):
            validate_ground_truth_record(self.record, self.manifest)

    def test_operator_role_is_the_non_sensitive_project_role(self) -> None:
        self.record["operator_role"] = "personal-user"
        with self.assertRaisesRegex(ValueError, "operator_role"):
            validate_ground_truth_record(self.record, self.manifest)

    def test_execution_executable_must_match_the_scenario(self) -> None:
        self.record["execution"]["executable"] = r"C:\Windows\System32\powershell.exe"
        with self.assertRaisesRegex(ValueError, "execution.executable"):
            validate_ground_truth_record(self.record, self.manifest)

    def test_resolved_inputs_and_command_must_match_the_scenario(self) -> None:
        self.record["execution"]["command"] = "hostname"
        with self.assertRaisesRegex(ValueError, "execution.command"):
            validate_ground_truth_record(self.record, self.manifest)

    def test_file_cleanup_must_use_the_exact_resolved_target(self) -> None:
        record = valid_ground_truth_record(self.manifest, scenario_index=2)
        validate_ground_truth_record(record, self.manifest)
        record["cleanup"]["command"] = "del unrelated.bin"
        with self.assertRaisesRegex(ValueError, "exact resolved command"):
            validate_ground_truth_record(record, self.manifest)

    def test_endpoint_fields_are_required(self) -> None:
        del self.record["endpoint"]["computer_name"]
        with self.assertRaisesRegex(ValueError, "endpoint.*missing"):
            validate_ground_truth_record(self.record, self.manifest)

    def test_endpoint_ipv4_and_identity_tuple_are_validated(self) -> None:
        invalid_ip = deepcopy(self.record)
        invalid_ip["endpoint"]["host_only_ipv4"] = "999.999.999.999"
        with self.assertRaisesRegex(ValueError, "IPv4"):
            validate_ground_truth_record(invalid_ip, self.manifest)

        mismatched = deepcopy(self.record)
        mismatched["endpoint"]["computer_name"] = "WIN11-01"
        with self.assertRaisesRegex(ValueError, "approved WS07 Windows identity"):
            validate_ground_truth_record(mismatched, self.manifest)

        win11_01 = deepcopy(self.record)
        win11_01["endpoint"] = {
            "inventory_name": "win11-01",
            "computer_name": "WIN11-01",
            "host_only_ipv4": "192.168.56.60",
            "interface": "Ethernet",
        }
        validate_ground_truth_record(win11_01, self.manifest)

    def test_no_prerequisite_scenarios_require_not_required_status(self) -> None:
        for status in ("satisfied", "failed", "blocked"):
            with self.subTest(status=status):
                record = deepcopy(self.record)
                record["prerequisite"]["status"] = status
                with self.assertRaisesRegex(ValueError, "not_required"):
                    validate_ground_truth_record(record, self.manifest)

    def test_cleanup_result_vocabulary_is_constrained(self) -> None:
        self.record["cleanup"]["result"] = "clean-ish"
        with self.assertRaisesRegex(ValueError, "cleanup"):
            validate_ground_truth_record(self.record, self.manifest)

    def test_cleanup_and_post_state_combinations_are_consistent(self) -> None:
        file_record = valid_ground_truth_record(self.manifest, scenario_index=2)
        validate_ground_truth_record(file_record, self.manifest)

        failed = deepcopy(file_record)
        failed["cleanup"]["result"] = "failed"
        failed["cleanup"]["independently_verified"] = False
        failed["post_state_verification"]["status"] = "failed"
        validate_ground_truth_record(failed, self.manifest)

        contradictions = []
        candidate = deepcopy(file_record)
        candidate["cleanup"]["independently_verified"] = False
        contradictions.append(candidate)
        candidate = deepcopy(file_record)
        candidate["cleanup"]["result"] = "failed"
        candidate["post_state_verification"]["status"] = "verified"
        contradictions.append(candidate)
        candidate = deepcopy(file_record)
        candidate["cleanup"]["result"] = "failed"
        candidate["cleanup"]["independently_verified"] = True
        candidate["post_state_verification"]["status"] = "failed"
        contradictions.append(candidate)
        candidate = deepcopy(self.record)
        candidate["cleanup"]["independently_verified"] = True
        contradictions.append(candidate)
        candidate = deepcopy(self.record)
        candidate["post_state_verification"]["status"] = "verified"
        contradictions.append(candidate)

        for candidate in contradictions:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                validate_ground_truth_record(candidate, self.manifest)

    def test_telemetry_observation_states_are_constrained(self) -> None:
        self.record["telemetry_observations"][0]["state"] = "expected"
        with self.assertRaisesRegex(ValueError, "observation state"):
            validate_ground_truth_record(self.record, self.manifest)

    def test_unsanitized_telemetry_fields_are_rejected(self) -> None:
        self.record["telemetry_observations"][0]["event_body"] = "raw XML"
        with self.assertRaisesRegex(ValueError, "unexpected fields"):
            validate_ground_truth_record(self.record, self.manifest)

    def test_every_expected_telemetry_item_must_be_accounted_for(self) -> None:
        record = valid_ground_truth_record(self.manifest, scenario_index=2)
        record["telemetry_observations"] = record["telemetry_observations"][:-1]
        with self.assertRaisesRegex(ValueError, "every scenario telemetry"):
            validate_ground_truth_record(record, self.manifest)

        record = valid_ground_truth_record(self.manifest, scenario_index=2)
        record["telemetry_observations"][0] = {
            "state": "missing_expected",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": 1,
        }
        record["telemetry_observations"][1] = {
            "state": "not_available",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": 11,
        }
        record["telemetry_observations"].append(
            {
                "state": "unexpected",
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 99,
            }
        )
        validate_ground_truth_record(record, self.manifest)

    def test_observed_telemetry_requires_correlation_reference(self) -> None:
        for missing in ("record_id", "timestamp_utc"):
            with self.subTest(missing=missing):
                record = deepcopy(self.record)
                del record["telemetry_observations"][0][missing]
                with self.assertRaisesRegex(ValueError, "observed telemetry"):
                    validate_ground_truth_record(record, self.manifest)

    def test_v1_record_objects_reject_unexpected_fields(self) -> None:
        mutations = (
            ((), "unexpected_top"),
            (("endpoint",), "unexpected_endpoint"),
            (("source_provenance",), "unexpected_provenance"),
            (("execution",), "unexpected_execution"),
            (("prerequisite",), "unexpected_prerequisite"),
            (("clock_evidence",), "unexpected_clock"),
            (("preflight",), "unexpected_preflight"),
            (("cleanup",), "unexpected_cleanup"),
            (("post_state_verification",), "unexpected_post_state"),
            (("telemetry_window",), "unexpected_window"),
        )
        for path, field in mutations:
            with self.subTest(path=path, field=field):
                record = deepcopy(self.record)
                target = record
                for component in path:
                    target = target[component]
                target[field] = "not allowed"
                with self.assertRaisesRegex(ValueError, "unexpected fields"):
                    validate_ground_truth_record(record, self.manifest)

    def test_nested_later_workstream_variants_are_rejected_by_closed_objects(self) -> None:
        mutations = (
            ("execution", "splunk_search_text"),
            ("source_provenance", "sigma_rule_id"),
            ("endpoint", "velociraptor_collection"),
        )
        for container, field in mutations:
            with self.subTest(container=container, field=field):
                record = deepcopy(self.record)
                record[container][field] = "out of scope"
                with self.assertRaisesRegex(ValueError, "unexpected fields"):
                    validate_ground_truth_record(record, self.manifest)

        nested_values = (
            ("prerequisite", "details", {"splunk_search_text": "out of scope"}),
            ("preflight", "checks", [{"sigma_rule_id": "out of scope"}]),
            (
                "post_state_verification",
                "details",
                {"velociraptor_collection": "out of scope"},
            ),
        )
        for container, field, value in nested_values:
            with self.subTest(container=container, field=field):
                record = deepcopy(self.record)
                record[container][field] = value
                with self.assertRaises(ValueError):
                    validate_ground_truth_record(record, self.manifest)

        validate_ground_truth_record(self.record, self.manifest)

    def test_forbidden_ws08_and_ws09_fields_are_rejected(self) -> None:
        for forbidden in sorted(FORBIDDEN_WS08_WS09_FIELDS):
            with self.subTest(forbidden=forbidden):
                record = deepcopy(self.record)
                record[forbidden] = "out of scope"
                with self.assertRaisesRegex(ValueError, "forbidden WS08/WS09"):
                    validate_ground_truth_record(record, self.manifest)


if __name__ == "__main__":
    unittest.main()
