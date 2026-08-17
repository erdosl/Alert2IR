"""Repository contracts for attack scenarios and ground-truth evidence.

These offline tests preserve historical v1 records and validate the Tier 1
portfolio plus the future sanitized v2 contract. They do not execute a
scenario, contact a lab system, or manufacture runtime evidence.
"""

import base64
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
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
GROUND_TRUTH_V2_SCHEMA = (
    REPOSITORY_ROOT
    / "config"
    / "attack-simulation"
    / "ground-truth-v2.schema.json"
)
LIVE_ATTESTATION_SCHEMA = (
    REPOSITORY_ROOT
    / "config"
    / "attack-simulation"
    / "live-attestation.schema.json"
)
STAGING_ACL_CONTRACT = (
    REPOSITORY_ROOT
    / "config"
    / "windows"
    / "attack-simulation-staging-acl.json"
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
HISTORICAL_EVIDENCE_SHA256 = {
    "validation/attack-simulation/2c752432-9aa7-4a4d-bdb5-4ffacd2698b7.json": (
        "e16867fd3537b4be94bf3b4717858b9a2e28157c32166d7a88ecf63244c0b800"
    ),
    "validation/attack-simulation/34b43f09-1023-4c5c-8609-03c410bb28a3.json": (
        "a447694d5d76089070545c32495a995167b830567eb643852932dcb42b9d29b1"
    ),
    "validation/attack-simulation/45e78645-170d-4f2c-b158-32fdc89bec8d.json": (
        "7a7778222f7c1a8c93434127b6474cb0b6bf69e5845f097f5dffd6ffb7635340"
    ),
    "validation/detection/t1057-process-discovery-tasklist.json": (
        "034ce4a28b19267119866427ff746694f88a038dbeb03f1736e874409450cdec"
    ),
    "validation/detection/t1059-001-powershell-encoded-command.json": (
        "964ffd0d568b762b803eadbcd77212ea974feb31f6b024cab3afd7c978f74ac6"
    ),
    "validation/detection/t1059-003-cmd-temp-file-write-display.json": (
        "2fe12cd5d25d99a471e34a236af4113029057b6f97bcfe6c19c8f5aaaccbf0c6"
    ),
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
    "network_scope",
    "downloads",
    "c2",
    "credentials",
    "external_target",
    "nat_or_internet_allowed",
    "reboot_required",
    "logoff_required",
    "security_control_change",
    "service_change",
    "account_change",
    "firewall_change",
    "scheduled_task_change",
    "registry_change",
    "persistence",
    "privilege_escalation",
}

EXPECTED_PRIMARY_SCENARIOS = {
    *EXPECTED_SCENARIOS,
    "alert2ir.tier1.windows.host-only-tcp.v1",
    "alert2ir.tier1.windows.owned-alias-dns.v1",
    "alert2ir.tier1.windows.benign-ads.v1",
    "alert2ir.tier1.windows.script-host-ancestry.v1",
}
CONTROL_VARIANT_ID = (
    "alert2ir.tier1.windows.script-host-ancestry.control-benign-parent.v1"
)
VALID_TELEMETRY_ROLES = {"primary", "secondary", "cleanup", "related"}
VALID_TELEMETRY_PHASES = {"execution", "investigation_window", "cleanup"}

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
    scenario_provenance = scenario["provenance"]
    expected_provenance = {
        "technique_id": scenario["technique_id"],
        "atomic_guid": scenario_provenance["test_id"],
        "atomic_commit": scenario_provenance["commit"],
        "definition_path": scenario_provenance["definition_path"],
        "definition_sha256": scenario_provenance["definition_sha256"],
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
            "atomic_guid": scenario["provenance"]["test_id"],
            "atomic_commit": scenario["provenance"]["commit"],
            "definition_path": scenario["provenance"]["definition_path"],
            "definition_sha256": scenario["provenance"]["definition_sha256"],
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
        cls.controls = {
            control["control_variant_id"]: control
            for control in cls.manifest["control_variants"]
        }

    def test_manifest_has_seven_primary_scenarios_and_one_control(self) -> None:
        self.assertEqual(self.manifest["schema_version"], 2)
        self.assertEqual(
            self.manifest["risk_classes"],
            {
                "A": "bounded stateless",
                "B": "uniquely identified reversible temporary state",
                "C": "sensitive state",
            },
        )
        self.assertEqual(set(self.scenarios), EXPECTED_PRIMARY_SCENARIOS)
        self.assertEqual(len(self.scenarios), 7)
        self.assertEqual(set(self.controls), {CONTROL_VARIANT_ID})
        self.assertTrue(
            all(scenario["scenario_kind"] == "primary" for scenario in self.scenarios.values())
        )
        self.assertEqual(self.controls[CONTROL_VARIANT_ID]["scenario_kind"], "negative_control")

    def test_existing_atomic_pins_and_behavior_are_preserved_exactly(self) -> None:
        for scenario_id, expected in EXPECTED_SCENARIOS.items():
            with self.subTest(scenario_id=scenario_id):
                scenario = self.scenarios[scenario_id]
                provenance = scenario["provenance"]
                self.assertEqual(scenario["technique_id"], expected["technique_id"])
                self.assertEqual(scenario["name"], expected["atomic_test_name"])
                self.assertEqual(provenance["kind"], "atomic")
                self.assertEqual(provenance["repository"], ATOMIC_REPOSITORY)
                self.assertEqual(provenance["commit"], ATOMIC_COMMIT)
                self.assertEqual(provenance["test_id"], expected["atomic_guid"])
                self.assertEqual(provenance["definition_path"], expected["definition_path"])
                self.assertEqual(provenance["definition_sha256"], expected["definition_sha256"])
                self.assertNotIn("latest", json.dumps(provenance).lower())

        tasklist = self.scenarios["alert2ir.ws07.windows.process-discovery-tasklist.v1"]
        self.assertEqual(tasklist["executor"]["command_template"], "tasklist")
        powershell = self.scenarios["alert2ir.ws07.windows.powershell-command.v1"]
        self.assertEqual(powershell["executor"]["command_template"], "powershell.exe -e  #{obfuscated_code}")
        decoded = base64.b64decode(
            powershell["inputs"]["obfuscated_code"], validate=True
        ).decode("utf-16le")
        self.assertEqual(decoded, POWERSHELL_DECODED_SCRIPT)
        self.assertNotIn("executionpolicy", powershell["executor"]["command_template"].lower())
        self.assertNotIn("bypass", powershell["executor"]["command_template"].lower())

    def test_historical_ground_truth_and_detection_evidence_bytes_are_immutable(self) -> None:
        for relative_path, expected_hash in HISTORICAL_EVIDENCE_SHA256.items():
            with self.subTest(path=relative_path):
                self.assertEqual(
                    sha256((REPOSITORY_ROOT / relative_path).read_bytes()).hexdigest(),
                    expected_hash,
                )

    def test_local_wrappers_and_reviewed_artifacts_are_hash_pinned(self) -> None:
        local_items = [
            scenario
            for scenario in self.scenarios.values()
            if scenario["provenance"]["kind"] == "alert2ir_local"
        ] + list(self.controls.values())
        self.assertEqual(len(local_items), 5)
        for item in local_items:
            with self.subTest(name=item.get("scenario_id", item.get("control_variant_id"))):
                provenance = item["provenance"]
                self.assertEqual(
                    set(provenance),
                    {
                        "kind",
                        "repository",
                        "definition_path",
                        "definition_sha256",
                        "local_wrapper_version",
                        "local_wrapper_sha256",
                    },
                )
                self.assertNotIn("atomic", json.dumps(provenance).lower())
                wrapper_bytes = (REPOSITORY_ROOT / provenance["definition_path"]).read_bytes()
                wrapper_hash = sha256(wrapper_bytes).hexdigest()
                self.assertEqual(wrapper_hash, provenance["definition_sha256"])
                self.assertEqual(wrapper_hash, provenance["local_wrapper_sha256"])
                self.assertEqual(provenance["local_wrapper_version"], "1")

        ancestry = self.scenarios["alert2ir.tier1.windows.script-host-ancestry.v1"]
        artifact = ancestry["reviewed_artifacts"][0]
        self.assertEqual(
            sha256((REPOSITORY_ROOT / artifact["path"]).read_bytes()).hexdigest(),
            artifact["sha256"],
        )

    def test_risk_and_safety_boundaries_are_explicit(self) -> None:
        for item in [*self.scenarios.values(), *self.controls.values()]:
            item_id = item.get("scenario_id", item.get("control_variant_id"))
            with self.subTest(item=item_id):
                self.assertIn(item["risk_class"], {"A", "B"})
                self.assertNotEqual(item["risk_class"], "C")
                self.assertEqual(set(item["safety"]), SAFETY_FLAGS)
                for flag in (
                    "downloads",
                    "c2",
                    "credentials",
                    "external_target",
                    "nat_or_internet_allowed",
                    "security_control_change",
                    "service_change",
                    "account_change",
                    "firewall_change",
                    "scheduled_task_change",
                    "registry_change",
                    "persistence",
                    "privilege_escalation",
                ):
                    self.assertIs(item["safety"][flag], False)

        networked = {scenario_id for scenario_id, scenario in self.scenarios.items() if scenario["safety"]["requires_network"]}
        self.assertEqual(
            networked,
            {
                "alert2ir.tier1.windows.host-only-tcp.v1",
                "alert2ir.tier1.windows.owned-alias-dns.v1",
            },
        )

    def test_network_scenarios_are_contained_with_explicit_live_prerequisites(self) -> None:
        tcp = self.scenarios["alert2ir.tier1.windows.host-only-tcp.v1"]
        self.assertEqual(tcp["inputs"]["destination_address"], "${approved_host_only_address}")
        self.assertEqual(tcp["inputs"]["destination_port"], "9997")
        self.assertEqual(tcp["network_constraints"]["required_address_range"], "192.168.56.0/24")
        self.assertEqual(tcp["network_constraints"]["required_port"], 9997)
        self.assertEqual(
            set(tcp["network_constraints"]["allowed_destination_addresses"]),
            {f"192.168.56.{last}" for last in range(60, 66)},
        )
        self.assertTrue(tcp["network_constraints"]["requires_existing_approved_listener"])
        self.assertEqual(
            tcp["network_constraints"]["live_acceptance"],
            "target_preflight_passed_live_execution_deferred",
        )

        dns = self.scenarios["alert2ir.tier1.windows.owned-alias-dns.v1"]
        self.assertEqual(dns["inputs"]["query_name"], "splunk.alert2ir.test")
        self.assertEqual(dns["inputs"]["owned_suffix"], ".alert2ir.test")
        self.assertFalse(dns["network_constraints"]["external_resolver_or_target_allowed"])
        self.assertEqual(
            set(dns["network_constraints"]["allowed_answer_addresses"]),
            {f"192.168.56.{last}" for last in range(60, 66)},
        )
        self.assertEqual(
            dns["network_constraints"]["live_acceptance"],
            "dns_infrastructure_validated_live_scenario_execution_deferred",
        )
        for scenario in (tcp, dns):
            text = json.dumps(
                {
                    "executor": scenario["executor"],
                    "inputs": scenario["inputs"],
                    "network_constraints": scenario["network_constraints"],
                }
            ).lower()
            self.assertNotIn("http://", text)
            self.assertNotIn("https://", text)
            self.assertNotIn("download", scenario["executor"]["command_template"].lower())

    def test_local_wrapper_delivery_cannot_work_around_restricted_policy(self) -> None:
        local_items = [
            scenario
            for scenario in self.scenarios.values()
            if scenario["provenance"]["kind"] == "alert2ir_local"
        ] + list(self.controls.values())
        wrapper_directory = REPOSITORY_ROOT / "tools" / "windows" / "attack-simulation"
        self.assertEqual(
            {path.name for path in wrapper_directory.iterdir()},
            {
                "Alert2IR-AncestryChild.vbs",
                "Invoke-Alert2IRBenignAds.ps1",
                "Invoke-Alert2IRHostOnlyTcp.ps1",
                "Invoke-Alert2IROwnedAliasDns.ps1",
                "Invoke-Alert2IRScriptHostAncestry.ps1",
            },
        )
        wrapper_sources = {
            path.name: path.read_text(encoding="utf-8")
            for path in sorted(wrapper_directory.iterdir())
            if path.suffix.lower() in {".ps1", ".vbs"}
        }

        for item in local_items:
            item_id = item.get("scenario_id", item.get("control_variant_id"))
            command = item["executor"]["command_template"]
            wrapper_name = Path(item["provenance"]["definition_path"]).name
            with self.subTest(item=item_id):
                self.assertEqual(command.lower().count(" -file "), 1)
                self.assertIn(rf"AttackSimulation\{wrapper_name}", command)
                self.assertNotIn("executionpolicy", command.lower())
                for field in ("command_template", "cleanup_command_template"):
                    value = item["executor"].get(field)
                    if value is not None:
                        self.assertNotRegex(
                            value.lower(), r"\s-(?:command|encodedcommand)\b"
                        )

        prohibited = (
            r"-executionpolicy\s+(?:bypass|unrestricted)",
            r"set-executionpolicy",
            r"psexecutionpolicypreference",
            r"invoke-expression",
            r"unblock-file",
            r"-encodedcommand\b",
            r"allsigned",
            r"remotesigned",
            r"authenticode",
            r"trustedpublisher",
            r"new-selfsignedcertificate",
            r"set-authenticodesignature",
            r"import-certificate",
            r"(?:currentversion\\powershell|microsoft\\powershell).*executionpolicy",
        )
        for name, source in wrapper_sources.items():
            for pattern in prohibited:
                with self.subTest(wrapper=name, pattern=pattern):
                    self.assertNotRegex(source.lower(), pattern)
        for item in local_items:
            item_id = item.get("scenario_id", item.get("control_variant_id"))
            delivery = json.dumps(item["executor"]).lower()
            for pattern in prohibited:
                with self.subTest(item=item_id, delivery_pattern=pattern):
                    self.assertNotRegex(delivery, pattern)

        # The ancestry behavior has one reviewed inline child command on each
        # positive/control path. It is the detection subject, not wrapper delivery.
        self.assertEqual(
            wrapper_sources["Invoke-Alert2IRScriptHostAncestry.ps1"].count(
                "'-Command'"
            ),
            1,
        )
        self.assertEqual(
            wrapper_sources["Alert2IR-AncestryChild.vbs"].count(" -Command "),
            1,
        )
        for name in (
            "Invoke-Alert2IRHostOnlyTcp.ps1",
            "Invoke-Alert2IROwnedAliasDns.ps1",
            "Invoke-Alert2IRBenignAds.ps1",
        ):
            self.assertNotRegex(wrapper_sources[name], r"(?i)\s-command\b")

        encoded = [
            scenario
            for scenario in self.scenarios.values()
            if "encoded_powershell" in scenario["behavior_class"]
        ]
        self.assertEqual(
            [scenario["scenario_id"] for scenario in encoded],
            ["alert2ir.ws07.windows.powershell-command.v1"],
        )
        self.assertTrue(
            all(scenario["provenance"]["kind"] == "atomic" for scenario in encoded)
        )

    def test_staging_acl_is_a_static_future_hardening_contract(self) -> None:
        contract = json.loads(STAGING_ACL_CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(
            set(contract),
            {"schema_version", "path", "purpose", "desired_acl", "implementation"},
        )
        self.assertEqual(contract["schema_version"], 1)
        self.assertEqual(
            contract["path"], r"C:\ProgramData\Alert2IR\AttackSimulation"
        )
        desired = contract["desired_acl"]
        self.assertEqual(desired["owner"], r"BUILTIN\Administrators")
        self.assertTrue(desired["inheritance_protected"])
        self.assertFalse(desired["preserve_inherited_rules"])
        self.assertFalse(desired["standard_users_may_create_or_replace"])
        self.assertEqual(
            desired["access"],
            [
                {
                    "principal": r"BUILTIN\Administrators",
                    "type": "allow",
                    "rights": "full_control",
                    "applies_to": "this_folder_subfolders_and_files",
                },
                {
                    "principal": r"NT AUTHORITY\SYSTEM",
                    "type": "allow",
                    "rights": "full_control",
                    "applies_to": "this_folder_subfolders_and_files",
                },
                {
                    "principal": r"BUILTIN\Users",
                    "type": "allow",
                    "rights": "read_and_execute",
                    "applies_to": "this_folder_subfolders_and_files",
                },
            ],
        )
        implementation = contract["implementation"]
        self.assertEqual(implementation["repository_contract_status"], "verified_code")
        self.assertEqual(implementation["live_remediation_status"], "not_applied")
        self.assertEqual(
            implementation["owner"],
            "future_separately_authorized_endpoint_hardening",
        )

    def test_local_wrapper_source_enforces_bounded_behavior_and_exact_cleanup(self) -> None:
        wrapper_directory = REPOSITORY_ROOT / "tools" / "windows" / "attack-simulation"
        tcp = (wrapper_directory / "Invoke-Alert2IRHostOnlyTcp.ps1").read_text(encoding="utf-8")
        dns = (wrapper_directory / "Invoke-Alert2IROwnedAliasDns.ps1").read_text(encoding="utf-8")
        ads = (wrapper_directory / "Invoke-Alert2IRBenignAds.ps1").read_text(encoding="utf-8")
        ancestry = (wrapper_directory / "Invoke-Alert2IRScriptHostAncestry.ps1").read_text(encoding="utf-8")
        child = (wrapper_directory / "Alert2IR-AncestryChild.vbs").read_text(encoding="utf-8")

        self.assertEqual(tcp.count("ConnectAsync("), 1)
        self.assertIn("192.168.56.0/24", tcp)
        self.assertIn("LAB_SCOPE.md", tcp)
        self.assertNotIn("Invoke-WebRequest", tcp)
        self.assertNotIn("Download", tcp)

        self.assertEqual(dns.count("Resolve-DnsName"), 1)
        self.assertIn("-Type A", dns)
        self.assertIn("LAB_SCOPE.md", dns)
        self.assertNotIn("Clear-DnsClientCache", dns)
        self.assertNotIn("Set-DnsClient", dns)

        self.assertEqual(ads.count("[System.IO.File]::WriteAllText"), 2)
        self.assertIn("Remove-Item -LiteralPath $BaseFilePath", ads)
        self.assertNotIn("Start-Process", ads)
        self.assertNotIn("Invoke-Expression", ads)

        self.assertIn("Stop-Process -Id $ChildProcessId", ancestry)
        self.assertNotIn("Stop-Process -Name", ancestry)
        self.assertIn("Remove-Item -LiteralPath $ScriptPath", ancestry)
        self.assertIn("$child.CommandLine.Contains($Marker)", ancestry)
        self.assertEqual(child.count("shell.Run("), 1)
        for text in (tcp, dns, ads, ancestry, child):
            lowered = text.lower()
            self.assertNotIn("http://", lowered)
            self.assertNotIn("https://", lowered)
            self.assertNotIn("bitsadmin", lowered)
            self.assertNotIn("certutil", lowered)

    def test_run_identity_and_class_b_cleanup_are_exact(self) -> None:
        class_b = {scenario_id: scenario for scenario_id, scenario in self.scenarios.items() if scenario["risk_class"] == "B"}
        self.assertEqual(
            set(class_b),
            {
                FILE_SCENARIO_ID,
                "alert2ir.tier1.windows.benign-ads.v1",
                "alert2ir.tier1.windows.script-host-ancestry.v1",
            },
        )
        for scenario_id, scenario in class_b.items():
            with self.subTest(scenario_id=scenario_id):
                unique_inputs = scenario["run_identity"]["unique_inputs"]
                self.assertTrue(unique_inputs)
                for name in unique_inputs:
                    self.assertIn(name, scenario["inputs"])
                    self.assertTrue(
                        "${run_id}" in scenario["inputs"][name]
                        or "${control_id}" in scenario["inputs"][name]
                    )
                cleanup = scenario["cleanup"]
                self.assertTrue(cleanup["required"])
                self.assertTrue(cleanup["action_summary"].strip())
                self.assertTrue(cleanup["exact_subjects"])
                self.assertFalse(cleanup["wildcard_allowed"])
                self.assertEqual(
                    cleanup["command_template"],
                    scenario["executor"]["cleanup_command_template"],
                )
                cleanup_text = cleanup["command_template"].lower()
                self.assertNotIn("*", cleanup_text)
                self.assertNotIn("..", cleanup_text)
                self.assertNotIn(" /s ", cleanup_text)
                self.assertNotIn("remove-item c:\\windows\\temp", cleanup_text)
                self.assertTrue(scenario["pre_state"])
                self.assertTrue(scenario["post_cleanup"])

        ads = class_b["alert2ir.tier1.windows.benign-ads.v1"]
        self.assertIn("${run_id}", ads["inputs"]["base_file_path"])
        self.assertIn("${run_id}", ads["inputs"]["stream_name"])
        self.assertNotIn("execute", ads["inputs"]["marker"].lower())

    def test_file_scenario_resolves_to_the_exact_historical_resource(self) -> None:
        scenario = self.scenarios[FILE_SCENARIO_ID]
        self.assertEqual(scenario["inputs"]["file_contents_path"], FILE_PATH_TEMPLATE)
        self.assertEqual(scenario["inputs"]["message"], FILE_MESSAGE_TEMPLATE)
        run_id = "12345678-1234-4234-9234-123456789abc"
        inputs, command, cleanup = resolve_scenario(scenario, run_id)
        resolved_path = rf"C:\Windows\Temp\Alert2IR-WS07-{run_id}.bin"
        self.assertEqual(inputs["file_contents_path"], resolved_path)
        self.assertIn(f'"{resolved_path}"', command)
        self.assertEqual(cleanup, f'del "{resolved_path}" >nul 2>&1')

        candidate = deepcopy(scenario)
        candidate["inputs"]["file_contents_path"] = r"C:\Windows\Temp\*.bin"
        with self.assertRaises(ValueError):
            resolve_scenario(candidate, run_id)
        candidate = deepcopy(scenario)
        candidate["executor"]["cleanup_command_template"] = "del unrelated.bin"
        with self.assertRaisesRegex(ValueError, "cleanup"):
            resolve_scenario(candidate, run_id)

    def test_telemetry_roles_phases_cardinality_and_event_coverage(self) -> None:
        primary_event_ids = {}
        for scenario_id, scenario in self.scenarios.items():
            expectation_ids = [item["expectation_id"] for item in scenario["expected_telemetry"]]
            self.assertEqual(len(expectation_ids), len(set(expectation_ids)))
            primary = [item for item in scenario["expected_telemetry"] if item["role"] == "primary"]
            self.assertEqual(len(primary), 1, scenario_id)
            primary_event_ids[scenario_id] = primary[0]["event_id"]
            for item in scenario["expected_telemetry"]:
                with self.subTest(scenario_id=scenario_id, expectation=item["expectation_id"]):
                    self.assertIn(item["role"], VALID_TELEMETRY_ROLES)
                    self.assertIn(item["phase"], VALID_TELEMETRY_PHASES)
                    self.assertIsInstance(item["min_count"], int)
                    self.assertGreaterEqual(item["min_count"], 0)
                    if item["max_count"] is not None:
                        self.assertGreaterEqual(item["max_count"], item["min_count"])
                    self.assertNotEqual(item["event_id"], 4688)

        self.assertEqual(
            primary_event_ids,
            {
                "alert2ir.ws07.windows.process-discovery-tasklist.v1": 1,
                "alert2ir.ws07.windows.powershell-command.v1": 1,
                FILE_SCENARIO_ID: 11,
                "alert2ir.tier1.windows.host-only-tcp.v1": 3,
                "alert2ir.tier1.windows.owned-alias-dns.v1": 22,
                "alert2ir.tier1.windows.benign-ads.v1": 15,
                "alert2ir.tier1.windows.script-host-ancestry.v1": 1,
            },
        )

    def test_relationships_reference_declared_expectations(self) -> None:
        ancestry = self.scenarios["alert2ir.tier1.windows.script-host-ancestry.v1"]
        expectation_ids = {item["expectation_id"] for item in ancestry["expected_telemetry"]}
        parent_child = [relationship for relationship in ancestry["telemetry_relationships"] if relationship["kind"] == "parent_of"]
        self.assertEqual(len(parent_child), 1)
        self.assertEqual(parent_child[0]["from_expectation_id"], "ancestry_parent_process")
        self.assertEqual(parent_child[0]["to_expectation_id"], "ancestry_child_process")
        for scenario in self.scenarios.values():
            declared = {item["expectation_id"] for item in scenario["expected_telemetry"]}
            for relationship in scenario["telemetry_relationships"]:
                self.assertIn(relationship["from_expectation_id"], declared)
                self.assertIn(relationship["to_expectation_id"], declared)
        self.assertTrue(expectation_ids)

    def test_ancestry_control_is_independent_and_not_a_primary(self) -> None:
        control = self.controls[CONTROL_VARIANT_ID]
        self.assertEqual(
            control["positive_scenario_id"],
            "alert2ir.tier1.windows.script-host-ancestry.v1",
        )
        self.assertEqual(control["expected_result"], "zero_attributable_matches")
        self.assertEqual(control["unexpected_match_policy"], "preserve_and_classify")
        self.assertTrue(control["validation_window"]["must_not_overlap_positive"])
        self.assertEqual(
            control["comparison"]["same_child_image"],
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )
        self.assertNotEqual(
            control["comparison"]["positive_parent_image"],
            control["comparison"]["control_parent_image"],
        )
        self.assertEqual(control["run_identity"]["unique_inputs"], ["control_id", "marker"])

    def test_scenario_fields_remain_detection_and_investigation_neutral(self) -> None:
        reject_forbidden_fields(self.manifest)


def validate_ground_truth_v2(record: object, manifest: dict) -> None:
    """Validate chronology, relationships, cleanup, and privacy for future v2."""
    forbidden = {
        "raw_xml",
        "raw_event_xml",
        "raw_process_inventory",
        "raw_command_output",
        "raw_script_contents",
        "credentials",
        "user_secrets",
        "dns_cache_dump",
        "unrelated_endpoint_state",
    }
    if forbidden.intersection({key.lower() for key in mapping_keys(record)}):
        raise ValueError("ground-truth v2 contains a forbidden privacy field")

    record = require_exact_fields(
        record,
        {
            "schema",
            "run_id",
            "scenario_id",
            "alert2ir_commit",
            "operator_role",
            "endpoint_ref",
            "endpoint",
            "clock_evidence",
            "execution",
            "pre_state",
            "cleanup",
            "post_state_verification",
            "telemetry_window",
            "events",
            "deviations",
        },
        "ground-truth v2",
    )
    if record["schema"] != "alert2ir-ground-truth-v2":
        raise ValueError("ground-truth v2 schema is invalid")
    if str(UUID(record["run_id"])) != record["run_id"]:
        raise ValueError("ground-truth v2 run_id must be canonical")
    scenarios = {scenario["scenario_id"]: scenario for scenario in manifest["scenarios"]}
    if record["scenario_id"] not in scenarios:
        raise ValueError("ground-truth v2 scenario_id is unknown")
    scenario = scenarios[record["scenario_id"]]
    if re.fullmatch(r"[0-9a-f]{40}", record["alert2ir_commit"]) is None:
        raise ValueError("ground-truth v2 alert2ir_commit is invalid")
    if re.fullmatch(r"endpoint-[a-z0-9-]+", record["endpoint_ref"]) is None:
        raise ValueError("endpoint_ref must be a sanitized local reference")
    endpoint = require_exact_fields(
        record["endpoint"],
        {"inventory_name", "computer_name", "host_only_ipv4", "interface"},
        "ground-truth v2 endpoint",
    )
    endpoint_identity = (
        endpoint["inventory_name"],
        endpoint["computer_name"],
        endpoint["host_only_ipv4"],
        endpoint["interface"],
    )
    if endpoint_identity not in APPROVED_ENDPOINTS:
        raise ValueError("ground-truth v2 endpoint is outside the documented inventory")
    clock = require_exact_fields(
        record["clock_evidence"],
        {"operator_before_utc", "endpoint_utc", "operator_after_utc"},
        "ground-truth v2 clock_evidence",
    )
    operator_before = require_utc(
        clock["operator_before_utc"], "clock_evidence.operator_before_utc"
    )
    endpoint_time = require_utc(
        clock["endpoint_utc"], "clock_evidence.endpoint_utc"
    )
    operator_after = require_utc(
        clock["operator_after_utc"], "clock_evidence.operator_after_utc"
    )
    if not operator_before <= endpoint_time <= operator_after:
        raise ValueError("endpoint time is outside the operator clock bracket")

    execution = require_exact_fields(
        record["execution"],
        {"start_utc", "end_utc", "exit_code", "result"},
        "ground-truth v2 execution",
    )
    execution_start = require_utc(execution["start_utc"], "execution.start_utc")
    execution_end = require_utc(execution["end_utc"], "execution.end_utc")
    if execution_end < execution_start:
        raise ValueError("execution end precedes start")

    window = require_exact_fields(
        record["telemetry_window"],
        {"start_utc", "end_utc"},
        "ground-truth v2 telemetry_window",
    )
    window_start = require_utc(window["start_utc"], "telemetry_window.start_utc")
    window_end = require_utc(window["end_utc"], "telemetry_window.end_utc")
    if window_end < window_start:
        raise ValueError("telemetry window end precedes start")

    declared = {
        expectation["expectation_id"]: expectation
        for expectation in scenario["expected_telemetry"]
    }
    events = record["events"]
    if not isinstance(events, list) or not events:
        raise ValueError("ground-truth v2 events must be non-empty")
    event_refs = {event.get("event_ref") for event in events}
    if len(event_refs) != len(events):
        raise ValueError("ground-truth v2 event_ref values must be unique")
    observed_counts = {expectation_id: 0 for expectation_id in declared}
    cleanup_action = record["cleanup"].get("action_at_utc")
    cleanup_time = (
        require_utc(cleanup_action, "cleanup.action_at_utc")
        if cleanup_action is not None
        else None
    )
    for event in events:
        event = require_exact_fields(
            event,
            {
                "expectation_id",
                "event_ref",
                "role",
                "phase",
                "state",
                "channel",
                "event_id",
                "record_id",
                "timestamp_utc",
                "process_ref",
                "parent_process_ref",
                "relationship_to",
            },
            "ground-truth v2 event",
        )
        expectation = declared.get(event["expectation_id"])
        if expectation is None:
            raise ValueError("event references an unknown expectation_id")
        for field in ("role", "phase", "channel", "event_id"):
            if event[field] != expectation[field]:
                raise ValueError(f"event {field} contradicts its expectation")
        if event["state"] not in TELEMETRY_OBSERVATION_STATES:
            raise ValueError("event state is invalid")
        if re.fullmatch(r"event-[a-z0-9-]+", event["event_ref"]) is None:
            raise ValueError("event_ref must be sanitized")
        for process_field in ("process_ref", "parent_process_ref"):
            value = event[process_field]
            if value is not None and re.fullmatch(r"process-[a-z0-9-]+", value) is None:
                raise ValueError(f"{process_field} must be sanitized")
        if event["relationship_to"] is not None and event["relationship_to"] not in event_refs:
            raise ValueError("relationship_to must reference another local event")
        if event["state"] == "observed":
            if not isinstance(event["record_id"], int) or event["record_id"] <= 0:
                raise ValueError("observed event requires a positive record_id")
            timestamp = require_utc(event["timestamp_utc"], "event.timestamp_utc")
            if not window_start <= timestamp <= window_end:
                raise ValueError("telemetry event falls outside telemetry window")
            if event["phase"] == "cleanup" and (
                cleanup_time is None or timestamp < cleanup_time
            ):
                raise ValueError("cleanup event precedes cleanup action")
            observed_counts[event["expectation_id"]] += 1

    for expectation_id, expectation in declared.items():
        count = observed_counts[expectation_id]
        if execution["result"] == "succeeded" and count < expectation["min_count"]:
            raise ValueError("observed cardinality is below min_count")
        maximum = expectation["max_count"]
        if maximum is not None and count > maximum:
            raise ValueError("observed cardinality exceeds max_count")
    if execution["result"] != "succeeded":
        primary_states = {
            event["state"]
            for event in events
            if event["role"] == "primary"
        }
        if not primary_states.intersection({"missing_expected", "not_available"}):
            raise ValueError("failed or blocked execution must preserve missing primary state")
        if not record["deviations"]:
            raise ValueError("failed or blocked execution requires a deviation")

    cleanup = require_exact_fields(
        record["cleanup"],
        {"required", "subject_ref", "action_summary", "action_at_utc", "exit_code", "result"},
        "ground-truth v2 cleanup",
    )
    post_state = require_exact_fields(
        record["post_state_verification"],
        {"status", "checked_at_utc", "subject_ref", "residual_artifact"},
        "ground-truth v2 post_state_verification",
    )
    if scenario["risk_class"] == "B":
        if not record["pre_state"] or not all(
            item.get("status") in {"absent", "known"}
            and item.get("subject_ref")
            and item.get("checked_at_utc")
            for item in record["pre_state"]
        ):
            raise ValueError("Class B evidence requires known pre-state")
        for item in record["pre_state"]:
            checked_at = require_utc(
                item["checked_at_utc"], "pre_state.checked_at_utc"
            )
            if checked_at > execution_start:
                raise ValueError("Class B pre-state was checked after execution began")
        if cleanup["required"] is not True or not cleanup["subject_ref"]:
            raise ValueError("Class B evidence requires exact cleanup subject")
        if not isinstance(cleanup["exit_code"], int):
            raise ValueError("Class B evidence requires cleanup exit status")
        if cleanup["result"] not in {"succeeded", "failed", "blocked"}:
            raise ValueError("Class B cleanup result is invalid")
        if cleanup_time is None or cleanup_time < execution_end:
            raise ValueError("Class B cleanup must follow execution")
        verified_at = require_utc(
            post_state["checked_at_utc"],
            "post_state_verification.checked_at_utc",
        )
        if verified_at < cleanup_time:
            raise ValueError("post-state verification precedes cleanup")
        if post_state["subject_ref"] != cleanup["subject_ref"]:
            raise ValueError("post-state subject must match exact cleanup subject")
        if post_state["residual_artifact"] is True and post_state["status"] not in {
            "failed",
            "review_required",
        }:
            raise ValueError("residual state must fail or require review")


def valid_ground_truth_v2() -> dict:
    """Return synthetic relationship-rich data; never write it as evidence."""
    return {
        "schema": "alert2ir-ground-truth-v2",
        "run_id": "12345678-1234-4234-9234-123456789abc",
        "scenario_id": "alert2ir.tier1.windows.script-host-ancestry.v1",
        "alert2ir_commit": "a" * 40,
        "operator_role": "lab-admin",
        "endpoint_ref": "endpoint-owned-canary",
        "endpoint": {
            "inventory_name": "win11-02",
            "computer_name": "WIN11-02",
            "host_only_ipv4": "192.168.56.62",
            "interface": "Ethernet",
        },
        "clock_evidence": {
            "operator_before_utc": "2026-08-17T09:59:58Z",
            "endpoint_utc": "2026-08-17T09:59:59Z",
            "operator_after_utc": "2026-08-17T10:00:00Z",
        },
        "execution": {
            "start_utc": "2026-08-17T10:00:00Z",
            "end_utc": "2026-08-17T10:00:05Z",
            "exit_code": 0,
            "result": "succeeded",
        },
        "pre_state": [
            {
                "subject_ref": "subject-ancestry-run",
                "status": "absent",
                "checked_at_utc": "2026-08-17T09:59:55Z",
            }
        ],
        "cleanup": {
            "required": True,
            "subject_ref": "subject-ancestry-run",
            "action_summary": "Removed only the exact run-scoped script after the bounded child exited.",
            "action_at_utc": "2026-08-17T10:00:06Z",
            "exit_code": 0,
            "result": "succeeded",
        },
        "post_state_verification": {
            "status": "verified_absent",
            "checked_at_utc": "2026-08-17T10:00:08Z",
            "subject_ref": "subject-ancestry-run",
            "residual_artifact": False,
        },
        "telemetry_window": {
            "start_utc": "2026-08-17T09:59:50Z",
            "end_utc": "2026-08-17T10:00:10Z",
        },
        "events": [
            {
                "expectation_id": "ancestry_parent_process",
                "event_ref": "event-parent",
                "role": "secondary",
                "phase": "execution",
                "state": "observed",
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "record_id": 1001,
                "timestamp_utc": "2026-08-17T10:00:01Z",
                "process_ref": "process-parent",
                "parent_process_ref": "process-wrapper",
                "relationship_to": None,
            },
            {
                "expectation_id": "ancestry_child_process",
                "event_ref": "event-child",
                "role": "primary",
                "phase": "execution",
                "state": "observed",
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "record_id": 1002,
                "timestamp_utc": "2026-08-17T10:00:02Z",
                "process_ref": "process-child",
                "parent_process_ref": "process-parent",
                "relationship_to": "event-parent",
            },
            {
                "expectation_id": "ancestry_script_create",
                "event_ref": "event-script-create",
                "role": "secondary",
                "phase": "execution",
                "state": "observed",
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 11,
                "record_id": 1003,
                "timestamp_utc": "2026-08-17T10:00:00.500000Z",
                "process_ref": "process-wrapper",
                "parent_process_ref": None,
                "relationship_to": None,
            },
            {
                "expectation_id": "ancestry_script_delete",
                "event_ref": "event-script-delete",
                "role": "cleanup",
                "phase": "cleanup",
                "state": "observed",
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 26,
                "record_id": 1004,
                "timestamp_utc": "2026-08-17T10:00:07Z",
                "process_ref": "process-wrapper",
                "parent_process_ref": None,
                "relationship_to": "event-script-create",
            },
        ],
        "deviations": [],
    }


class GroundTruthV2ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_manifest()
        cls.schema = json.loads(GROUND_TRUTH_V2_SCHEMA.read_text(encoding="utf-8"))
        record_directory = REPOSITORY_ROOT / "validation" / "attack-simulation"
        cls.records = {
            path.name: json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(record_directory.glob("*.json"))
            if json.loads(path.read_text(encoding="utf-8")).get("schema")
            == "alert2ir-ground-truth-v2"
        }

    def test_schema_is_closed_and_exposes_required_relationship_fields(self) -> None:
        self.assertFalse(self.schema["additionalProperties"])
        self.assertTrue(
            {"endpoint", "clock_evidence"}.issubset(self.schema["required"])
        )
        event_schema = self.schema["properties"]["events"]["items"]
        self.assertFalse(event_schema["additionalProperties"])
        self.assertTrue(
            {
                "expectation_id",
                "event_ref",
                "role",
                "phase",
                "state",
                "channel",
                "event_id",
                "record_id",
                "timestamp_utc",
                "process_ref",
                "parent_process_ref",
                "relationship_to",
            }.issubset(event_schema["required"])
        )

    def test_valid_multi_event_relationship_and_cleanup_record(self) -> None:
        validate_ground_truth_v2(valid_ground_truth_v2(), self.manifest)

    def test_repository_v2_records_validate_and_are_run_named(self) -> None:
        self.assertTrue(self.records)
        for filename, record in self.records.items():
            with self.subTest(filename=filename):
                validate_ground_truth_v2(record, self.manifest)
                self.assertEqual(filename, f'{record["run_id"]}-v2.json')

    def test_repository_v2_records_remain_sanitized(self) -> None:
        prohibited = (
            "authorization:",
            "bearer ",
            "password",
            "private key",
            "<event xmlns=",
            '"raw_xml"',
            '"raw_command_output"',
        )
        record_directory = REPOSITORY_ROOT / "validation" / "attack-simulation"
        for filename in self.records:
            text = (record_directory / filename).read_text(encoding="utf-8").lower()
            for value in prohibited:
                with self.subTest(filename=filename, value=value):
                    self.assertNotIn(value, text)

    def test_chronology_and_cleanup_order_are_enforced(self) -> None:
        mutations = []
        candidate = valid_ground_truth_v2()
        candidate["execution"]["end_utc"] = "2026-08-17T09:59:59Z"
        mutations.append(candidate)
        candidate = valid_ground_truth_v2()
        candidate["events"][0]["timestamp_utc"] = "2026-08-17T10:01:00Z"
        mutations.append(candidate)
        candidate = valid_ground_truth_v2()
        candidate["events"][-1]["timestamp_utc"] = "2026-08-17T10:00:05Z"
        mutations.append(candidate)
        candidate = valid_ground_truth_v2()
        candidate["post_state_verification"]["checked_at_utc"] = "2026-08-17T10:00:05Z"
        mutations.append(candidate)
        candidate = valid_ground_truth_v2()
        candidate["clock_evidence"]["endpoint_utc"] = "2026-08-17T10:00:01Z"
        mutations.append(candidate)
        for candidate in mutations:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                validate_ground_truth_v2(candidate, self.manifest)

    def test_residual_artifact_requires_failure_or_review(self) -> None:
        candidate = valid_ground_truth_v2()
        candidate["post_state_verification"]["residual_artifact"] = True
        with self.assertRaisesRegex(ValueError, "residual state"):
            validate_ground_truth_v2(candidate, self.manifest)
        candidate["post_state_verification"]["status"] = "review_required"
        validate_ground_truth_v2(candidate, self.manifest)

    def test_privacy_fields_and_raw_identifiers_are_rejected(self) -> None:
        candidate = valid_ground_truth_v2()
        candidate["events"][0]["raw_xml"] = "<Event />"
        with self.assertRaisesRegex(ValueError, "privacy"):
            validate_ground_truth_v2(candidate, self.manifest)
        candidate = valid_ground_truth_v2()
        candidate["events"][0]["process_ref"] = "{raw-process-guid}"
        with self.assertRaisesRegex(ValueError, "sanitized"):
            validate_ground_truth_v2(candidate, self.manifest)


class LiveAcceptanceAttestationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(LIVE_ATTESTATION_SCHEMA.read_text(encoding="utf-8"))
        record_directory = REPOSITORY_ROOT / "validation" / "attack-simulation"
        cls.paths = sorted(record_directory.glob("live-attestation-*.json"))
        cls.records = {
            path.name: json.loads(path.read_text(encoding="utf-8"))
            for path in cls.paths
        }

    def test_schema_and_attestation_objects_are_closed(self) -> None:
        self.assertFalse(self.schema["additionalProperties"])
        for name in ("sysmon", "splunk", "scenario_prerequisites"):
            self.assertFalse(
                self.schema["properties"][name]["additionalProperties"]
            )

    def test_repository_attestation_proves_the_live_prerequisites(self) -> None:
        self.assertEqual(len(self.records), 1)
        record = next(iter(self.records.values()))
        self.assertEqual(record["schema"], "alert2ir-live-attestation-v1")
        self.assertEqual(
            (
                record["endpoint"]["inventory_name"],
                record["endpoint"]["computer_name"],
                record["endpoint"]["host_only_ipv4"],
                record["endpoint"]["interface"],
            ),
            ("win11-02", "WIN11-02", "192.168.56.62", "Ethernet"),
        )
        clock = record["clock_evidence"]
        self.assertLessEqual(
            require_utc(clock["operator_before_utc"], "operator before"),
            require_utc(clock["endpoint_utc"], "endpoint clock"),
        )
        self.assertLessEqual(
            require_utc(clock["endpoint_utc"], "endpoint clock"),
            require_utc(clock["operator_after_utc"], "operator after"),
        )

        policy_hash = sha256(
            (REPOSITORY_ROOT / "config" / "sysmon" / "alert2ir-sysmon.xml").read_bytes()
        ).hexdigest()
        sysmon = record["sysmon"]
        self.assertEqual(sysmon["tracked_policy_sha256"], policy_hash)
        self.assertEqual(sysmon["active_configuration_sha256"], policy_hash)
        self.assertTrue(sysmon["tracked_policy_matches_active"])
        self.assertEqual(sysmon["service_state"], "running")
        self.assertTrue(sysmon["operational_channel_enabled"])
        self.assertEqual(set(sysmon["required_event_ids"]), {1, 3, 11, 15, 22, 26})
        self.assertEqual(sysmon["registry_status"], "excluded")

        splunk = record["splunk"]
        self.assertEqual(splunk["status"], "passed")
        self.assertEqual(splunk["source"], "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")
        self.assertEqual(splunk["sourcetype"], "XmlWinEventLog")
        self.assertGreater(splunk["result_count"], 0)
        window_start = require_utc(splunk["validation_window"]["start_utc"], "window start")
        window_end = require_utc(splunk["validation_window"]["end_utc"], "window end")
        latest = require_utc(splunk["latest_event_utc"], "latest event")
        self.assertLessEqual(window_start, latest)
        self.assertLessEqual(latest, window_end)

        prerequisites = record["scenario_prerequisites"]
        self.assertEqual(prerequisites["tcp_target"]["status"], "passed")
        self.assertEqual(prerequisites["dns_containment"]["status"], "blocked")
        self.assertEqual(
            prerequisites["powershell_wrapper_execution"]["status"], "blocked"
        )

    def test_repository_attestation_is_sanitized(self) -> None:
        for path in self.paths:
            text = path.read_text(encoding="utf-8").lower()
            for prohibited in (
                "authorization:",
                "bearer ",
                "password",
                "token",
                "private key",
                "10.0.2.3",
                "<event xmlns=",
            ):
                with self.subTest(path=path.name, prohibited=prohibited):
                    self.assertNotIn(prohibited, text)


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
            record = json.loads(record_path.read_text(encoding="utf-8"))
            if record.get("schema") in {
                "alert2ir-ground-truth-v2",
                "alert2ir-live-attestation-v1",
            }:
                continue
            with self.subTest(record=record_path.name):
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
