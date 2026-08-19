"""Contracts for detection objectives and sanitized validation evidence.

These offline tests inspect durable repository evidence and synthetic v2
contract data only. They do not contact Splunk or execute detections.
"""

from datetime import datetime, timezone
from decimal import Decimal
from hashlib import sha256
import json
from pathlib import Path
import re
import unittest
from uuid import UUID


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DETECTION_EVIDENCE_DIRECTORY = REPOSITORY_ROOT / "validation" / "detection"
SCENARIO_MANIFEST = REPOSITORY_ROOT / "config" / "attack-simulation" / "scenarios.json"
DETECTION_OBJECTIVES = (
    REPOSITORY_ROOT / "config" / "attack-simulation" / "detection-objectives.json"
)
DETECTION_V2_SCHEMA = (
    REPOSITORY_ROOT
    / "config"
    / "attack-simulation"
    / "detection-validation-v2.schema.json"
)
MATCH_CLASSIFICATIONS = {
    "expected_primary",
    "expected_secondary",
    "related_wrapper",
    "unexpected_related",
    "environmental_noise",
    "false_positive",
}
RESULT_STATES = {
    "pass",
    "pass_with_related",
    "fail_missing_primary",
    "fail_control_matched",
    "review_unexpected_match",
    "blocked_telemetry",
}


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as source_file:
        return json.load(source_file, parse_float=Decimal)


def sha256_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


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


class DetectionObjectiveContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_json(SCENARIO_MANIFEST)
        cls.authority = load_json(DETECTION_OBJECTIVES)
        cls.scenarios = {
            scenario["scenario_id"]: scenario
            for scenario in cls.manifest["scenarios"]
        }
        cls.controls = {
            control["control_variant_id"]: control
            for control in cls.manifest["control_variants"]
        }

    def test_each_of_seven_primaries_has_one_unique_objective(self) -> None:
        objectives = self.authority["objectives"]
        self.assertEqual(self.authority["schema_version"], 2)
        self.assertEqual(len(objectives), 7)
        scenario_ids = [objective["positive_scenario_id"] for objective in objectives]
        self.assertEqual(len(scenario_ids), len(set(scenario_ids)))
        self.assertEqual(set(scenario_ids), set(self.scenarios))

        for objective in objectives:
            scenario = self.scenarios[objective["positive_scenario_id"]]
            primary = [
                expectation
                for expectation in scenario["expected_telemetry"]
                if expectation["role"] == "primary"
            ]
            self.assertEqual(len(primary), 1)
            self.assertEqual(objective["primary_expectation_id"], primary[0]["expectation_id"])
            rule_path = REPOSITORY_ROOT / objective["rule_path"]
            self.assertTrue(rule_path.is_file())
            rule_id = re.search(
                r"(?m)^id: ([0-9a-f-]+)$",
                rule_path.read_text(encoding="utf-8"),
            )
            self.assertIsNotNone(rule_id)
            self.assertEqual(objective["rule_id"], rule_id.group(1))
            self.assertTrue((REPOSITORY_ROOT / objective["pipeline_path"]).is_file())
            self.assertIn(objective["content_class"], {"production_intent", "validation_only"})
            self.assertEqual(objective["expected_result"], "attributable_match")

    def test_static_and_live_portfolio_statuses_are_unambiguous(self) -> None:
        self.assertEqual(
            self.authority["status_vocabulary"],
            {
                "static": ["implemented"],
                "live": [
                    "validated_historical",
                    "validated_live",
                    "live_deferred",
                ],
            },
        )
        expected_live_status = {
            "alert2ir.attack-simulation.windows.process-discovery-tasklist.v1": (
                "validated_historical"
            ),
            "alert2ir.attack-simulation.windows.powershell-command.v1": (
                "validated_historical"
            ),
            "alert2ir.attack-simulation.windows.cmd-file-write.v1": "validated_live",
            "alert2ir.tier1.windows.host-only-tcp.v1": "live_deferred",
            "alert2ir.tier1.windows.owned-alias-dns.v1": "live_deferred",
            "alert2ir.tier1.windows.benign-ads.v1": "live_deferred",
            "alert2ir.tier1.windows.script-host-ancestry.v1": "live_deferred",
        }
        objectives = {
            item["positive_scenario_id"]: item
            for item in self.authority["objectives"]
        }
        self.assertEqual(set(objectives), set(expected_live_status))
        for scenario_id, live_status in expected_live_status.items():
            objective = objectives[scenario_id]
            with self.subTest(scenario_id=scenario_id):
                self.assertEqual(objective["static_status"], "implemented")
                self.assertEqual(objective["live_status"], live_status)
                self.assertTrue(objective["live_status_reason"].strip())

        live_validated = [
            scenario_id
            for scenario_id, objective in objectives.items()
            if objective["live_status"] == "validated_live"
        ]
        self.assertEqual(
            live_validated,
            ["alert2ir.attack-simulation.windows.cmd-file-write.v1"],
        )
        self.assertEqual(
            next(
                item["event_id"]
                for item in self.scenarios[live_validated[0]]["expected_telemetry"]
                if item["role"] == "primary"
            ),
            11,
        )

        for scenario_id in (
            "alert2ir.tier1.windows.host-only-tcp.v1",
            "alert2ir.tier1.windows.owned-alias-dns.v1",
            "alert2ir.tier1.windows.benign-ads.v1",
            "alert2ir.tier1.windows.script-host-ancestry.v1",
        ):
            reason = objectives[scenario_id]["live_status_reason"].lower()
            self.assertIn("deferred by project decision", reason)
            self.assertIn("does not permit repository .ps1 execution", reason)
            self.assertIn("will not weaken, bypass", reason)

        dns = objectives["alert2ir.tier1.windows.owned-alias-dns.v1"]
        self.assertEqual(
            dns["live_prerequisites"],
            {"dns_nrpt_infrastructure": "validated_live"},
        )
        self.assertIn("dns/nrpt prerequisite is validated-live", dns["live_status_reason"].lower())

        ancestry = objectives[
            "alert2ir.tier1.windows.script-host-ancestry.v1"
        ]
        self.assertEqual(ancestry["control_static_status"], "implemented")
        self.assertEqual(ancestry["control_live_status"], "live_deferred")
        self.assertEqual(
            ancestry["control_variant_id"],
            "alert2ir.tier1.windows.script-host-ancestry.control-benign-parent.v1",
        )

    def test_file_objective_is_event_11_and_cmd_rule_is_retired_only(self) -> None:
        objective = next(
            item
            for item in self.authority["objectives"]
            if item["positive_scenario_id"]
            == "alert2ir.attack-simulation.windows.cmd-file-write.v1"
        )
        self.assertEqual(objective["primary_expectation_id"], "temporary_file_create")
        primary = next(
            item
            for item in self.scenarios[objective["positive_scenario_id"]]["expected_telemetry"]
            if item["expectation_id"] == objective["primary_expectation_id"]
        )
        self.assertEqual(primary["event_id"], 11)
        self.assertIn("file-create", objective["rule_path"])

        retired = self.authority["retired_rules"]
        self.assertEqual(len(retired), 1)
        retired_rule = retired[0]
        self.assertTrue(retired_rule["retired_from_active_portfolio"])
        self.assertEqual(
            retired_rule["rule_path"],
            "detections/sigma/windows/cmd-temp-file-write-display.yml",
        )
        self.assertNotIn(
            retired_rule["rule_id"],
            {item["rule_id"] for item in self.authority["objectives"]},
        )
        evidence = load_json(REPOSITORY_ROOT / retired_rule["historical_evidence_path"])
        retired_summary = next(
            item
            for item in evidence["earlier_detection_results"]
            if item["rule_id"] == retired_rule["rule_id"]
        )
        self.assertEqual(retired_summary["rule_path"], retired_rule["rule_path"])
        self.assertEqual(evidence["record_type"], "derived_current_summary")
        self.assertIn("contains|all", retired_rule["preserved_semantics"])

    def test_only_ancestry_objective_has_the_one_negative_control(self) -> None:
        controlled = [
            objective
            for objective in self.authority["objectives"]
            if "control_variant_id" in objective
        ]
        self.assertEqual(len(controlled), 1)
        objective = controlled[0]
        self.assertEqual(
            objective["positive_scenario_id"],
            "alert2ir.tier1.windows.script-host-ancestry.v1",
        )
        control_id = objective["control_variant_id"]
        self.assertEqual(set(self.controls), {control_id})
        self.assertEqual(self.controls[control_id]["expected_result"], "zero_attributable_matches")

    def test_validation_only_rules_are_distinguishable_by_path_and_metadata(self) -> None:
        for objective in self.authority["objectives"]:
            in_validation_tree = objective["rule_path"].startswith(
                "detections/sigma/validation/"
            )
            self.assertEqual(
                in_validation_tree,
                objective["content_class"] == "validation_only",
            )


def require_utc_timestamp(value: object, context: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{context} must be a timestamp string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ValueError(f"{context} must be ISO-8601") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{context} must be timezone-aware UTC")
    return parsed


def exact_fields(value: object, expected: set[str], context: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{context} must be a closed object")
    return value


def validate_detection_v2(record: object) -> None:
    """Validate the generalized, relationship-aware future evidence contract."""
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
    if forbidden.intersection({key.lower() for key in nested_strings(record)}):
        raise ValueError("detection v2 contains a forbidden privacy field")
    record = exact_fields(
        record,
        {
            "schema",
            "validation_id",
            "positive_scenario_id",
            "objective",
            "toolchain",
            "ground_truth",
            "searches",
            "matches",
            "control_results",
            "result_state",
        },
        "detection v2",
    )
    if record["schema"] != "alert2ir-detection-validation-v2":
        raise ValueError("detection v2 schema is invalid")
    if str(UUID(record["validation_id"])) != record["validation_id"]:
        raise ValueError("validation_id must be a canonical UUID")
    if record["result_state"] not in RESULT_STATES:
        raise ValueError("result_state is invalid")
    objective = exact_fields(
        record["objective"],
        {
            "primary_expectation_id",
            "rule_path",
            "rule_id",
            "pipeline_path",
            "content_class",
        },
        "detection v2 objective",
    )
    if str(UUID(objective["rule_id"])) != objective["rule_id"]:
        raise ValueError("objective rule_id must be a canonical UUID")
    if not objective["rule_path"].startswith("detections/sigma/"):
        raise ValueError("objective rule_path is invalid")
    if not objective["pipeline_path"].startswith("config/sigma/pipelines/"):
        raise ValueError("objective pipeline_path is invalid")
    if objective["content_class"] not in {"production_intent", "validation_only"}:
        raise ValueError("objective content_class is invalid")
    toolchain = exact_fields(
        record["toolchain"],
        {"sigma_cli", "pysigma", "pysigma_backend_splunk"},
        "detection v2 toolchain",
    )
    if any(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value) is None for value in toolchain.values()):
        raise ValueError("detection v2 toolchain version is invalid")

    ground_truth = exact_fields(
        record["ground_truth"], {"expected_events"}, "detection v2 ground_truth"
    )
    expected_events = {}
    for event in ground_truth["expected_events"]:
        event = exact_fields(
            event,
            {"expectation_id", "event_ref", "role", "phase", "timestamp_utc"},
            "detection v2 expected event",
        )
        if event["event_ref"] in expected_events:
            raise ValueError("expected event references must be unique")
        if event["role"] not in {"primary", "secondary", "cleanup", "related"}:
            raise ValueError("expected event role is invalid")
        if event["phase"] not in {"execution", "investigation_window", "cleanup"}:
            raise ValueError("expected event phase is invalid")
        require_utc_timestamp(event["timestamp_utc"], "expected event timestamp")
        expected_events[event["event_ref"]] = event
    if not expected_events:
        raise ValueError("detection v2 requires expected events")

    searches = {}
    for search in record["searches"]:
        search = exact_fields(
            search,
            {
                "search_id",
                "logsource",
                "event_code",
                "validation_window",
                "environment_scope",
                "referenced_event_refs",
                "generated_spl",
                "executed_spl",
                "hashes",
                "result_count",
                "search_executed_at_utc",
            },
            "detection v2 search",
        )
        if search["search_id"] in searches:
            raise ValueError("search_id values must be unique")
        exact_fields(search["logsource"], {"product", "category"}, "search logsource")
        exact_fields(search["environment_scope"], {"scope_ref", "summary"}, "environment scope")
        window = exact_fields(
            search["validation_window"], {"start_utc", "end_utc"}, "search window"
        )
        window_start = require_utc_timestamp(window["start_utc"], "search window start")
        window_end = require_utc_timestamp(window["end_utc"], "search window end")
        if window_end < window_start:
            raise ValueError("search window end precedes start")
        search_executed_at = require_utc_timestamp(
            search["search_executed_at_utc"], "search_executed_at_utc"
        )
        if search_executed_at < window_end:
            raise ValueError("search execution precedes the validation window end")
        if not search["referenced_event_refs"]:
            raise ValueError("search must reference ground-truth events")
        for event_ref in search["referenced_event_refs"]:
            if event_ref not in expected_events:
                raise ValueError("search references unknown ground-truth event")
            event_time = require_utc_timestamp(
                expected_events[event_ref]["timestamp_utc"], "ground-truth event"
            )
            if not window_start <= event_time <= window_end:
                raise ValueError("search window does not contain ground-truth event")
        hashes = exact_fields(
            search["hashes"],
            {
                "rule_sha256",
                "pipeline_sha256",
                "generated_spl_sha256",
                "executed_spl_sha256",
            },
            "search hashes",
        )
        if any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in hashes.values()):
            raise ValueError("search hash is invalid")
        if hashes["generated_spl_sha256"] != sha256_text(search["generated_spl"]):
            raise ValueError("generated SPL hash mismatch")
        if hashes["executed_spl_sha256"] != sha256_text(search["executed_spl"]):
            raise ValueError("executed SPL hash mismatch")
        if not isinstance(search["result_count"], int) or search["result_count"] < 0:
            raise ValueError("search result_count is invalid")
        searches[search["search_id"]] = search
    if not searches:
        raise ValueError("detection v2 requires searches")

    matches = {}
    match_count_by_search = {search_id: 0 for search_id in searches}
    for match in record["matches"]:
        match = exact_fields(
            match,
            {
                "match_ref",
                "search_id",
                "event_ref",
                "classification",
                "attributable",
                "event_code",
                "timestamp_utc",
            },
            "detection v2 match",
        )
        if match["match_ref"] in matches or match["search_id"] not in searches:
            raise ValueError("match identity or search reference is invalid")
        if match["event_ref"] is not None and match["event_ref"] not in expected_events:
            raise ValueError("match references unknown event")
        if match["classification"] not in MATCH_CLASSIFICATIONS:
            raise ValueError("match classification is invalid")
        require_utc_timestamp(match["timestamp_utc"], "match timestamp")
        matches[match["match_ref"]] = match
        match_count_by_search[match["search_id"]] += 1
    for search_id, count in match_count_by_search.items():
        if searches[search_id]["result_count"] != count:
            raise ValueError("search result_count does not match preserved matches")

    for control in record["control_results"]:
        control = exact_fields(
            control,
            {
                "control_variant_id",
                "control_run_id",
                "search_id",
                "expected_attributable_count",
                "attributable_count",
                "match_refs",
                "result",
            },
            "detection v2 control result",
        )
        if str(UUID(control["control_run_id"])) != control["control_run_id"]:
            raise ValueError("control_run_id must be a canonical UUID")
        if control["search_id"] not in searches or control["expected_attributable_count"] != 0:
            raise ValueError("control search or zero-match expectation is invalid")
        referenced_matches = []
        for match_ref in control["match_refs"]:
            if match_ref not in matches:
                raise ValueError("control references an unknown preserved match")
            if matches[match_ref]["search_id"] != control["search_id"]:
                raise ValueError("control match belongs to another search")
            referenced_matches.append(matches[match_ref])
        attributable_count = sum(match["attributable"] for match in referenced_matches)
        if control["attributable_count"] != attributable_count:
            raise ValueError("control attributable_count is inconsistent")
        if attributable_count > 0 and (
            control["result"] != "fail_control_matched"
            or record["result_state"] != "fail_control_matched"
        ):
            raise ValueError("attributable control match must fail")

    unexpected_attributable = any(
        match["attributable"]
        and match["classification"] in {"unexpected_related", "false_positive"}
        for match in matches.values()
    )
    if unexpected_attributable and record["result_state"] not in {
        "review_unexpected_match",
        "fail_control_matched",
    }:
        raise ValueError("unknown attributable match requires review")
    if record["result_state"] in {"pass", "pass_with_related"} and not any(
        match["attributable"] and match["classification"] == "expected_primary"
        for match in matches.values()
    ):
        raise ValueError("passing positive validation requires an attributable primary")


def valid_detection_v2() -> dict:
    """Return synthetic multi-search/control data; never persist it as evidence."""
    positive_generated = (
        "source=sysmon EventCode=1 ParentImage=*cscript.exe "
        "Image=*powershell.exe CommandLine=*Start-Sleep*\n"
    )
    positive_executed = "scope=positive " + positive_generated.rstrip("\n")
    control_generated = positive_generated
    control_executed = "scope=control " + control_generated.rstrip("\n")
    hashes = lambda generated, executed: {
        "rule_sha256": "a" * 64,
        "pipeline_sha256": "b" * 64,
        "generated_spl_sha256": sha256_text(generated),
        "executed_spl_sha256": sha256_text(executed),
    }
    return {
        "schema": "alert2ir-detection-validation-v2",
        "validation_id": "aaaaaaaa-1234-4234-9234-123456789abc",
        "positive_scenario_id": "alert2ir.tier1.windows.script-host-ancestry.v1",
        "objective": {
            "primary_expectation_id": "ancestry_child_process",
            "rule_path": "detections/sigma/validation/windows/process-creation-script-host-ancestry.yml",
            "rule_id": "d1e4f829-7c81-4e72-b3e9-4acbb72d74ec",
            "pipeline_path": "config/sigma/pipelines/alert2ir-splunk-xml-sysmon.yml",
            "content_class": "validation_only",
        },
        "toolchain": {
            "sigma_cli": "3.1.0",
            "pysigma": "1.5.0",
            "pysigma_backend_splunk": "2.1.0",
        },
        "ground_truth": {
            "expected_events": [
                {
                    "expectation_id": "ancestry_parent_process",
                    "event_ref": "event-positive-parent",
                    "role": "secondary",
                    "phase": "execution",
                    "timestamp_utc": "2026-08-17T10:00:05Z",
                },
                {
                    "expectation_id": "ancestry_child_process",
                    "event_ref": "event-positive-child",
                    "role": "primary",
                    "phase": "execution",
                    "timestamp_utc": "2026-08-17T10:00:06Z",
                },
                {
                    "expectation_id": "control_child_process",
                    "event_ref": "event-control-child",
                    "role": "primary",
                    "phase": "execution",
                    "timestamp_utc": "2026-08-17T10:05:06Z",
                },
            ]
        },
        "searches": [
            {
                "search_id": "search-positive",
                "logsource": {"product": "windows", "category": "process_creation"},
                "event_code": 1,
                "validation_window": {
                    "start_utc": "2026-08-17T10:00:00Z",
                    "end_utc": "2026-08-17T10:00:30Z",
                },
                "environment_scope": {
                    "scope_ref": "scope-owned-canary",
                    "summary": "Bounded owned-lab positive run scope.",
                },
                "referenced_event_refs": ["event-positive-parent", "event-positive-child"],
                "generated_spl": positive_generated,
                "executed_spl": positive_executed,
                "hashes": hashes(positive_generated, positive_executed),
                "result_count": 1,
                "search_executed_at_utc": "2026-08-17T10:01:00Z",
            },
            {
                "search_id": "search-control",
                "logsource": {"product": "windows", "category": "process_creation"},
                "event_code": 1,
                "validation_window": {
                    "start_utc": "2026-08-17T10:05:00Z",
                    "end_utc": "2026-08-17T10:05:30Z",
                },
                "environment_scope": {
                    "scope_ref": "scope-owned-canary-control",
                    "summary": "Independent bounded owned-lab control run scope.",
                },
                "referenced_event_refs": ["event-control-child"],
                "generated_spl": control_generated,
                "executed_spl": control_executed,
                "hashes": hashes(control_generated, control_executed),
                "result_count": 1,
                "search_executed_at_utc": "2026-08-17T10:06:00Z",
            },
        ],
        "matches": [
            {
                "match_ref": "match-positive-child",
                "search_id": "search-positive",
                "event_ref": "event-positive-child",
                "classification": "expected_primary",
                "attributable": True,
                "event_code": 1,
                "timestamp_utc": "2026-08-17T10:00:06Z",
            },
            {
                "match_ref": "match-control-noise",
                "search_id": "search-control",
                "event_ref": None,
                "classification": "environmental_noise",
                "attributable": False,
                "event_code": 1,
                "timestamp_utc": "2026-08-17T10:05:20Z",
            },
        ],
        "control_results": [
            {
                "control_variant_id": "alert2ir.tier1.windows.script-host-ancestry.control-benign-parent.v1",
                "control_run_id": "bbbbbbbb-1234-4234-9234-123456789abc",
                "search_id": "search-control",
                "expected_attributable_count": 0,
                "attributable_count": 0,
                "match_refs": ["match-control-noise"],
                "result": "pass",
            }
        ],
        "result_state": "pass",
    }


class DetectionValidationV2ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = load_json(DETECTION_V2_SCHEMA)
        cls.records = {
            path.name: load_json(path)
            for path in sorted(DETECTION_EVIDENCE_DIRECTORY.glob("*.json"))
            if load_json(path).get("schema") == "alert2ir-detection-validation-v2"
        }
        cls.objectives = {
            item["positive_scenario_id"]: item
            for item in load_json(DETECTION_OBJECTIVES)["objectives"]
        }

    def test_schema_is_closed_and_has_generalized_collections(self) -> None:
        self.assertFalse(self.schema["additionalProperties"])
        self.assertTrue(
            {"objective", "toolchain", "ground_truth", "searches", "matches", "control_results", "result_state"}.issubset(
                self.schema["required"]
            )
        )
        self.assertEqual(
            set(
                self.schema["properties"]["matches"]["items"]["properties"][
                    "classification"
                ]["enum"]
            ),
            MATCH_CLASSIFICATIONS,
        )
        self.assertEqual(set(self.schema["properties"]["result_state"]["enum"]), RESULT_STATES)

    def test_multiple_events_searches_and_zero_attributable_control_pass(self) -> None:
        record = valid_detection_v2()
        validate_detection_v2(record)
        self.assertGreater(len(record["ground_truth"]["expected_events"]), 1)
        self.assertGreater(len(record["searches"]), 1)
        self.assertEqual(record["control_results"][0]["attributable_count"], 0)
        for search in record["searches"]:
            start = require_utc_timestamp(search["validation_window"]["start_utc"], "start")
            end = require_utc_timestamp(search["validation_window"]["end_utc"], "end")
            self.assertGreater((end - start).total_seconds(), 1)

    def test_current_tree_uses_an_explicit_sanitized_summary(self) -> None:
        self.assertFalse(self.records)
        summary_path = DETECTION_EVIDENCE_DIRECTORY / "validation-summary.json"
        summary = load_json(summary_path)
        self.assertEqual(summary["record_type"], "derived_current_summary")
        self.assertTrue(summary["original_records_preserved_in_git_history"])
        text = summary_path.read_text(encoding="utf-8").lower()
        for prohibited in (
            "authorization:",
            "bearer ",
            "password",
            "private key",
            "<event xmlns=",
            '"_raw"',
        ):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, text)

    def test_search_chronology_and_timezone_awareness_are_enforced(self) -> None:
        candidate = valid_detection_v2()
        candidate["searches"][0]["validation_window"]["end_utc"] = "2026-08-17T10:00:04Z"
        with self.assertRaisesRegex(ValueError, "does not contain"):
            validate_detection_v2(candidate)
        candidate = valid_detection_v2()
        candidate["searches"][0]["search_executed_at_utc"] = "2026-08-17T10:01:00"
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            validate_detection_v2(candidate)
        candidate = valid_detection_v2()
        candidate["searches"][0]["search_executed_at_utc"] = "2026-08-17T10:00:20Z"
        with self.assertRaisesRegex(ValueError, "precedes"):
            validate_detection_v2(candidate)

    def test_attributable_control_match_fails(self) -> None:
        candidate = valid_detection_v2()
        control_match = candidate["matches"][1]
        control_match["classification"] = "false_positive"
        control_match["attributable"] = True
        candidate["control_results"][0]["attributable_count"] = 1
        with self.assertRaisesRegex(ValueError, "must fail"):
            validate_detection_v2(candidate)
        candidate["control_results"][0]["result"] = "fail_control_matched"
        candidate["result_state"] = "fail_control_matched"
        validate_detection_v2(candidate)

    def test_unknown_attributable_match_requires_review(self) -> None:
        candidate = valid_detection_v2()
        candidate["matches"][0]["classification"] = "unexpected_related"
        with self.assertRaisesRegex(ValueError, "requires review"):
            validate_detection_v2(candidate)
        candidate["result_state"] = "review_unexpected_match"
        validate_detection_v2(candidate)

    def test_privacy_field_is_rejected(self) -> None:
        candidate = valid_detection_v2()
        candidate["matches"][0]["raw_xml"] = "<Event />"
        with self.assertRaisesRegex(ValueError, "privacy"):
            validate_detection_v2(candidate)


if __name__ == "__main__":
    unittest.main()
