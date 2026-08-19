"""Contracts for the separately installed Sigma translation toolchain.

The ordinary Alert2IR application environment deliberately excludes these
packages. Default discovery records one explained module skip there; the
dedicated Sigma environment executes every contract below.
"""

from importlib.metadata import PackageNotFoundError, version
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PIPELINE = (
    REPOSITORY_ROOT
    / "config"
    / "sigma"
    / "pipelines"
    / "alert2ir-splunk-xml-sysmon.yml"
)
BREADTH_PIPELINE = (
    REPOSITORY_ROOT
    / "config"
    / "sigma"
    / "pipelines"
    / "alert2ir-splunk-xml-sysmon-breadth.yml"
)
OBJECTIVES = (
    REPOSITORY_ROOT / "config" / "attack-simulation" / "detection-objectives.json"
)
FIXTURE = (
    REPOSITORY_ROOT
    / "tests"
    / "fixtures"
    / "sigma"
    / "windows-process-creation.yml"
)
UNRELATED_FIXTURE = (
    REPOSITORY_ROOT
    / "tests"
    / "fixtures"
    / "sigma"
    / "windows-file-delete.yml"
)
DELIVERY_VALIDATION_RULE = (
    REPOSITORY_ROOT
    / "detections"
    / "sigma"
    / "validation"
    / "windows"
    / "investigation-delivery-marker.yml"
)
DELIVERY_SAVED_SEARCH = (
    REPOSITORY_ROOT
    / "integrations"
    / "splunk"
    / "alert2ir_delivery"
    / "default"
    / "savedsearches.conf"
)
DETECTION_EVIDENCE_DIRECTORY = REPOSITORY_ROOT / "validation" / "detection"
SIGMA_EXECUTABLE = Path(sys.executable).with_name("sigma")
EXPECTED_VERSIONS = {
    "sigma-cli": "3.1.0",
    "pysigma": "1.5.0",
    "pysigma-backend-splunk": "2.1.0",
}


def installed_version(distribution: str) -> str | None:
    try:
        return version(distribution)
    except PackageNotFoundError:
        return None


INSTALLED_VERSIONS = {
    distribution: installed_version(distribution)
    for distribution in EXPECTED_VERSIONS
}


def setUpModule() -> None:
    if not all(INSTALLED_VERSIONS.values()):
        raise unittest.SkipTest(
            "requires the dedicated environment installed from requirements-sigma.txt"
        )


def run_sigma(*arguments: str) -> bytes:
    environment = os.environ.copy()
    environment.update(
        {
            "LC_ALL": "C.UTF-8",
            "LANG": "C.UTF-8",
            "TZ": "UTC",
            "PYTHONUTF8": "1",
            "PYTHONHASHSEED": "0",
        }
    )
    completed = subprocess.run(
        [str(SIGMA_EXECUTABLE), *arguments],
        cwd=REPOSITORY_ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"sigma command exited {completed.returncode}:\n"
            f"{completed.stderr.decode('utf-8', errors='replace')}"
        )
    return completed.stdout


def convert(
    rule: Path,
    pipeline: Path = PIPELINE,
    *,
    pipeline_check: bool = True,
) -> bytes:
    arguments = [
        "convert",
        "--target",
        "splunk",
        "--pipeline",
        str(pipeline),
    ]
    if pipeline_check:
        arguments.append("--pipeline-check")
    arguments.extend(
        [
            "--format",
            "default",
            "--fail-unsupported",
            "--output",
            "-",
            str(rule),
        ]
    )
    return run_sigma(*arguments)


class SigmaToolchainContractTests(unittest.TestCase):
    def test_approved_direct_versions_are_installed(self) -> None:
        self.assertEqual(INSTALLED_VERSIONS, EXPECTED_VERSIONS)
        self.assertTrue(SIGMA_EXECUTABLE.is_file())

    def test_pipeline_is_the_narrow_approved_mapping(self) -> None:
        import yaml

        pipeline = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))

        self.assertEqual(
            pipeline,
            {
                "name": "Alert2IR Splunk XML Sysmon process creation",
                "priority": 20,
                "allowed_backends": ["splunk"],
                "transformations": [
                    {
                        "id": "alert2ir_splunk_xml_sysmon_process_creation",
                        "type": "add_condition",
                        "conditions": {
                            "source": (
                                "XmlWinEventLog:"
                                "Microsoft-Windows-Sysmon/Operational"
                            ),
                            "sourcetype": "XmlWinEventLog",
                            "EventCode": 1,
                        },
                        "rule_conditions": [
                            {
                                "type": "logsource",
                                "product": "windows",
                                "category": "process_creation",
                            }
                        ],
                    },
                ],
            },
        )
        pipeline_text = PIPELINE.read_text(encoding="utf-8")
        self.assertNotIn("index", pipeline_text.lower())
        self.assertNotIn("host", pipeline_text.lower())

    def test_breadth_pipeline_has_four_non_overlapping_narrow_mappings(self) -> None:
        import yaml

        pipeline = yaml.safe_load(BREADTH_PIPELINE.read_text(encoding="utf-8"))
        self.assertEqual(pipeline["allowed_backends"], ["splunk"])
        expected = {
            "network_connection": 3,
            "file_event": 11,
            "create_stream_hash": 15,
            "dns_query": 22,
        }
        actual = {}
        for transformation in pipeline["transformations"]:
            self.assertEqual(transformation["type"], "add_condition")
            self.assertEqual(len(transformation["rule_conditions"]), 1)
            logsource = transformation["rule_conditions"][0]
            self.assertEqual(logsource["type"], "logsource")
            self.assertEqual(logsource["product"], "windows")
            category = logsource["category"]
            self.assertNotIn(category, actual)
            conditions = transformation["conditions"]
            self.assertEqual(
                conditions["source"],
                "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            )
            self.assertEqual(conditions["sourcetype"], "XmlWinEventLog")
            actual[category] = conditions["EventCode"]
        self.assertEqual(actual, expected)
        pipeline_text = BREADTH_PIPELINE.read_text(encoding="utf-8").lower()
        self.assertNotIn("index", pipeline_text)
        self.assertNotIn("host:", pipeline_text)
        self.assertNotIn("192.168.56", pipeline_text)
        self.assertNotIn("lab.test", pipeline_text)

    def test_fixture_is_canonical_and_contains_only_synthetic_selectors(self) -> None:
        import yaml

        fixture_text = FIXTURE.read_text(encoding="utf-8")
        fixture = yaml.safe_load(fixture_text)

        self.assertEqual(
            fixture["logsource"],
            {"product": "windows", "category": "process_creation"},
        )
        self.assertEqual(
            fixture["detection"]["selection"],
            {
                "Image|endswith": "\\Alert2IRFixture.exe",
                "CommandLine|contains": "--alert2ir-fixture-mode",
            },
        )
        self.assertEqual(fixture["detection"]["condition"], "selection")
        self.assertTrue(
            {"host", "index", "source", "sourcetype", "EventCode"}.isdisjoint(
                fixture.keys()
            )
        )
        lowered = fixture_text.lower()
        for prohibited in (
            "win11-02",
            "index=main",
            "xmlwineventlog",
            "eventcode",
            "internal-milestone",
            "tasklist",
            "powershell",
            "encodedcommand",
        ):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, lowered)

    def test_fixture_passes_sigma_check(self) -> None:
        run_sigma(
            "check",
            "--fail-on-error",
            "--fail-on-issues",
            str(FIXTURE),
        )

    def test_all_active_rules_pass_sigma_check(self) -> None:
        objectives = json.loads(OBJECTIVES.read_text(encoding="utf-8"))
        active_rules = [
            str(REPOSITORY_ROOT / objective["rule_path"])
            for objective in objectives["objectives"]
        ]
        run_sigma(
            "check",
            "--fail-on-error",
            "--fail-on-issues",
            *active_rules,
        )

    def test_translation_contains_required_mapping_and_fixture_fields(self) -> None:
        query = convert(FIXTURE).decode("utf-8")

        for expected in (
            'source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"',
            'sourcetype="XmlWinEventLog"',
            "EventCode=1",
            "Image=",
            "Alert2IRFixture.exe",
            "CommandLine=",
            "--alert2ir-fixture-mode",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, query)
        for prohibited in ("index=main", "host=win11-02", "internal-milestone"):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, query.lower())

    def test_repeated_translation_is_byte_identical(self) -> None:
        first = convert(FIXTURE)
        second = convert(FIXTURE)

        self.assertEqual(first, second)

    def test_delivery_validation_rule_checks_and_matches_saved_search_predicate(self) -> None:
        run_sigma(
            "check",
            "--fail-on-error",
            "--fail-on-issues",
            str(DELIVERY_VALIDATION_RULE),
        )
        first = convert(DELIVERY_VALIDATION_RULE)
        second = convert(DELIVERY_VALIDATION_RULE)
        self.assertEqual(first, second)
        expected = (
            'source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" '
            'sourcetype="XmlWinEventLog" EventCode=1 Image="*\\\\cmd.exe" '
            'CommandLine="*Alert2IR-INVESTIGATE-*"\n'
        )
        self.assertEqual(first.decode("utf-8"), expected)
        saved_search = DELIVERY_SAVED_SEARCH.read_text(encoding="utf-8")
        self.assertIn(
            "search = index=main "
            + expected.rstrip("\n")
            + " | table _time Computer host source sourcetype EventCode "
            "RecordID ProcessGuid Image ParentImage TargetFilename",
            saved_search,
        )

    def test_current_validation_summary_resolves_canonical_rules(self) -> None:
        summary = json.loads(
            (DETECTION_EVIDENCE_DIRECTORY / "validation-summary.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(summary["record_type"], "derived_current_summary")
        self.assertTrue(summary["original_records_preserved_in_git_history"])
        for result in summary["earlier_detection_results"]:
            with self.subTest(rule=result["rule_path"]):
                rule_path = REPOSITORY_ROOT / result["rule_path"]
                self.assertTrue(rule_path.is_file())
                self.assertIn(
                    f'id: {result["rule_id"]}',
                    rule_path.read_text(encoding="utf-8"),
                )

    def test_breadth_rule_translation_is_deterministic_and_event_specific(self) -> None:
        contracts = {
            "detections/sigma/validation/windows/network-connection-host-only.yml": (
                3,
                ("DestinationPort=9997", "Initiated=", "Protocol="),
            ),
            "detections/sigma/validation/windows/file-create-alert2ir-temp.yml": (
                11,
                ("TargetFilename=", "Alert2IR-AttackSimulation-"),
            ),
            "detections/sigma/validation/windows/create-stream-hash-alert2ir-ads.yml": (
                15,
                ("TargetFilename=", "Alert2IR-ADS-", ":Alert2IR-"),
            ),
            "detections/sigma/validation/windows/dns-query-owned-alias.yml": (
                22,
                ("QueryName=", ".alert2ir.test"),
            ),
        }
        common = (
            'source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"',
            'sourcetype="XmlWinEventLog"',
        )
        for relative_path, (event_code, terms) in contracts.items():
            rule = REPOSITORY_ROOT / relative_path
            with self.subTest(rule=relative_path):
                first = convert(rule, BREADTH_PIPELINE)
                second = convert(rule, BREADTH_PIPELINE)
                self.assertEqual(first, second)
                query = first.decode("utf-8")
                for term in (*common, f"EventCode={event_code}", *terms):
                    self.assertIn(term, query)
                for other_event_code in {3, 11, 15, 22} - {event_code}:
                    self.assertNotIn(f"EventCode={other_event_code}", query)

    def test_breadth_pipeline_does_not_transform_unrelated_logsource(self) -> None:
        query = convert(
            UNRELATED_FIXTURE,
            BREADTH_PIPELINE,
            pipeline_check=False,
        ).decode("utf-8")
        self.assertIn("TargetFilename=", query)
        self.assertNotIn("EventCode=", query)
        self.assertNotIn("XmlWinEventLog", query)


if __name__ == "__main__":
    unittest.main()
