"""Contracts for the separately installed Sigma translation toolchain.

The ordinary Alert2IR application environment deliberately excludes these
packages. Default discovery records one explained module skip there; the
dedicated Sigma environment executes every contract below.
"""

from importlib.metadata import PackageNotFoundError, version
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
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
SIGMA_REQUIREMENTS = REPOSITORY_ROOT / "requirements-sigma.txt"
VALIDATION_DATA = REPOSITORY_ROOT / "config" / "sigma" / "validation-data.json"
PREPARATION_HELPER = (
    REPOSITORY_ROOT / "tools" / "sigma" / "prepare_validation_data.py"
)
NETWORK_GUARD_DIRECTORY = (
    REPOSITORY_ROOT / "tests" / "support" / "sigma_no_network"
)
SIGMA_EXECUTABLE = Path(sys.executable).with_name("sigma")
DIRECT_SIGMA_DISTRIBUTIONS = frozenset(
    {"sigma-cli", "pysigma", "pysigma-backend-splunk"}
)
NETWORK_DENIAL_MESSAGE = "Alert2IR Sigma subprocess attempted network access"
CONTROLLED_SIGMA_HOME: Path | None = None


def load_preparation_helper():
    specification = importlib.util.spec_from_file_location(
        "alert2ir_prepare_validation_data", PREPARATION_HELPER
    )
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load Sigma preparation helper: {PREPARATION_HELPER}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


PREPARE_VALIDATION_DATA = load_preparation_helper()


def exact_sigma_requirement_versions() -> dict[str, str]:
    pins = {}
    for line_number, raw_line in enumerate(
        SIGMA_REQUIREMENTS.read_text(encoding="utf-8").splitlines(), start=1
    ):
        requirement = raw_line.partition("#")[0].strip()
        if not requirement:
            continue
        match = re.fullmatch(
            r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s;]+)", requirement
        )
        if match is None:
            raise RuntimeError(
                f"{SIGMA_REQUIREMENTS}:{line_number} is not an exact == pin"
            )
        distribution = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        if distribution in pins:
            raise RuntimeError(
                f"{SIGMA_REQUIREMENTS}:{line_number} duplicates {distribution}"
            )
        pins[distribution] = match.group(2)
    if set(pins) != DIRECT_SIGMA_DISTRIBUTIONS:
        raise RuntimeError(
            "requirements-sigma.txt must contain exactly the direct Sigma tools "
            f"{sorted(DIRECT_SIGMA_DISTRIBUTIONS)!r}, got {sorted(pins)!r}"
        )
    return pins


EXPECTED_VERSIONS = exact_sigma_requirement_versions()


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
    global CONTROLLED_SIGMA_HOME
    if not all(INSTALLED_VERSIONS.values()):
        raise unittest.SkipTest(
            "requires the dedicated environment installed from requirements-sigma.txt"
        )
    configured_home = os.environ.get("ALERT2IR_SIGMA_HOME")
    if not configured_home:
        message = (
            "requires ALERT2IR_SIGMA_HOME pointing to a cache prepared by "
            "tools/sigma/prepare_validation_data.py"
        )
        if os.environ.get("CI", "").lower() == "true":
            raise RuntimeError(message)
        raise unittest.SkipTest(message)
    CONTROLLED_SIGMA_HOME = Path(configured_home)
    if not CONTROLLED_SIGMA_HOME.is_absolute():
        raise RuntimeError("ALERT2IR_SIGMA_HOME must be an absolute path")
    if not CONTROLLED_SIGMA_HOME.is_dir():
        raise RuntimeError(
            f"ALERT2IR_SIGMA_HOME does not exist: {CONTROLLED_SIGMA_HOME}"
        )


def sigma_subprocess_environment(home: Path | None = None) -> dict[str, str]:
    selected_home = home if home is not None else CONTROLLED_SIGMA_HOME
    if selected_home is None:
        raise RuntimeError("controlled Sigma home has not been configured")
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(selected_home),
            "XDG_CACHE_HOME": str(selected_home / ".cache"),
            "LC_ALL": "C.UTF-8",
            "LANG": "C.UTF-8",
            "TZ": "UTC",
            "PYTHONUTF8": "1",
            "PYTHONHASHSEED": "0",
            "ALERT2IR_SIGMA_DENY_NETWORK": "1",
        }
    )
    python_path = [str(NETWORK_GUARD_DIRECTORY)]
    if environment.get("PYTHONPATH"):
        python_path.append(environment["PYTHONPATH"])
    environment["PYTHONPATH"] = os.pathsep.join(python_path)
    return environment


def run_sigma_completed(
    *arguments: str, home: Path | None = None
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [str(SIGMA_EXECUTABLE), *arguments],
        cwd=REPOSITORY_ROOT,
        env=sigma_subprocess_environment(home),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_sigma(*arguments: str) -> bytes:
    completed = run_sigma_completed(*arguments)
    if completed.returncode != 0:
        raise AssertionError(
            f"sigma command exited {completed.returncode}:\n"
            f"stdout:\n{completed.stdout.decode('utf-8', errors='replace')}\n"
            f"stderr:\n{completed.stderr.decode('utf-8', errors='replace')}"
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
    def test_sigma_direct_versions_are_derived_from_exact_requirements(self) -> None:
        self.assertEqual(set(EXPECTED_VERSIONS), DIRECT_SIGMA_DISTRIBUTIONS)
        self.assertEqual(INSTALLED_VERSIONS, EXPECTED_VERSIONS)
        self.assertTrue(SIGMA_EXECUTABLE.is_file())

    def test_external_validation_data_has_immutable_provenance(self) -> None:
        manifest = PREPARE_VALIDATION_DATA.load_manifest(VALIDATION_DATA)
        self.assertEqual(
            set(manifest),
            {"schema", "datasets"},
        )
        self.assertEqual(
            manifest["schema"], "alert2ir.sigma-validation-data.v1"
        )
        self.assertEqual(
            set(manifest["datasets"]), {"mitre_attack", "mitre_d3fend"}
        )
        attack = manifest["datasets"]["mitre_attack"]
        d3fend = manifest["datasets"]["mitre_d3fend"]
        self.assertRegex(attack["commit"], r"\A[0-9a-f]{40}\Z")
        self.assertNotIn(attack["commit"].lower(), {"master", "main", "latest"})
        self.assertNotIn("url", attack)
        self.assertRegex(attack["sha256"], r"\A[0-9a-f]{64}\Z")
        self.assertRegex(d3fend["sha256"], r"\A[0-9a-f]{64}\Z")
        self.assertGreater(attack["size"], 0)
        self.assertGreater(d3fend["size"], 0)
        self.assertTrue(attack["version"])
        self.assertTrue(d3fend["version"])
        attack_url = PREPARE_VALIDATION_DATA.attack_download_url(attack)
        self.assertIn(f"/{attack['commit']}/", attack_url)
        self.assertNotRegex(attack_url.lower(), r"/(master|main|latest)/")

    def test_validation_data_manifest_rejects_unknown_fields_and_mutable_refs(
        self,
    ) -> None:
        manifest = json.loads(VALIDATION_DATA.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "validation-data.json"
            manifest["unexpected"] = True
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                PREPARE_VALIDATION_DATA.ManifestError,
                r"^Invalid Sigma validation-data manifest:.*unknown fields",
            ):
                PREPARE_VALIDATION_DATA.load_manifest(path)

            del manifest["unexpected"]
            manifest["datasets"]["mitre_attack"]["commit"] = "master"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                PREPARE_VALIDATION_DATA.ManifestError,
                r"^Invalid Sigma validation-data manifest:.*mutable ref",
            ):
                PREPARE_VALIDATION_DATA.load_manifest(path)

            manifest = json.loads(VALIDATION_DATA.read_text(encoding="utf-8"))
            manifest["datasets"]["mitre_d3fend"]["version"] = "current"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                PREPARE_VALIDATION_DATA.ManifestError,
                (
                    r"^Invalid Sigma validation-data manifest: "
                    r"datasets\.mitre_d3fend\.version .*mutable ref"
                ),
            ):
                PREPARE_VALIDATION_DATA.load_manifest(path)

            manifest = json.loads(VALIDATION_DATA.read_text(encoding="utf-8"))
            manifest["datasets"]["mitre_d3fend"]["url"] = (
                "https://d3fend.mitre.org/ontologies/d3fend/current/d3fend.json"
            )
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                PREPARE_VALIDATION_DATA.ManifestError,
                (
                    r"^Invalid Sigma validation-data manifest: "
                    r"datasets\.mitre_d3fend\.url must be the versioned HTTPS"
                ),
            ):
                PREPARE_VALIDATION_DATA.load_manifest(path)

    def test_prepare_validation_data_rejects_hash_mismatch(self) -> None:
        content = b"synthetic Sigma validation data"
        actual_sha256 = hashlib.sha256(content).hexdigest()
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "dataset.json"
            path.write_bytes(content)
            with self.assertRaises(
                PREPARE_VALIDATION_DATA.PreparationError
            ) as size_failure:
                PREPARE_VALIDATION_DATA.verify_dataset_file(
                    "mitre_attack", path, len(content) + 1, actual_sha256
                )
            size_message = str(size_failure.exception)
            self.assertIn("mitre_attack", size_message)
            self.assertIn(f"expected {len(content) + 1}", size_message)
            self.assertIn(f"got {len(content)}", size_message)

            expected_sha256 = "0" * 64
            with self.assertRaises(
                PREPARE_VALIDATION_DATA.PreparationError
            ) as hash_failure:
                PREPARE_VALIDATION_DATA.verify_dataset_file(
                    "mitre_attack", path, len(content), expected_sha256
                )
            hash_message = str(hash_failure.exception)
            self.assertIn("mitre_attack", hash_message)
            self.assertIn(expected_sha256, hash_message)
            self.assertIn(actual_sha256, hash_message)

    def test_sigma_subprocess_network_guard_is_active(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                "import socket; socket.getaddrinfo('example.com', 443)",
            ],
            cwd=REPOSITORY_ROOT,
            env=sigma_subprocess_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        combined_output = completed.stdout + completed.stderr
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(NETWORK_DENIAL_MESSAGE.encode(), combined_output)

    def test_seeded_validation_versions_match_metadata_in_fresh_process(
        self,
    ) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import json; "
                    "from sigma.data import mitre_attack, mitre_d3fend; "
                    "print(json.dumps({"
                    "'mitre_attack': mitre_attack.mitre_attack_version, "
                    "'mitre_d3fend': mitre_d3fend.mitre_d3fend_version"
                    "}, sort_keys=True))"
                ),
            ],
            cwd=REPOSITORY_ROOT,
            env=sigma_subprocess_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            (completed.stdout + completed.stderr).decode(
                "utf-8", errors="replace"
            ),
        )
        actual = json.loads(completed.stdout.decode("utf-8"))
        metadata = PREPARE_VALIDATION_DATA.load_manifest(VALIDATION_DATA)["datasets"]
        self.assertEqual(
            actual,
            {
                "mitre_attack": metadata["mitre_attack"]["version"],
                "mitre_d3fend": metadata["mitre_d3fend"]["version"],
            },
        )

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

    def test_all_active_rules_pass_sigma_check_without_network(self) -> None:
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

    def test_attack_tag_validator_remains_enabled_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            rule = Path(temporary_directory) / "invalid-attack-tag.yml"
            rule.write_text(
                FIXTURE.read_text(encoding="utf-8")
                + "\ntags:\n  - attack.t999999\n",
                encoding="utf-8",
            )
            completed = run_sigma_completed(
                "check",
                "--fail-on-error",
                "--fail-on-issues",
                str(rule),
            )
        combined_output = completed.stdout + completed.stderr
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"InvalidATTACKTagIssue", combined_output)
        self.assertNotIn(NETWORK_DENIAL_MESSAGE.encode(), combined_output)

    def test_empty_controlled_cache_cannot_fall_back_to_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            empty_home = Path(temporary_directory) / "home"
            empty_home.mkdir()
            completed = run_sigma_completed(
                "check",
                "--fail-on-error",
                "--fail-on-issues",
                str(
                    REPOSITORY_ROOT
                    / "detections"
                    / "sigma"
                    / "windows"
                    / "process-discovery-tasklist.yml"
                ),
                home=empty_home,
            )
        combined_output = completed.stdout + completed.stderr
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(NETWORK_DENIAL_MESSAGE.encode(), combined_output)

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
