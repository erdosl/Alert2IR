"""Contracts for the separately installed WS08 Sigma translation toolchain.

The ordinary Alert2IR application environment deliberately excludes these
packages. Default discovery records one explained module skip there; the
dedicated Sigma environment executes every contract below.
"""

from importlib.metadata import PackageNotFoundError, version
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
FIXTURE = (
    REPOSITORY_ROOT
    / "tests"
    / "fixtures"
    / "sigma"
    / "windows-process-creation.yml"
)
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


def convert(rule: Path) -> bytes:
    return run_sigma(
        "convert",
        "--target",
        "splunk",
        "--pipeline",
        str(PIPELINE),
        "--pipeline-check",
        "--format",
        "default",
        "--fail-unsupported",
        "--output",
        "-",
        str(rule),
    )


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
            "ws07",
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
        for prohibited in ("index=main", "host=win11-02", "ws07"):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, query.lower())

    def test_repeated_translation_is_byte_identical(self) -> None:
        first = convert(FIXTURE)
        second = convert(FIXTURE)

        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
