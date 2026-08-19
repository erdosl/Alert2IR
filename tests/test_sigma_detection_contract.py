"""Contracts for active and historical Alert2IR Sigma detection content.

The ordinary application environment omits Sigma packages. The dedicated
Sigma environment parses and checks every active rule while retaining the
retired cmd rule as immutable historical regression content.
"""

from importlib.metadata import PackageNotFoundError, version
import json
from pathlib import Path
import unittest
from uuid import UUID


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RULE_DIRECTORY = REPOSITORY_ROOT / "detections" / "sigma"
OBJECTIVES_PATH = (
    REPOSITORY_ROOT / "config" / "attack-simulation" / "detection-objectives.json"
)
EXPECTED_RULE_FILES = {
    "windows/cmd-temp-file-write-display.yml",
    "windows/powershell-encoded-command.yml",
    "windows/process-discovery-tasklist.yml",
    "validation/windows/create-stream-hash-alert2ir-ads.yml",
    "validation/windows/dns-query-owned-alias.yml",
    "validation/windows/file-create-alert2ir-temp.yml",
    "validation/windows/investigation-delivery-marker.yml",
    "validation/windows/network-connection-host-only.yml",
    "validation/windows/process-creation-script-host-ancestry.yml",
}
DELIVERY_VALIDATION_RULE_FILES = {
    "validation/windows/investigation-delivery-marker.yml",
}
REQUIRED_SIGMA_DISTRIBUTIONS = (
    "sigma-cli",
    "pysigma",
    "pysigma-backend-splunk",
)
KNOWN_VALIDATION_RUN_IDS = {
    "45e78645-170d-4f2c-b158-32fdc89bec8d",
    "2c752432-9aa7-4a4d-bdb5-4ffacd2698b7",
    "34b43f09-1023-4c5c-8609-03c410bb28a3",
}
KNOWN_ATOMIC_GUIDS = {
    "c5806a4f-62b8-4900-980b-c7ec004e9908",
    "a538de64-1c74-46ed-aa60-b995ed302598",
    "127b4afe-2346-4192-815c-69042bec570e",
}
HISTORICAL_BASE64_PAYLOAD = (
    "JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkA"
    "IAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcA"
    "SAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIAIgArACIAbwBtACAAUAAiACsA"
    "IgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwAbAAhACcAIgApAA=="
)

RULE_CONTRACTS = {
    "windows/cmd-temp-file-write-display.yml": {
        "status": "experimental",
        "logsource": {"product": "windows", "category": "process_creation"},
        "level": "low",
    },
    "windows/powershell-encoded-command.yml": {
        "status": "experimental",
        "logsource": {"product": "windows", "category": "process_creation"},
        "level": "medium",
    },
    "windows/process-discovery-tasklist.yml": {
        "status": "experimental",
        "logsource": {"product": "windows", "category": "process_creation"},
        "level": "low",
    },
    "validation/windows/file-create-alert2ir-temp.yml": {
        "status": "test",
        "logsource": {"product": "windows", "category": "file_event"},
        "level": "informational",
    },
    "validation/windows/investigation-delivery-marker.yml": {
        "status": "test",
        "logsource": {"product": "windows", "category": "process_creation"},
        "level": "high",
    },
    "validation/windows/network-connection-host-only.yml": {
        "status": "test",
        "logsource": {"product": "windows", "category": "network_connection"},
        "level": "informational",
    },
    "validation/windows/dns-query-owned-alias.yml": {
        "status": "test",
        "logsource": {"product": "windows", "category": "dns_query"},
        "level": "informational",
    },
    "validation/windows/create-stream-hash-alert2ir-ads.yml": {
        "status": "test",
        "logsource": {"product": "windows", "category": "create_stream_hash"},
        "level": "informational",
    },
    "validation/windows/process-creation-script-host-ancestry.yml": {
        "status": "test",
        "logsource": {"product": "windows", "category": "process_creation"},
        "level": "informational",
    },
}


def installed(distribution: str) -> bool:
    try:
        version(distribution)
    except PackageNotFoundError:
        return False
    return True


def setUpModule() -> None:
    if not all(installed(name) for name in REQUIRED_SIGMA_DISTRIBUTIONS):
        raise unittest.SkipTest(
            "requires the dedicated environment installed from requirements-sigma.txt"
        )


class SigmaDetectionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import yaml

        cls.paths = sorted(
            (*RULE_DIRECTORY.rglob("*.yml"), *RULE_DIRECTORY.rglob("*.yaml"))
        )
        cls.texts = {
            path.relative_to(RULE_DIRECTORY).as_posix(): path.read_text(encoding="utf-8")
            for path in cls.paths
        }
        cls.rules = {
            name: yaml.safe_load(text) for name, text in cls.texts.items()
        }
        cls.objectives = json.loads(OBJECTIVES_PATH.read_text(encoding="utf-8"))

    def test_ruleset_distinguishes_objectives_retired_and_delivery_validation(self) -> None:
        self.assertEqual(set(self.rules), EXPECTED_RULE_FILES)
        active_paths = {
            objective["rule_path"].removeprefix("detections/sigma/")
            for objective in self.objectives["objectives"]
        }
        retired_paths = {
            item["rule_path"].removeprefix("detections/sigma/")
            for item in self.objectives["retired_rules"]
        }
        self.assertEqual(len(active_paths), 7)
        self.assertEqual(retired_paths, {"windows/cmd-temp-file-write-display.yml"})
        self.assertTrue(active_paths.isdisjoint(retired_paths))
        self.assertTrue(active_paths.isdisjoint(DELIVERY_VALIDATION_RULE_FILES))
        self.assertTrue(retired_paths.isdisjoint(DELIVERY_VALIDATION_RULE_FILES))
        self.assertEqual(
            active_paths | retired_paths | DELIVERY_VALIDATION_RULE_FILES,
            EXPECTED_RULE_FILES,
        )

    def test_rule_ids_are_unique_valid_and_not_ground_truth_ids(self) -> None:
        rule_ids = [rule["id"] for rule in self.rules.values()]
        self.assertEqual(len(rule_ids), 9)
        self.assertEqual(len(set(rule_ids)), 9)
        for rule_id in rule_ids:
            with self.subTest(rule_id=rule_id):
                self.assertEqual(str(UUID(rule_id)), rule_id)
                self.assertNotIn(rule_id, KNOWN_VALIDATION_RUN_IDS)
                self.assertNotIn(rule_id, KNOWN_ATOMIC_GUIDS)

    def test_common_metadata_and_expected_logsources(self) -> None:
        required_fields = {
            "title",
            "id",
            "status",
            "description",
            "author",
            "date",
            "logsource",
            "detection",
            "falsepositives",
            "level",
        }
        for name, rule in self.rules.items():
            contract = RULE_CONTRACTS[name]
            with self.subTest(rule=name):
                self.assertTrue(required_fields.issubset(rule))
                self.assertEqual(rule["author"], "Alert2IR")
                self.assertEqual(rule["status"], contract["status"])
                self.assertEqual(rule["logsource"], contract["logsource"])
                self.assertEqual(rule["level"], contract["level"])
                self.assertTrue(rule["detection"])
                self.assertTrue(rule["falsepositives"])
                if name == "validation/windows/investigation-delivery-marker.yml":
                    self.assertEqual(str(rule["date"]), "2026-08-18")
                elif name.startswith("validation/"):
                    self.assertEqual(str(rule["date"]), "2026-08-17")
                else:
                    self.assertEqual(str(rule["date"]), "2026-08-13")

    def test_rules_do_not_embed_environment_scope_or_runtime_identity(self) -> None:
        prohibited = {
            "win11-01",
            "win11-02",
            "192.168.56.",
            "index=",
            "host=",
            "xmlwineventlog",
            "microsoft-windows-sysmon/operational",
            "eventcode",
            "recordid",
            "_time",
            HISTORICAL_BASE64_PAYLOAD.lower(),
            *(value.lower() for value in KNOWN_VALIDATION_RUN_IDS),
            *(value.lower() for value in KNOWN_ATOMIC_GUIDS),
        }
        for name, text in self.texts.items():
            lowered = text.lower()
            for value in prohibited:
                with self.subTest(rule=name, prohibited=value):
                    self.assertNotIn(value, lowered)

    def test_existing_semantic_regressions_are_preserved(self) -> None:
        tasklist = self.rules["windows/process-discovery-tasklist.yml"]
        self.assertEqual(
            tasklist["detection"],
            {
                "selection": {"Image|endswith": r"\tasklist.exe"},
                "condition": "selection",
            },
        )
        powershell = self.rules["windows/powershell-encoded-command.yml"]
        self.assertEqual(
            powershell["detection"],
            {
                "selection_image": {"Image|endswith": r"\powershell.exe"},
                "selection_encoded_switch": {
                    "CommandLine|contains": ["-e ", "-enc ", "-encodedcommand"]
                },
                "condition": "selection_image and selection_encoded_switch",
            },
        )
        retired = self.rules["windows/cmd-temp-file-write-display.yml"]
        self.assertEqual(
            retired["detection"]["selection_behavior"],
            {
                "CommandLine|contains|all": [
                    "echo",
                    "type",
                    "\\Windows\\Temp\\",
                ]
            },
        )

    def test_direct_file_rule_uses_target_filename_startswith(self) -> None:
        rule = self.rules["validation/windows/file-create-alert2ir-temp.yml"]
        self.assertEqual(
            rule["detection"],
            {
                "selection": {
                    "TargetFilename|startswith": r"C:\Windows\Temp\Alert2IR-AttackSimulation-"
                },
                "condition": "selection",
            },
        )

    def test_network_dns_and_ads_rules_use_intended_direct_fields(self) -> None:
        network = self.rules["validation/windows/network-connection-host-only.yml"]
        self.assertEqual(
            network["detection"]["selection"],
            {
                "Image|endswith": r"\powershell.exe",
                "DestinationPort": 9997,
                "Initiated": "true",
                "Protocol": "tcp",
            },
        )
        dns = self.rules["validation/windows/dns-query-owned-alias.yml"]
        self.assertEqual(
            dns["detection"]["selection"],
            {
                "Image|endswith": r"\powershell.exe",
                "QueryName|endswith": ".alert2ir.test",
            },
        )
        self.assertNotIn("QueryStatus", self.texts["validation/windows/dns-query-owned-alias.yml"])
        ads = self.rules["validation/windows/create-stream-hash-alert2ir-ads.yml"]
        self.assertEqual(
            ads["detection"],
            {
                "selection_path": {
                    "TargetFilename|startswith": r"C:\Windows\Temp\Alert2IR-ADS-"
                },
                "selection_stream": {"TargetFilename|contains": ":Alert2IR-"},
                "condition": "selection_path and selection_stream",
            },
        )
        self.assertNotIn("Zone.Identifier", self.texts["validation/windows/create-stream-hash-alert2ir-ads.yml"])

    def test_ancestry_rule_materially_depends_on_parent_image(self) -> None:
        rule = self.rules[
            "validation/windows/process-creation-script-host-ancestry.yml"
        ]
        self.assertEqual(
            rule["detection"],
            {
                "selection": {
                    "ParentImage|endswith": r"\cscript.exe",
                    "Image|endswith": r"\powershell.exe",
                    "CommandLine|contains": "Start-Sleep -Seconds 5",
                },
                "condition": "selection",
            },
        )
        self.assertNotEqual(
            rule["detection"]["selection"]["ParentImage|endswith"],
            rule["detection"]["selection"]["Image|endswith"],
        )

    def test_delivery_validation_rule_uses_only_the_reserved_safe_marker(self) -> None:
        rule = self.rules[
            "validation/windows/investigation-delivery-marker.yml"
        ]
        self.assertEqual(
            rule["detection"],
            {
                "selection": {
                    "Image|endswith": r"\cmd.exe",
                    "CommandLine|contains": "Alert2IR-INVESTIGATE-",
                },
                "condition": "selection",
            },
        )
        self.assertIn("not production detection content", rule["description"])


if __name__ == "__main__":
    unittest.main()
