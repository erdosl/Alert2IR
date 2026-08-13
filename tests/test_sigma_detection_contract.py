"""Contracts for the three canonical WS08 production Sigma detections.

The ordinary Alert2IR application environment deliberately excludes Sigma
packages. Default discovery records one explained module skip there; the
dedicated Sigma environment executes every contract below.
"""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import unittest
from uuid import UUID


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RULE_DIRECTORY = REPOSITORY_ROOT / "detections" / "sigma" / "windows"
EXPECTED_RULE_FILES = {
    "cmd-temp-file-write-display.yml",
    "powershell-encoded-command.yml",
    "process-discovery-tasklist.yml",
}
REQUIRED_SIGMA_DISTRIBUTIONS = (
    "sigma-cli",
    "pysigma",
    "pysigma-backend-splunk",
)
KNOWN_WS07_RUN_IDS = {
    "45e78645-170d-4f2c-b158-32fdc89bec8d",
    "2c752432-9aa7-4a4d-bdb5-4ffacd2698b7",
    "34b43f09-1023-4c5c-8609-03c410bb28a3",
}
KNOWN_ATOMIC_GUIDS = {
    "c5806a4f-62b8-4900-980b-c7ec004e9908",
    "a538de64-1c74-46ed-aa60-b995ed302598",
    "127b4afe-2346-4192-815c-69042bec570e",
}
WS07_BASE64_PAYLOAD = (
    "JgAgACgAZwBjAG0AIAAoACcAaQBlAHsAMAB9ACcAIAAtAGYAIAAnAHgAJwApACkA"
    "IAAoACIAVwByACIAKwAiAGkAdAAiACsAIgBlAC0ASAAiACsAIgBvAHMAdAAgACcA"
    "SAAiACsAIgBlAGwAIgArACIAbABvACwAIABmAHIAIgArACIAbwBtACAAUAAiACsA"
    "IgBvAHcAIgArACIAZQByAFMAIgArACIAaAAiACsAIgBlAGwAbAAhACcAIgApAA=="
)
WS07_TEMP_TARGET = (
    r"C:\Windows\Temp\Alert2IR-WS07-"
    "34b43f09-1023-4c5c-8609-03c410bb28a3.bin"
)
WS07_MESSAGE = (
    "Alert2IR WS07 ground truth "
    "34b43f09-1023-4c5c-8609-03c410bb28a3"
)
RULE_CONTRACTS = {
    "cmd-temp-file-write-display.yml": {
        "technique": "attack.t1059.003",
        "tactic": "attack.execution",
        "level": "low",
    },
    "powershell-encoded-command.yml": {
        "technique": "attack.t1059.001",
        "tactic": "attack.execution",
        "level": "medium",
    },
    "process-discovery-tasklist.yml": {
        "technique": "attack.t1057",
        "tactic": "attack.discovery",
        "level": "low",
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
            path.name: path.read_text(encoding="utf-8") for path in cls.paths
        }
        cls.rules = {
            name: yaml.safe_load(text) for name, text in cls.texts.items()
        }

    def test_ruleset_has_exactly_the_three_approved_files(self) -> None:
        relative_paths = {
            path.relative_to(RULE_DIRECTORY).as_posix() for path in self.paths
        }

        self.assertEqual(relative_paths, EXPECTED_RULE_FILES)
        self.assertEqual(len(self.rules), 3)

    def test_rule_ids_are_unique_valid_and_not_ground_truth_ids(self) -> None:
        rule_ids = [rule["id"] for rule in self.rules.values()]

        self.assertEqual(len(rule_ids), 3)
        self.assertEqual(len(set(rule_ids)), 3)
        for rule_id in rule_ids:
            with self.subTest(rule_id=rule_id):
                self.assertEqual(str(UUID(rule_id)), rule_id)
                self.assertNotIn(rule_id, KNOWN_WS07_RUN_IDS)
                self.assertNotIn(rule_id, KNOWN_ATOMIC_GUIDS)

    def test_common_metadata_logsource_and_attack_tags(self) -> None:
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
            "tags",
        }

        for name, rule in self.rules.items():
            contract = RULE_CONTRACTS[name]
            with self.subTest(rule=name):
                self.assertTrue(required_fields.issubset(rule))
                self.assertTrue(rule["title"].strip())
                self.assertTrue(rule["description"].strip())
                self.assertEqual(rule["status"], "experimental")
                self.assertEqual(rule["author"], "Alert2IR")
                self.assertEqual(str(rule["date"]), "2026-08-13")
                self.assertEqual(
                    rule["logsource"],
                    {"product": "windows", "category": "process_creation"},
                )
                self.assertTrue(rule["detection"])
                self.assertTrue(rule["falsepositives"])
                self.assertEqual(rule["level"], contract["level"])
                self.assertIn(contract["tactic"], rule["tags"])
                self.assertIn(contract["technique"], rule["tags"])

    def test_rules_do_not_embed_splunk_lab_or_ws07_values(self) -> None:
        prohibited = {
            "win11-02",
            "index=main",
            "splunk",
            "xmlwineventlog",
            "microsoft-windows-sysmon/operational",
            "eventcode",
            "recordid",
            "_time",
            "1300570",
            "1300904",
            "1301448",
            "1301449",
            "1301589",
            "alert2ir-ws07-",
            WS07_BASE64_PAYLOAD.lower(),
            WS07_TEMP_TARGET.lower(),
            WS07_MESSAGE.lower(),
            *(value.lower() for value in KNOWN_WS07_RUN_IDS),
            *(value.lower() for value in KNOWN_ATOMIC_GUIDS),
        }

        for name, text in self.texts.items():
            lowered = text.lower()
            for value in prohibited:
                with self.subTest(rule=name, prohibited=value):
                    self.assertNotIn(value, lowered)

    def test_tasklist_rule_has_the_approved_selector_only(self) -> None:
        rule = self.rules["process-discovery-tasklist.yml"]

        self.assertEqual(
            rule["detection"],
            {
                "selection": {"Image|endswith": r"\tasklist.exe"},
                "condition": "selection",
            },
        )
        tasklist_text = self.texts["process-discovery-tasklist.yml"].lower()
        self.assertNotIn("parentimage", tasklist_text)

    def test_powershell_rule_has_approved_encoded_switch_semantics(self) -> None:
        rule = self.rules["powershell-encoded-command.yml"]

        self.assertEqual(
            rule["detection"],
            {
                "selection_image": {"Image|endswith": r"\powershell.exe"},
                "selection_encoded_switch": {
                    "CommandLine|contains": [
                        "-e ",
                        "-enc ",
                        "-encodedcommand",
                    ]
                },
                "condition": "selection_image and selection_encoded_switch",
            },
        )
        self.assertNotIn(
            WS07_BASE64_PAYLOAD,
            self.texts["powershell-encoded-command.yml"],
        )

    def test_cmd_rule_has_approved_temporary_file_behavior(self) -> None:
        rule = self.rules["cmd-temp-file-write-display.yml"]

        self.assertEqual(
            rule["detection"],
            {
                "selection_image": {"Image|endswith": r"\cmd.exe"},
                "selection_behavior": {
                    "CommandLine|contains|all": [
                        "echo",
                        "type",
                        "\\Windows\\Temp\\",
                    ]
                },
                "condition": "selection_image and selection_behavior",
            },
        )
        text = self.texts["cmd-temp-file-write-display.yml"]
        self.assertNotIn(WS07_TEMP_TARGET, text)
        self.assertNotIn(WS07_MESSAGE, text)
        self.assertNotIn("EventID", text)


if __name__ == "__main__":
    unittest.main()
