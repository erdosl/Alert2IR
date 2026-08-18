"""Contracts for the ir-core host-administration SSH firewall boundary."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
LAB_GUIDE = ROOT / "docs" / "LAB.md"
EVIDENCE_PATH = (
    ROOT / "validation" / "integration" / "host-ssh-firewall-2026-08-18.json"
)


class HostSshFirewallContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lab_guide = LAB_GUIDE.read_text(encoding="utf-8")
        cls.evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))

    def test_lab_guide_records_exact_separate_ssh_paths(self) -> None:
        for expected in (
            "192.168.56.64 -> 192.168.56.63:22/TCP",
            "192.168.56.1 -> 192.168.56.63:22/TCP",
            "Neither rule authorizes `192.168.56.0/24` or an arbitrary source.",
            "independent of the Alert2IR `DOCKER-USER` forwarding boundary",
            "sudo ufw allow in on enp0s8 from 192.168.56.1 "
            "to 192.168.56.63 port 22 proto tcp "
            "comment 'host SSH administration'",
            "sudo iptables -S ufw-user-input",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.lab_guide)

    def test_contract_keeps_two_exact_sources_without_subnet_widening(self) -> None:
        contract = self.evidence["contract"]
        expected_common = {
            "destination_ipv4": "192.168.56.63",
            "interface": "enp0s8",
            "protocol": "tcp",
            "destination_port": 22,
        }
        self.assertEqual(
            [rule["source_ipv4"] for rule in contract["ssh_rules"]],
            ["192.168.56.64", "192.168.56.1"],
        )
        for rule in contract["ssh_rules"]:
            with self.subTest(source=rule["source_ipv4"]):
                for key, value in expected_common.items():
                    self.assertEqual(rule[key], value)
        self.assertFalse(contract["subnet_wide_ssh_allowed"])
        self.assertFalse(contract["arbitrary_source_ssh_allowed"])
        self.assertNotIn("192.168.56.0/24", json.dumps(contract["ssh_rules"]))

    def test_evidence_records_reboot_persistence_and_live_ssh(self) -> None:
        validation = self.evidence["live_validation"]
        self.assertTrue(validation["full_vm_reboot_completed"])
        self.assertEqual(validation["post_reboot"]["persistence_result"], "pass")
        self.assertTrue(validation["post_reboot"]["stored_host_rule_present"])
        self.assertTrue(validation["post_reboot"]["effective_host_rule_present"])
        self.assertTrue(validation["post_reboot"]["host_ssh_remained_available"])
        reverification = validation["read_only_reverification"]
        self.assertEqual(reverification["host_rule_count"], 1)
        self.assertEqual(reverification["dev01_rule_count"], 1)
        self.assertEqual(reverification["dev01_ssh_connection"], "successful")
        self.assertGreaterEqual(
            reverification["current_boot_sshd_accepted_event_count_from_192_168_56_1"],
            1,
        )

    def test_docker_boundary_and_side_effects_remain_unchanged(self) -> None:
        docker_user = self.evidence["docker_user_non_regression"]
        self.assertTrue(docker_user["unchanged"])
        self.assertEqual(len(docker_user["rules"]), 2)
        self.assertIn("192.168.56.61/32", docker_user["rules"][0])
        self.assertIn("--ctorigdstport 8091", docker_user["rules"][0])
        self.assertIn("--ctorigdstport 8091", docker_user["rules"][1])
        self.assertFalse(
            self.evidence["non_regression"]["new_endpoint_validation_marker"]
        )
        self.assertFalse(
            self.evidence["non_regression"]["new_velociraptor_investigation"]
        )
        self.assertFalse(self.evidence["sanitization"]["sensitive_material_recorded"])


if __name__ == "__main__":
    unittest.main()
