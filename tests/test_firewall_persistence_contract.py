"""Contracts for the persistent Splunk adapter firewall boundary."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIREWALL_SCRIPT = ROOT / "tools" / "linux" / "alert2ir-splunk-adapter-firewall.sh"
DOCKER_DROP_IN = ROOT / "config" / "firewall" / "20-alert2ir-splunk-adapter-firewall.conf"
DEPLOYMENT_GUIDE = ROOT / "docs" / "DEPLOYMENT.md"
EVIDENCE_PATH = (
    ROOT / "validation" / "integration" / "firewall-persistence-2026-08-18.json"
)


class FirewallPersistenceArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = FIREWALL_SCRIPT.read_text(encoding="utf-8")
        cls.drop_in = DOCKER_DROP_IN.read_text(encoding="utf-8")

    def test_script_is_shell_valid_and_executable(self) -> None:
        completed = subprocess.run(
            ["bash", "-n", str(FIREWALL_SCRIPT)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(FIREWALL_SCRIPT.stat().st_mode & 0o111)

    def test_exact_owned_lab_boundary_is_frozen(self) -> None:
        expected_assignments = {
            "EXPECTED_HOST": "ir-core",
            "HOST_ONLY_INTERFACE": "enp0s8",
            "ADAPTER_HOST_IPV4": "192.168.56.63",
            "ADAPTER_HOST_CIDR": "192.168.56.63/24",
            "SPLUNK_IPV4": "192.168.56.61",
            "ADAPTER_PORT": "8091",
        }
        for name, value in expected_assignments.items():
            with self.subTest(name=name):
                self.assertRegex(
                    self.script,
                    re.compile(
                        rf'^readonly {name}="{re.escape(value)}"$',
                        re.MULTILINE,
                    ),
                )
        self.assertIn('--ctorigdst "${ADAPTER_HOST_IPV4}"', self.script)
        self.assertIn('--ctorigdstport "${ADAPTER_PORT}"', self.script)
        self.assertIn('"${SPLUNK_IPV4}/32"', self.script)
        self.assertIn('-j ACCEPT', self.script)
        self.assertIn('-j DROP', self.script)

    def test_rules_have_distinct_ownership_markers_and_exact_order_checks(self) -> None:
        self.assertIn('alert2ir:splunk-adapter:allow', self.script)
        self.assertIn('alert2ir:splunk-adapter:drop', self.script)
        self.assertIn('"${DOCKER_USER_CHAIN}" 1 "${ALLOW_RULE[@]}"', self.script)
        self.assertIn('"${DOCKER_USER_CHAIN}" 1 "${DROP_RULE[@]}"', self.script)
        self.assertIn('"${DOCKER_USER_CHAIN}" 2)', self.script)
        self.assertIn('remove_owned_rules_below_boundary', self.script)
        self.assertIn('remove_legacy_rules', self.script)

    def test_reconciliation_never_flushes_or_replaces_unrelated_policy(self) -> None:
        for prohibited in (
            "iptables-restore",
            "iptables-save",
            "nft flush",
            "ufw reset",
            ' -F ',
            "--flush",
            "-P FORWARD",
        ):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, self.script)
        self.assertNotIn("rm -", self.script)
        self.assertIn('-D "${DOCKER_USER_CHAIN}" "${index}"', self.script)

    def test_docker_start_is_fail_closed_and_post_start_is_verified(self) -> None:
        self.assertEqual(
            [
                line
                for line in self.drop_in.splitlines()
                if line.startswith(("ExecStartPre=", "ExecStartPost="))
            ],
            [
                "ExecStartPre=/usr/local/sbin/alert2ir-splunk-adapter-firewall apply",
                "ExecStartPost=/usr/local/sbin/alert2ir-splunk-adapter-firewall check",
            ],
        )
        self.assertIn("{{.FirewallBackend.Driver}}", self.script)
        self.assertIn("-A FORWARD -j DOCKER-USER", self.script)


class FirewallPersistenceDocumentationTests(unittest.TestCase):
    def test_guide_documents_install_verify_boot_and_narrow_rollback(self) -> None:
        guide = DEPLOYMENT_GUIDE.read_text(encoding="utf-8")
        for expected in (
            "20-alert2ir-splunk-adapter-firewall.conf",
            "/usr/local/sbin/alert2ir-splunk-adapter-firewall apply",
            "/usr/local/sbin/alert2ir-splunk-adapter-firewall check",
            "/usr/local/sbin/alert2ir-splunk-adapter-firewall remove",
            "ExecStartPre",
            "ExecStartPost",
            "HMAC remains required",
            "127.0.0.1:8000",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, guide)


class FirewallPersistenceEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))

    def test_evidence_proves_reboot_boundary_and_no_manual_reapply(self) -> None:
        evidence = self.evidence
        self.assertEqual(
            evidence["repository"]["baseline_commit"],
            "11338a084279b65a44a48084a9dd2119010b52f8",
        )
        self.assertEqual(evidence["final_verdict"], "pass")
        self.assertEqual(evidence["investigation"]["docker"]["firewall_backend"], "iptables")
        self.assertTrue(evidence["controlled_reboot"]["completed"])
        self.assertNotEqual(
            evidence["controlled_reboot"]["old_boot_id"],
            evidence["controlled_reboot"]["new_boot_id"],
        )
        self.assertFalse(evidence["controlled_reboot"]["manual_post_reboot_firewall_apply"])
        firewall = evidence["post_reboot"]["firewall"]
        self.assertEqual(firewall["owned_allow_count"], 1)
        self.assertEqual(firewall["owned_drop_count"], 1)
        self.assertEqual(firewall["unexpected_duplicate_count"], 0)
        self.assertEqual(
            evidence["post_reboot"]["network_probes"],
            {
                "observed_at_utc": "2026-08-18T18:11:03Z",
                "splunk_to_adapter_8091": "reachable_http_200",
                "dev01_to_adapter_8091": "blocked_connect_timeout",
                "splunk_to_canonical_8000": "blocked_connect_timeout",
            },
        )
        self.assertEqual(
            evidence["post_reboot"]["listeners"]["canonical"],
            "127.0.0.1:8000",
        )
        self.assertEqual(
            evidence["post_reboot"]["application"]["adapter_health"],
            "http_200_healthy",
        )
        self.assertEqual(evidence["post_reboot"]["additional_velociraptor_pslist_flows"], 0)

    def test_evidence_is_sanitized_and_records_non_regression(self) -> None:
        self.assertEqual(
            set(self.evidence["non_regression"]),
            {
                "hmac_authentication",
                "canonical_api_binding",
                "compose_network_topology",
                "alert2ir_core_behavior",
                "adapter_request_and_retry_behavior",
                "sender_behavior",
                "universal_forwarder_use_ack",
                "validation_saved_search",
                "new_endpoint_validation_marker",
                "new_velociraptor_investigation",
            },
        )
        self.assertFalse(self.evidence["non_regression"]["new_endpoint_validation_marker"])
        self.assertFalse(self.evidence["non_regression"]["new_velociraptor_investigation"])
        self.assertNotIn(
            "pending",
            json.dumps(self.evidence["regression_validation"]).lower(),
        )
        serialized = json.dumps(self.evidence, sort_keys=True).lower()
        for prohibited in (
            "-----begin",
            "authorization:",
            "client_private_key",
            "hmac_signature",
            "session_token",
        ):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, serialized)


if __name__ == "__main__":
    unittest.main()
