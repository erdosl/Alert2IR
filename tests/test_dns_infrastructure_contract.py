"""Static contracts for authoritative DNS, UFW, NRPT, and sanitized evidence."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
DNS_ROOT = ROOT / "config" / "dns"
CONTRACT_PATH = DNS_ROOT / "alert2ir-dns.json"
NRPT_PATH = ROOT / "config" / "windows" / "nrpt-alert2ir.test.json"
OPTIONS_PATH = DNS_ROOT / "named.conf.options.alert2ir"
LOCAL_PATH = DNS_ROOT / "named.conf.local.alert2ir"
ZONE_PATH = DNS_ROOT / "zones" / "db.alert2ir.test"
PROVISIONER = ROOT / "tools" / "linux" / "provision-alert2ir-dns.sh"
VALIDATOR = ROOT / "tools" / "linux" / "validate-alert2ir-dns.sh"
NRPT_SETTER = ROOT / "tools" / "windows" / "lab" / "Set-Alert2IRLabNrpt.ps1"
NRPT_TESTER = ROOT / "tools" / "windows" / "lab" / "Test-Alert2IRLabNrpt.ps1"
DNS_WRAPPER = (
    ROOT
    / "tools"
    / "windows"
    / "attack-simulation"
    / "Invoke-Alert2IROwnedAliasDns.ps1"
)
FIXTURES = ROOT / "tests" / "fixtures" / "nrpt-conflicts.json"
EVIDENCE_SCHEMA = DNS_ROOT / "dns-infrastructure-acceptance.schema.json"
EVIDENCE_ROOT = ROOT / "validation" / "infrastructure" / "dns"


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def normalized_namespace(value: str) -> str:
    stripped = value.strip().rstrip(".").lower()
    return "." if value.strip() == "." else stripped


def exact_fixture_rule(rule: dict) -> bool:
    return (
        rule["display_name"] == "Alert2IR-Lab-DNS-alert2ir.test"
        and normalized_namespace(rule["namespace"]) == ".alert2ir.test"
        and rule["name_servers"] == ["192.168.56.64"]
        and rule["direct_access"] is False
    )


def classify_fixture(fixture: dict) -> list[str]:
    conflicts: list[str] = []
    local = fixture["local"]
    effective = fixture["effective"]
    if sum(
        rule["display_name"] == "Alert2IR-Lab-DNS-alert2ir.test"
        for rule in local
    ) > 1:
        conflicts.append("duplicate_display_name")

    for rule in local:
        namespace = normalized_namespace(rule["namespace"])
        affects = (
            namespace in {".", ".test", "test", ".alert2ir.test"}
            or namespace.endswith(".alert2ir.test")
        )
        if not affects or exact_fixture_rule(rule):
            continue
        if rule["direct_access"]:
            conflicts.append("directaccess_or_vpn_conflict")
        elif namespace in {".test", "test"}:
            conflicts.append("broad_test_rule")
        elif namespace == ".":
            conflicts.append("root_catch_all_rule")
        elif namespace == ".alert2ir.test":
            conflicts.append("same_namespace_conflict")
        else:
            conflicts.append("more_specific_conflict")

    local_signatures = {
        (normalized_namespace(rule["namespace"]), tuple(rule["name_servers"]))
        for rule in local
    }
    for rule in effective:
        namespace = normalized_namespace(rule["namespace"])
        signature = (namespace, tuple(rule["name_servers"]))
        if (
            namespace in {".", ".test", "test", ".alert2ir.test"}
            or namespace.endswith(".alert2ir.test")
        ) and signature not in local_signatures:
            conflicts.append(
                "directaccess_or_vpn_conflict"
                if rule["direct_access"]
                else "gpo_or_effective_policy_conflict"
            )
    return sorted(set(conflicts))


class DnsAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_json(CONTRACT_PATH)
        cls.options = OPTIONS_PATH.read_text(encoding="utf-8")
        cls.local = LOCAL_PATH.read_text(encoding="utf-8")
        cls.zone = ZONE_PATH.read_text(encoding="utf-8")

    def test_contract_is_closed_exact_authority(self) -> None:
        self.assertEqual(
            set(self.contract),
            {"schema_version", "server", "zone", "clients", "nrpt_contract", "firewall"},
        )
        self.assertEqual(self.contract["schema_version"], 1)
        self.assertEqual(
            self.contract["server"],
            {
                "host": "dev01",
                "ipv4": "192.168.56.64",
                "interface": "enp0s8",
                "nat_ipv4": "10.0.2.15",
                "listeners": {"ipv4": ["192.168.56.64"], "ipv6": []},
            },
        )
        self.assertEqual(
            self.contract["clients"],
            [
                {"host": "win11-01", "ipv4": "192.168.56.60"},
                {"host": "win11-02", "ipv4": "192.168.56.62"},
            ],
        )
        self.assertEqual(self.contract["zone"]["name"], "alert2ir.test.")
        self.assertFalse(self.contract["zone"]["recursion"])
        self.assertEqual(self.contract["zone"]["forwarders"], [])
        self.assertFalse(self.contract["zone"]["dynamic_update"])
        self.assertFalse(self.contract["zone"]["zone_transfer"])
        self.assertEqual(
            self.contract["zone"]["records"],
            {
                "dev01.alert2ir.test.": "192.168.56.64",
                "splunk.alert2ir.test.": "192.168.56.61",
            },
        )

    def test_bind_listener_and_behavior_are_exact(self) -> None:
        self.assertRegex(self.options, r"listen-on\s*\{\s*192\.168\.56\.64;\s*\};")
        self.assertRegex(self.options, r"listen-on-v6\s*\{\s*none;\s*\};")
        for required in (
            "recursion no;",
            "allow-recursion { none; };",
            "allow-query-cache { none; };",
            "allow-transfer { none; };",
            "dnssec-validation no;",
            "session-keyfile none;",
            "notify no;",
        ):
            self.assertIn(required, self.options)
        combined = self.options + self.local
        self.assertNotRegex(combined, r"\bforwarders\b|\bforward\s+(?:first|only)\b")
        self.assertIn(
            "controls { };",
            (DNS_ROOT / "named.conf.alert2ir").read_text(encoding="utf-8"),
        )
        self.assertNotRegex(combined, r"\bkey\s+\"")
        self.assertNotIn("10.0.2.15", combined)
        self.assertNotIn("0.0.0.0", combined)
        self.assertNotIn("::", combined)
        self.assertNotRegex(combined, r"\b(localhost|localnets|any)\b")

    def test_bind_acl_has_only_dns_clients(self) -> None:
        acl = re.search(
            r'acl\s+"alert2ir-approved-clients"\s*\{(?P<body>.*?)\};',
            self.options,
            re.DOTALL,
        )
        self.assertIsNotNone(acl)
        addresses = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", acl.group("body"))
        self.assertEqual(addresses, ["192.168.56.60", "192.168.56.62"])
        self.assertNotIn("192.168.56.1;", self.options)
        self.assertNotIn("192.168.56.0/24", self.options)
        self.assertIn("allow-query { alert2ir-approved-clients; };", self.local)

    def test_zone_declaration_disables_update_transfer_and_notify(self) -> None:
        self.assertEqual(len(re.findall(r'\bzone\s+"', self.local)), 1)
        self.assertIn('zone "alert2ir.test"', self.local)
        self.assertIn("type primary;", self.local)
        self.assertIn("allow-update { none; };", self.local)
        self.assertIn("allow-transfer { none; };", self.local)
        self.assertIn("notify no;", self.local)
        self.assertNotRegex(self.local, r'zone\s+"(?:\d{1,3}\.){3}')

    def test_zone_records_are_exact(self) -> None:
        self.assertRegex(
            self.zone,
            r"@\s+IN\s+SOA\s+dev01\.alert2ir\.test\.\s+hostmaster\.alert2ir\.test\.",
        )
        self.assertRegex(self.zone, r"(?m)^\s*IN\s+NS\s+dev01\.alert2ir\.test\.\s*$")
        self.assertRegex(self.zone, r"(?m)^dev01\s+IN\s+A\s+192\.168\.56\.64\s*$")
        self.assertRegex(self.zone, r"(?m)^splunk\s+IN\s+A\s+192\.168\.56\.61\s*$")
        self.assertRegex(self.zone, r"(?m)^\s*20\d{8}\s*$")
        self.assertNotRegex(self.zone, r"(?m)^\s*20\d{6}(?:00|[0-9]{3,})\s*$")
        self.assertEqual(len(re.findall(r"(?m)^\w+\s+IN\s+A\s+", self.zone)), 2)
        self.assertNotRegex(self.zone, r"\b(?:AAAA|PTR|CNAME)\b")
        self.assertNotIn("*", self.zone)

    def test_all_contract_addresses_are_private_or_owned_management(self) -> None:
        addresses = [self.contract["server"]["ipv4"]]
        addresses.extend(client["ipv4"] for client in self.contract["clients"])
        addresses.extend(self.contract["zone"]["records"].values())
        addresses.append(self.contract["firewall"]["management"]["source_ipv4"])
        self.assertTrue(all(ipaddress.ip_address(value).is_private for value in addresses))

    def test_real_bind_validators(self) -> None:
        if shutil.which("named-checkconf") is None or shutil.which("named-checkzone") is None:
            self.skipTest("BIND validation utilities are not installed")
        completed = subprocess.run(
            [str(VALIDATOR), "repository"],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)


class FirewallContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_json(CONTRACT_PATH)
        cls.provisioner = PROVISIONER.read_text(encoding="utf-8")

    def test_management_rule_is_one_exact_host_only_tuple(self) -> None:
        self.assertEqual(
            self.contract["firewall"]["management"],
            {
                "source_ipv4": "192.168.56.1",
                "destination_ipv4": "192.168.56.64",
                "interface": "enp0s8",
                "protocol": "tcp",
                "destination_port": 22,
                "comment": "Alert2IR management SSH",
            },
        )

    def test_dns_rules_are_four_exact_endpoint_protocol_tuples(self) -> None:
        rules = self.contract["firewall"]["dns"]
        self.assertEqual(len(rules), 4)
        self.assertEqual(
            {
                (rule["source_ipv4"], rule["protocol"], rule["destination_port"])
                for rule in rules
            },
            {
                ("192.168.56.60", "udp", 53),
                ("192.168.56.60", "tcp", 53),
                ("192.168.56.62", "udp", 53),
                ("192.168.56.62", "tcp", 53),
            },
        )
        for rule in rules:
            self.assertEqual(rule["destination_ipv4"], "192.168.56.64")
            self.assertEqual(rule["interface"], "enp0s8")

    def test_no_broad_firewall_value_exists(self) -> None:
        serialized = json.dumps(self.contract["firewall"], sort_keys=True)
        for prohibited in (
            "0.0.0.0/0",
            "Anywhere",
            "192.168.56.0/24",
            "enp0s3",
            "::/0",
            "OpenSSH",
        ):
            self.assertNotIn(prohibited, serialized)

    def test_provisioner_has_safe_rollback_boundaries(self) -> None:
        self.assertIn("--alternate-management-verified", self.provisioner)
        self.assertIn("--dry-run", self.provisioner)
        self.assertIn("management-rule removal requires", self.provisioner)
        self.assertIn('rm -rf -- "${DEPLOY_ROOT}"', self.provisioner)
        self.assertNotIn("rm -rf -- /etc/bind", self.provisioner)
        self.assertNotIn("ufw reset", self.provisioner)
        self.assertNotIn("/etc/resolv.conf\" >", self.provisioner)
        self.assertNotIn("systemd-resolved restart", self.provisioner)


class NrptContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dns_contract = load_json(CONTRACT_PATH)
        cls.nrpt = load_json(NRPT_PATH)
        cls.setter = NRPT_SETTER.read_text(encoding="utf-8")
        cls.tester = NRPT_TESTER.read_text(encoding="utf-8")

    def test_nrpt_copy_matches_single_authority(self) -> None:
        self.assertEqual(
            self.dns_contract["nrpt_contract"],
            "config/windows/nrpt-alert2ir.test.json",
        )
        self.assertEqual(set(self.nrpt), {"schema_version", "display_name", "namespace", "name_servers", "policy_store", "dnssec_required", "direct_access", "comment"})
        self.assertEqual(self.nrpt["display_name"], "Alert2IR-Lab-DNS-alert2ir.test")
        self.assertEqual(self.nrpt["namespace"], ".alert2ir.test")
        self.assertEqual(self.nrpt["name_servers"], ["192.168.56.64"])
        self.assertEqual(self.nrpt["policy_store"], "local")
        self.assertFalse(self.nrpt["dnssec_required"])
        self.assertFalse(self.nrpt["direct_access"])

    def test_nrpt_contract_rejects_broad_or_alternate_values(self) -> None:
        self.assertNotIn(self.nrpt["namespace"], {"alert2ir.test", ".test", "."})
        self.assertNotIn("10.0.2.3", self.nrpt["name_servers"])
        self.assertNotIn("8.8.8.8", self.nrpt["name_servers"])
        self.assertEqual(len(self.nrpt["name_servers"]), 1)

    def test_helper_contains_fail_closed_conflict_and_exact_rollback(self) -> None:
        for conflict in (
            "duplicate_display_name",
            "same_namespace_conflict",
            "more_specific_conflict",
            "broad_test_rule",
            "root_catch_all_rule",
            "gpo_or_effective_policy_conflict",
            "directaccess_or_vpn_conflict",
        ):
            self.assertIn(conflict, self.setter)
        self.assertIn("Remove-DnsClientNrptRule -Name $ruleName -Confirm:$false", self.setter)
        self.assertIn("Refusing ambiguous NRPT rollback", self.setter)
        self.assertIn("DirectAccessEnabled", self.setter)
        self.assertIn("DirectAccessEnabled", self.tester)

    def test_helpers_do_not_change_unowned_windows_state(self) -> None:
        combined = self.setter + self.tester
        for prohibited in (
            "Set-ExecutionPolicy",
            "-ExecutionPolicy Bypass",
            "Set-DnsClientServerAddress",
            "Clear-DnsClientCache",
            "ipconfig /flushdns",
            "Set-NetFirewallRule",
            "New-NetFirewallRule",
            "drivers\\etc\\hosts",
        ):
            self.assertNotIn(prohibited.lower(), combined.lower())

    def test_conflict_fixtures_cover_required_cases(self) -> None:
        fixtures = load_json(FIXTURES)["fixtures"]
        self.assertEqual(
            {fixture["name"] for fixture in fixtures},
            {
                "no_rule",
                "exact_rule",
                "duplicate_rule",
                "same_namespace_conflict",
                "more_specific_conflict",
                "broad_test_conflict",
                "root_conflict",
                "gpo_conflict",
                "vpn_directaccess_conflict",
            },
        )
        for fixture in fixtures:
            self.assertEqual(classify_fixture(fixture), sorted(fixture["expected"]), fixture["name"])

    def test_event22_wrapper_remains_separate_from_dns_provisioning(self) -> None:
        wrapper = DNS_WRAPPER.read_text(encoding="utf-8").lower()
        for prohibited in (
            "add-dnsclientnrptrule",
            "remove-dnsclientnrptrule",
            "set-dnsclientserveraddress",
            "clear-dnsclientcache",
            "flushdns",
            "set-netfirewallrule",
            "new-netfirewallrule",
            "drivers\\etc\\hosts",
            "-server",
        ):
            self.assertNotIn(prohibited, wrapper)


class EvidenceContractTests(unittest.TestCase):
    def test_schema_is_closed_and_has_required_statuses(self) -> None:
        schema = load_json(EVIDENCE_SCHEMA)
        self.assertFalse(schema["additionalProperties"])
        statuses = set(schema["properties"]["overall_status"]["enum"])
        self.assertTrue(
            {
                "pass",
                "blocked",
                "review_required",
                "fail_leakage",
                "fail_listener",
                "fail_firewall",
                "fail_nrpt",
                "fail_authoritative",
            }.issubset(statuses)
        )
        self.assertEqual(schema["properties"]["event22_attack_simulation_run"]["const"], False)

    def test_committed_evidence_has_no_raw_capture(self) -> None:
        if not EVIDENCE_ROOT.exists():
            return
        prohibited_suffixes = {".etl", ".pcap", ".pcapng", ".evtx", ".cap"}
        self.assertFalse(
            [path for path in EVIDENCE_ROOT.rglob("*") if path.suffix.lower() in prohibited_suffixes]
        )

    def test_sanitized_evidence_matches_closed_live_contract(self) -> None:
        artifacts = sorted(EVIDENCE_ROOT.glob("dns-infrastructure-*.json"))
        self.assertEqual(len(artifacts), 1)
        evidence = load_json(artifacts[0])
        self.assertEqual(
            set(evidence),
            {
                "schema_version",
                "acceptance_id",
                "timestamp_utc",
                "repository",
                "pre_state",
                "server",
                "firewall",
                "endpoints",
                "rollback",
                "overall_status",
                "event22_attack_simulation_run",
            },
        )
        self.assertEqual(evidence["schema_version"], 1)
        self.assertEqual(evidence["overall_status"], "pass")
        self.assertFalse(evidence["event22_attack_simulation_run"])
        self.assertEqual(evidence["pre_state"]["observed_ufw_state"], "inactive")
        self.assertEqual(evidence["pre_state"]["stored_allowance_count"], 0)
        self.assertEqual(evidence["server"]["authorized_clients"], ["192.168.56.60", "192.168.56.62"])
        self.assertEqual(evidence["server"]["listeners"]["prohibited_listener_count"], 0)
        self.assertFalse(evidence["server"]["recursion"])
        self.assertEqual(evidence["server"]["forwarders"], [])
        self.assertEqual(evidence["firewall"]["new_ssh_reconnection"], "pending")

        contract = load_json(CONTRACT_PATH)
        expected_firewall = [contract["firewall"]["management"], *contract["firewall"]["dns"]]
        self.assertEqual(
            [
                {
                    "source_ipv4": rule["source"],
                    "destination_ipv4": rule["destination"],
                    "interface": rule["interface"],
                    "protocol": rule["protocol"],
                    "destination_port": rule["port"],
                    "comment": rule["comment"],
                    **({"client": expected_firewall[index]["client"]} if "client" in expected_firewall[index] else {}),
                }
                for index, rule in enumerate(evidence["firewall"]["rules"])
            ],
            expected_firewall,
        )

        endpoints = {endpoint["host"]: endpoint for endpoint in evidence["endpoints"]}
        self.assertEqual(set(endpoints), {"win11-01", "win11-02"})
        for host, expected_address in (("win11-01", "192.168.56.60"), ("win11-02", "192.168.56.62")):
            endpoint = endpoints[host]
            self.assertEqual(endpoint["host_only_address"], expected_address)
            self.assertEqual(endpoint["interface_dns_pre"], endpoint["interface_dns_post"])
            self.assertTrue(endpoint["interface_dns_unchanged"])
            self.assertRegex(endpoint["rule_guid"], r"^\{[0-9A-F-]{36}\}$")
            for path_name in ("success_path", "nxdomain_path", "unavailable_server"):
                path = endpoint[path_name]
                self.assertEqual(path["result"], "pass")
                self.assertTrue(path["raw_capture_deleted"])
                self.assertEqual(path["packets_to_nat"], 0)
                self.assertEqual(path["packets_to_other_ipv4"], 0)
                self.assertEqual(path["packets_to_ipv6"], 0)
                self.assertEqual(path["packets_to_vpn"], 0)
                self.assertGreater(path["packets_to_dev01"], 0)
            self.assertEqual(endpoint["ordinary_dns"]["packets_to_nat"], 1)
            self.assertEqual(endpoint["ordinary_dns"]["packets_to_dev01"], 0)
            self.assertTrue(endpoint["ordinary_dns"]["raw_capture_deleted"])
            self.assertEqual(endpoint["result"], "pass")

        serialized = json.dumps(evidence, sort_keys=True).lower()
        for prohibited in (
            "password",
            "private_key",
            "authorization:",
            "ssh-rsa",
            "raw_packet",
            ".pcap",
            ".etl",
            ".evtx",
        ):
            self.assertNotIn(prohibited, serialized)


if __name__ == "__main__":
    unittest.main()
