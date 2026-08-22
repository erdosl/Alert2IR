"""Contracts for the core container to native-host INPUT boundary."""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PATH = ROOT / "compose.yaml"
ARCHITECTURE_PATH = ROOT / "docs" / "ARCHITECTURE.md"
DEPLOYMENT_PATH = ROOT / "docs" / "DEPLOYMENT.md"
LAB_PATH = ROOT / "docs" / "LAB.md"
ADR_PATH = ROOT / "docs" / "adr" / "0018-core-container-host-input-boundary.md"
ADR_INDEX_PATH = ROOT / "docs" / "adr" / "README.md"

NETWORK_KEY = "alert2ir_private"
RUNTIME_NETWORK = "alert2ir_alert2ir_private"
BRIDGE = "alert2ir-prv0"
SUBNET = "172.30.63.0/28"
DYNAMIC_RANGE = "172.30.63.8/29"
GATEWAY = "172.30.63.1"
CORE_IPV4 = "172.30.63.2"
CORE_CIDR = "172.30.63.2/32"
HOST_IPV4 = "192.168.56.63"
PORTS = (8001, 4317)


def markdown_section(source: str, heading: str, next_heading: str) -> str:
    start_marker = f"## {heading}\n"
    end_marker = f"## {next_heading}\n"
    try:
        start = source.index(start_marker)
        end = source.index(end_marker, start + len(start_marker))
    except ValueError as error:
        raise AssertionError(
            f"missing bounded documentation section {heading!r}"
        ) from error
    return source[start:end]


class CoreContainerNetworkContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compose_text = COMPOSE_PATH.read_text(encoding="utf-8")
        cls.compose = yaml.safe_load(cls.compose_text)

    def test_canonical_project_and_exact_single_network_are_preserved(self) -> None:
        self.assertEqual(self.compose["name"], "alert2ir")
        self.assertEqual(set(self.compose["networks"]), {NETWORK_KEY})
        network = self.compose["networks"][NETWORK_KEY]
        self.assertEqual(network["driver"], "bridge")
        self.assertNotIn("name", network)
        self.assertNotIn("internal", network)
        self.assertNotIn("enable_ipv6", network)

    def test_bridge_ipam_and_core_principal_are_exact(self) -> None:
        network = self.compose["networks"][NETWORK_KEY]
        self.assertEqual(len(BRIDGE), 13)
        self.assertRegex(BRIDGE, r"^[A-Za-z0-9_.-]{1,15}$")
        self.assertEqual(
            network["driver_opts"],
            {"com.docker.network.bridge.name": BRIDGE},
        )
        self.assertEqual(
            network["ipam"],
            {
                "config": [
                    {
                        "subnet": SUBNET,
                        "ip_range": DYNAMIC_RANGE,
                        "gateway": GATEWAY,
                    }
                ]
            },
        )
        services = self.compose["services"]
        self.assertEqual(
            services["core"]["networks"],
            {NETWORK_KEY: {"ipv4_address": CORE_IPV4}},
        )
        for sibling in ("splunk_adapter", "postgres"):
            with self.subTest(sibling=sibling):
                self.assertEqual(services[sibling]["networks"], [NETWORK_KEY])
                self.assertNotIn("ipv4_address", services[sibling]["networks"])

    def test_core_principal_is_reserved_outside_dynamic_allocation(self) -> None:
        ipam = self.compose["networks"][NETWORK_KEY]["ipam"]["config"][0]
        core_text = self.compose["services"]["core"]["networks"][NETWORK_KEY][
            "ipv4_address"
        ]

        subnet = ip_network(ipam["subnet"])
        dynamic = ip_network(ipam["ip_range"])
        gateway = ip_address(ipam["gateway"])
        core = ip_address(core_text)

        self.assertTrue(dynamic.subnet_of(subnet))
        self.assertIn(gateway, subnet)
        self.assertIn(core, subnet)
        self.assertNotEqual(core, gateway)
        self.assertNotIn(core, dynamic)

    def test_no_multihoming_or_host_network_workaround_is_added(self) -> None:
        core_networks = self.compose["services"]["core"]["networks"]
        self.assertEqual(len(core_networks), 1)
        for service_name, service in self.compose["services"].items():
            for prohibited in (
                "container_name",
                "network_mode",
                "extra_hosts",
                "mac_address",
                "dns",
            ):
                with self.subTest(
                    service=service_name,
                    prohibited=prohibited,
                ):
                    self.assertNotIn(prohibited, service)
        self.assertNotIn("host-gateway", self.compose_text)


class CoreContainerFirewallDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.architecture = ARCHITECTURE_PATH.read_text(encoding="utf-8")
        cls.deployment = DEPLOYMENT_PATH.read_text(encoding="utf-8")
        cls.lab = LAB_PATH.read_text(encoding="utf-8")
        cls.adr = ADR_PATH.read_text(encoding="utf-8")
        cls.adr_index = ADR_INDEX_PATH.read_text(encoding="utf-8")
        cls.pr3_deployment = markdown_section(
            cls.deployment,
            "Core container-to-host INPUT migration",
            "Database migration",
        )

    def test_exact_identity_and_firewall_domain_are_consistent(self) -> None:
        sources = (
            self.architecture,
            self.pr3_deployment,
            self.lab,
            self.adr,
        )
        for value in (
            NETWORK_KEY,
            BRIDGE,
            CORE_IPV4,
            HOST_IPV4,
        ):
            with self.subTest(value=value):
                for source in sources:
                    self.assertIn(value, source)
        for value in (SUBNET, DYNAMIC_RANGE, GATEWAY):
            with self.subTest(value=value):
                for source in (
                    self.architecture,
                    self.pr3_deployment,
                    self.lab,
                    self.adr,
                ):
                    self.assertIn(value, source)
        for value in (RUNTIME_NETWORK, CORE_CIDR):
            with self.subTest(value=value):
                self.assertIn(value, self.pr3_deployment)
                self.assertIn(value, self.adr)
        self.assertIn("UFW remains the host `INPUT` authority", self.adr)
        self.assertIn("UFW `INPUT`", self.pr3_deployment)
        self.assertIn("default INPUT deny", self.pr3_deployment)

    def test_project_identity_is_fail_closed_before_compose_teardown(self) -> None:
        preflight_start = self.pr3_deployment.index(
            "### Preflight and evidence capture"
        )
        cutover_start = self.pr3_deployment.index("### Controlled Compose cutover")
        preflight = self.pr3_deployment[preflight_start:cutover_start]
        first_down = self.pr3_deployment.index(
            "-f compose.yaml -f compose.velociraptor.yaml down"
        )

        for expected in (
            '[ -n "${COMPOSE_PROJECT_NAME:-}" ]',
            "COMPOSE_PROJECT_NAME must be unset",
            "config --format json",
            'json.load(sys.stdin)["name"]',
            '[ "$effective_project" != "alert2ir" ]',
            "effective Compose project is %s, expected alert2ir",
            "Resolve the project identity first",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, preflight)
                self.assertLess(self.pr3_deployment.index(expected), first_down)

        project_check_start = preflight.index(
            'if [ -n "${COMPOSE_PROJECT_NAME:-}" ]'
        )
        project_check_end = preflight.index("Repeat the collision inventory")
        project_check = preflight[project_check_start:project_check_end]
        self.assertGreaterEqual(project_check.count("exit 1"), 2)
        self.assertIn("set -euo pipefail", preflight[:project_check_end])
        self.assertLess(
            preflight.index('[ -n "${COMPOSE_PROJECT_NAME:-}" ]'),
            preflight.index("config --quiet"),
        )
        self.assertEqual(
            project_check.count(
                "docker compose --env-file /etc/alert2ir/runtime.env"
            ),
            2,
        )
        self.assertEqual(
            project_check.count(
                "-f compose.yaml -f compose.velociraptor.yaml"
            ),
            2,
        )

        for block in re.findall(r"```bash\n(.*?)```", self.deployment, re.DOTALL):
            normalized_block = block.replace("\\\n", " ")
            for command in normalized_block.splitlines():
                if "docker compose" not in command:
                    continue
                self.assertNotIn("--project-name", command)
                self.assertNotRegex(command, r"(?:^|\s)-p(?:\s|$)")

    def test_ufw_security_gates_precede_all_cutover_mutation(self) -> None:
        preflight_start = self.pr3_deployment.index(
            "### Preflight and evidence capture"
        )
        cutover_start = self.pr3_deployment.index("### Controlled Compose cutover")
        preflight = self.pr3_deployment[preflight_start:cutover_start]
        first_down = self.pr3_deployment.index(
            "-f compose.yaml -f compose.velociraptor.yaml down"
        )

        for expected in (
            '"Status: active"',
            'configured_input" != "DROP"',
            'effective_input" != "DROP"',
            "Inactive UFW",
            "fresh `NEW` TCP packet",
            "unexpected shadowing rule",
            "STOP BEFORE MUTATION",
            "sudo iptables-save -t filter",
            "sudo /usr/local/sbin/alert2ir-splunk-adapter-firewall check",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, preflight)
                self.assertLess(self.pr3_deployment.index(expected), first_down)

        self.assertNotRegex(preflight, r"(?m)^sudo ufw (?:allow|delete)\b")
        self.assertNotRegex(
            preflight,
            r"(?m)^\s*docker (?:compose\b[^\n]*\bdown\b|rm\b|network rm\b)",
        )
        self.assertIn("Do not enable UFW or rewrite either default policy", preflight)
        self.assertIn("Do not delete or repair it as part of this migration", preflight)

    def test_known_legacy_preflight_is_exact_and_unexpected_policy_stops(self) -> None:
        preflight_start = self.pr3_deployment.index(
            "### Preflight and evidence capture"
        )
        cutover_start = self.pr3_deployment.index("### Controlled Compose cutover")
        preflight = self.pr3_deployment[preflight_start:cutover_start]
        expected = (
            (
                "br-d6c8e81dca5d",
                "172.19.0.0/16",
                8001,
                "Alert2IR Velociraptor API",
            ),
            (
                "br-d6c8e81dca5d",
                "172.19.0.0/16",
                4317,
                "Alert2IR local OTLP",
            ),
            (
                "br-987bf7432abc",
                "172.20.0.0/16",
                8001,
                "Alert2IR canonical Velociraptor API",
            ),
            (
                "br-987bf7432abc",
                "172.20.0.0/16",
                4317,
                "Alert2IR canonical local OTLP",
            ),
        )
        for bridge, subnet, port, comment in expected:
            with self.subTest(bridge=bridge, subnet=subnet, port=port):
                self.assertIn(
                    f"ufw allow in on {bridge} from {subnet} "
                    f"to {HOST_IPV4} port {port} proto tcp comment '{comment}'",
                    preflight,
                )
        self.assertIn("legacy_count", preflight)
        self.assertIn('[ "$legacy_count" -ne 1 ]', preflight)
        self.assertIn("Any additional earlier ACCEPT", preflight)
        self.assertIn("stop and inspect instead of guessing a deletion", preflight)

    def test_two_exact_ufw_allows_are_the_only_desired_authorizations(self) -> None:
        desired_start = self.pr3_deployment.index("The only desired authorizations")
        desired_end = self.pr3_deployment.index(
            "The following four rules are historical migration state",
            desired_start,
        )
        desired = self.pr3_deployment[desired_start:desired_end]
        normalized_desired = desired.replace("\\\n", " ")
        for port, comment in (
            (8001, "Alert2IR core Velociraptor API"),
            (4317, "Alert2IR core local OTLP"),
        ):
            with self.subTest(port=port):
                self.assertRegex(
                    normalized_desired,
                    re.compile(
                        rf"sudo ufw allow in on {re.escape(BRIDGE)}\s+"
                        rf"from {re.escape(CORE_IPV4)}\s+"
                        rf"to {re.escape(HOST_IPV4)}\s+"
                        rf"port {port}\s+"
                        rf"proto tcp\s+"
                        rf"comment '{re.escape(comment)}'"
                    ),
                )
        for unauthorized in (
            SUBNET,
            DYNAMIC_RANGE,
            "172.19.0.0/16",
            "172.20.0.0/16",
            "0.0.0.0/0",
            "splunk_adapter",
            "postgres",
        ):
            with self.subTest(unauthorized=unauthorized):
                self.assertNotIn(unauthorized, desired)

    def test_prestart_topology_uses_requested_ipam_address_before_mutation(self) -> None:
        cutover_start = self.pr3_deployment.index("### Controlled Compose cutover")
        firewall_start = self.pr3_deployment.index("### Exact UFW reconciliation")
        prestart = self.pr3_deployment[cutover_start:firewall_start]
        create_index = self.pr3_deployment.index(
            "-f compose.yaml -f compose.velociraptor.yaml create"
        )
        requested_address_index = self.pr3_deployment.index(
            ".IPAMConfig.IPv4Address"
        )
        first_ufw_mutation = self.pr3_deployment.index(
            "sudo ufw allow in on alert2ir-prv0"
        )
        compose_up = self.pr3_deployment.index(
            "-f compose.yaml -f compose.velociraptor.yaml up -d --wait"
        )
        for expected in (
            "docker network inspect alert2ir_alert2ir_private",
            "{{.IPRange}}",
            "docker inspect alert2ir-core-1",
            "core_requested_address",
            ".IPAMConfig.IPv4Address",
            '"172.30.63.8/29"',
            "dynamic.subnet_of(subnet)",
            "core in dynamic",
            "core firewall principal overlaps the dynamic range",
            "172.30.63.2` is not in `172.30.63.8/29",
            "STOP before UFW mutation or service start",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, prestart)
        self.assertRegex(
            prestart,
            re.compile(
                r'core_requested_address="\$\(\s*'
                r'docker inspect alert2ir-core-1 --format\s*\\\s*'
                r"'\{\{with index \.NetworkSettings\.Networks "
                r'"alert2ir_alert2ir_private"\}\}'
                r"\{\{\.IPAMConfig\.IPv4Address\}\}\{\{end\}\}'\s*"
                r'\)"',
                re.DOTALL,
            ),
        )
        self.assertIn(
            'python3 - "$network_fields" "$core_requested_address"',
            prestart,
        )
        self.assertIn("core_requested_text = sys.argv[2]", prestart)
        self.assertRegex(
            prestart,
            re.compile(
                r"if \(subnet_text, dynamic_text, gateway_text, "
                r'core_requested_text\) != \(\s*"'
                + re.escape(SUBNET)
                + r'",\s*"'
                + re.escape(DYNAMIC_RANGE)
                + r'",\s*"'
                + re.escape(GATEWAY)
                + r'",\s*"'
                + re.escape(CORE_IPV4)
                + r'",\s*\):',
                re.DOTALL,
            ),
        )
        self.assertNotIn(".IPAddress", prestart)
        self.assertLess(create_index, requested_address_index)
        self.assertLess(requested_address_index, firewall_start)
        self.assertLess(requested_address_index, first_ufw_mutation)
        self.assertLess(requested_address_index, compose_up)

    def test_poststart_acceptance_requires_actual_core_endpoint(self) -> None:
        compose_up = self.pr3_deployment.index(
            "-f compose.yaml -f compose.velociraptor.yaml up -d --wait"
        )
        acceptance_start = self.pr3_deployment.index(
            "### Source-correct live acceptance"
        )
        poststart = self.pr3_deployment[compose_up:acceptance_start]
        live_address_index = self.pr3_deployment.index(
            ".IPAddress",
            compose_up,
        )

        self.assertIn("core_live_address", poststart)
        self.assertIn(".IPAddress", poststart)
        self.assertNotIn(".IPAMConfig.IPv4Address", poststart)
        self.assertRegex(
            poststart,
            re.compile(
                r'core_live_address="\$\(\s*'
                r'docker inspect alert2ir-core-1 --format\s*\\\s*'
                r"'\{\{with index \.NetworkSettings\.Networks "
                r'"alert2ir_alert2ir_private"\}\}'
                r"\{\{\.IPAddress\}\}\{\{end\}\}'\s*"
                r'\)"',
                re.DOTALL,
            ),
        )
        self.assertIn(
            '[ "$core_live_address" != "172.30.63.2" ]',
            poststart,
        )
        self.assertIn("acceptance fails", poststart)
        self.assertIn("exit 1", poststart)
        self.assertLess(compose_up, live_address_index)
        self.assertLess(live_address_index, acceptance_start)

    def test_historical_broad_rules_have_exact_safe_removals(self) -> None:
        historical_start = self.pr3_deployment.index(
            "The following four rules are historical migration state"
        )
        historical_end = self.pr3_deployment.index(
            "After the narrow changes",
            historical_start,
        )
        historical = self.pr3_deployment[historical_start:historical_end]
        normalized_historical = historical.replace("\\\n", " ")
        expected = (
            ("br-d6c8e81dca5d", "172.19.0.0/16", 8001),
            ("br-d6c8e81dca5d", "172.19.0.0/16", 4317),
            ("br-987bf7432abc", "172.20.0.0/16", 8001),
            ("br-987bf7432abc", "172.20.0.0/16", 4317),
        )
        for bridge, subnet, port in expected:
            with self.subTest(bridge=bridge, subnet=subnet, port=port):
                self.assertRegex(
                    normalized_historical,
                    re.compile(
                        rf"sudo ufw --force delete allow in on {re.escape(bridge)}\s+"
                        rf"from {re.escape(subnet)} to {re.escape(HOST_IPV4)} "
                        rf"port {port} proto tcp"
                    ),
                )
        self.assertIn("known legacy migration inputs", self.pr3_deployment)
        self.assertIn("distinguishes them from unexplained policy", self.pr3_deployment)

    def test_input_and_docker_user_authorities_remain_separate(self) -> None:
        for source in (self.architecture, self.adr, self.pr3_deployment):
            self.assertIn("DOCKER-USER", source)
            self.assertIn(":8091", source)
            self.assertIn(":8001", source)
            self.assertIn(":4317", source)
        self.assertIn("UFW INPUT does not own the published `:8091` path", self.architecture)
        self.assertIn("`DOCKER-USER` does not own native `:8001` or `:4317`", self.architecture)

    def test_pr3_instructions_do_not_reset_or_replace_firewall_or_services(self) -> None:
        prohibited_patterns = (
            r"(?m)^\s*(?:sudo\s+)?ufw\s+(?:--force\s+)?reset\b",
            r"(?m)^\s*(?:sudo\s+)?iptables\b[^\n]*(?:\s-F\b|--flush\b)",
            r"(?m)^\s*(?:sudo\s+)?iptables\b[^\n]*\s-P\s+(?:INPUT|FORWARD)\b",
            r"(?m)^\s*(?:sudo\s+)?nft\s+flush\s+ruleset\b",
            r"(?m)^\s*(?:sudo\s+)?ufw\s+default\b",
            r"(?m)^\s*(?:sudo\s+)?systemctl\s+(?:restart|reload)\s+"
            r"(?:docker|containerd|alloy|velociraptor)",
            r"(?m)^\s*docker\s+restart\b",
        )
        for pattern in prohibited_patterns:
            with self.subTest(pattern=pattern):
                self.assertNotRegex(self.pr3_deployment, pattern)
        self.assertNotIn("ExecStart=", self.pr3_deployment)
        self.assertNotIn("core-input-firewall", self.pr3_deployment)
        self.assertIn(
            "Do not reset UFW, change a default policy, replace the user chains",
            self.pr3_deployment,
        )

    def test_acceptance_idempotence_persistence_and_rollback_are_frozen(self) -> None:
        for expected in (
            "Source-correct live acceptance",
            "alert2ir-splunk_adapter-1",
            "alert2ir-postgres-1",
            "raise SystemExit(1 if failed else 0)",
            "test \"$probe_status\" -eq 124 || exit 1",
            "FORWARD and DOCKER-USER counters must not move",
            "Health, topology, and process acceptance",
            "All three container IDs and start timestamps must change",
            "Idempotence and separate persistence gate",
            "same Docker network ID",
            "separately approved `ir-core` reboot",
            "Narrow rollback",
            "known overbroad sibling-container authorization",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.pr3_deployment)
        self.assertIn("`ufw.service` and UFW's stored rule state", self.adr)

    def test_adr_is_indexed_and_records_rejected_widening(self) -> None:
        self.assertIn(
            "`0018-core-container-host-input-boundary.md`",
            self.adr_index,
        )
        for expected in (
            "whole Docker subnet is not authorized",
            "A second network would multi-home `core`",
            "`DOCKER-USER` is not the packet path",
            "Puppet firewall ownership",
            "`enp0s8`",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.adr)


if __name__ == "__main__":
    unittest.main()
