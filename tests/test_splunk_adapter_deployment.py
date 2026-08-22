"""Static and local runtime contracts for the Splunk adapter deployment."""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from fastapi.testclient import TestClient
import yaml

from alert2ir.adapters.splunk.runtime import (
    CORE_URL_ENVIRONMENT_VARIABLE,
    REQUEST_TIMEOUT_ENVIRONMENT_VARIABLE,
    SECRET_FILE_ENVIRONMENT_VARIABLE,
    RuntimeConfigurationError,
    create_splunk_adapter_app_from_environment,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PATH = REPOSITORY_ROOT / "compose.yaml"
ENVIRONMENT_EXAMPLE_PATH = REPOSITORY_ROOT / ".env.example"
DEPLOYMENT_PATH = REPOSITORY_ROOT / "docs" / "DEPLOYMENT.md"
SPLUNK_APP_ROOT = (
    REPOSITORY_ROOT / "integrations" / "splunk" / "alert2ir_delivery"
)
SAVED_SEARCH_PATH = SPLUNK_APP_ROOT / "default" / "savedsearches.conf"
PACKAGE_SCRIPT_PATH = (
    REPOSITORY_ROOT / "tools" / "splunk" / "build-alert2ir-delivery-app.sh"
)

HOST_SECRET_SOURCE_VARIABLE = "ALERT2IR_SPLUNK_ADAPTER_SECRET_SOURCE"
POSTGRES_VOLUME_VARIABLE = "ALERT2IR_POSTGRES_VOLUME"
CONTAINER_SECRET_PATH = "/run/secrets/alert2ir-splunk-adapter"


def compose_service_blocks(source: str) -> dict[str, str]:
    lines = source.splitlines()
    try:
        start = lines.index("services:") + 1
    except ValueError as error:
        raise AssertionError("missing top-level services mapping") from error

    blocks: dict[str, list[str]] = {}
    current_service: str | None = None
    for line in lines[start:]:
        if line and not line.startswith((" ", "#")):
            break
        match = re.match(r"^  ([a-z][a-z0-9_-]*):\s*$", line)
        if match:
            current_service = match.group(1)
            blocks[current_service] = []
        elif current_service is not None:
            blocks[current_service].append(line)
    return {name: "\n".join(block) for name, block in blocks.items()}


def compose_service_ports(service: str) -> set[str]:
    lines = service.splitlines()
    try:
        start = lines.index("    ports:") + 1
    except ValueError:
        return set()

    ports: set[str] = set()
    for line in lines[start:]:
        if re.match(r"^    [a-z][a-z0-9_-]*:", line):
            break
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r'      - "([^"]+)"', line)
        if match is None:
            raise AssertionError("ports must use quoted short syntax")
        ports.add(match.group(1))
    return ports


class SplunkAdapterRuntimeConfigurationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.secret_path = Path(self.temporary.name) / "adapter.secret"
        self.secret_path.write_bytes(b"s" * 32 + b"\n")

    def environment(self, **overrides: str) -> dict[str, str]:
        result = {
            CORE_URL_ENVIRONMENT_VARIABLE: "http://core:8000",
            SECRET_FILE_ENVIRONMENT_VARIABLE: str(self.secret_path),
            REQUEST_TIMEOUT_ENVIRONMENT_VARIABLE: "5",
        }
        result.update(overrides)
        return result

    def test_valid_configuration_constructs_a_shallow_healthy_app(self) -> None:
        app = create_splunk_adapter_app_from_environment(self.environment())
        with TestClient(app) as client:
            response = client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_missing_required_configuration_is_rejected_at_construction(self) -> None:
        for variable in (
            CORE_URL_ENVIRONMENT_VARIABLE,
            SECRET_FILE_ENVIRONMENT_VARIABLE,
        ):
            with self.subTest(variable=variable):
                environment = self.environment()
                del environment[variable]
                with self.assertRaises(RuntimeConfigurationError):
                    create_splunk_adapter_app_from_environment(environment)

    def test_missing_directory_and_short_secret_are_rejected(self) -> None:
        cases = (
            self.secret_path.with_name("missing.secret"),
            Path(self.temporary.name),
        )
        for path in cases:
            with self.subTest(path=path.name):
                with self.assertRaisesRegex(
                    RuntimeConfigurationError,
                    "secret file",
                ):
                    create_splunk_adapter_app_from_environment(
                        self.environment(
                            **{SECRET_FILE_ENVIRONMENT_VARIABLE: str(path)}
                        )
                    )

        self.secret_path.write_bytes(b"s" * 31)
        with self.assertRaisesRegex(RuntimeConfigurationError, "32 bytes"):
            create_splunk_adapter_app_from_environment(self.environment())

    def test_invalid_core_url_and_timeout_are_rejected(self) -> None:
        invalid_values = (
            (CORE_URL_ENVIRONMENT_VARIABLE, "core:8000"),
            (CORE_URL_ENVIRONMENT_VARIABLE, "http://core:8000/v1/alerts"),
            (REQUEST_TIMEOUT_ENVIRONMENT_VARIABLE, "0"),
            (REQUEST_TIMEOUT_ENVIRONMENT_VARIABLE, "nan"),
            (REQUEST_TIMEOUT_ENVIRONMENT_VARIABLE, "not-a-number"),
        )
        for variable, value in invalid_values:
            with self.subTest(variable=variable, value=value):
                with self.assertRaises(RuntimeConfigurationError):
                    create_splunk_adapter_app_from_environment(
                        self.environment(**{variable: value})
                    )

    def test_configuration_errors_do_not_echo_secret_material(self) -> None:
        sensitive = "do-not-echo-this-secret-value"
        self.secret_path.write_text(sensitive, encoding="utf-8")
        with self.assertRaises(RuntimeConfigurationError) as raised:
            create_splunk_adapter_app_from_environment(self.environment())
        self.assertNotIn(sensitive, str(raised.exception))


class SplunkAdapterComposeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compose = COMPOSE_PATH.read_text(encoding="utf-8")
        cls.configuration = yaml.safe_load(cls.compose)
        cls.services = compose_service_blocks(cls.compose)

    def test_separate_adapter_service_and_exact_host_publications(self) -> None:
        self.assertRegex(self.compose, r"(?m)^name: alert2ir$")
        self.assertNotIn("container_name:", self.compose)
        self.assertEqual(
            set(self.services),
            {"core", "postgres", "splunk_adapter"},
        )
        self.assertEqual(
            compose_service_ports(self.services["core"]),
            {"127.0.0.1:8000:8000"},
        )
        self.assertEqual(
            compose_service_ports(self.services["splunk_adapter"]),
            {"192.168.56.63:8091:8091"},
        )
        self.assertEqual(compose_service_ports(self.services["postgres"]), set())
        self.assertNotIn("0.0.0.0:8091", self.compose)
        self.assertNotIn("network_mode: host", self.compose)
        self.assertNotIn("extra_hosts:", self.compose)
        self.assertNotIn("host-gateway", self.compose)

    def test_adapter_uses_runtime_factory_and_private_core_origin(self) -> None:
        adapter = self.services["splunk_adapter"]
        self.assertIn(
            "alert2ir.adapters.splunk.runtime:create_splunk_adapter_app_from_environment",
            adapter,
        )
        self.assertIn("--factory", adapter)
        self.assertIn(f"{CORE_URL_ENVIRONMENT_VARIABLE}: http://core:8000", adapter)
        self.assertIn(
            f'{REQUEST_TIMEOUT_ENVIRONMENT_VARIABLE}: "5"',
            adapter,
        )
        self.assertNotIn("/v1/alerts", adapter)
        self.assertNotIn("Idempotency-Key", adapter)
        self.assertNotIn("ALERT2IR_DATABASE_URL", adapter)
        self.assertNotIn("VELOCIRAPTOR", adapter)
        self.assertNotIn("/var/run/docker.sock", adapter)
        self.assertNotIn("privileged: true", adapter)
        self.assertRegex(
            adapter,
            r"(?m)^    depends_on:\n      core:\n        condition: service_healthy$",
        )

    def test_adapter_secret_is_an_external_read_only_file_mount(self) -> None:
        adapter = self.services["splunk_adapter"]
        expected_source = (
            "${ALERT2IR_SPLUNK_ADAPTER_SECRET_SOURCE:?"
            "ALERT2IR_SPLUNK_ADAPTER_SECRET_SOURCE is required}"
        )
        self.assertIn(f"source: {expected_source}", adapter)
        self.assertIn(f"target: {CONTAINER_SECRET_PATH}", adapter)
        self.assertIn("read_only: true", adapter)
        self.assertIn("create_host_path: false", adapter)
        self.assertIn(
            f"{SECRET_FILE_ENVIRONMENT_VARIABLE}: {CONTAINER_SECRET_PATH}",
            adapter,
        )
        self.assertNotRegex(
            adapter,
            r"(?m)^\s*(?:shared_secret|ALERT2IR_SPLUNK_ADAPTER_SECRET):",
        )

    def test_adapter_health_logging_and_private_network_are_explicit(self) -> None:
        adapter = self.services["splunk_adapter"]
        self.assertIn("http://127.0.0.1:8091/healthz", adapter)
        self.assertNotIn("/readyz", adapter)
        self.assertIn('max-size: "10m"', adapter)
        self.assertIn('max-file: "3"', adapter)
        self.assertNotIn("restart_policy", adapter)
        for service_name in ("postgres", "splunk_adapter"):
            with self.subTest(service=service_name):
                self.assertRegex(
                    self.services[service_name],
                    r"(?m)^    networks:\n      - alert2ir_private$",
                )
        self.assertRegex(
            self.services["core"],
            r"(?m)^    networks:\n      alert2ir_private:\n"
            r"        ipv4_address: 172\.30\.63\.2$",
        )

    def test_private_network_has_exact_stable_ipam_and_bridge_contract(self) -> None:
        self.assertEqual(self.configuration["name"], "alert2ir")
        self.assertEqual(
            set(self.configuration["networks"]),
            {"alert2ir_private"},
        )
        network = self.configuration["networks"]["alert2ir_private"]
        self.assertEqual(network["driver"], "bridge")
        self.assertEqual(
            network["driver_opts"],
            {"com.docker.network.bridge.name": "alert2ir-prv0"},
        )
        self.assertEqual(
            network["ipam"],
            {
                "config": [
                    {
                        "subnet": "172.30.63.0/28",
                        "ip_range": "172.30.63.8/29",
                        "gateway": "172.30.63.1",
                    }
                ]
            },
        )
        self.assertNotIn("name", network)
        self.assertNotIn("internal", network)
        self.assertNotIn("enable_ipv6", network)

    def test_core_static_address_is_semantically_reserved_from_dynamic_ipam(self) -> None:
        ipam = self.configuration["networks"]["alert2ir_private"]["ipam"][
            "config"
        ][0]
        core_text = self.configuration["services"]["core"]["networks"][
            "alert2ir_private"
        ]["ipv4_address"]

        subnet = ip_network(ipam["subnet"])
        dynamic = ip_network(ipam["ip_range"])
        gateway = ip_address(ipam["gateway"])
        core = ip_address(core_text)

        self.assertTrue(dynamic.subnet_of(subnet))
        self.assertIn(gateway, subnet)
        self.assertIn(core, subnet)
        self.assertNotEqual(core, gateway)
        self.assertNotIn(core, dynamic)

    def test_only_core_has_one_static_private_network_address(self) -> None:
        services = self.configuration["services"]
        self.assertEqual(
            services["core"]["networks"],
            {"alert2ir_private": {"ipv4_address": "172.30.63.2"}},
        )
        for service_name in ("postgres", "splunk_adapter"):
            with self.subTest(service=service_name):
                self.assertEqual(
                    services[service_name]["networks"],
                    ["alert2ir_private"],
                )
                self.assertNotIn(
                    "ipv4_address",
                    self.services[service_name],
                )

    def test_restart_readiness_ordering_and_external_database_volume(self) -> None:
        for service_name in ("core", "postgres", "splunk_adapter"):
            with self.subTest(service=service_name):
                self.assertRegex(
                    self.services[service_name],
                    r"(?m)^    restart: unless-stopped$",
                )
        self.assertRegex(
            self.services["core"],
            r"(?m)^    depends_on:\n      postgres:\n"
            r"        condition: service_healthy$",
        )
        self.assertIn("http://127.0.0.1:8000/healthz", self.services["core"])
        self.assertNotIn("/readyz", self.services["core"])
        self.assertRegex(
            self.compose,
            r"(?m)^volumes:\n  postgres_data:\n"
            r"    external: true\n"
            r"    name: \$\{ALERT2IR_POSTGRES_VOLUME:\?"
            r"ALERT2IR_POSTGRES_VOLUME is required\}$",
        )

    def test_environment_template_contains_only_a_secret_path(self) -> None:
        template = ENVIRONMENT_EXAMPLE_PATH.read_text(encoding="utf-8")
        self.assertIn(f"{HOST_SECRET_SOURCE_VARIABLE}=", template)
        self.assertIn(
            f"{POSTGRES_VOLUME_VARIABLE}=alert2ir-postgres-data",
            template,
        )
        self.assertNotIn("ALERT2IR_SPLUNK_ADAPTER_SECRET=", template)


class SplunkDeploymentArtifactTests(unittest.TestCase):
    def test_splunk_app_is_self_contained_and_has_no_local_configuration(self) -> None:
        files = {
            path.relative_to(SPLUNK_APP_ROOT).as_posix()
            for path in SPLUNK_APP_ROOT.rglob("*")
            if path.is_file()
        }
        self.assertEqual(
            files,
            {
                "README.md",
                "README/alert_actions.conf.spec",
                "bin/alert2ir_delivery.py",
                "default/alert_actions.conf",
                "default/app.conf",
                "default/savedsearches.conf",
                "metadata/default.meta",
            },
        )
        self.assertTrue((SPLUNK_APP_ROOT / "bin" / "alert2ir_delivery.py").stat().st_mode & 0o111)
        self.assertFalse((SPLUNK_APP_ROOT / "local").exists())

    def test_host_specific_action_values_are_not_in_defaults(self) -> None:
        saved_search = SAVED_SEARCH_PATH.read_text(encoding="utf-8")
        self.assertRegex(
            saved_search,
            r"(?m)^action\.alert2ir_delivery\.param\.adapter_url\s*=\s*$",
        )
        self.assertRegex(
            saved_search,
            r"(?m)^action\.alert2ir_delivery\.param\.secret_file\s*=\s*$",
        )
        self.assertIn("disabled = true", saved_search)
        self.assertIn("enableSched = 0", saved_search)
        self.assertNotIn("192.168.56.63", saved_search)
        self.assertNotIn("/opt/splunk", saved_search)

    def test_packaging_script_is_shell_valid_and_refuses_worktree_input(self) -> None:
        completed = subprocess.run(
            ["bash", "-n", str(PACKAGE_SCRIPT_PATH)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        script = PACKAGE_SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn("git -C", script)
        self.assertIn('git -C "$repository_root" archive', script)
        self.assertIn("sha256sum", script)
        self.assertNotIn("tar -C integrations", script)

    def test_deployment_guide_freezes_firewall_and_validation_boundaries(self) -> None:
        deployment = DEPLOYMENT_PATH.read_text(encoding="utf-8")
        for expected in (
            "192.168.56.61",
            "192.168.56.63:8091",
            "DOCKER-USER",
            "--ctorigdst 192.168.56.63",
            "--ctorigdstport 8091",
            "high-severity validation marker remains disabled",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, deployment)


if __name__ == "__main__":
    unittest.main()
