"""Repository contracts for the WS12 Stage 2 observability configuration.

These standard-library checks freeze security and topology invariants without
pretending to replace the pinned upstream component validators or Stage 3
runtime validation.
"""

from pathlib import Path
import configparser
import json
import re
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
OBSERVABILITY_ROOT = REPOSITORY_ROOT / "observability"
APPLICATION_COMPOSE_PATH = REPOSITORY_ROOT / "compose.yaml"
COMPOSE_PATH = OBSERVABILITY_ROOT / "compose.yaml"
IR_CORE_ALLOY_PATH = OBSERVABILITY_ROOT / "alloy" / "ir-core.alloy"
OBS01_ALLOY_PATH = OBSERVABILITY_ROOT / "alloy" / "obs01.alloy"
LAB_PATH = REPOSITORY_ROOT / "docs" / "LAB.md"
DATASOURCES_PATH = (
    OBSERVABILITY_ROOT
    / "grafana"
    / "provisioning"
    / "datasources"
    / "datasources.yml"
)
DASHBOARD_PROVIDER_PATH = (
    OBSERVABILITY_ROOT
    / "grafana"
    / "provisioning"
    / "dashboards"
    / "dashboards.yml"
)
DASHBOARDS_ROOT = OBSERVABILITY_ROOT / "grafana" / "dashboards"
PROMETHEUS_RULES_PATH = (
    OBSERVABILITY_ROOT / "prometheus" / "rules" / "alert2ir.yml"
)
PROMETHEUS_RULE_TESTS_PATH = (
    OBSERVABILITY_ROOT / "prometheus" / "tests" / "alert2ir_rules_test.yml"
)
README_PATH = OBSERVABILITY_ROOT / "README.md"

REQUIRED_FILES = {
    ".env.example",
    "README.md",
    "alertmanager/alertmanager.yml",
    "alloy/ir-core.alloy",
    "alloy/obs01.alloy",
    "compose.yaml",
    "grafana/dashboards/alert2ir-application.json",
    "grafana/dashboards/alert2ir-edge.json",
    "grafana/dashboards/alert2ir-platform.json",
    "grafana/grafana.ini",
    "grafana/provisioning/dashboards/dashboards.yml",
    "grafana/provisioning/datasources/datasources.yml",
    "loki/loki.yml",
    "prometheus/prometheus.yml",
    "prometheus/rules/alert2ir.yml",
    "prometheus/tests/alert2ir_rules_test.yml",
    "tempo/tempo.yml",
}
CENTRAL_SERVICES = {"grafana", "prometheus", "alertmanager", "loki", "tempo"}
IMAGE_REFERENCE = re.compile(
    r"^[a-z0-9./_-]+:v?\d+\.\d+\.\d+@sha256:[0-9a-f]{64}$"
)


def read(relative_path: str) -> str:
    return (OBSERVABILITY_ROOT / relative_path).read_text(encoding="utf-8")


def yaml_children(source: str, top_level_key: str) -> list[str]:
    """Return direct child keys of one simple top-level YAML mapping."""
    lines = source.splitlines()
    try:
        start = lines.index(f"{top_level_key}:") + 1
    except ValueError as error:
        raise AssertionError(f"missing top-level {top_level_key!r} mapping") from error

    children = []
    for line in lines[start:]:
        if line and not line.startswith((" ", "#")):
            break
        match = re.match(r"^  ([a-z][a-z0-9_-]*):\s*$", line)
        if match:
            children.append(match.group(1))
    return children


def compose_service_blocks(source: str) -> dict[str, str]:
    """Return each service body from the repository's simple Compose model."""
    lines = source.splitlines()
    try:
        start = lines.index("services:") + 1
    except ValueError as error:
        raise AssertionError("missing top-level 'services' mapping") from error

    blocks: dict[str, list[str]] = {}
    current_service = None
    for line in lines[start:]:
        if line and not line.startswith((" ", "#")):
            break
        match = re.match(r"^  ([a-z][a-z0-9_-]*):\s*$", line)
        if match:
            current_service = match.group(1)
            blocks[current_service] = []
        elif current_service is not None:
            blocks[current_service].append(line)
    return {name: "\n".join(lines) for name, lines in blocks.items()}


def compose_service_ports(service: str) -> set[str]:
    """Return exact short-syntax publications, rejecting implicit/long forms."""
    lines = service.splitlines()
    try:
        start = lines.index("    ports:") + 1
    except ValueError:
        return set()

    ports = set()
    for line in lines[start:]:
        if re.match(r"^    [a-z][a-z0-9_-]*:", line):
            break
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r'      - "([^"]+)"', line)
        if not match:
            raise AssertionError(
                "host publications must use quoted IP:host-port:container-port syntax"
            )
        ports.add(match.group(1))
    return ports


def compose_service_logging(service: str) -> dict[str, object]:
    """Return the explicit driver and options from one service logging block."""
    lines = service.splitlines()
    try:
        start = lines.index("    logging:") + 1
    except ValueError as error:
        raise AssertionError("service must define an explicit logging block") from error

    block = []
    for line in lines[start:]:
        if re.match(r"^    [a-z][a-z0-9_-]*:", line):
            break
        block.append(line)

    drivers = re.findall(r"^      driver: ([a-z0-9-]+)$", "\n".join(block), re.MULTILINE)
    options = dict(
        re.findall(
            r'^        ([a-z][a-z0-9-]*): "([^"]+)"$',
            "\n".join(block),
            re.MULTILINE,
        )
    )
    if len(drivers) != 1:
        raise AssertionError("logging block must define exactly one driver")
    return {"driver": drivers[0], "options": options}


def alloy_blocks(source: str, block_name: str) -> list[str]:
    """Extract balanced Alloy blocks for narrow label-policy assertions."""
    blocks = []
    for match in re.finditer(rf"\b{re.escape(block_name)}\s*\{{", source):
        opening = source.index("{", match.start(), match.end())
        depth = 0
        for index in range(opening, len(source)):
            if source[index] == "{":
                depth += 1
            elif source[index] == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(source[opening + 1 : index])
                    break
        else:
            raise AssertionError(f"unterminated Alloy {block_name} block")
    return blocks


def sole_alloy_block(source: str, block_name: str) -> str:
    """Return exactly one named Alloy block."""
    blocks = alloy_blocks(source, block_name)
    if len(blocks) != 1:
        raise AssertionError(
            f"expected exactly one Alloy {block_name} block, found {len(blocks)}"
        )
    return blocks[0]


def alloy_listener(block: str) -> tuple[str, int]:
    """Return the exact address and port from one Alloy listener block."""
    addresses = re.findall(
        r'^\s*listen_address\s*=\s*"([^"]+)"\s*$', block, re.MULTILINE
    )
    ports = re.findall(r"^\s*listen_port\s*=\s*(\d+)\s*$", block, re.MULTILINE)
    if len(addresses) != 1 or len(ports) != 1:
        raise AssertionError("Alloy listener must define one address and one port")
    return addresses[0], int(ports[0])


def alloy_endpoint(block: str) -> str:
    """Return the exact endpoint from one Alloy transport block."""
    endpoints = re.findall(r'^\s*endpoint\s*=\s*"([^"]+)"\s*$', block, re.MULTILINE)
    if len(endpoints) != 1:
        raise AssertionError("Alloy transport must define exactly one endpoint")
    return endpoints[0]


def alloy_string_list(block: str, field: str) -> list[str]:
    """Return one Alloy list containing only quoted string values."""
    matches = re.findall(
        rf"^\s*{re.escape(field)}\s*=\s*\[(.*?)^\s*\]\s*$",
        block,
        re.MULTILINE | re.DOTALL,
    )
    if len(matches) != 1:
        raise AssertionError(f"expected exactly one Alloy {field!r} list")
    values = re.findall(r'^\s*"([^"]+)"\s*,?\s*$', matches[0], re.MULTILINE)
    if not values:
        raise AssertionError(f"Alloy {field!r} list must contain quoted values")
    return values


def alloy_rule_fields(block: str) -> dict[str, object]:
    """Parse the narrow scalar/list fields used by metric relabel rules."""
    fields: dict[str, object] = {
        key: value
        for key, value in re.findall(
            r'^\s*([a-z_]+)\s*=\s*"([^"]*)"\s*$', block, re.MULTILINE
        )
    }
    source_labels = re.findall(
        r'^\s*source_labels\s*=\s*\["([^"]+)"\]\s*$', block, re.MULTILINE
    )
    if source_labels:
        if len(source_labels) != 1:
            raise AssertionError("relabel rule must define at most one source list")
        fields["source_labels"] = [source_labels[0]]
    return fields


def bounded_container_labels(
    labels: dict[str, str], expected_project: str
) -> dict[str, str] | None:
    """Model only the reviewed bounded container-identity invariant."""
    project_label = "container_label_com_docker_compose_project"
    service_label = "container_label_com_docker_compose_service"
    if labels.get(project_label) != expected_project:
        return None

    service_name = labels.get(service_label, "")
    if not service_name:
        return None

    result = {
        key: value
        for key, value in labels.items()
        if key not in {"id", "name", "image"}
        and not key.startswith("container_label_")
    }
    result["service_name"] = service_name
    return result


class ObservabilityRepositoryContractTests(unittest.TestCase):
    def test_required_configuration_tree_is_exact(self) -> None:
        files = {
            path.relative_to(OBSERVABILITY_ROOT).as_posix()
            for path in OBSERVABILITY_ROOT.rglob("*")
            if path.is_file()
        }
        self.assertEqual(files, REQUIRED_FILES)
        self.assertFalse((OBSERVABILITY_ROOT / ".env").exists())
        self.assertFalse((OBSERVABILITY_ROOT / "secrets").exists())

    def test_central_compose_has_exact_services_and_immutable_amd64_images(self) -> None:
        compose = COMPOSE_PATH.read_text(encoding="utf-8")
        self.assertIn("name: alert2ir-observability", compose)
        self.assertEqual(set(yaml_children(compose, "services")), CENTRAL_SERVICES)

        images = re.findall(r"^    image: (\S+)$", compose, re.MULTILINE)
        self.assertEqual(len(images), len(CENTRAL_SERVICES))
        for image in images:
            self.assertRegex(image, IMAGE_REFERENCE)
            self.assertNotRegex(image.lower(), r":(?:latest|main|stable|v?\d+)(?:@|$)")

        self.assertEqual(compose.count("    platform: linux/amd64"), 5)
        self.assertNotRegex(compose, r"^  alloy:", re.MULTILINE)

    def test_compose_exact_publication_and_privilege_boundary(self) -> None:
        compose = COMPOSE_PATH.read_text(encoding="utf-8")
        services = compose_service_blocks(compose)
        expected_publications = {
            "grafana": {"192.168.56.65:3000:3000"},
            "prometheus": {"127.0.0.1:19090:9090"},
            "alertmanager": set(),
            "loki": {"127.0.0.1:13100:3100"},
            "tempo": {"127.0.0.1:14317:4317"},
        }
        self.assertEqual(
            {name: compose_service_ports(service) for name, service in services.items()},
            expected_publications,
        )
        self.assertEqual(yaml_children(compose, "networks"), ["observability_internal"])
        for service in services.values():
            self.assertRegex(
                service,
                r"(?m)^    networks:\n      - observability_internal$",
            )

        self.assertNotIn("0.0.0.0:", compose)
        self.assertNotIn("[::]:", compose)
        self.assertNotIn("internal: true", compose)
        self.assertNotIn("network_mode: host", compose)
        self.assertNotIn("privileged: true", compose)
        self.assertNotIn("/var/run/docker.sock", compose)
        self.assertIn("${OBSERVABILITY_DATA_ROOT:?", compose)

    def test_prometheus_contract_enables_bounded_storage_and_remote_write(self) -> None:
        compose = COMPOSE_PATH.read_text(encoding="utf-8")
        prometheus = read("prometheus/prometheus.yml")
        self.assertIn("--storage.tsdb.retention.time=30d", compose)
        self.assertIn("--storage.tsdb.retention.size=12GB", compose)
        self.assertIn("--web.enable-remote-write-receiver", compose)
        self.assertIn("--no-web.enable-admin-api", compose)
        self.assertIn("scrape_interval: 15s", prometheus)
        self.assertIn("evaluation_interval: 30s", prometheus)
        for target in (
            "prometheus:9090",
            "grafana:3000",
            "alertmanager:9093",
            "loki:3100",
            "tempo:3200",
        ):
            self.assertIn(target, prometheus)
        self.assertNotIn("192.168.56.63", prometheus)

    def test_loki_is_monolithic_local_tsdb_with_bounded_retention(self) -> None:
        compose = COMPOSE_PATH.read_text(encoding="utf-8")
        loki = read("loki/loki.yml")
        self.assertIn("- -target=all", compose)
        for value in (
            "auth_enabled: false",
            "store: tsdb",
            "object_store: filesystem",
            "schema: v13",
            "period: 24h",
            "retention_period: 336h",
            "retention_enabled: true",
            "delete_request_store: filesystem",
            "dir: /loki/wal",
            "active_index_directory: /loki/tsdb-index",
            "cache_location: /loki/tsdb-cache",
        ):
            self.assertIn(value, loki)
        self.assertNotRegex(loki.lower(), r"memberlist|s3:|gcs:|azure:")

    def test_tempo_is_monolithic_local_and_has_no_metrics_generator_or_broker(self) -> None:
        tempo = read("tempo/tempo.yml")
        self.assertIn("backend: local", tempo)
        self.assertIn("block_retention: 336h", tempo)
        self.assertIn("path: /var/tempo/wal", tempo)
        self.assertIn("path: /var/tempo/blocks", tempo)
        self.assertIn("endpoint: 0.0.0.0:4317", tempo)
        self.assertNotRegex(tempo.lower(), r"metrics_generator|kafka|redpanda")

    def test_alloy_configs_freeze_native_collection_and_explicit_bindings(self) -> None:
        ir_core = IR_CORE_ALLOY_PATH.read_text(encoding="utf-8")
        obs01 = OBS01_ALLOY_PATH.read_text(encoding="utf-8")
        for config in (ir_core, obs01):
            self.assertIn('prometheus.exporter.unix "host"', config)
            self.assertIn('prometheus.exporter.cadvisor "containers"', config)
            self.assertIn("unix:///var/run/docker.sock", config)
            self.assertIn("queue_size", config)
            self.assertIn("max_elapsed_time", config)
            self.assertIn("max_backoff_retries", config)

        application_receiver = sole_alloy_block(
            ir_core, 'otelcol.receiver.otlp "application"'
        )
        self.assertEqual(
            alloy_endpoint(sole_alloy_block(application_receiver, "grpc")),
            "192.168.56.63:4317",
        )
        self.assertIn('prometheus.exporter.blackbox "alert2ir_health"', ir_core)
        blackbox = sole_alloy_block(
            ir_core, 'prometheus.exporter.blackbox "alert2ir_health"'
        )
        targets = []
        for target in alloy_blocks(blackbox, "target"):
            fields = {
                key: value
                for key, value in re.findall(
                    r'^\s*([a-z_]+)\s*=\s*"([^"]+)"\s*$',
                    target,
                    re.MULTILINE,
                )
            }
            self.assertEqual(fields.get("module"), "http_2xx")
            targets.append((fields.get("name"), fields.get("address")))
        self.assertCountEqual(
            targets,
            [
                ("liveness", "http://127.0.0.1:8000/healthz"),
                ("readiness", "http://127.0.0.1:8000/readyz"),
            ],
        )
        self.assertIn('regex         = "core|splunk_adapter"', ir_core)
        self.assertIn('service_name = "alert2ir"', ir_core)
        self.assertIn("http://192.168.56.65:9999/api/v1/metrics/write", ir_core)
        self.assertIn('endpoint = "192.168.56.65:4317"', ir_core)
        self.assertIn("http://192.168.56.65:3500/loki/api/v1/push", ir_core)
        self.assertNotRegex(ir_core, r'endpoint\s*=\s*"(?:0\.0\.0\.0|\[?::\]?)')

        expected_receivers = {
            'prometheus.receive_http "edge_metrics"': {
                "http": ("192.168.56.65", 9999),
                "grpc": ("127.0.0.1", 0),
            },
            'loki.source.api "edge_logs"': {
                "http": ("192.168.56.65", 3500),
                "grpc": ("127.0.0.1", 0),
            },
        }
        for component_name, expected_listeners in expected_receivers.items():
            component = sole_alloy_block(obs01, component_name)
            self.assertEqual(
                {
                    protocol: alloy_listener(sole_alloy_block(component, protocol))
                    for protocol in expected_listeners
                },
                expected_listeners,
            )

        listener_addresses = re.findall(
            r'^\s*listen_address\s*=\s*"([^"]+)"\s*$', obs01, re.MULTILINE
        )
        self.assertCountEqual(
            listener_addresses,
            ["192.168.56.65", "127.0.0.1", "192.168.56.65", "127.0.0.1"],
        )
        self.assertTrue({"0.0.0.0", "::", "[::]"}.isdisjoint(listener_addresses))

        trace_receiver = sole_alloy_block(obs01, 'otelcol.receiver.otlp "edge_traces"')
        trace_grpc = sole_alloy_block(trace_receiver, "grpc")
        self.assertEqual(alloy_endpoint(trace_grpc), "192.168.56.65:4317")

        readme = README_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "Alloy's UI/management endpoint must be started as "
            "`127.0.0.1:12345` on both hosts.",
            readme,
        )
        self.assertIn("http://127.0.0.1:19090/api/v1/write", obs01)
        self.assertIn('endpoint = "127.0.0.1:14317"', obs01)
        self.assertIn("http://127.0.0.1:13100/loki/api/v1/push", obs01)

    def test_native_alloy_self_metrics_use_each_hosts_existing_metrics_path(
        self,
    ) -> None:
        contracts = (
            (
                IR_CORE_ALLOY_PATH.read_text(encoding="utf-8"),
                "prometheus.relabel.edge_metrics.receiver",
                'prometheus.remote_write "central_metrics"',
                "http://192.168.56.65:9999/api/v1/metrics/write",
            ),
            (
                OBS01_ALLOY_PATH.read_text(encoding="utf-8"),
                "prometheus.relabel.obs01_metrics.receiver",
                'prometheus.remote_write "prometheus"',
                "http://127.0.0.1:19090/api/v1/write",
            ),
        )

        for config, metrics_receiver, remote_write_name, remote_write_url in contracts:
            with self.subTest(remote_write=remote_write_name):
                exporter = sole_alloy_block(
                    config, 'prometheus.exporter.self "alloy"'
                )
                self.assertEqual(exporter.strip(), "")

                scrape = sole_alloy_block(config, 'prometheus.scrape "alloy"')
                self.assertRegex(
                    scrape,
                    r"(?m)^\s*targets\s*=\s*"
                    r"prometheus\.exporter\.self\.alloy\.targets$",
                )
                self.assertRegex(
                    scrape,
                    rf"(?m)^\s*forward_to\s*=\s*\[{re.escape(metrics_receiver)}\]$",
                )
                self.assertRegex(
                    scrape,
                    r'(?m)^\s*scrape_interval\s*=\s*"15s"$',
                )
                self.assertRegex(
                    scrape,
                    r'(?m)^\s*scrape_timeout\s*=\s*"10s"$',
                )
                self.assertNotRegex(
                    exporter + scrape,
                    r"\b(?:listen_address|listen_port|endpoint)\s*=",
                )

                self.assertEqual(
                    len(re.findall(r'\bprometheus\.remote_write\s+"', config)),
                    1,
                )
                remote_write = sole_alloy_block(config, remote_write_name)
                self.assertIn(f'url            = "{remote_write_url}"', remote_write)

    def test_cadvisor_metrics_preserve_bounded_compose_service_identity(self) -> None:
        application_services = set(
            compose_service_blocks(
                APPLICATION_COMPOSE_PATH.read_text(encoding="utf-8")
            )
        )
        self.assertEqual(
            application_services,
            {"core", "postgres", "splunk_adapter"},
        )
        self.assertIn(
            "alert2ir-ws09-live_postgres_data",
            LAB_PATH.read_text(encoding="utf-8"),
        )

        contracts = (
            (
                OBS01_ALLOY_PATH.read_text(encoding="utf-8"),
                "alert2ir-observability",
                CENTRAL_SERVICES,
                "prometheus.relabel.obs01_metrics.receiver",
            ),
            (
                IR_CORE_ALLOY_PATH.read_text(encoding="utf-8"),
                "alert2ir-ws09-live",
                application_services,
                "prometheus.relabel.edge_metrics.receiver",
            ),
        )
        raw_compose_labels = [
            "com.docker.compose.project",
            "com.docker.compose.service",
        ]

        for config, project, services, destination in contracts:
            with self.subTest(project=project):
                exporter = sole_alloy_block(
                    config, 'prometheus.exporter.cadvisor "containers"'
                )
                self.assertRegex(
                    exporter,
                    r"(?m)^\s*store_container_labels\s*=\s*false$",
                )
                self.assertEqual(
                    alloy_string_list(exporter, "allowlisted_container_labels"),
                    raw_compose_labels,
                )

                relabel = sole_alloy_block(
                    config, 'prometheus.relabel "container_cardinality"'
                )
                self.assertIn(f"forward_to = [{destination}]", relabel)
                rules = [
                    alloy_rule_fields(rule) for rule in alloy_blocks(relabel, "rule")
                ]
                self.assertEqual(
                    rules,
                    [
                        {
                            "source_labels": [
                                "container_label_com_docker_compose_project"
                            ],
                            "regex": project,
                            "action": "keep",
                        },
                        {
                            "source_labels": [
                                "container_label_com_docker_compose_service"
                            ],
                            "regex": "(.+)",
                            "target_label": "service_name",
                            "replacement": "$1",
                            "action": "replace",
                        },
                        {
                            "source_labels": ["service_name"],
                            "regex": ".+",
                            "action": "keep",
                        },
                        {
                            "action": "labeldrop",
                            "regex": "id|name|image|container_label_.*",
                        },
                    ],
                )
                self.assertIsNone(
                    re.fullmatch(rules[-1]["regex"], "service_name")
                )

                scrape = sole_alloy_block(
                    config, 'prometheus.scrape "containers"'
                )
                self.assertIn(
                    "forward_to      = "
                    "[prometheus.relabel.container_cardinality.receiver]",
                    scrape,
                )

                transformed = []
                for index, service in enumerate(sorted(services)):
                    result = bounded_container_labels(
                        {
                            "__name__": "container_memory_usage_bytes",
                            "container_label_com_docker_compose_project": project,
                            "container_label_com_docker_compose_service": service,
                            "container_label_com_docker_compose_config_hash": (
                                f"config-{index}"
                            ),
                            "id": f"/docker/container-{index}",
                            "name": f"{project}-{service}-1",
                            "image": f"example.invalid/{service}@sha256:{index:064x}",
                            "device": "/dev/sda",
                        },
                        project,
                    )
                    self.assertIsNotNone(result)
                    transformed.append(result)

                self.assertEqual(
                    {labels["service_name"] for labels in transformed}, services
                )
                self.assertEqual(
                    len({tuple(sorted(labels.items())) for labels in transformed}),
                    len(services),
                )
                for labels in transformed:
                    self.assertEqual(labels["device"], "/dev/sda")
                    self.assertTrue(
                        {"id", "name", "image"}.isdisjoint(labels)
                    )
                    self.assertFalse(
                        any(label.startswith("container_label_") for label in labels)
                    )

                self.assertIsNone(
                    bounded_container_labels(
                        {
                            "container_label_com_docker_compose_project": (
                                "unrelated-project"
                            ),
                            "container_label_com_docker_compose_service": "grafana",
                        },
                        project,
                    )
                )
                self.assertIsNone(
                    bounded_container_labels(
                        {
                            "container_label_com_docker_compose_project": project,
                            "container_label_com_docker_compose_service": "",
                        },
                        project,
                    )
                )

    def test_application_compose_passes_optional_local_otlp_configuration(self) -> None:
        compose = APPLICATION_COMPOSE_PATH.read_text(encoding="utf-8")
        services = compose_service_blocks(compose)
        self.assertEqual(set(services), {"core", "postgres", "splunk_adapter"})
        core = services["core"]
        postgres = services["postgres"]
        environment_lines = re.findall(
            r"^      ([A-Z0-9_]+):\s*(.*)$",
            core,
            re.MULTILINE,
        )
        environment = dict(environment_lines)

        self.assertEqual(
            environment["OTEL_EXPORTER_OTLP_ENDPOINT"],
            "${OTEL_EXPORTER_OTLP_ENDPOINT:-}",
        )
        self.assertNotIn("192.168.56.65", core)
        self.assertNotIn("192.168.56.63", core)
        self.assertIn(
            "OTEL_EXPORTER_OTLP_ENDPOINT=",
            (REPOSITORY_ROOT / ".env.example").read_text(encoding="utf-8"),
        )
        self.assertIn("/healthz", core)
        self.assertNotIn("/readyz", core)
        self.assertEqual(compose_service_ports(core), {"127.0.0.1:8000:8000"})
        self.assertEqual(compose_service_ports(postgres), set())
        self.assertRegex(
            postgres,
            r"(?m)^    volumes:\n      - postgres_data:/var/lib/postgresql$",
        )
        self.assertEqual(yaml_children(compose, "volumes"), ["postgres_data"])

        expected_logging = {
            "driver": "json-file",
            "options": {"max-size": "10m", "max-file": "3"},
        }
        for name in ("core", "postgres", "splunk_adapter"):
            with self.subTest(service=name):
                self.assertEqual(
                    compose_service_logging(services[name]),
                    expected_logging,
                )

    def test_correlation_identities_never_become_loki_labels(self) -> None:
        alloy = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (IR_CORE_ALLOY_PATH, OBS01_ALLOY_PATH)
        )
        for labels_block in alloy_blocks(alloy, "stage.labels"):
            for identifier in ("trace_id", "request_id", "processing_id"):
                self.assertNotIn(identifier, labels_block)
        self.assertNotRegex(
            alloy,
            r'target_label\s*=\s*"(?:trace_id|request_id|processing_id)"',
        )

    def test_grafana_provisions_unique_internal_data_sources_and_correlations(self) -> None:
        datasources = DATASOURCES_PATH.read_text(encoding="utf-8")
        uids = re.findall(r"^    uid: ([a-z][a-z0-9_-]*)$", datasources, re.MULTILINE)
        self.assertEqual(uids, ["prometheus", "loki", "tempo", "alertmanager"])
        self.assertEqual(len(uids), len(set(uids)))
        for url in (
            "http://prometheus:9090",
            "http://loki:3100",
            "http://tempo:3200",
            "http://alertmanager:9093",
        ):
            self.assertIn(f"url: {url}", datasources)
        self.assertIn("datasourceUid: tempo", datasources)
        self.assertIn("datasourceUid: loki", datasources)
        self.assertIn("tracesToLogsV2:", datasources)
        self.assertIn('"trace_id"', datasources)
        self.assertIn("([0-9a-f]{32})", datasources)
        self.assertIn("trace_id=", datasources)

        parser = configparser.ConfigParser()
        grafana_ini = read("grafana/grafana.ini")
        parser.read_string("[DEFAULT]\n" + grafana_ini)
        self.assertEqual(parser["auth.anonymous"]["enabled"], "false")
        self.assertEqual(parser["analytics"]["reporting_enabled"], "false")
        self.assertEqual(parser["plugins"]["preinstall_disabled"], "true")

    def test_grafana_provisions_exact_read_only_operator_dashboards(self) -> None:
        provider = DASHBOARD_PROVIDER_PATH.read_text(encoding="utf-8")
        for contract in (
            "name: Alert2IR",
            "folder: Alert2IR",
            "type: file",
            "disableDeletion: true",
            "allowUiUpdates: false",
            "path: /etc/grafana/dashboards",
            "foldersFromFilesStructure: false",
        ):
            self.assertIn(contract, provider)

        compose = COMPOSE_PATH.read_text(encoding="utf-8")
        grafana = compose_service_blocks(compose)["grafana"]
        for source, target in (
            (
                "./grafana/provisioning/dashboards",
                "/etc/grafana/provisioning/dashboards",
            ),
            ("./grafana/dashboards", "/etc/grafana/dashboards"),
        ):
            self.assertRegex(
                grafana,
                rf"(?ms)^        source: {re.escape(source)}$.*?"
                rf"^        target: {re.escape(target)}$.*?"
                r"^        read_only: true$",
            )

        expected = {
            "alert2ir-application": ("Alert2IR Application", {"prometheus", "loki"}),
            "alert2ir-edge": ("Alert2IR Edge", {"prometheus"}),
            "alert2ir-platform": (
                "Alert2IR Observability Platform",
                {"prometheus"},
            ),
        }
        paths = sorted(DASHBOARDS_ROOT.glob("*.json"))
        self.assertEqual(len(paths), 3)
        dashboards = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
        self.assertEqual({dashboard["uid"] for dashboard in dashboards}, set(expected))

        for dashboard in dashboards:
            uid = dashboard["uid"]
            with self.subTest(uid=uid):
                title, required_datasources = expected[uid]
                self.assertEqual(dashboard["title"], title)
                self.assertFalse(dashboard["editable"])
                self.assertEqual(dashboard["refresh"], "30s")
                self.assertEqual(dashboard["time"], {"from": "now-1h", "to": "now"})
                self.assertEqual(dashboard["templating"], {"list": []})
                self.assertNotIn("id", dashboard)
                self.assertEqual(dashboard["version"], 1)
                self.assertTrue(dashboard["panels"])

                datasource_uids = set()
                expressions = []
                for panel in dashboard["panels"]:
                    datasource = panel.get("datasource", {})
                    if datasource:
                        datasource_uids.add(datasource["uid"])
                    for target in panel.get("targets", []):
                        datasource_uids.add(target["datasource"]["uid"])
                        expression = target.get("expr", "")
                        self.assertTrue(expression.strip())
                        expressions.append(expression)

                self.assertEqual(datasource_uids, required_datasources)
                query_text = "\n".join(expressions)
                self.assertNotRegex(
                    query_text,
                    r"(?i)\bby\s*\([^)]*"
                    r"(?:request_id|trace_id|span_id|processing_id)",
                )
                self.assertNotRegex(
                    query_text,
                    r"\{[^}]*\b(?:request_id|trace_id|span_id|processing_id)\s*=",
                )

        application = next(
            dashboard
            for dashboard in dashboards
            if dashboard["uid"] == "alert2ir-application"
        )
        application_queries = "\n".join(
            target["expr"]
            for panel in application["panels"]
            for target in panel.get("targets", [])
        )
        for required in (
            "integrations/blackbox/readiness",
            "integrations/blackbox/liveness",
            "alert2ir_processing_total",
            "alert2ir_processing_duration_seconds_bucket",
            "alert2ir_persistence_operations_total",
            "alert2ir_persistence_duration_seconds_bucket",
            "alert2ir_backend_executions_total",
            "alert2ir_backend_duration_seconds_bucket",
            'service_name=\"alert2ir\"',
        ):
            self.assertIn(required, application_queries)
        logs_panel = next(
            panel for panel in application["panels"] if panel["type"] == "logs"
        )
        self.assertIn("| json", logs_panel["targets"][0]["expr"])
        for field in (
            "event",
            "level",
            "request_id",
            "trace_id",
            "processing_id",
            "outcome",
            "error_category",
        ):
            self.assertIn(field, logs_panel["description"])

    def test_prometheus_loads_exact_bounded_alert_rules_and_tests_stay_off_path(
        self,
    ) -> None:
        prometheus = read("prometheus/prometheus.yml")
        compose = COMPOSE_PATH.read_text(encoding="utf-8")
        service = compose_service_blocks(compose)["prometheus"]
        rules = PROMETHEUS_RULES_PATH.read_text(encoding="utf-8")
        rule_tests = PROMETHEUS_RULE_TESTS_PATH.read_text(encoding="utf-8")

        self.assertRegex(
            prometheus,
            r"(?m)^rule_files:\n  - /etc/prometheus/rules/\*\.yml$",
        )
        self.assertRegex(
            service,
            r"(?ms)^        source: \./prometheus/rules$.*?"
            r"^        target: /etc/prometheus/rules$.*?"
            r"^        read_only: true$",
        )
        self.assertNotIn("prometheus/tests", prometheus)
        self.assertNotIn("prometheus/tests", service)
        self.assertEqual(PROMETHEUS_RULE_TESTS_PATH.parent.name, "tests")
        self.assertNotEqual(
            PROMETHEUS_RULE_TESTS_PATH.parent,
            PROMETHEUS_RULES_PATH.parent,
        )
        self.assertIn("- ../rules/alert2ir.yml", rule_tests)

        expected_alerts = {
            "Alert2IRReadinessFailing",
            "Alert2IRLivenessFailing",
            "Alert2IRProcessingErrors",
            "Alert2IRPersistenceErrors",
            "IrCoreAlloyTelemetryMissing",
            "AlloyConfigLoadFailed",
            "CentralObservabilityTargetDown",
            "ObservabilityHostRootFilesystemLow",
        }
        alerts = re.findall(r"^      - alert: ([A-Za-z][A-Za-z0-9]+)$", rules, re.MULTILINE)
        self.assertEqual(set(alerts), expected_alerts)
        self.assertEqual(len(alerts), len(expected_alerts))
        for alert in expected_alerts:
            self.assertIn(f"alertname: {alert}", rule_tests)

        self.assertIn(
            'absent_over_time(alloy_build_info{host="ir-core"}[1m])',
            rules,
        )
        self.assertIn(
            'probe_success{host="ir-core",job="integrations/blackbox/readiness"}',
            rules,
        )
        self.assertIn(
            'probe_success{host="ir-core",job="integrations/blackbox/liveness"}',
            rules,
        )
        self.assertIn(
            'up{job=~"prometheus|grafana|alertmanager|loki|tempo"}',
            rules,
        )
        self.assertNotRegex(
            rules,
            r"(?i)\b(?:request_id|trace_id|span_id|processing_id|operation_reference)\b",
        )
        self.assertIn("--no-web.enable-admin-api", compose)

        alertmanager = read("alertmanager/alertmanager.yml")
        self.assertEqual(
            re.findall(r"^  - name: ([a-z][a-z0-9-]*)$", alertmanager, re.MULTILINE),
            ["lab-null"],
        )
        self.assertIn("receiver: lab-null", alertmanager)
        self.assertNotRegex(
            alertmanager,
            r"(?i)email_configs|slack_configs|pagerduty_configs|webhook_configs",
        )

    def test_external_secret_contract_contains_no_committed_secret(self) -> None:
        all_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in OBSERVABILITY_ROOT.rglob("*")
            if path.is_file()
        )
        self.assertNotRegex(all_text, r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
        self.assertNotRegex(all_text, r"(?i)authorization:\s*bearer\s+")
        self.assertNotRegex(all_text, r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@\s]+@")
        self.assertNotRegex(
            all_text,
            r"(?im)^\s*(?:password|api_key|token)\s*[:=]\s*[^<\s$#/][^\s#]*",
        )
        compose = COMPOSE_PATH.read_text(encoding="utf-8")
        self.assertIn("GF_SECURITY_ADMIN_PASSWORD__FILE", compose)
        self.assertIn("GF_SECURITY_SECRET_KEY__FILE", compose)


if __name__ == "__main__":
    unittest.main()
