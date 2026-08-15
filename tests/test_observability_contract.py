"""Repository contracts for the WS12 Stage 2 observability configuration.

These standard-library checks freeze security and topology invariants without
pretending to replace the pinned upstream component validators or Stage 3
runtime validation.
"""

from pathlib import Path
import configparser
import re
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
OBSERVABILITY_ROOT = REPOSITORY_ROOT / "observability"
COMPOSE_PATH = OBSERVABILITY_ROOT / "compose.yaml"
IR_CORE_ALLOY_PATH = OBSERVABILITY_ROOT / "alloy" / "ir-core.alloy"
OBS01_ALLOY_PATH = OBSERVABILITY_ROOT / "alloy" / "obs01.alloy"
DATASOURCES_PATH = (
    OBSERVABILITY_ROOT
    / "grafana"
    / "provisioning"
    / "datasources"
    / "datasources.yml"
)

REQUIRED_FILES = {
    ".env.example",
    "README.md",
    "alertmanager/alertmanager.yml",
    "alloy/ir-core.alloy",
    "alloy/obs01.alloy",
    "compose.yaml",
    "grafana/grafana.ini",
    "grafana/provisioning/datasources/datasources.yml",
    "loki/loki.yml",
    "prometheus/prometheus.yml",
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


class ObservabilityRepositoryContractTests(unittest.TestCase):
    def test_required_configuration_tree_is_exact_and_has_no_stage6_content(self) -> None:
        files = {
            path.relative_to(OBSERVABILITY_ROOT).as_posix()
            for path in OBSERVABILITY_ROOT.rglob("*")
            if path.is_file()
        }
        self.assertEqual(files, REQUIRED_FILES)
        self.assertFalse(list(OBSERVABILITY_ROOT.rglob("*.json")))
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

    def test_compose_exposure_and_privilege_boundary(self) -> None:
        compose = COMPOSE_PATH.read_text(encoding="utf-8")
        published = re.findall(r'^      - "([^"]+:[^"]+:[^"]+)"$', compose, re.MULTILINE)
        self.assertEqual(
            set(published),
            {
                "192.168.56.65:3000:3000",
                "127.0.0.1:19090:9090",
                "127.0.0.1:13100:3100",
                "127.0.0.1:14317:4317",
            },
        )
        self.assertNotIn("0.0.0.0:", compose)
        self.assertNotIn("network_mode: host", compose)
        self.assertNotIn("privileged: true", compose)
        self.assertNotIn("/var/run/docker.sock", compose)
        self.assertIn("internal: true", compose)
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
            self.assertNotIn("0.0.0.0", config)
            self.assertIn('prometheus.exporter.unix "host"', config)
            self.assertIn('prometheus.exporter.cadvisor "containers"', config)
            self.assertIn("unix:///var/run/docker.sock", config)
            self.assertIn("queue_size", config)
            self.assertIn("max_elapsed_time", config)
            self.assertIn("max_backoff_retries", config)

        self.assertIn('endpoint          = "192.168.56.63:4317"', ir_core)
        self.assertIn('prometheus.exporter.blackbox "alert2ir_health"', ir_core)
        self.assertIn("http://127.0.0.1:8000/healthz", ir_core)
        self.assertNotIn("/readyz", ir_core)
        self.assertIn('regex         = "core"', ir_core)
        self.assertIn('service_name = "alert2ir"', ir_core)
        self.assertIn("http://192.168.56.65:9999/api/v1/metrics/write", ir_core)
        self.assertIn('endpoint = "192.168.56.65:4317"', ir_core)
        self.assertIn("http://192.168.56.65:3500/loki/api/v1/push", ir_core)

        self.assertIn('listen_address = "192.168.56.65"', obs01)
        self.assertIn("listen_port    = 9999", obs01)
        self.assertIn("listen_port    = 3500", obs01)
        self.assertIn('endpoint          = "192.168.56.65:4317"', obs01)
        self.assertIn("http://127.0.0.1:19090/api/v1/write", obs01)
        self.assertIn('endpoint = "127.0.0.1:14317"', obs01)
        self.assertIn("http://127.0.0.1:13100/loki/api/v1/push", obs01)

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
