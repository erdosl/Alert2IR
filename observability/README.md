# WS12 reference observability deployment

## Status and purpose

**Configuration only. Not yet provisioned.** This directory is the Git-tracked deployment contract for the open-source WS12 reference lab platform. Git configuration is canonical; runtime metrics, logs, traces, queues, and local databases are disposable lab state. The platform is optional: Alert2IR processing must continue when Alloy, `obs01`, or any central service is unavailable, and bounded queues may drop telemetry during an outage.

The application contract remains portable OpenTelemetry metrics/traces plus structured newline-delimited JSON logs. The components here are a reference implementation, not a required production backend.

## Architecture

`obs01` will run Grafana, Prometheus, Alertmanager, monolithic Loki, and monolithic Tempo in the explicitly named `alert2ir-observability` Compose project. Grafana Alloy 1.18.1 will run natively on `obs01` and `ir-core`; Alloy is deliberately absent from Compose.

```text
Alert2IR container on ir-core
  -> ir-core native Alloy OTLP receiver (192.168.56.63:4317)
  -> obs01 native Alloy gateways
       traces:  192.168.56.65:4317 -> 127.0.0.1:14317 -> Tempo
       metrics: 192.168.56.65:9999 -> 127.0.0.1:19090 -> Prometheus
       logs:    192.168.56.65:3500 -> 127.0.0.1:13100 -> Loki
```

The repository application Compose defines services `core` and `postgres`, publishes `core` only at `127.0.0.1:8000`, leaves PostgreSQL internal, uses the implicit default Compose network, and does not override Docker's logging driver. The edge log pipeline therefore discovers the real `core` service through Docker Compose labels and reads stdout through the Docker API.

An Alert2IR container cannot reach host Alloy through its own `127.0.0.1`. Stage 5 must configure the future OTel exporter to use `192.168.56.63:4317`, confirm the container can route to that host-only address, and add only the required local/container firewall allowance. If the runtime later uses a host-gateway alias instead, both the application Compose integration and this documented endpoint must be reviewed together. Stage 2 changes neither networking nor firewall state.

## Versions and immutable image identities

The selected versions were stable, non-prerelease upstream releases on 2026-08-15. Each Compose reference uses the exact version and the Linux/amd64 manifest digest rather than the multi-platform index digest.

| Component | Version | Multi-platform index | Linux/amd64 manifest |
| --- | --- | --- | --- |
| Grafana | 13.1.3 | `sha256:ab5cb380e3ff3172d6c8bd2e7cfd31cce977d2881b260e1f5bc089bf0b759b43` | `sha256:e27e68cfd5795c1bea54950766078a02e84dfa3bafe0a4d0e5382f713dfd8e4e` |
| Prometheus | 3.13.2 | `sha256:508729e0e2d18e11fd742a5a5ca70e557b940a93948c3c95fd0123a6fd538b69` | `sha256:1147c92841726a6fef55fe6124491d6f85480f8de204f7d420304ca5bbd0a8f7` |
| Alertmanager | 0.33.1 | `sha256:9e082985f56f4c8c9f724e18f2288c6708f472e56a5286b8863d080434ea065d` | `sha256:a89f8d4520954079275441eecdb71444328bd90633dd4eddfc33b9ed657f349b` |
| Loki | 3.7.6 | `sha256:efd47c67f9bac88ca29bcf8cb997d9ab29d1848bd0aff579282295542a745952` | `sha256:83c76da7858a8f4f88117ac521864ac33896fdae7a352a1df4068556e7513f64` |
| Tempo | 3.0.3 | `sha256:0296560ac66f8a3600d7fb3014a52c189d4d9c3549ad6ff441bf2409855d68d5` | `sha256:05321ebf1f191fde34282b3dc86e68f511d489133df7963cd1670a2e1e11b33c` |

Release verification sources are the official Grafana and Prometheus GitHub releases. Registry identities were resolved with `docker buildx imagetools inspect` against the exact tags. Loki 3.7.6 supersedes the earlier 3.7.4 discovery candidate because 3.7.6 was the current stable release at Stage 2 review.

Native Alloy is pinned to official Grafana Alloy `1.18.1`. Stage 3 should use the official Grafana APT repository with its signed repository metadata and request the exact `1.18.1-1` package, then verify the installed version. The independently published official release checksum for `alloy-1.18.1-1.amd64.deb` is `sha256:7d7b8211ac97f5cda63f908325f64d52aa4bbaeb496897d8234f75bad87d9cb2`; Stage 3 should retain and verify the package identity before installation rather than accepting a later version.

## Ports and exposure

| Endpoint | Host bind | Consumer | Purpose |
| --- | --- | --- | --- |
| Grafana | `192.168.56.65:3000` | Lab operators | Only host-only operator UI |
| obs01 Alloy OTLP/gRPC | `192.168.56.65:4317` | ir-core Alloy | Trace gateway |
| obs01 Alloy remote write | `192.168.56.65:9999` | ir-core Alloy | Metrics gateway at `/api/v1/metrics/write` |
| obs01 Alloy Loki API | `192.168.56.65:3500` | ir-core Alloy | Log gateway at `/loki/api/v1/push` |
| Prometheus | `127.0.0.1:19090 -> 9090` | obs01 Alloy | Remote-write receiver and host-side validation |
| Loki | `127.0.0.1:13100 -> 3100` | obs01 Alloy | Log ingestion and host-side validation |
| Tempo OTLP/gRPC | `127.0.0.1:14317 -> 4317` | obs01 Alloy | Trace ingestion |
| Alertmanager | Compose network only | Prometheus and Grafana | Alert state, routing, and silences |
| Tempo query API | Compose network only | Grafana and Prometheus | Trace queries and metrics scrape |

No published port uses a wildcard address or the NAT interface. Prometheus, Loki, and Tempo loopback mappings exist only for native central Alloy; Grafana queries every backend through Compose DNS. Alloy's UI/management endpoint must be started as `127.0.0.1:12345` on both hosts.

## Storage and retention

Stage 3 will use `/srv/alert2ir-observability` on `obs01`, with one bind-mounted directory for each central service and `/srv/alert2ir-observability/alloy` as native Alloy's `--storage.path`. `ir-core` Alloy will use the separately created `/var/lib/alloy/alert2ir` state path. These Alloy paths retain component state, Docker log positions, and Prometheus remote-write WAL data across restarts; trace and log queues remain deliberately bounded rather than lossless.

- Prometheus: 30-day time retention and 12 GB size retention; deletion occurs when either boundary requires it.
- Loki: 14 days (`336h`) with filesystem TSDB schema v13, 24-hour index periods, WAL, compactor state, and deletion markers below `/loki`.
- Tempo: 14 days (`336h`) with local WAL/live data and trace blocks below `/var/tempo`; the metrics-generator is intentionally disabled.
- Docker stdout: Stage 3 must configure bounded daemon log rotation before deployment; this repository does not change Docker settings.

The 100 GB virtual disk currently exposes only about 49 GB through `/`. Stage 3 must inspect LVM with privilege and make an approved amount of storage available before applying this budget; Stage 2 assumes neither free extents nor an expansion method.

## Secrets and host permissions

Copy `.env.example` to an ignored private `.env` only during Stage 3, or provide the variables directly. The required external files are:

- `GRAFANA_ADMIN_PASSWORD_FILE`: a private file containing the initial Grafana admin password;
- `GRAFANA_SECRET_KEY_FILE`: a stable private Grafana security key.

Compose mounts both as runtime secrets and Grafana reads them through supported `__FILE` environment variables. No real value belongs in Git. Grafana anonymous access, external reporting, update checks, news, snapshots, and startup plugin installation are disabled.

Both native Alloy configurations use `/var/run/docker.sock` for discovery, stdout collection, and cAdvisor integration. Docker socket access is security-sensitive and effectively root-equivalent. Stage 3/5 must choose and validate the narrowest workable service-account permissions; never make the socket world-writable. Committing this configuration does not authorize or apply a permission change.

## Static validation

Run from the repository root. The commands never start an observability server and use no network inside validator containers.

```bash
validation_dir=$(mktemp -d)
touch "$validation_dir/grafana_admin_password" "$validation_dir/grafana_secret_key"
OBSERVABILITY_DATA_ROOT=/srv/alert2ir-observability \
GRAFANA_ADMIN_PASSWORD_FILE="$validation_dir/grafana_admin_password" \
GRAFANA_SECRET_KEY_FILE="$validation_dir/grafana_secret_key" \
docker compose --env-file /dev/null -f observability/compose.yaml config --quiet
rm -r "$validation_dir"
```

```bash
docker run --rm --network none \
  -v "$PWD/observability/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro" \
  --entrypoint /bin/promtool \
  quay.io/prometheus/prometheus:v3.13.2@sha256:1147c92841726a6fef55fe6124491d6f85480f8de204f7d420304ca5bbd0a8f7 \
  check config /etc/prometheus/prometheus.yml

docker run --rm --network none \
  -v "$PWD/observability/alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro" \
  --entrypoint /bin/amtool \
  quay.io/prometheus/alertmanager:v0.33.1@sha256:a89f8d4520954079275441eecdb71444328bd90633dd4eddfc33b9ed657f349b \
  check-config /etc/alertmanager/alertmanager.yml

docker run --rm --network none \
  -v "$PWD/observability/loki/loki.yml:/etc/loki/loki.yml:ro" \
  docker.io/grafana/loki:3.7.6@sha256:83c76da7858a8f4f88117ac521864ac33896fdae7a352a1df4068556e7513f64 \
  -config.file=/etc/loki/loki.yml -verify-config

docker run --rm --network none \
  -v "$PWD/observability/alloy/ir-core.alloy:/etc/alloy/config.alloy:ro" \
  docker.io/grafana/alloy:v1.18.1@sha256:754409730f1a4ed9781f8a2ea3b6a8c55750ee125a267ecf8fb449f9a25c109a \
  validate /etc/alloy/config.alloy

docker run --rm --network none \
  -v "$PWD/observability/alloy/obs01.alloy:/etc/alloy/config.alloy:ro" \
  docker.io/grafana/alloy:v1.18.1@sha256:754409730f1a4ed9781f8a2ea3b6a8c55750ee125a267ecf8fb449f9a25c109a \
  validate /etc/alloy/config.alloy

docker run --rm --network none \
  -v "$PWD/observability/tempo/tempo.yml:/etc/tempo/tempo.yml:ro" \
  --entrypoint /tempo \
  docker.io/grafana/tempo:3.0.3@sha256:05321ebf1f191fde34282b3dc86e68f511d489133df7963cd1670a2e1e11b33c \
  -config.file=/etc/tempo/tempo.yml -config.verify=true
```

Parse every tracked YAML artifact without constructing application objects:

```bash
.venv/bin/python -c \
  'import pathlib, sys, yaml; [yaml.compose(pathlib.Path(name).read_text(encoding="utf-8")) for name in sys.argv[1:]]' \
  observability/compose.yaml \
  observability/prometheus/prometheus.yml \
  observability/alertmanager/alertmanager.yml \
  observability/loki/loki.yml \
  observability/tempo/tempo.yml \
  observability/grafana/provisioning/datasources/datasources.yml
```

Grafana 13.1.3 has no standalone provisioning validator. Stage 2 therefore parses its INI/YAML and contract-tests UIDs, internal URLs, and correlation references; Stage 3 must record provisioning startup and data-source health.

Run the standard-library repository contracts and ordinary regression suite:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python -m unittest -v tests.test_observability_contract
env -u ALERT2IR_TEST_DATABASE_URL PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python -m unittest discover -v
.venv/bin/python -m pip check
```

## Stage 3 boundary

Stage 3 may inspect LVM with privileged read-only commands, make separately approved disk capacity available, install and pin Docker/Compose and Alloy, create the documented storage and secret paths, configure the reviewed firewall exposure, and apply this exact Git revision. It must validate component health and effective port exposure. This README is not a provisioning script and Stage 2 performs none of those operations.

Application instrumentation, `/readyz`, real dashboards, Alert2IR-specific alert rules, and application/runtime Compose integration remain later WS12 work.
