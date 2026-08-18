# Observability reference configuration

## Purpose and ownership

This directory is the Git-tracked deployment and configuration contract for the
open-source reference platform. It owns exact versions and image identities,
ports and listeners, retention and data paths, secrets, runtime privileges,
Compose structure, immutable deployment, and static configuration validation.
Runtime metrics, logs, traces, queues, and local databases are disposable lab
state; configuration in Git is canonical.

The reference stack is optional. Alert2IR processing continues when either
Alloy instance, `obs01`, or a central service is unavailable. The durable
application contract is vendor-neutral OpenTelemetry metrics/traces plus
structured newline-delimited JSON stdout.

Operator first-look checks, dashboards, alert interpretation, correlation,
recovery, and operational warnings are documented in the
[`docs/OBSERVABILITY.md`](../docs/OBSERVABILITY.md) runbook. Do not duplicate
those procedures here.

## Architecture

```text
Alert2IR container on ir-core
  -> ir-core native Alloy OTLP receiver (192.168.56.63:4317)
  -> obs01 native Alloy gateways
       traces:  192.168.56.65:4317 -> 127.0.0.1:14317 -> Tempo
       metrics: 192.168.56.65:9999 -> 127.0.0.1:19090 -> Prometheus
       logs:    192.168.56.65:3500 -> 127.0.0.1:13100 -> Loki
  -> Grafana

Prometheus -> Alertmanager -> lab-null
```

The central Compose project is explicitly named `alert2ir-observability` and
contains Grafana, Prometheus, Alertmanager, Loki, and Tempo. Alloy 1.18.1 runs
natively on `obs01` and `ir-core`, outside Compose.

The application Compose project contains `core`, `splunk_adapter`, and
`postgres`. It publishes the canonical application only on `127.0.0.1:8000`,
publishes the adapter on the exact host-only address `192.168.56.63:8091`, and
passes the optional local OTLP endpoint only to `core`. All three services retain
Docker `json-file` logging bounded by `10m` and three files. Native `ir-core`
Alloy discovers those controlled service identities for container metrics and
reads only `core` and `splunk_adapter` stdout through the Docker API.

## Configuration inventory

| Path | Purpose |
| --- | --- |
| `compose.yaml` | Five central services, persistence, secrets, mounts, and exposure |
| `alloy/obs01.alloy` | Central gateways, host/container/self metrics, and forwarding |
| `alloy/ir-core.alloy` | Edge OTLP, Docker logs, host/container/self metrics, and probes |
| `prometheus/prometheus.yml` | Scrapes, Alertmanager target, and production rule loading |
| `prometheus/rules/alert2ir.yml` | Eight production alerts |
| `prometheus/tests/alert2ir_rules_test.yml` | Deterministic alert firing/clearing tests |
| `alertmanager/alertmanager.yml` | Internal `lab-null` routing |
| `loki/loki.yml` | Monolithic filesystem-backed log store |
| `tempo/tempo.yml` | Monolithic filesystem-backed trace store |
| `grafana/grafana.ini` | Hardened reference Grafana settings |
| `grafana/provisioning/` | Stable datasource and dashboard providers |
| `grafana/dashboards/` | Three source-provisioned operator dashboards |

Production rule loading is limited to `prometheus/rules/*.yml`; the deterministic
fixtures under `prometheus/tests/` are never loaded by the running Prometheus.

## Versions and immutable image identities

The validated reference versions are exact non-prerelease Linux/amd64 images or
packages. They are reference-lab identities, not universal production
requirements.

| Component | Version | Linux/amd64 manifest |
| --- | --- | --- |
| Grafana | 13.1.3 | `sha256:e27e68cfd5795c1bea54950766078a02e84dfa3bafe0a4d0e5382f713dfd8e4e` |
| Prometheus | 3.13.2 | `sha256:1147c92841726a6fef55fe6124491d6f85480f8de204f7d420304ca5bbd0a8f7` |
| Alertmanager | 0.33.1 | `sha256:a89f8d4520954079275441eecdb71444328bd90633dd4eddfc33b9ed657f349b` |
| Loki | 3.7.6 | `sha256:83c76da7858a8f4f88117ac521864ac33896fdae7a352a1df4068556e7513f64` |
| Tempo | 3.0.3 | `sha256:05321ebf1f191fde34282b3dc86e68f511d489133df7963cd1670a2e1e11b33c` |
| Alloy | 1.18.1 | native package `1.18.1-1`; validator image `sha256:754409730f1a4ed9781f8a2ea3b6a8c55750ee125a267ecf8fb449f9a25c109a` |

The accepted Alloy Debian package SHA-256 is
`7d7b8211ac97f5cda63f908325f64d52aa4bbaeb496897d8234f75bad87d9cb2`.

## Ports and exposure

| Endpoint | Host bind | Consumer |
| --- | --- | --- |
| Grafana | `192.168.56.65:3000` | Operators from `dev01` |
| obs01 Alloy OTLP/gRPC | `192.168.56.65:4317` | `ir-core` Alloy |
| obs01 Alloy remote write | `192.168.56.65:9999` | `ir-core` Alloy |
| obs01 Alloy Loki API | `192.168.56.65:3500` | `ir-core` Alloy |
| Prometheus | `127.0.0.1:19090 -> 9090` | Native obs01 Alloy and host validation |
| Loki | `127.0.0.1:13100 -> 3100` | Native obs01 Alloy and host validation |
| Tempo OTLP/gRPC | `127.0.0.1:14317 -> 4317` | Native obs01 Alloy |
| Alertmanager | Compose network only | Prometheus and Grafana |
| Tempo query API | Compose network only | Grafana and Prometheus |

No published port uses a wildcard or NAT-interface bind. Alloy's UI/management endpoint must be started as `127.0.0.1:12345` on both hosts. Stable host relationships are described in [`docs/LAB.md`](../docs/LAB.md); authorization remains governed by [`docs/LAB_SCOPE.md`](../docs/LAB_SCOPE.md).

## Storage and retention

Central service data is below `/srv/alert2ir-observability` on `obs01`. Native
obs01 Alloy uses `/srv/alert2ir-observability/alloy`; `ir-core` Alloy uses
`/var/lib/alloy/alert2ir`. These state paths retain Docker positions and
remote-write WAL data across restarts, but queues remain bounded rather than
lossless.

- Prometheus: 30 days and a 12 GB size cap; either boundary may cause deletion.
- Loki: 14 days (`336h`).
- Tempo: 14 days (`336h`).
- Docker stdout on `core`, `splunk_adapter`, and `postgres`: `json-file`, `10m`, three files; Alloy log ingestion keeps `core` and `splunk_adapter`.

## Secrets and runtime privilege

`.env.example` documents variable names only. Grafana's admin password and
security key are external files mounted as Compose secrets and read through
supported `__FILE` variables. No real value belongs in Git.

Both native Alloy configurations require Docker metadata/log access. Membership
in the Docker group is effectively root-equivalent. `ir-core` uses the dedicated
`alloy-containerd` group for its root-owned `0660` containerd socket; API access
is security-sensitive and is not inherently read-only. Alloy runs as a non-root
service account, and no runtime socket is world-accessible.

## Immutable deployment model

Central releases are staged as exact Git trees below:

```text
/opt/alert2ir-observability/releases/<git-sha>/observability
/opt/alert2ir-observability/current
```

Verify archive and manifest identity, switch `current` atomically, preserve prior
releases and data directories, and recreate only services whose configuration or
mounts changed. Never use `down -v` or prune retained data as a deployment step.

## Static validation

Run from the repository root. Validator containers have no network and start no
observability service.

Render central Compose with bounded synthetic secret files:

```bash
validation_dir=$(mktemp -d)
trap 'find "$validation_dir" -depth -delete' EXIT
touch "$validation_dir/grafana_admin_password" "$validation_dir/grafana_secret_key"

OBSERVABILITY_DATA_ROOT=/srv/alert2ir-observability \
GRAFANA_ADMIN_PASSWORD_FILE="$validation_dir/grafana_admin_password" \
GRAFANA_SECRET_KEY_FILE="$validation_dir/grafana_secret_key" \
docker compose --env-file /dev/null \
  -f observability/compose.yaml config --quiet
```

Validate Prometheus configuration, rules, and deterministic tests:

```bash
prometheus_image=quay.io/prometheus/prometheus:v3.13.2@sha256:1147c92841726a6fef55fe6124491d6f85480f8de204f7d420304ca5bbd0a8f7

docker run --rm --network none \
  -v "$PWD/observability/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro" \
  -v "$PWD/observability/prometheus/rules:/etc/prometheus/rules:ro" \
  --entrypoint /bin/promtool "$prometheus_image" \
  check config /etc/prometheus/prometheus.yml

docker run --rm --network none \
  -v "$PWD/observability/prometheus/rules:/rules:ro" \
  --entrypoint /bin/promtool "$prometheus_image" \
  check rules /rules/alert2ir.yml

docker run --rm --network none \
  -v "$PWD/observability/prometheus:/prometheus:ro" \
  --entrypoint /bin/promtool "$prometheus_image" \
  test rules /prometheus/tests/alert2ir_rules_test.yml
```

Validate the remaining pinned services:

```bash
docker run --rm --network none \
  -v "$PWD/observability/alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml:ro" \
  --entrypoint /bin/amtool \
  quay.io/prometheus/alertmanager:v0.33.1@sha256:a89f8d4520954079275441eecdb71444328bd90633dd4eddfc33b9ed657f349b \
  check-config /etc/alertmanager/alertmanager.yml

docker run --rm --network none \
  -v "$PWD/observability/loki/loki.yml:/etc/loki/loki.yml:ro" \
  docker.io/grafana/loki:3.7.6@sha256:83c76da7858a8f4f88117ac521864ac33896fdae7a352a1df4068556e7513f64 \
  -config.file=/etc/loki/loki.yml -verify-config

for alloy_config in ir-core obs01; do
  docker run --rm --network none \
    -v "$PWD/observability/alloy/${alloy_config}.alloy:/etc/alloy/config.alloy:ro" \
    docker.io/grafana/alloy:v1.18.1@sha256:754409730f1a4ed9781f8a2ea3b6a8c55750ee125a267ecf8fb449f9a25c109a \
    validate /etc/alloy/config.alloy
done

docker run --rm --network none \
  -v "$PWD/observability/tempo/tempo.yml:/etc/tempo/tempo.yml:ro" \
  --entrypoint /tempo \
  docker.io/grafana/tempo:3.0.3@sha256:05321ebf1f191fde34282b3dc86e68f511d489133df7963cd1670a2e1e11b33c \
  -config.file=/etc/tempo/tempo.yml -config.verify=true
```

Grafana 13.1.3 has no standalone provisioning validator. Repository contracts
parse its INI, YAML, and dashboard JSON and enforce stable UIDs, datasource
references, read-only mounts, and bounded queries.

Run repository validation:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  .venv/bin/python -m unittest -v tests.test_observability_contract

env -u ALERT2IR_TEST_DATABASE_URL PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  .venv/bin/python -m unittest discover -v

.venv/bin/python -m pip check
```
