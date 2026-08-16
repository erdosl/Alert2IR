# Observability Operator Guide

This is the canonical operator runbook for the Alert2IR reference observability
deployment. Git-tracked configuration under [`observability/`](../observability/)
is authoritative; runtime telemetry and local service data are disposable lab
state. The deployment is a reference implementation, not a production sizing or
backend requirement.

## System overview

```text
Alert2IR container on ir-core
  |-- OpenTelemetry metrics and traces
  |-- structured JSON stdout -> bounded Docker JSON logs
  v
native ir-core Alloy
  v
native obs01 Alloy
  |-- metrics -> Prometheus
  |-- logs    -> Loki
  `-- traces  -> Tempo
                    |
                    v
                  Grafana

Prometheus -> Alertmanager -> lab-null
```

Alert2IR exports metrics and traces only to its local Alloy. Application logs
remain newline-delimited JSON on stdout; Docker captures them and local Alloy
forwards them. Alert2IR does not send directly to Prometheus, Loki, Tempo, or
`obs01`.

Observability is failure-isolated. Alert2IR processing does not depend on either
Alloy instance, Grafana, Prometheus, Alertmanager, Loki, or Tempo. Collector
outages can delay or lose telemetry but must not change application results.

## Host inventory

| Host | Address | Role |
| --- | --- | --- |
| `ir-core` | `192.168.56.63` | Alert2IR, PostgreSQL, native Alloy |
| `dev01` | `192.168.56.64` | Development and operator host |
| `obs01` | `192.168.56.65` | Central reference observability platform |

The complete authorized lab boundary remains in [`LAB_SCOPE.md`](LAB_SCOPE.md).

## Reference component versions

| Component | Reference version | Runtime model |
| --- | --- | --- |
| Grafana | 13.1.3 | `obs01` Compose |
| Prometheus | 3.13.2 | `obs01` Compose |
| Alertmanager | 0.33.1 | `obs01` Compose |
| Loki | 3.7.6 | `obs01` Compose, monolithic |
| Tempo | 3.0.3 | `obs01` Compose, monolithic |
| Grafana Alloy | 1.18.1 (`1.18.1-1` package) | Native systemd service on both hosts |

These versions describe the validated lab. The durable application contract is
vendor-neutral OpenTelemetry plus structured JSON stdout.

## First-look service checks

Run these checks through the established operator SSH path. They are read-only.

### obs01

```bash
systemctl is-active alloy
systemctl is-enabled alloy
curl -fsS http://127.0.0.1:12345/-/ready

docker ps \
  --filter label=com.docker.compose.project=alert2ir-observability \
  --format 'table {{.Names}}\t{{.Status}}'

curl -fsS http://192.168.56.65:3000/api/health
curl -fsS http://127.0.0.1:19090/-/healthy
curl -fsS http://127.0.0.1:19090/-/ready
curl -fsS http://127.0.0.1:13100/ready
```

Alertmanager and Tempo are intentionally not published for general host access;
their Compose health states are the first-line check. Use Grafana's provisioned
datasources or a bounded container-network diagnostic when deeper inspection is
required.

### ir-core

```bash
systemctl is-active alloy
systemctl is-enabled alloy
curl -fsS http://127.0.0.1:12345/-/ready

docker ps \
  --filter label=com.docker.compose.project=alert2ir-ws09-live \
  --format 'table {{.Names}}\t{{.Status}}'

curl -fsS http://127.0.0.1:8000/healthz
curl -fsS http://127.0.0.1:8000/readyz
```

## Liveness and readiness

`GET /healthz` means that the Alert2IR process is alive. It does not check
PostgreSQL, investigation backends, Alloy, or the central platform. The Docker
healthcheck intentionally uses `/healthz`.

`GET /readyz` means that PostgreSQL is reachable and the exact required
Alert2IR schema revision is present. It does not check Velociraptor, Alloy,
`obs01`, Grafana, Prometheus, Loki, or Tempo. A readiness failure should therefore
start with PostgreSQL and schema inspection, not telemetry troubleshooting.

## Daily operator workflow

1. Open **Alert2IR Observability Platform** and review active alerts and central
   service health.
2. Open **Alert2IR Edge** and check `ir-core`, Alloy, probes, and the `core` and
   `postgres` containers.
3. Open **Alert2IR Application** and review readiness, processing, persistence,
   latency, and recent structured logs.
4. For a request problem, search by `request_id`, then navigate from logs to its
   trace.
5. Use the processing, backend, and persistence evidence to identify the failing
   stage before restarting anything.

## Dashboards

All three dashboards are source-provisioned in the `Alert2IR` folder, use stable
datasource UIDs, and cannot be persistently edited through the UI.

| Dashboard | UID | Operator purpose |
| --- | --- | --- |
| Alert2IR Application | `alert2ir-application` | Liveness/readiness, processing counts and errors, latency, persistence, backend activity, and structured logs |
| Alert2IR Edge | `alert2ir-edge` | `ir-core` host capacity, Alloy self-health, probes, `core`/`postgres`, and forwarding health |
| Alert2IR Observability Platform | `alert2ir-platform` | Central targets, `obs01` capacity, central containers, `obs01` Alloy, and active alerts |

Backend panels can correctly show no data until a backend investigation occurs.
That alone is not a monitoring failure.

### First-line dashboard interpretation

- **Application readiness red:** query `/readyz`, check PostgreSQL health, and
  confirm the required schema revision. Do not start with Alloy.
- **Processing errors increasing:** inspect the bounded `error_category`, locate
  the request's structured logs, and open the correlated trace.
- **Edge Alloy unhealthy or absent:** check the Alloy unit, local readiness,
  recent bounded journal output, and gateway reachability. Check Docker and
  containerd access only if their components report permission errors.
- **Central target down:** inspect only the named central service, its health,
  and its recent logs. Do not restart the entire platform by default.
- **Low disk:** identify the affected host and retained data source before
  deleting anything. Never prune or remove volumes blindly.

## Alert catalog and response

| Alert | Meaning | First checks | Severity |
| --- | --- | --- | --- |
| `Alert2IRReadinessFailing` | PostgreSQL connectivity or required schema readiness failed | Query `/readyz`; inspect PostgreSQL and schema revision | critical |
| `Alert2IRLivenessFailing` | Alert2IR process probe failed | Query `/healthz`; inspect only the `core` container and recent logs | critical |
| `Alert2IRProcessingErrors` | One or more processing operations failed in the recent window | Review `error_category`, request logs, and trace | warning |
| `Alert2IRPersistenceErrors` | One or more save operations failed in the recent window | Check PostgreSQL health, then bounded persistence category and trace | warning |
| `IrCoreAlloyTelemetryMissing` | Central Prometheus has stopped receiving `ir-core` Alloy self-metrics | Check the `ir-core` Alloy unit, readiness, and central gateway reachability; confirm the application remains healthy | critical |
| `AlloyConfigLoadFailed` | The latest Alloy configuration load failed on a monitored host | Inspect the named host's Alloy status/journal and validate its installed config | critical |
| `CentralObservabilityTargetDown` | Prometheus cannot scrape one of the five controlled central jobs | Identify `job`; inspect only that Compose service and preserve its data | critical |
| `ObservabilityHostRootFilesystemLow` | Less than 15 percent of `/` remains available | Inspect host disk use and retained telemetry/log growth; do not prune blindly | warning |

Prometheus evaluates these rules and routes alerts to Alertmanager. The sole
receiver is `lab-null`: routing is real, but no external notification is sent.
Stage 6 validated `IrCoreAlloyTelemetryMissing` through
`inactive -> pending -> firing -> resolved` and proved delivery to `lab-null`.
The other alert transitions are covered deterministically by
`promtool test rules`. Routinely stopping services to retest alerts is neither
required nor recommended.

## Correlation identities

The identifiers are deliberately distinct.

| Identity | Purpose | Where stored or used |
| --- | --- | --- |
| `request_id` | Server-generated HTTP correlation returned as `X-Request-ID` | Structured JSON logs and HTTP response header |
| `trace_id` | OpenTelemetry trace identity | Structured logs and Tempo; drives Loki-to-Tempo navigation |
| `span_id` | Active OpenTelemetry span identity | Structured logs for precise span correlation |
| `processing_id` | Durable Alert2IR domain/persistence identity | Response/persistence and structured logs; not a metric label or span attribute |
| Backend operation reference | Opaque remote-operation identity | `backend.operation.submitted` log event; not a metric label or default span attribute |

### Request to trace to logs

1. Start from the server-returned `X-Request-ID`.
2. In the application dashboard or Explore, search the bounded Loki stream and
   parse JSON:

   ```logql
   {environment="lab",host="ir-core",service_name="alert2ir"}
     | json
     | request_id="00000000-0000-4000-8000-000000000000"
   ```

3. Read `trace_id` from the structured event.
4. Use the provisioned derived field to open Tempo.
5. Review the stable span hierarchy: `POST /v1/alerts`,
   `alert2ir.process`, optional `backend.investigate` and backend-specific span,
   then `persistence.save`.
6. Use Tempo trace-to-logs to return to the related Loki context.

The UUID above is synthetic. Do not put runtime request, trace, or processing
identifiers into Git documentation.

### Processing-ID lookup

When starting from a `processing_id`, search it as a parsed JSON field in the
same bounded Loki stream. Identify the associated `request_id` and `trace_id`,
then navigate to Tempo. `processing_id` is intentionally excluded from
Prometheus labels and span attributes to bound cardinality.

### Backend remote-operation lookup

`backend.operation.submitted` is emitted immediately after a valid remote
operation reference exists. It distinguishes "the remote action was created and
Alert2IR later failed" from "no remote action was created." Search the opaque
reference as a JSON field; it is not a metric label, span attribute, or Loki
stream label.

The event and its ordering are deterministically tested. WS12 did not perform a
new live backend-operation observability exercise because no suitable
already-online authorized target was available during Stage 5; that optional
exercise was deferred and does not weaken the validated telemetry transport.

## Error-category interpretation

Telemetry uses a bounded shared taxonomy and never derives dimensions from an
arbitrary exception message or class name.

| Category | Operator interpretation |
| --- | --- |
| `input_validation` | The request failed FastAPI/Pydantic validation |
| `routing_unsupported` | No backend supports the required capability set |
| `routing_ambiguous` | More than one backend matched without a unique route |
| `backend_target` | The backend could not resolve or accept the requested target |
| `backend_timeout` | Backend work exceeded its bounded deadline |
| `backend_execution` | Backend execution failed for another bounded reason |
| `persistence_unavailable` | PostgreSQL connection or interface was unavailable |
| `persistence_timeout` | Persistence operation exceeded its bounded timeout |
| `persistence_constraint` | PostgreSQL rejected a uniqueness/constraint operation |
| `persistence_mapping` | Persisted data could not be mapped to the domain contract |
| `persistence_internal` | Another persistence-internal failure occurred |
| `internal_error` | An unexpected application failure crossed the safe boundary |

## Telemetry safety and cardinality

Application telemetry intentionally excludes raw alert payloads, target host
values, source alert identifiers and titles, commands, credentials, DSNs,
certificates, tokens, raw backend results, and arbitrary exception text.

Correlation identifiers remain structured fields. They must not become
Prometheus labels or Loki stream labels. Metric and stream labels use only
bounded dimensions such as host, controlled service identity, decision,
outcome, capability, operation, and error category.

## Alloy recovery

### ir-core Alloy

1. Inspect `systemctl status alloy --no-pager`.
2. Inspect a bounded window, for example
   `journalctl -u alloy --since '-15 minutes' --no-pager`.
3. Validate the installed file with
   `sudo alloy validate /etc/alloy/config.alloy`.
4. Check `curl -fsS http://127.0.0.1:12345/-/ready`.
5. Verify reachability from `ir-core` to the central gateways on
   `192.168.56.65:4317`, `:9999`, and `:3500`.
6. Restart Alloy only when configuration or runtime evidence supports it; do not
   restart Alert2IR merely because telemetry is unavailable.
7. Confirm `alloy_build_info{host="ir-core"}` returns centrally and that probes,
   metrics, logs, and traces resume.

### obs01 Alloy

Use the same bounded systemd, journal, validation, and local readiness checks.
Then verify its loopback backend paths: Prometheus on `127.0.0.1:19090`, Loki
on `127.0.0.1:13100`, and Tempo OTLP on `127.0.0.1:14317`. Confirm
`alloy_build_info{host="obs01"}` centrally after recovery. Application
availability must not depend on this work.

## Central service recovery

1. Identify the failing service with `docker ps` or the current release's
   `docker compose ps`.
2. Inspect only a bounded relevant log window.
3. Check that service's existing health endpoint or Docker health state.
4. Validate the exact Git-tracked configuration before recreation.
5. Recreate only the affected service when evidence requires it, preserving its
   data directory and the existing Compose project.

Never use `docker compose down -v`, `docker system prune`, `docker volume prune`,
or manual Docker-log truncation as routine recovery. Do not broaden socket or
firewall permissions merely to silence a warning.

## Deployment and provenance

The central immutable-release convention is:

```text
/opt/alert2ir-observability/releases/<git-sha>/observability
/opt/alert2ir-observability/current
```

Deploy an exact hosted-green Git SHA, verify the archive and deterministic
manifest, switch the `current` symlink atomically, recreate only services whose
mounts or configuration changed, and retain prior releases for bounded rollback.
Never deploy from an uncommitted working tree.

Alert2IR application releases follow the same provenance principle: use an exact
hosted-green Git revision and the existing `ir-core` deployment convention,
preserve the Compose project and PostgreSQL volume, and do not replace runtime
secrets.

## Docker log retention

Both `core` and `postgres` use:

```yaml
logging:
  driver: json-file
  options:
    max-size: "10m"
    max-file: "3"
```

Docker JSON format is required by the accepted Alloy log path; rotation bounds
host disk growth. Do not manually modify or truncate Docker-managed log files.

## Runtime privilege and firewall model

Native Alloy runs as the non-root `alloy` account.

- Docker access uses membership in `docker`. **Docker-group membership is
  effectively root-equivalent.** Never make `/var/run/docker.sock`
  world-accessible.
- containerd access uses the dedicated `alloy-containerd` group. The main socket
  remains root-owned with group access and mode `0660`. **containerd API access
  is security-sensitive and is not inherently read-only.** Only Alloy is
  assigned to this dedicated group; no world-writable socket or transient ACL is
  used.

The high-level UFW contract is:

- `obs01`: default-deny incoming; administrative SSH and Grafana operator access
  from `dev01`; OTLP, remote-write, and Loki gateways only from `ir-core`.
- `ir-core`: default-deny incoming; SSH from `dev01`; the actual application
  Docker subnet may reach local Alloy OTLP and the Velociraptor API; the existing
  authorized `win11-02` Velociraptor frontend path remains allowed.

Rule numbers are not part of the contract. Do not broaden either host to the
whole host-only subnet without separate review. No Docker or containerd socket
is exposed over TCP.

## Known non-blocking warnings

| Observation | Impact | Operator action |
| --- | --- | --- |
| cAdvisor filesystem-stat permission warnings for some root-owned Docker storage paths | Some filesystem-stat data can be unavailable; required CPU, memory, network, and bounded container identities still work | Do not broaden host-path or socket permissions merely to suppress the warning |
| Grafana's generic Alertmanager datasource health operation can report `plugin.unavailable` | The generic plugin-health call is not authoritative; the datasource proxy and real Prometheus-to-Alertmanager routing work | Check Alertmanager container health/status and the datasource proxy before declaring failure |
| Backend dashboard panels can show no data | No backend execution occurred in the selected window | Confirm expected request behavior; do not manufacture backend work |

Previously corrected listener, host-publication, cAdvisor identity, containerd
access, Alloy self-metric, and Docker-log-retention defects are not current
warnings.

## Reference resource observations

These are reference lab observations from WS12 validation, not sizing guarantees.

### obs01

| Resource | Reference observation |
| --- | --- |
| Load average | Approximately `0.02 / 0.07 / 0.08` |
| Memory | Approximately 6.6 GiB available of 7.8 GiB |
| Swap | 0 used of 4.0 GiB |
| Root filesystem | Approximately 11 GiB used, 82 GiB available, 97 GiB total |
| Grafana | Approximately 155 MiB |
| Prometheus | Approximately 75 MiB |
| Alertmanager | Approximately 14 MiB |
| Loki | Approximately 69 MiB |
| Tempo | Approximately 33 MiB |
| Alloy | Approximately 357 MiB RSS |

`obs01` has one vCPU. The observed WS12 workload is acceptable and retained
substantial idle CPU. Increase CPU only when sustained operational evidence
supports it; this is not a production-sizing conclusion.

### ir-core

| Resource | Reference observation |
| --- | --- |
| Load average | Approximately `0.03 / 0.05 / 0.06` |
| Memory | Approximately 3.0 GiB available of 3.8 GiB |
| Swap | Negligible use of 3.8 GiB |
| Root filesystem | Approximately 9.7 GiB used, 83 GiB available, 97 GiB total |
| Alert2IR core | Approximately 54 MiB |
| PostgreSQL | Approximately 26 MiB |
| Alloy | Approximately 327 MiB RSS |

## Reference retention

| Store | Retention |
| --- | --- |
| Prometheus | 30 days, bounded additionally by a 12 GB size cap |
| Loki | 14 days (`336h`) |
| Tempo | 14 days (`336h`) |

These are reference lab settings, not a universal production policy.

## Validated failure isolation

WS12 stopped local `ir-core` Alloy without disabling it and sent a controlled
no-action request. The request returned HTTP 200 with `X-Request-ID`, `/healthz`
and `/readyz` remained 200, `core` did not restart, and PostgreSQL remained
healthy. Telemetry warnings and loss during collector outage are acceptable;
changing the application/domain result is not. After Alloy recovery, metrics,
logs, traces, probes, correlation, and alert resolution resumed.
