# Observability operator guide

## Purpose and ownership

This is the operator runbook for the Alert2IR reference observability deployment. It owns first-look workflow, dashboard and alert interpretation, request/log/trace correlation, recovery, failure-isolation expectations, and operational privilege warnings.

Exact component pins, listeners, data paths, image-coupled directory ownership, retention, Compose structure, immutable deployment convention, and configuration validation belong in the [`observability/` configuration reference](../observability/README.md). Git-tracked configuration is authoritative; runtime telemetry and local service data are disposable lab state, although routine service recreation preserves the retained host bind directories.

## System overview

```text
Alert2IR application on ir-core
  |-- OpenTelemetry metrics and traces
  `-- structured JSON stdout -> bounded Docker JSON logs
                    |
                    v
            native ir-core Alloy
                    |
                    v
             native obs01 Alloy
              |      |      |
          Prometheus Loki  Tempo
              \      |      /
                   Grafana

Prometheus -> Alertmanager -> lab-null
```

Alert2IR sends metrics and traces only to local Alloy. Docker captures structured stdout and local Alloy forwards it. The application does not send directly to the central services.

Observability is failure-isolated. An Alloy or central-platform outage may delay or lose telemetry but must not change application processing, `/healthz`, or `/readyz`. Host roles and authorization remain in [LAB.md](LAB.md) and [LAB_SCOPE.md](LAB_SCOPE.md).

## First-look checks

Use the established operator SSH path. These checks are read-only.

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

Alertmanager and Tempo are not published for general host access. Start with their Compose health state, then use provisioned Grafana datasources or a bounded container-network diagnostic if necessary.

### ir-core

```bash
systemctl is-active alloy
systemctl is-enabled alloy
curl -fsS http://127.0.0.1:12345/-/ready

docker ps \
  --filter label=com.docker.compose.project=alert2ir \
  --format 'table {{.Names}}\t{{.Status}}'

curl -fsS http://127.0.0.1:8000/healthz
curl -fsS http://127.0.0.1:8000/readyz
```

`/healthz` proves Alert2IR application process liveness only and remains the Docker healthcheck. `/readyz` proves PostgreSQL connectivity and the required schema revision. Neither checks an investigation backend or observability. A readiness failure starts with PostgreSQL/schema inspection, not telemetry troubleshooting.

## Daily operator workflow

1. Open **Alert2IR Observability Platform** and review active alerts and central service health.
2. Open **Alert2IR Edge** and check `ir-core`, local Alloy, probes, and the `core`, `splunk_adapter`, and `postgres` containers.
3. Open **Alert2IR Application** and review readiness, processing, persistence, latency, and recent structured logs.
4. For a request problem, search by `request_id`, then navigate from logs to its trace.
5. Use processing, investigation-backend, and persistence evidence to identify the failed stage before restarting anything.

## Dashboards

The three source-provisioned dashboards are read-only operator views in the `Alert2IR` folder:

| Dashboard | Operator purpose |
| --- | --- |
| Alert2IR Application | Liveness/readiness, processing outcomes, latency, persistence, backend activity, and structured logs |
| Alert2IR Edge | `ir-core` capacity, Alloy self-health, probes, application containers, and forwarding health |
| Alert2IR Observability Platform | Central targets, `obs01` capacity, central services, Alloy, and active alerts |

First interpretations:

- **Application readiness red:** query `/readyz`, then inspect PostgreSQL health and schema revision.
- **Processing errors increasing:** inspect the bounded `error_category`, request logs, and correlated trace.
- **Edge Alloy absent:** inspect the unit, local readiness, bounded journal output, and gateway reachability. Check container API permissions only when their components report permission errors.
- **Central target down:** inspect the named service, its health, and recent bounded logs. Do not restart the whole platform by default.
- **Low disk:** identify the host and retained data source before deletion. Never prune or remove volumes blindly.
- **Backend panels empty:** confirm whether an investigation occurred in the selected window; no data alone is not a monitoring failure.

## Alert catalog and response

| Alert | Meaning | First checks | Severity |
| --- | --- | --- | --- |
| `Alert2IRReadinessFailing` | PostgreSQL connectivity or required schema readiness failed | Query `/readyz`; inspect PostgreSQL and schema revision | critical |
| `Alert2IRLivenessFailing` | Alert2IR process probe failed | Query `/healthz`; inspect only `core` and recent logs | critical |
| `Alert2IRProcessingErrors` | Processing failed in the recent window | Review `error_category`, request logs, and trace | warning |
| `Alert2IRPersistenceErrors` | One or more save operations failed | Check PostgreSQL, bounded persistence category, and trace | warning |
| `IrCoreAlloyTelemetryMissing` | Central Prometheus stopped receiving `ir-core` Alloy self-metrics | Check local Alloy, readiness, and gateway reachability; confirm application health | critical |
| `AlloyConfigLoadFailed` | Latest Alloy configuration load failed | Inspect the named Alloy unit/journal and validate its installed config | critical |
| `CentralObservabilityTargetDown` | Prometheus cannot scrape a controlled central job | Identify `job`; inspect only that service and preserve its data | critical |
| `ObservabilityHostRootFilesystemLow` | Less than 15 percent of `/` remains available | Inspect host disk use and retained telemetry/log growth | warning |

Prometheus routes alerts through Alertmanager to the internal `lab-null` receiver. Routing is real, but no external notification is sent. Alert firing and clearing are covered by deterministic rule tests; operators do not need to stop services to retest them.

## Correlation identities

| Identity | Purpose | Where used |
| --- | --- | --- |
| `request_id` | Server-generated HTTP correlation returned as `X-Request-ID` | Structured logs and response header |
| `trace_id` | OpenTelemetry trace identity | Structured logs and Tempo |
| `span_id` | Active span identity | Structured logs |
| `processing_id` | Durable application/persistence identity | Response, PostgreSQL, and structured logs |
| `attempt_id` | Internal execution-attempt correlation | Selected structured reconciliation/execution events only |
| Backend operation reference | Opaque remote-operation identity | Safe `backend.operation.submitted` event |

These identifiers have different lifetimes and must not be substituted for each other. Processing and request identifiers are structured fields, not Prometheus or Loki stream labels.

### Request to trace to logs

1. Start from the server-returned `X-Request-ID`.
2. In the application dashboard or Explore, parse the bounded Loki stream and search the `request_id` field:

   ```logql
   {environment="lab",host="ir-core",service_name="alert2ir"}
     | json
     | request_id="00000000-0000-4000-8000-000000000000"
   ```

3. Read `trace_id` from a structured event and use the provisioned derived field to open Tempo.
4. Review the HTTP span and bounded application evidence for acceptance, durable transitions, backend submission/polling, and completion.
5. Use trace-to-logs to return to the surrounding Loki context.

The UUID is synthetic. Never put runtime identifiers into Git documentation.

### Processing-ID lookup

Search `processing_id` as a parsed JSON field in the same bounded Loki stream. Use the related `request_id` and `trace_id` to navigate. The processing ID is deliberately absent from metric labels and span attributes.

### Backend remote-operation lookup

`backend.operation.submitted` appears after a valid remote operation reference exists and before terminal polling. Search the opaque reference as a JSON field when determining whether remote work may outlive a later timeout or persistence failure. This narrowly scoped operator event does not make the operation reference public investigation evidence. The reference is not a metric label, default span attribute, or Loki stream label. The event and ordering are deterministically tested; no live exercise is required for routine validation.

## Error-category interpretation

| Category | Operator interpretation |
| --- | --- |
| `validation_error` | FastAPI/Pydantic rejected the canonical request |
| `routing_unsupported` | No investigation backend supports the required capabilities |
| `routing_ambiguous` | More than one investigation backend matched without a unique route |
| `backend_target` | The investigation backend could not resolve or accept the target |
| `backend_timeout` | Backend work exceeded its bounded deadline |
| `backend_execution` | Backend execution failed for another bounded reason |
| `persistence_unavailable` | PostgreSQL connection or interface was unavailable |
| `persistence_timeout` | Persistence exceeded its bounded timeout |
| `persistence_constraint` | PostgreSQL rejected a uniqueness/constraint operation |
| `persistence_mapping` | Persisted data could not be mapped to the domain contract |
| `persistence_internal` | Another persistence-internal failure occurred |
| `internal_error` | An unexpected application failure crossed the safe boundary |

Durable Execution adds these bounded categories: `validation_error`, `idempotency_conflict`, `unsupported_capability`, `backend_selection_error`, `backend_submission_failed`, `backend_submission_unknown`, `backend_execution_failed`, `backend_protocol_error`, `persistence_failed`, and `recovery_required`. `backend_timeout` now means a known operation remains `submitted`; `backend_submission_unknown` means automatic resubmission is unsafe.

Telemetry never derives dimensions from arbitrary exception messages or class names.

## Telemetry safety and cardinality

Application telemetry excludes raw alert payloads, target values, source alert identifiers and titles, commands, credentials, DSNs, certificates, tokens, raw backend results, and arbitrary exception text.

Correlation identifiers remain structured fields. Metrics and stream labels use only bounded dimensions such as host, controlled service identity, decision, outcome, capability, operation, and error category.

Durable lifecycle metrics are `alert2ir.processing.transitions`, `alert2ir.idempotency.requests`, `alert2ir.backend.submissions`, `alert2ir.reconciliation.operations`, `alert2ir.processing.stale`, and `alert2ir.processing.recovery_required`. Their dimensions are restricted to bounded state, transition, outcome, backend, and error-category values. Idempotency keys, fingerprints, processing/attempt/external IDs, source alert IDs, and trace IDs are never metric labels.

Reconciliation creates and resets correlation context for each row so processing or attempt identity cannot leak into the next non-HTTP work item. Idempotency keys and fingerprints are excluded from logs and traces as well as metrics.

## Alloy recovery

### ir-core Alloy

1. Inspect `systemctl status alloy --no-pager`.
2. Inspect a bounded window with `journalctl -u alloy --since '-15 minutes' --no-pager`.
3. Validate the installed file with `sudo alloy validate /etc/alloy/config.alloy`.
4. Check `curl -fsS http://127.0.0.1:12345/-/ready`.
5. Verify reachability to the three central gateways defined in the [configuration reference](../observability/README.md).
6. Restart Alloy only when configuration or runtime evidence supports it; do not restart Alert2IR merely because telemetry is unavailable.
7. Confirm Alloy self-metrics and application probes, metrics, logs, and traces resume centrally.

### obs01 Alloy

Use the same bounded systemd, journal, validation, and local-readiness checks. Then verify its loopback Prometheus, Loki, and Tempo paths from the configuration reference. Confirm central Alloy self-metrics after recovery. Application availability must remain independent.

## Central service recovery

1. Identify the failing service with the current release's `docker compose ps` or bounded `docker ps` query.
2. Inspect only a relevant recent log window.
3. Check the existing health endpoint or container health state.
4. Validate the exact Git-tracked configuration before recreation.
5. If a service bind-directory entry is missing or drifted, run the reviewed deployment helper with the explicit `/srv/alert2ir-observability` root; it normalizes only the entry and never recursively rewrites retained contents.
6. Recreate only the affected service when evidence requires it, preserving data paths and the Compose project.

Never use `docker compose down -v`, `docker system prune`, `docker volume prune`, or manual Docker-log truncation as routine recovery. Exact deployment, retention, data-path, and rollback conventions are in the [configuration reference](../observability/README.md).

## Operational privilege and warning boundaries

Native Alloy is non-root but receives security-sensitive Docker and containerd access. Docker-group membership is effectively root-equivalent, and containerd API access is not inherently read-only. Never make either socket world-accessible, expose it over TCP, or broaden firewall/socket access merely to suppress an error. Exact group/socket and listener configuration belongs in the configuration reference.

The existing cAdvisor discovery automatically includes `splunk_adapter` container metrics under its bounded Compose service label. Docker log discovery explicitly admits `core|splunk_adapter`; no new listener, dashboard, or source-gateway health dependency is introduced. Adapter Uvicorn logs remain subject to the same bounded Docker JSON rotation and must not contain request bodies, HMAC headers, secrets, or idempotency keys.

Current non-blocking warnings:

| Observation | Interpretation | Safe action |
| --- | --- | --- |
| cAdvisor filesystem-stat permission warnings for some root-owned storage | Some filesystem data may be absent while required CPU, memory, network, and bounded service identities remain available | Do not broaden filesystem or socket permissions merely to silence it |
| Grafana generic Alertmanager datasource health reports `plugin.unavailable` | The generic plugin-health call is not authoritative | Check Alertmanager container health and the datasource proxy |
| Backend dashboard panels have no data | No investigation occurred in the selected interval | Confirm expected request behavior; do not manufacture backend work |

The [observability configuration reference](../observability/README.md) is the source for exact versions, ports, retention, storage, secrets, deployment, and static validation.
