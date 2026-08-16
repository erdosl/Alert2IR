# Alert2IR application

## Purpose

The Alert2IR application accepts normalized security alerts, applies deterministic investigation policy, selects a capability-compatible investigation backend when investigation is required, persists the completed processing state, and returns a bounded HTTP response.

The application is the Python/FastAPI process. The `core` name identifies that process's Compose service, `src/alert2ir/core` is its domain model/workflow package, and `ir-core` is a lab VM hostname. None of those narrower names is a synonym for the whole application.

## Canonical alert model

`POST /v1/alerts` accepts a vendor-neutral canonical alert rather than a source-specific event. The request contains:

| Concept | Contract |
| --- | --- |
| Detection | Required nonblank identifier and optional nonblank name |
| Detection time | Required timezone-aware `detected_at` value |
| Source provenance | Required nonblank source and optional nonblank source alert ID |
| Entities | Ordered `{kind, value}` references; both values are nonblank and kinds are open strings |
| Severity | Exactly `low`, `medium`, `high`, or `critical` |
| Evidence | Ordered opaque references with an optional nonblank kind |

The entities and evidence collections may be empty. Unknown fields are rejected at the API boundary, so vendor payload fields must be normalized before submission. Evidence references do not imply URL semantics, and the canonical alert has no generated canonical-alert identifier.

No source adapter is implemented in this repository. Splunk is a validated detection execution target for the detection work, not an Alert2IR ingestion adapter; an API client must submit the canonical request.

## Processing flow

Request processing follows this order:

```text
HTTP request validation
  -> canonical domain conversion
  -> policy decision
  -> optional investigation request, backend selection, and execution
  -> processing ID generation
  -> completed-record persistence
  -> HTTP response
```

Validation, policy, routing, or investigation-backend failure occurs before a processing ID is generated or persistence is attempted. After orchestration succeeds, the application generates the processing ID and asks the repository to save the accepted alert and completed result once. A persistence failure prevents a successful response.

## Decision semantics

The `baseline-severity-v1` policy produces one of two outcomes and retains source provenance in its decision:

- `no_action`: `low` and `medium` severity. The application creates no incident or investigation request and does not select or execute an investigation backend. The completed no-action result is still persisted.
- `investigate`: `high` and `critical` severity. The application creates an incident, builds an investigation request, selects an eligible investigation backend, executes it synchronously, and persists the complete result.

This baseline is deterministic severity policy, not a correlation engine or a risk-scoring claim.

## Investigation backend selection

An investigation request states a desired outcome, one or more required capabilities, and ordered entity targets without naming a vendor. Capability identifiers are nonblank open strings. An investigation backend advertises the capabilities it supports and is eligible when it supports every required capability; selection proceeds only when exactly one backend is eligible.

| Eligible backends | Behavior |
| --- | --- |
| Zero | Fail explicitly as unsupported; the API returns HTTP 409 |
| One | Select and execute that investigation backend |
| More than one | Fail explicitly as ambiguous; the API returns HTTP 500 without choosing |

Capabilities split across different backends do not satisfy one request. The router defines no priority, fallback, fan-out, or tie-breaking policy.

## HTTP API

### `POST /v1/alerts`

The route accepts the canonical alert schema and, after successful persistence, returns HTTP 200 with:

- a server-generated `processing_id`;
- the policy decision;
- an incident, investigation request, and investigation result for `investigate`;
- null investigation fields for `no_action`.

`created_at` and persistence snapshot details are not exposed. The repository implements no public read, list, update, or delete route.

| Status | Meaning |
| --- | --- |
| 200 | Processing completed and the result was persisted |
| 409 | No configured investigation backend supports all requested capabilities |
| 422 | The request failed schema or canonical-value validation |
| 500 | Routing was ambiguous, or an internal, investigation-backend, or persistence failure occurred |

Unsupported and ambiguous routing have bounded typed error responses. Other internal failures return a generic error and do not expose exception text.

For each request, middleware generates a new UUID and returns it as `X-Request-ID`, including on request-validation and supported error paths. A caller-supplied `X-Request-ID` is ignored. The request ID is an HTTP-attempt correlation value, not the durable processing ID and not an OpenTelemetry trace ID.

## Liveness and readiness

`GET /healthz` is process liveness only. It returns HTTP 200 with `{"status":"ok"}` and performs no PostgreSQL, investigation-backend, or observability dependency check. The Compose healthcheck intentionally uses this route.

`GET /readyz` verifies PostgreSQL connectivity and that the database is at the exact Alembic revision required by the application. It returns HTTP 200 with `{"status":"ready"}` when both checks pass, and a sanitized HTTP 503 response `{"status":"not_ready"}` otherwise. It does not check an investigation backend, Alloy, the central observability host, Prometheus, or Grafana.

## Processing identity and persistence

`processing_id` is the application-generated UUID and primary identity of one durable completed-processing record. It is allocated only after policy evaluation and any investigation-backend execution succeed, immediately before the save attempt. It is distinct from detection identity, `source_alert_id`, request ID, and trace/span identity; it is retained in logs and traces but is not promoted to a telemetry label.

The application-facing repository stores one immutable completed aggregate: the processing ID, database-assigned timezone-aware `created_at`, accepted canonical alert, decision, and any incident/request/result graph. The deployed application uses the PostgreSQL repository. Each save uses a short transaction after orchestration; no database transaction spans investigation-backend execution. The processing ID is unique, and duplicate insertion fails rather than replacing a record.

The PostgreSQL representation uses an explicit snapshot version and preserves ordered entities, evidence, reasons, targets, and capability values. Migrations and schema constraints are the exact storage authority; they do not create independent identities for the nested domain values.

## External-effect and acknowledgement boundaries

An investigation backend may produce a remote effect before Alert2IR can finish local processing. The Velociraptor client, for example, emits `backend.operation.submitted` with the opaque operation reference after one remote flow is scheduled and before terminal polling. A later timeout, remote-status error, or persistence failure does not undo that flow. Consequently, an HTTP failure does not prove that no remote side effect occurred; operators should correlate the operation reference before deciding whether to retry.

There is a separate persistence/response acknowledgement window. A database commit may succeed even if the client disconnects or does not observe the HTTP 200 response. The application provides no distributed transaction, durable idempotency key, automatic reconciliation, or retry protocol across the remote effect, local record, and HTTP acknowledgement boundaries.

## Supported investigation capabilities

The runtime request factory asks for the open-string capability `process.list` and copies the alert entities into the investigation targets.

- The deterministic `MockBackend` supports `process.list` without external systems and returns synthetic evidence.
- The Velociraptor investigation backend supports `process.list` by privately mapping it to process collection. It requires exactly one `host` target with an exact configured host-to-client mapping, executes one synchronous bounded collection call, and returns the fresh opaque collection reference as evidence.

The Velociraptor boundary does not expose process rows in the API result and does not provide discovery, hostname normalization, retry, cancellation, failover, fan-out, or generalized artifact selection.

## Observability and correlation contract

The application emits structured JSON events plus OpenTelemetry traces and metrics. Export is optional and failure-isolated from request processing. Telemetry does not contain raw alert payloads. Request ID, processing ID, trace ID, span ID, and investigation-backend operation reference remain distinct identifiers with different lifetimes.

See the [observability operator guide](OBSERVABILITY.md) for correlation steps, bounded error categories, dashboards, alerts, and recovery procedures.

## Current limitations

- Canonical alerts must be supplied through `/v1/alerts`; there is no automatic Splunk, SIEM, EDR, or webhook ingestion adapter.
- Request planning is limited to the deterministic `process.list` mapping, and the runtime configures exactly one investigation backend.
- Request processing, investigation-backend execution, and PostgreSQL access are synchronous on the asynchronous route.
- The application has no public processing retrieval, retry, durable idempotency, interrupted-work recovery, mutable incident lifecycle, or backend failover.

See the [roadmap](ROADMAP.md) for project direction instead of treating this list as a workstream ledger.

## Sources of truth

Executable source and tests define exact behavior. The principal references are:

- [`src/alert2ir`](../src/alert2ir/) for API, application, domain, backend, persistence, and runtime composition;
- [`tests`](../tests/) for executable contracts;
- [`migrations`](../migrations/) for the database schema and migration policy;
- [architecture](ARCHITECTURE.md) for system-level boundaries;
- [deployment](DEPLOYMENT.md) for repository-defined Compose operation;
- [observability](OBSERVABILITY.md) for telemetry and operator procedures;
- [roadmap](ROADMAP.md) for project direction.
