# Alert2IR architecture

## Purpose and ownership

This document describes the implemented logical components of Alert2IR, their interactions, and their trust, persistence, and failure boundaries. It also identifies the deliberately narrow extension points without presenting possible extensions as deployed behavior.

The [project definition](PROJECT.md) owns mission and non-goals. The [application reference](APPLICATION.md) owns exact API, domain, routing, persistence, and acknowledgement semantics; the [deployment guide](DEPLOYMENT.md) owns repository-defined Compose operation. [Architecture decision records](adr/README.md) preserve why major choices were made, while executable source and tests define exact behavior.

## Current logical architecture

```text
Canonical alert request
        |
        v
Alert2IR API validation and domain conversion
        |
        v
Deterministic severity policy
        |
        +--------------------+
        |                    |
        v                    v
   no_action             investigate
                             |
                             v
                    investigation request
                             |
                             v
                   capability-based router
                             |
                             v
                  one investigation backend
                             |
                             v
                       backend result
        |                    |
        +---------+----------+
                  v
       completed orchestration
                  |
                  v
   processing identity and completed aggregate
                  |
                  v
          PostgreSQL persistence
                  |
                  v
              API response
```

The Alert2IR application is a Python/FastAPI process. Its `src/alert2ir/core` package contains the vendor-neutral domain model and workflow contracts; it is not a separate service or the name of the whole application. The `core` name is reserved for the Compose service that runs the application.

## Canonical alert and detection boundaries

Alert2IR accepts a canonical, vendor-neutral alert through `POST /v1/alerts`. API validation is the input boundary, after which application processing uses the canonical domain model. Vendor-specific event conversion belongs in a source adapter outside that model. No automatic Splunk, SIEM, EDR, or webhook ingestion adapter is implemented.

Detection execution is a separate concern from Alert2IR ingestion. The repository keeps Sigma as canonical detection-as-code and applies a repository-owned processing pipeline to derive Splunk SPL for the validated Windows process-creation cases:

```text
Canonical Sigma
    -> repository-owned target processing pipeline
    -> derived Splunk SPL
    -> Splunk execution and validation against controlled ground truth
```

This makes Splunk a validated detection execution target, not an Alert2IR alert-ingestion source. A finding must be represented as a canonical request and supplied to the API by an external caller; the repository implements no automated transition between those paths.

## Decision and investigation boundaries

The implemented policy is deterministic and bounded: low- and medium-severity alerts produce `no_action`, while high- and critical-severity alerts produce `investigate`. No correlation engine, machine-learning score, generalized risk engine, or dynamic policy orchestration is implemented. Policy is isolated behind an interface so a later policy can be reviewed without changing the canonical alert or investigation-backend contracts.

An investigation request states an open-string required capability independently of a vendor API. Investigation backends advertise supported capabilities, and the router applies an explicit cardinality rule:

- zero eligible investigation backends produces a bounded unsupported-routing outcome;
- exactly one eligible investigation backend is selected;
- multiple eligible investigation backends produce a bounded ambiguity outcome rather than an implicit preference.

Runtime composition provides exactly one investigation backend: the deterministic `MockBackend` for the open/testable path or the Velociraptor implementation for live process collection. Both support the current `process.list` capability. Velociraptor privately maps that capability to its collection operation; vendor identifiers and result rows do not enter the canonical model.

## Persistence and availability boundaries

PostgreSQL is the current durable store for completed processing aggregates. Persistence follows policy evaluation and any investigation-backend execution, uses a migration-managed schema, and assigns a durable processing identity before the save attempt. Detailed ordering, transaction, uniqueness, remote-effect, and HTTP-acknowledgement semantics belong in the [application reference](APPLICATION.md).

The availability endpoints deliberately expose different failure domains:

- `/healthz` proves Alert2IR application process liveness and performs no dependency checks;
- `/readyz` proves PostgreSQL connectivity and the required Alembic/schema revision.

Readiness does not depend on an investigation backend or any observability component. The [deployment guide](DEPLOYMENT.md) defines how operators use both endpoints.

## Observability architecture

The application emits structured JSON logs and optional OpenTelemetry traces and metrics. The reference lab deployment is:

```text
Alert2IR application on ir-core ---- OTel ----+
Docker JSON stdout ---------------------------+--> local ir-core Alloy
                                                      |
                                                      v
                                               central obs01 Alloy
                                                  |     |     |
                                             metrics   logs  traces
                                                  |     |     |
                                                  v     v     v
                                            Prometheus Loki  Tempo
                                                  \     |     /
                                                   \    |    /
                                                      Grafana

Prometheus -> Alertmanager -> lab-null
```

Telemetry export is failure-isolated from application processing, liveness, and readiness. The named hosts implement the reference lab topology; they are not mandatory logical components. [ADR 0011](adr/0011-observability-architecture.md) records the decision, the [observability operator guide](OBSERVABILITY.md) owns monitoring and recovery procedures, and [`observability/`](../observability/README.md) owns exact reference configuration.

## Failure boundaries

| Failure domain | Architectural effect |
| --- | --- |
| Investigation backend | An investigation request can fail without a completed local record. A submitted remote operation can nevertheless outlive a later timeout or persistence failure; the application reference defines this acknowledgement window. |
| PostgreSQL | Readiness fails when connectivity or schema revision is wrong. A persistence failure prevents completion acknowledgement and may follow an already-submitted remote operation. |
| Local Alloy | Application processing, `/healthz`, and `/readyz` remain independent; telemetry can be delayed or lost during bounded non-blocking degradation. |
| Central observability platform | Prometheus, Loki, Tempo, Grafana, and Alertmanager are operator facilities, not application dependencies. |
| Detection platform | Detection execution or search can fail without changing the canonical Alert2IR API contract; alert delivery remains an external concern. |

The architecture defines no high-availability, automatic retry, reconciliation, failover, fan-out, or arbitrary rollback guarantee.

## Trust and security boundaries

- External alert input crosses the API validation boundary before becoming a canonical domain value.
- PostgreSQL contains internal application state and is not published by the repository-defined Compose deployment.
- Database and investigation-backend credentials, certificates, and live target mappings remain external secrets and must not enter Git.
- Velociraptor calls cross an external-effect boundary; their opaque operation references are retained for correlation.
- Native Alloy access to Docker and containerd metadata is highly privileged and belongs only on trusted lab hosts.
- The reference deployment publishes the application on host loopback; broader exposure requires an independently reviewed access-control and transport boundary.
- Authorization for security testing is governed by [LAB_SCOPE.md](LAB_SCOPE.md), not inferred from network reachability or component capability.

## Logical architecture and extension points

The [lab inventory](LAB.md) maps these logical contracts onto `ir-core`, `obs01`, and the other owned systems. Alternate deployments may place the application, database, telemetry collector, and observability backends differently while preserving the same boundaries.

Intentional extension points are source adapters, policy implementations, investigation capabilities and backends, persistence implementations, and OpenTelemetry-compatible destinations. They do not imply that generalized source ingestion, correlation, asynchronous workers, commercial backends, Kubernetes, queues, caches, or distributed processing exist. Proposed work and deferrals belong in the [roadmap](ROADMAP.md).

## Related references

- [Project mission and non-goals](PROJECT.md)
- [Application and API contract](APPLICATION.md)
- [Compose deployment and lifecycle](DEPLOYMENT.md)
- [Owned-lab topology and deployed integrations](LAB.md)
- [Authorized lab scope](LAB_SCOPE.md)
- [Observability operation and recovery](OBSERVABILITY.md)
- [Workstream status and future work](ROADMAP.md)
- [Architecture decision record index](adr/README.md)
