# Roadmap

## Purpose

This roadmap records delivered capability, explicit deferrals, planned work, and the next actionable workstream. It does not preserve implementation chronology, validation transcripts, or commit history; canonical references and Git retain that detail.

Workstream numbering communicates a useful progression but is not a rigid serial dependency. Work may overlap when prerequisites, risk, and validation permit.

## Workstream state

| Workstream | Status | Outcome or objective |
| --- | --- | --- |
| WS01 — Baseline & Architecture | Complete | Repository conventions, project boundaries, architecture decisions, owned-lab record, and authorization scope established. |
| WS02 — Windows Endpoint Reproducibility | Complete | Endpoint inventory, Sysmon collection policy, and repeatable telemetry prerequisites established for both Windows endpoints. |
| WS03 — Docker / IR-Core | Complete | Minimal loopback-published Compose application deployment established on the reference runtime host. |
| WS04 — Alert2IR Core | Complete | Canonical alert, deterministic policy, incident/investigation, capability routing, mock backend, and typed API contracts delivered. |
| WS05 — Persistence | Complete | PostgreSQL, explicit migrations, durable completed-processing records, and data-preserving lifecycle behavior delivered. |
| WS06 — Puppet | Complete | Narrow Windows roles/profiles and deterministic standalone convergence contracts delivered. |
| WS07 — Attack Simulation | Complete | Three pinned controlled scenarios, sanitized canary ground truth, and verified cleanup evidence delivered. |
| WS08 — Sigma + Splunk | Complete | Canonical Sigma detections, deterministic Splunk translation, and execution validation against controlled ground truth delivered. |
| WS09 — Velociraptor | Complete | Optional `process.list` investigation backend and durable operation-reference path delivered. |
| WS10 — Testing & GitHub Actions | Complete | Routine application, PostgreSQL, migration, Sigma, and repository validation established without live-lab dependencies. |
| WS11 — Binalyze AIR | Deferred | Optional integration discovery is complete; implementation requires trial/license and deployable service access. |
| WS12 — Observability | Complete | Failure-isolated OpenTelemetry, Alloy, Prometheus/Loki/Tempo/Grafana, alerting, dashboards, readiness, and operator procedures delivered. |
| WS13 — CrowdStrike | Deferred | Optional integration requires trial/license access and is not a dependency of Alert2IR operation. |
| WS14 — Packer | Next | Evaluate and implement reproducible machine images where image lifecycle provides demonstrated value. |
| WS15 — osquery / Extended Backends | Planned | Add capability-oriented investigation backends only when concrete use cases justify them. |

## Next actionable workstream

**WS14 — Packer** is the next actionable workstream. It should establish a bounded image-lifecycle requirement before adding image-building infrastructure; this roadmap does not preselect an implementation beyond the accepted [configuration-management decision](adr/0006-machine-configuration.md).

## Deferred resumption conditions

- **WS11 — Binalyze AIR:** resume when a legitimate trial or license and a deployable service endpoint are available for scoped implementation and validation.
- **WS13 — CrowdStrike:** resume when legitimate trial or license access is available and a concrete optional-backend use case is approved.

Neither deferral blocks the open-source application path.

## Canonical outcome references

- [Application and API behavior](APPLICATION.md)
- [Compose deployment and lifecycle](DEPLOYMENT.md)
- [Current architecture](ARCHITECTURE.md)
- [Owned-lab topology](LAB.md)
- [Observability operation and recovery](OBSERVABILITY.md)
- [Architecture decision records](adr/README.md)
