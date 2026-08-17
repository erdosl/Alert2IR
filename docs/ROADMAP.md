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
| WS14 — Packer | Planned | Evaluate reproducible machine images only when an independently demonstrated image-lifecycle need justifies the infrastructure. |
| WS15 — osquery / Extended Backends | Planned | Add capability-oriented investigation backends only when concrete use cases justify them. |
| WS16 — Durable Execution | Complete | Source-scoped idempotent acceptance, canonical fingerprints, processing/attempt lifecycle, exact-operation resume, status retrieval, and bounded reconciliation delivered without a queue or worker service. |
| WS17 — Attack Simulation Breadth | Complete within bounded scope | Seven primaries and one control remain statically implemented; Event 11/Event 26 meet minimum live breadth acceptance; PowerShell-dependent live execution is deliberately deferred. |
| WS18 — Authoritative DNS & Windows NRPT | Complete | Native authoritative-only BIND, exact UFW/ACL exposure, dual-endpoint local NRPT, success containment, and unavailable-server no-leak behavior VALIDATED-LIVE. |
| WS19 — Authenticated Splunk Detection Delivery Discovery | Next | Define one bounded authenticated Splunk-finding delivery path with deterministic source normalization, explicit severity provenance, canonical alert construction, and handoff to existing durable processing. |

## Next actionable workstream

**WS19 — Authenticated Splunk Detection Delivery Discovery** is the next actionable workstream. It should define, but not yet assume, the smallest production boundary for:

```text
one bounded Splunk finding
  -> authenticated delivery
  -> deterministic source normalization
  -> canonical alert with explicit severity provenance
  -> existing durable Alert2IR processing and acknowledgement
```

The current repository has only the generic `SourceAdapter` protocol and accepts already-canonical alerts from a trusted loopback caller. It has no production Splunk adapter, automated Splunk-to-`/v1/alerts` delivery, API authentication/authorization, or source-owned severity-mapping provenance. In contrast, source-scoped idempotency, durable processing lookup/acknowledgement, deterministic severity policy, capability-aware routing, and the current `process.list` investigation path are already implemented. Closing the source-to-canonical delivery boundary therefore advances the actual detection-to-investigation product path more than additional lab simulation or image tooling.

WS19 is discovery only at this stage. It does not authorize an adapter, authentication implementation, API exposure change, or new runtime service.

## Deferred resumption conditions

- **WS11 — Binalyze AIR:** resume when a legitimate trial or license and a deployable service endpoint are available for scoped implementation and validation.
- **WS13 — CrowdStrike:** resume when legitimate trial or license access is available and a concrete optional-backend use case is approved.
- **WS17 — PowerShell-dependent live breadth:** revisit Event 3/15/22 and ancestry positive/control only if an independent endpoint-baseline requirement introduces an approved trusted script-execution model. There is no calendar trigger.

None of these deferrals blocks the open-source application path.

WS17's stopping condition is satisfied: seven primary scenarios and one ancestry control exist statically; direct Event 11, Event 26 cleanup, and independent cleanup verification are VALIDATED-LIVE; WS18 separately established VALIDATED-LIVE DNS/NRPT success and no-leak containment; and every deferred scenario retains active rules, mappings, contracts, provenance, and deterministic tests. Event 22's DNS prerequisite is satisfied. Live Event 3/15/22 and ancestry positive/control are deliberately deferred under the unchanged Windows execution baseline and are not prerequisites for product progress. Breadth coverage is intentionally asymmetric between static validation and live endpoint execution.

Alert2IR will not introduce `AllSigned`/Authenticode infrastructure, use `RemoteSigned`, bypass or mutate execution policy, deliver wrapper behavior inline, or rewrite/compile the scenarios solely for more simulation coverage. `docs/adr/0015-bounded-live-attack-simulation-coverage.md` records the decision. Registry, PowerShell Operational, named pipes, and Class C/high-risk scenarios remain separate policy or later-tier decisions rather than hidden WS17 completion requirements.

## Canonical outcome references

- [Application and API behavior](APPLICATION.md)
- [Compose deployment and lifecycle](DEPLOYMENT.md)
- [Current architecture](ARCHITECTURE.md)
- [Owned-lab topology](LAB.md)
- [Observability operation and recovery](OBSERVABILITY.md)
- [Architecture decision records](adr/README.md)
