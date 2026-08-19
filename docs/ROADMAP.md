# Alert2IR roadmap

## Purpose

This roadmap records delivered capabilities, explicit deferrals, and planned product work. It uses functional names; Git history and validation records retain implementation chronology.

## Capability state

| Capability | Status | Outcome or objective |
| --- | --- | --- |
| Project architecture and boundaries | Complete | Repository conventions, architecture decisions, owned-lab records, and authorization scope are established. |
| Windows endpoint reproducibility | Complete | Endpoint inventory, Sysmon collection policy, and repeatable telemetry prerequisites are established for both Windows endpoints. |
| Application composition | Complete | The loopback-published application, PostgreSQL, and authenticated source gateway are defined with Docker Compose. |
| Canonical alert processing | Complete | Vendor-neutral alerts, deterministic policy, incidents, investigations, capability routing, mock backend, and typed APIs are delivered. |
| PostgreSQL persistence | Complete | Explicit migrations, durable processing records, execution attempts, and data-preserving lifecycle behavior are delivered. |
| Puppet endpoint configuration | Complete within bounded scope | Narrow Windows roles/profiles and deterministic standalone convergence contracts are delivered. |
| Controlled attack simulation | Complete within bounded scope | Seven primary scenarios and one control are statically implemented; direct file telemetry and cleanup have live validation. |
| Sigma detection content | Complete within bounded scope | Canonical rules, deterministic Splunk translation, and controlled validation are delivered. |
| Velociraptor backend | Complete | Optional `process.list` investigation and durable operation-reference handling are delivered. |
| Automated verification | Complete | Application, PostgreSQL, migration, Sigma, Compose, and repository tests run without live-lab dependencies. |
| Reference observability | Complete | Failure-isolated OpenTelemetry, Alloy, Prometheus, Loki, Tempo, Grafana, alerting, dashboards, readiness, and operator procedures are delivered. |
| Durable execution | Complete | Source-scoped idempotency, canonical fingerprints, processing lifecycle, exact-operation resume, status retrieval, and bounded reconciliation are delivered without a queue service. |
| Authoritative DNS and Windows NRPT | Complete | Authoritative-only BIND, exact UFW/ACL exposure, endpoint-local NRPT, success containment, and unavailable-server no-leak behavior are validated live. |
| Authenticated Splunk finding delivery | Complete in the owned lab | Bounded normalization, HMAC gateway, standalone sender, constrained deployment, marker-to-Pslist completion, and side-effect-safe replay are evidenced. |
| Binalyze AIR backend | Deferred | Optional integration requires legitimate trial or license access and a deployable endpoint. |
| CrowdStrike backend | Deferred | Optional integration requires legitimate trial or license access and an approved capability use case. |
| Reproducible machine images | Planned | Evaluate Packer only when an independently demonstrated image-lifecycle requirement justifies it. |
| Additional open investigation backends | Planned | Add capability-oriented backends such as osquery only when concrete use cases justify them. |

## Current validated integration

The accepted owned-lab path is:

```text
win11-02
  -> Sysmon Event 1
  -> Splunk scheduled Sigma-derived search
  -> alert2ir_delivery per-result action
  -> HMAC-authenticated splunk_adapter
  -> private Alert2IR core
  -> durable PostgreSQL processing
  -> Velociraptor Windows.System.Pslist
  -> reconciliation
  -> completed processing
```

Replay of the same logical finding returned the same processing record without another backend operation. The validation saved search was disabled afterward. This proves the bounded observed path, not globally lossless or exactly-once delivery.

Universal Forwarder acknowledgement hardening remains an operational follow-up. The application source restriction is independently persisted across runtime-host reboot.

## Deliberate deferrals

- Resume optional commercial backends only when legitimate access and a concrete capability requirement are approved.
- Revisit PowerShell-dependent live simulation only if an independent endpoint-baseline requirement introduces an approved trusted script-execution model.
- Registry telemetry, PowerShell Operational logging, named pipes, and higher-risk simulation classes remain separate policy decisions.

The attack-simulation stopping condition is satisfied: all scenarios and the ancestry control remain statically valid; direct Event 11, Event 26 cleanup, and independent cleanup verification are validated live; DNS/NRPT containment is separately validated; and deferred scenarios retain rules, mappings, contracts, provenance, and deterministic tests. Alert2IR will not add signing infrastructure, weaken execution policy, or replace scenario semantics solely to increase live coverage. ADR 0015 records that decision.
