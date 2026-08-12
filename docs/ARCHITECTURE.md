# Architecture

## Status

This document describes the planned architecture. Vendor-neutral canonical-alert and source-adapter boundaries, decisions, incidents, investigation requests, backend capability contracts, a deterministic MockBackend, in-memory orchestration, and the typed FastAPI core boundary are implemented and validated on `ir-core`. WS05 completed PostgreSQL composition, the completed-processing schema and repository, and durable `POST /v1/alerts` request-path integration; the exact committed artifact was validated on `ir-core` and deliberately removed afterward rather than becoming a permanent deployment. Successful `no_action` and `investigate` responses include a processing UUID after the completed aggregate is persisted. The persistence boundary remains deliberately narrow: no retries, durable idempotency, execution recovery, mutable incident lifecycle, correlation, retention, backup/DR, HA, readiness endpoint, or production-scale claim is implied. Detection content, live detection-source integration, and real investigation backends remain future work. WS06 completed deterministic repository contracts for the existing Windows Puppet roles/profiles and validated one unchanged Git-derived artifact with standalone Puppet 8.20.0 on both endpoints. The catalog manages the running and startup state of already-installed Sysmon and Splunk Universal Forwarder services and stages the project-owned canonical Sysmon XML; each endpoint's noop and two enforcing applies were clean, including the idempotent second apply. Staging owns file bytes only: it does not apply or compare Sysmon's active configuration, reload either telemetry service, own the Sysmon Operational channel, or manage complete Splunk local configuration. Puppet Agent remains stopped and disabled outside catalog ownership, and no Puppet Server control plane was introduced.

## Conceptual flow

```text
Alert sources
    |
    v
Source adapters -- normalization boundary --> Canonical alert
                                              |
                                              v
                                  Correlation / risk / policy
                                              |
                                              v
                                  Investigation request
                                              |
                                              v
                              Capability-based backend selection
                                    |                    |
                               MockBackend          Real backends
                                                    (Velociraptor first)
```

### Alert sources

Source adapters ingest vendor-specific detections. Splunk is the initial real source, but core contracts must not encode Splunk as the universal model.

### Normalization boundary and canonical alert

Normalization ends source-specific concerns and produces a canonical alert representation. The representation will carry the detection identity, time and entities, source provenance, evidence references, severity or confidence inputs, and other fields established during application design. This document intentionally does not fix a premature schema.

### Correlation, risk, and policy

Canonical alerts enter a decision layer that may correlate related activity, calculate or accept risk signals, and enforce policy. Its output determines whether and what investigation should be requested. Decisions should be explainable and retain provenance.

### Investigation request

An investigation request expresses the desired outcome and required capabilities independently of a vendor API. It is the boundary between detection decisions and investigation execution.

### Capability-based backends

Backends advertise supported investigation capabilities. Routing and validation use those capabilities; unsupported operations fail explicitly rather than being hidden behind a misleading common interface.

The initial strategy is:

1. Build a MockBackend with deterministic behavior for core integration tests.
2. Add Velociraptor as the first real investigation backend.
3. Add Binalyze AIR only after the open-source workflow functions.
4. Treat CrowdStrike as optional and never a runtime requirement.

## Planned platform boundaries

Python and FastAPI are planned for the core application, PostgreSQL for persistence, and Docker Compose for application/service composition. Puppet owns desired-state configuration; Packer may later own reproducible machine-image construction. These responsibilities are decisions, not evidence that any component is currently deployed.

No Kubernetes or speculative queues, caches, or distributed workers are planned without a demonstrated requirement.
