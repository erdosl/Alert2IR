# ADR 0011: Adopt OpenTelemetry and a failure-isolated reference observability platform

**Status:** Accepted

## Context

The observability capability adds operational signals justified by the running Alert2IR system. Earlier operation exposed diagnostic gaps across API processing, backend execution and remote side effects, and persistence. The reference design expands application logging into a complete observability deployment while retaining open-source operation, optional monitoring, vendor-neutral application contracts, deterministic CI without live infrastructure, and sanitized operational evidence.

## Decision

### Application telemetry contract

Alert2IR will use OpenTelemetry for metrics and traces and will emit structured newline-delimited JSON application logs to stdout. It will generate a caller-facing `X-Request-ID` and keep its `request_id` distinct from OpenTelemetry `trace_id` and `span_id`, the durable `processing_id`, and any opaque backend operation reference retained where safe and operationally useful. Instrumentation will cover meaningful application, backend, and persistence boundaries and expose health and readiness semantics where appropriate.

This application-side contract is portable. A deployment may consume the OpenTelemetry and structured-log contracts with any compatible telemetry system; the reference lab stack is not a mandatory production dependency.

### Reference lab deployment

The reference open-source lab deployment will run Grafana, Prometheus, Alertmanager, monolithic Loki, monolithic Tempo, and central Grafana Alloy on `obs01`, with local Alloy on `ir-core`. One instance of Prometheus, Alertmanager, and Grafana is sufficient for this small-lab design. Alloy integrations will collect node/system, blackbox, and container telemetry where practical instead of requiring duplicate agents.

`obs01` is a separate observability failure domain. Alert2IR's processing outcome must not depend on `obs01`, Grafana, Prometheus, Alertmanager, Loki, Tempo, central Alloy, or successful telemetry export. An observability outage is a monitoring failure, not an application-processing failure; degradation must remain bounded and non-blocking, and telemetry loss during an outage is acceptable.

### CI and configuration ownership

Hosted CI will neither require `obs01` or the owned lab nor start the reference stack. Application telemetry behavior will be tested deterministically with local, fake, or in-memory instrumentation and without lab secrets, live Velociraptor, Splunk, AIR, CrowdStrike, or other external services.

Future observability deployment configuration under `observability/**` will be Git-tracked as canonical project state, including Compose, telemetry-backend and alerting configuration, Alloy configuration, and Grafana provisioning and dashboards. Runtime metrics, logs, traces, and other telemetry data are disposable lab state rather than canonical project evidence.

### Privacy and cardinality

Telemetry must be sanitized and bounded. Implementations must avoid unnecessary emission of raw alert payloads, forensic evidence, credentials, database DSNs, private keys or certificates, bearer tokens, raw vendor responses, arbitrary exception messages, command lines, and sensitive endpoint data. High-cardinality identifiers must not be metric labels or Loki stream labels.

## Alternatives considered

- Structured logs alone would leave the accepted metrics, tracing, infrastructure, dashboard, and alerting needs unmet.
- Prometheus-specific application instrumentation would unnecessarily couple the application contract to one backend.
- Direct application export to central backends would increase coupling and weaken local collection and failure-isolation boundaries.
- Co-locating the stack on `ir-core` would place monitoring in the application runtime's failure domain.
- A distributed or Kubernetes stack would add complexity without a demonstrated small-lab requirement.
- A commercial observability service would weaken the open reference path and cannot be required for core operation or CI.
- Separate application-telemetry and lab-platform ADRs would split one reviewed observability decision without improving its boundary.

## Consequences

The design enables request-to-backend-to-persistence diagnosis and correlation across metrics, logs, and traces while preserving portable application contracts, reproducible open-source lab configuration, resource visibility for the initial one-vCPU `obs01`, and CI independence. The reference-stack choice does not prevent production deployments from using other compatible telemetry backends.

Costs include application and deployment dependencies, a new VM and runtime configuration, telemetry retention and storage work, Docker/runtime permissions, privacy and cardinality controls, version-sensitive monitoring configuration, and operational validation. `obs01` starts with one vCPU; CPU adequacy is evaluated during operational validation using host and container telemetry, and the architecture will not be reduced solely because of the initial CPU allocation.
