# Owned lab

## Purpose and authorization

This document records the current systems in the owned Alert2IR lab, their durable roles, stable network relationships, and concise deployed integration state. It is not a deployment transcript, validation archive, or authorization grant.

Security testing is authorized only as defined by [LAB_SCOPE.md](LAB_SCOPE.md). Network reachability, NAT access, host aliases, or a component's technical capability do not expand that boundary.

## Infrastructure and network

The lab runs on an owned physical Ubuntu/VirtualBox hypervisor. The physical host is infrastructure only and is not an attack-simulation target.

All six virtual machines use the host-only `192.168.56.0/24` lab network. NAT interfaces provide ordinary package installation and updates; they are not authorized testing paths. Each VM's hostname, `.lab.test`, `.admin`, and `.admin.lab.test` aliases resolve to the same host-only address. These aliases do not constitute a separate management network.

## Current systems

| Host | Address | Platform | Durable role | Key deployed services |
| --- | --- | --- | --- | --- |
| `win11-01` | `192.168.56.60` | Windows 11 | Reference Windows telemetry endpoint | Sysmon, Splunk Universal Forwarder |
| `splunk` | `192.168.56.61` | Ubuntu Server | Detection execution and validation platform | Splunk Enterprise |
| `win11-02` | `192.168.56.62` | Windows 11 | Canary and investigation target | Sysmon, Splunk Universal Forwarder, Velociraptor client |
| `ir-core` | `192.168.56.63` | Ubuntu Server | Alert2IR application and investigation host | Alert2IR `core`, PostgreSQL, native Alloy, native Velociraptor |
| `dev01` | `192.168.56.64` | Ubuntu | Development and lab administration | Repository checkout and validation tools |
| `obs01` | `192.168.56.65` | Ubuntu Server | Central observability host | Native Alloy, Prometheus, Loki, Tempo, Grafana, Alertmanager |

The hostnames identify reference-lab machines, not logical application components. In particular, `ir-core` is a VM hostname, while `core` is the Compose service running the Alert2IR application.

## Stable network and integration relationships

| From | To | Relationship |
| --- | --- | --- |
| `dev01` | Owned lab hosts | Repository development, controlled management, and validation over the host-only network |
| `win11-01`, `win11-02` | `splunk` | Sysmon Operational events forwarded to the Splunk receiving service on TCP `9997` |
| Local operator on `ir-core` | Alert2IR application | Loopback-only API publication on `127.0.0.1:8000` |
| Alert2IR `core` service | PostgreSQL | Internal Compose-network database connection; PostgreSQL has no published host port |
| Alert2IR application | Velociraptor API on `ir-core` | Optional investigation calls when the Velociraptor Compose override is enabled |
| `win11-02` | Velociraptor frontend on `ir-core` | Enrolled endpoint communication for the current investigation target |
| Native Alloy on `ir-core` | Native Alloy on `obs01` | Metrics, logs, and traces forwarded to the central observability gateways |
| Operator on `dev01` | Grafana on `obs01` | Dashboard and alert inspection on TCP `3000` |

Host firewall policy limits these relationships to their intended lab sources. Exact listeners, container networks, and collector pipelines are owned by deployment and component configuration rather than duplicated here.

## Alert2IR deployment

The repository-defined Compose deployment runs on `ir-core` with:

- the `core` service for the Alert2IR application;
- the internal `postgres` service and persistent named volume;
- loopback-only API publication;
- `/healthz` for application liveness and the Docker healthcheck;
- `/readyz` for PostgreSQL connectivity and required schema readiness.

The base deployment selects the deterministic mock investigation backend. The Velociraptor override selects the live investigation backend and injects an external API configuration plus one exact host-to-client mapping. These modes are mutually exclusive in runtime composition.

Alert processing uses source-scoped idempotency and durable execution state in PostgreSQL. Callers must retain their `Idempotency-Key` for acknowledgement recovery, and operators may inspect the returned processing-status resource or run the bounded one-shot reconciliation command documented in [DEPLOYMENT.md](DEPLOYMENT.md). No queue, broker, or separate worker is deployed.

The deployed Compose project's PostgreSQL volume is `alert2ir-ws09-live_postgres_data`. This exact current identity ties the data-preservation target to the same deployed project whose bounded service labels are retained by edge cAdvisor; routine lifecycle commands must preserve the volume.

See [APPLICATION.md](APPLICATION.md) for application behavior and [DEPLOYMENT.md](DEPLOYMENT.md) for configuration, migration, startup, acceptance, and data-preserving lifecycle procedures.

## Detection and endpoint telemetry

Sysmon on both Windows endpoints supplies host telemetry through Splunk Universal Forwarder to `splunk`. Canonical Sigma rules live under [`detections/sigma`](../detections/sigma/); the repository-owned pipeline under [`config/sigma`](../config/sigma/) derives the validated Splunk searches for the initial Windows process-creation cases. Sanitized deterministic and live evidence remains under [`validation/attack-simulation`](../validation/attack-simulation/) and [`validation/detection`](../validation/detection/).

Splunk is a validated detection execution target. It is not an Alert2IR alert-ingestion source, and the repository implements no Splunk-to-`/v1/alerts` adapter. Canonical alert delivery remains an external caller responsibility.

The [attack-simulation reference](ATTACK_SIMULATION.md) owns controlled ground-truth provenance, [SYSMON.md](SYSMON.md) owns the endpoint collection profile, and [WINDOWS_ENDPOINT_INVENTORY.md](WINDOWS_ENDPOINT_INVENTORY.md) owns the read-only inventory procedure. Detailed detection authoring guidance remains outside this topology document.

## Velociraptor integration

Velociraptor runs natively on `ir-core`, and `win11-02` is the enrolled endpoint used by the current investigation path. Alert2IR can select Velociraptor as its investigation backend for the `process.list` capability. The application requires exactly one canonical `host` target and resolves it through an externally configured exact client mapping.

Certificates, API credentials, client identifiers, and generated server state remain outside Git. The application contract deliberately excludes client discovery, hostname normalization, generalized artifact selection, retry, failover, and fan-out. Application-facing semantics belong in [APPLICATION.md](APPLICATION.md); safe activation belongs in [DEPLOYMENT.md](DEPLOYMENT.md).

## Puppet configuration boundary

The repository's Puppet environment applies deliberately through standalone `puppet apply` on the two Windows endpoints; no Puppet Server control plane is deployed. Its current catalog boundary:

- keeps the already-installed Sysmon and Splunk Universal Forwarder services running and enabled at startup;
- stages the project-owned Sysmon XML bytes;
- does not apply or compare the active Sysmon configuration;
- does not own the complete Splunk forwarding configuration, endpoint networking, or lab administration.

Exact ownership, artifact assembly, and validation procedures are in [`infra/puppet/README.md`](../infra/puppet/README.md).

## Observability deployment

Native Alloy on `ir-core` receives application OpenTelemetry data and observes host/container metrics, Docker logs, and local probes. It forwards edge telemetry to native Alloy gateways on `obs01`. The central Alloy instance forwards metrics to Prometheus, logs to Loki, and traces to Tempo. Grafana is the operator view, and Prometheus sends alerts through Alertmanager to the internal `lab-null` receiver.

The observability path is failure-isolated: neither local Alloy nor the central platform is required for Alert2IR request processing, `/healthz`, or `/readyz`. [OBSERVABILITY.md](OBSERVABILITY.md) owns operator correlation, alerts, and recovery; [`observability/README.md`](../observability/README.md) owns the exact reference configuration and deployment procedure.

## Security and information boundaries

- [LAB_SCOPE.md](LAB_SCOPE.md) is the sole authorization boundary for controlled security activity.
- Database credentials, Velociraptor trust material, private endpoint inventories, and other secrets remain outside Git.
- Sanitized validation artifacts may preserve deterministic evidence; raw endpoint or product data must not be committed.
- The host-only network and loopback API publication reduce exposure but do not replace authentication, authorization, or transport review for any broader deployment.
- Native Alloy access to Docker and containerd metadata is privileged and is confined to trusted lab hosts.

## Canonical references

- [Current architecture](ARCHITECTURE.md)
- [Application and API contract](APPLICATION.md)
- [Compose deployment and lifecycle](DEPLOYMENT.md)
- [Authorized lab scope](LAB_SCOPE.md)
- [Observability operation and recovery](OBSERVABILITY.md)
- [Sysmon collection profile](SYSMON.md)
- [Windows endpoint inventory procedure](WINDOWS_ENDPOINT_INVENTORY.md)
- [Puppet environment](../infra/puppet/README.md)
- [Observability reference configuration](../observability/README.md)
