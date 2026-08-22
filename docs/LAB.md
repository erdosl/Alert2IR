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
| `splunk` | `192.168.56.61` | Ubuntu Server 24.04 LTS | Detection execution and validation platform | Splunk Enterprise |
| `win11-02` | `192.168.56.62` | Windows 11 | Canary and investigation target | Sysmon, Splunk Universal Forwarder, Velociraptor client |
| `ir-core` | `192.168.56.63` | Ubuntu Server 24.04 LTS | Alert2IR application and investigation host | Alert2IR `core`, PostgreSQL, native Alloy, native Velociraptor |
| `dev01` | `192.168.56.64` | Ubuntu 24.04 LTS | Development and lab administration | Repository checkout, validation tools, native authoritative BIND 9 |
| `obs01` | `192.168.56.65` | Ubuntu Server 24.04 LTS | Central observability host | Native Alloy, Prometheus, Loki, Tempo, Grafana, Alertmanager |

The hostnames identify reference-lab machines, not logical application components. In particular, `ir-core` is a VM hostname, while `core` is the Compose service running the Alert2IR application.

## Stable network and integration relationships

| From | To | Relationship |
| --- | --- | --- |
| `dev01` | Owned lab hosts | Repository development, controlled management, validation, and intended standalone Puppet control over the host-only network |
| `win11-01`, `win11-02` | `dev01` | Local NRPT routes only `.alert2ir.test` to authoritative UDP/TCP `53` on `192.168.56.64` |
| `win11-01`, `win11-02` | `splunk` | Sysmon Operational events forwarded to the Splunk receiving service on TCP `9997` |
| `dev01` (`192.168.56.64`) | `ir-core` (`192.168.56.63:22`) | Exact UFW host-input exception for development and lab-administration SSH |
| `splunk` (`192.168.56.61`) | `ir-core` (`192.168.56.63:8091`) | Live-validated HMAC-authenticated bounded finding delivery; persistent Docker firewall boundary admits the Splunk host only |
| Local operator on `ir-core` | Alert2IR application | Loopback-only API publication on `127.0.0.1:8000` |
| Alert2IR `splunk_adapter` service | Alert2IR `core` service | Live-validated one-shot delivery to `http://core:8000` on the private Compose network |
| Alert2IR `core` service | PostgreSQL | Internal Compose-network database connection; PostgreSQL has no published host port |
| Alert2IR application | Velociraptor API on `ir-core` | Optional investigation calls when the Velociraptor Compose override is enabled |
| `win11-02` | Velociraptor frontend on `ir-core` | Enrolled endpoint communication for the current investigation target |
| Native Alloy on `ir-core` | Native Alloy on `obs01` | Metrics, logs, and traces forwarded to the central observability gateways |
| Operator on `dev01` | Grafana on `obs01` | Dashboard and alert inspection on TCP `3000` |
| Physical-host operator source `192.168.56.1` | `dev01` | Exact host-only management SSH exception on TCP `22`; not an approved DNS client |
| Physical-host operator source `192.168.56.1` | `ir-core` (`192.168.56.63:22`) | Exact UFW host-input exception for SSH administration |

Host firewall policy limits these relationships to their intended lab sources. Exact listeners, container networks, and collector pipelines are owned by deployment and component configuration rather than duplicated here.

## ir-core host-administration firewall

`ir-core` keeps its host-local SSH policy in operator-managed UFW with default incoming deny. The two approved administration sources remain separate exact rules on `enp0s8`: `192.168.56.64 -> 192.168.56.63:22/TCP` for `dev01` administration and `192.168.56.1 -> 192.168.56.63:22/TCP` for physical-host administration. Neither rule authorizes `192.168.56.0/24` or an arbitrary source.

```bash
sudo ufw allow in on enp0s8 from 192.168.56.64 to 192.168.56.63 port 22 proto tcp comment 'dev01 SSH administration'
sudo ufw allow in on enp0s8 from 192.168.56.1 to 192.168.56.63 port 22 proto tcp comment 'host SSH administration'
sudo ufw status numbered
sudo iptables -S ufw-user-input
```

Run a bounded ordinary SSH connection to `192.168.56.63` from each exact source after policy changes. Do not replace these rules with a subnet-wide allowance.

These UFW `INPUT` allowances are independent of the Alert2IR `DOCKER-USER` forwarding boundary, which continues to admit only `192.168.56.61` to the original Docker-published destination `192.168.56.63:8091` and drops other `enp0s8` sources to that destination. After the physical-host SSH allowance was added, a full `ir-core` VM reboot preserved the rule and SSH availability. The sanitized [host SSH firewall acceptance record](../validation/integration/host-ssh-firewall-2026-08-18.json) owns the validation detail.

## Authoritative DNS and Windows NRPT

`dev01` runs native packaged BIND 9 authoritative-only for `alert2ir.test.` on `192.168.56.64:53` over UDP and TCP. It has no NAT/wildcard/IPv6 listener, recursion, forwarding, transfer, dynamic update, or command channel. The zone contains only `dev01.alert2ir.test -> 192.168.56.64` and `splunk.alert2ir.test -> 192.168.56.61`. UFW default-deny and the BIND ACL independently restrict DNS to `win11-01` and `win11-02`.

Each Windows endpoint has exactly one local `.alert2ir.test -> 192.168.56.64` NRPT rule. Interface DNS remains unchanged. All-NIC packet capture proved success and authoritative NXDOMAIN used only `dev01`; with `named.service` stopped, each endpoint sent three retries only to `dev01`, failed resolution, and sent zero packets for the owned name to NAT, other IPv4, IPv6, or VPN resolvers. Ordinary `splunk.lab.test` continued through `10.0.2.3`. The sanitized **VALIDATED-LIVE** authority is `validation/infrastructure/dns/dns-infrastructure-2f770f89-d84f-47b9-a633-17e42454b01c.json`; raw captures were deleted.

Implementation re-attestation superseded the discovery expectation that UFW was active: it was inactive with default incoming deny and zero stored allowances. The exact `.1 -> .64:22` management exception was approved before activation and the existing session survived; effective policy is exact, while a fresh connection from `.1` could not be originated by this execution environment and remains explicitly pending rather than fabricated.

## Alert2IR deployment

The tracked Compose deployment for `ir-core` defines:

- the `core` service for the Alert2IR application;
- the separate stateless `splunk_adapter` service for HMAC-authenticated Splunk findings;
- the internal `postgres` service and persistent named volume;
- loopback-only canonical API publication at `127.0.0.1:8000`;
- source-adapter publication only at `192.168.56.63:8091`, with an operator-owned firewall requirement admitting `192.168.56.61` alone;
- `/healthz` for application liveness and the Docker healthcheck;
- `/readyz` for PostgreSQL connectivity and required schema readiness.

The base deployment selects the deterministic mock investigation backend. The Velociraptor override selects the live investigation backend and injects an external API configuration plus one exact host-to-client mapping. These modes are mutually exclusive in runtime composition.

The private application network is the logical Compose network `alert2ir_private`, backed in the reference deployment by Linux bridge `alert2ir-prv0` and IPv4 subnet `172.30.63.0/28` with gateway `172.30.63.1`. Docker's configured dynamic IPAM range is `172.30.63.8/29`. Only `core` has a static container address, `172.30.63.2`; it is deliberately outside the dynamic allocation range so `splunk_adapter`, `postgres`, or another dynamically addressed sibling cannot consume the firewall principal before `core` claims it. UFW INPUT admits only `172.30.63.2/32` on that bridge to native `192.168.56.63:8001` for the Velociraptor API and `192.168.56.63:4317` for local Alloy OTLP. The host default INPUT deny excludes sibling containers from those ports. This is independent of the existing `DOCKER-USER` boundary for Docker-published `:8091`.

Tracked configuration defines the deployment boundary but is not by itself live evidence. The adapter, protected secrets, and Splunk app were directly observed during the 2026-08-18 source-integration acceptance. The later firewall-persistence acceptance records that the exact source restriction is reconciled by a Docker systemd pre-start hook and survived a controlled `ir-core` reboot without manual firewall reapplication. Sanitized records under `validation/integration/` own that evidence.

Alert processing uses source-scoped idempotency and durable execution state in PostgreSQL. Callers must retain their `Idempotency-Key` for acknowledgement recovery, and operators may inspect the returned processing-status resource or run the bounded one-shot reconciliation command documented in [DEPLOYMENT.md](DEPLOYMENT.md). No queue, broker, or separate worker is deployed.

The current lab still uses a legacy project-scoped PostgreSQL volume recorded in the separately reviewed live-migration inventory. Migration A does not rename, copy, attach, or otherwise alter that volume. Routine lifecycle commands must preserve it; the canonical repository contract requires `ALERT2IR_POSTGRES_VOLUME` to be set to the exact approved data-bearing volume during a later cutover.

See [APPLICATION.md](APPLICATION.md) for application behavior and [DEPLOYMENT.md](DEPLOYMENT.md) for configuration, migration, startup, acceptance, and data-preserving lifecycle procedures.

## Detection and endpoint telemetry

Sysmon on both Windows endpoints supplies host telemetry through Splunk Universal Forwarder to `splunk`. Canonical Sigma rules live under [`detections/sigma`](../detections/sigma/); narrow repository-owned pipelines under [`config/sigma`](../config/sigma/) preserve the historically validated Event 1 process mapping and statically implement Event 3, 11, 15, and 22 mappings. Sanitized historical live evidence remains under [`validation/attack-simulation`](../validation/attack-simulation/) and [`validation/detection`](../validation/detection/).

The repository defines seven primary attack-simulation scenarios plus one ancestry negative-control variant. Authorized acceptance on 2026-08-17 attested `win11-02`, active Sysmon policy equality, and current Splunk forwarding, then **VALIDATED-LIVE** the direct Event 11 objective, Event 26 cleanup, and independent post-state verification. Authoritative DNS/NRPT validation separately established Event 22's DNS infrastructure prerequisite on both endpoints. Event 3/15/22 and ancestry positive/control remain statically implemented, but their PowerShell-wrapper-dependent live execution is **DEFERRED BY PROJECT DECISION** under the unchanged endpoint execution baseline. Event 22 is not DNS-blocked.

Splunk is a validated detection execution target and the repository implements one narrow sender/gateway path from a per-result finding to the existing canonical API. Splunk never receives direct host-network access to `/v1/alerts`: it calls only `POST /v1/splunk/findings` on port `8091`, while the gateway fixes source identity, canonicalizes, and calls core privately. Controlled acceptance on 2026-08-18 proved one validation-only high finding reached durable `process.list` completion through Velociraptor and that replay returned the same processing with zero additional `Windows.System.Pslist` operations. The validation search was disabled again afterward. Universal Forwarder `useACK=false` remains a separate reliability-hardening concern; neither the acceptance nor this lab design claims lossless or exactly-once delivery.

The staging path `C:\ProgramData\Alert2IR\AttackSimulation` has a repository-only desired ACL contract under `config/windows/attack-simulation-staging-acl.json`. No endpoint ACL remediation was applied by the breadth closure, and Puppet does not currently own that path.

The [attack-simulation reference](ATTACK_SIMULATION.md) owns controlled ground-truth provenance, [SYSMON.md](SYSMON.md) owns the endpoint collection profile, and [WINDOWS_ENDPOINT_INVENTORY.md](WINDOWS_ENDPOINT_INVENTORY.md) owns the read-only inventory procedure. Detailed detection authoring guidance remains outside this topology document.

## Velociraptor integration

Velociraptor runs natively on `ir-core`, and `win11-02` is the enrolled endpoint used by the current investigation path. Alert2IR can select Velociraptor as its investigation backend for the `process.list` capability. The application requires exactly one canonical `host` target and resolves it through an externally configured exact client mapping.

Certificates, API credentials, client identifiers, and generated server state remain outside Git. The application contract deliberately excludes client discovery, hostname normalization, generalized artifact selection, retry, failover, and fan-out. Application-facing semantics belong in [APPLICATION.md](APPLICATION.md); safe activation belongs in [DEPLOYMENT.md](DEPLOYMENT.md).

## Puppet configuration boundary

The repository's Puppet environment uses deliberate standalone `puppet apply`; no Puppet Server control plane is deployed. Windows catalog application remains established on the two endpoints. Linux foundation and bounded role-specific desired state are represented for all four Ubuntu 24.04 LTS amd64 hosts, but no Linux host currently has Puppet or Facter installed and no live Linux convergence is claimed.

The catalog boundary:

- keeps the already-installed Sysmon and Splunk Universal Forwarder services running and enabled at startup;
- stages the project-owned Sysmon XML bytes;
- does not apply or compare the active Sysmon configuration;
- verifies Linux platform and physical identity facts without changing them;
- ensures `ripgrep` and `shellcheck` are installed on the four Linux reference VMs;
- owns exact Docker public-source/package state on `dev01`, `ir-core`, and `obs01`, including one portable containerd baseline and bounded `obs01` log rotation;
- owns native Alloy public-source/package/config/service state on `ir-core` and `obs01`, including additive named-group access to the exact containerd socket;
- owns `git` on `dev01`, stable documented application/observability parents, the root observability data directory, and native Alloy host-service state;
- does not own Linux runtime bootstrap, the `jgipsz` account, ordinary public-key SSH authorization, private keys, `sshd`, sudo, firewall policy, endpoint networking, Compose/release lifecycle, Splunk Enterprise, Velociraptor protected state, or BIND.

`dev01` remains the lab administration and intended Puppet control origin. Existing SSH and sudo access are bootstrap/external prerequisites rather than Puppet-managed desired state.

Puppet does not restart Docker or containerd when their canonical configuration
files change. Current adoption therefore migrates the two host-local numeric
containerd socket GIDs to a name-based `alloy-containerd` contract without
disrupting containers; a later reviewed containerd restart or reboot must prove
the systemd post-start reconciliation and Alloy telemetry access. The Compose
`core` source identity and native `:8001`/`:4317` UFW INPUT policy remain
separate operator-owned network and firewall contracts outside Puppet.

Exact ownership, artifact assembly, and validation procedures are in [`infra/puppet/README.md`](../infra/puppet/README.md).

## Observability deployment

Native Alloy on `ir-core` receives application OpenTelemetry data and observes host/container metrics, Docker logs, and local probes. It forwards edge telemetry to native Alloy gateways on `obs01`. The central Alloy instance forwards metrics to Prometheus, logs to Loki, and traces to Tempo. Grafana is the operator view, and Prometheus sends alerts through Alertmanager to the internal `lab-null` receiver.

On `obs01`, Puppet owns the stable `/srv/alert2ir-observability` parent and
native Alloy's `alloy` child. The observability deployment owns the
Alertmanager, Prometheus, Grafana, Loki, and Tempo bind-directory entries and
their runtime UID/GID mapping to the exact pinned images; it does not create
host accounts for those numeric container identities.

The observability path is failure-isolated: neither local Alloy nor the central platform is required for Alert2IR request processing, `/healthz`, or `/readyz`. [OBSERVABILITY.md](OBSERVABILITY.md) owns operator correlation, alerts, and recovery; [`observability/README.md`](../observability/README.md) owns the exact reference configuration and deployment procedure.

## Security and information boundaries

- [LAB_SCOPE.md](LAB_SCOPE.md) is the sole authorization boundary for controlled security activity.
- Database credentials, Velociraptor trust material, private endpoint inventories, and other secrets remain outside Git.
- Raw DNS packet captures and unrelated resolver/firewall inventories remain outside Git; only sanitized counts and exact owned tuples are retained.
- Sanitized validation artifacts may preserve deterministic evidence; raw endpoint or product data must not be committed.
- The host-only network and loopback API publication reduce exposure but do not replace authentication, authorization, or transport review for any broader deployment.
- The adapter's HMAC protects authentication and integrity but not confidentiality. Its HTTP publication is acceptable only within the owned host-only lab with the exact Splunk-source firewall restriction; broader use requires TLS review.
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
