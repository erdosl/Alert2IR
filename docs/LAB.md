# Lab Inventory

## Host

The physical hypervisor is Ubuntu 24.04.4 LTS Desktop running VirtualBox 7.2.8. It has 64 GB RAM, 8 physical CPU cores, and ext4 SSD storage with substantial free capacity. It remains hypervisor-only; Codex is neither installed nor required there.

## Network

The VirtualBox host-only network is `192.168.56.0/24`. Each listed VM also has a VirtualBox NAT interface for normal Internet access.

Existing aliases follow `hostname`, `hostname.lab.test`, `hostname.admin`, and `hostname.admin.lab.test`. The `.admin` names currently resolve to the same host-only interfaces. They are aliases, not a separate management network.

## Systems

| Host | Host-only IP | Known state |
| --- | --- | --- |
| `win11-01` | `192.168.56.60` | Windows 11 Enterprise Evaluation 25H2; EditionID `EnterpriseEval`; build `26200.8875`; VirtualBox Guest Additions; Sysmon 15.21 and Splunk Universal Forwarder 10.4.2 installed and running |
| `splunk` | `192.168.56.61` | Ubuntu Server 24.04.4 LTS; Splunk Enterprise 10.4.1 build `5a009d941268`; currently 1 vCPU |
| `win11-02` | `192.168.56.62` | Windows 11 Enterprise Evaluation 25H2; EditionID `EnterpriseEval`; build `26200.8875`; VirtualBox Guest Additions; Sysmon 15.21 and Splunk Universal Forwarder 10.4.2 installed and running |
| `ir-core` | `192.168.56.63` | Ubuntu Server 24.04.4 LTS x86_64; Alert2IR runtime host; Docker Engine 29.7.2 and Docker Compose v5.4.0; currently 1 vCPU |
| `dev01` | `192.168.56.64` | Ubuntu Server 24.04.4 LTS; dedicated development/admin VM; Python 3.12.3, Git 2.43.0, Codex CLI 0.147.0; currently 1 vCPU |

WS03 successfully built, deployed, and validated the minimal containerized `core` service on `ir-core`. Validation covered the deterministic health endpoint, non-root runtime identity, loopback-only publication, restart convergence, and teardown/recreation. The service and its automatic Compose network were removed after validation; the built image and isolated validation artifact were intentionally preserved. Docker Engine, Docker Compose, and SSH were pre-existing host/bootstrap state and are not managed by the current Puppet catalog.

WS04 subsequently built and validated the typed Alert2IR core API on `ir-core` using the observed Docker Engine 29.7.2 and Docker Compose v5.4.0 runtime. Validation covered health, canonical investigate and no-action paths, strict request rejection, restart and full recreation, and publication only on `127.0.0.1:8000`. The validation service, container, and automatic Compose network were torn down afterward; the built image and isolated artifact may remain cached or preserved. This was not a permanent deployment, did not add PostgreSQL or external exposure, and did not place Docker under Puppet management.

## Existing telemetry path

Both Windows endpoints forward Sysmon Operational events to Splunk at `192.168.56.61:9997`. Current telemetry from both endpoints was verified during WS02 validation.

The current Universal Forwarder input is:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true
index = main
source = XmlWinEventLog\:Microsoft-Windows-Sysmon/Operational
sourcetype = XmlWinEventLog
```

Effective forwarding is:

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 192.168.56.61:9997
```

Splunk currently uses the default `main` index. Installed apps include Splunk Add-on for Sysmon, Splunk Security Essentials, and Splunk Common Information Model. These are observed effective settings; the current Puppet catalog does not own the complete Splunk local configuration files, and this baseline does not redesign them.

## WS08 validated detection path

WS08 validated the initial Sigma-to-Splunk detection path against the three committed WS07 ground-truth scenarios. The observed validation target was Splunk Enterprise `10.4.1` build `5a009d941268` with Splunk Add-on for Sysmon `5.0.1`.

Validation searches used index `main`, exact bounded one-second windows, and generated SPL containing the source `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, sourcetype `XmlWinEventLog`, EventCode `1`, and each rule's selectors.

The matched events reported host `win11-02`, source `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, and sourcetype `XmlWinEventLog`. Relevant extracted fields included `EventCode`, its `EventID` alias, `RecordID`, `Image`, `ParentImage`, `CommandLine`, and `TargetFilename`.

These are WS08-validated lab facts, not permanent desired state. WS08 did not change Splunk server configuration, Universal Forwarder ownership, endpoint `inputs.conf` or `outputs.conf`, the active Sysmon configuration, Windows audit policy, or PowerShell logging. Puppet still owns neither the complete endpoint forwarding configuration nor Splunk server configuration.

### Translation contract

Sigma remains canonical detection-as-code, and Splunk is the first concrete execution target. The validation used Sigma specification `2.1.0`, backend `splunk`, output format `default`, and this direct-pinned toolchain:

| Direct dependency | Version |
| --- | --- |
| `sigma-cli` | `3.1.0` |
| `pysigma` | `1.5.0` |
| `pysigma-backend-splunk` | `2.1.0` |

This is a direct-pinned translation toolchain with resolved-environment provenance, not a fully hermetic environment: transitive dependencies are not fully locked.

[`config/sigma/pipelines/alert2ir-splunk-xml-sysmon.yml`](../config/sigma/pipelines/alert2ir-splunk-xml-sysmon.yml) is the repository-owned target boundary. It applies only to `product=windows`, `category=process_creation` and adds:

```text
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
sourcetype="XmlWinEventLog"
EventCode=1
```

It does not map arbitrary Sysmon categories or add `index` or `host`; those Splunk/lab constraints remain outside canonical Sigma. No generic Sysmon pipeline dependency was introduced.

### Initial minimum detection set

The initial set is deliberately limited to three experimental process-creation rules:

| ATT&CK | Rule | Rule ID | Path | Status | Level | Primary behavior |
| --- | --- | --- | --- | --- | --- | --- |
| `T1057` | Process Discovery via Tasklist | `78441abe-99b0-4e6e-bd85-d52748e59d0e` | [`detections/sigma/windows/process-discovery-tasklist.yml`](../detections/sigma/windows/process-discovery-tasklist.yml) | `experimental` | `low` | `Image` ends with `\tasklist.exe`. |
| `T1059.001` | Encoded Windows PowerShell Command | `aebe017f-0dc6-4cae-8f07-6dc611963471` | [`detections/sigma/windows/powershell-encoded-command.yml`](../detections/sigma/windows/powershell-encoded-command.yml) | `experimental` | `medium` | `powershell.exe` with `-e `, `-enc `, or `-encodedcommand`. |
| `T1059.003` | Command Shell Temporary File Write and Display | `f769367f-7f3c-4ea4-8e68-fc39f93fd0a8` | [`detections/sigma/windows/cmd-temp-file-write-display.yml`](../detections/sigma/windows/cmd-temp-file-write-display.yml) | `experimental` | `low` | `cmd.exe` and a command line containing all of `echo`, `type`, and `\Windows\Temp\`. |

The T1057 rule does not require `ParentImage=cmd.exe`. The T1059.001 rule neither claims exhaustive PowerShell abbreviation coverage nor Script Block Logging support. The T1059.003 rule does not require literal `>` or `&` characters or the exact WS07 target filename.

### Live-validation results and evidence

Each detection search combined `index=main`, the exact bounded one-second WS07 validation window, and the exact generated detection SPL. Returned RecordIDs were then inspected. The expected RecordID was not a detection filter; no search filtered on an expected RecordID, WS07 run ID, exact PowerShell payload, or exact T1059.003 target or message.

| ATT&CK | Expected WS07 RecordID | Result count | Status | Observation |
| --- | ---: | ---: | --- | --- |
| `T1057` | `1300570` | `1` | `pass` | Expected process-creation event returned. |
| `T1059.001` | `1300904` | `1` | `pass` | Expected event returned; matched switch was `-e`. |
| `T1059.003` | `1301448` | `2` | `pass_with_additional_matches` | Expected event and related wrapper RecordID `1301440` returned. |

RecordID `1301440` is a `related_wrapper`: an SSH-launched `cmd.exe` wrapper whose command line also genuinely contained the three reviewed behavior fragments. It is not classified as a false positive, noise, a duplicate, or a detection failure. Corroborating WS07 file events `1301449` (EventCode 11) and `1301589` (EventCode 26) were not outputs of this process-creation detection.

WS07 raw `TimeCreated` retained greater-than-millisecond precision, while Splunk `_time` represented the expected events at millisecond precision. The observed Splunk-minus-WS07 differences were `-0.0009226 s` for T1057, `-0.0002803 s` for T1059.001, and `-0.0001030 s` for T1059.003; each reflected truncation below one millisecond. These observations establish no universal timing tolerance, and Sysmon `UtcTime` is not treated as Windows `TimeCreated`.

Canonical sanitized evidence is under [`validation/detection/`](../validation/detection/) with schema identifier `alert2ir-detection-validation-v1`. The records preserve canonical rule identity, path, hash, blob and commit; validation-time repository HEAD; toolchain and processing-pipeline provenance; generated and executed SPL plus hashes; target Splunk/Sysmon facts; the one-second window and WS07 correlation; result status and sanitized match summaries; and the additional-match relationship. They intentionally omit credentials and token values, the full PowerShell Base64 payload, raw XML and `_raw`, and the exact UUID-scoped T1059.003 target and message. The evidence records, rather than this summary, are authoritative for exact generated and executed SPL.

The chronology is deliberate: live validation ran at repository HEAD `9312f681919a3d05f05e85cb52d8981e61a80584` while the rule files were untracked. The exact validated blobs were then committed unchanged in canonical rule commit `19ad59060ccca96fc3205f39f26831da67fd8ba3`; sanitized validation records followed in `7ce9a021ef7124c5e4b71fdbafe804221a47ba1f`. The evidence therefore does not imply that validation occurred only after the rule commit.

### Scope boundaries

WS08 intentionally added no further Atomic executions, endpoint telemetry instrumentation, active Sysmon configuration change, Windows audit-policy change, or Script Block Logging. It did not attempt broad ATT&CK coverage or a large detection catalog; add a generic SIEM abstraction, generic Sysmon pipeline dependency, correlation engine, or Event 11/26 correlation rule; create Splunk saved searches, alerts, or dashboards; redesign production Splunk architecture or Universal Forwarder ownership; or fully lock the Sigma environment's transitive dependencies.

WS08 also did not add a Splunk-to-Alert2IR source adapter or ingestion path, modify `/v1/alerts`, implement an incident-response backend, use Velociraptor, or begin WS09. Validated Sigma-to-Splunk execution alone does not define the detection identity, source provenance, entity mapping, severity, evidence-reference, or delivery contract required for future ingestion.

## WS09 minimum Velociraptor bootstrap design

### Status

This section records the approved design and observed partial B1 implementation state. WS09 remains incomplete:

- **PACKAGE INSTALLED; SERVICE INTENTIONALLY INACTIVE/DISABLED PENDING B1 REVALIDATION**
- **NOT YET ENROLLED**
- **NOT YET API-VALIDATED**
- **NO LIVE VELOCIRAPTOR COLLECTION HAS RUN**

B1 server activation is not yet complete because service re-enable plus final reachability and identity revalidation has not run.

### Approved release, placement, and proof boundary

| Item | Approved value |
| --- | --- |
| Velociraptor release | `v0.77.2` |
| Release commit recorded by discovery | `c0c9dd609140139efcb37c47e2afa79ed57e6c84` |
| Linux AMD64 artifact | `velociraptor-v0.77.2-linux-amd64` |
| Linux SHA-256 | `6c4c23c466d892788ff56ddcd3a31f844e4c0d797ade454c5e2625eb9e427077` |
| Windows AMD64 MSI | `velociraptor-v0.77.2-windows-amd64.msi` |
| MSI SHA-256 | `7965d63d7c7434db425dba9dc7430f3e12c60e914017da9ac3617d0f3c9991e9` |
| GPG verification fingerprint | `0572 F28B 4EF1 9A04 3F4C BBE0 B22A 7FB1 9CB6 CFA1` |

The server package is installed on `ir-core` (`192.168.56.63`) under the approved native generated Debian package and systemd deployment model. Velociraptor is not part of Alert2IR Compose and is not owned by Puppet. The sole initial endpoint is `win11-02` (`192.168.56.62`); `win11-01` is outside this deployment slice. The only initial capability is `process.list`, privately realized by the backend with `Windows.System.Pslist`. No custom artifact or additional investigation capability is approved.

Discovery recorded `ir-core` as Ubuntu 24.04.4 LTS on `amd64`, with 1 vCPU, 3.8 GiB RAM, 3.8 GiB swap, and approximately 38 GiB free on the root filesystem. This is accepted only for the narrow WS09 lab proof: one server, one connected endpoint, and one process-list collection. It is not a production-sizing claim.

### Server configuration provenance and package realization

The three sanitized configuration identities are:

| Configuration stage | SHA-256 | Size | Provenance role |
| --- | --- | ---: | --- |
| Prepared source `server.config.yaml` | `88dc03cf978efa7bed86c74d5a36dc880ceeccc674d23cac63ecd7098a873a19` | 12714 bytes | Direct output of the reviewed `config generate` step; package-generation input provenance |
| Debian-package payload `server.config.yaml` | `0f8118bc192b0549c2370915a349b3e5e70a2113bc6e30274f1df98d361230bf` | 12806 bytes | Package-realized installation provenance |
| Installed `/etc/velociraptor/server.config.yaml` | `0f8118bc192b0549c2370915a349b3e5e70a2113bc6e30274f1df98d361230bf` | 12806 bytes | Installed-file identity |

The installed config bytes equal the Debian package payload config bytes. The configuration transformation therefore occurred during the reviewed `velociraptor 0.77.2 debian server` package-generation step, not during `dpkg` installation or `postinst`.

The sanitized semantic comparison established exactly one meaningful difference:

```text
prepared:        Frontend.run_as_user = unset / null
package-realized: Frontend.run_as_user = velociraptor
```

All previously approved values for `Client.server_urls`, `Client.use_self_signed_ssl`, `Frontend.hostname`, `Frontend.bind_address`, `Frontend.bind_port`, `API.hostname`, `API.bind_address`, `API.bind_port`, `GUI.bind_address`, `GUI.bind_port`, `Datastore.location`, and `Datastore.filestore_directory` remained identical. No private configuration values are recorded here.

The narrow reproducibility rule is:

```text
prepared server config = package-generation input provenance
Debian payload server config = package-realized installation provenance
installed server config = Debian payload bytes
```

For this exact reviewed package, `0f8118bc192b0549c2370915a349b3e5e70a2113bc6e30274f1df98d361230bf` is the required installed-config SHA-256. The prepared-source hash `88dc03cf978efa7bed86c74d5a36dc880ceeccc674d23cac63ecd7098a873a19` remains the expected pre-package source-configuration identity and must not be used as the installed-file gate.

`Frontend.run_as_user = velociraptor` is accepted as the expected v0.77.2 native Debian-package realization. It aligns with the package-created `velociraptor` system account, the systemd service running as user and group `velociraptor`, and the selected low-privilege native-service deployment model. It changes neither Alert2IR domain semantics nor Puppet ownership.

### B1 observed installation state

| Item | Observed fact |
| --- | --- |
| Installed package | `velociraptor-server` `0.77.2` `amd64` |
| Installed binary | `/usr/local/bin/velociraptor` |
| Installed binary SHA-256 | `6c4c23c466d892788ff56ddcd3a31f844e4c0d797ade454c5e2625eb9e427077`; exact pinned upstream Linux binary |
| systemd unit | `velociraptor_server.service` |
| Service user and group | `velociraptor:velociraptor` |
| Current containment | Package installed; service intentionally inactive and disabled pending B1 revalidation |

Before deliberate containment, the first service start demonstrated exactly these listeners:

```text
192.168.56.63:8443
192.168.56.63:8001
127.0.0.1:8889
127.0.0.1:8003
```

No approved Velociraptor surface was observed on `0.0.0.0`, `10.0.2.15`, or `[::]`. When the obsolete prepared-source-config hash gate failed against the package-realized installed config, the service was deliberately stopped and disabled. That hash mismatch is resolved package provenance, not a package defect or continuing B1 blocker. The service remains inactive and disabled until final B1 re-enable, reachability, and identity revalidation.

### Intended network bindings and accepted lab exposure

| Surface | Intended binding | Boundary |
| --- | --- | --- |
| Client frontend | `192.168.56.63:8443` | Host-only endpoint path |
| gRPC API | `192.168.56.63:8001` | Alert2IR runtime path using certificate authentication |
| GUI | `127.0.0.1:8889` | Loopback-only operator access |
| Monitoring, if emitted by generated configuration | `127.0.0.1:8003` | Loopback-only; no monitoring stack is introduced |
| Existing Alert2IR core | `127.0.0.1:8000` | Unchanged |

The approved bindings were observed on first start before deliberate containment, but they are not current live listeners while the service is intentionally inactive. Final B1 revalidation must verify them again after the separately authorized re-enable. The native frontend and API must bind only to `192.168.56.63`, not `0.0.0.0` or the NAT address `10.0.2.15`, unless separately reviewed. If v0.77.2 cannot provide the exact approved bindings, bootstrap must stop for architect review rather than broaden them. The GUI must remain loopback-only. No Velociraptor surface may be exposed to a public or Internet network.

#### Firewall ground truth and lab-scoped acceptance

Privileged inspection established the following current `ir-core` facts:

| Item | Observed or configured value |
| --- | --- |
| UFW runtime state | inactive |
| Saved UFW user rules | none |
| `/etc/default/ufw` `IPV6` | `yes` |
| `/etc/default/ufw` `DEFAULT_INPUT_POLICY` | `"DROP"` |
| `/etc/default/ufw` `DEFAULT_OUTPUT_POLICY` | `"ACCEPT"` |
| `/etc/default/ufw` `DEFAULT_FORWARD_POLICY` | `"DROP"` |
| Live IPv4 `INPUT` policy | `ACCEPT` |
| Live IPv6 `INPUT` policy | `ACCEPT` |

Because UFW is inactive, its configured defaults are not currently enforcing host-input filtering. Observed nftables/iptables content consisted of Docker NAT and forwarding rules and did not provide a native host-input restriction for the planned Velociraptor listeners. `ir-core` must not be described as presently protected by UFW, and Docker forwarding rules do not provide the intended Velociraptor input boundary.

For this owned, isolated WS09 lab environment, the architect accepts the absence of an `ir-core` host firewall for the initial Velociraptor proof. UFW activation and UFW rule creation are not required for WS09. Puppet firewall ownership and generic firewall tooling are not introduced. This is a lab-scoped acceptance, not a production security recommendation, a production deployment claim, a general Alert2IR firewall policy, or a precedent requiring removal of firewalls elsewhere. No compensating nftables, iptables, reverse-proxy, VPN, service-mesh, or other firewall infrastructure is introduced.

Without a host `INPUT` firewall, TCP/8443 and TCP/8001 may be reachable by other routable systems on the host-only `192.168.56.0/24` network. That reachability is explicitly accepted for this owned lab environment. WS09 functional scope nevertheless remains exactly one enrolled endpoint, `win11-02`; no other host may be enrolled or used merely because a listener is network-reachable. Useful API access still requires Velociraptor certificate authentication and the separately reviewed API authorization policy.

#### GUI TLS and protocol-security boundary

WS09 introduces no public CA certificate, Let's Encrypt integration, custom certificate lifecycle, reverse proxy, TLS termination proxy, or new web-security infrastructure. The Velociraptor GUI remains loopback-only at `127.0.0.1:8889` and retains Velociraptor's generated self-signed/internal TLS behavior. Bootstrap must not set `GUI.use_plain_http: true` or spend WS09 effort replacing the generated certificate. Browser certificate warnings are acceptable in this owned lab. GUI use is optional operator convenience and is not required to prove the Alert2IR backend; SSH forwarding may be used if convenient but is not a WS09 product requirement. A public or otherwise browser-trusted certificate is not required. WS09 avoids custom TLS infrastructure while preserving the protocol behavior Velociraptor itself expects.

This browser-facing convenience decision does not remove Velociraptor's frontend or API protocol security. The client path remains:

```text
win11-02
-> https://192.168.56.63:8443/
-> generated Velociraptor server/client trust
```

`Client.use_self_signed_ssl = true` remains required; the frontend must not be changed to clear-text HTTP. The API remains certificate-authenticated gRPC on `192.168.56.63:8001`, not clear text or unauthenticated transport. The later API identity, effective-ACL validation, and authorization checkpoint remain required.

### WS09 required proof and explicit non-goals

The WS09 roadmap-required proof is one Velociraptor server, one `win11-02` client, frontend connectivity, a certificate-authenticated API, one `process.list` collection, exact target mapping, and validation evidence.

A host firewall, UFW, custom GUI TLS, a public CA, a reverse proxy, TLS lifecycle automation, Puppet firewall ownership, a generic network-hardening framework, a second endpoint, production HA, backup/DR, and a monitoring stack are explicitly not required. This slice introduces no infrastructure or tooling polish for those non-goals.

### External runtime state and sensitive material

All generated Velociraptor material is external runtime/lab state and must never be committed. The minimum handling boundary is:

| Material | Classification and handling |
| --- | --- |
| `server.config.yaml` | Secret; contains server and CA private material |
| Generated server `.deb` | Secret-bearing because it embeds server configuration |
| Velociraptor datastore | Sensitive investigation, identity, and ACL state |
| Root client configuration | Sensitive enrollment configuration |
| Repacked MSI | Sensitive because it embeds client configuration |
| API client configuration | Secret; contains a private key and certificate |
| Windows client configuration and writeback | Sensitive client cryptographic identity |
| Observed `C.<client-id>` | Identifier, not a credential |

Official hashes, release identifiers, the GPG fingerprint, sanitized validation facts, and the exact observed `C.<client-id>` mapping may be documented where needed. Private configuration, key, certificate, or embedded secret material may not be committed.

### Endpoint enrollment and host mapping

Bootstrap may enroll only `win11-02` (`192.168.56.62`). After enrollment, the mapping must bind the exact Alert2IR host value `win11-02` to the exact observed Velociraptor `C.<client-id>`. No client ID is assumed in advance. Runtime hostname search, DNS lookup, normalization, and fuzzy matching remain prohibited.

#### Official release MSI provenance

Before repacking, the exact official MSI must pass the architect-pinned SHA-256 check and the Velociraptor detached GPG-signature check using the pinned fingerprint. For v0.77.2, package-level Windows Authenticode is not a required acceptance gate, and the official v0.77.2 MSI must not be described as Authenticode-signed.

#### Embedded executable trust

Before repacking, validation must inspect the `Velociraptor.exe` embedded in the verified official MSI without installing the product. The executable must have valid Windows Authenticode status and the expected signer identity consistent with the upstream Velociraptor release, currently documented upstream as `Rapid7 LLC`; its SHA-256 must be recorded. The exact extraction and inspection command is deferred to the separately reviewed Phase A resume.

#### Repacked lab MSI

For the owned WS09 lab and `win11-02` only, an unsigned repacked MSI remains acceptable. Repacking does not make the resulting MSI trusted or signed, and no code-signing certificate will be introduced or procured for WS09. Bootstrap validation must record the repacked MSI's SHA-256. Before installation, it must verify that the embedded `Velociraptor.exe` is the same previously verified executable by exact SHA-256 identity and still validates under Windows Authenticode. Installation remains limited to `win11-02`, and the installed `Velociraptor.exe` must receive an independent Authenticode verification afterward.

#### Phase A observation

The first Phase A attempt matched the exact approved MSI SHA-256 and passed the detached GPG-signature check. Package-level `Get-AuthenticodeSignature` returned `NotSigned`, and execution correctly stopped under the then-current gate. At that stop, no server configuration, Debian package, client configuration, or repacked MSI had been generated.

### API identity and pre-collection checkpoint

The intended least-privilege target is identity `Alert2IRWS09` in the root organization only, with the `api` role and `COLLECT_CLIENT` plus `READ_RESULTS`. This is a **TARGET POLICY**, not a validated effective ACL. Bootstrap must create no administrator API identity, inspect the effective policy after creation, and require exactly the permissions needed by the approved collection and result-read strategy. If the v0.77.2 effective ACL differs from the intended policy, bootstrap must stop for architect review and must never widen permissions automatically.

Before any real collection, bootstrap must issue a certificate-authenticated, non-mutating gRPC query for the exact enrolled client ID. This checkpoint must not schedule an artifact. It must establish that the API endpoint is reachable, mutual TLS authentication succeeds, minimal read authorization succeeds, and the observed `C.<client-id>` resolves to `win11-02`.

Slice 1 deliberately contains no external Velociraptor dependency. The eventual live adapter may use official `pyvelociraptor`, but no Python dependency pin is authorized until the v0.77.2 live API is established and compatibility is reviewed. Bootstrap includes no dependency-management redesign.

### Timeout and effect windows

The candidate WS09 timeout is 60 seconds. It is a lab-validation bound only, not a production claim. Successful scheduling followed by timeout may leave an upstream flow that later completes without an Alert2IR processing record. Successful collection followed by PostgreSQL persistence failure may likewise leave an upstream collection without a durable Alert2IR completion row. This slice adds no retry, cancellation orchestration, recovery, queue, worker, saga, or reconciliation mechanism.

### Teardown, reproducibility, and deferrals

Future bootstrap must be reproducible from the approved release artifacts and hashes while generating all environment-specific configuration, credentials, packages, identities, and datastore state outside Git. Future teardown must deliberately account for only WS09-created service/package state, endpoint client state, generated material, and datastore state. Sanitized validation facts and the exact non-secret client-ID mapping may remain documented; teardown does not create a backup or disaster-recovery design.

This bootstrap does not deploy Velociraptor in a container, add it to Alert2IR Compose, assign it to Puppet, enroll a second endpoint, add custom artifacts or capabilities, add public exposure, or introduce a reverse proxy, VPN, service mesh, general secret-management system, monitoring stack, backup/DR design, HA, retries or recovery, queues or workers, backend priority, failover, fan-out, or Splunk ingestion. Live adapter composition, dependency selection, and collection execution remain deferred to separately reviewed runtime work after bootstrap validation.
