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

This section is **APPROVED DESIGN / NOT YET DEPLOYED**. It records the minimum bootstrap contract and does not describe current lab state. WS09 remains incomplete:

- **NOT YET INSTALLED**
- **NOT YET ENROLLED**
- **NOT YET API-VALIDATED**
- **NO LIVE VELOCIRAPTOR COLLECTION HAS RUN**

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

The server is planned for `ir-core` (`192.168.56.63`) as a native generated Debian package and systemd service. Velociraptor is not part of Alert2IR Compose and is not owned by Puppet. The sole initial endpoint is `win11-02` (`192.168.56.62`); `win11-01` is outside this deployment slice. The only initial capability is `process.list`, privately realized by the backend with `Windows.System.Pslist`. No custom artifact or additional investigation capability is approved.

Discovery recorded `ir-core` as Ubuntu 24.04.4 LTS on `amd64`, with 1 vCPU, 3.8 GiB RAM, 3.8 GiB swap, and approximately 38 GiB free on the root filesystem. This is accepted only for the narrow WS09 lab proof: one server, one connected endpoint, and one process-list collection. It is not a production-sizing claim.

### Intended network bindings and firewall checkpoints

| Surface | Intended binding | Boundary |
| --- | --- | --- |
| Client frontend | `192.168.56.63:8443` | Host-only endpoint path |
| gRPC API | `192.168.56.63:8001` | Alert2IR runtime path using certificate authentication |
| GUI | `127.0.0.1:8889` | Loopback-only operator access |
| Monitoring, if emitted by generated configuration | `127.0.0.1:8003` | Loopback-only; no monitoring stack is introduced |
| Existing Alert2IR core | `127.0.0.1:8000` | Unchanged |

The `8443` and `8001` bindings are approved intentions, not live validation facts. Bootstrap must inspect the exact generated configuration and verify actual listeners. If v0.77.2 cannot bind the API exactly to `192.168.56.63`, bootstrap must stop for architect review and must not broaden the listener to `0.0.0.0`. The GUI must remain loopback-only. GUI or SSH forwarding is operator convenience, not a WS09 product requirement. No Velociraptor surface may be exposed to a public or Internet network.

UFW is currently active. Discovery could not read the existing UFW rules without elevation, so bootstrap must inspect the existing rule set before making any firewall change. Later frontend access should be limited to source `win11-02` (`192.168.56.62`) on TCP/8443. No broad TCP/8001 allow rule is approved. The Alert2IR container-to-host API path and its actual Compose source subnet and interface must be established in the later runtime slice before any API firewall allowance is designed.

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

For the owned WS09 lab and `win11-02` only, an unsigned repacked MSI is acceptable. This exception does not mean that the repacked package is trusted or signed, and no code-signing certificate will be introduced or procured for WS09. Future bootstrap validation must:

- verify the official downloaded MSI against the approved SHA-256;
- verify the official MSI's expected Authenticode signature before repacking;
- record the repacked lab MSI's SHA-256;
- install it only on `win11-02`; and
- verify that the installed Velociraptor executable retains the expected valid Authenticode signature.

The repacked MSI itself must not be described as retaining the official MSI signature.

### API identity and pre-collection checkpoint

The intended least-privilege target is identity `Alert2IRWS09` in the root organization only, with the `api` role and `COLLECT_CLIENT` plus `READ_RESULTS`. This is a **TARGET POLICY**, not a validated effective ACL. Bootstrap must create no administrator API identity, inspect the effective policy after creation, and require exactly the permissions needed by the approved collection and result-read strategy. If the v0.77.2 effective ACL differs from the intended policy, bootstrap must stop for architect review and must never widen permissions automatically.

Before any real collection, bootstrap must issue a certificate-authenticated, non-mutating gRPC query for the exact enrolled client ID. This checkpoint must not schedule an artifact. It must establish that the API endpoint is reachable, mutual TLS authentication succeeds, minimal read authorization succeeds, and the observed `C.<client-id>` resolves to `win11-02`.

Slice 1 deliberately contains no external Velociraptor dependency. The eventual live adapter may use official `pyvelociraptor`, but no Python dependency pin is authorized until the v0.77.2 live API is established and compatibility is reviewed. Bootstrap includes no dependency-management redesign.

### Timeout and effect windows

The candidate WS09 timeout is 60 seconds. It is a lab-validation bound only, not a production claim. Successful scheduling followed by timeout may leave an upstream flow that later completes without an Alert2IR processing record. Successful collection followed by PostgreSQL persistence failure may likewise leave an upstream collection without a durable Alert2IR completion row. This slice adds no retry, cancellation orchestration, recovery, queue, worker, saga, or reconciliation mechanism.

### Teardown, reproducibility, and deferrals

Future bootstrap must be reproducible from the approved release artifacts and hashes while generating all environment-specific configuration, credentials, packages, identities, and datastore state outside Git. Future teardown must deliberately account for only WS09-created service/package state, endpoint client state, generated material, datastore state, and any narrowly approved firewall change. Sanitized validation facts and the exact non-secret client-ID mapping may remain documented; teardown does not create a backup or disaster-recovery design.

This bootstrap does not deploy Velociraptor in a container, add it to Alert2IR Compose, assign it to Puppet, enroll a second endpoint, add custom artifacts or capabilities, add public exposure, or introduce a reverse proxy, VPN, service mesh, general secret-management system, monitoring stack, backup/DR design, HA, retries or recovery, queues or workers, backend priority, failover, fan-out, or Splunk ingestion. Live adapter composition, dependency selection, API firewall design, and collection execution remain deferred to separately reviewed runtime work after bootstrap validation.
