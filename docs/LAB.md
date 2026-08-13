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
