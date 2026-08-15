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

This section records the approved design and observed implementation state. WS09 is operationally complete:

- **B1 HISTORICAL FUNCTIONAL VALIDATION: COMPLETE**
- **RETIRED SERVER/CLIENT DEPLOYMENT TEARDOWN: COMPLETE**
- **FRESH-PKI ARTIFACT GENERATION: COMPLETE**
- **FRESH B1 SERVER VALIDATION: COMPLETE**
- **FRESH B2 CLIENT INSTALLATION AND IDENTITY VALIDATION: COMPLETE**
- **B3 MINIMUM API IDENTITY AND ACL PROOF: COMPLETE**
- **FIRST LIVE `process.list` INVESTIGATION COLLECTION PROOF: COMPLETE**
- **`pyvelociraptor` COLLECTION CLIENT: IMPLEMENTED**
- **ALERT2IR LIVE BACKEND RUNTIME COMPOSITION: DEPLOYED AND VALIDATED**
- **FIRST ALERT2IR-TO-VELOCIRAPTOR END-TO-END ATTEMPT: FAILED AT ADAPTER FLOW-STATE VALIDATION**
- **CORRECTED CORE REDEPLOY: COMPLETE**
- **FINAL SUCCESSFUL ALERT2IR-TO-VELOCIRAPTOR END-TO-END INVESTIGATION: COMPLETE**
- **WS09: OPERATIONALLY COMPLETE**

The achieved scope is the real Velociraptor-backed `process.list` path for the exact lab mapping `"win11-02" -> "C.4c0d758c0344d6b5"`. Runtime composition still selects exactly `mock` or `velociraptor`; the live graph contains one `VelociraptorBackend`, `PyVelociraptorCollectionClient`, the fixed `60.0`-second timeout, and no `MockBackend`. This completion does not imply generalized Velociraptor support or begin WS10.

### First Alert2IR-to-Velociraptor end-to-end attempt (failed)

Detection `ws09-e2e-process-list-001` issued exactly one canonical alert POST with semantics `high -> investigate -> process.list -> win11-02 -> VelociraptorBackend`. The HTTP result was 500 with an empty response body. Velociraptor nevertheless scheduled fresh flow `F.D9VPIBOAOTBD8` through creator `Alert2IRWS09` for `Windows.System.Pslist`; the flow later reached `FINISHED` with 156 collected rows and remains retained as historical lab evidence. Completed-processing rows remained zero, and no retry occurred.

This was forensic `CASE B`: the Velociraptor side effect occurred, but Alert2IR did not durably complete processing. The exact application exception was `VelociraptorCollectionError: Velociraptor flow returned a malformed or unknown state`. The pre-fix adapter recognized only `RUNNING` as nonterminal, rejected a legitimate transient Velociraptor 0.77.2 state, and aborted orchestration before persistence while the remote flow subsequently finished. The failed-attempt flow ID is evidence, not runtime configuration, and has no corresponding completed-processing record.

### Corrected core redeploy and provenance

The correction was deployed from exact canonical Git content after the first attempt:

| Item | Validated identity |
| --- | --- |
| Commit | `ed12b445a0a9430c360fb4b4356eafc8ef98fc5d` |
| Tree | `f0592affe9d3dafcda217d7ac534f86eb7851e99` |
| Subject | `fix: handle Velociraptor transient flow states` |
| Source method | `git archive ed12b445a0a9430c360fb4b4356eafc8ef98fc5d` |
| Staging path | `/home/jgipsz/alert2ir-ws09-live-ed12b445a0a9` |
| Archive SHA-256 | `c4612121e9fb74cd5280bd8e1d66780a7aac8243305e2c7c22ba681e5cc1ca75` |
| Core image ID/repository digest | `sha256:fdf9eb454bc702e5df744c042207ad3734798eaea256dbec93b789d4224394c0` |
| Platform manifest | `sha256:472ba22da984aaacb8690b10c11206b33ad5ec4fbdfcb97fd911355e56801a29` |
| Image config | `sha256:02bfd61f440f3e266629a816f20aea363697ea67e7d1b02e3bebdb535fa6acb7` |
| Commit-specific local tag | `alert2ir-ws09-live-core:ed12b445a0a9430c360fb4b4356eafc8ef98fc5d` |
| Corrected core container | `3bd21b009de73128919d243a035fdfc256a690e6ee33c95a08c3acb373274174` |

Only `core` was replaced. PostgreSQL container `0996963153bef558de3d8b74a2ec351fd7e572f2ac72b60c64f32cf23a044f23`, named volume `alert2ir-ws09-live_postgres_data`, and migration `0001_processing_records` were preserved without reset or recreation. Completed-processing rows remained zero through redeploy.

#### Protected API credential boundary

Exactly one secret-bearing API configuration remains external to Git at `/home/jgipsz/velociraptor-bootstrap/v0.77.2/Alert2IRWS09.api.config.yaml` and is mounted read-only inside core at `/run/secrets/alert2ir-velociraptor-api.yaml`. Its validated SHA-256 is `485bc8c1c4d39d059fe9009a81c4c86ce888a4c3364b75ae64a8075331459422`, size is 4333 bytes, and owner/group is `jgipsz:jgipsz`. The authoritative ACL is:

```text
user::rw-
user:999:r--
group::---
mask::r--
other::---
```

The visible stat mode may be `0640` because of POSIX ACL mask semantics; the named-user ACL is intentional. Principal `Alert2IRWS09` retains stored role `api` with explicit `read_results=true` and `collect_client=true`. Its complete effective TRUE permission set remains exactly `ANY_QUERY`, `READ_RESULTS`, and `COLLECT_CLIENT`; no administrator-equivalent expansion occurred.

#### Corrected flow-state behavior

For Velociraptor 0.77.2, the deployed adapter classifies `UNSET`, `RUNNING`, `WAITING`, `IN_PROGRESS`, and `UNRESPONSIVE` as nonterminal, `FINISHED` as terminal success, and `ERROR` as terminal failure. `FAILED` is not a 0.77.2 enum state and remains fail-closed as unknown protocol drift.

The adapter retains one scheduling query, captures one fresh `F.*` flow ID, polls only that same flow under one bounded monotonic deadline, and adds no scheduling retry, replacement flow, or automatic cancellation. Unknown states fail closed.

### Successful Alert2IR-to-Velociraptor end-to-end attempt

Detection `ws09-e2e-process-list-002` carried request timestamp `2026-08-14T23:41:12Z`. Exactly one POST to `http://127.0.0.1:8000/v1/alerts` ran from `2026-08-14T23:42:43Z` through `2026-08-14T23:42:47Z`, with HTTP retry disabled. It returned HTTP 200 OK and no retry was performed.

| Field | Validated value |
| --- | --- |
| Processing UUID | `bcebe47f-c5e1-4834-a92c-1c765ea6771f` |
| Decision | `investigate` |
| Policy | `baseline-severity-v1` |
| Desired outcome | `collect process inventory` |
| Required capability | `process.list` |
| Target | `win11-02` |
| Backend | `velociraptor` |
| Completed capability | `process.list` |
| Fresh flow | `F.D9VQFSTQD87H4` |
| Flow creator | `Alert2IRWS09` |
| Flow client | `C.4c0d758c0344d6b5` |
| Flow artifact | `Windows.System.Pslist` only |
| Final state | `FINISHED` |
| Collected rows | 158 |

Completed-processing rows transitioned exactly `0 -> 1`. The sole row is for `ws09-e2e-process-list-002`; its processing-record ID and the HTTP processing ID are both `bcebe47f-c5e1-4834-a92c-1c765ea6771f`. The returned and persisted evidence kind is `collection`, and the primary cross-layer equality is:

```text
HTTP EvidenceReference.reference
= persisted EvidenceReference.reference
= actual fresh Velociraptor flow ID
= F.D9VQFSTQD87H4
```

#### Final retained flow cardinality

At closure, exactly three flows (`total = 3`) match creator `Alert2IRWS09` plus artifact `Windows.System.Pslist`:

| Flow | Purpose | State | Rows |
| --- | --- | --- | ---: |
| `F.D9VKVH7ES21BA` | Historical direct API/backend substrate proof | `FINISHED` | 157 |
| `F.D9VPIBOAOTBD8` | Failed application E2E #1 side effect | `FINISHED` | 156 |
| `F.D9VQFSTQD87H4` | Successful application E2E #2 | `FINISHED` | 158 |

No fourth matching flow exists. All three are retained, and their IDs remain evidence/provenance rather than runtime configuration. The successful E2E used one application request and created exactly one new Pslist flow; WS09 introduced no HTTP or scheduling retry, replacement flow, fallback, failover, fan-out, or overlapping `MockBackend` plus `VelociraptorBackend` execution.

At completion, corrected core and PostgreSQL remained running and healthy; core remained published only at `127.0.0.1:8000`; PostgreSQL retained no host publication of TCP/5432; `GET /healthz` returned HTTP 200 with `{"status":"ok"}`; completed-processing rows equaled `1`; migration remained `0001_processing_records`; and the credential hash, ownership, and ACL remained unchanged. Git remained canonical and clean at `ed12b445a0a9430c360fb4b4356eafc8ef98fc5d`. WS09 is operationally complete for the exact live `process.list` lab path and does not claim broader resilience, generalized Velociraptor support, or completion of any later workstream.

### Fresh-PKI artifact-generation checkpoint

This checkpoint is **ACCEPTED ARTIFACT PROVENANCE / NOT DEPLOYED**. It records the clean transition from the retired trust deployment to fresh deployment inputs without erasing the historical B1/B2 chronology below.

#### Retired teardown state

The retired server and client deployment was completely removed before fresh generation. The retired Debian package, systemd unit, installed binary, server configuration, datastore, Windows service and MSI registration, endpoint configuration and writeback, generated server and client packages, and repacked MSI no longer remain. The `velociraptor` operating-system user and group were intentionally retained because they hold no cryptographic trust identity.

Only the verified public v0.77.2 Linux and Windows release artifacts, their detached signatures, and the isolated public GPG verification state survived teardown. Retired hashes remain documented below as historical provenance only and are prohibited for reuse.

#### Fresh generation status

```text
Fresh-PKI artifact generation: COMPLETE
Fresh deployment: NOT YET PERFORMED
Fresh B1 validation: NOT YET PERFORMED
Fresh B2 enrollment validation: NOT YET PERFORMED
B3: NOT YET PERFORMED
NO LIVE VELOCIRAPTOR COLLECTION HAS RUN
```

#### Approved non-secret bootstrap decisions

The fresh bootstrap used exactly these approved non-secret merge values:

| Section | Field | Approved value |
| --- | --- | --- |
| Client | `server_urls` | exactly `https://192.168.56.63:8443/` |
| Client | `use_self_signed_ssl` | `true` |
| Client | `writeback_windows` | `$ProgramFiles\Velociraptor\velociraptor.writeback.yaml` |
| Frontend | `hostname` | `192.168.56.63` |
| Frontend | `bind_address` | `192.168.56.63` |
| Frontend | `bind_port` | `8443` |
| API | `hostname` | `192.168.56.63` |
| API | `bind_address` | `192.168.56.63` |
| API | `bind_port` | `8001` |
| GUI | `bind_address` | `127.0.0.1` |
| GUI | `bind_port` | `8889` |
| GUI | initial users | none |
| Monitoring | `bind_address` | `127.0.0.1` |
| Monitoring | `bind_port` | `8003` |
| Datastore | `location` | `/opt/velociraptor` |
| Datastore | `filestore_directory` | `/opt/velociraptor` |

No other configuration was added.

#### Fresh artifact provenance

| Artifact | Filename or stage | SHA-256 | Size | Classification |
| --- | --- | --- | ---: | --- |
| Prepared server configuration | `server.config.yaml` | `cb0b51234713c09d0139a81d05033faf66eea76666feb5464399375e23f2f9d7` | 12722 bytes | Secret-bearing generation artifact |
| Debian-package payload server configuration | package payload `server.config.yaml` | `1d1711837a92e1c9f16ee3f890abae94a27fbc140407f5d95d33025fd0ca2a21` | 12814 bytes | Package-realized secret-bearing server config |
| Root client configuration | `client.root.config.yaml` | `5eaae96c06aec022e5d4add8c7076b9676a5c718854cb72595d7aa64767516cb` | 2691 bytes | Secret-bearing client deployment config |
| Generated Debian package | `velociraptor-server-0.77.2.amd64.deb` | `e7afff45864c2dc600dc53656df6b95583ae74c99868dc0f6c56cdc130de03b1` | 30485672 bytes | Secret-bearing because it embeds server configuration |
| Fresh repacked `win11-02` MSI | `velociraptor-v0.77.2-win11-02-repacked.msi` | `0485a9c7ec649440eabf650b8a7bcf33fb24b60d6bfe1a826b4aa28560bf002d` | 27537408 bytes | Secret-bearing because it embeds client configuration |

These fresh hashes identify the current approved deployment inputs. They do not establish that any artifact is installed or active.

#### Package realization and freshness proof

Fresh package generation reproduced the known v0.77.2 realization:

```text
prepared Frontend.run_as_user: null / unset
package payload Frontend.run_as_user: velociraptor
```

All other approved sanitized deployment fields and trust material were verified equal between the prepared and package-realized server configurations. This is expected package-generation behavior, not drift.

The fresh server and client trust material is internally consistent: the client nonce matched the fresh server nonce, and the client CA matched the fresh server CA. Both fresh trust identities differed from their retired counterparts, and all four fresh generated-artifact hashes differ from the corresponding retired server configuration, root client configuration, Debian package, and repacked MSI hashes.

No nonce value, nonce fingerprint, PEM body, private key, full server configuration, or full client configuration is recorded. Generated server and client configuration must never be emitted unfiltered; Git records only hashes, sizes, non-secret deployment settings, and sanitized equality and freshness conclusions.

#### Deployment boundary and next action

At this artifact-generation checkpoint, the generated artifacts were accepted provenance inputs for the resumed WS09 proof, but generation did **not** establish a deployed B1 server or an enrolled B2 client. The next separately authorized action at that checkpoint was fresh B1 server installation and activation on `ir-core`. That action was subsequently authorized and completed as recorded in the fresh B1 checkpoint below; artifact generation itself still does not prove deployment.

This checkpoint introduces no change to `win11-01`, `ir-core` capacity, the accepted host-firewall boundary, custom browser TLS, a reverse proxy, containerized Velociraptor, Puppet ownership, retry or recovery behavior, backend priority, failover, fan-out, Splunk ingestion, Alert2IR runtime composition, B3-and-later work, or WS10-and-later work. It introduces no Vault, SOPS, HSM, cloud secret manager, general PKI framework, or additional secret-management tooling.

### Fresh B1 server-validation checkpoint

This checkpoint is **FRESH B1 COMPLETE / FRESH B2 NOT YET PERFORMED**. At this checkpoint, the exact reviewed fresh server package was installed and validated on `ir-core`; `win11-02` remained completely undeployed; WS09 remained incomplete; and no live Velociraptor collection had run.

#### Installed package, binary, and configuration identities

| Item | Validated identity |
| --- | --- |
| Fresh Debian package | `velociraptor-server-0.77.2.amd64.deb`; SHA-256 `e7afff45864c2dc600dc53656df6b95583ae74c99868dc0f6c56cdc130de03b1`; 30485672 bytes |
| Installed package | `velociraptor-server`; `install ok installed`; version `0.77.2`; architecture `amd64` |
| Installed binary | `/usr/local/bin/velociraptor`; SHA-256 `6c4c23c466d892788ff56ddcd3a31f844e4c0d797ade454c5e2625eb9e427077`; 85616152 bytes; mode `0755`; `root:root` |
| Installed binary capabilities | `cap_net_bind_service,cap_sys_resource=eip` |
| Installed package-realized server configuration | `/etc/velociraptor/server.config.yaml`; SHA-256 `1d1711837a92e1c9f16ee3f890abae94a27fbc140407f5d95d33025fd0ca2a21`; 12814 bytes; mode `0600`; `velociraptor:velociraptor` |
| Prepared fresh server configuration | SHA-256 `cb0b51234713c09d0139a81d05033faf66eea76666feb5464399375e23f2f9d7`; 12722 bytes |

The installed configuration exactly equals the fresh Debian-package payload identity, not the prepared generation-input identity. This is the expected v0.77.2 package realization described in the artifact-generation checkpoint. No server-configuration contents or private material are recorded.

#### Service and runtime validation

| Item | Validated state |
| --- | --- |
| Unit | `velociraptor_server.service` |
| Service state | active and enabled |
| Service user/group | `velociraptor:velociraptor` |
| Runtime | Velociraptor `0.77.2`; commit `c0c9dd609` |

The validated logical command is:

```text
/usr/local/bin/velociraptor \
  --config /etc/velociraptor/server.config.yaml \
  frontend
```

No transient process ID is canonical provenance.

#### Listener and bind validation

| Surface | Validated local listener |
| --- | --- |
| Frontend | `192.168.56.63:8443` |
| gRPC API | `192.168.56.63:8001` |
| GUI | `127.0.0.1:8889` |
| Monitoring | `127.0.0.1:8003` |

WS09 local binds were validated absent on `0.0.0.0`, `[::]`, and the NAT-side address `10.0.2.15`. A remote-peer wildcard column such as `0.0.0.0:*` in `ss` output was not interpreted as a local listener bind.

#### Network validation

| Source | Target | Result |
| --- | --- | --- |
| `ir-core` | `192.168.56.63:8443` | reachable |
| `ir-core` | `192.168.56.63:8001` | reachable |
| `ir-core` | `127.0.0.1:8889` | reachable |
| `ir-core` | `127.0.0.1:8003` | reachable |
| `ir-core` | `10.0.2.15:8443` | not reachable |
| `ir-core` | `10.0.2.15:8001` | not reachable |
| `ir-core` | `10.0.2.15:8889` | not reachable |
| `ir-core` | `10.0.2.15:8003` | not reachable |
| `win11-02` | `192.168.56.63:8443` | reachable |
| `win11-02` | `192.168.56.63:8001` | reachable |
| `win11-02` | `192.168.56.63:8889` | not reachable |
| `win11-02` | `192.168.56.63:8003` | not reachable |

These results preserve the accepted owned-lab exposure model. They introduce no firewall or TLS-hardening change.

#### Datastore realization

`/opt/velociraptor` exists as a directory owned by `velociraptor:velociraptor` with mode `0755`. No datastore contents are documented.

#### Fresh B1 completion and client boundary

Fresh B1 is complete because the exact reviewed package was installed; the installed binary identity passed; the installed configuration equaled the fresh package-realized configuration; the service was active and enabled under the low-privilege `velociraptor` identity; the runtime release, exact listener containment, and datastore path passed; local and `win11-02` network checks passed; `win11-02` remained undeployed; and Git remained canonical and clean.

After fresh B1 validation, `win11-02` still has no Velociraptor service, process, MSI registration, install directory, WS09 staging, client ID, or mapping. Fresh B1 therefore does **not** establish B2 completion, client enrollment, a usable live backend, an API identity, or proven collection capability.

#### Fresh B2 next-slice boundary

The next separately authorized WS09 slice is fresh B2: `win11-02` client installation and first enrollment. Its initial gates are:

1. Recheck the fresh repacked MSI provenance.
2. Administratively extract the repacked MSI and prove the embedded `Velociraptor.exe` SHA-256, version, Authenticode status, and signer without installing the product.
3. Confirm that extraction did not install the product.
4. Install the exact validated MSI.
5. Validate the service, executable, and configuration.
6. Validate frontend reachability and first enrollment.
7. Record the exact observed `C.<client-id>` and evaluate this exact mapping candidate:

   ```text
   "win11-02" -> "C.<observed-id>"
   ```

At Fresh B1 closure, none of these fresh B2 actions had occurred. Fresh B2 includes no B3 action, API identity, credential, ACL, or collection.

This checkpoint changes none of `win11-01`, `ir-core` capacity, the host firewall, Windows Firewall, Defender, Sysmon, Splunk Forwarder, Puppet, custom TLS, reverse-proxy behavior, container ownership, organization scope, GUI users, API identities or credentials, ACLs, collection state, retry or recovery behavior, backend priority, failover, fan-out, Splunk ingestion, Alert2IR runtime composition, or WS10-and-later work.

### Fresh B2 client-installation and identity-validation checkpoint

This checkpoint is **FRESH B2 COMPLETE / B3 NOT YET PERFORMED**. At this checkpoint, the exact reviewed fresh client package was installed and validated on `win11-02`; the endpoint's physical and live server identities were proven; the architect accepted the exact lab mapping; WS09 remained incomplete; Alert2IR runtime composition remained the deterministic `MockBackend`; and no live Velociraptor investigation collection had run.

#### Fresh repacked MSI provenance and non-installing extraction

| Item | Validated identity or result |
| --- | --- |
| Fresh repacked MSI | `velociraptor-v0.77.2-win11-02-repacked.msi`; SHA-256 `0485a9c7ec649440eabf650b8a7bcf33fb24b60d6bfe1a826b4aa28560bf002d`; 27537408 bytes |
| Source validation | Identity passed on `ir-core` |
| Transfer | `scp -3` through `dev01` succeeded without a persistent `dev01` copy |
| Windows validation | Transferred MSI SHA-256 and size matched the reviewed source |
| Administrative extraction | `msiexec /a` exited `0` |
| Extraction boundary | Administrative extraction did not install the product, create the service, start a process, register the MSI, or create `C:\Program Files\Velociraptor` |

The administrative extraction was performed only to prove the repacked payload before installation. No sensitive embedded client-configuration contents are recorded.

#### Embedded and installed executable proof

| Property | Validated value |
| --- | --- |
| Executable | `Velociraptor.exe` |
| SHA-256 | `686E4F5888FDD66D07ACE3B6C1CBD7D2DD0D8D5FB4D3B5D905A7DF3341DFB86F` |
| Size | 70499832 bytes |
| File version | `0.77.2.0` |
| Product version | `0.77.2.0` |
| Authenticode | Valid |
| Signer | `Rapid7 LLC` |
| Signer thumbprint | `8DD67269B148092AC5A14A4982C920C9FDCA3B91` |

Administrative extraction proved this embedded executable identity before installation. The independently validated installed executable matched it exactly.

#### MSI installation and service identity

The exact validated MSI installation exited `0`. It required no retry, repair, or reboot.

| Item | Validated state |
| --- | --- |
| Product | `Velociraptor` |
| Version | `0.77.2` |
| Publisher | `Velocidex` |
| Product code | `{2154C220-4579-49B7-A616-249C6494865F}` |
| Service name | `Velociraptor` |
| Service state | Running |
| Startup | Automatic |
| Service identity | `LocalSystem` |

No transient process ID is canonical provenance. The service-path representation containing `Velociraptor\/client.config.yaml` was proven to resolve to the intended installed client configuration and is not a B2 failure.

#### Installed client-configuration provenance

| Representation | SHA-256 | Size |
| --- | --- | ---: |
| Reviewed fresh source client configuration | `5eaae96c06aec022e5d4add8c7076b9676a5c718854cb72595d7aa64767516cb` | 2691 bytes |
| Installed/repacked payload representation | `8d26990c605e72b8ed4368510db6ad216afcff0739a68c9a7f95425dce4549d0` | 23898 bytes |

The administratively extracted repacked payload and installed `client.config.yaml` were byte-for-byte identical. The SHA-256 of exactly the first 2691 bytes of the installed/repacked representation equals the reviewed fresh source client-configuration hash. The full 23898-byte representation parses successfully when invoked with correct command-line argument handling; it is not characterized as malformed.

Sanitized validation passed for the approved server URL `https://192.168.56.63:8443/`, self-signed setting, `$ProgramFiles\Velociraptor\velociraptor.writeback.yaml` writeback path, nonce presence, and CA presence. No nonce value, CA contents, PEM, private key, full configuration, or other secret-bearing configuration material is recorded.

#### Writeback identity and frontend transport

The primary and backup writeback files exist, and the client writeback identity initialized after installation. Neither writeback was read, copied, rekeyed, deleted, or exposed. Mutable writeback timestamps and sizes are not canonical provenance.

Frontend TCP validation to `192.168.56.63:8443` passed, and the installed service owned an established connection to that frontend. No client restart, reinstall, repair, rekey, configuration replacement, or writeback change was required. After accepted B2 validation, the transferred MSI's identity was rechecked and the dedicated temporary Windows B2 staging directory was removed; the installed product, configuration, and writebacks remain intact.

#### Physical client identity proof

The exact server-side cryptographic client ID is:

```text
C.4c0d758c0344d6b5
```

An already-existing `Generic.Client.Info` `BasicInformation` result was read directly from the server filestore without recollection. It reported only these accepted identity fields:

| Field | Observed value |
| --- | --- |
| Hostname | `win11-02` |
| OS | `windows` |
| Architecture | `amd64` |
| Platform | `Microsoft Windows 11 Enterprise Evaluation` |
| PlatformVersion | `25H2` |
| Fqdn | `win11-02` |

This existing physical result associates the server-side cryptographic client ID `C.4c0d758c0344d6b5` with `win11-02`. No MAC address or unrelated endpoint information is recorded.

#### Live server identity proof

The running Velociraptor GUI independently resolved both the exact client-ID search `C.4c0d758c0344d6b5` and the hostname search `host:win11-02` to the same client. Host Information displayed:

| Field | Observed value |
| --- | --- |
| Client ID | `C.4c0d758c0344d6b5` |
| Hostname | `win11-02` |
| Operating system | `windows` |
| Agent version | `0.77.2` |
| State | Connected |

The running server's Debug Console Notifier also showed `C.4c0d758c0344d6b5 / win11-02` directly connected in the root organization. No Interrogate, Collect, Hunt, VFS refresh, or other state-changing GUI action was performed.

#### Diagnostic chronology and accepted live-context boundary

Fresh B2 diagnosis initially observed zero rows from standalone command-line `clients()` enumeration, indexed search, direct-ID lookup, `client_info()`, `flows()`, and logical `source()` access even while TCP and application-level frontend connectivity were present. Bounded manual client and foreground-frontend diagnostics, read-only datastore inspection, and snapshot-loader inspection preserved this failure evidence rather than rewriting it as a successful standalone lookup.

Physical filestore inspection subsequently proved the existing `BasicInformation` endpoint identity. The client-info snapshot contained one structurally valid compact JSON record for `C.4c0d758c0344d6b5`; its opaque `info` representation was valid even-length hex and decoded successfully, and a verbose standalone loader reported loading one snapshot record without an error or warning. The standalone command-line lookup nevertheless remained empty. The architect accepted this as a non-blocking, context-specific standalone CLI diagnostic anomaly because the running server GUI resolved the exact client by ID and hostname and the live Notifier proved the same ID directly connected. No index rebuild, snapshot edit, client creation, reinterrogation, or recollection was performed. The separately authorized foreground-frontend trace temporarily stopped and restored the normal systemd frontend without changing server configuration, datastore state, or trust material.

#### Accepted exact mapping and B2 boundary

The architect-accepted exact lab mapping is:

```text
"win11-02" -> "C.4c0d758c0344d6b5"
```

Fresh B2 is complete because MSI provenance passed; non-installing extraction proved the embedded executable; installation, registration, service, executable, configuration, writeback, and frontend transport validation passed; physical `BasicInformation` proved the endpoint identity; the live GUI resolved the client by exact ID and hostname; the live Notifier proved direct connection; temporary B2 staging cleanup passed; and Git remained canonical and clean.

At Fresh B2 closure, this mapping was a validated lab fact but was not yet implemented in Alert2IR runtime configuration. B3 had not been performed or authorized: there was no API identity or credential, no target ACL or effective-ACL proof, no certificate-authenticated API validation, and no collection. B3 was subsequently authorized and completed as recorded in the next checkpoint. WS09 remained incomplete at Fresh B2 closure.

### Fresh B3 minimum API identity and ACL validation checkpoint

This checkpoint is **B3 MINIMUM API IDENTITY AND ACL PROOF COMPLETE / FIRST INVESTIGATION COLLECTION NOT YET PERFORMED**. At this checkpoint, one dedicated certificate-authenticated API principal had the minimum measured Velociraptor permissions for the initial WS09 backend contract; the live gRPC API resolved the accepted client mapping; no live Velociraptor investigation collection had run; Alert2IR runtime composition remained the deterministic `MockBackend`; and WS09 remained incomplete.

#### Dedicated API identity and credential provenance

| Item | Validated identity or result |
| --- | --- |
| Principal | `Alert2IRWS09` |
| Credential form | Certificate-authenticated Velociraptor API configuration |
| Connection target | `192.168.56.63:8001` |
| Protected external path | `/home/jgipsz/velociraptor-bootstrap/v0.77.2/Alert2IRWS09.api.config.yaml` on `ir-core`, outside the repository |
| API configuration SHA-256 | `485bc8c1c4d39d059fe9009a81c4c86ce888a4c3364b75ae64a8075331459422` |
| Size | 4333 bytes |
| Mode | `0600` |
| Owner/group | `jgipsz:jgipsz` |

The API configuration is secret-bearing because it contains certificate and private-key material. Exactly one protected API configuration is retained outside Git. No API configuration contents, PEM bodies, certificate material, or private keys are stored or documented in the repository.

#### Version-exact API-role baseline and final ACL

The API-role baseline was measured from the installed Velociraptor `0.77.2` binary rather than assumed from documentation. Immediately after identity generation, the stored role set contained only `api`, and that role contributed exactly these effective TRUE permissions in this deployment:

```text
ANY_QUERY
READ_RESULTS
```

This is the observed v0.77.2 baseline for this deployment, not a permanent guarantee for other Velociraptor versions.

The dedicated principal then received only the authorized explicit backend permissions `READ_RESULTS` and `COLLECT_CLIENT` through ACL merge semantics. No additional role was granted. The persisted final policy is:

```text
roles: api only
read_results: true
collect_client: true
```

The complete final effective TRUE permission set, verified both before and after the controlled restart, is:

```text
ANY_QUERY
READ_RESULTS
COLLECT_CLIENT
```

No additional TRUE permission or administrator-equivalent expansion was observed.

#### Controlled restart and client continuity

Exactly one controlled `velociraptor_server.service` restart occurred after the CLI ACL changes. The restart succeeded; the service returned active and enabled as `velociraptor:velociraptor`; and the exact listener set remained:

| Surface | Preserved listener |
| --- | --- |
| Frontend | `192.168.56.63:8443` |
| gRPC API | `192.168.56.63:8001` |
| GUI | `127.0.0.1:8889` |
| Monitoring | `127.0.0.1:8003` |

No second recovery restart was required. The `win11-02` Velociraptor service remained running as `LocalSystem` with automatic startup throughout, and its service-owned frontend connection recovered successfully. No transient process ID is canonical provenance.

#### Certificate-authenticated live API proof

The built-in Velociraptor client was invoked with `--api_config` and the dedicated `Alert2IRWS09` API configuration. It did not use the privileged server configuration for this proof. The only API operation was a non-mutating query that projected exactly these fields and returned exactly one row:

| Field | API-visible value |
| --- | --- |
| `client_id` | `C.4c0d758c0344d6b5` |
| `hostname` | `win11-02` |
| `system` | `windows` |

This proves that certificate authentication succeeds, gRPC API connectivity succeeds, the minimum API query and `READ_RESULTS` authorization succeeds, and the accepted exact mapping is visible through the integration path that WS09 intends to use. No raw API request or response beyond those projected fields is documented.

#### Standalone execution-context disposition

The historical B2 diagnostic fact remains: standalone server-context CLI `clients()` queries returned zero rows even while the running server knew the client. The decisive B3 observation is that certificate-authenticated `--api_config` execution in the live server context correctly returned `C.4c0d758c0344d6b5 / win11-02 / windows`.

The architect disposition is that the visibility discrepancy is isolated to the standalone execution context and requires no WS09 repair. No client-info or index repair is roadmap-required unless a future actual integration path reproduces a related defect. No speculative root cause is assigned.

#### Least-privilege and authorization boundary

The approved B3 identity has the `api` role plus `READ_RESULTS` and `COLLECT_CLIENT` for the initial WS09 backend contract. `READ_RESULTS` is organization-scoped in the root organization; Velociraptor ACLs do not restrict it to only client `C.4c0d758c0344d6b5`. Therefore the accepted exact mapping:

```text
"win11-02" -> "C.4c0d758c0344d6b5"
```

remains an Alert2IR application-routing boundary rather than a per-client Velociraptor authorization boundary. B3 introduces no generalized authorization framework.

#### No-collection and credential-retention boundary

B3 performed identity creation, ACL configuration, stored and effective ACL validation, and one non-mutating certificate-authenticated API query. It performed no client artifact collection, `Windows.System.Pslist`, `collect_client()` call, hunt, interrogation, or new investigation flow. Automatic platform or client-monitoring activity is not the WS09 investigation collection proof.

Exactly one protected API configuration is retained outside Git. B3 introduces no Vault, SOPS, HSM, cloud secret manager, generic credential broker, or generic PKI framework. `pyvelociraptor` is not installed. Runtime credential injection and dependency selection remain part of a later implementation slice.

#### Next collection slice and broader non-goals

The next separately authorized WS09 action is the first real investigation collection proof:

| Contract field | Approved value |
| --- | --- |
| Capability | `process.list` |
| Backend-private artifact | `Windows.System.Pslist` |
| Target | `C.4c0d758c0344d6b5` |
| Desired outcome | Collect process inventory |

That collection must use the dedicated certificate-authenticated API identity and the accepted exact host-to-client mapping. It was not executed in B3 and is not authorized by this documentation checkpoint. The future collection proof does not itself authorize generalized runtime composition, retries, queues, failover, fan-out, additional capabilities, or a generalized authorization or credential-management framework.

B3 changes none of `win11-01`, `ir-core` capacity, the accepted firewall boundary, Defender, Sysmon, Splunk Forwarder, Puppet, TLS or reverse-proxy behavior, organization scope, backend priority, failover, fan-out, Splunk ingestion, persistence, or WS10-and-later work. No investigation collection ran during B3.

### First live `process.list` investigation collection proof

This checkpoint is **FIRST LIVE `process.list` INVESTIGATION COLLECTION PROOF COMPLETE / ALERT2IR LIVE BACKEND RUNTIME IMPLEMENTATION NOT YET PERFORMED**. At this checkpoint, it proved the external Velociraptor capability substrate for the existing narrow backend contract; Alert2IR runtime composition remained the deterministic `MockBackend`; and WS09 remained incomplete.

#### Collection contract and scheduling provenance

The exact collection contract was:

| Contract field | Validated value |
| --- | --- |
| Canonical capability | `process.list` |
| Desired outcome | `collect process inventory` |
| Backend-private Velociraptor artifact | `Windows.System.Pslist` |
| Exact endpoint mapping | `"win11-02" -> "C.4c0d758c0344d6b5"` |
| API identity | `Alert2IRWS09` |
| Collection timeout | 60 seconds |

No environment override, artifact-spec override, urgency override, row-limit override, byte-limit override, or retry was used.

Exactly one `collect_client()` operation was executed through the dedicated certificate-authenticated `Alert2IRWS09` API identity. It returned collection reference `F.D9VKVH7ES21BA` for client `C.4c0d758c0344d6b5` and artifact `Windows.System.Pslist`.

#### Terminal flow and result-read proof

Read-only revalidation through the dedicated API configuration established:

| Flow property | Validated value |
| --- | --- |
| Flow | `F.D9VKVH7ES21BA` |
| Client | `C.4c0d758c0344d6b5` |
| Creator | `Alert2IRWS09` |
| State | `FINISHED` |
| Status | no error / empty status |
| Requested artifact | `Windows.System.Pslist` only |
| Artifact with results | `Windows.System.Pslist` only |
| Total collected rows | 157 |
| Uploaded files | 0 |
| Uploaded bytes | 0 |

Flow results were read through the same dedicated certificate-authenticated API identity. The process-result count was exactly 157, and a bounded one-row projection of only `Pid`, `Ppid`, and `Name` proved process-inventory shape and readability. A `Velociraptor.exe` process name was also present as a bounded sanity observation. No process-table sample or general process inventory is retained in Git; the process data remains lab evidence rather than repository fixture data.

#### Exactly-one-collection proof

Before the proof, zero `Alert2IRWS09` flows requesting `Windows.System.Pslist` existed for the target. After the proof, exactly one matching flow existed: `F.D9VKVH7ES21BA`.

The proof created no retry, second flow, other-artifact collection, other-client collection, hunt, interrogation, or server-artifact flow. The successful flow is intentionally retained as lab evidence and was not deleted or altered.

#### Evidence-reference interpretation

`F.D9VKVH7ES21BA` is the historical lab collection reference proving the existing `VelociraptorBackend` collection-reference contract. It maps conceptually to the existing canonical result shape:

```text
EvidenceReference:
  kind = "collection"
  reference = "F.D9VKVH7ES21BA"
```

This flow ID is not runtime configuration and must never be hard-coded into the backend. For each future live investigation, the backend must return the fresh collection or flow ID produced by that execution.

#### Capability proof and runtime implementation boundary

The live lab now proves all underlying Velociraptor operations required by the already-implemented backend contract:

- the exact host-to-client routing fact exists;
- certificate-authenticated API access works;
- the minimum collection and result-read ACL works;
- `Windows.System.Pslist` can be scheduled;
- one exact client flow is returned;
- the flow reaches successful completion;
- process results are readable; and
- the flow ID provides the collection evidence reference.

This proves the external capability substrate. It does not prove that the Python `VelociraptorBackend` implementation performs these operations.

The next implementation work must bridge the existing narrow backend protocol to the now-proven Velociraptor API operations without broadening the architecture. The contract remains:

```text
capability: process.list only
desired outcome: collect process inventory
target: one host
exact host mapping: "win11-02" -> "C.4c0d758c0344d6b5"
private artifact: Windows.System.Pslist
result: existing InvestigationResult
evidence: one EvidenceReference(kind="collection", reference=<fresh flow ID>)
```

No lifecycle or status model, retry, recovery, queue, priority, failover, fan-out, multiple artifacts, hostname discovery, client normalization, metadata bags, or new canonical model fields are added.

#### Dependency, ACL, credential, and non-goal boundaries

The live API protocol is now established. This documentation slice neither installs nor pins `pyvelociraptor`; dependency and client-library selection must be reviewed in the next implementation-preparation slice. That review must first identify the narrowest supported implementation of the proven API operations and must not assume that `pyvelociraptor` is required or introduce a generalized dependency-management redesign.

The B3 ACL and credential boundary is unchanged. Principal `Alert2IRWS09` retains the `api` role with stored `read_results=true` and `collect_client=true`; its complete effective TRUE permission set remains exactly `ANY_QUERY`, `READ_RESULTS`, and `COLLECT_CLIENT`. The protected API configuration remains outside Git, no credential content enters repository configuration, and the collection proof caused no permission broadening.

No change was made to `win11-01`, `ir-core` capacity, firewalls, Defender, Sysmon, Splunk Forwarder, Puppet, TLS or reverse-proxy behavior, additional organizations, backend priority, failover, fan-out, Splunk ingestion, persistence, or WS10-and-later work. No second collection was executed.

### WS09 trust-material exposure and rebootstrap decision

The following subsections preserve the retired deployment and remediation-decision chronology. Statements about containment, installation, or generated artifacts in that chronology describe the observed state at the cited historical checkpoint; the current state is the completed WS09 application E2E checkpoint above.

#### Sanitized exposure chronology and containment

During B2 enrollment diagnosis, a failed filtering command emitted the secret-bearing installed Velociraptor server configuration into the operator terminal and diagnostic conversation. No secret value is reproduced in this repository. The configuration was not committed to Git, and Git did not contain the exposed material, but terminal or conversation exposure is sufficient to treat the affected trust material as compromised.

At the containment checkpoint, the affected services were deliberately contained pending separately authorized teardown and redeployment:

- `velociraptor_server.service` on `ir-core` is inactive and disabled, with no listeners on TCP/8443, TCP/8001, TCP/8889, or TCP/8003.
- The `Velociraptor` service on `win11-02` is stopped and disabled.

This documentation slice neither deletes the compromised artifacts nor changes package, datastore, client writeback, configuration, certificate, or service state.

#### Retired trust-material boundary

The generated server configuration contains the Velociraptor internal PKI and trust material, including the internal CA trust root. The architect decision is:

```text
current WS09 Velociraptor trust root:
RETIRED / NOT ACCEPTABLE FOR FURTHER VALIDATION
```

The following artifacts derive from that retired trust root and must not be reused for the resumed WS09 proof:

```text
current server.config.yaml
current generated server Debian package
current root client configuration
current repacked win11-02 MSI
```

Their previously recorded hashes remain historical provenance only. The artifacts are not deleted by this decision record.

Ordinary server-certificate or key rotation is insufficient because the exposure includes the internal CA trust root. WS09 will therefore not remediate this incident merely with:

```text
config reissue_certs
config rotate_keys
```

The remediation target is a newly generated Velociraptor configuration with a fresh internal CA. Generation, teardown, and redeployment remain separately gated and are not performed by this documentation slice.

#### Bounded redeployment consequence and preserved validation

Replacing the internal CA changes the CA certificate embedded in client configurations, so the affected client deployment must also be replaced. The impact remains bounded to `ir-core` and `win11-02`: `win11-01` remains out of scope, no API identity was created, no collection completed, and no canonical `C.<client-id>` mapping was established. This does not justify a production-fleet migration, generalized certificate-rotation framework, or additional endpoint.

B1 still functionally established the native Debian/systemd installation model, package-realized configuration behavior, low-privilege service identity, listener bindings, and lab-network reachability. Those observations remain useful architectural and lab evidence; B1 did happen and its historical functional validation remains complete. The specific cryptographic material used for that B1 instance is retired and cannot serve as the final WS09 validation substrate.

#### Fresh-PKI rebootstrap strategy

The approved rebootstrap strategy is:

```text
reuse already-verified public Velociraptor v0.77.2 release artifacts

generate entirely fresh server configuration / internal CA

retain the same approved non-secret deployment decisions:
  ir-core
  192.168.56.63:8443 frontend
  192.168.56.63:8001 API
  127.0.0.1:8889 GUI
  127.0.0.1:8003 monitoring
  /opt/velociraptor datastore
  native Debian/systemd
  win11-02 only

generate fresh:
  server package
  root client config
  repacked win11-02 MSI

redeploy:
  server
  win11-02 client

then repeat:
  B1 server identity/listener validation
  B2 enrollment/client-ID validation
```

No public-release redownload is required unless an already-pinned public artifact fails its recorded hash gate. Because no useful client enrollment, collection, API identity, mapping, or WS09 datastore evidence exists, the preferred remediation is a clean lab redeployment rather than preservation of the compromised PKI deployment. Exact destructive cleanup commands remain separately gated; no teardown is performed here.

#### Secret-handling boundary and non-goals

Future diagnostic commands must never emit unfiltered `config show` output containing secret values. Immediate in-memory sanitized projection, presence checks, and one-way hashes remain the inspection model. This narrow handling improvement does not introduce Vault, SOPS, cloud or commercial secret management, an HSM, generic PKI automation, or other generalized secret-management infrastructure.

The rebootstrap decision also does not introduce `win11-01`, larger `ir-core` capacity, a host firewall, custom browser TLS, containerized Velociraptor, Puppet ownership, retry or recovery infrastructure, backend priority, failover, fan-out, Splunk ingestion, Alert2IR runtime composition, or WS10-and-later work.

### Approved release, placement, and proof boundary

| Item | Approved value |
| --- | --- |
| Velociraptor release | `v0.77.2` |
| Release commit recorded by discovery | `c0c9dd609140139efcb37c47e2afa79ed57e6c84` |
| Linux AMD64 artifact | `velociraptor-v0.77.2-linux-amd64` |
| Linux SHA-256 | `6c4c23c466d892788ff56ddcd3a31f844e4c0d797ade454c5e2625eb9e427077` |
| Generated Debian package | `velociraptor-server-0.77.2.amd64.deb` |
| Generated Debian package SHA-256 | `e0ee2902ec134032f03e85366a614187aac8c74c430d4fb6975746b71b8f0326` |
| Windows AMD64 MSI | `velociraptor-v0.77.2-windows-amd64.msi` |
| MSI SHA-256 | `7965d63d7c7434db425dba9dc7430f3e12c60e914017da9ac3617d0f3c9991e9` |
| GPG verification fingerprint | `0572 F28B 4EF1 9A04 3F4C BBE0 B22A 7FB1 9CB6 CFA1` |

The pinned public release artifacts remain reusable subject to their existing hash and signature gates. The generated Debian package in this table belongs to the retired trust root; its hash is historical provenance only and is not an approved fresh-PKI redeployment artifact.

The retired server package was installed on `ir-core` (`192.168.56.63`) under the approved native generated Debian package and systemd deployment model. It has since been purged, and the fresh package has not been installed. Velociraptor is not part of Alert2IR Compose and is not owned by Puppet. The sole initial endpoint remains `win11-02` (`192.168.56.62`); `win11-01` is outside this deployment slice. The only initial capability is `process.list`, privately realized by the backend with `Windows.System.Pslist`. No custom artifact or additional investigation capability is approved.

Discovery recorded `ir-core` as Ubuntu 24.04.4 LTS on `amd64`, with 1 vCPU, 3.8 GiB RAM, 3.8 GiB swap, and approximately 38 GiB free on the root filesystem. This is accepted only for the narrow WS09 lab proof: one server, one connected endpoint, and one process-list collection. It is not a production-sizing claim.

### Server configuration provenance and package realization

The three sanitized configuration identities are:

| Configuration stage | SHA-256 | Size | Provenance role |
| --- | --- | ---: | --- |
| Prepared source `server.config.yaml` | `88dc03cf978efa7bed86c74d5a36dc880ceeccc674d23cac63ecd7098a873a19` | 12714 bytes | Direct output of the reviewed `config generate` step; package-generation input provenance |
| Debian-package payload `server.config.yaml` | `0f8118bc192b0549c2370915a349b3e5e70a2113bc6e30274f1df98d361230bf` | 12806 bytes | Package-realized installation provenance |
| Installed `/etc/velociraptor/server.config.yaml` | `0f8118bc192b0549c2370915a349b3e5e70a2113bc6e30274f1df98d361230bf` | 12806 bytes | Installed-file identity |

Following the trust-material retirement decision, these identities document only the historical B1 instance. They must not be used as acceptance gates for the fresh-PKI rebootstrap.

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

Final B1 validation after the successful service re-enable reconfirmed `/etc/velociraptor/server.config.yaml` at the same package-realized SHA-256. The installed file is mode `0600`, owned by `velociraptor:velociraptor`, and is 12806 bytes. No configuration contents or private material are recorded.

### B1 completed server validation

| Item | Observed fact |
| --- | --- |
| Installed package | `velociraptor-server` |
| Package status | `install ok installed` |
| Package version | `0.77.2` |
| Package architecture | `amd64` |
| Installed binary | `/usr/local/bin/velociraptor` |
| Installed binary SHA-256 | `6c4c23c466d892788ff56ddcd3a31f844e4c0d797ade454c5e2625eb9e427077`; exact pinned upstream Linux binary |
| Binary mode, owner/group, and size | `0755`, `root:root`, 85616152 bytes |
| Binary capabilities | `cap_net_bind_service,cap_sys_resource=eip` |
| Binary version provenance | version `0.77.2`; commit `c0c9dd609`; system `linux`; architecture `amd64` |
| systemd unit | `velociraptor_server.service` |
| Service state | active and enabled |
| Service user and group | user `velociraptor`; group `velociraptor` |
| Executable, configuration, and mode | `/usr/local/bin/velociraptor`; `/etc/velociraptor/server.config.yaml`; `frontend` |

The installed package remains the exact reviewed Phase A package; final B1 validation did not reinstall it.

The active/enabled service-state row is a historical B1 observation. Current containment has the server service inactive and disabled with the WS09 listeners absent.

The observed process command was:

```text
/usr/local/bin/velociraptor --config /etc/velociraptor/server.config.yaml frontend
```

Runtime-ephemeral process IDs are not canonical evidence.

#### Final listener and local reachability validation

Final B1 validation established exactly these listener bindings:

| Surface | Validated listener | Interpretation |
| --- | --- | --- |
| Client frontend | `192.168.56.63:8443` | Host-only `ir-core` address |
| gRPC API | `192.168.56.63:8001` | Host-only `ir-core` address |
| GUI | `127.0.0.1:8889` | Loopback-only |
| Monitoring | `127.0.0.1:8003` | Loopback-only |

No approved service was observed bound to `0.0.0.0` or `[::]`. The `0.0.0.0:*` remote-peer column displayed by `ss` was not interpreted as a local listener address. Local address-specific TCP validation produced:

| Address | Result |
| --- | --- |
| `192.168.56.63:8443` | reachable |
| `192.168.56.63:8001` | reachable |
| `127.0.0.1:8889` | reachable |
| `127.0.0.1:8003` | reachable |
| `10.0.2.15:8443` | not reachable |
| `10.0.2.15:8001` | not reachable |
| `10.0.2.15:8889` | not reachable |
| `10.0.2.15:8003` | not reachable |

These are lab validation observations, not general network guarantees.

From `win11-02`, source address `192.168.56.62`, TCP/8443 and TCP/8001 on `192.168.56.63` were reachable; TCP/8889 and TCP/8003 were not reachable. TCP/8001 reachability does not establish authenticated API access. Certificate and effective-ACL validation remain B3 responsibilities.

At B1 closure, `win11-02` had zero Velociraptor services, no `C:\Program Files\Velociraptor` directory, and zero Velociraptor uninstall registrations. B1 therefore neither installed nor enrolled the endpoint, and no client ID is claimed.

No host firewall was enabled or modified during B1. Frontend/API reachability across the owned host-only lab network remains an accepted WS09 lab limitation; listener containment passed independently of firewalling. GUI and monitoring remain loopback-only, and no custom TLS infrastructure is introduced.

#### B1 chronology

1. The reviewed server package was installed.
2. First start established the intended listeners and service identity.
3. The obsolete pre-package-config hash gate caused deliberate service containment for architect review; this was not a server failure.
4. Diagnosis established the Debian-package transformation `Frontend.run_as_user = velociraptor`.
5. Git documented and accepted the package-realized config identity.
6. The service was re-enabled.
7. Final package, binary, config, process, listener, local-network, and `win11-02` reachability validation passed.
8. B1 completed.

### B2 partial state and resumed proof boundary

B2 is incomplete. The historical `win11-02` MSI installation succeeded; the installed executable identity and Authenticode signature passed; and service installation and initial running/automatic state passed. Enrollment was not established, repeated read-only root-organization queries returned no clients, and no `C.<client-id>` was observed. The retired client was first stopped and disabled and was later completely removed during teardown; the fresh client has not been installed.

The enrollment root cause remains unresolved. The secret exposure did not cause the already-observed enrollment failure; these are separate facts. Continuing to debug enrollment against the retired trust material is no longer useful. The resumed fresh-PKI proof must repeat the complete boundary:

```text
repacked MSI transfer
-> exact MSI SHA verification
-> administrative extraction
-> exact embedded Velociraptor.exe SHA equality
-> valid Rapid7 LLC Authenticode
-> MSI installation
-> service verification
-> first enrollment
-> observe exact C.<client-id>
-> STOP
```

The former repacked MSI SHA-256 `9e3dd27587bba3116f5af81ce761b084cb94ced0fec360444cbf8f98b61ffe82` is historical provenance for an artifact derived from the retired trust root and must not be reused. The previously verified official embedded `Velociraptor.exe` identity remains SHA-256 `686E4F5888FDD66D07ACE3B6C1CBD7D2DD0D8D5FB4D3B5D905A7DF3341DFB86F`, version `0.77.2.0`, signed by `Rapid7 LLC`.

### Intended network bindings and accepted lab exposure

| Surface | Intended binding | Boundary |
| --- | --- | --- |
| Client frontend | `192.168.56.63:8443` | Host-only endpoint path |
| gRPC API | `192.168.56.63:8001` | Alert2IR runtime path using certificate authentication |
| GUI | `127.0.0.1:8889` | Loopback-only operator access |
| Monitoring, if emitted by generated configuration | `127.0.0.1:8003` | Loopback-only; no monitoring stack is introduced |
| Existing Alert2IR core | `127.0.0.1:8000` | Unchanged |

Final B1 revalidation confirmed these exact bindings. The native frontend and API must remain bound only to `192.168.56.63`, not `0.0.0.0` or the NAT address `10.0.2.15`, unless separately reviewed. The GUI and monitoring surfaces remain loopback-only. No Velociraptor surface may be exposed to a public or Internet network.

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

`Client.use_self_signed_ssl = true` remains required; the frontend must not be changed to clear-text HTTP. The API remains certificate-authenticated gRPC on `192.168.56.63:8001`, not clear text or unauthenticated transport. B3 subsequently validated the dedicated API identity, its stored and effective ACL, and certificate-authenticated access without changing this transport boundary.

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

The B3 checkpoint validated identity `Alert2IRWS09` in the root organization with the `api` role and only the explicit `COLLECT_CLIENT` plus `READ_RESULTS` backend permissions. The measured v0.77.2 API-role baseline was `ANY_QUERY` plus `READ_RESULTS`; the complete final effective TRUE set after merge was exactly `ANY_QUERY`, `READ_RESULTS`, and `COLLECT_CLIENT`. No administrator API identity, additional role, or administrator-equivalent permission expansion was introduced.

Before any real collection, B3 issued the required certificate-authenticated, non-mutating gRPC query for the exact enrolled client ID. The query used the dedicated API configuration rather than the privileged server configuration, scheduled no artifact, and returned `C.4c0d758c0344d6b5 / win11-02 / windows`. Certificate authentication, API connectivity, minimum read authorization, and live-context mapping visibility therefore passed.

At the B3 checkpoint, the completed bootstrap state contained no external Velociraptor dependency. The eventual live adapter could use official `pyvelociraptor`, but it was not installed and no Python dependency pin was authorized in B3. Runtime credential injection, dependency selection, and any dependency-management change remained deferred to a later implementation slice.

### Timeout and effect windows

The validated WS09 timeout is 60 seconds. It is a lab-validation bound only, not a production claim. Successful scheduling followed by timeout may leave an upstream flow that later completes without an Alert2IR processing record. Successful collection followed by PostgreSQL persistence failure may likewise leave an upstream collection without a durable Alert2IR completion row. WS09 adds no retry, cancellation orchestration, recovery, queue, worker, saga, or reconciliation mechanism.

### Teardown, reproducibility, and deferrals

Future bootstrap must be reproducible from the approved release artifacts and hashes while generating all environment-specific configuration, credentials, packages, identities, and datastore state outside Git. Future teardown must deliberately account for only WS09-created service/package state, endpoint client state, generated material, and datastore state. Sanitized validation facts and the exact non-secret client-ID mapping may remain documented; teardown does not create a backup or disaster-recovery design.

This bootstrap does not deploy Velociraptor in a container, assign it to Puppet, enroll a second endpoint, add custom artifacts or capabilities, add public exposure, or introduce a reverse proxy, VPN, service mesh, general secret-management system, monitoring stack, backup/DR design, HA, retries or recovery, queues or workers, backend priority, failover, fan-out, or Splunk ingestion. The separately implemented repository runtime composition and live-only Alert2IR Compose override have since been deployed. Their first end-to-end attempt scheduled a retained flow but failed adapter state validation before durable processing; it therefore does not prove successful Alert2IR runtime execution. The corrected second attempt recorded in the closure checkpoint above supplies that final operational proof.
