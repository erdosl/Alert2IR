# Sysmon telemetry policy

## Purpose and authority

Sysmon provides endpoint activity evidence for investigation and detection validation. It is a collection layer, not the Alert2IR detection model: Sigma rules and target translation belong in [DETECTIONS.md](DETECTIONS.md).

[`config/sysmon/alert2ir-sysmon.xml`](../config/sysmon/alert2ir-sysmon.xml) is the sole Git-tracked configuration authority. The profile is intentionally small, contains no endpoint identities or ATT&CK-specific signatures, and does not vendor third-party XML. This guide explains its current policy; the XML defines exact behavior.

## Collection principles

- Collect activity that provides durable process, connection, file, driver, interprocess, WMI, DNS, and process-tampering context.
- Keep detection logic out of endpoint filters unless a demonstrated collection requirement makes it unavoidable.
- Disable noisy categories explicitly with empty `onmatch="include"` filters rather than relying on omitted elements.
- Add exclusions only for measured, narrowly identified self-observation; never exclude an entire process or path class without evidence.
- Collect deletion metadata without archiving deleted content.
- Measure event volume on the canary before broadening collection.

## Global settings

| Setting | Value | Rationale |
| --- | --- | --- |
| Schema | `4.91` | Matches the reviewed standalone Sysmon configuration contract |
| `HashAlgorithms` | `SHA256` | Provides a single widely supported file identity without multi-hash cost |
| `CheckRevocation` | `true` | Preserves revocation checking during signature inspection |
| `DnsLookup` | `false` | Avoids reverse-DNS enrichment latency and traffic; `DnsQuery` still records names applications request |
| Deleted-file archival | Disabled | The policy needs deletion metadata, not retained deleted content |

## Event policy

| Event IDs | Configuration element | Policy | Purpose |
| ---: | --- | --- | --- |
| 1 | `ProcessCreate` | Enabled | Process lineage, command line, identity, and hashes |
| 3 | `NetworkConnect` | Enabled | Process-associated connection evidence |
| 6 | `DriverLoad` | Enabled | Driver identity, hash, and signature evidence |
| 8 | `CreateRemoteThread` | Enabled | Cross-process thread creation context |
| 9 | `RawAccessRead` | Enabled | Direct raw-device read evidence |
| 11 | `FileCreate` | Enabled with one narrow exception | File creation outside measured Splunk checkpoint churn |
| 15 | `FileCreateStreamHash` | Enabled | Alternate data stream creation and content identity |
| 17–18 | `PipeEvent` | Enabled | Named-pipe creation and connection context |
| 19–21 | `WmiEvent` | Enabled | WMI filter, consumer, and binding registration |
| 22 | `DnsQuery` | Enabled | Application-requested DNS names |
| 25 | `ProcessTampering` | Enabled | Process image manipulation evidence |
| 26 | `FileDeleteDetected` | Enabled with one narrow exception | Deletion metadata without content archival |
| 2, 5, 7, 10, 12–14, 23–24, 27–29 | Corresponding filterable elements | Deferred with empty include filters | Collection value or volume is not yet justified |
| 4, 16 | Sysmon-generated, non-filterable | Observable when emitted | Service-state and configuration-change evidence |

The only current content exception is an exact process-and-path conjunction for Splunk Universal Forwarder's Windows Event Log checkpoint files. It suppresses `splunk-winevtlog.exe` self-observation for file creation/deletion beneath its checkpoint directory. Activity by another process in that path, and Splunk activity elsewhere, remains observable. Re-evaluate the exception if the forwarder layout or collection backend changes.

## Puppet staging boundary

The [Puppet environment](../infra/puppet/README.md) takes the canonical XML from the same reviewed Git revision used to build its artifact and stages it at:

```text
C:\ProgramData\Alert2IR\Sysmon\alert2ir-sysmon.xml
```

Puppet also keeps the already-installed `Sysmon64` service running and enabled. It does not install Sysmon, execute `Sysmon64.exe -c`, compare the staged file with active configuration, restart Sysmon when the file changes, or manage the Operational channel. Equality of staged bytes therefore proves deployment of the reviewed file, not active semantic convergence.

## Validation workflow

### Repository checks

Before endpoint use:

1. parse the canonical XML with a standard XML parser;
2. confirm the root schema and global settings above;
3. compare enabled and deferred elements with the event-policy table;
4. confirm deferred elements contain no child filters;
5. confirm archival settings are absent;
6. inspect the single Splunk checkpoint exception for its exact process-and-path conjunction;
7. run the Puppet repository contract, which proves the artifact contains the exact canonical XML bytes:

   ```bash
   PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
     .venv/bin/python -m unittest -v tests.test_puppet_contract
   ```

### Canary verification

Any active configuration change requires separate authorization and must be evaluated on `win11-02` before promotion:

1. collect the bounded endpoint state described in [WINDOWS_ENDPOINT_INVENTORY.md](WINDOWS_ENDPOINT_INVENTORY.md);
2. verify the copied XML hash against the reviewed repository file and parse the copy;
3. query the active configuration with the explicit installed `Sysmon64.exe -c` path before changing it;
4. if application of the reviewed profile is authorized, pass only the verified XML to `Sysmon64.exe -c` and require a successful exit;
5. query active configuration again and confirm a recent event ID 16, running service, and enabled Operational channel;
6. generate only small benign activity and inspect representative enabled events such as IDs 1, 3, 11, 16, and 22;
7. verify deferred filterable categories do not produce new post-change events without manufacturing destructive or privileged activity;
8. confirm representative Sysmon events arrive through the existing Splunk forwarding path;
9. observe volume over a representative interval before promoting the same reviewed configuration to `win11-01`.

Do not use controlled attack scenarios merely to exercise the Sysmon profile. Detection execution and comparison belong in [DETECTIONS.md](DETECTIONS.md).

## Tuning and rollback

Tuning must start from measured canary evidence. Prefer narrow field conjunctions, preserve investigative context, and record material policy changes in Git. Do not add a broad process exclusion because one event source is noisy.

If Sysmon rejects a profile or the telemetry is operationally unsafe, stop promotion. Roll back only to an explicit reviewed configuration whose bytes are verified, then repeat service, channel, event ID 16, representative-event, and forwarding checks. Do not rely on command history, undocumented endpoint paths, or assumed defaults.

Current limitations and future project work belong in the [roadmap](ROADMAP.md); endpoint roles and forwarding relationships belong in [LAB.md](LAB.md).
