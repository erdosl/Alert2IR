# Sysmon Telemetry

## Purpose

Sysmon provides endpoint evidence for investigation. Its configuration is not the Alert2IR detection layer: Sigma and Splunk will later own detection logic. This initial profile collects useful host activity without embedding signatures, ATT&CK-specific matching, or endpoint identities.

## Ownership

[`config/sysmon/alert2ir-sysmon.xml`](../config/sysmon/alert2ir-sysmon.xml) is an Alert2IR-owned profile and is intentionally small. Its design was informed by Microsoft Sysmon documentation and general design lessons from SwiftOnSecurity's `sysmon-config` and Olaf Hartong's `sysmon-modular`. No third-party rules, comments, or XML configurations are vendored or copied.

The identical schemas captured from both laboratory endpoints report standalone Sysmon 15.21 and configuration schema version `4.91`. Private inventory artifacts remain outside Git.

## Puppet staging boundary

The WS02 Puppet catalog stages the canonical profile at `C:\ProgramData\Alert2IR\Sysmon\alert2ir-sysmon.xml`. Artifact assembly obtains both the Puppet environment and `config/sysmon/alert2ir-sysmon.xml` from the same reviewed Git commit; the module-files copy exists only in the generated deployment artifact.

This managed file is a deployment artifact, not evidence that Sysmon's active configuration matches it. File changes do not invoke `Sysmon64.exe -c` and have no service reload or restart relationship. Active-configuration drift detection and application remain deferred.

## Global settings

- `HashAlgorithms` is `SHA256`, providing a widely supported, collision-resistant file identity without the added cost and volume of calculating several hashes.
- `CheckRevocation` is `true` so signature inspection continues to check whether signing certificates have been revoked.
- `DnsLookup` is `false` to avoid reverse-DNS enrichment, latency, and extra resolver traffic while processing network events. `DnsQuery` remains enabled because the names applications actively query are useful first-party endpoint evidence; it serves a different purpose.
- Deleted-file archival is not enabled. This workstream needs deletion metadata, not preservation of deleted content, so `ArchiveDirectory`, `CopyOnDeletePE`, `CopyOnDeleteSIDs`, `CopyOnDeleteExtensions`, and related archival settings are absent.

## Canary revision

The initial profile was accepted on `win11-02` by Sysmon 15.21 using schema `4.91`, and Sysmon emitted configuration-change event ID 16. The post-change canary interval contained 11,687 registry object create/delete events (ID 12) and 47 registry value-set events (ID 13). Of the ID 12 events, 7,088 were produced by `svchost.exe` CreateKey activity and 4,493 by `powershell.exe` CreateKey activity. These aggregate counts demonstrate that broad `RegistryEvent` collection exceeded the initial volume acceptance threshold; they are not evidence that either process is globally safe, and they do not justify process-wide exclusions.

Process-termination events (ID 5) also continued after the configuration-change event even though `ProcessTerminate` was omitted from the initial XML. Version 0.1 therefore represents every deferred filterable class explicitly with an empty `onmatch="include"` filter. Under Sysmon include semantics, the absence of child matches disables collection for that class. IDs 4 and 16 remain absent because Sysmon does not expose filters for them.

`RegistryEvent` will be reconsidered in a later tuning iteration using narrow `TargetObject` and process evidence. No registry exclusions are introduced in this revision.

A subsequent 15-minute canary measurement on `win11-02`, after `RegistryEvent` was deferred, recorded 884 file-creation events (ID 11) and 884 detected file-deletion events (ID 26) from `splunk-winevtlog.exe` in the Splunk Universal Forwarder's `var\lib\splunk\modinputs\WinEventLog` checkpoint area. Other ID 11 and 26 activity was comparatively small. The profile therefore excludes only this self-observation and checkpoint churn, using an exact process image and beginning-of-target-path conjunction.

The conjunction preserves telemetry when another process modifies Splunk's checkpoint area, while Splunk activity outside that area remains observable. It does not exclude `splunk-winevtlog.exe` or the checkpoint directory globally. The exclusion is specific to the observed `win11-02` canary evidence and must be revisited if the Splunk installation layout or collection backend changes. No exclusion is added for `splunkd.exe` `tracker.log` activity or other observed low-volume activity.

## Event matrix

The captured schema supports event IDs 1 through 29. An empty `onmatch="exclude"` filter collects the corresponding filterable category broadly. "Deferred" means that the filterable tag is present but explicitly disabled with an empty `onmatch="include"` filter; it does not mean that the tag is absent. IDs 4 and 16 are emitted by Sysmon itself and cannot be filtered.

| ID | Event | Policy | Rationale |
| ---: | --- | --- | --- |
| 1 | ProcessCreate | Enabled | Preserves process lineage, command-line, identity, and hash evidence. |
| 2 | FileCreateTime | Deferred | Timestamp changes can be noisy; enable only after a measured collection need. |
| 3 | NetworkConnect | Enabled | Preserves process-associated connection evidence. |
| 4 | Sysmon service state change | Non-filterable | Sysmon emits operational service-state events without a configurable event filter. |
| 5 | ProcessTerminate | Deferred | Usually adds high volume and limited context beyond process creation in this initial profile. |
| 6 | DriverLoad | Enabled | Preserves driver identity, hash, and signature evidence. |
| 7 | ImageLoad | Deferred | Module-load volume is potentially very high and requires measured scoping. |
| 8 | CreateRemoteThread | Enabled | Preserves cross-process thread creation context for investigation. |
| 9 | RawAccessRead | Enabled | Records direct raw-device reads that can matter in host investigations. |
| 10 | ProcessAccess | Deferred | Process-handle access is potentially noisy and needs evidence-backed scoping. |
| 11 | FileCreate | Enabled | Preserves broad file-creation context except measured Splunk UF WinEventLog checkpoint churn. |
| 12 | Registry object create/delete | Deferred | Broad canary collection exceeded the initial volume threshold; revisit with narrow target and process evidence. |
| 13 | Registry value set | Deferred | `RegistryEvent` is deferred as one filterable class while narrow collection is designed. |
| 14 | Registry object rename | Deferred | `RegistryEvent` is deferred as one filterable class while narrow collection is designed. |
| 15 | FileCreateStreamHash | Enabled | Preserves alternate data stream creation and content identity. |
| 16 | Sysmon configuration change | Non-filterable | Sysmon emits configuration-change events without a configurable event filter. |
| 17 | Pipe created | Enabled | Preserves named-pipe creation evidence. |
| 18 | Pipe connected | Enabled | Preserves named-pipe connection evidence. |
| 19 | WMI filter | Enabled | Preserves WMI event-filter registration evidence. |
| 20 | WMI consumer | Enabled | Preserves WMI event-consumer registration evidence. |
| 21 | WMI binding | Enabled | Preserves WMI filter-to-consumer binding evidence. |
| 22 | DNSQuery | Enabled | Preserves application DNS-query evidence even though reverse lookup enrichment is disabled. |
| 23 | FileDelete | Deferred | This event archives deleted content; content preservation is outside this workstream. |
| 24 | ClipboardChange | Deferred | Clipboard hashing is not yet justified by a concrete collection requirement. |
| 25 | ProcessTampering | Enabled | Preserves evidence of process image manipulation. |
| 26 | FileDeleteDetected | Enabled | Preserves deletion metadata without archiving content, except measured Splunk UF WinEventLog checkpoint churn. |
| 27 | FileBlockExecutable | Deferred | Enforcement is outside this evidence-collection profile. |
| 28 | FileBlockShredding | Deferred | Enforcement is outside this evidence-collection profile. |
| 29 | FileExecutableDetected | Deferred | Executable-file detection volume and value need measurement before collection. |

## Tuning policy

Version 0.1 is broad for the enabled categories in the controlled lab, while deferred filterable categories are explicitly disabled. Before tuning, measure actual event volume and log churn. Add only narrow, evidence-backed filters, and avoid broad exclusions that destroy investigative context. Record material telemetry-policy changes in Git. Keep detection logic out of Sysmon filters unless a concrete collection requirement justifies placing it there.

## Validation procedure

Validate on `win11-02` first from an elevated PowerShell session. Do not use Atomic Red Team in this workstream.

1. On `dev01`, calculate and record the source artifact's SHA-256 before copying it through the normal administrative transfer path:

   ```bash
   sha256sum config/sysmon/alert2ir-sysmon.xml
   ```

2. On the Windows endpoint, calculate the copied file's SHA-256 and compare the complete value with the value recorded on `dev01`:

   ```powershell
   $Config = 'C:\path\to\alert2ir-sysmon.xml'
   Get-FileHash -Algorithm SHA256 -LiteralPath $Config
   ```

3. Parse the copy before use. This verifies XML well-formedness independently of Sysmon:

   ```powershell
   $ParsedConfig = [xml](Get-Content -Raw -LiteralPath $Config)
   $ParsedConfig.Sysmon.schemaversion
   ```

   Confirm the root is `Sysmon` and the reported schema version is `4.91`.

4. Set `$Sysmon` to the explicit, verified path of the already-installed standalone executable. Inspect the active configuration before changing it and retain the output with the pre-change evidence:

   ```powershell
   $Sysmon = 'C:\known\path\to\Sysmon64.exe'
   & $Sysmon -c
   ```

5. Apply the copied configuration, checking both the output and process exit code:

   ```powershell
   & $Sysmon -c $Config
   if ($LASTEXITCODE -ne 0) { throw "Sysmon rejected the configuration: exit code $LASTEXITCODE" }
   ```

6. Query the active configuration again with `& $Sysmon -c`. Confirm Sysmon accepted schema `4.91`, `SHA256`, revocation checking, disabled DNS lookup enrichment, broad empty-exclude filters for enabled classes, and empty-include filters with no child rules for deferred classes.

7. Confirm a recent event ID 16 records the configuration change, the standalone Sysmon service is running, and the operational channel remains enabled:

   ```powershell
   Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=16; StartTime=(Get-Date).AddMinutes(-10)}
   Get-Service -Name Sysmon64
   Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' | Select-Object LogName, IsEnabled, RecordCount
   ```

8. Generate small benign activity: start a command shell that creates a temporary text file, use `Resolve-DnsName` for a domain the lab ordinarily accesses, and make a normal outbound web request to that same benign destination. Remove the test file afterward. Do not attempt to synthesize privileged or destructive event types merely to exercise every category.

9. Inspect recent local events and confirm representative enabled or non-filterable IDs such as 1 (process), 3 (network), 11 (file creation), 16 (configuration change), and 22 (DNS query) appear with expected fields:

   ```powershell
   Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=(Get-Date).AddMinutes(-15)} |
     Where-Object Id -in 1,3,11,16,22 |
     Select-Object TimeCreated, Id, ProviderName
   ```

   For activity occurring after the ID 16 configuration change, confirm deferred filterable classes do not produce new events, including IDs 5 and 12-14. IDs 4 and 16 can still appear because they are non-filterable. Do not generate destructive or privileged activity solely to test a deferred class.

10. Verify the representative Sysmon events reach Splunk using the existing forwarding path. Compare endpoint event timestamps and IDs with indexed results; do not change Splunk configuration as part of this validation.

11. Observe event volume and operational-log churn on `win11-02` over a representative lab interval. Apply the configuration to `win11-01` only after `win11-02` accepts it, remains healthy, forwards events successfully, and produces acceptable volume.

## Static validation expectations

Before endpoint validation:

- Parse the XML with Python's standard-library `xml.etree.ElementTree` parser.
- Confirm schema `4.91`, `SHA256`, `CheckRevocation` set to `true`, and `DnsLookup` set to `false`.
- Confirm every enabled filterable tag is present with `onmatch="exclude"`.
- Confirm every deferred filterable tag, including `RegistryEvent`, is present with `onmatch="include"` and contains no child filter rules.
- Confirm every configured tag exists in the captured Sysmon schema `4.91` evidence.
- Confirm IDs 4 and 16 have no tags in `EventFiltering` because they are non-filterable.
- Confirm archival settings are absent, the diff contains no Puppet changes or private canary evidence, and `git diff --check` passes.

## Rollback and failure handling

If Sysmon rejects the configuration or the profile is operationally problematic, stop the rollout. Do not perform ad-hoc tuning on `win11-01`, and do not apply the profile there. Preserve the pre-change inventory evidence and the outputs captured during validation.

Rollback must use an explicit, reviewed, known configuration file whose content and SHA-256 are recorded. Apply it with the verified standalone executable using the same `Sysmon64.exe -c <configuration>` mechanism, check the exit code, and repeat the service, channel, event ID 16, and forwarding checks. Do not rely on assumptions about defaults, command history, an undocumented prior path, or an endpoint's historical installation command.
