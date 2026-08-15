# Attack Simulation and Ground Truth

## Status and scope

WS07 is complete. It defines a deliberately small set of controlled Atomic Red Team-derived scenarios, validates them once on the owned canary, and preserves a vendor-neutral ground-truth contract. Broad ATT&CK coverage was not a WS07 goal or completion criterion. Security testing remained limited to the owned lab in [`LAB_SCOPE.md`](LAB_SCOPE.md).

WS07 does not implement Sigma rules, Splunk searches or detections, Alert2IR alerts or decisions, incidents, investigations, or Velociraptor collection. Sigma and validated Splunk execution were completed later in WS08; they remain outside the WS07 boundary. Investigation-backend work was deferred from WS07 to WS09, which subsequently completed it.

## Implementation provenance

The scenario and contract implementation is commit `2be9f04eac3c7314753793dd5e7c6651f382f815` (`feat: define WS07 attack simulation contracts`). The sanitized canary evidence is commit `8852fabf0685c1e053859bf2d230e0546fae65d0` (`test: record WS07 canary ground truth`). Keeping these commits distinct separates the reviewed execution definition from the later physical execution evidence.

[`config/attack-simulation/scenarios.json`](../config/attack-simulation/scenarios.json) is the committed Alert2IR scenario-definition artifact. Its validated size is `6894` bytes and its SHA-256 is `99907c3d39bd473d3466c98e6171972b5bde93d3d888eed00b512fab766e2f86`. It derives from Atomic Red Team commit `1ba1dd8d9ce6f74700f7aec2e60de5632f667f03`; it is not a packaged Atomic distribution or an endpoint Atomic checkout.

## Pinned minimum scenario set

The artifact contains exactly three reviewed Windows scenarios:

| Scenario ID | ATT&CK | Atomic GUID | Atomic test | Purpose |
| --- | --- | --- | --- | --- |
| `alert2ir.ws07.windows.process-discovery-tasklist.v1` | `T1057` | `c5806a4f-62b8-4900-980b-c7ec004e9908` | `Process Discovery - tasklist` | Native process-discovery ground truth. |
| `alert2ir.ws07.windows.powershell-command.v1` | `T1059.001` | `a538de64-1c74-46ed-aa60-b995ed302598` | `PowerShell Command Execution` | PowerShell process-execution ground truth. |
| `alert2ir.ws07.windows.cmd-file-write.v1` | `T1059.003` | `127b4afe-2346-4192-815c-69042bec570e` | `Writes text to a file and displays it.` | Bounded file-create/delete ground truth. |

The pinned source definitions are:

| ATT&CK | Definition path | Definition SHA-256 |
| --- | --- | --- |
| `T1057` | `atomics/T1057/T1057.yaml` | `dc79938deab7d7f04c7cc35f5031f21a1af4cfe8fa85b17ccdb8191a2384bff5` |
| `T1059.001` | `atomics/T1059.001/T1059.001.yaml` | `9b02ed22b78f97873617aa4b9d4dcca3eb9e7ca8d5ed72a21e90baf7e8935fb7` |
| `T1059.003` | `atomics/T1059.003/T1059.003.yaml` | `5318d81746f483458ea2f906f64223a2a4e9506fded9df509f53986391ad572c` |

The minimum set was selected for determinism, no prerequisite acquisition, no external target, no credentials, no security-control changes, no reboot or logoff, bounded or absent persistent host effects, and reversible cleanup where required. Each definition records its exact upstream path and SHA-256, executor, project executable, elevation requirement, command and cleanup templates, project inputs, prerequisite state, safety properties, bounded effects, and expected local telemetry.

The file scenario resolves one target only:

```text
C:\Windows\Temp\Alert2IR-WS07-${run_id}.bin
```

The resolved file must be absent before execution and after cleanup. Cleanup may target only that file; no per-run directory or unrelated `C:\Windows\Temp` content is in scope.

## Execution-framework decision

WS07 deliberately used literal reviewed commands derived from the pinned Atomic definitions. Every attack command ran through the reviewed project executable `C:\Windows\System32\cmd.exe`. The committed scenario artifact, rather than a mutable upstream `latest`, was the execution definition.

WS07 did not install or use an Atomic Red Team checkout on either endpoint, Invoke-AtomicRedTeam, automatic prerequisite acquisition, an Alert2IR attack runner, or a generalized attack-orchestration service. Invoke-AtomicRedTeam was not validated. No command added `-ExecutionPolicy Bypass` or changed endpoint execution policy.

The pinned upstream tests do not require elevation. The physical executions truthfully record `actual_elevated: true` because the existing SSH administration context was elevated; that observed context does not change the upstream elevation requirement.

## Ground-truth record version 1

Sanitized execution evidence is committed under [`validation/attack-simulation/`](../validation/attack-simulation/). A version 1 record requires these concepts:

| Field | Contract |
| --- | --- |
| `schema_version` | Integer `1`. |
| `run_id` | UUID identifying one physical execution. |
| `scenario_id` | An ID present in the committed scenario manifest. |
| `alert2ir_commit` | Full 40-character hexadecimal Git commit containing the reviewed scenario definition. |
| `operator_role` | Exact non-sensitive attribution `lab-admin`; a personal username is not accepted. |
| `endpoint` | A coherent approved identity tuple. |
| `source_provenance` | `technique_id`, `atomic_guid`, `atomic_commit`, `definition_path`, and `definition_sha256`, all matching the selected scenario. |
| `execution` | Executable, executor, actual elevation, resolved inputs and command, UTC bounds, exit code, and result. |
| `prerequisite` | Status and details; the three scenarios require no prerequisite acquisition. |
| `clock_evidence` | `dev01_before_utc`, `endpoint_utc`, and `dev01_after_utc`. |
| `preflight` | Overall status and reviewed stop-condition results. |
| `cleanup` | Whether required, the exact command or `null`, constrained result, and independent-verification state. |
| `post_state_verification` | Verification status and bounded observed post-state. |
| `telemetry_window` | Explicit UTC bounds for local event correlation. |
| `telemetry_observations` | Sanitized local event observations and references. |
| `deviations` | Reviewed differences from the scenario or validation instructions. |

The validator accepts execution results `succeeded`, `failed`, or `blocked`; prerequisite result `not_required`; cleanup results `succeeded`, `failed`, or `not_required`; and post-state results `verified`, `failed`, or `not_applicable` under explicit cross-field rules. A no-cleanup scenario uses the fixed `not_required` representation. Successful required cleanup must be independently verified with `verified` post-state. All timestamps must be timezone-aware UTC.

Scenario definitions describe local, detection-neutral expectations. Run records use only `observed`, `missing_expected`, `not_available`, or `unexpected`; `expected` is not a run observation result. A sanitized telemetry reference contains only `channel`, `event_id`, `record_id`, and `timestamp_utc`. Missing expected telemetry is an observation result, not proof that execution did not occur.

## Canary identity and execution model

The sole WS07 execution endpoint was:

| Field | Value |
| --- | --- |
| Inventory name | `win11-02` |
| Computer name | `WIN11-02` |
| Host-only IPv4 | `192.168.56.62` |
| Interface | `Ethernet` |
| Actual execution context | Elevated |

`win11-02` was the canary. No WS07 scenario was executed on `win11-01`; it did not fail validation and was intentionally not used. The canary supplied sufficient execution, cleanup, provenance, and local telemetry ground truth, so a second-host reproduction was not required. Avoiding redundant attack execution reduced unnecessary endpoint impact.

The committed JSON records are the canonical sanitized execution evidence:

| ATT&CK | Run ID | Evidence record |
| --- | --- | --- |
| `T1057` | `45e78645-170d-4f2c-b158-32fdc89bec8d` | [`45e78645-170d-4f2c-b158-32fdc89bec8d.json`](../validation/attack-simulation/45e78645-170d-4f2c-b158-32fdc89bec8d.json) |
| `T1059.001` | `2c752432-9aa7-4a4d-bdb5-4ffacd2698b7` | [`2c752432-9aa7-4a4d-bdb5-4ffacd2698b7.json`](../validation/attack-simulation/2c752432-9aa7-4a4d-bdb5-4ffacd2698b7.json) |
| `T1059.003` | `34b43f09-1023-4c5c-8609-03c410bb28a3` | [`34b43f09-1023-4c5c-8609-03c410bb28a3.json`](../validation/attack-simulation/34b43f09-1023-4c5c-8609-03c410bb28a3.json) |

## Canary validation results

### T1057 process discovery

The exact reviewed `tasklist` command succeeded with exit code `0`. Transient local attribution verified `tasklist.exe` executing the reviewed command with `cmd.exe` as its parent. No tasklist standard output or process inventory was retained in Git.

The expected `Microsoft-Windows-Sysmon/Operational` event ID `1` was observed as record ID `1300570` at `2026-08-12T20:26:12.7059226Z`.

### T1059.001 PowerShell execution

The exact resolved encoded command succeeded with exit code `0`. PowerShell execution policy remained `Restricted`; no execution-policy bypass was introduced.

The expected `Microsoft-Windows-Sysmon/Operational` event ID `1` was observed as record ID `1300904` at `2026-08-12T20:28:41.4392803Z`.

No attributable `Microsoft-Windows-PowerShell/Operational` event was found within the execution window, so that expectation is recorded as `missing_expected` with `event_id: null` and no fabricated record ID or timestamp. The expectation was explicitly non-guaranteed because comprehensive Script Block Logging was not established. Its absence does not contradict the successful process execution or observed Sysmon process evidence, and the channel is not described as failed or broken. No PowerShell logging configuration was changed to manufacture additional telemetry.

### T1059.003 bounded file create/delete

The exact resolved target was absent before execution:

```text
C:\Windows\Temp\Alert2IR-WS07-34b43f09-1023-4c5c-8609-03c410bb28a3.bin
```

The exact committed Atomic-derived command executed unchanged, created that UUID-scoped target, and exited `0`. The expected Sysmon observations were:

| Event ID | Record ID | Timestamp UTC |
| ---: | ---: | --- |
| `1` | `1301448` | `2026-08-12T20:32:40.3421030Z` |
| `11` | `1301449` | `2026-08-12T20:32:40.3524437Z` |
| `26` | `1301589` | `2026-08-12T20:33:36.7062250Z` |

The exact reviewed cleanup command was:

```text
del "C:\Windows\Temp\Alert2IR-WS07-34b43f09-1023-4c5c-8609-03c410bb28a3.bin" >nul 2>&1
```

Cleanup exited `0` and succeeded. Independent post-state verification found the exact target absent, and the final `Alert2IR-WS07-*.bin` residue check found none.

An additional execution-time verification expected the file's single logical line to equal the project message without quote effects. That extra equality check did not match. The file was not manually corrected, and the attack command was neither rewritten nor rerun. No exact alternate file content is claimed because it was not retained as sanitized evidence. This deviation belongs to the additional validation assertion, not to source provenance or cleanup integrity; it does not by itself make the committed Atomic-derived scenario a failed execution. Exact reviewed cleanup still succeeded, and post-cleanup absence was independently verified.

## Pending-maintenance deviation

During preflight and execution, `PendingFileRenameOperations` contained the same 24 architect-reviewed Windows print-driver rename entries. The architect accepted them as unrelated pre-existing maintenance state for this scenario set. The value was not manually cleared or otherwise modified, the count and content remained unchanged through final validation, the raw 24 registry strings were not committed, and no reboot occurred. `CBS RebootPending` and Windows Update `RebootRequired` were both false. The endpoint is not claimed to have had no pending maintenance condition.

## Clock evidence

Per-run three-timestamp clock evidence was captured because W32Time was not providing synchronized-clock assurance. The measured approximate endpoint-minus-`dev01`-midpoint offsets were:

| ATT&CK | Offset |
| --- | ---: |
| `T1057` | `+193.607 ms` |
| `T1059.001` | `+180.618 ms` |
| `T1059.003` | `+217.373 ms` |

These three observations do not establish a universal fixed event-time tolerance. WS07 does not claim W32Time was synchronized, and no time configuration was changed.

## Final endpoint health and residual state

Final validation recorded:

| Item | State |
| --- | --- |
| Defender | Healthy |
| `Sysmon64` | Running / Automatic |
| `SplunkForwarder` | Running / Automatic |
| Puppet Agent | Stopped / Disabled |
| Sysmon Operational | Enabled |
| PowerShell Operational | Enabled |
| PowerShell execution policy | `Restricted` |
| Exact WS07 target | Absent |
| `Alert2IR-WS07-*.bin` residue | None |
| Atomic Red Team endpoint checkout | Absent |
| Invoke-AtomicRedTeam | Absent |
| Reboot | None |

WS07 changed no Defender, Sysmon, logging, auditing, execution-policy, service, firewall, user, scheduled-task, registry, network, or time configuration.

## Repository validation and privacy boundary

The Python-standard-library contract tests validate:

- pinned scenario identities and provenance;
- exact commands and inputs;
- decoded benign PowerShell content;
- explicit safety flags and absence of prerequisites;
- deterministic file targeting and exact cleanup scope;
- closed ground-truth version 1 records;
- approved endpoint identity and actual execution context;
- exact execution, cleanup, and post-state semantics;
- timezone-aware UTC timestamps;
- sanitized telemetry references and expectation accounting;
- exclusion of later-workstream concerns;
- presence of the three canonical canary records; and
- equality of each filename stem and loaded `run_id`.

This is a repository contract, not an attack-execution framework.

Committed run evidence intentionally excludes tasklist standard output, full event XML, raw Windows event messages, personal SSH usernames, complete process inventories, raw `PendingFileRenameOperations` paths, credentials, unrelated private filesystem data, and raw file bytes. Telemetry evidence is represented only through sanitized local event references and bounded deviations.

## Execution controls

The committed Slice 1 contract did not itself authorize endpoint execution. Slice 2 began only after separate architect-approved preflight and exact-artifact verification. That process verified physical identity, service and channel health, three-timestamp clock evidence, collision-free resolved targets, the Alert2IR commit and manifest hash, pinned Atomic provenance, resolved commands and inputs, and cleanup with independent post-state checks.

The exact `config/attack-simulation/scenarios.json` bytes were extracted from the reviewed Git commit and SHA-256 verified on `dev01`. The three execution commands and project inputs were resolved from that committed manifest before controlled execution on `win11-02`; the sanitized run records preserve the exact resolved commands and source provenance. An artifact-builder was not added for one JSON file. Future execution must stop if identity or provenance differs; an unexpected prerequisite, download, external target, security-control change, reboot, or logoff appears; a target collides; telemetry health is insufficient; cleanup is broader than the reviewed target or fails; prior residue remains; or private/raw evidence would enter Git.

## Completion and following-workstream boundary

WS07 is complete because exactly three minimum scenarios were pinned with reproducible source GUIDs, Atomic commit, definition paths and hashes, commands, and project inputs; none required prerequisite acquisition or an external target; one exact committed scenario artifact was used; canary identity and actual elevation were recorded; all three processes exited `0`; every required Sysmon expectation was observed; the non-guaranteed PowerShell Operational absence was recorded honestly; file cleanup succeeded and was independently verified; no WS07 residue remained; sanitized ground truth is committed and contract-tested; no raw/private evidence entered Git; a redundant second-host execution was unnecessary; and no detection implementation was pulled forward. Large ATT&CK coverage is not a completion criterion.

WS07 did not create Sigma rules or SPL searches, run Splunk searches, validate Splunk detections, add Splunk sourcetype mappings or correlation searches, create Alert2IR canonical alerts from the simulations, invoke Alert2IR orchestration, run Velociraptor, or implement investigation workflows. WS08 subsequently completed Sigma + Splunk detection-as-code content and validated Splunk execution without changing this WS07 scope. WS09 subsequently completed the investigation-backend and collection work without changing this WS07 scope.

## Current telemetry limitations

- Security event 4688 is unavailable under the current process-creation audit policy.
- Comprehensive PowerShell Script Block Logging is not established.
- The staged Sysmon XML proves staged-file bytes only, not active configuration equality.
- Windows Time is not an assumed control; each execution requires measured clock evidence.

These are ground-truth constraints, not authorization to change instrumentation. WS08 subsequently consumed this ground truth without changing instrumentation.
