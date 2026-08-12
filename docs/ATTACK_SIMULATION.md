# Attack Simulation and Ground Truth

## Scope

WS07 defines a small set of controlled Atomic Red Team scenarios and a vendor-neutral ground-truth contract. It does not implement Sigma rules, Splunk searches or detections, Alert2IR alerts or decisions, incidents, investigations, or Velociraptor collection. Those concerns remain in WS08 and WS09.

Security testing is limited to the owned lab in [`LAB_SCOPE.md`](LAB_SCOPE.md). Slice 1 is repository-only: it defines scenarios and contracts but does not execute an Atomic test, install an execution framework, change endpoint state, or create an execution record.

## Pinned scenario definitions

[`config/attack-simulation/scenarios.json`](../config/attack-simulation/scenarios.json) is the Alert2IR execution-definition artifact. It contains exactly three Windows scenarios derived from Atomic Red Team commit `1ba1dd8d9ce6f74700f7aec2e60de5632f667f03`:

| Scenario ID | Technique | Atomic test GUID | Atomic test |
| --- | --- | --- | --- |
| `alert2ir.ws07.windows.process-discovery-tasklist.v1` | `T1057` | `c5806a4f-62b8-4900-980b-c7ec004e9908` | `Process Discovery - tasklist` |
| `alert2ir.ws07.windows.powershell-command.v1` | `T1059.001` | `a538de64-1c74-46ed-aa60-b995ed302598` | `PowerShell Command Execution` |
| `alert2ir.ws07.windows.cmd-file-write.v1` | `T1059.003` | `127b4afe-2346-4192-815c-69042bec570e` | `Writes text to a file and displays it.` |

Each definition records the exact upstream path and SHA-256, executor, project execution executable `C:\Windows\System32\cmd.exe`, elevation requirement, command and cleanup templates, project inputs, prerequisite state, safety properties, bounded effects, and expected local telemetry. The upstream tests do not require elevation, while a future run may use the existing elevated SSH administration context; the run record must preserve the actual context separately.

The file scenario resolves one target only:

```text
C:\Windows\Temp\Alert2IR-WS07-${run_id}.bin
```

The resolved file must be absent before execution and absent after cleanup. Cleanup may target only that resolved file. No additional per-run directory is created, and no unrelated `C:\Windows\Temp` content may be removed.

## Execution framework

The WS07 baseline deliberately uses literal reviewed commands derived from the pinned Atomic definitions. It does not install or use Invoke-AtomicRedTeam, acquire Atomic prerequisites or payloads, add an endpoint-side Atomic checkout, or add an Alert2IR runner or wrapper. The committed scenario manifest, not a mutable upstream `latest`, is the execution definition.

No command may add `-ExecutionPolicy Bypass` or change endpoint execution policy. Actual elevation is an execution fact and must be recorded even though none of the three pinned upstream tests requires elevation.

## Ground-truth record version 1

Future sanitized run records are reserved for `validation/attack-simulation/`. Slice 1 adds no synthetic or fake run record; Slice 2 will add the first record only after an authorized execution.

A version 1 record requires these concepts:

| Field | Contract |
| --- | --- |
| `schema_version` | Integer `1`. |
| `run_id` | UUID identifying one physical execution. |
| `scenario_id` | An ID present in the committed scenario manifest. |
| `alert2ir_commit` | Full 40-character hexadecimal Git commit containing the reviewed scenario definition. |
| `operator_role` | Exact non-sensitive attribution `lab-admin`; a personal username is not accepted. |
| `endpoint` | A coherent approved identity tuple: `win11-02` / `WIN11-02` / `192.168.56.62` / `Ethernet`, or `win11-01` / `WIN11-01` / `192.168.56.60` / `Ethernet`. |
| `source_provenance` | `technique_id`, `atomic_guid`, `atomic_commit`, `definition_path`, and `definition_sha256`, all matching the selected scenario. |
| `execution` | `executable`, `executor`, boolean `actual_elevated`, exact resolved `inputs`, exact resolved `command`, UTC `start_utc` and `end_utc`, process `exit_code`, and execution `result`. |
| `prerequisite` | Status and details; the three current scenarios require no prerequisite acquisition. |
| `clock_evidence` | `dev01_before_utc`, `endpoint_utc`, and `dev01_after_utc`. |
| `preflight` | Overall status and the reviewed stop-condition results. |
| `cleanup` | Boolean `required`, exact command or `null`, constrained result, and boolean `independently_verified`. |
| `post_state_verification` | Verification status and a bounded description of observed post-state. |
| `telemetry_window` | Explicit UTC `start_utc` and `end_utc` for local event correlation. |
| `telemetry_observations` | Sanitized local event observations and references. |
| `deviations` | A list of reviewed differences from the scenario contract; empty when none occurred. |

The current narrow repository validator accepts execution results `succeeded`, `failed`, or `blocked`; prerequisite result `not_required`; cleanup results `succeeded`, `failed`, or `not_required`; and post-state results `verified`, `failed`, or `not_applicable` under the cross-field rules below.

For the three current no-prerequisite scenarios, the prerequisite result must be `not_required`. A scenario without cleanup must record `not_required`, no cleanup command, no independent cleanup verification, and `not_applicable` post-state. Successful required cleanup must be independently verified with `verified` post-state. Failed required cleanup remains valid ground-truth evidence only with failed post-state, and it stops further WS07 execution.

All timestamps must be timezone-aware UTC. Raw endpoint output, complete Windows event bodies, private inventory, and personal usernames remain outside Git.

## Telemetry expectations and observations

Scenario definitions describe local, detection-neutral expectations. Run records use only these observation states:

- `observed`
- `missing_expected`
- `not_available`
- `unexpected`

`expected` is not a run observation result. A sanitized telemetry reference may contain only `channel`, `event_id`, `record_id`, and `timestamp_utc`. Missing expected telemetry is a telemetry result; it is not proof that the execution did not occur.

The tasklist scenario expects Sysmon Operational event ID 1. The PowerShell scenario expects Sysmon event ID 1 and records PowerShell Operational activity as non-guaranteed because comprehensive Script Block Logging is not established. The bounded file scenario expects Sysmon IDs 1, 11, and 26. Security event 4688 is not required because process-creation auditing is currently unavailable.

The contracts contain no Splunk search, SPL, sourcetype, Splunk detection, Sigma rule, Alert2IR canonical alert or decision, incident, investigation, or Velociraptor fields.

## Execution readiness

Committing the Slice 1 scenario contract does not authorize endpoint execution. Slice 2 requires a separate architect-approved read-only preflight before any Atomic command is run.

Before any future execution, the operator must:

1. Verify the physical endpoint identity and host-only address.
2. Verify Defender and Sysmon health and the required local event channels.
3. Measure `dev01` and endpoint clocks using the three-timestamp clock evidence.
4. Verify that every resolved target path is collision-free.
5. Verify the Alert2IR commit and exact scenario artifact hash.
6. Verify the Atomic commit, GUID, definition path, and definition SHA-256.
7. Review the exact resolved command and inputs.
8. Review cleanup and independent post-state verification before execution.

`PendingFileRenameOperations` was populated on both endpoints during the WS07 design inspection. This does not block repository-only Slice 1. If it remains populated during Slice 2 preflight, do not clear it manually and do not execute a scenario; retain the exact values and readiness evidence for architect review.

Do not change Windows Time, PowerShell execution policy, the elevated SSH administration path, Defender, Sysmon configuration, PowerShell logging, Security auditing, Splunk Universal Forwarder configuration, or any service merely to satisfy WS07. Per-run clock measurements are required. The staged Sysmon XML is not proof of active Sysmon configuration equality.

## Stop conditions

Stop before execution or before the next scenario if any of these conditions exists:

- physical endpoint identity does not match the reviewed endpoint;
- Alert2IR scenario or Atomic commit, hash, GUID, path, command, or input differs;
- a pending-reboot marker still requires review;
- an unexpected prerequisite, download, or installation is requested;
- an external or remote target is introduced;
- a security control would be disabled or excluded;
- a service, account, firewall, scheduled task, or registry change appears;
- a reboot or logoff is requested;
- the resolved target path already exists;
- a required telemetry service or channel is unhealthy;
- cleanup is absent or broader than the reviewed target;
- cleanup or independent post-state verification fails;
- a prior scenario has residual state; or
- private or raw endpoint evidence would be committed.

## Exact-artifact canary model

Slice 2 should begin only from committed scenario definitions. Extract the exact `config/attack-simulation/scenarios.json` bytes from that Git commit, calculate and record their SHA-256 on `dev01`, transfer only the required artifact and reviewed runbook material to `win11-02`, independently hash the received bytes, and record both the Alert2IR commit and pinned Atomic provenance in the run record.

An artifact-builder script is not justified for one JSON file. `win11-02` is the default canary; execution on `win11-01` is not required unless later evidence demonstrates a reproducibility need.

## Current telemetry limitations

- Security event 4688 is unavailable under the current process-creation audit policy.
- Comprehensive PowerShell Script Block Logging is not established.
- The staged Sysmon XML proves staged-file bytes only, not active configuration equality.
- Windows Time is not an assumed control; each execution requires measured clock evidence.

These are ground-truth constraints, not authorization to change instrumentation. WS08 will consume WS07 ground truth when it implements Sigma and Splunk detection content.
