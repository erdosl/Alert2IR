# Controlled attack scenarios and ground truth

## Purpose and authority

This guide describes the repository's controlled Windows scenario contract: authorized scope, reviewed actions, safety properties, expected local telemetry, cleanup, and sanitized ground-truth evidence.

[`config/attack-simulation/scenarios.json`](../config/attack-simulation/scenarios.json) is the executable scenario authority. [`tests/test_attack_simulation_contract.py`](../tests/test_attack_simulation_contract.py) validates that manifest and the committed records under [`validation/attack-simulation/`](../validation/attack-simulation/). This document is not an attack runner and does not itself authorize execution.

Detection authoring and Splunk comparison belong in [DETECTIONS.md](DETECTIONS.md). Current host roles belong in [LAB.md](LAB.md).

## Authorization and safety boundary

Security testing is permitted only on the owned systems and for the activities defined in [LAB_SCOPE.md](LAB_SCOPE.md). External targets, Internet systems, third-party infrastructure, and any system absent from that authorization are out of scope.

Every current scenario is deliberately bounded:

- Windows only, with literal reviewed commands derived from pinned Atomic Red Team definitions;
- no prerequisite acquisition, download, credential, or external target;
- no reboot, logoff, security-control change, service change, account change, firewall change, scheduled-task change, or registry change;
- no network requirement;
- no persistent effect except the one explicitly temporary file, which requires exact cleanup and independent absence verification.

Stop before execution if the Git revision, scenario provenance, endpoint identity, resolved command, safety flags, or cleanup scope differs from the reviewed manifest. Also stop for an unexpected prerequisite, target collision, insufficient telemetry health, unrelated residual state that makes attribution unsafe, or any risk of committing raw/private evidence.

## Current scenario set

The manifest contains exactly three reviewed scenarios:

| Scenario | ATT&CK | Controlled action | Expected observable ground truth | Cleanup |
| --- | --- | --- | --- | --- |
| `alert2ir.ws07.windows.process-discovery-tasklist.v1` | T1057 | Run `tasklist` through the reviewed command-prompt executable | Sysmon process creation, event ID 1 | No persistent effect expected |
| `alert2ir.ws07.windows.powershell-command.v1` | T1059.001 | Run the manifest's reviewed benign encoded PowerShell command through command prompt | Sysmon process creation, event ID 1; PowerShell Operational activity is non-guaranteed | No persistent effect expected |
| `alert2ir.ws07.windows.cmd-file-write.v1` | T1059.003 | Create and display one run-scoped file beneath `C:\Windows\Temp` through command prompt | Sysmon process creation, file creation, and detected deletion: IDs 1, 11, and 26 | Delete exactly the resolved file and independently verify absence |

The manifest owns the exact Atomic commit, test GUIDs, definition paths and hashes, executor, command templates, inputs, safety flags, pre-state, cleanup, and expected telemetry. Do not copy a mutable upstream `latest` definition or substitute a locally edited command.

The repository does not install an Atomic Red Team checkout, use Invoke-AtomicRedTeam, acquire prerequisites automatically, or provide generalized attack orchestration. No command may add an execution-policy bypass that is absent from the reviewed manifest.

## Execution prerequisites

Any new physical execution requires a separately reviewed and authorized plan. Before running one scenario:

1. identify the intended endpoint independently by computer name and host-only address;
2. use a clean reviewed Git revision and verify the exact manifest bytes and pinned Atomic provenance;
3. resolve all manifest inputs and require that no placeholder remains;
4. verify the Sysmon service and Operational channel are healthy;
5. capture a bounded clock comparison with the operator host because synchronized Windows time is not assumed;
6. confirm every pre-state condition, including absence of the resolved file target where applicable;
7. confirm that the command affects no target beyond the manifest's bounded scope;
8. define the local telemetry window and evidence-handling path before execution.

`win11-02` is the lab canary role. Canary-first use does not replace explicit authorization or physical-identity verification.

## Execution and cleanup contract

Run only the exact resolved command from the reviewed manifest, once per approved scenario/run. Record timezone-aware UTC bounds, exit status, actual execution context, resolved inputs, and deviations. Do not rewrite and rerun a scenario merely to improve an observation.

For the temporary-file scenario:

- require the exact resolved target to be absent before execution;
- allow only creation of that target as the planned persistent host effect;
- run only the manifest's exact cleanup command;
- verify the exact target is absent independently after cleanup;
- check for residual files matching the project prefix without deleting unrelated content.

If required cleanup fails, stop, preserve bounded evidence, and escalate. Never broaden a cleanup command to a directory or wildcard merely to obtain a passing result.

## Ground-truth evidence contract

Each sanitized version 1 record binds one run to one committed scenario. It retains:

| Concept | Evidence requirement |
| --- | --- |
| Identity | Canonical run and scenario identifiers plus non-personal operator role |
| Endpoint | Approved inventory name, computer name, host-only address, and interface |
| Provenance | Scenario technique and pinned Atomic source identity |
| Execution | Exact resolved command/inputs, actual elevation, UTC bounds, exit code, and outcome |
| Preconditions | Explicit preflight and prerequisite state |
| Cleanup | Required command/result and independent post-state verification |
| Timing | Operator/endpoint clock evidence and bounded telemetry window |
| Telemetry | Expected-item accounting using sanitized channel, event ID, record ID, and UTC time references |
| Deviations | Honest bounded differences from the reviewed expectation |

Observation states distinguish `observed`, `missing_expected`, `not_available`, and `unexpected`. Missing non-guaranteed telemetry does not invalidate a successful process execution, and expected telemetry must never be fabricated.

The three committed records demonstrate the current evidence schema. They are immutable validation artifacts, not templates to edit for a new run; a new authorized execution requires a new record and independent review.

## Evidence handling and privacy

Committed ground truth excludes raw event XML and messages, command output, process inventories, personal usernames, credentials, unrelated registry content, raw file bytes, and private endpoint data. Store only the bounded facts accepted by the evidence contract. Raw evidence, if operationally retained, remains outside Git under approved lab handling.

The contract tests verify scenario identity and provenance, safety flags, command resolution, exact cleanup scope, closed evidence objects, authorized endpoint tuples, UTC timestamps, telemetry accounting, privacy constraints, and the canonical evidence set. They do not execute a scenario, parse upstream Atomic YAML, or prove a detection.

## Current telemetry constraints

- Security event 4688 is unavailable under the current process-creation audit policy.
- Comprehensive PowerShell Script Block Logging is not established, so PowerShell Operational evidence is non-guaranteed.
- Puppet proves staged Sysmon XML bytes, not active Sysmon configuration equality.
- Windows Time is not assumed to be synchronized; each execution requires measured clock evidence.

These constraints describe ground-truth interpretation and do not authorize instrumentation changes. See [SYSMON.md](SYSMON.md) for the endpoint collection policy and [DETECTIONS.md](DETECTIONS.md) for detection validation against this ground truth.
