# Controlled attack scenarios and ground truth

## Purpose and authority

This guide describes Alert2IR's repository-static Windows attack-simulation portfolio, safety boundary, provenance, and sanitized ground-truth contracts. It is not an attack runner and does not authorize endpoint execution.

The authorities are deliberately separate:

| Path | Authority |
| --- | --- |
| [`config/attack-simulation/scenarios.json`](../config/attack-simulation/scenarios.json) | Attack behavior, safety, run identity, cleanup plan, and expected telemetry |
| `config/attack-simulation/detection-objectives.json` | Scenario-to-detection objective, active/retired state, control association, and static/live portfolio status |
| `config/attack-simulation/ground-truth-v2.schema.json` | Sanitized multi-event ground truth |
| [`validation/attack-simulation/`](../validation/attack-simulation/) | Current derived validation summary plus sanitized live prerequisite and blocked-run evidence |
| `tools/windows/attack-simulation/` | Reviewed Alert2IR-local safe wrappers and script template |

Detection authoring and Splunk evidence belong in [DETECTIONS.md](DETECTIONS.md). Future investigation value does not expand the current Alert2IR `process.list` runtime capability.

## Implementation and evidence status

The seven-scenario portfolio, wrappers, contracts, rules, and mappings remain **VERIFIED-CODE**. The 2026-08-17 authorized acceptance established active endpoint/Sysmon/Splunk prerequisites and completed one new **VALIDATED-LIVE** direct Event 11 run with **VALIDATED-LIVE** Event 26 cleanup and independent post-state verification. Later infrastructure validation established **VALIDATED-LIVE** authoritative `alert2ir.test` DNS, local NRPT on both endpoints, success containment, and unavailable-server no-leak behavior.

Event 3, Event 15, Event 22, ancestry positive, and ancestry negative-control live execution are **DEFERRED BY PROJECT DECISION**. The current Windows endpoint baseline does not permit repository `.ps1` execution. Alert2IR will not weaken or bypass that baseline, introduce a script-signing/trust infrastructure solely for attack-simulation coverage, or rewrite the scenarios to evade the boundary. Event 22's DNS prerequisite is satisfied; its remaining live boundary is wrapper execution, not DNS containment.

Three earlier controlled records remain **VALIDATED-HISTORICAL** for their exact original behavior and observations in Git history. The current derived summary maps those facts to functional scenario names without relabeling the original runs. That label does not transfer live validation to a new detection objective, mapping, scenario, or control.

## Seven-primary-scenario portfolio

The manifest contains exactly seven primary scenarios and one companion control that is not counted as a primary:

| Primary scenario | Risk | Primary expected telemetry | Static status |
| --- | --- | ---: | --- |
| Existing Process Discovery — tasklist | A | Sysmon 1 | Historical run retained; active production-intent objective |
| Existing Encoded PowerShell | A | Sysmon 1 | Historical run retained; active production-intent objective |
| Existing temporary file | B | Sysmon 11 | **VALIDATED-LIVE** direct rule, related Event 1, Event 26, and exact cleanup |
| Owned host-only TCP | A | Sysmon 3 | Implemented; live execution deliberately deferred |
| Controlled owned-alias DNS | A | Sysmon 22 | Implemented; DNS prerequisite VALIDATED-LIVE; live scenario deliberately deferred |
| Benign run-scoped NTFS alternate stream | B | Sysmon 15 | Implemented; live execution deliberately deferred |
| Benign script-host ancestry | B | Sysmon 1 ancestry | Implemented; positive/control live execution deliberately deferred |

The ancestry companion uses the same harmless bounded PowerShell `Start-Sleep` child behavior under a PowerShell parent rather than `cscript.exe`. It has an independent control identity and future validation window. The ancestry rule must return zero attributable matches for that control; environmental matches are retained and classified, and any attributable rule match is `fail_control_matched`.

## Safety classes

- **Class A — bounded stateless:** no planned persistent host state; any network activity is a single bounded owned-lab operation.
- **Class B — uniquely identified reversible temporary state:** every resource is run-scoped, pre-state is known, cleanup names only the exact resource, cleanup status is recorded, and post-state is checked independently.
- **Class C — sensitive state:** not permitted in the active Tier 1 portfolio.

Every active item explicitly rejects downloads, C2, credentials, external targets, NAT/Internet destinations, persistence, privilege escalation, service/account/firewall/scheduled-task/registry changes, reboot, and logoff. Cleanup plans set `wildcard_allowed` to false. The ADS wrapper writes a static benign marker but never executes stream content. The ancestry wrapper uses a hash-pinned VBScript template and one bounded harmless child; it performs no download, connection, bypass, persistence, elevation, or sensitive mutation.

The TCP definition accepts only an operator-approved address inside `192.168.56.0/24` and the reviewed port `9997`; the 2026-08-17 acceptance separately approved the exact listener and proved the direct host-only route. The DNS definition uses `splunk.alert2ir.test` beneath the exact `.alert2ir.test` NRPT namespace and rejects answers outside the host-only range. Infrastructure acceptance proves that namespace remains on the owned path in both success and server-failure conditions. Neither prerequisite changes the deliberate wrapper-execution deferral.

## Provenance and immutable content

Provenance is per scenario:

- `atomic` items retain the exact repository, commit, definition path/hash, and test GUID. The three original pins remain unchanged and never use `latest`.
- `alert2ir_local` items identify the Alert2IR repository path, definition hash, local wrapper version, and wrapper hash. The ancestry script template has its own reviewed artifact hash.

Local wrappers are intentionally not presented as exact upstream Atomic tests. ATT&CK identifiers on ADS and VBScript ancestry are conceptual behavior context. Before any future authorized execution, stage the exact repository bytes at the manifest's reviewed endpoint path and verify the committed hashes; do not substitute an edited local script.

`Invoke-Alert2IRHostOnlyTcp.ps1`, `Invoke-Alert2IROwnedAliasDns.ps1`, `Invoke-Alert2IRBenignAds.ps1`, `Invoke-Alert2IRScriptHostAncestry.ps1`, and `Alert2IR-AncestryChild.vbs` remain reviewed behavior definitions, provenance anchors, static implementations, and future re-evaluation assets. Their code validity is independent of their deferred runtime status. They are not signed, encoded, converted to inline delivery, rewritten, or deleted by this closure.

## Run identity, telemetry, and relationships

`run_identity.unique_inputs` declares the resource names or markers that must differ per run. Class B paths and ADS stream names contain the canonical run UUID. Network and DNS wrappers also accept a run UUID for secondary process attribution without adding it to a canonical detection.

Every expected telemetry item has a stable `expectation_id`, role, phase, and minimum/maximum cardinality. Roles are `primary`, `secondary`, `cleanup`, or `related`; phases are `execution`, `investigation_window`, or `cleanup`. A null maximum means legitimate multiplicity is allowed. Detection-neutral relationships express `same_process`, `same_resource`, and `parent_of` without embedding Splunk, Sigma, or investigation-product fields in the scenario authority.

PowerShell Operational activity remains non-guaranteed. Registry and Security 4688 are not claimed. Expected Sysmon field names in static rules do not prove current Splunk Add-on extraction.

## Ground-truth v1 and v2

The earlier v1 records remain immutable in Git history. Their Atomic pins, run IDs, commands, sanitized Sysmon references, cleanup proof, deviations, and clock bracketing were not regenerated or rewritten. `validation/attack-simulation/validation-summary.json` is explicitly a current summary derived from those records, not original evidence.

The v2 schema adds sanitized event aliases and relationship evidence:

```text
expectation_id, event_ref, role, phase, state
channel, event_id, record_id, timestamp_utc
process_ref, parent_process_ref, relationship_to
```

Local aliases such as `event-*`, `process-*`, and `subject-*` replace unnecessary raw identifiers. V2 keeps execution and telemetry windows distinct, records the approved endpoint tuple and operator/endpoint clock bracket, and permits multi-event windows longer than one second. Contract tests require execution start before end, events inside the telemetry window, cleanup events after the cleanup action, and UTC-aware times. Failed/blocked runs retain explicit missing-primary state and a deviation instead of being made to satisfy positive cardinality.

For Class B evidence, v2 requires known pre-state, an exact subject, cleanup action/time/exit code/result, independent post-state status/time/subject, and a residual-artifact value. Residual state must fail or require review. Cleanup may never widen to wildcard, traversal, directory, broad-prefix, or unrelated process deletion.

Committed evidence continues to exclude raw XML, process inventories, command output, script contents, credentials, user secrets, DNS cache dumps, and unrelated endpoint state.

## Bounded stopping condition

The bounded portfolio is complete when the seven primary scenarios and one ancestry control remain statically valid, Event 11 and Event 26 remain VALIDATED-LIVE, DNS/NRPT infrastructure remains VALIDATED-LIVE, deferred scenarios retain their rules/mappings/contracts, and the deliberate deferral rationale remains explicit. Live Event 3/15/22 or ancestry acceptance is not a completion requirement. Breadth coverage is intentionally asymmetric between static validation and live endpoint execution.

The execution-policy discovery branch is closed by `docs/adr/0015-bounded-live-attack-simulation-coverage.md`. `AllSigned` plus Authenticode infrastructure, `RemoteSigned`, inline wrapper delivery, execution-policy bypass or mutation, and replacement implementations solely for coverage are rejected. The current Windows endpoint baseline remains unchanged. Revisit live wrapper execution only if an independent endpoint-baseline requirement later establishes an approved trusted script-execution model.

If such an independent trigger occurs, any physical execution would still require a separate reviewed plan under [LAB_SCOPE.md](LAB_SCOPE.md), identity and clock bracketing, active Sysmon/configuration attestation, exact wrapper/hash verification, pre-state checks, bounded local telemetry windows, and exact post-state verification. The existing DNS infrastructure record is prerequisite evidence, not Event 22 scenario ground truth.

Ordinary CI performs only schema, provenance, hashing, privacy, cleanup-safety, Sigma parsing, and deterministic translation checks. It never executes attacks, endpoint commands, live searches, cleanup, endpoint configuration, Alert2IR POSTs, or investigation-backend calls.

## 2026-08-17 live acceptance

The sanitized prerequisite attestation is `validation/attack-simulation/live-attestation-2026-08-17-win11-02.json`. It proves the tracked Sysmon policy hash matched the active configuration, the service and Operational channel were active, required Event 1/3/11/15/22/26 categories were available, registry remained excluded, and the expected Splunk source/sourcetype path was receiving current canary events.

Run `31d78a8c-d64a-4b5e-bff8-a318ad7c72cc` established the first live non-process breadth result. Event 11 record `1757566` was attributable to the exact run-scoped file and related to Event 1 record `1757564`; the deterministic Sigma-derived bounded search returned that primary, and Event 26 record `1757773` followed exact cleanup. Independent post-state verification found no residual artifact. The current summary preserves those sanitized facts; the original v2 records remain in Git history.

TCP run `f3aa96e4-4df1-4323-a4f3-b90a277eabba` preserves the blocked attempt: route/listener containment passed, the wrapper process was observed, the wrapper did not start under effective `Restricted` policy, and no attributable Event 3 was created. No execution-policy bypass was attempted. DNS produced no scenario run during that acceptance because containment then failed before query generation. Infrastructure record `validation/infrastructure/dns/dns-infrastructure-2f770f89-d84f-47b9-a633-17e42454b01c.json` subsequently satisfies only the DNS prerequisite; Event 22 remains not run. The other PowerShell-wrapper scenarios were not retried against the already-established execution-policy blocker.

Those records remain truthful historical/live evidence of what occurred. The current portfolio status is a project deferral, not a claim that DNS is blocked or an invitation to solve the wrapper prerequisite.

## Staging-directory integrity

The independent desired ACL for `C:\ProgramData\Alert2IR\AttackSimulation` is recorded in `config/windows/attack-simulation-staging-acl.json`: Administrators and SYSTEM have full control, Users have read-and-execute, inherited write access is removed, and standard users cannot create or replace staged assets. This closure adds only the repository contract and static tests. It does not change live endpoint ACLs, and the current Puppet catalog does not own this path. Live remediation belongs to a future separately authorized endpoint-hardening change and does not reopen the execution-policy decision.

## Explicit deferrals

Event 3 live acceptance, Event 22 live attack/detection acceptance, Event 15 live acceptance, ancestry positive, and ancestry negative control are deliberately deferred under the unchanged Windows execution baseline. They remain implemented, reviewed, and statically validated; they are not failed, unsupported, or abandoned.

Registry remains blocked by the separate telemetry-policy decision because IDs 12–14 are disabled. PowerShell 4103/4104 remains blocked by logging, forwarding, and privacy policy. Named pipes remain Tier 2. Class C and high-risk service, task, WMI persistence, driver, raw-read, remote-thread, tampering, external C2/download, and high-volume activity remain out of scope.
