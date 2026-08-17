# ADR 0013: Bound attack-simulation breadth with explicit provenance and evidence authorities

**Status:** Accepted

## Context

The initial three-scenario portfolio and detection evidence concentrated on Sysmon Event ID 1 and process command lines even though the collection profile already retained file creation, network connection, stream hash, DNS query, deletion, and parent-process context. The existing temporary-file run observed IDs 1, 11, and 26, but its active detection objective remained the process command. A single Atomic repository pin also could not accurately describe Alert2IR-authored wrappers that deliberately remove unnecessary external, executable-stream, or other unsafe behavior.

Expanding scenario count without relationship, cleanup, control, and evidence semantics would increase activity without improving validation quality. Live lab work also requires separate authorization and cannot be inferred from static implementation.

## Decision

Extend ADR 0007 with a bounded portfolio of exactly seven primary scenarios: the three existing pinned behaviors plus owned host-only TCP, owned-alias DNS, benign run-scoped ADS storage, and a benign VBScript-host ancestry chain. Add exactly one different-parent negative control for ancestry; it is not a primary scenario.

Use risk Class A for bounded stateless behavior and Class B for uniquely identified reversible temporary state. Do not admit Class C behavior. Class B requires known pre-state, exact subjects, exact non-wildcard cleanup, recorded cleanup status, independent timed post-state verification, and failure/review for residue.

Make provenance per scenario. Preserve exact Atomic repository, commit, definition hash/path, and test GUID for upstream behavior. Identify Alert2IR-local wrappers by repository path, content hash, and wrapper version, and never claim that modified safe behavior is the exact upstream Atomic test.

Keep attack behavior, ground truth, detection objective, Sigma, target translation, validation evidence, and future investigation as separate authorities. Map each primary scenario to exactly one active objective. Move the existing temporary-file objective to direct Event 11 file telemetry while retaining the old cmd rule and evidence as retired historical regression content.

Preserve historical v1 evidence bytes and validation. Add closed v2 contracts for multi-event roles, phases, cardinality, sanitized process/resource aliases, relationships, multiple searches, constrained match classification, and control results. Unknown attributable results require review; any attributable ancestry-control match fails.

Preserve the historically pinned process pipeline and add separate narrow mappings for Event 3, 11, 15, and 22. Validation-only rules must be explicit and must not be presented as production-quality detections. Static mapping and deterministic translation do not prove active Sysmon configuration, current field extraction, or live detection.

## Consequences

The repository gains higher-information telemetry and ancestry coverage without adding runtime services, application domain fields, commercial dependencies, or live-lab CI. Local safe wrappers and cleanup logic become reviewed repository content whose hashes are contractually checked.

The new scenarios and mappings remain VERIFIED-CODE until separately authorized execution produces sanitized evidence. TCP listener approval, DNS containment, current extracted fields, Event 3/11/15/22 matching, ancestry positive/control behavior, and Class B cleanup require live acceptance.

Registry and PowerShell Operational remain separate telemetry-policy decisions, named pipes remain Tier 2, and Class C/high-risk or external behavior remains deferred. The portfolio stops at seven primary scenarios unless a future demonstrated requirement justifies revisiting this decision.
