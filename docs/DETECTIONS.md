# Detection development and validation

## Purpose and authorities

Alert2IR keeps detection execution separate from canonical alert ingestion. Sigma is canonical detection-as-code, repository pipelines derive deterministic Splunk SPL, and the concrete Splunk per-result action supplies a bounded finding only to the authenticated source gateway. The gateway, not Splunk, derives the canonical alert and calls private `POST /v1/alerts`.

| Path | Authority |
| --- | --- |
| [`detections/sigma/windows/`](../detections/sigma/windows/) | Production-intent rules plus the byte-preserved retired cmd rule |
| `detections/sigma/validation/windows/` | Explicit validation-only breadth rules |
| `config/attack-simulation/detection-objectives.json` | Active objective, content class, pipeline, control, retired-rule mapping, and static/live status |
| `config/sigma/validation-data.json` | Reviewed ATT&CK and D3FEND versions, immutable source provenance, exact sizes, and SHA-256 digests used by Sigma validation |
| [`alert2ir-splunk-xml-sysmon.yml`](../config/sigma/pipelines/alert2ir-splunk-xml-sysmon.yml) | Historically pinned process-creation mapping to EventCode 1 |
| `config/sigma/pipelines/alert2ir-splunk-xml-sysmon-breadth.yml` | New narrow mappings to EventCodes 3, 11, 15, and 22 |
| `config/attack-simulation/detection-validation-v2.schema.json` | Generalized sanitized validation evidence |
| [`validation/detection/`](../validation/detection/) | Current summary derived from earlier sanitized Splunk validation evidence |

## Active portfolio

There are exactly seven active primary objectives:

| Scenario | Rule class | Sigma logsource | Pipeline EventCode | Evidence status |
| --- | --- | --- | ---: | --- |
| Tasklist | production intent | `windows/process_creation` | 1 | VALIDATED-HISTORICAL |
| Encoded PowerShell | production intent | `windows/process_creation` | 1 | VALIDATED-HISTORICAL |
| Existing temporary file | validation only | `windows/file_event` | 11 | VALIDATED-LIVE; exact `TargetFilename` primary and cleanup evidence |
| Host-only TCP | validation only | `windows/network_connection` | 3 | VERIFIED-CODE; live execution deliberately deferred |
| Owned-alias DNS | validation only | `windows/dns_query` | 22 | VERIFIED-CODE; DNS prerequisite VALIDATED-LIVE; live scenario deliberately deferred |
| Benign ADS | validation only | `windows/create_stream_hash` | 15 | VERIFIED-CODE; live execution deliberately deferred |
| Script-host ancestry | validation only | `windows/process_creation` | 1 | VERIFIED-CODE; positive/control live execution deliberately deferred |

The direct temporary-file rule selects `TargetFilename|startswith` for the existing UUID-scoped prefix. Its primary objective is now Sysmon 11, while the creating process (1) is secondary and deletion (26) is cleanup evidence.

The old cmd command-line rule remains byte-identical at its original path because its generated SPL, hashes, live evidence, and `contains|all` regression value are historical authority. It is listed only under `retired_rules` and is not an active primary objective.

## Rule intent and semantic coverage

Validation-only rules live under an explicit directory and are also labeled `validation_only` in the objective authority. They validate telemetry and translation semantics; they are not represented as deployable high-signal production detections.

Static implementation and live acceptance are independent dimensions. A `live_deferred` objective remains active: its Sigma rule, mapping, provenance, cardinality, cleanup, schema, and deterministic translation contracts continue to be required.

Preserved semantics include `endswith`, `contains`, `contains|all`, list-as-OR, simple AND, and multi-selection AND. The breadth rules add `startswith`, direct non-process fields, exact numeric `DestinationPort`, `Initiated` and `Protocol` equality, Windows ADS colon escaping, `ParentImage` ancestry, non-process logsources, and zero-attributable control semantics. The ancestry rule requires `ParentImage`, `Image`, and the bounded child command pattern; removing the parent condition changes the rule's meaning.

Rules never embed a host, index, run UUID, historical record ID, raw payload, or lab IP. The network validation rule fixes port `9997` because that is the reviewed objective field value, but does not select a destination address; authorized preflight must still approve the listener. The DNS validation rule uses only the repository-owned `.alert2ir.test` suffix, not one endpoint name or resolver address. The ADS rule intentionally has no broad `Zone.Identifier` exclusion; legitimate stream noise must be measured before any production allowlist decision.

## Translation pipelines

The original process pipeline remains unchanged so committed translation hashes stay resolvable. The breadth pipeline contains four separate `add_condition` transformations:

```text
windows/network_connection -> EventCode=3
windows/file_event          -> EventCode=11
windows/create_stream_hash  -> EventCode=15
windows/dns_query           -> EventCode=22
```

Every mapping adds the same deterministic XML Sysmon source and sourcetype and applies only to its exact logsource. Neither pipeline adds an index, host, destination, alias, run identity, or historical record. Environment scoping belongs only in executed-search evidence.

The mapping is **VERIFIED-CODE** and repeated translations are byte-deterministic. The authorized Event 11 run additionally proves current live `TargetFilename`, `Image`, `ProcessGuid`, and `RecordID` extraction for that bounded file-event result. It does not transfer verification to `DestinationIp`, `DestinationPort`, `Initiated`, `Protocol`, `QueryName`, `QueryStatus`, or stream-hash fields. `QueryStatus` and stream-hash existence logic remain omitted until the corresponding mapping is verified rather than guessed.

## Deterministic verification

The ordinary environment intentionally omits Sigma packages, so the Sigma modules report explained skips there. Direct Sigma tool versions remain pinned only in `requirements-sigma.txt`. MITRE validation inputs are pinned independently in `config/sigma/validation-data.json`; neither the toolchain tests nor CI use pySigma's ambient user cache.

Use the separately pinned environment and prepare a fresh cache outside the repository:

```bash
python3 -m venv .venv-sigma
.venv-sigma/bin/python -m pip install --requirement requirements-sigma.txt
.venv-sigma/bin/python -m pip check
sigma_root="$(mktemp -d)"
.venv-sigma/bin/python tools/sigma/prepare_validation_data.py \
  --metadata config/sigma/validation-data.json \
  --download-directory "$sigma_root/downloads" \
  --cache-home "$sigma_root/home"
PYTHONDONTWRITEBYTECODE=1 ALERT2IR_SIGMA_HOME="$sigma_root/home" \
  .venv-sigma/bin/python -m unittest -v \
  tests.test_sigma_detection_contract \
  tests.test_sigma_toolchain_contract
```

Preparation downloads the ATT&CK file from the manifest's full `attack-stix-data` commit and the independently versioned D3FEND URL. It verifies each file's exact size and SHA-256 digest before parsing it, verifies the embedded dataset version, and seeds both caches through pySigma's supported loader APIs. The contracts then give the real `sigma` subprocess only that fresh isolated `HOME` and install an explicit Python network-denial guard. Any attempted network access during validation fails with `Alert2IR Sigma subprocess attempted network access`; all default validators, including ATT&CK and D3FEND tag validation, remain enabled.

Those contracts parse every active rule, preserve the retired rule distinction, verify exact logsource-to-EventCode isolation, reject environment scope in canonical content, compile the new semantics, check unrelated-logsource non-transformation, require byte-identical repeated SPL, prove the network guard is active, and prove an invalid ATT&CK tag still fails semantically.

To update ATT&CK deliberately, select and review a release, resolve it to a full 40-character commit in `mitre-attack/attack-stix-data`, download `enterprise-attack/enterprise-attack.json` from that commit, compute its exact byte size and SHA-256 digest, and confirm its `x-mitre-collection` embedded version. Update the single manifest entry, prepare a cold cache, run the network-denied Sigma suite, and review every tag-validation change before committing. Update D3FEND independently by selecting a reviewed versioned ontology URL, computing its size and digest, confirming its embedded ontology version, and following the same cold-cache test process. Never update either input by following `master`, `main`, or `latest`.

## Detection-validation v1 and v2

The three earlier v1 records remain immutable **VALIDATED-HISTORICAL** evidence in Git history. In particular, the old cmd record preserves its generated/executed queries, hashes, expected process match, and honest `related_wrapper` classification. Its one-second historical window remains a fact about that search, not a v2 restriction. `validation/detection/validation-summary.json` is a derived current summary, not a rewritten execution record.

The v2 schema generalizes process-only evidence to:

```text
ground_truth.expected_events[]
searches[]
matches[]
control_results[]
```

Each search records logsource, event code, a bounded validation window, sanitized environment scope, referenced ground-truth events, canonical objective/rule/pipeline identity, pinned toolchain versions, generated/executed SPL and hashes, result count, and a timezone-aware execution timestamp. Search windows must contain referenced events and may span more than one second.

Match classes are limited to `expected_primary`, `expected_secondary`, `related_wrapper`, `unexpected_related`, `environmental_noise`, and `false_positive`. Extra events do not become related automatically. Unknown attributable results require `review_unexpected_match`.

Result states are `pass`, `pass_with_related`, `fail_missing_primary`, `fail_control_matched`, `review_unexpected_match`, and `blocked_telemetry`. The ancestry control expects zero attributable matches. Environmental matches remain preserved and classified; any attributable control match requires `fail_control_matched`.

## Live validation boundary

The direct Event 11 objective is **VALIDATED-LIVE** in the current derived validation summary, achieving the accepted non-process breadth result. The original execution record remains in Git history. Event 3/15/22 and ancestry positive/control remain without live detection acceptance and are **DEFERRED BY PROJECT DECISION**. TCP route/listener preflight passed. Separate DNS infrastructure acceptance proves `.alert2ir.test` containment and no-leak failure behavior on both endpoints, satisfying the Event 22 prerequisite; Event 22 is not DNS-blocked.

The current Windows endpoint baseline remains unchanged. Alert2IR will not add signing/trust infrastructure, bypass or mutate execution policy, deliver the wrappers inline, or replace the scenarios solely to obtain more live coverage. `docs/adr/0015-bounded-live-attack-simulation-coverage.md` closes that branch. Reconsideration requires an independent endpoint-baseline need for an approved trusted script-execution model, not an environment-specific rule change.

Ordinary CI remains lab-independent. Registry, PowerShell Operational 4103/4104, named pipes, Class C behavior, and commercial detection products remain outside this bounded portfolio. The separate Splunk delivery integration consumes Sigma-derived per-result searches without changing this detection authority; its validation-only high marker is not production-intent detection content.
