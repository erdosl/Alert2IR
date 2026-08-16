# Detection development and validation

## Purpose

This guide defines how Alert2IR detection content is authored as Sigma, translated through the repository-owned Splunk pipeline, validated deterministically, and related to controlled live evidence. It is for detection developers, security analysts, contributors, and evaluators.

Detection execution is not Alert2IR ingestion. Splunk is the validated detection execution target; no repository component automatically sends Splunk findings to `POST /v1/alerts`.

## Sources of truth

| Path | Authority |
| --- | --- |
| [`detections/sigma/windows/`](../detections/sigma/windows/) | Canonical detection rules |
| [`config/sigma/pipelines/alert2ir-splunk-xml-sysmon.yml`](../config/sigma/pipelines/alert2ir-splunk-xml-sysmon.yml) | Repository-specific Splunk translation conditions |
| [`requirements-sigma.txt`](../requirements-sigma.txt) | Exact supported direct Sigma toolchain versions |
| [`tests/test_sigma_detection_contract.py`](../tests/test_sigma_detection_contract.py) | Canonical ruleset and rule-content contract |
| [`tests/test_sigma_toolchain_contract.py`](../tests/test_sigma_toolchain_contract.py) | Pipeline and deterministic translation contract |
| [`tests/test_detection_validation_contract.py`](../tests/test_detection_validation_contract.py) | Sanitized live-evidence contract |
| [`validation/detection/`](../validation/detection/) | Committed sanitized Splunk execution evidence |

The rules and pipeline are the executable detection definition. Generated SPL is derived output and must not replace the Sigma source.

## Authoring Sigma rules

The current rules are experimental Windows `process_creation` detections. A rule must remain vendor-neutral and include a unique Sigma UUID, meaningful title and description, author and date, false-positive guidance, severity level, ATT&CK tags, a canonical logsource, and bounded detection selectors.

Do not embed lab-specific or validation-specific values in canonical rules, including:

- Splunk index, source, sourcetype, or event-code constraints;
- endpoint names or addresses;
- controlled run identifiers, exact ground-truth payloads, or event record IDs;
- generated SPL or product-specific field projections.

Those concerns belong in the translation pipeline or sanitized validation evidence. The existing contract intentionally freezes exactly three approved rules; changing the ruleset requires a deliberate update to its contracts and evidence, not only a new YAML file.

## Translation pipeline

The repository pipeline applies only to Sigma rules with:

```text
product: windows
category: process_creation
```

For the Splunk backend it adds the validated XML Sysmon representation:

- source `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`;
- sourcetype `XmlWinEventLog`;
- event code `1`.

It deliberately adds no index or host constraint. This keeps environment-specific search scope outside the canonical rule and translation contract.

In an environment installed from `requirements-sigma.txt`, validate and translate a rule with the supported command form:

```bash
sigma check --fail-on-error --fail-on-issues \
  detections/sigma/windows/process-discovery-tasklist.yml

sigma convert \
  --target splunk \
  --pipeline config/sigma/pipelines/alert2ir-splunk-xml-sysmon.yml \
  --pipeline-check \
  --format default \
  --fail-unsupported \
  --output - \
  detections/sigma/windows/process-discovery-tasklist.yml
```

Review derived SPL for the rule selectors and the three pipeline-added conditions. Never add a lab index or host to the canonical pipeline merely to make one validation search convenient.

## Deterministic validation

The ordinary application environment deliberately omits Sigma packages. In that environment, the two Sigma modules report explained skips; the standard-library evidence contracts still run.

Use a separate environment installed from the pinned file for the dedicated contracts:

```bash
python3 -m venv .venv-sigma
.venv-sigma/bin/python -m pip install --requirement requirements-sigma.txt
.venv-sigma/bin/python -m pip check
.venv-sigma/bin/python -m unittest -v \
  tests.test_sigma_detection_contract \
  tests.test_sigma_toolchain_contract
```

The 13 tests verify the exact three-rule set, vendor-neutral rule content, approved direct dependency versions, the narrow pipeline, `sigma check`, required generated terms, and byte-identical repeated translation. They use a synthetic fixture where appropriate and require no live Splunk service.

`tests.test_detection_validation_contract` separately validates the closed evidence schema, rule and pipeline provenance, bounded search windows, ground-truth linkage, sanitized matches, and honest result classifications using only repository data.

## Live Splunk validation boundary

Deterministic translation proves reproducible rule-to-SPL behavior; it does not prove that a live platform indexes the expected telemetry or that a query finds controlled activity. The committed records under `validation/detection/` preserve the separate live validation boundary.

For a reviewed live validation:

1. use an authorized endpoint and platform from [LAB_SCOPE.md](LAB_SCOPE.md);
2. select committed ground truth from [`validation/attack-simulation/`](../validation/attack-simulation/);
3. translate the exact canonical rule with the pinned pipeline and toolchain;
4. bound the lab search to the recorded event window and explicitly add environment-specific scope outside the canonical rule/pipeline;
5. compare matches with the expected ground-truth event and retain additional genuine matches honestly;
6. commit only a sanitized record satisfying the evidence contract.

Live Splunk execution is owned-lab evidence, not a hosted-CI dependency. Do not reproduce raw event bodies, credentials, session data, or unrelated endpoint content in Git.

## Ground-truth relationship

[`ATTACK_SIMULATION.md`](ATTACK_SIMULATION.md) owns scenario definition, safety, expected observable behavior, cleanup, and ground-truth evidence. This guide owns detection authoring, translation, execution comparison, and detection evidence. A scenario can succeed while a detection does not match; the evidence must report those results independently.

The current relationship is:

```text
reviewed controlled scenario
  -> sanitized ground-truth record
  -> canonical Sigma rule
  -> repository Splunk pipeline
  -> derived SPL
  -> bounded Splunk execution
  -> sanitized detection-validation record
```

## Relationship to Alert2IR ingestion

A validated finding can be represented by an external caller as the canonical alert described in [APPLICATION.md](APPLICATION.md). The repository provides no Splunk saved-search action, webhook, polling adapter, or other automatic Splunk-to-Alert2IR delivery mechanism.

## Current limitations

- The validated pipeline covers Windows process-creation rules represented by XML Sysmon event code 1; it is not a general Sysmon or SIEM abstraction.
- The canonical ruleset contains three experimental detections tied to the controlled scenario set, not broad ATT&CK coverage.
- Hosted tests validate content and translation without contacting Splunk.
- Commercial detection platforms are neither implemented nor required.

See the [lab inventory](LAB.md) for current platform roles and the [roadmap](ROADMAP.md) for project-level future work.
