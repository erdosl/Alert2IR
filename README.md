# Alert2IR

Alert2IR is a vendor-neutral, detection-driven incident-response orchestration project. It durably accepts idempotent canonical alerts before external work, applies deterministic investigation policy, optionally drives one capability-compatible backend operation, and exposes bounded result/status retrieval. It does not replace a SIEM, EDR, forensic platform, full SOAR product, or distributed job platform.

The current application path is:

```text
canonical alert + Idempotency-Key through POST /v1/alerts
  -> validation and canonical fingerprint
  -> accepted processing committed in PostgreSQL
  -> deterministic policy and durable attempt planning
  -> claimed submit, durable external operation ID, exact-operation poll
  -> HTTP 200 or durable 202 + GET /v1/processings/{processing_id}
```

PostgreSQL uniqueness suppresses duplicate logical acceptance, and an atomic attempt claim permits at most one automatic submission attempt in Durable Execution v1. A known operation is restart-resumable. An ambiguous remote submission becomes `recovery_required` and is never automatically resubmitted. These database guarantees do not prove globally exactly-once remote execution.

Sigma is the canonical detection-as-code format, Splunk is the validated detection execution target, the deterministic mock investigation backend keeps application behavior testable without a live lab, and Velociraptor provides the implemented `process.list` investigation path. The repository defines seven primary attack-simulation scenarios, one ancestry control, and deterministic Sysmon Event 1/3/11/15/22 translation coverage. Direct Event 11 detection and Event 26 cleanup are **VALIDATED-LIVE**. Authoritative `alert2ir.test` DNS and fail-closed Windows NRPT are also **VALIDATED-LIVE**, satisfying the Event 22 infrastructure prerequisite. Event 3/15/22 and ancestry positive/control remain implemented and statically verified, but their PowerShell-wrapper-dependent live execution is deliberately deferred under the unchanged Windows endpoint baseline.

Detection execution and canonical ingestion remain separate components, now joined by one lab-scoped path: a standalone Splunk per-result action sends a bounded finding to an HMAC-authenticated `splunk_adapter` service, which deterministically creates the existing canonical alert and calls the loopback-isolated core over a private Compose network. Controlled owned-lab acceptance proved the full `win11-02` marker-to-`Windows.System.Pslist` path and proved that replay of the same logical finding returned the same processing without a second backend operation. A current summary derived from the sanitized evidence is retained under `validation/integration/`, while the original records remain in Git history; this is not an exactly-once network-delivery or production-readiness claim.

## Start here

Application users and developers should begin with the [application and API contract](docs/APPLICATION.md). Deployers should use the [Compose deployment guide](docs/DEPLOYMENT.md), which covers configuration, migration, startup, `/healthz` and `/readyz` acceptance, backend mode selection, and data-preserving lifecycle.

## Documentation

| If you want to... | Read |
| --- | --- |
| Understand project goals and non-goals | [Project definition](docs/PROJECT.md) |
| Understand logical architecture, trust, and failure boundaries | [Architecture](docs/ARCHITECTURE.md) |
| Develop against the application or API | [Application reference](docs/APPLICATION.md) |
| Deploy or upgrade the Alert2IR application | [Deployment guide](docs/DEPLOYMENT.md) |
| Understand the owned lab and authorization boundary | [Lab inventory](docs/LAB.md) and [lab scope](docs/LAB_SCOPE.md) |
| Operate monitoring and recover telemetry services | [Observability operator guide](docs/OBSERVABILITY.md) |
| Deploy or validate the observability configuration | [Observability configuration reference](observability/README.md) |
| Author, translate, or validate detections | [Detection development and validation](docs/DETECTIONS.md) |
| Understand controlled attack scenarios and ground truth | [Attack simulation](docs/ATTACK_SIMULATION.md) |
| Understand endpoint telemetry policy | [Sysmon telemetry](docs/SYSMON.md) |
| Collect bounded Windows endpoint inventory | [Windows endpoint inventory](docs/WINDOWS_ENDPOINT_INVENTORY.md) |
| Operate or validate authoritative DNS and Windows NRPT | `config/dns/README.md` |
| Apply the repository-owned Windows desired state | [Puppet environment](infra/puppet/README.md) |
| Understand accepted architectural rationale | [Architecture decision records](docs/adr/README.md) |
| See completed, deferred, and next work | [Roadmap](docs/ROADMAP.md) |

## Testing and CI

Install the ordinary development dependencies in a local virtual environment and verify the resolved environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --requirement requirements-dev.txt
.venv/bin/python -m pip check
```

Run the ordinary suite from the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
  .venv/bin/python -m unittest discover -v
```

Without `ALERT2IR_TEST_DATABASE_URL`, the nine PostgreSQL migration/persistence tests skip. Point that variable only at a disposable test database when those integrations are required; never use a production, shared, or live-lab database.

The ordinary environment intentionally excludes Sigma dependencies, so its two Sigma modules also skip. The [detection guide](docs/DETECTIONS.md) documents the separate pinned environment and 21 deterministic Sigma contracts.

The GitHub Actions `Tests` workflow installs Ubuntu's BIND validation utilities, runs the full Python and DNS contract suite with ephemeral PostgreSQL, and runs the Sigma contracts in a separate job. Routine CI requires neither a commercial product nor the owned live lab and never applies BIND, UFW, or NRPT. Green CI does not claim live Splunk or Velociraptor behavior, Windows scenario execution, Puppet convergence, production readiness, or unrecorded infrastructure behavior.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
