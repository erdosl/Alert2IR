# Alert2IR

Alert2IR is a vendor-neutral, detection-driven incident-response orchestration project. It accepts canonical security alerts, applies deterministic investigation policy, optionally invokes one capability-compatible investigation backend, persists completed processing, and returns a bounded API response. It does not replace a SIEM, EDR, forensic platform, or full SOAR product.

The current application path is:

```text
canonical alert through POST /v1/alerts
  -> validation and deterministic policy
  -> optional capability-based investigation
  -> PostgreSQL persistence
  -> API response
```

Sigma is the canonical detection-as-code format, Splunk is the validated detection execution target, the deterministic mock investigation backend keeps application behavior testable without a live lab, and Velociraptor provides the implemented `process.list` investigation path. Detection execution and Alert2IR ingestion are separate: no Splunk-to-Alert2IR source adapter is implemented.

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

Without `ALERT2IR_TEST_DATABASE_URL`, the six PostgreSQL migration/persistence tests skip. Point that variable only at a disposable test database when those integrations are required; never use a production, shared, or live-lab database.

The ordinary environment intentionally excludes Sigma dependencies, so its two Sigma modules also skip. The [detection guide](docs/DETECTIONS.md) documents the separate pinned environment and 13 deterministic Sigma contracts.

The GitHub Actions `Tests` workflow runs the full Python suite with ephemeral PostgreSQL and runs the Sigma contracts in a separate job. Routine CI requires neither a commercial product nor the owned live lab. Green CI does not claim live Splunk or Velociraptor behavior, Windows execution, Puppet convergence, production readiness, or broad infrastructure validation.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
