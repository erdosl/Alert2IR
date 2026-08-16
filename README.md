# Alert2IR

Alert2IR is a vendor-neutral, detection-driven incident-response orchestration project. It aims to turn alerts into consistent investigation requests without trying to replace a SIEM, EDR, forensic platform, or full SOAR product.

The intended flow is:

```text
Detection source
  -> alert normalization
  -> canonical alert
  -> correlation / risk / policy
  -> investigation request
  -> capability-based investigation backend
```

Splunk is the first real detection source, Sigma is the canonical detection-as-code format, the deterministic MockBackend keeps the core workflow testable without a live lab or commercial products, and Velociraptor is the first real investigation backend.

The repository contains an implemented and owned-lab-validated core. WS05 persistence is complete: PostgreSQL composition, explicit migrations, and durable completed-processing storage support successful `no_action` and `investigate` requests, which return a `processing_id`. WS06 Puppet is complete for its narrow existing Windows roles/profiles boundary. WS07 records three deterministic Atomic-derived scenarios and sanitized ground truth; WS08 provides three canonical Sigma rules and deterministic Splunk translation validated against that evidence. WS09 is operationally complete for the narrow live Velociraptor `process.list` path and does not imply generalized backend support, discovery, retry, failover, or production readiness. WS10 provides routine hosted ordinary, PostgreSQL, Sigma, and repository validation without a live lab or commercial product. WS12 Observability is complete: Alert2IR emits structured JSON logs and vendor-neutral OpenTelemetry metrics/traces with server-generated request correlation; `/readyz` reports PostgreSQL/schema readiness; native edge and central Alloy forward to the failure-isolated Prometheus, Loki, Tempo, Grafana, and Alertmanager reference platform; and source-provisioned dashboards, deterministic alerts, null-receiver routing, failure isolation, and recovery were validated. Splunk-to-Alert2IR ingestion remains future work.

The current persistence and lifecycle boundaries are recorded in [the IR-Core runtime document](docs/IR_CORE.md) and [core design record](docs/CORE.md). Puppet ownership is in [the Puppet environment document](infra/puppet/README.md); WS07 provenance is in [the attack-simulation document](docs/ATTACK_SIMULATION.md); WS08/WS09 evidence is in [the lab inventory](docs/LAB.md); and normal monitoring, correlation, alert interpretation, and recovery procedures are in [the observability operator guide](docs/OBSERVABILITY.md).

See [the project definition](docs/PROJECT.md), [architecture](docs/ARCHITECTURE.md), and [roadmap](docs/ROADMAP.md).

## Testing and CI

Install the ordinary development dependencies in a local virtual environment and verify the resolved environment:

```bash
python -m pip install --requirement requirements-dev.txt
python -m pip check
```

Run the ordinary suite from the repository root with the source layout on `PYTHONPATH`:

```bash
PYTHONPATH=src python -m unittest discover -v
```

The ordinary environment intentionally excludes the dedicated Sigma dependencies. Without `ALERT2IR_TEST_DATABASE_URL`, the six PostgreSQL migration and persistence tests skip; the two Sigma modules likewise skip until run in their separate environment.

To execute the PostgreSQL tests, point `ALERT2IR_TEST_DATABASE_URL` only at a disposable local test database. The suite applies the repository migration and uses that real PostgreSQL database for one migration test and five persistence tests. Do not use a production, shared, or live-lab database. For example, with a synthetic local database already available:

```bash
ALERT2IR_TEST_DATABASE_URL=postgresql://alert2ir_test:alert2ir_test@127.0.0.1:5432/alert2ir_test \
  PYTHONPATH=src python -m unittest discover -v
```

Run the 13 dedicated Sigma contracts in a separate virtual environment installed from `requirements-sigma.txt`:

```bash
python -m pip install --requirement requirements-sigma.txt
python -m pip check
python -m unittest -v \
  tests.test_sigma_detection_contract \
  tests.test_sigma_toolchain_contract
```

These tests validate the canonical Sigma content, the repository-owned processing pipeline, the direct toolchain versions, and deterministic translation behavior. They do not require live Splunk.

The GitHub Actions `Tests` workflow runs for pull requests and pushes to `main` on Ubuntu 24.04 with Python 3.12.13. Its `python-tests` job gives the ordinary suite full Git history and an ephemeral PostgreSQL service, while `sigma-contracts` installs and exercises the Sigma environment separately. Routine CI requires neither a commercial product nor the owned live lab.

Green routine CI does not establish live Splunk ingestion or search correctness, live Velociraptor operation, Windows endpoint or attack-simulation execution, Puppet application to real systems, Docker/Compose deployment correctness, production readiness, HA/load/backup behavior, a fully hermetic supply chain, or broad security-scanner certification. Hosted runner images and transitive dependency resolution remain outside a fully locked reproducibility boundary.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
