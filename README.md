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

This repository is in its early implementation stage. A minimal typed Alert2IR core and FastAPI workflow using the deterministic MockBackend has been validated on `ir-core`. WS05 persistence is complete: PostgreSQL composition, explicit migrations, and durable completed-processing storage support successful `no_action` and `investigate` requests, which return a `processing_id`. The exact Git artifact was validated on `ir-core` and deliberately removed afterward; this did not create a permanent deployment. WS06 Puppet is also complete: repository-native contract tests freeze the existing narrow Windows roles/profiles boundary, and one exact Git-derived artifact was validated as already converged and idempotent with standalone Puppet 8.20.0 on both Windows endpoints. This did not expand Puppet ownership or introduce Puppet Server or scheduled agent convergence. WS07 Attack Simulation is complete: three deterministic Atomic-derived scenarios, their exact repository contract, and sanitized canary ground truth from `win11-02` are committed and contract-tested, with required cleanup independently verified. WS08 Sigma + Splunk is complete: three initial canonical Sigma rules, deterministic repository-owned Splunk translation, and sanitized live-validation evidence is committed and contract-tested against the WS07 ground truth. This did not implement Splunk-to-Alert2IR ingestion or begin investigation-backend work. WS09 Velociraptor is operationally complete for the narrow live `process.list` path using the exact lab mapping `"win11-02" -> "C.4c0d758c0344d6b5"`; one application-to-Velociraptor E2E succeeded and retained its exact `collection` evidence through completed processing. This does not imply generalized Velociraptor support, client discovery, hostname normalization, retry, fallback, failover, fan-out, or production readiness. The current persistence and lifecycle boundaries, including their explicit limitations, are recorded in [the IR-Core runtime document](docs/IR_CORE.md) and [core design record](docs/CORE.md); Puppet ownership and validation evidence are recorded in [the Puppet environment document](infra/puppet/README.md); WS07 provenance and ground truth are recorded in [the attack-simulation document](docs/ATTACK_SIMULATION.md); and WS08 detection execution plus exact WS09 operational provenance and evidence are recorded in [the lab inventory](docs/LAB.md). Splunk-to-Alert2IR ingestion remains future work. WS10 Testing & GitHub Actions is complete for the automated repository boundary documented below; live-lab validation remains separate.

See [the project definition](docs/PROJECT.md), [planned architecture](docs/ARCHITECTURE.md), and [roadmap](docs/ROADMAP.md).

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
