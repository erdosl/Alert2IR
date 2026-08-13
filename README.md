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

Splunk is the first real detection source, Sigma is the canonical detection-as-code format, and Velociraptor will be the first real investigation backend. A mock backend will keep the core workflow testable without a live lab or commercial products.

This repository is in its early implementation stage. A minimal typed Alert2IR core and FastAPI workflow using the deterministic MockBackend has been validated on `ir-core`. WS05 persistence is complete: PostgreSQL composition, explicit migrations, and durable completed-processing storage support successful `no_action` and `investigate` requests, which return a `processing_id`. The exact Git artifact was validated on `ir-core` and deliberately removed afterward; this did not create a permanent deployment. WS06 Puppet is also complete: repository-native contract tests freeze the existing narrow Windows roles/profiles boundary, and one exact Git-derived artifact was validated as already converged and idempotent with standalone Puppet 8.20.0 on both Windows endpoints. This did not expand Puppet ownership or introduce Puppet Server or scheduled agent convergence. WS07 Attack Simulation is complete: three deterministic Atomic-derived scenarios, their exact repository contract, and sanitized canary ground truth from `win11-02` are committed and contract-tested, with required cleanup independently verified. WS08 Sigma + Splunk is complete: three initial canonical Sigma rules, deterministic repository-owned Splunk translation, and sanitized live-validation evidence is committed and contract-tested against the WS07 ground truth. This did not implement Splunk-to-Alert2IR ingestion or begin investigation-backend work. The current persistence and lifecycle boundaries, including their explicit limitations, are recorded in [the IR-Core runtime document](docs/IR_CORE.md) and [core design record](docs/CORE.md); Puppet ownership and validation evidence are recorded in [the Puppet environment document](infra/puppet/README.md); WS07 provenance and ground truth are recorded in [the attack-simulation document](docs/ATTACK_SIMULATION.md); and WS08 detection execution and lab facts are recorded in [the lab inventory](docs/LAB.md). Live detection-source ingestion and real investigation integrations remain future work, with WS09 Velociraptor next.

See [the project definition](docs/PROJECT.md), [planned architecture](docs/ARCHITECTURE.md), and [roadmap](docs/ROADMAP.md).

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
