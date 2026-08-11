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

This repository is in its early bootstrap stage. It records project decisions, lab scope, the roadmap, and a validated narrow Puppet environment for Windows telemetry service state and canonical Sysmon configuration staging. A minimal containerized FastAPI runtime scaffold now exists, but the Alert2IR domain workflow and integrations remain unimplemented. Runtime validation on `ir-core` is pending.

See [the project definition](docs/PROJECT.md), [planned architecture](docs/ARCHITECTURE.md), and [roadmap](docs/ROADMAP.md).

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
