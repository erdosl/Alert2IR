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

This repository is in its early implementation stage. A minimal typed Alert2IR core and FastAPI workflow using the deterministic MockBackend has been validated on `ir-core`. PostgreSQL composition and the baseline processing-record migration are implemented, while request processing remains in-memory until later persistence slices. Real source and investigation integrations remain future work.

See [the project definition](docs/PROJECT.md), [planned architecture](docs/ARCHITECTURE.md), and [roadmap](docs/ROADMAP.md).

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
