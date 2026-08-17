# Architecture Decision Records

ADRs record accepted decisions that shape more than one part of Alert2IR. They describe intent and consequences, not implementation status. Add or supersede a record when a material architectural decision changes; do not silently rewrite historical decisions.

| ADR | Decision |
| --- | --- |
| [0001](0001-vendor-neutral-alert-model.md) | Vendor-neutral alert normalization |
| [0002](0002-capability-based-backends.md) | Capability-based investigation backends |
| [0003](0003-open-testable-backend-path.md) | Open-source and mock test path; deferred commercial integrations |
| [0004](0004-application-stack.md) | Python, FastAPI, and PostgreSQL |
| [0005](0005-service-composition.md) | Docker Compose rather than Kubernetes |
| [0006](0006-machine-configuration.md) | Puppet desired state and later Packer responsibility |
| [0007](0007-detection-validation-strategy.md) | Sigma, Splunk, and Atomic Red Team strategy |
| [0008](0008-lab-boundaries.md) | Lab network and no-Active-Directory scope |
| [0009](0009-repository-and-license.md) | Public monorepo and Apache-2.0 |
| [0010](0010-host-responsibilities.md) | Development, runtime, and hypervisor separation |
| [0011](0011-observability-architecture.md) | OpenTelemetry and a failure-isolated reference observability platform |
| [0012](0012-durable-processing-before-execution.md) | Durable idempotent processing before external execution and separate execution attempts |
