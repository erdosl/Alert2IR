# ADR 0002: Capability-based investigation backends

**Status:** Accepted

## Context

Investigation products have materially different collection and analysis functions. A uniform interface that implies identical functionality would hide gaps and create unreliable behavior.

## Decision

Investigation requests express required capabilities, and backends declare the capabilities they support. Unsupported operations are explicit. Velociraptor will be the first real backend.

## Consequences

Routing can be vendor-neutral without claiming false parity. Backend contracts and tests must cover capability discovery, selection, and unsupported requests.

