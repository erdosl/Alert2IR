# ADR 0005: Service composition

**Status:** Accepted

## Context

The initial lab needs understandable composition for a small number of application services. Cluster orchestration is not a demonstrated requirement.

## Decision

Use Docker Compose for application and service composition. Do not introduce Kubernetes.

## Consequences

Local and lab deployments stay comparatively simple. Scaling or orchestration needs must be demonstrated before adding infrastructure; Compose itself is deferred to its roadmap workstream.

