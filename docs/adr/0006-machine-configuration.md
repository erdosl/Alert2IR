# ADR 0006: Machine configuration and images

**Status:** Accepted

## Context

Desired state on existing machines and reproducible construction of machine images are related but distinct responsibilities.

## Decision

Use Puppet for desired-state configuration. Packer may later produce reproducible machine images where justified.

## Consequences

Puppet roles and profiles own convergent configuration, while any later Packer templates own image construction. The bootstrap supplies only no-op Puppet structure and no Packer implementation.

