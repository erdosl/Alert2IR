# ADR 0010: Host responsibilities

**Status:** Accepted

## Context

Development tooling, application runtime, and physical virtualization have different trust and operational responsibilities.

## Decision

Use `dev01` for development and Codex activity, `ir-core` for the planned Alert2IR runtime and supporting services, and keep the physical Ubuntu host infrastructure-only. Codex must not be installed or required on the physical host.

## Consequences

Development dependencies remain off the runtime and hypervisor where possible. Deployment processes must move reviewed artifacts from development to runtime without making the physical host an application dependency.

