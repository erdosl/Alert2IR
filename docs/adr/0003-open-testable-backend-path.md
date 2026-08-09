# ADR 0003: Open and testable backend path

**Status:** Accepted

## Context

Core development and CI must not depend on a live lab, commercial licensing, or commercial credentials.

## Decision

A deterministic MockBackend will support core integration tests. The first end-to-end real workflow will use open components and Velociraptor. Binalyze AIR is deferred until that workflow functions; CrowdStrike is optional and never required.

## Consequences

The project remains accessible and testable. Commercial adapters may arrive later and must not leak requirements into core operation.

