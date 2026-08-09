# ADR 0001: Vendor-neutral alert normalization

**Status:** Accepted

## Context

Detection sources expose different schemas and semantics. Coupling downstream logic to one source would limit portability and obscure provenance.

## Decision

Source adapters normalize alerts at an explicit boundary into a canonical internal alert representation. The core remains vendor-neutral while retaining source provenance.

## Consequences

Each source needs a maintained adapter and mapping tests. Core decision and investigation logic can operate consistently without treating Splunk's representation as universal.

