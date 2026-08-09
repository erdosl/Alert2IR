# ADR 0007: Detection and validation strategy

**Status:** Accepted

## Context

The project needs portable detection definitions, an initial real detection platform, and repeatable controlled activity with known ground truth.

## Decision

Use Sigma as the canonical detection-as-code format, Splunk as the initial real SIEM/detection source, and Atomic Red Team for controlled simulations and ground truth.

## Consequences

Mappings and validation must make product-specific behavior visible. Simulations remain within the authorized lab, and none of these integrations is implemented in the bootstrap.

