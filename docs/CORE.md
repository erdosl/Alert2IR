# Alert2IR Core

## Purpose

WS04 builds the vendor-neutral, in-memory Alert2IR core.

## Slice 1 boundary

Slice 1 establishes the canonical alert model, source provenance, entities, evidence references, normalized severity, and the source-adapter contract. Synthetic mapping tests demonstrate that a source-specific payload is normalized at the adapter boundary without leaking source-only fields into the core model.

## Initial application choices

These are current WS04 design choices, not immutable project-wide standards:

- Normalized severity is `low`, `medium`, `high`, or `critical`.
- Each canonical alert has one required, timezone-aware `detected_at` value.
- Entity kinds are open strings; examples do not define an exhaustive taxonomy.
- Evidence references are opaque strings and do not imply URI or URL semantics.
- Canonical alerts have no generated canonical alert identifier.

## Deliberate omissions

Slice 1 does not implement decision or policy behavior, risk scoring, incident representation, investigation requests, backend capabilities, MockBackend, an alert API route, PostgreSQL, Splunk or Sigma integration, Velociraptor, raw vendor payload retention, or generic vendor-extension metadata.

The canonical model may be refined before real source or backend integration if evidence from WS08 or WS09 demonstrates a need.
