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

## Slice 2 boundary

Slice 2 adds vendor-neutral decision, incident, and investigation-request representations. Decisions have either an `investigate` or `no_action` outcome and retain source provenance with an explainable reason.

The initial `baseline-severity-v1` policy is a current WS04 application choice. It deterministically maps `low` and `medium` severity to `no_action`, and `high` and `critical` severity to `investigate`. An incident can represent only an `investigate` decision, and its alert and decision must have matching source provenance.

An `InvestigationRequest` states a desired outcome, required capabilities, and entity targets without naming a backend. Capability identifiers remain open strings. `process.list` is the first demonstrated identifier only; it is not an exhaustive or permanent capability taxonomy.

## Slice 2 deferrals

Slice 2 does not implement backend capability advertisement, backend selection or routing, unsupported-capability execution behavior, MockBackend, orchestration, a FastAPI alert endpoint, persistence, correlation, sophisticated risk scoring, incident lifecycle, Splunk or Sigma integration, or Velociraptor.

## Slice 3 boundary

Slice 3 adds vendor-neutral backend capability advertisement, explicit backend selection, and a deterministic, stateless MockBackend. A backend is eligible only when it alone supports every capability required by an investigation request. Zero eligible backends fail explicitly as unsupported. Multiple eligible backends fail explicitly as ambiguous because priority and tie-breaking policy have not been designed.

Capability identifiers remain open strings. `process.list` remains a demonstrated identifier, not a frozen taxonomy. MockBackend preserves requested capability order and produces one stable evidence reference per requested capability without using time, randomness, host state, or mutable counters.

An `InvestigationResult` identifies the backend, completed capabilities, and evidence references. It does not define execution lifecycle or persistence semantics.

## Slice 3 deferrals

Slice 3 does not implement Velociraptor, commercial backends, backend priority, failover, fan-out, dynamic discovery, backend health checking, orchestration, a FastAPI alert route, persistence, or Splunk or Sigma integration.
