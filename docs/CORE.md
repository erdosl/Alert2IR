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

## Slice 4 boundary

Slice 4 adds the in-memory `AlertOrchestrator` application service. The decision gates all investigation work: `no_action` returns without creating an incident, requesting an investigation plan, selecting a backend, or executing one. For `investigate`, the service creates an incident, obtains an investigation request from an injected request factory, selects a capable backend, and executes it. Routing and backend errors propagate explicitly.

`OrchestrationResult` represents the coherent in-memory decision and, when investigation occurs, its incident, request, and backend result. Request planning is injected because a permanent mapping from alerts and decisions to desired outcomes, capabilities, and targets has not been designed.

## Slice 4 deferrals

Slice 4 does not implement production request-planning policy, a FastAPI alert endpoint, persistence, retries or recovery, background workers, durable idempotency, Splunk or Sigma integration, Velociraptor, or backend priority or failover.

## Slice 5 boundary

Slice 5 adds `POST /v1/alerts` as the typed canonical-core HTTP boundary. Strict request schemas reject unknown source-specific fields, convert explicitly to the domain model, and return a typed orchestration response. Raw source ingestion and adapter dispatch remain outside this route. Ordinary FastAPI request-validation failures remain HTTP 422; unsupported capabilities map to HTTP 409, and ambiguous backend routing maps to HTTP 500 without choosing a backend.

The module-level WS04 runtime composes `BaselineSeverityPolicy`, one deterministic MockBackend, and a narrow request factory for `process.list`. This is an initial WS04 application choice, not a permanent request-planning standard.

## Slice 5 deferrals

Slice 5 does not implement PostgreSQL, durable lifecycle, live Splunk or Sigma integration, Velociraptor, authentication, TLS or external exposure, background jobs, or CI.

## WS04 runtime validation and closure

Exact-artifact validation used commit `e56bec56dfa4f08efb129cbd239d33fcf58c0fda` (`feat: expose typed Alert2IR core API`). The input was `/tmp/alert2ir-ws04-e56bec56dfa4.tar`, created from that commit with `git archive`; its SHA-256 was `a53ec40170b7b6564f68f5b7abbecf357032a6a741026d5c813637c41f8ee05e`, and independent hashes on `dev01` and `ir-core` matched before extraction. The physical target identified itself as `ir-core` at host-only IPv4 `192.168.56.63`, with Docker Engine 29.7.2 and Docker Compose v5.4.0.

The exact image built successfully as `e56bec56dfa4-core:latest` with image ID `sha256:bf1573e523259e3c719998e5e63d76fcf2a22788ebe43dbc7e236005aca943f0`. It contained FastAPI 0.139.2, Pydantic 2.13.4, and Uvicorn 0.51.0 and ran non-root as `uid=999(alert2ir)` and `gid=999(alert2ir)`. The single `core` service became healthy; `GET /healthz` returned HTTP 200 with `{"status":"ok"}`.

A HIGH canonical alert returned HTTP 200 and traversed `baseline-severity-v1`, an Incident, an InvestigationRequest for `process.list`, and MockBackend, preserving source provenance and returning deterministic `mock:process.list` evidence. A LOW alert returned HTTP 200 with `no_action` and no incident, request, or result. An extra source-specific field and a naive `detected_at` were each rejected with HTTP 422. OpenAPI exposed `/healthz` and the typed `/v1/alerts` request and documented 200, 409, 500, and FastAPI's default 422 behavior.

Publication remained only on `127.0.0.1:8000`. Restart and full down/up recreation returned the service to healthy and repeated the health and orchestration checks without mutable state. The active boundary was one application container, the automatic Compose default network, no named volumes, no database, and no supporting service. Final teardown removed the container and network, left no volumes, and stopped TCP/8000; the built image and isolated artifact directory were retained but are not required for runtime.

This completes the documented WS04 in-memory core/API boundary. `baseline-severity-v1`, the current request factory, `process.list`, and MockBackend remain initial WS04 application, test, and runtime choices rather than immutable policy, planning, capability-taxonomy, or real-backend standards. PostgreSQL, migrations, and durable lifecycle; GitHub Actions; live Splunk ingestion, Sigma execution, and current telemetry mapping; Velociraptor, Atomic Red Team, and commercial or other real backends; production authentication, TLS, and external exposure; queues, workers, caches, and Kubernetes; and comprehensive entity, capability, risk, policy, and request-planning models remain deferred to later workstreams or demonstrated need.

## WS05 persistence Slice 1 boundary

WS05 Slice 1 defines the application-facing persistence semantics without implementing durable storage. One immutable completed processing record binds an Alert2IR-generated processing UUID and a repository-assigned, timezone-aware `created_at` value to both the accepted `CanonicalAlert` and its completed `OrchestrationResult`. The alert remains explicit because a `no_action` orchestration result does not otherwise retain it. For an investigated result, the incident must contain the same complete canonical alert; matching source provenance alone is insufficient.

The processing UUID is storage identity and is distinct from detection identity and `SourceProvenance.source_alert_id`. Canonical alerts, decisions, incidents, investigation requests, and investigation results do not gain independent persistence identities. `Incident` remains an immutable WS04 value representation; mutable status, ownership, acknowledgement, closure, retries, idempotency, deletion, correlation, and other case-management semantics remain deferred.

The application-facing repository contract is deliberately limited to saving one completed aggregate under a caller-supplied processing UUID and retrieving it by that UUID. A deterministic in-memory implementation assigns `created_at` through an injected clock and rejects duplicate processing UUIDs. PostgreSQL schema and access, SQL serialization, migrations, runtime wiring, public retrieval, and persistence-failure HTTP behavior remain later WS05 slices.

The planned transaction boundary is orchestration first, followed by one short persistence operation for the completed aggregate. A database transaction will not span backend execution, including when later backends perform external work.

## WS05 persistence Slice 2 boundary

WS05 Slice 2 adds the PostgreSQL storage substrate and a forward-only Alembic baseline for the completed processing aggregate. The `processing_records` table uses one application-supplied UUID primary key, a database-assigned `created_at`, relational scalar fields, and constrained JSONB value snapshots. Database checks enforce the current severity and decision vocabularies, non-blank scalar values, JSON array shapes, and complete `no_action` or `investigate` records. No component object gains independent identity, and no lookup indexes or source-level uniqueness are introduced.

Migrations are an explicit operator action and never run during application startup. PostgreSQL repository save/get behavior, domain serialization, runtime persistence wiring, processing identifiers in the API, public retrieval, and persistence-failure HTTP behavior remain later WS05 slices.
