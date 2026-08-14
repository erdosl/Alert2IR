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

## WS05 persistence Slice 3 boundary

WS05 Slice 3 implements the application-facing `ProcessingRepository` for PostgreSQL with Psycopg and an explicit snapshot-version-1 mapping. Each save uses one short transaction, writes one completed aggregate, lets PostgreSQL assign `created_at`, and validates the returned `ProcessingRecord` before commit. Retrieval reconstructs the immutable canonical alert, decision, incident, request, and investigation result graph by value through the existing domain constructors; unsupported snapshot versions fail explicitly.

The adapter opens one connection per save or get operation and does not introduce pooling, generic CRUD, or a unit of work. FastAPI and request-path composition do not use this repository yet; processing-ID generation, API response changes, public retrieval, and persistence-failure HTTP behavior remain future WS05 work.

## WS05 persistence Slice 4 boundary

WS05 Slice 4 adds a persistence-aware application service that first invokes the separately pure and testable `AlertOrchestrator`, then assigns an application-generated processing UUID and saves the accepted canonical alert with its completed orchestration result through `ProcessingRepository`. UUID generation occurs only after successful orchestration. Both successful `no_action` and `investigate` results are persistence candidates; investigated results are saved only after routing and backend execution finish.

Validation, policy, routing, and backend failures propagate without generating a processing UUID or calling the repository. Persistence failures propagate after UUID generation and one save attempt, with no retry. FastAPI and runtime composition do not use this service yet, so the current `/v1/alerts` request path is not durable.

## WS05 persistence Slice 5 boundary

WS05 Slice 5 wires `POST /v1/alerts` to `PersistentAlertProcessor` and the runtime `PostgresProcessingRepository`. Successful `no_action` and `investigate` processing is persisted after orchestration and any backend execution completes, and the existing response gains only the durable `processing_id`. The repository-produced `ProcessingRecord` is authoritative; `created_at` and persistence snapshot details are not exposed. A persistence failure propagates to FastAPI's normal HTTP 500 boundary and never returns a successful response. WS05 defines no stable persistence-failure response body, while ambiguous backend routing retains its existing explicit error body. The short PostgreSQL transaction begins only after orchestration, so it never spans backend execution.

The route remains `async def` and directly calls the synchronous processor. This blocks the process event loop during orchestration and PostgreSQL I/O. It is an accepted limitation of the currently validated WS05 execution path, not a scalability claim; thread-backed FastAPI and AnyIO execution hung in the demonstrated `dev01` environment. `GET /healthz` remains liveness-only and does not query or prove readiness of PostgreSQL. Public read, list, update, and delete APIs; retries, durable idempotency, recovery state, and mutable incident lifecycle remain deferred.

## WS05 exact runtime validation and closure

WS05 exact-artifact validation used committed Slice 5 `6f9ae1b14bb033ced620023d82460cd5553607b4` (`feat: persist alert processing via PostgreSQL`). `git archive` on `dev01` produced `/tmp/alert2ir-ws05-6f9ae1b14bb0.tar` with SHA-256 `6391dd2ba69b52a8f47aa02fd08c540aad8d7720a9c4705d3660dfe019523c1d`; the independently calculated `ir-core` hash matched before extraction. The artifact built without application-image cache as `alert2ir-ws05-6f9ae1b14bb0-core` with image ID `sha256:88c207629997b3457f8bcc99a2d9626e336f3d09720933e235a6a89d8ffd35f4`. It used `postgres:18.4-bookworm`, and the running application identity was `uid=999(alert2ir) gid=999(alert2ir)`.

An empty named PostgreSQL volume had no `processing_records` table. Explicit `alembic upgrade head` created the table and recorded exactly revision `0001_processing_records`; an immediate second invocation succeeded as an already-current no-op. A LOW canonical alert persisted completed `no_action` as `b59f6814-e8dd-45a6-a195-2651e403cefe`, with snapshot version 1 and null investigation/request/result storage fields. A separate HIGH canonical alert persisted completed `investigate` as `d0adadbd-84e1-4289-a213-8067e180ed7d`, with `collect process inventory`, `process.list`, backend `mock`, and deterministic `mock:process.list` evidence. Controlled PostgreSQL readback confirmed both IDs and their submitted canonical detection and source-provenance values.

The OpenAPI document retained the typed canonical request boundary; successful responses expose UUID-formatted `processing_id` but not `created_at`, 409 remains modeled by `ApiErrorResponse`, and 500 has no claimed universal response body. Recreating only `core` preserved both durable rows. Ordinary `docker compose down` removed the validation containers and network while retaining `postgres_data`; after PostgreSQL startup, repeat migration, and core startup, both rows remained. TCP/8000 was exactly loopback-bound at `127.0.0.1:8000`; PostgreSQL TCP/5432 had no host publication. The only Compose services were `core` and `postgres`, and inspection confirmed the vendor-neutral `processing_records` schema has no raw vendor payload, Splunk-specific columns, incident lifecycle, retry, idempotency, or independent component-ID fields.

During a deliberate PostgreSQL outage, core remained healthy and `GET /healthz` returned exactly HTTP 200 with `{"status":"ok"}`, while a valid alert POST returned HTTP 500 rather than false durability success. Once PostgreSQL was restarted and healthy, a new LOW processing record `45524943-b3e5-416f-a9e1-4eb660e01f2a` persisted successfully. This is renewed database availability, not application retry or execution recovery. The isolated validation deployment was then deliberately removed with volumes, local image, temporary `.env`, transferred archive, and extracted directory; no validation-specific containers, network, volume, image, credentials, or artifact directory remain. Ordinary `docker compose down` remains the documented volume-preserving lifecycle operation.

WS05 demonstrates durable completed `no_action` and `investigate` processing, explicit and repeatable migrations, and persistence across core recreation and ordinary Compose down/up. It does not guarantee retries, durable idempotency, interrupted-execution resume/recovery, correlation, retention/deletion policy, mutable incident lifecycle, backup/disaster recovery, HA/replication, a database readiness endpoint, or production concurrency/scalability. The `async def` alert route directly invokes synchronous orchestration and Psycopg, so it blocks that process event loop during the operation. A future effectful backend may complete, then PostgreSQL persistence may fail before durable commit; the external effect may therefore exist without an Alert2IR processing row. Separately, a database commit may succeed while the client fails to receive or observe the HTTP success response. WS05 supplies no retry, queue, saga, distributed transaction, event sourcing, idempotency, or reconciliation protocol for either window; neither limitation is a failure of the current deterministic MockBackend.

## WS09 Velociraptor Slice 1 boundary

WS09 Slice 1 adds the first concrete investigation-backend contract for exactly the existing open-string `process.list` capability. The Velociraptor operation requires exactly one target whose kind is `host`, resolves the target value by exact match through an injected host-to-client-ID mapping, and privately maps `process.list` to Velociraptor process collection. `InvestigationRequest.desired_outcome` remains descriptive free text and does not select the artifact or backend behavior.

The backend calls an injected narrow collection client with the resolved client ID, backend-private artifact name, and a configured finite positive timeout. On success it returns the existing `InvestigationResult`: backend `velociraptor`, the successfully completed requested capability tuple, and exactly one `EvidenceReference` of kind `collection` containing the client's nonblank opaque collection reference. The canonical request and result models gain no Velociraptor-specific fields.

This slice does not change runtime composition, add an external Velociraptor dependency, or imply that a lab server is deployed or that a live collection has run. It adds no retries, execution lifecycle, asynchronous workers, backend priority, failover, or fan-out.

## WS09 Velociraptor Slice 2 boundary

WS09 Slice 2 adds `PyVelociraptorCollectionClient` as the concrete vendor API implementation behind the unchanged `VelociraptorCollectionClient` protocol. Construction accepts only an external API-configuration path, loads the certificate-authenticated connection material once, and keeps credential contents outside canonical models and repository configuration.

One synchronous `collect()` call creates one secure API channel, schedules exactly one client flow, captures its fresh flow ID, and polls only that client and flow until successful completion or the local deadline. Success returns only the fresh flow ID to `VelociraptorBackend`; the backend continues to place it in one `EvidenceReference` of kind `collection`. Process rows and other artifact results do not enter `InvestigationResult`, and zero result rows do not make an otherwise successfully completed collection fail.

This client adds no retry, automatic flow cancellation, failover, fan-out, client discovery, multi-artifact framework, result ingestion, background execution, or connection pool. At Slice 2 closure, runtime composition still used `MockBackend`; API-config path injection and live runtime wiring remained deferred.

## WS09 Velociraptor Slice 3 runtime composition boundary

WS09 Slice 3 adds exact `mock` or `velociraptor` runtime selection through `ALERT2IR_BACKEND`. An absent selector retains the open, deterministic mock default. Mock mode and live mode each construct a singleton `BackendRouter`; the runtime never combines the overlapping `MockBackend` and `VelociraptorBackend`, and it adds no priority, fallback, failover, or fan-out.

Live mode requires one scalar API-config path, one exact host, and one exact client ID. These values must be present, nonempty, and free of leading or trailing whitespace, and the mapping is constructed as exactly the configured host to the configured client ID. The API configuration remains an external file; credential bodies do not enter application environment settings. The backend receives the fixed WS09 collection timeout of 60 seconds.

Application construction reads and validates the local API-configuration file but does not create a gRPC channel, authenticate to Velociraptor, query clients or flows, or schedule a collection. Those operations remain investigation-time effects. This repository composition has deterministic tests but has not been deployed through the live override or proven through the final Alert2IR-to-Velociraptor end-to-end path.
