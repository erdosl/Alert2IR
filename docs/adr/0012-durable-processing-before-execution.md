# ADR 0012: Persist logical processing before external investigation and separate execution attempts

**Status:** Accepted

## Context

The original synchronous path invoked an investigation backend before a durable processing identity existed. Caller retry, backend side effect, PostgreSQL commit, and HTTP acknowledgement are separate failure domains. A server-generated UUID prevents primary-key collision, but it does not identify repeated delivery of one logical request. A remote operation may also outlive the HTTP connection that initiated it.

Velociraptor returns a flow ID after scheduling, but the supported client interface does not prove caller-supplied submission idempotency or discovery of a flow from an Alert2IR operation key. If scheduling crosses the network and its response is lost, Alert2IR cannot prove whether a flow exists.

## Decision

`POST /v1/alerts` requires a case-sensitive caller-generated `Idempotency-Key`. In the current loopback-only trusted deployment, the exact canonical alert `source` is the initial idempotency scope. PostgreSQL enforces uniqueness on `(idempotency_scope, idempotency_key)`. Source is caller-controlled and is not an authorization boundary; broader publication requires authenticated principal/source scoping.

Alert2IR fingerprints the validated canonical alert, not raw HTTP JSON. Fingerprint v1 uses a versioned semantic document, UTC timestamps with six fractional digits, explicit nulls, deterministic JSON, and a SHA-256 digest. Reuse of one scoped key with a different version or digest is a conflict.

A processing row containing the server-generated processing ID, canonical alert, scoped key, fingerprint, and `accepted` state commits before planning or backend work. Investigation planning and execution attempt 1 then commit together. Processing and execution-attempt state changes use expected-state updates. PostgreSQL constraints enforce identity, state, and active-attempt coherence.

The backend contract is split into:

- `submit(request, operation_key)`, which only creates an operation and returns an opaque external ID;
- `poll(request, external_operation_id)`, which only inspects a known operation;
- `collect_result(request, external_operation_id)`, which builds the vendor-neutral result without submission.

Only the winner of an atomic `planned` to `submitting` attempt claim may call `submit`. No database transaction or lock spans a backend call. A returned external ID commits in `submitted` before the first poll. Known nonterminal operations remain durable and are restart-pollable. Completion stores the terminal attempt, processing state, and public result atomically.

Definitive rejection may become `failed`. An ambiguous scheduling outcome without a durable external ID becomes `recovery_required` and is never automatically resubmitted. A timeout for a known external ID remains `submitted`.

The POST path retains a bounded synchronous fast path and returns `202` when work remains. `GET /v1/processings/{processing_id}` provides bounded status retrieval. Durable deterministic failures reconstruct their public classification on replay. External operation IDs remain internal execution identity rather than public evidence. Startup runs one row- and deadline-bounded, failure-isolated reconciliation pass; remaining time is propagated to supported backend submission and polling deadlines, although synchronous vendor code may overrun its supplied timeout. Operators may run `python -m alert2ir.cli reconcile --once`. V1 adds no permanent scheduler, separate worker, queue, cache, or broker.

## Alternatives considered

- **`(source, source_alert_id)` only:** source alert IDs are optional and do not express a caller's retry boundary.
- **Fingerprint only:** two intentional deliveries with identical content could not be distinguished, and caller ownership of retry identity would be lost.
- **Server processing UUID only:** UUID uniqueness does not suppress repeated logical delivery.
- **One expanded processing table:** this overloads logical request state with backend execution lifecycle and makes a future second attempt require redesign.
- **In-process background tasks:** process-local tasks do not survive restart and are not a durable execution boundary.
- **Separate worker:** it adds a deployment and coordination unit not required for bounded v1 recovery.
- **External message broker:** Kafka, RabbitMQ, Redis, and similar infrastructure add delivery semantics and operations without solving ambiguous remote submission.
- **Append-only event sourcing:** it adds projection and event-schema complexity beyond the demonstrated requirement.

## Consequences

API acceptance and completed acknowledgement replay are safe for the same scoped key and canonical request. Concurrent identical delivery converges on one logical processing, and Alert2IR concurrency control permits at most one automatic submission attempt for v1 attempt 1. A known operation can be resumed after restart without resubmission, and long-running operations no longer depend on one HTTP connection.

Persistence is now mutable and stateful. The migration must preserve historical completed rows while adding lifecycle constraints and an execution-attempt table. Application deployment must follow successful forward migration to revision `0002_durable_execution`; startup does not run migrations. Forward-only rollback remains operationally constrained.

Database idempotency and duplicate suppression do **not** prove globally exactly-once remote execution. For Velociraptor, a lost scheduling response can still leave an unknown remote effect. Alert2IR preserves that uncertainty as `recovery_required`; verified discovery or explicit operator resolution would be needed to advance it.
