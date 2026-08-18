# Alert2IR application

## Purpose

Alert2IR accepts a validated vendor-neutral alert, commits its logical processing identity before external work, applies deterministic policy, and optionally drives one capability-compatible investigation operation. PostgreSQL is the durable coordination boundary. The application provides replay-safe acceptance, bounded synchronous completion, durable nonterminal status, and one-shot reconciliation without a queue or separate worker.

The application is the Python/FastAPI process. `core` is its Compose service, `src/alert2ir/core` is its vendor-neutral domain package, and `ir-core` is a lab VM hostname.

## Canonical alert and fingerprint

`POST /v1/alerts` accepts the existing canonical alert: detection identity, timezone-aware detection time, source provenance, ordered entities, normalized severity, and ordered evidence. Unknown fields are rejected. Source-specific conversion remains outside the canonical application and `alert2ir.core`; the repository's concrete Splunk conversion runs in the separate source gateway under `alert2ir.adapters.splunk`.

Durable acceptance fingerprints the canonical domain value after validation; raw HTTP JSON is never hashed. Fingerprint version 1 is identified by `alert2ir.canonical-alert-fingerprint.v1` and includes every accepted semantic field. It:

- converts time to UTC and emits exactly six fractional digits;
- represents missing optional values as JSON `null`;
- preserves order, duplicates, case, and exact validated strings;
- uses deterministic member ordering and compact JSON encoding;
- hashes UTF-8 bytes with SHA-256;
- stores integer version 1 separately from the 32-byte digest.

HTTP member order, JSON whitespace, and equivalent timezone offsets therefore do not change a fingerprint. Any accepted semantic field change does.

## Idempotency contract

Every POST requires exactly one `Idempotency-Key` header. It is case-sensitive, is not normalized, and must contain 1–128 visible ASCII characters (`0x21`–`0x7e`), with no whitespace or control characters.

The current scope is the exact canonical alert `source`. PostgreSQL enforces:

```text
UNIQUE (idempotency_scope, idempotency_key)
```

The current API is published only on loopback and source is caller-controlled. Source scoping prevents accidental collision in that trusted deployment; it is not authentication or authorization. Broader publication requires an authenticated identity boundary and reviewed principal/source scoping.

The key and fingerprint are internal durable metadata. They are never returned, logged, traced, or used as metric labels.

## Durable processing flow

```text
validate canonical alert and idempotency header
  -> fingerprint canonical domain value
  -> INSERT accepted processing or resolve uniqueness conflict
  -> deterministic policy and planning
  -> persist plan plus execution attempt 1
  -> atomically claim attempt for submission
  -> backend submit outside any database transaction
  -> persist opaque external operation ID
  -> poll that exact operation once on the synchronous fast path
  -> atomically persist terminal result/failure, or return durable 202 status
```

Only the caller that inserted a new processing runs the POST fast path. A replay reads and returns the current durable state; it does not create an attempt, submit, or poll merely because the caller repeated the request. Interrupted `accepted` or `planned` work is resumed by bounded reconciliation.

## Processing states

| State | Meaning |
| --- | --- |
| `accepted` | Canonical request, scoped key, fingerprint, and processing ID committed; no backend action occurred |
| `planned` | Investigate decision, vendor-neutral request, backend selection, and attempt 1 committed; no submission occurred |
| `submitting` | One caller won the atomic submission claim and may be crossing the remote side-effect boundary |
| `submitted` | A backend operation ID is durable; queued, waiting, running, and polling-timeout work remains here |
| `completed` | Terminal public result and processing success committed atomically |
| `failed` | Definitive terminal failure and bounded sanitized error committed atomically |
| `recovery_required` | Automatic progress cannot safely infer whether to discover, resume, submit, or fail; no automatic resubmission |

`completed` and `failed` are terminal in v1. There is no `timed_out` state and no cancellation or public retry operation.

## Processing and execution attempts

A processing represents one logical request and its public outcome. `execution_attempts` represents backend execution state, including attempt number, backend, Alert2IR operation key, opaque external operation ID, poll observations, and bounded failure/recovery metadata.

V1 creates at most attempt 1. The schema uses `(processing_id, attempt_number)` uniqueness and a partial unique active-attempt index so a future explicitly authorized attempt 2 can be appended without redesign. Replaying POST never creates it.

All transition methods use expected-state conditions. A losing compare-and-set caller re-reads durable state. PostgreSQL transactions are short and never span `submit`, `poll`, or result collection. Completion changes the attempt to completed and stores the public processing result in the same transaction.

Historical `0001_processing_records` rows remain completed processings with their original UUIDs, snapshots, and timestamps. Their idempotency and fingerprint fields are null, and no execution attempts are inferred from historical result evidence.

## Policy and routing

The deterministic `baseline-severity-v1` policy is unchanged: low and medium produce `no_action`; high and critical produce `investigate`. No-action completion is committed directly from `accepted` with no backend call.

Investigation requests remain vendor-neutral and use open-string capabilities. Routing still requires exactly one backend supporting the complete capability set. Unsupported routing is a durable `failed` processing with HTTP 409; ambiguous routing is a durable `failed` processing with HTTP 500. No priority, fallback, fan-out, or split-capability routing is introduced.

## Backend lifecycle

Backends implement three independent operations:

```text
submit(request, operation_key) -> external operation ID
poll(request, external operation ID) -> nonterminal | succeeded | failed
collect_result(request, external operation ID) -> vendor-neutral result
```

`submit` does not poll. `poll` and `collect_result` never submit. The external operation ID is execution metadata and never enters `CanonicalAlert`, `Decision`, `Incident`, or `InvestigationRequest`. It is not reused as public investigation evidence.

The deterministic mock completes immediately and retains its generic public evidence contract. Velociraptor maps `process.list` to `Windows.System.Pslist`, schedules with `collect_client()`, returns the opaque flow ID, and polls that exact ID through `flows(client_id, flow_id)`. A new process can poll a persisted flow without invoking scheduling. Because v1 has no distinct caller-facing Velociraptor evidence locator, its public result has no evidence reference rather than exposing the flow ID.

The supported Velociraptor API does not establish caller-supplied scheduling idempotency or flow discovery by Alert2IR operation key. If a scheduling request may have crossed the network but no flow ID became durable, Alert2IR records `recovery_required`. It does not submit again. This is duplicate suppression and conservative recovery, not proof of globally exactly-once remote execution.

## HTTP API

### `POST /v1/alerts`

| Status | Meaning |
| --- | --- |
| 200 | Processing completed and its public result is durable |
| 202 | Processing is `accepted`, `planned`, `submitting`, `submitted`, or `recovery_required` |
| 400 | Idempotency key is missing, duplicated, or invalid |
| 409 | Scoped key conflicts with another canonical payload, or capability is unsupported |
| 422 | Canonical request schema/domain validation failed |
| 500 | Durable terminal failure, ambiguous routing, or an unexpected internal failure |
| 503 | Durable acceptance or required persistence is unavailable |

Successful and status responses include `processing_id`, `state`, timestamps, `status_url`, available decision/result values, and bounded error metadata. They include `Location: /v1/processings/<processing_id>`. A replay includes `Idempotency-Replayed: true`. A completed replay returns the same processing ID and durable logical result without backend work. A deterministic durable failure is reconstructed with its public classification: for example, an unsupported-capability replay remains HTTP 409, while durable backend/internal failures retain their existing 5xx semantics.

Every HTTP attempt receives a fresh server UUID in `X-Request-ID`; caller-supplied values remain ignored.

### `GET /v1/processings/{processing_id}`

GET returns one bounded public status or 404. It exposes available decision, request, result, terminal timestamps, and sanitized error values. It does not expose the idempotency key, fingerprint, operation key, attempt claim data, backend credentials, or external operation ID. There is no list/search route and no GET-by-idempotency-key. A caller recovers a lost processing ID by replaying the original POST.

UUID possession is not authorization. Loopback publication remains the current trust assumption.

## Recovery and reconciliation

Application startup launches one bounded, failure-isolated reconciliation pass without delaying liveness/readiness. The query is row-bounded. The pass computes a monotonic deadline, starts no new work after observing an exhausted budget, and passes the smaller of the remaining pass budget and configured backend timeout to submission and polling. A known-operation timeout leaves the processing `submitted`. These controls are the strongest synchronous bound Alert2IR can enforce; a vendor library can still return after its supplied timeout, because v1 does not use unsafe thread or process cancellation. Operators can invoke the same one-shot mechanism:

```bash
python -m alert2ir.cli reconcile --once
```

Rules are state-safe:

- `accepted` may repeat deterministic planning;
- `planned` may win the first submission claim;
- stale `submitting` becomes `recovery_required` because no supported backend discovery exists;
- `submitted` polls only its durable external ID and may complete/fail/remain submitted;
- `recovery_required` is not automatically advanced or resubmitted.

GET is read-only and never initiates submission.

## Availability, security, and observability

`/healthz` remains process liveness only. `/readyz` checks PostgreSQL connectivity and exact revision `0002_durable_execution`; it does not wait for reconciliation or remote completion. Startup never runs Alembic.

Durable errors use bounded categories such as `idempotency_conflict`, `unsupported_capability`, `backend_selection_error`, `backend_submission_failed`, `backend_submission_unknown`, `backend_execution_failed`, `backend_timeout`, `backend_protocol_error`, `persistence_failed`, and `recovery_required`. Public detail is fixed and sanitized; arbitrary exception messages are not persisted or returned.

Metrics use only bounded state, outcome, backend, and error-category dimensions. Processing, attempt, request, trace, fingerprint, idempotency, source-alert, and external-operation identities are never metric labels. Reconciliation establishes and resets correlation context separately for every work item.

## Current limitations

- The Splunk source gateway remains a separate edge process; this canonical application does not parse Splunk findings or authenticate Splunk callers.
- Runtime composition selects one mock or Velociraptor backend and one `process.list` plan.
- V1 has one automatic attempt, one bounded startup pass, and an operator one-shot command; it has no permanent scheduler, worker service, queue, broker, cancellation, retry endpoint, fallback, or fan-out.
- Velociraptor flow discovery by operation key is unsupported, so ambiguous scheduling requires verified operator resolution.
- Source-scoped idempotency remains a duplicate-suppression namespace, not access control. The canonical API stays loopback-published and the separate source gateway owns Splunk authentication.

See [ADR 0012](adr/0012-durable-processing-before-execution.md), [architecture](ARCHITECTURE.md), and [deployment](DEPLOYMENT.md).
