# IR-Core Runtime

## Purpose

WS03 established the minimal Docker Compose application/runtime substrate intended for `ir-core`. WS05 completes its PostgreSQL persistence substrate, explicit migrations, and durable completed-processing request path. WS09 adds repository-defined mock and live Velociraptor runtime composition while preserving mock as the default deployment mode.

## Current implementation boundary

WS03 established and validated the minimal Docker runtime substrate on `ir-core`. WS04 subsequently validated the typed, in-memory Alert2IR core API on the same host, including `GET /healthz` and `POST /v1/alerts`. WS05 adds an internal-only PostgreSQL service, a named data volume, explicit Alembic migrations, and durable completed-processing writes on successful alert requests. The exact committed WS05 artifact has been validated and deliberately cleaned up on `ir-core`; the validation was not a permanent deployment. WS09 live Velociraptor composition is deployed and operationally validated for exactly `process.list` with mapping `"win11-02" -> "C.4c0d758c0344d6b5"`; `docs/LAB.md` is the exact operational evidence record.

## Runtime model

Docker Compose defines the `core` application and its supporting `postgres` service. The application listens on TCP/8000 inside the container, while Compose publishes it only on host loopback at `127.0.0.1:8000`. Successful `POST /v1/alerts` calls persist completed `no_action` and `investigate` aggregates and return a `processing_id`. The route directly invokes synchronous orchestration and PostgreSQL persistence from `async def`, blocking the process event loop during that work; this is an accepted WS05 limitation, not a scalability claim.

`GET /healthz` returns `{"status":"ok"}` with HTTP status 200 and is used by the container healthcheck. It is liveness-only and does not query PostgreSQL, so it can remain successful during a database outage while durable alert requests fail with HTTP 500.

The application runs as a dedicated non-root container user. PostgreSQL is a supporting Compose service on the default network with no published host port, and `postgres_data` is its named data volume. The application API retains loopback-only publication and has no external exposure.

## WS03 runtime validation

Validation used Git commit `fb6b956bdcd5bc8534af2ec3b4538fa9d39da8d1` (`feat: add minimal IR-Core runtime scaffold`). The runtime input was `/tmp/alert2ir-ws03-fb6b956bdcd5.tar`, created directly from that commit with `git archive`. Its SHA-256 was `579c0914df1cc157394f46cfb831c342dacde6fd4118bf61490192eb4b33231c`; independent hashes on `dev01` and `ir-core` matched before extraction.

The physical target identified itself as `ir-core` at host-only IPv4 address `192.168.56.63`. The observed host platform was Ubuntu 24.04.4 LTS x86_64 with Docker Engine 29.7.2 and Docker Compose v5.4.0. Docker and SSH were already enabled host/bootstrap capabilities; validation did not install, configure, or place them under Puppet management.

`docker compose config` succeeded and rendered the intended single `core` service. The image built successfully as `fb6b956bdcd5-core:latest`, with observed image ID `sha256:3ba1d7afac1a26326dd213ec75289871bcbab77d9fc6969750a8cdd5dfc09716`. The running process had `uid=999(alert2ir)` and `gid=999(alert2ir)`, confirming non-root execution.

The service reached `healthy`. `GET /healthz` returned HTTP 200 with JSON exactly equal to `{"status":"ok"}`. Docker published container TCP/8000 only as `127.0.0.1:8000`; no TCP/8000 listener appeared on wildcard IPv4, the host-only or NAT address, or IPv6 wildcard.

After `docker compose restart core`, the service returned to `healthy` and the exact health response passed again. A full `docker compose down` followed by `docker compose up -d` recreated the service without mutable container state; health and loopback-only publication passed again. While active, the project used one application container, the normal implicit Compose default network, no named volumes, no database, and no supporting services.

Final teardown removed the application container and Compose default network. No project volumes remained and TCP/8000 no longer listened. The built image and isolated validation artifact directory were left in place after validation; neither is required for runtime operation. Runtime validation changed no host packages, Docker daemon, SSH, firewall, Puppet configuration, or repository files.

## WS04 core API validation

WS04 exact-artifact validation used commit `e56bec56dfa4f08efb129cbd239d33fcf58c0fda`. The typed API reached healthy state on the existing WS03 substrate and passed `/healthz`, canonical HIGH investigate and LOW no-action flows, schema rejection, OpenAPI, restart, full recreation, and loopback-only publication checks. It retained the same single-service, non-root, no-volume, no-database runtime boundary. Final teardown removed the application container and automatic Compose network, so this validation does not represent a permanent deployment.

## WS05 persistence runtime validation and closure

Exact validation ran on `ir-core` from Git commit `6f9ae1b14bb033ced620023d82460cd5553607b4` (`feat: persist alert processing via PostgreSQL`), not a development working tree. The `dev01` archive `/tmp/alert2ir-ws05-6f9ae1b14bb0.tar` had SHA-256 `6391dd2ba69b52a8f47aa02fd08c540aad8d7720a9c4705d3660dfe019523c1d`, which independently matched on `ir-core` before extraction. Core was rebuilt with `--no-cache` as `alert2ir-ws05-6f9ae1b14bb0-core`, image ID `sha256:88c207629997b3457f8bcc99a2d9626e336f3d09720933e235a6a89d8ffd35f4`; the supporting image was `postgres:18.4-bookworm`. Core ran as `uid=999(alert2ir) gid=999(alert2ir)`, and both services reached healthy state.

The fresh `postgres_data` volume contained no application table before the operator-run `alembic upgrade head`. That command created `processing_records` and `alembic_version` at `0001_processing_records`; its immediate repetition was a successful already-current invocation. Exact HTTP and PostgreSQL checks established durable LOW `no_action` processing ID `b59f6814-e8dd-45a6-a195-2651e403cefe` and HIGH `investigate` ID `d0adadbd-84e1-4289-a213-8067e180ed7d`. The HIGH row retained the expected MockBackend `process.list` request/result graph and `mock:process.list` evidence; both rows retained their canonical detection identity and source provenance.

Core recreation preserved both rows. An ordinary `docker compose down` removed containers and the automatic network while retaining `postgres_data`; PostgreSQL restart, explicit repeat migration, and core startup preserved both records again. Core publication was exactly `127.0.0.1:8000:8000`; host TCP/5432 was not published, and the only runtime services were `core` and `postgres`. `/openapi.json` preserved the typed canonical request, a UUID `processing_id` in successful responses, no `created_at`, 409 `ApiErrorResponse`, and description-only 500 documentation. Schema inspection confirmed no vendor payload, Splunk-specific data, incident state/owner/acknowledgement/closure, retry or idempotency state, or independent component IDs.

With only PostgreSQL stopped, `/healthz` remained liveness-only and returned exact HTTP 200 `{"status":"ok"}`; a valid POST returned HTTP 500. PostgreSQL restart returned it to health, after which processing ID `45524943-b3e5-416f-a9e1-4eb660e01f2a` persisted successfully. This does not demonstrate application retry or interrupted-work recovery.

The temporary project was deliberately destroyed after validation with its retained volume, locally built core image, temporary `.env`, transferred archive, and extracted directory. No validation-specific container, network, volume, image, credential file, or artifact directory remains on `ir-core`; this was not a permanent service deployment. This final destructive cleanup is distinct from normal `docker compose down`, which preserves `postgres_data`.

## Run and revalidate

On the intended Docker runtime host, run these commands from the root of a checkout or artifact containing the reviewed repository content:

```bash
docker compose config
docker compose build
docker compose up -d
docker compose ps
curl http://127.0.0.1:8000/healthz
docker compose restart core
docker compose down
```

After startup, `core` should become healthy and `/healthz` should return HTTP 200 with `{"status":"ok"}`. The service is published only on host loopback. PostgreSQL requires the explicit environment and migration procedure below.

## PostgreSQL substrate and explicit migrations

Copy `.env.example` to a local, Git-ignored `.env` and replace every placeholder. `POSTGRES_PASSWORD` and the password embedded in `ALERT2IR_DATABASE_URL` must correspond; URL-encode the URL password when required. PostgreSQL TCP/5432 is available only on the Compose network and is not published on the host. The `postgres_data` named volume contains PostgreSQL state.

From the repository root, initialize or advance the database explicitly before starting the application:

```bash
docker compose up -d --wait postgres
docker compose run --rm core alembic upgrade head
docker compose up -d core
```

The application does not run migrations at startup. Completed processing is orchestrated first and then written in one short transaction; no PostgreSQL transaction spans backend execution. Persistence failure does not return a successful alert response. Public read, list, update, and delete processing APIs, retries, durable idempotency, recovery, and mutable incident lifecycle remain deferred. `docker compose down` removes containers and the default network while preserving `postgres_data`. Intentional destruction is a separate operation:

```bash
docker compose down --volumes
```

## WS09 backend runtime modes

Base `compose.yaml` passes `ALERT2IR_BACKEND`, defaulting to `mock`, and requires no Velociraptor setting or credential. Normal base Compose operation therefore retains the deterministic singleton `MockBackend` runtime.

The separately selected live shape merges the base file first and the live override second:

```bash
docker compose -f compose.yaml -f compose.velociraptor.yaml config
docker compose -f compose.yaml -f compose.velociraptor.yaml up -d
```

Live deployment requires these external interpolation inputs:

- `ALERT2IR_VELOCIRAPTOR_API_CONFIG_SOURCE`: absolute host path to the protected external API-configuration file.
- `ALERT2IR_VELOCIRAPTOR_HOST`: the one exact Alert2IR host target.
- `ALERT2IR_VELOCIRAPTOR_CLIENT_ID`: the one exact Velociraptor client ID.

The source-path value is used by Compose interpolation only and is not passed into the container. The override mounts that file read-only at `/run/secrets/alert2ir-velociraptor-api.yaml`; the application receives only this container path. The file remains external to Git, is not copied into the image, and is not stored in a named volume.

The live core container runs as dedicated non-root UID/GID `999:999`. Its single secret-bearing API configuration remains outside Git and is mounted read-only; the host file grants named-user read access to UID 999 while retaining `jgipsz:jgipsz` ownership. The authoritative ACL is `user::rw-`, `user:999:r--`, `group::---`, `mask::r--`, and `other::---`. A visible stat mode of `0640` reflects POSIX ACL mask semantics and does not make the file world-readable.

Application construction performs local path and API-config validation only. It does not connect, authenticate, query clients or flows, or schedule a collection. The live override was subsequently deployed from exact `git archive` content for corrected commit `ed12b445a0a9430c360fb4b4356eafc8ef98fc5d` as image `sha256:fdf9eb454bc702e5df744c042207ad3734798eaea256dbec93b789d4224394c0`. One authorized E2E POST persisted processing UUID `bcebe47f-c5e1-4834-a92c-1c765ea6771f`; its HTTP and PostgreSQL `collection` reference both equal fresh finished flow `F.D9VQFSTQD87H4`. PostgreSQL and its named volume were preserved, and no retry, replacement flow, fallback, failover, or fan-out occurred.

## Current runtime deferrals

- Public processing read, list, update, or delete APIs
- Retries, durable idempotency, execution recovery/resume, correlation, and retention/deletion policy
- Mutable incident lifecycle, backup/disaster recovery, HA/replication, database readiness, and production concurrency/scalability
- Live Splunk integration
- Puppet ownership of Docker
- Reverse proxy or TLS termination
- Kubernetes, queues, workers, or caches
- External API exposure

The alert route is `async def` but directly executes synchronous orchestration and Psycopg, blocking the process event loop during that operation. A future effectful backend could complete before PostgreSQL persistence subsequently fails, leaving an external effect without a durable Alert2IR record. A database commit may also succeed before a client fails to receive or observe the HTTP response. WS05 records these consistency and acknowledgement windows but does not introduce retries, queues, sagas, distributed transactions, event sourcing, idempotency, or client reconciliation; they are not current MockBackend failures.

## Host administration boundary

Docker Engine and SSH administration are existing runtime-host/bootstrap state for this slice. This implementation task does not change them or place them under Puppet management.
