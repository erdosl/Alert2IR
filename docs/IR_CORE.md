# IR-Core Runtime

## Purpose

WS03 established the minimal Docker Compose application/runtime substrate intended for `ir-core`. WS05 Slice 2 extends it with the PostgreSQL persistence substrate and explicit migrations.

## Current implementation boundary

WS03 established and validated the minimal Docker runtime substrate on `ir-core`. WS04 subsequently validated the typed, in-memory Alert2IR core API on the same host, including `GET /healthz` and `POST /v1/alerts`. WS05 Slice 2 adds an internal-only PostgreSQL service, a named data volume, and an explicit Alembic migration baseline. Request processing remains in-memory until a later WS05 slice wires the application repository, and real integrations remain future work.

## Runtime model

Docker Compose defines one application service, `core`. The process listens on TCP/8000 inside the container, while Compose publishes it only on host loopback at `127.0.0.1:8000`. `GET /healthz` returns `{"status":"ok"}` with HTTP status 200 and is also used by the container healthcheck.

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

The application does not run migrations at startup and does not yet read or write processing records during requests. `docker compose down` removes containers and the default network while preserving `postgres_data`. Intentional destruction is a separate operation:

```bash
docker compose down --volumes
```

## Explicit non-goals for this slice

- PostgreSQL or other persistence
- Splunk integration
- Alert2IR domain workflow
- Investigation backends
- Puppet ownership of Docker
- Reverse proxy or TLS termination
- Kubernetes
- Queues or caches
- Persistent volumes
- External API exposure

## Host administration boundary

Docker Engine and SSH administration are existing runtime-host/bootstrap state for this slice. This implementation task does not change them or place them under Puppet management.
