# IR-Core Runtime

## Purpose

WS03 establishes the minimal Docker Compose application/runtime substrate intended for `ir-core`.

## Current implementation boundary

The repository contains a minimal containerized FastAPI scaffold. Runtime validation on `ir-core` remains pending until the reviewed Git artifact is committed and deployed. This repository-edit task does not deploy or validate the service on `ir-core`.

## Runtime model

Docker Compose defines one application service, `core`. The process listens on TCP/8000 inside the container, while Compose publishes it only on host loopback at `127.0.0.1:8000`. `GET /healthz` returns `{"status":"ok"}` with HTTP status 200 and is also used by the container healthcheck.

The application runs as a dedicated non-root container user. It has no persistence, supporting services, bind mounts, named volumes, custom networks, or external API exposure.

## Intended validation procedure

After the reviewed artifact is committed and made available on `ir-core`, validate it from the repository root on that host:

```bash
docker compose config
docker compose build
docker compose up -d
docker compose ps
curl http://127.0.0.1:8000/healthz
docker compose restart core
docker compose down
```

Successful runtime validation has not yet occurred as part of this repository-edit task. Record observed runtime results separately when deployment is authorized.

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
