# Alert2IR deployment

## Scope

This guide describes the repository-defined Docker Compose deployment of the Alert2IR application. The `core` Compose service runs the application, and the `postgres` service provides its PostgreSQL database. The application is published only on host loopback at `127.0.0.1:8000`; PostgreSQL has no published host port.

`ir-core` is the exact hostname of the corresponding lab VM, not the application or an architectural component. Host provisioning, topology, and firewall facts belong in the [lab inventory](LAB.md).

## Prerequisites

- Docker Engine with Docker Compose support;
- a reviewed repository checkout containing the Compose files, Dockerfile, Alembic configuration, and migrations;
- a local environment file derived from `.env.example`;
- a readable external Velociraptor API configuration only when that investigation-backend mode is selected.

Host package installation and bootstrap are outside this guide. The repository-owned Puppet boundary is documented in [`infra/puppet`](../infra/puppet/README.md).

## Configuration

Copy the template to the Git-ignored local environment file and replace every placeholder:

```bash
cp .env.example .env
```

| Input | Requirement | Purpose |
| --- | --- | --- |
| `POSTGRES_DB` | Required | Database created by the `postgres` service |
| `POSTGRES_USER` | Required | PostgreSQL role used by the application |
| `POSTGRES_PASSWORD` | Required | PostgreSQL role password |
| `ALERT2IR_DATABASE_URL` | Required | Application connection URL for the internal `postgres` service |
| `ALERT2IR_BACKEND` | Optional; defaults to `mock` | Selects exactly `mock` or `velociraptor` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Optional; blank disables external export | OpenTelemetry collector endpoint |
| `ALERT2IR_VELOCIRAPTOR_API_CONFIG_SOURCE` | Velociraptor mode | Absolute host path to the external API configuration |
| `ALERT2IR_VELOCIRAPTOR_HOST` | Velociraptor mode | One exact canonical `host` target value |
| `ALERT2IR_VELOCIRAPTOR_CLIENT_ID` | Velociraptor mode | Velociraptor client mapped to that host |

`POSTGRES_PASSWORD` and the password embedded in `ALERT2IR_DATABASE_URL` must agree; URL-encode the URL password when necessary. Compose keeps the database on its internal network and injects the connection URL into `core`.

Validate interpolation and the resulting base deployment without starting services:

```bash
docker compose config
```

## Secrets

Do not commit `.env`, database credentials, certificates, private keys, or live host/client mappings. `.env.example` contains names and placeholders only.

Velociraptor credentials and certificates remain together in an external API-configuration file. The override mounts the file read-only at `/run/secrets/alert2ir-velociraptor-api.yaml`; the host source path is used only by Compose interpolation and is not passed to the application. The file must be a readable regular file for the non-root application process. It is not copied into the image or stored in a named volume.

## Database migration

Migrations are an explicit operator action; application startup does not run them. Build the application image, start PostgreSQL, and apply the repository migration from a one-off `core` container:

```bash
docker compose build
docker compose up -d --wait postgres
docker compose run --rm core alembic upgrade head
```

`alembic upgrade head` is repeatable when the database is already at the required revision. Migration must complete before readiness acceptance.

## Start the application

After configuration validation and migration:

```bash
docker compose up -d core
docker compose ps
```

The `core` image runs the application as a dedicated non-root user. The preceding `up -d --wait postgres` step establishes PostgreSQL container health before `core` starts; the Compose file does not declare automatic readiness gating between the services.

## Deployment acceptance

Require all of the following after startup:

```bash
docker compose ps
curl -fsS http://127.0.0.1:8000/healthz
curl -fsS http://127.0.0.1:8000/readyz
```

- `core` is healthy and `postgres` is healthy.
- `/healthz` returns HTTP 200 with `{"status":"ok"}`. This proves process liveness only.
- `/readyz` returns HTTP 200 with `{"status":"ready"}`. This proves PostgreSQL connectivity and the required Alembic/schema revision.

The `core` container healthcheck intentionally calls `/healthz`; Docker health does not replace the separate `/readyz` deployment-acceptance check. Readiness does not depend on an investigation backend or the observability platform.

## Investigation backend modes

### Mock/open mode

Base `compose.yaml` defaults `ALERT2IR_BACKEND` to `mock`. This selects one deterministic `MockBackend` with `process.list` capability and requires no external investigation system or credential file. Any Velociraptor application setting in mock mode is rejected.

Use the base commands shown above for configuration, migration, startup, acceptance, restart, and shutdown.

### Velociraptor mode

Set the three Velociraptor interpolation inputs in the local environment and merge the base file first and the override second:

```bash
docker compose -f compose.yaml -f compose.velociraptor.yaml config
```

Use the same `-f compose.yaml -f compose.velociraptor.yaml` pair on every `build`, `up`, `run`, `restart`, and `down` command for that deployment. The override selects `velociraptor`, mounts the external configuration read-only, and supplies the fixed container path to the application.

Application construction validates the local file and exact host/client mapping but does not connect to Velociraptor. Connection and collection are request-time effects. This mode supports one exact host mapping and the `process.list` application capability; it does not enable discovery, fallback, or multi-backend routing.

## Observability export

`OTEL_EXPORTER_OTLP_ENDPOINT` is optional. Blank or unset configures no external OpenTelemetry exporter, and the application continues to process requests. A configured endpoint sends application traces and metrics to that collector; the lab deployment points it at the Alloy process local to `ir-core`.

Collector or central-platform unavailability must not become an application dependency: telemetry export is failure-isolated from request processing, and `/readyz` does not check observability. See the [observability operator guide](OBSERVABILITY.md) for the reference Alloy, Prometheus, Loki, Tempo, Grafana, and Alertmanager deployment.

## Data persistence

The `postgres_data` named volume owns PostgreSQL state. Container restart, `docker compose restart core`, application-container recreation, and ordinary Compose down/up preserve that volume.

Use the same Compose file set that started the deployment for normal shutdown:

```bash
docker compose down
```

Start PostgreSQL, reapply the migration command, and start `core` to restore the deployment. Reapplying an already-current migration does not delete processing rows.

## Upgrade or redeploy

For an application revision change:

1. Select a reviewed revision with successful hosted validation and inspect its Compose, environment, dependency, and migration changes.
2. Preserve `.env`, any external Velociraptor configuration, and the `postgres_data` volume.
3. Run `docker compose config` with the selected Compose file set.
4. Build the application image and ensure PostgreSQL is healthy.
5. Run `docker compose run --rm core alembic upgrade head` with that same file set.
6. Run `docker compose up -d core` to recreate the application service when required.
7. Verify container state, `/healthz`, and `/readyz`.

Migrations are forward-only: the baseline migration provides no supported downgrade. An older application revision is therefore not automatically safe against an advanced schema. Assess application/schema compatibility and data recovery before any rollback; this repository defines no arbitrary downgrade guarantee.

## Destructive reset boundary

Normal troubleshooting and shutdown must not remove named volumes. This command intentionally destroys the PostgreSQL volume and its Alert2IR records:

```bash
docker compose down --volumes
```

Run it only for an explicitly authorized destructive reset with an understood recovery plan. Use the matching Compose file set when Velociraptor mode was selected.

## Troubleshooting boundaries

- Application model, API, routing, persistence, and effect semantics: [application reference](APPLICATION.md)
- Collector, telemetry, dashboard, alert, and recovery procedures: [observability operator guide](OBSERVABILITY.md)
- Host topology, addresses, firewall, and deployed lab integration facts: [lab inventory](LAB.md)
- Authorized security-testing boundary: [lab scope](LAB_SCOPE.md)
- Project direction and remaining work: [roadmap](ROADMAP.md)

## Sources of truth

Compose files, environment parsing, and migrations define exact deployment behavior:

- [`compose.yaml`](../compose.yaml) for the base application and PostgreSQL services;
- [`compose.velociraptor.yaml`](../compose.velociraptor.yaml) for live investigation-backend activation;
- [`.env.example`](../.env.example) for repository-owned environment inputs;
- [`src/alert2ir/main.py`](../src/alert2ir/main.py) for runtime composition and validation;
- [`migrations`](../migrations/) and [`alembic.ini`](../alembic.ini) for schema changes;
- [`tests`](../tests/) for executable deployment and application contracts.
