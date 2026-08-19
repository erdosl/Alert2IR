# Alert2IR deployment

## Scope

This guide describes the repository-defined Docker Compose deployment of the Alert2IR application and its lab-scoped Splunk source gateway. The `core` service runs the canonical application, `postgres` provides its database, and the separate `splunk_adapter` service authenticates and converts bounded Splunk findings before making one private request to `core`. The canonical API remains published only on host loopback at `127.0.0.1:8000`; PostgreSQL has no published host port. Only the adapter is published on the host-only interface at `192.168.56.63:8091`.

`ir-core` is the exact hostname of the corresponding lab VM, not the application or an architectural component. Host provisioning, topology, and firewall facts belong in the [lab inventory](LAB.md).

## Prerequisites

- Docker Engine with Docker Compose support;
- a reviewed repository checkout containing the Compose files, Dockerfile, Alembic configuration, and migrations;
- a local environment file derived from `.env.example`;
- one external HMAC secret installed as protected files on both `ir-core` and `splunk` when the source gateway is enabled;
- a source-restricted host firewall rule for the Docker-published adapter port;
- a readable external Velociraptor API configuration only when that investigation-backend mode is selected.

Host package installation and bootstrap are outside this guide. The repository-owned Puppet boundary is documented in [`infra/puppet`](../infra/puppet/README.md).

## Canonical identity and target host layout

The application Compose project is declared as `alert2ir` in `compose.yaml`. Operators do not supply a project name, and Compose therefore generates predictable names such as `alert2ir-core-1`, `alert2ir-postgres-1`, and `alert2ir-splunk_adapter-1`. The independent observability deployment remains the separate functional project `alert2ir-observability`.

The repository target for a managed runtime host is:

```text
/opt/alert2ir/
    releases/<full-git-sha>/
    current -> releases/<full-git-sha>

/etc/alert2ir/
    runtime.env
    secrets/
        splunk-adapter.secret
        velociraptor-api.yaml
```

Release directories contain reviewed repository deployment files. Runtime environment, credentials, and generated configuration remain external so a release path can be replaced or rolled back without copying secrets into a checkout. Operational commands run from `/opt/alert2ir/current` and may use `--env-file /etc/alert2ir/runtime.env`; they do not use `--project-name`.

This is the repository target design, not a claim about the current lab. The current legacy deployment, its data-bearing volume, and its runtime paths remain untouched by Migration A. A separately approved Migration B must inventory them, preserve rollback configuration, and perform the live cutover.

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
| `ALERT2IR_POSTGRES_VOLUME` | Required | Exact pre-existing external Docker volume that owns PostgreSQL data |
| `ALERT2IR_BACKEND` | Optional; defaults to `mock` | Selects exactly `mock` or `velociraptor` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Optional; blank disables external export | OpenTelemetry collector endpoint |
| `ALERT2IR_SPLUNK_ADAPTER_SECRET_SOURCE` | Required by `splunk_adapter` | Absolute protected host path to the shared HMAC secret file; this is a path, never secret bytes |
| `ALERT2IR_VELOCIRAPTOR_API_CONFIG_SOURCE` | Velociraptor mode | Absolute host path to the external API configuration |
| `ALERT2IR_VELOCIRAPTOR_HOST` | Velociraptor mode | One exact canonical `host` target value |
| `ALERT2IR_VELOCIRAPTOR_CLIENT_ID` | Velociraptor mode | Velociraptor client mapped to that host |

`POSTGRES_PASSWORD` and the password embedded in `ALERT2IR_DATABASE_URL` must agree; URL-encode the URL password when necessary. Compose keeps the database on its internal network and injects the connection URL into `core`. The external-volume contract fails interpolation when `ALERT2IR_POSTGRES_VOLUME` is absent, preventing Compose from silently creating a new project-prefixed database volume.

For a fresh deployment only, deliberately create the neutral volume before first startup and set the variable to the same name:

```bash
docker volume create alert2ir-postgres-data
```

An existing deployment must instead use the exact data-bearing volume approved by its migration plan. Changing the Compose project name does not rename or automatically attach a project-prefixed volume. Migration A creates or attaches no volume.

Validate interpolation and the resulting base deployment without starting services:

```bash
docker compose config
```

## Secrets

Do not commit `.env`, database credentials, HMAC material, certificates, private keys, or live host/client mappings. `.env.example` contains names and path placeholders only.

Create one random secret in a protected staging location without placing its value on a command line. A 32-byte random value rendered as hexadecimal provides 64 bytes to the HMAC implementation:

```bash
umask 077
openssl rand -hex 32 > /protected/staging/alert2ir-splunk-adapter.secret
```

Transfer the same file through an approved protected administrative channel to both hosts. Do not independently generate two secrets, and do not reuse a database, Velociraptor, Splunk administrative, or other application credential. On `ir-core`, set `ALERT2IR_SPLUNK_ADAPTER_SECRET_SOURCE` to an absolute path such as `/etc/alert2ir/secrets/splunk-adapter.secret`. The image runs as a non-root `alert2ir` user whose numeric ID must be taken from the reviewed built image rather than guessed:

```bash
sudo install -d -o root -g root -m 0750 /etc/alert2ir/secrets
docker compose build core splunk_adapter
adapter_uid=$(docker compose run --rm --no-deps --entrypoint id splunk_adapter -u)
adapter_gid=$(docker compose run --rm --no-deps --entrypoint id splunk_adapter -g)
sudo install -o "$adapter_uid" -g "$adapter_gid" -m 0400 \
  /protected/staging/alert2ir-splunk-adapter.secret \
  /etc/alert2ir/secrets/splunk-adapter.secret
```

The host file is mounted read-only at `/run/secrets/alert2ir-splunk-adapter`; only that container path is passed to the process. The application rejects a missing, non-regular, unreadable, oversized, or shorter-than-32-byte secret before Uvicorn becomes healthy. Secret bytes are neither copied into the image nor supplied through Compose environment values or command-line arguments. Re-attest the image user and file ownership after a Dockerfile user change.

Velociraptor credentials and certificates remain together in an external API-configuration file. The override mounts the file read-only at `/run/secrets/alert2ir-velociraptor-api.yaml`; the host source path is used only by Compose interpolation and is not passed to the application. The file must be a readable regular file for the non-root application process. It is not copied into the image or stored in a named volume.

## Adapter firewall boundary

Puppet does not own the `ir-core` firewall. A UFW `INPUT` rule alone is not an adequate contract for a Docker-published port because Docker forwards published traffic through its own chains. The reference host uses Docker's `iptables` firewall backend through Ubuntu's `iptables-nft` compatibility implementation. It does not use Docker's experimental native-nftables backend, `iptables-persistent`, `netfilter-persistent`, or the disabled `nftables.service` for this boundary.

The checked-in [`alert2ir-splunk-adapter-firewall.sh`](../tools/linux/alert2ir-splunk-adapter-firewall.sh) reconciles only the two Alert2IR-owned `DOCKER-USER` rules. It requires host `ir-core`, `enp0s8` holding only `192.168.56.63/24`, and the `iptables-nft` implementation. The rules use comments `alert2ir:splunk-adapter:allow` and `alert2ir:splunk-adapter:drop` as ownership markers. Apply always installs a drop before its allow, places the final allow/drop pair at positions 1 and 2, removes older marked copies and the two exact pre-persistence legacy equivalents, and preserves every unrelated rule. The accepted semantics remain:

```bash
sudo iptables -S DOCKER-USER
# -A DOCKER-USER -s 192.168.56.61/32 -i enp0s8 -p tcp \
#   -m conntrack --ctorigdst 192.168.56.63 --ctorigdstport 8091 \
#   -m comment --comment "alert2ir:splunk-adapter:allow" -j ACCEPT
# -A DOCKER-USER -i enp0s8 -p tcp \
#   -m conntrack --ctorigdst 192.168.56.63 --ctorigdstport 8091 \
#   -m comment --comment "alert2ir:splunk-adapter:drop" -j DROP
```

Install the reviewed script and Docker systemd drop-in, reload unit metadata, apply while the existing boundary is still active, and verify:

```bash
sudo install -o root -g root -m 0755 \
  tools/linux/alert2ir-splunk-adapter-firewall.sh \
  /usr/local/sbin/alert2ir-splunk-adapter-firewall
sudo install -o root -g root -m 0755 -d /etc/systemd/system/docker.service.d
sudo install -o root -g root -m 0644 \
  config/firewall/20-alert2ir-splunk-adapter-firewall.conf \
  /etc/systemd/system/docker.service.d/20-alert2ir-splunk-adapter-firewall.conf
sudo systemctl daemon-reload
sudo /usr/local/sbin/alert2ir-splunk-adapter-firewall apply
sudo /usr/local/sbin/alert2ir-splunk-adapter-firewall check
sudo systemd-analyze verify docker.service
systemctl show docker.service -p DropInPaths
```

The systemd drop-in uses `ExecStartPre` to reconcile the boundary after the host-only interface is online but before `dockerd` can restore containers or publish port 8091. The script explicitly creates `DOCKER-USER` when it is absent after boot; it does not rely on a ruleset restore racing Docker chain creation. A failed pre-start check prevents Docker from starting. `ExecStartPost` then requires Docker to report the `iptables` backend and verifies that the first `FORWARD` rule enters `DOCKER-USER`; a failed post-start check fails and stops the Docker start. Docker 29.7.2 on the accepted host preserves the pre-created chain during startup, as separately recorded by reboot acceptance evidence. A Docker/backend upgrade requires re-attestation before relying on this ordering.

Run `apply` repeatedly to reconcile drift; the resulting two owned rules still exist exactly once. `check` is read-only. The Compose bind to `192.168.56.63` prevents publication on the NAT interface, while these rules independently admit only `splunk` (`192.168.56.61`) to the original published destination and drop every other host-only source. HMAC remains required for adapter requests. The canonical API remains host-published only at `127.0.0.1:8000`; this mechanism neither opens nor manages port 8000, UFW policy, Docker-created rules, or unrelated `DOCKER-USER` entries.

For rollback, first stop `splunk_adapter`, confirm no TCP 8091 listener remains, remove only the named Docker drop-in, reload systemd, and invoke the script's narrow removal mode before deleting the installed script:

```bash
docker compose stop splunk_adapter
sudo rm -f /etc/systemd/system/docker.service.d/20-alert2ir-splunk-adapter-firewall.conf
sudo systemctl daemon-reload
sudo /usr/local/sbin/alert2ir-splunk-adapter-firewall remove
sudo rm -f /usr/local/sbin/alert2ir-splunk-adapter-firewall
```

Removal refuses to proceed while port 8091 has a listener and deletes only rules carrying the two Alert2IR ownership comments. It does not flush or remove `DOCKER-USER` and does not alter unrelated host policy.

## Database migration

Migrations are an explicit operator action; application startup does not run them. Build the application image, start PostgreSQL, and apply the repository migration from a one-off `core` container:

```bash
docker compose build
docker compose up -d --wait postgres
docker compose run --rm core alembic upgrade head
```

`alembic upgrade head` is repeatable when the database is already at the required revision. Migration must complete before readiness acceptance.

Durable Execution v1 advances the required revision from `0001_processing_records` to `0002_durable_execution`. Upgrade PostgreSQL first with the reviewed new image/code and migration command, then recreate `core` with that same revision. The migration preserves existing processing UUIDs and completed snapshots, backfills their lifecycle timestamps, leaves idempotency metadata null, and creates no historical execution attempts. Do not start the new application against `0001`; exact-revision readiness rejects it. Do not run the old application against the advanced mutable schema.

## Start the application and source gateway

After configuration validation, migration, protected-secret installation, and firewall review:

```bash
docker compose up -d core splunk_adapter
docker compose ps
```

Both Python services use the same repository Dockerfile and build context and run as its dedicated non-root user. `splunk_adapter` overrides only the container command to run the source-gateway application factory on container port `8091`. It receives `http://core:8000` as its private upstream origin and shares the `alert2ir_private` bridge network with `core`; it receives no database or Velociraptor credentials. Compose starts `core` only after the PostgreSQL healthcheck succeeds, then starts the adapter after the shallow `core` healthcheck succeeds. This ordering does not replace runtime readiness: a later database outage leaves `/healthz` shallow while `/readyz` reports persistence/schema unavailability. A request arriving while core delivery is unavailable receives the existing bounded transient classification; there is no adapter queue or infrastructure retry.

`splunk_adapter` startup fails if its core URL, timeout, or secret file is invalid. Its `/healthz` reports only that configuration loaded and the HTTP process is alive. It does not probe Splunk, core, PostgreSQL, or Velociraptor.

## Deployment acceptance

Require all of the following after startup:

```bash
docker compose ps
curl -fsS http://127.0.0.1:8000/healthz
curl -fsS http://127.0.0.1:8000/readyz
curl -fsS http://192.168.56.63:8091/healthz
docker compose exec splunk_adapter python -c \
  "import urllib.request; urllib.request.urlopen('http://core:8000/healthz', timeout=2).read()"
```

- `core`, `postgres`, and `splunk_adapter` are healthy.
- `/healthz` returns HTTP 200 with `{"status":"ok"}`. This proves process liveness only.
- `/readyz` returns HTTP 200 with `{"status":"ready"}`. This proves PostgreSQL connectivity and the required Alembic/schema revision.
- The adapter health request returns `{"status":"ok"}` without testing dependencies.
- The explicit container-network check proves adapter-to-core name resolution and private health reachability; it is not part of adapter health.

The two Python container healthchecks intentionally call their shallow `/healthz` endpoints. Docker health does not replace the separate core `/readyz` deployment-acceptance check. Readiness does not depend on an investigation backend or the observability platform.

Verify listener isolation on `ir-core` and from the exact lab sources. Record only bounded status results, never signatures or secret bytes:

```bash
ss -ltn '( sport = :8000 or sport = :8091 )'
```

The host must show `127.0.0.1:8000` and `192.168.56.63:8091`, never `0.0.0.0` for either publication. From `splunk`, adapter health must succeed and direct canonical API access must fail:

```bash
curl -fsS --connect-timeout 3 http://192.168.56.63:8091/healthz
curl -fsS --connect-timeout 3 http://192.168.56.63:8000/healthz
```

The second command is expected to fail. From another host-only system such as `dev01`, the first adapter command is expected to be blocked by `DOCKER-USER`. These source tests cannot be replaced by a same-host curl.

After health succeeds, verify the authentication boundary without sending a valid finding. Each request below must return HTTP `401`; the zero digest is intentionally invalid and is not secret material:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'Content-Type: application/json' --data '{}' \
  http://192.168.56.63:8091/v1/splunk/findings

curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'Content-Type: application/json' \
  -H "X-Alert2IR-Timestamp: $(date +%s)" \
  -H 'X-Alert2IR-Signature: v1=0000000000000000000000000000000000000000000000000000000000000000' \
  --data '{}' http://192.168.56.63:8091/v1/splunk/findings

curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'Content-Type: application/json' \
  -H 'X-Alert2IR-Timestamp: 0' \
  -H 'X-Alert2IR-Signature: v1=0000000000000000000000000000000000000000000000000000000000000000' \
  --data '{}' http://192.168.56.63:8091/v1/splunk/findings
```

A separately authorized low-severity signed smoke finding may prove adapter-to-core delivery without requesting investigation. It is optional and must be recorded as a delivery smoke test, not end-to-end acceptance. The high-severity validation marker remains disabled during deployment preflight and must not be executed until a separately authorized end-to-end validation.

After startup, the application launches one bounded failure-isolated reconciliation pass. It does not delay liveness/readiness or wait for every remote operation. Review its bounded telemetry when incomplete work exists.

## Durable processing operation

Every alert caller must send a valid `Idempotency-Key`. Preserve the same key and canonical body when retrying after a lost acknowledgement. A completed replay returns the same processing ID; an active replay returns durable status without creating another attempt.

Inspect one known processing through its returned `Location` path. For a bounded operator-triggered reconciliation pass, use the same application image and environment as the deployment:

```bash
docker compose run --rm core python -m alert2ir.cli reconcile --once
```

This command may plan accepted work, claim planned attempt 1, or poll a known external operation. A stale unknown submission becomes `recovery_required`; the command never blindly resubmits it. It is a one-shot operator mechanism, not a scheduler or worker daemon.

## Investigation backend modes

### Mock/open mode

Base `compose.yaml` defaults `ALERT2IR_BACKEND` to `mock`. This selects one deterministic `MockBackend` with `process.list` capability and requires no external investigation system or credential file. Any Velociraptor application setting in mock mode is rejected.

Use the base commands shown above for configuration, migration, startup, acceptance, restart, and shutdown. The source gateway is independent of backend selection; a valid low/medium finding continues to produce `no_action` under the existing policy.

### Velociraptor mode

Set the three Velociraptor interpolation inputs in the local environment and merge the base file first and the override second:

```bash
docker compose -f compose.yaml -f compose.velociraptor.yaml config
```

Use the same `-f compose.yaml -f compose.velociraptor.yaml` pair on every `build`, `up`, `run`, `restart`, and `down` command for that deployment. The override selects `velociraptor`, mounts the external configuration read-only, and supplies the fixed container path to the application.

Application construction validates the local file and exact host/client mapping but does not connect to Velociraptor. Connection and collection are request-time effects. This mode supports one exact host mapping and the `process.list` application capability; it does not enable discovery, fallback, or multi-backend routing.

## Splunk app package and installation

Build the standalone app only from a reviewed committed revision. The deterministic builder excludes the surrounding Alert2IR source tree, refuses to overwrite an artifact, and reports its complete SHA-256:

```bash
tools/splunk/build-alert2ir-delivery-app.sh <reviewed-git-ref> <existing-output-directory>
```

Transfer the resulting `alert2ir_delivery-<commit>.tgz` and verify its complete hash on `splunk`. Install it under `$SPLUNK_HOME/etc/apps/alert2ir_delivery` with the local Splunk CLI or by an equivalent reviewed archive install, then ensure the tree is owned by the Splunk service account. The package contains only `default/`, `README/`, `metadata/`, `bin/`, and its README; it does not import the Alert2IR application environment.

Repository-owned portable values stay in `default/`. Put the host-specific URL and sender secret path in the untracked/deployed `local/savedsearches.conf`:

```ini
[Alert2IR Investigation Delivery Validation Marker]
disabled = true
enableSched = 0
action.alert2ir_delivery.param.adapter_url = http://192.168.56.63:8091/v1/splunk/findings
action.alert2ir_delivery.param.secret_file = /opt/splunk/etc/auth/alert2ir/alert2ir_delivery.secret
```

Install the same HMAC bytes used by the adapter without placing them in `local/` or any `.conf` file:

```bash
sudo install -d -o splunk -g splunk -m 0700 /opt/splunk/etc/auth/alert2ir
sudo install -o splunk -g splunk -m 0400 \
  /protected/staging/alert2ir-splunk-adapter.secret \
  /opt/splunk/etc/auth/alert2ir/alert2ir_delivery.secret
```

Use the actual Splunk account and `$SPLUNK_HOME` if the lab package differs. Compare the two protected files through a controlled administrative procedure without copying their bytes into logs or Git. The Git-tracked default has blank adapter/secret paths, so missing `local/` configuration fails closed at action execution.

The custom-action registration and app metadata require a Splunk restart after initial installation unless the installed Splunk release documents an equivalent safe reload. Do not put an administrative password in shell history; use the normal protected local administration path. After restart, validate effective configuration without executing the action:

```bash
sudo -u splunk /opt/splunk/bin/splunk btool alert_actions list alert2ir_delivery --debug
sudo -u splunk /opt/splunk/bin/splunk btool savedsearches list \
  'Alert2IR Investigation Delivery Validation Marker' --debug
```

Require the effective saved search to retain `disabled = true` and `enableSched = 0`, the reviewed rule UUID/title/level, per-result delivery, the exact adapter URL, and the protected sender secret path. Confirm `bin/alert2ir_delivery.py` remains executable. Do not run the reserved marker or enable the schedule during deployment preflight.

The HMAC protects authentication and body integrity but does not encrypt HTTP. This is acceptable only on the owned host-only network with exact-interface binding and the source firewall rule above. TLS is required before crossing a broader or untrusted network boundary.

## Observability export

`OTEL_EXPORTER_OTLP_ENDPOINT` is optional. Blank or unset configures no external OpenTelemetry exporter, and the application continues to process requests. A configured endpoint sends application traces and metrics to that collector; the lab deployment points it at the Alloy process local to `ir-core`.

Collector or central-platform unavailability must not become an application dependency: telemetry export is failure-isolated from request processing, and `/readyz` does not check observability. See the [observability operator guide](OBSERVABILITY.md) for the reference Alloy, Prometheus, Loki, Tempo, Grafana, and Alertmanager deployment.

## Data persistence

The logical `postgres_data` mount is backed by the explicit external volume selected by `ALERT2IR_POSTGRES_VOLUME`. Container restart, `docker compose restart core`, application-container recreation, and ordinary Compose down/up preserve that volume. Because it is external, Compose does not create, rename, copy, or delete it.

Use the same Compose file set that started the deployment for normal shutdown:

```bash
docker compose down
```

Start PostgreSQL, reapply the migration command, and start `core` to restore the deployment. Reapplying an already-current migration does not delete processing rows.

## Upgrade or redeploy

For an application revision change:

1. Select a reviewed revision with successful hosted validation and inspect its Compose, environment, dependency, and migration changes.
2. Preserve the runtime environment, external secret/configuration files, and the exact volume selected by `ALERT2IR_POSTGRES_VOLUME`.
3. Run `docker compose config` with the selected Compose file set.
4. Build the application image and ensure PostgreSQL is healthy.
5. Run `docker compose run --rm core alembic upgrade head` with that same file set.
6. Run `docker compose up -d core splunk_adapter` to recreate the Python services when required.
7. Verify container state, both `/healthz` endpoints, core `/readyz`, listener isolation, and firewall behavior.

Migrations are forward-only: neither the baseline nor Durable Execution migration provides a supported downgrade. An older application revision is not compatible with the mutable advanced lifecycle schema. Rollback requires a reviewed data restore or forward repair; retain a verified database backup before upgrade.

## Destructive reset boundary

Normal troubleshooting and shutdown must not remove the external PostgreSQL volume. `docker compose down --volumes` does not own that external resource and is not a database-reset procedure. Any deliberate database reset requires separate destructive authorization, an exact inspected volume name, and an understood recovery plan; this guide intentionally provides no routine removal command.

## Source-gateway rollback

Rollback the source boundary without deleting durable processing data:

1. keep the validation saved search disabled, or disable any later explicitly enabled delivery search;
2. stop only the gateway with `docker compose stop splunk_adapter`;
3. follow the adapter-firewall rollback above to remove the owned Docker drop-in and its two comment-marked `DOCKER-USER` rules;
4. remove the Splunk app only through its normal app lifecycle if the rollback requires it;
5. remove the two protected HMAC files only after both sender and gateway are stopped and no rollback will reuse them.

Do not delete the PostgreSQL volume or Alert2IR processing rows as source-gateway rollback. A prolonged gateway outage can exhaust the sender's bounded three attempts and requires deliberate operator re-dispatch; no durable source queue exists.

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
- `src/alert2ir/adapters/splunk/runtime.py` for adapter process composition and startup validation;
- `integrations/splunk/alert2ir_delivery` for the standalone Splunk application package;
- [`migrations`](../migrations/) and [`alembic.ini`](../alembic.ini) for schema changes;
- [`tests`](../tests/) for executable deployment and application contracts.
