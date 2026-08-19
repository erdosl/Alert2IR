# ADR 0017: Canonical deployment identity and stable runtime layout

**Status:** Accepted for repository configuration; live cutover pending

## Context

Temporary development identifiers entered checkout names, Compose project identity, generated resource names, operator documentation, and observability filters. That coupling obscures deployment provenance and makes a source checkout name appear to be product identity. Compose's default project-scoped volume naming also makes a project rename dangerous because a new project name does not automatically attach the existing PostgreSQL data.

The repository change and the live resource cutover have different risk profiles. Repository configuration can establish the target contract without stopping services or touching data. The live deployment must use a separately reviewed migration with a rollback window and an exact inventory of its data-bearing volume and external configuration.

## Decision

- The canonical application Compose project name is `alert2ir`.
- Compose generates service container and application-network names; the repository does not set `container_name`.
- Stable release paths use the full Git revision, for example `/opt/alert2ir/releases/<full-git-sha>` with `/opt/alert2ir/current` selecting the reviewed release. Dates, branches, and internal development labels are not deployment identity.
- Runtime environment and protected configuration remain external to release directories. The repository target is `/etc/alert2ir/runtime.env` with protected files under `/etc/alert2ir/secrets/`, subject to host conventions and a separately reviewed deployment procedure.
- PostgreSQL data identity is explicit. `ALERT2IR_POSTGRES_VOLUME` selects a pre-existing external Docker volume; a fresh deployment uses the neutral intended name `alert2ir-postgres-data` after that volume is deliberately created.
- Git history remains unchanged. Earlier development terminology and original validation evidence stay available through history instead of defining the current product tree.
- Migration A changes repository contracts only. Renaming or recreating live containers, attaching the existing data volume to the canonical project, moving host configuration, and retiring old resources belong to the separately approved Migration B.

## Consequences

Normal future Compose commands do not need `--project-name`. Rendered service names derive predictably from `alert2ir`, while the separate `alert2ir-observability` project remains independent. Operators must provide an explicit PostgreSQL volume name, which makes accidental initialization of a new empty project-prefixed volume less likely.

Fresh deployment now requires deliberate volume creation before startup. Migration B must point `ALERT2IR_POSTGRES_VOLUME` at the exact existing data-bearing volume or use a separately approved offline copy. It must never allow two PostgreSQL instances to open the same data directory concurrently. The old release checkout, runtime environment, protected files, and deployment definition remain available until canonical validation and the rollback window are complete.
