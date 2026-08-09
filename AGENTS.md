# Contributor and Agent Guide

Git-tracked documentation is the source of truth. Before working, read the documents relevant to the change: `docs/PROJECT.md`, `docs/ARCHITECTURE.md`, `docs/LAB.md`, `docs/LAB_SCOPE.md`, `docs/ROADMAP.md`, and applicable records in `docs/adr/`.

- Preserve vendor neutrality and never assume a commercial platform is available.
- Never commit credentials, secrets, or private environment data.
- Keep security testing within the owned lab scope documented in `docs/LAB_SCOPE.md`.
- Prefer the simplest architecture that satisfies a demonstrated requirement.
- Do not add infrastructure or dependencies merely because they may be useful later.
- Update documentation and ADRs when architectural decisions materially change.
- Inspect and preserve existing user work; never silently overwrite it.

