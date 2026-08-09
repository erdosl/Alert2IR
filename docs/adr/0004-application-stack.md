# ADR 0004: Core application stack

**Status:** Accepted

## Context

The orchestration service needs an API-oriented implementation language and durable relational persistence.

## Decision

Use Python and FastAPI for the planned core application and PostgreSQL for planned persistent storage.

## Consequences

Application conventions, migrations, and tests will target this stack. This decision does not authorize implementation during the repository bootstrap.

