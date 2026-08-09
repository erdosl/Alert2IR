# ADR 0008: Initial lab boundaries

**Status:** Accepted

## Context

Security testing requires an unambiguous authorization boundary, and Active Directory would add complexity unrelated to initial goals.

## Decision

Keep the initial lab on the owned `192.168.56.0/24` VirtualBox host-only network and do not deploy Active Directory initially. Security testing is limited to the owned systems documented in `docs/LAB_SCOPE.md`.

## Consequences

Initial scenarios must work without domain services. NAT is for ordinary installation and updates, not external attack simulation; aliases do not expand scope.

