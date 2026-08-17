# ADR 0014: Use dev01 authoritative DNS with endpoint-local Windows NRPT

**Status:** Accepted

## Context

Event 22 acceptance was blocked because neither Windows endpoint had NRPT and the only usable DNS service was `10.0.2.3` on the NAT interface. Sending the owned test name through that resolver could forward it outside the host-only lab and did not provide a fail-closed namespace boundary.

Implementation re-attestation also found UFW inactive with default incoming deny, no stored allowances, and the active `dev01` management path sourced from `192.168.56.1`. Enabling only DNS rules would have risked management lockout.

## Decision

Run Ubuntu's native BIND 9 package on `dev01` as authoritative-only for `alert2ir.test.`. Bind UDP and TCP 53 only to `192.168.56.64` on `enp0s8`; disable IPv6 listening, recursion, forwarding, dynamic update, transfer, and external resolution. Allow authoritative queries only from exact clients `win11-01` (`192.168.56.60`) and `win11-02` (`192.168.56.62`).

Create one local Windows NRPT rule per endpoint for `.alert2ir.test` to `192.168.56.64`. Leave interface DNS, routing, ordinary DNS, GPO, DirectAccess, and VPN policy unchanged. An unavailable authoritative server must cause the owned lookup to fail rather than fall back to any other resolver.

Keep UFW default-deny and allow exactly the four endpoint/protocol DNS tuples plus exact host-only management SSH from `192.168.56.1` to `192.168.56.64:22`. The management source is not a DNS client. Default rollback retains this SSH exception unless an alternate management path is independently verified.

## Alternatives rejected

- Hosts files do not exercise DNS telemetry or prove resolver containment.
- Public DNS and the NAT resolver violate the owned, fail-closed namespace boundary.
- Replacing interface DNS would couple unrelated name resolution to a lab-only authoritative service.
- CoreDNS, dnsmasq, Unbound, and a containerized service add a different runtime or weaker fit when packaged native BIND directly supplies authoritative-only behavior.
- Active Directory/GPO adds an unneeded control plane; local NRPT is sufficient for two endpoints.
- Puppet ownership is unnecessary for this bounded infrastructure workstream and would expand its current endpoint catalog boundary.

## Consequences

The lab owns a narrow split-DNS dependency on `dev01`; ordinary client DNS remains independent. BIND configuration, exact firewall/NRPT contracts, validation, and rollback are repository-controlled, while raw pre-state and packet captures remain outside Git. DNS infrastructure readiness does not validate Event 22 itself or resolve the separate PowerShell wrapper execution prerequisite.
