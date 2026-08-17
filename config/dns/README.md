# Alert2IR authoritative DNS contract

[`alert2ir-dns.json`](alert2ir-dns.json) is the closed machine-readable authority for the `dev01` listener, the two approved DNS clients, the `alert2ir.test.` zone, and the five exact UFW exceptions. It points to the separate exact Windows authority at `config/windows/nrpt-alert2ir.test.json` instead of duplicating NRPT values. The management source is a firewall exception only and is deliberately absent from the BIND client ACL.

The BIND files define an authoritative-only service. They contain no root hints, recursion, forwarder, dynamic update, transfer, wildcard, reverse zone, IPv6 listener, or NAT listener. The zone serial uses `YYYYMMDDnn`: use the UTC change date and increase the two-digit sequence for every same-day published change. Never decrease a published serial.

Validate repository content with:

```bash
tools/linux/validate-alert2ir-dns.sh repository
```

`provision-alert2ir-dns.sh` supports read-only `check`, idempotent `apply`, and owned-state `remove`. The `firewall-stage` and `firewall-enable` safety submodes permit inspection between storing rules and activating a previously inactive default-deny policy. Use `remove --dry-run` to resolve exact rollback targets without changing state. Default removal retains the management SSH rule so rollback cannot silently remove the active administrative path. `remove --remove-management-rule` requires an explicitly verified alternate management path. Package purge is a separate `--purge-packages` option.

The deployment uses `/etc/bind/alert2ir/` plus one Alert2IR-owned systemd drop-in. It does not edit Ubuntu's packaged `named.conf*` files, `/etc/resolv.conf`, or `systemd-resolved` configuration.

The live sanitized acceptance record is `validation/infrastructure/dns/dns-infrastructure-2f770f89-d84f-47b9-a633-17e42454b01c.json`. It classifies DNS/NRPT infrastructure as **VALIDATED-LIVE** while recording that Event 22 attack simulation was not run.
