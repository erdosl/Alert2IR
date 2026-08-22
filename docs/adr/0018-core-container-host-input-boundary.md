# ADR 0018: Core container to host INPUT boundary

**Status:** Accepted for repository configuration; live cutover pending

## Context

The Alert2IR `core` container must reach two native services on `ir-core`: the Velociraptor API on TCP `8001` and the local Alloy OTLP receiver on TCP `4317`. Docker-assigned container addresses and network-ID-derived Linux bridge names are not stable identities. The previous UFW allowances trusted entire Docker `/16` networks, which also authorized sibling containers even though the intended principal is the `core` container alone.

Container connections to the native listeners retain their container source address and enter the host `INPUT` path on the application bridge. This differs from the Docker NAT and forwarding path used by the published Splunk adapter port.

## Decision

Evolve the existing `alert2ir_private` Compose network rather than adding a second `core` network. Configure explicit IPv4 IPAM with subnet `172.30.63.0/28`, gateway `172.30.63.1`, Docker dynamic allocation range `172.30.63.8/29`, static `core` address `172.30.63.2`, and Linux bridge name `alert2ir-prv0`. Static identity is not sufficient by itself: `core` address `172.30.63.2` is outside the dynamic allocation range so a dependency or sibling container cannot consume the firewall principal before `core` claims it.

The runtime network name `alert2ir_alert2ir_private` is derived from effective Compose project name `alert2ir`. Because Compose project-name inputs can override the top-level declaration, canonical deployment rejects a non-empty `COMPOSE_PROJECT_NAME` and any effective project name other than exactly `alert2ir` before it tears down containers or networks or changes UFW. It does not use `-p`, `--project-name`, or an explicit runtime network-name override.

UFW remains the host `INPUT` authority. It admits only `172.30.63.2/32` arriving on `alert2ir-prv0` to `192.168.56.63:8001/tcp` and `192.168.56.63:4317/tcp`. Existing default INPUT deny rejects new connections from `splunk_adapter`, `postgres`, and other sources. The whole Docker subnet is not authorized.

Persistence remains owned by `ufw.service` and UFW's stored rule state. This boundary adds no raw iptables or nftables reconciler, systemd unit, or Puppet firewall resource.

The adapter continues to resolve and call `http://core:8000` through Compose DNS. The native-service destinations remain `192.168.56.63:8001` and `192.168.56.63:4317`; no application endpoint or native-service binding changes.

The firewall authorities remain separate:

```text
core -> native ir-core :8001/:4317
  = UFW / INPUT

Splunk -> Docker-published ir-core :8091
  = existing DOCKER-USER reconciler
```

The `:8091` helper, ownership markers, ordering, systemd persistence, and source restriction do not change.

## Consequences

The firewall principal and ingress bridge become stable and source-specific without multi-homing `core`, changing application endpoints, or restarting Docker, containerd, Alloy, or Velociraptor. The constrained dynamic range reserves the static principal without assigning static sibling addresses. Compose DNS and the existing adapter-to-core relationship remain intact.

The application network must be replaced once, which necessarily recreates `core`, `splunk_adapter`, and `postgres`; the external PostgreSQL volume remains unchanged. Deployment must repeat the route, Docker IPAM, VirtualBox, and lab-private collision check immediately before cutover. Before any teardown or firewall mutation, deployment fails closed unless UFW is active, configured and effective INPUT policy is deny/drop, the four historical broad rules are exactly understood, and no additional earlier ACCEPT can admit a fresh unauthorized connection to either native port. UFW's active default INPUT deny remains part of acceptance and persistence testing.

## Rejected alternatives

- Authorizing `172.30.63.0/28` would trust sibling containers instead of the exact `core` principal.
- A dynamic `core` address or Docker-generated `br-<network-id>` name would not provide durable firewall identity.
- A second network would multi-home `core` and introduce default-route and source-selection complexity without a material benefit.
- `DOCKER-USER` is not the packet path for these native listeners.
- Rebinding Velociraptor or Alloy to Docker addresses would couple native services to Docker and require unnecessary service changes.
- Puppet firewall ownership or a general firewall rewrite would overlap the established UFW authority.
- `enp0s8` identifies the current host-only attachment but is not the container trust identity.
