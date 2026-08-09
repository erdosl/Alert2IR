# Authorized Lab Scope

## Authorization boundary

Security-testing activity for Alert2IR is authorized only on the owned `192.168.56.0/24` lab and these systems:

- `win11-01` (`192.168.56.60`)
- `splunk` (`192.168.56.61`)
- `win11-02` (`192.168.56.62`)
- `ir-core` (`192.168.56.63`)
- `dev01` (`192.168.56.64`)

Permitted activity includes controlled attack simulation, security telemetry generation, detection testing, defensive investigation, forensic acquisition, response testing, and security-control validation.

External systems, Internet targets, third-party infrastructure, and any unauthorized systems are out of scope. NAT interfaces may be used for ordinary software installation and updates, but attack simulations must never target systems outside the owned lab. Host aliases do not expand authorization. In particular, `.admin` aliases use the same host-only interfaces and are not a separate management network.

The physical Ubuntu host is infrastructure-only and is not an attack-simulation target. Work must respect the purpose and ownership of every system even when an address falls within the subnet.

