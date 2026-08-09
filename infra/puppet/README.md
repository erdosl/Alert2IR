# Puppet Environment

This directory establishes roles/profiles and Hiera conventions for the Alert2IR lab. It is intentionally inert: the classes contain no resources, and `site.pp` performs no node classification yet.

Actual package installation, Sysmon and Splunk Universal Forwarder management, firewall and network changes, user creation, Docker configuration, and Velociraptor deployment belong to later workstreams and require review and testing before they are added.

## Layout

- `manifests/site.pp` — eventual node classification entry point
- `site-modules/role` — node-purpose classes
- `site-modules/profile` — reusable configuration classes
- `data/common.yaml` and `data/nodes/` — Hiera data, currently empty

Never store secrets or credentials in Hiera or elsewhere in the repository. Use an approved secret-management approach when a demonstrated requirement exists.

