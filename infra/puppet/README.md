# Puppet Environment

This directory establishes roles/profiles and Hiera conventions for the Alert2IR lab. It is intentionally inert: the classes contain no resources, and `site.pp` performs no node classification yet.

Actual package installation, Sysmon and Splunk Universal Forwarder management, firewall and network changes, user creation, Docker configuration, and Velociraptor deployment belong to later workstreams and require review and testing before they are added.

## Layout

- `manifests/site.pp` — eventual node classification entry point
- `site-modules/role` — node-purpose classes
- `site-modules/profile` — reusable configuration classes
- `data/common.yaml` and `data/nodes/` — Hiera data, currently empty

Never store secrets or credentials in Hiera or elsewhere in the repository. Use an approved secret-management approach when a demonstrated requirement exists.

## WS02 control model

Workstream 02 uses standalone `puppet apply`. Catalog execution is deliberate and human-triggered from an elevated PowerShell session. The Puppet Agent Windows service remains disabled, and `puppet agent` is not the WS02 control mechanism.

This phase does not introduce Puppet Server, Puppet CA or certificate enrollment, scheduled agent convergence, or a dependency on port 8140. The `puppet apply` model is an operating decision for WS02, not the permanent Alert2IR Puppet architecture; it neither permanently rejects nor selects Puppet Server for later work.

`win11-02` is the canary endpoint. Promote the catalog to `win11-01` only after it has been successfully validated on `win11-02`.

## Puppet bootstrap

Puppet itself is bootstrap and provisioning state during WS02. Puppet does not manage its own installation. Bootstrap both Windows endpoints with the same validated, pinned x64 Puppet Core Windows MSI obtained through the official distribution mechanism. Never use an unpinned `latest` installer, and never commit distribution credentials, tokens, or other secrets.

Install the MSI with the property:

```text
PUPPET_AGENT_STARTUP_MODE=Disabled
```

The validated `win11-02` canary evidence is:

| Item | Observed value |
| --- | --- |
| Endpoint | `win11-02` |
| Puppet version | `8.20.0` |
| Installer filename | `puppet-agent-8.20.0-x64.msi` |
| Installer SHA-256 | `40358285884F7496AC6477DB4FEC08025392DB00BD1D553713AD2A70CAB84142` |
| Authenticode status | `Valid` |
| Authenticode signer | `Perforce Software, Inc.` |
| Service name | `puppet` |
| Service display name | `Puppet Agent` |
| Service state | `Stopped` |
| Service start mode | `Disabled` |
| Service account | `LocalSystem` |

The MSI process exit status was not captured: `$LASTEXITCODE` was inspected only after a later `hostname` invocation. The validated hash, signature, and version identify the tested artifact, but its actual download or source location is not recorded in this repository. Record that source provenance before promotion to `win11-01`.

## Observed Windows Puppet settings

Runtime inspection of Puppet 8.20.0 on `win11-02` reported:

| Setting | Observed value |
| --- | --- |
| `codedir` | `C:/ProgramData/PuppetLabs/code` |
| `environmentpath` | `C:/ProgramData/PuppetLabs/code/environments` |
| `basemodulepath` | `C:/ProgramData/PuppetLabs/code/modules;C:/Program Files/Puppet Labs/Puppet/puppet/modules` |
| `confdir` | `C:/ProgramData/PuppetLabs/puppet/etc` |
| Default environment | `production` |

These paths are WS02 runtime evidence from one installation, not abstract project architecture or proof that the observed endpoint state is desired state.

The observed `puppet.conf` on `win11-02` was:

```ini
[main]
server=puppet
autoflush=true
manage_internal_file_permissions=false
```

Do not change or normalize those settings as part of the WS02 documentation/bootstrap work. Choosing standalone `puppet apply` for WS02 does not imply that the configured `server` setting is used.

## Node identity and Hiera

Puppet's implicit certname on `win11-02` was an environment-derived FQDN rather than the repository's desired short node key. Do not depend on a certname derived from the guest environment. Every standalone WS02 run must explicitly provide the appropriate short identity:

```text
--certname win11-01
--certname win11-02
```

The override was runtime-tested on `win11-02` and resolved to `win11-02`. Supplying it is required so the existing `nodes/%{trusted.certname}.yaml` Hiera hierarchy deterministically selects the intended per-node file. Do not modify Puppet's global certname solely for this workflow unless a later design decision requires it.

## Code delivery and directory environment

`dev01` remains the development and administration system. Code executed on an endpoint must originate from a reviewed Git revision. Stage the repository's `infra/puppet` directory as a Puppet directory environment while preserving:

- `environment.conf`
- `hiera.yaml`
- `manifests/`
- `site-modules/`
- `data/`

Record the Git commit ID and the staged artifact hash as execution evidence. The Windows endpoints do not require Git or Codex, and this document does not prescribe the artifact transport. A final staging environment name and path have not yet been runtime-tested and are therefore not specified. If a temporary WS02-specific Puppet environment name is needed in later examples, use a Puppet-valid name such as `alert2ir_ws02`.

## Validation workflow

For each catalog revision:

1. Verify that the staged code corresponds to the reviewed Git revision.
2. Verify the staged artifact and its hash.
3. Verify the Puppet runtime and version.
4. Verify that the Puppet Agent service is `Stopped` and `Disabled`.
5. Explicitly supply the intended short certname.
6. Run the intended catalog with `--noop` and `--detailed-exitcodes`.
7. Review every proposed change.
8. Apply on `win11-02`.
9. Verify the managed Windows state.
10. Verify the relevant Sysmon and Splunk telemetry.
11. Run the catalog again and require no corrective changes.
12. Introduce deliberate, harmless drift in managed state.
13. Verify that a no-op run detects the drift.
14. Apply the catalog and verify that Puppet repairs the drift.
15. Verify that telemetry remains healthy.
16. Repeat the validation and promote on `win11-01`.
17. Review the Git diff before any commit or push.

With `--detailed-exitcodes`, exit code `0` means success with no changes and `2` means success with changes. Exit codes `1`, `4`, and `6` indicate failure conditions and must not be treated as successful convergence.

## First functional catalog boundary

The first functional WS02 catalog will manage selected desired state for already-installed telemetry components. Observed endpoint state is evidence to classify and review; it does not automatically define desired state.

The following remain explicitly outside that first catalog:

- Puppet self-management or package management
- Sysmon installer or package acquisition
- Splunk Universal Forwarder installer or package acquisition
- Windows guest networking
- VirtualBox NIC configuration
- Hostname management
- Time-sync policy
- Splunk deployment server
- Splunk-generated product defaults such as `serverName`
- Unrelated Windows hardening
- Atomic Red Team
- Velociraptor
- Binalyze AIR
- CrowdStrike
- Alert2IR application implementation
- Active Directory

Installer and package lifecycle management for Sysmon and Splunk Universal Forwarder may be added later, after installer provenance and version policy are deliberately designed. This boundary does not claim that guest networking or time synchronization is solved.
