# Puppet Environment

This directory establishes roles/profiles and Hiera conventions for the Alert2IR lab. Its first functional catalog manages only the running and startup state of already-installed Sysmon and Splunk Universal Forwarder services on the two Windows endpoints.

Package installation, telemetry configuration, firewall and network changes, user creation, Docker configuration, and Velociraptor deployment remain outside this initial functional catalog and require separate reviewed and tested follow-up work.

## Layout

- `manifests/site.pp` — explicit node classification entry point
- `modules/role` — node-purpose classes
- `modules/profile` — reusable configuration classes
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

The validated bootstrap artifact was acquired over HTTPS from `artifacts-puppetcore.puppet.com` at `/v1/download` with these request parameters:

| Parameter | Value |
| --- | --- |
| `version` | `8.20.0` |
| `os_name` | `windows` |
| `os_version` | `latest` |
| `os_arch` | `x64` |

The request used HTTP Basic authentication with the literal username `forge-key` and a Puppet Forge API key supplied interactively as the password. Never record the API key, credentials, Authorization header, or shell/session secrets.

Puppet version `8.20.0` was explicitly requested and pinned. The exact resulting `puppet-agent-8.20.0-x64.msi` bytes were validated on `win11-02`, and the recorded SHA-256 and Authenticode signature were independently verified. This provenance is sufficient to promote the same artifact bytes to `win11-01`; any different artifact must be verified separately.

The MSI process exit status was not captured: `$LASTEXITCODE` was inspected only after a later `hostname` invocation.

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
- `modules/`
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

For an enforcing `puppet apply --detailed-exitcodes`, exit code `0` means a successful run with no actual changes, and exit code `2` means a successful run that made actual changes. Exit codes `1`, `4`, and `6` are failure-bearing outcomes and must not be treated as successful convergence.

For `puppet apply --noop --detailed-exitcodes`, the exit code alone is not sufficient evidence that no drift exists. Simulated corrective changes are reported in Puppet's noop output or report, and WS02 validation must inspect that evidence for pending changes. Puppet 8.20.0 returned exit code `0` during the validated WS02 drift-detection noop described below while reporting a simulated corrective change. This observed behavior does not establish that noop always returns `0` when drift exists; operationally, a noop exit code of `0` does not by itself prove convergence.

### Validated functional canary evidence

The first functional catalog was runtime-validated with the following evidence:

| Item | Validated value |
| --- | --- |
| Endpoint | `win11-02` |
| Puppet version | `8.20.0` |
| Functional catalog commit | `646fa6bb310bcf95a384f21b2d03ad8ca027bc23` |
| Artifact | `alert2ir_ws02-646fa6bb310b.zip` |
| Artifact SHA-256 | `2b5af50b337e9dfde287d8f5f6e6c33630b73ddf4741a3a75c94fd7a6a198ade` |

The observed validation sequence was:

1. A functional noop on the already-compliant services succeeded with exit code `0` and no corrective events.
2. An enforcing apply on the already-compliant services succeeded with exit code `0` and no changes.
3. Harmless drift was introduced by manually changing `SplunkForwarder` startup mode from `Automatic` to `Manual`; the service remained `Running`.
4. The drift-detection noop reported `enable changed 'manual' to 'true' (noop)` and returned exit code `0`; `SplunkForwarder` remained `Running` and `Manual` after the noop.
5. A repairing apply restored `Automatic` startup and returned exit code `2`; `SplunkForwarder` remained `Running`.
6. A final noop returned exit code `0` with no corrective events.
7. Final managed state was `Sysmon64` `Running`/`Automatic`, `SplunkForwarder` `Running`/`Automatic`, and Puppet Agent `Stopped`/`Disabled`.
8. Splunk verification confirmed that current Sysmon telemetry continued after the drift and repair test.

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
