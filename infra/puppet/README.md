# Puppet Environment

This directory establishes roles/profiles and Hiera conventions for the Alert2IR lab. The first functional catalog manages the running and startup state of already-installed Sysmon and Splunk Universal Forwarder services on the two Windows endpoints. The second narrow convergence slice additionally stages the project-owned Sysmon XML bytes without applying them to Sysmon's active configuration.

Package installation, active Sysmon configuration, complete Splunk local configuration ownership, firewall and network changes, user creation, Docker configuration, and Velociraptor deployment remain outside this intentionally narrow catalog. They are not prerequisites for WS02 closure.

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

The explicit certname selects Puppet data; it does not prove which physical endpoint is running the command. Before every endpoint Puppet execution, independently verify both operational identity signals:

```powershell
$env:COMPUTERNAME

Get-NetIPAddress -AddressFamily IPv4 |
Where-Object { $_.IPAddress -like '192.168.56.*' } |
Select-Object IPAddress, InterfaceAlias
```

The intended computer name and host-only IPv4 must match this inventory:

| Computer name | Host-only IPv4 |
| --- | --- |
| `WIN11-01` | `192.168.56.60` |
| `WIN11-02` | `192.168.56.62` |

Stop before running Puppet if either value does not match the intended endpoint. This is a mandatory operational validation guard, not Puppet ownership of the hostname or network configuration; both remain unmanaged.

## Code delivery and directory environment

`dev01` remains the development and administration system. Code executed on an endpoint must originate from a reviewed Git revision. Build the WS02 directory-environment ZIP with:

```bash
tools/puppet/build-ws02-puppet-artifact.sh <reviewed-git-ref> [output-directory]
```

The builder materializes `infra/puppet` from the resolved commit, not from the working tree, and preserves these paths at the extracted environment root:

- `environment.conf`
- `hiera.yaml`
- `manifests/`
- `modules/`
- `data/`

During artifact assembly, the builder reads the canonical `config/sysmon/alert2ir-sysmon.xml` from that same commit and writes it only inside the temporary environment as `modules/profile/files/sysmon/alert2ir-sysmon.xml`. There is no second Git-tracked copy. The resulting file is available to the catalog as `puppet:///modules/profile/sysmon/alert2ir-sysmon.xml`.

Record the reported Git commit ID, artifact SHA-256, and staged Sysmon XML SHA-256 as execution evidence. The Windows endpoints do not require Git or Codex, and this document does not prescribe the artifact transport. A final staging environment name and path have not yet been runtime-tested and are therefore not specified. If a temporary WS02-specific Puppet environment name is needed in later examples, use a Puppet-valid name such as `alert2ir_ws02`.

## Staged Sysmon configuration boundary

The second narrow WS02 convergence slice creates `C:\ProgramData\Alert2IR` and `C:\ProgramData\Alert2IR\Sysmon`, then manages the canonical XML bytes at `C:\ProgramData\Alert2IR\Sysmon\alert2ir-sysmon.xml`. It does not manage owner, group, mode, or Windows ACL policy, and it does not purge, recurse over, or otherwise manage unrelated files in either directory.

Staging the XML is not convergence of Sysmon's active configuration. No file relationship invokes `Sysmon64.exe -c`, reloads or restarts `Sysmon64`, or changes the Sysmon Operational channel. Active-configuration drift detection and conditional application remain explicitly deferred. Validate file deployment on `win11-02` first; only the exact same reviewed artifact bytes may then be promoted to `win11-01`.

## Validation workflow

For each catalog revision:

1. Verify that the staged code corresponds to the reviewed Git revision.
2. Verify the staged artifact and its hash.
3. Verify the Puppet runtime and version.
4. Verify that the Puppet Agent service is `Stopped` and `Disabled`.
5. Before every Puppet execution, verify that `$env:COMPUTERNAME` and the host-only IPv4 both match the intended endpoint inventory above.
6. Explicitly supply the intended short certname.
7. Run the intended catalog with `--noop` and `--detailed-exitcodes`.
8. Review every proposed change.
9. Apply on `win11-02`.
10. Verify the managed Windows state.
11. Verify the relevant Sysmon and Splunk telemetry.
12. Run the catalog again and require no corrective changes.
13. Introduce deliberate, harmless drift in managed state.
14. Verify that a no-op run detects the drift.
15. Apply the catalog and verify that Puppet repairs the drift.
16. Verify that telemetry remains healthy.
17. Repeat the validation and promote on `win11-01`, repeating the physical-identity guard before execution.
18. Review the Git diff before any commit or push.

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

### Validated win11-01 promotion and cross-endpoint reproducibility

The exact `alert2ir_ws02-646fa6bb310b.zip` catalog artifact bytes validated on `win11-02` were promoted unchanged to `win11-01`. The artifact corresponds to functional catalog commit `646fa6bb310bcf95a384f21b2d03ad8ca027bc23` and has SHA-256 `2b5af50b337e9dfde287d8f5f6e6c33630b73ddf4741a3a75c94fd7a6a198ade`.

Both endpoints use Puppet `8.20.0` from the same `puppet-agent-8.20.0-x64.msi` bytes, with SHA-256 `40358285884F7496AC6477DB4FEC08025392DB00BD1D553713AD2A70CAB84142`. On both endpoints, the Puppet Agent Windows service remains `Stopped`, `Disabled`, and configured to run as `LocalSystem`.

The `win11-01` promotion explicitly used standalone identity `--certname win11-01`. The promotion noop compiled successfully, returned exit code `0`, and reported no corrective noop events. The enforcing apply compiled successfully, returned exit code `0`, and made no changes. The final noop compiled successfully, returned exit code `0`, and reported no corrective noop events.

Final managed state on `win11-01` was `Sysmon64` `Running`/`Automatic`, `SplunkForwarder` `Running`/`Automatic`, and Puppet Agent `Stopped`/`Disabled`. Splunk verification after promotion confirmed that expected active Sysmon event classes continued to arrive; transient event counts are validation observations, not desired state.

The first functional Windows endpoint Puppet slice is therefore validated across the `win11-02` canary and the `win11-01` promotion. This demonstrates reproducibility of the same Puppet 8.20.0 runtime artifact, the same Git-derived Puppet catalog artifact, and the same desired service state on both Windows endpoints. `win11-02` performed the deliberate harmless startup-mode drift test; `win11-01` did not repeat it because promotion tested reproducibility of the already-validated runtime and catalog.

That first-slice conclusion is limited to managing `Sysmon64` as `Running`/`Automatic` and `SplunkForwarder` as `Running`/`Automatic`. Its validation did not cover the staged-file slice documented below or claim convergence of Sysmon's active configuration, implementation of Splunk inputs or outputs management, package lifecycle management, networking, or time synchronization.

### Validated staged Sysmon configuration slice

The second narrow Puppet convergence slice was runtime-validated on both Windows endpoints from this exact implementation provenance:

| Item | Validated value |
| --- | --- |
| Git commit | `88f0e8fddca1837cf221ede5f2d8b4c99e8913d9` |
| Commit message | `feat: stage Sysmon config with Puppet` |
| Artifact | `alert2ir_ws02-88f0e8fddca1.zip` |
| Artifact SHA-256 | `48085012ab89f8898e9beee61c0f0ad21b3ca068c5b9e10ced0ac3818927a436` |
| Canonical and staged XML SHA-256 | `71b792bfdbe3e3fc0ede56a6b9dd680c0a708c06130f54d1fa5b9c15267b9932` |

The exact same ZIP bytes were used unchanged for the `win11-02` canary and `win11-01` promotion. Temporary extraction paths are execution details, not portable desired state.

On physical endpoint `win11-02` (`192.168.56.62`), Puppet Core `8.20.0` ran as standalone `puppet apply` with explicit `--certname=win11-02`. The target `C:\ProgramData\Alert2IR\Sysmon\alert2ir-sysmon.xml` was initially absent. The initial noop compiled successfully, exited `0`, and proposed exactly `C:/ProgramData/Alert2IR`, `C:/ProgramData/Alert2IR/Sysmon`, and the target XML with its canonical content hash. It proposed no `Sysmon64` or `SplunkForwarder` correction and did not create the target. The first enforcing apply exited `2`, created exactly those three resources, and deployed the canonical XML. A second enforcing apply exited `0` with no corrective changes, and the XML remained canonical.

For the canary drift test, a comment was appended only to the staged managed XML; active Sysmon configuration was not modified. The drifted file SHA-256 was `7bf1831f457bc4d77108c5188bf31b90387fa75b5555c7a2b013129ac8dacba5`. A drift noop exited `0` while explicitly proposing replacement of the drifted content with the canonical SHA-256, proposed no other correction, and left the drifted file unchanged. The repairing apply exited `2` and restored the canonical XML. The final noop exited `0` with no corrective resource events, and the final XML SHA-256 was canonical. This reinforces the existing finding that noop exit `0` alone is not proof of convergence: simulated corrective events in the report or output must be inspected.

During the canary, the Sysmon event ID 16 count was `0`. `Sysmon64` remained `Running`/`Automatic`/`LocalSystem`; `SplunkForwarder` remained `Running`/`Automatic`/`NT SERVICE\SplunkForwarder`; and Puppet Agent remained `Stopped`/`Disabled`/`LocalSystem`. Current Sysmon telemetry remained available in Splunk.

Before promotion, the physical identity of `win11-01` (`192.168.56.60`) was explicitly verified independently of Puppet certname. Puppet Core `8.20.0` ran as standalone `puppet apply` with explicit `--certname=win11-01`. The received artifact and embedded XML matched the SHA-256 values above, and the target was initially absent. The promotion noop exited `0`, proposed exactly the same three resources as the canary, and proposed no service or unrelated correction. The enforcing promotion exited `2`, created the three intended resources, and deployed the canonical XML. The final promotion noop exited `0` with no corrective events.

During promotion, the Sysmon event ID 16 count was `0`. `Sysmon64`, `SplunkForwarder`, and Puppet Agent retained the same respective service state, startup mode, and accounts recorded for the canary. Current Sysmon telemetry continued arriving in Splunk; transient telemetry counts are not desired state or promotion requirements.

#### Physical-identity safety finding

During promotion preparation, commands intended for `win11-01` were accidentally run in the existing `win11-02` PowerShell session while Puppet was explicitly given `--certname=win11-01`. Puppet compiled successfully as `win11-01` even though the physical machine was `WIN11-02` at `192.168.56.62`. Because that endpoint was already converged, the mistaken noop and apply reported no corrective events and required no rollback.

This demonstrates that `trusted.certname` and `--certname` are not sufficient proof of physical endpoint identity in the standalone WS02 workflow. The computer-name and host-only-IPv4 check documented above is therefore mandatory before endpoint Puppet execution. It is an operational guard only and does not change the accepted boundary that Puppet leaves networking and hostname unmanaged.

The second narrow Puppet slice is validated across both Windows endpoints. The cumulative validated WS02 Puppet boundary now covers:

- Previously validated first-slice controls: `Sysmon64` `Running`/`Automatic` and `SplunkForwarder` `Running`/`Automatic`.
- Newly validated second-slice control: the project-owned canonical Sysmon XML staged at `C:\ProgramData\Alert2IR\Sysmon\alert2ir-sysmon.xml`, with staged-file content drift detected and repaired idempotently and the same Git-derived artifact reproducing the result on both endpoints.

Puppet Agent `Stopped`/`Disabled` remains the accepted WS02 execution and control model; it is not a resource newly managed by this slice.

Together, the two validated slices satisfy the documented WS02 boundary and WS02 is complete. Active Sysmon semantic convergence was investigated and deferred because `Sysmon64.exe -c` is not a trustworthy full semantic comparator; no heuristic comparator is implemented. Other non-blocking deferred enhancements are Sysmon Operational channel ownership, safe ownership or migration of Splunk `inputs.conf` and `outputs.conf`, Event Log Readers membership management, package and installer lifecycle, time-sync desired state if a timing problem is demonstrated, and deeper rebuild automation.

Puppet Server, Puppet CA/enrollment, scheduled Puppet Agent convergence, Windows networking, VirtualBox vNIC ownership, and SSH/key/firewall lab administration are explicit WS02 non-goals. The current catalog does not own the complete Splunk local configuration files.

## WS06 tested roles/profiles validation

WS06 added deterministic repository contracts around the existing roles/profiles implementation without changing its manifests or ownership. The exact validated implementation provenance is:

| Item | Validated value |
| --- | --- |
| Git commit | `8227653814dd25e938ee7ff04849d11968285ca5` |
| Commit message | `test: add Puppet desired-state contracts` |
| Artifact | `alert2ir_ws02-8227653814dd.zip` |
| Artifact SHA-256 | `a13e4b9a5afcab7c8d6a5a8ee69ca36c82f35d40eff944d0f1cbc432b8e028d6` |
| Canonical and staged XML SHA-256 | `71b792bfdbe3e3fc0ede56a6b9dd680c0a708c06130f54d1fa5b9c15267b9932` |
| Endpoint Puppet runtime | `8.20.0` |

The artifact was built once from the reviewed commit. `dev01` calculated the artifact SHA-256 above, `win11-02` independently calculated the same value before canary extraction, and `win11-01` independently calculated the same value before promotion extraction. The ZIP was neither rebuilt nor modified between endpoints. `win11-02` remained the canary, and `win11-01` received the unchanged promoted bytes.

### Repository contract layer

[`tests/test_puppet_contract.py`](../../tests/test_puppet_contract.py) uses only the Python standard library to establish repository contracts for:

- exact `role::windows_endpoint` composition and its resource-free role body;
- the intentionally empty `profile::base`;
- the Sysmon directories, staged file, file source, explicit parent relationships, and service state;
- Splunk Universal Forwarder service-only ownership;
- absence of packages, execs, and notification, subscription, or refresh relationships;
- exact `site.pp` classification of `win11-01` and `win11-02`;
- intentionally empty Git-tracked Hiera data;
- deterministic construction of the Git-derived Puppet ZIP;
- exact canonical Sysmon bytes in the artifact; and
- exclusion of private and unrelated repository content from the artifact.

These are repository contract tests, not a Puppet parser, catalog compiler, provider test, or substitute for endpoint convergence validation. Compilation and application with the endpoint-installed Puppet 8.20.0 runtime provide the real Puppet validation layer.

### Frozen desired-state boundary

`role::windows_endpoint` composes `profile::base`, `profile::sysmon`, and `profile::splunk_forwarder`; the role owns no direct resources. `profile::base` remains resource-free.

`profile::sysmon` owns only:

- directory `C:/ProgramData/Alert2IR`;
- directory `C:/ProgramData/Alert2IR/Sysmon`;
- exact staged file `C:/ProgramData/Alert2IR/Sysmon/alert2ir-sysmon.xml` from `puppet:///modules/profile/sysmon/alert2ir-sysmon.xml`;
- `Sysmon64` running; and
- `Sysmon64` automatic.

`profile::splunk_forwarder` owns only:

- `SplunkForwarder` running; and
- `SplunkForwarder` automatic.

WS06 does not install or upgrade Sysmon, apply or reload active Sysmon configuration, compare the staged XML with active Sysmon configuration, or own the Sysmon Operational channel. It does not install or upgrade Splunk Universal Forwarder, own `inputs.conf` or `outputs.conf`, or restart either telemetry service because the staged XML changes. It does not manage Puppet Agent service state, introduce Puppet Server or its CA, create scheduled agent convergence, or introduce a port-8140 control plane, PuppetDB, Puppetfile/r10k, Forge modules, PDK, or RSpec-Puppet. It does not manage firewall, SSH, users, endpoint hostname or IP configuration, general Windows packages, Docker, or later Alert2IR workstreams.

The staged XML SHA-256 proves only equality between the project-owned canonical bytes and the managed staged file. It is not evidence that Sysmon's active configuration equals that file.

### Standalone validation commands

WS06 retained deliberate standalone `puppet apply` with the endpoint-installed Puppet 8.20.0 runtime. Puppet Agent remained stopped and disabled; no agent/server enrollment or Puppet Server relationship was introduced.

Before every Puppet invocation, the operator independently guarded physical identity with:

```powershell
$env:COMPUTERNAME

Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -like '192.168.56.*' } |
  Select-Object IPAddress, InterfaceAlias
```

The canary identity was `win11-02` / `WIN11-02` / `192.168.56.62` / `Ethernet`. Its enforcing command was:

```powershell
& 'C:\Program Files\Puppet Labs\Puppet\bin\puppet.bat' apply `
  'C:\Windows\Temp\Alert2IR-WS06-8227653814dd\environment\manifests\site.pp' `
  --modulepath='C:\Windows\Temp\Alert2IR-WS06-8227653814dd\environment\modules' `
  --hiera_config='C:\Windows\Temp\Alert2IR-WS06-8227653814dd\environment\hiera.yaml' `
  --certname=win11-02 `
  --detailed-exitcodes
```

The noop used the same command with `--noop` in addition to `--detailed-exitcodes`.

The promotion identity was `win11-01` / `WIN11-01` / `192.168.56.60` / `Ethernet`. Its enforcing command was:

```powershell
& 'C:\Program Files\Puppet Labs\Puppet\bin\puppet.bat' apply `
  'C:\Windows\Temp\Alert2IR-WS06-8227653814dd\environment\manifests\site.pp' `
  --modulepath='C:\Windows\Temp\Alert2IR-WS06-8227653814dd\environment\modules' `
  --hiera_config='C:\Windows\Temp\Alert2IR-WS06-8227653814dd\environment\hiera.yaml' `
  --certname=win11-01 `
  --detailed-exitcodes
```

Its noop likewise added `--noop`. These paths were endpoint-local temporary extraction paths used only during validation; they no longer exist.

### Endpoint results and cleanup

Both endpoints produced the same result sequence:

| Endpoint | Noop | First enforcing apply | Second enforcing apply |
| --- | --- | --- | --- |
| `win11-02` | exit `0`; no corrective resource events | exit `0`; no corrective resource events | exit `0`; no corrective resource events |
| `win11-01` | exit `0`; no corrective resource events | exit `0`; no corrective resource events | exit `0`; no corrective resource events |

No deliberate drift was introduced during WS06. WS02 had already demonstrated corrective service and staged-file drift detection and repair. WS06 instead proved that the exact now-tested roles/profiles artifact was already converged and that repeated enforcing application was idempotent on both endpoints.

Final state on both endpoints was:

- `Sysmon64`: `Running` / `Automatic`;
- `SplunkForwarder`: `Running` / `Automatic`;
- Puppet Agent: `Stopped` / `Disabled`; and
- `C:\ProgramData\Alert2IR\Sysmon\alert2ir-sysmon.xml`: present with canonical SHA-256 `71b792bfdbe3e3fc0ede56a6b9dd680c0a708c06130f54d1fa5b9c15267b9932`.

After evidence was recorded, `C:\Windows\Temp\Alert2IR-WS06-8227653814dd` was removed from both endpoints and the temporary artifact output directory was removed from `dev01`. Cleanup did not remove or alter the Puppet-managed staged XML, manually change either telemetry service, or change Puppet Agent state. No credentials or private Hiera values entered Git.

## First functional catalog boundary

The first functional WS02 catalog manages selected desired state for already-installed telemetry components. Observed endpoint state is evidence to classify and review; it does not automatically define desired state.

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
