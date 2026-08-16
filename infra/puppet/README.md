# Puppet environment

## Purpose and source authority

This directory defines the repository-owned Puppet desired state, deterministic artifact assembly, and safe standalone application workflow for the Alert2IR Windows endpoints.

Executable authority is divided as follows:

| Path | Authority |
| --- | --- |
| [`manifests/site.pp`](manifests/site.pp) | Explicit node classification |
| [`modules/role/`](modules/role/) | Node-purpose composition |
| [`modules/profile/`](modules/profile/) | Managed resources |
| [`hiera.yaml`](hiera.yaml) and [`data/`](data/) | Hiera hierarchy; Git-tracked data is intentionally empty |
| [`tools/puppet/build-ws02-puppet-artifact.sh`](../../tools/puppet/build-ws02-puppet-artifact.sh) | Deterministic Git-derived directory-environment builder |
| [`tests/test_puppet_contract.py`](../../tests/test_puppet_contract.py) | Repository ownership and artifact contract |

Never store credentials, private endpoint data, or secrets in manifests, Hiera, artifacts, or documentation.

## Current ownership

`site.pp` classifies only `win11-01` and `win11-02` into `role::windows_endpoint`. That role composes the resource-free `profile::base`, `profile::sysmon`, and `profile::splunk_forwarder`.

| Profile | Puppet owns |
| --- | --- |
| `profile::sysmon` | `C:/ProgramData/Alert2IR`, its `Sysmon` subdirectory, the canonical staged XML file, and `Sysmon64` running/automatic state |
| `profile::splunk_forwarder` | `SplunkForwarder` running/automatic state only |
| `profile::base` | No resources |

The Sysmon XML source is [`config/sysmon/alert2ir-sysmon.xml`](../../config/sysmon/alert2ir-sysmon.xml). The artifact builder takes it from the same reviewed Git commit as the Puppet environment and exposes one artifact-local copy through `puppet:///modules/profile/sysmon/alert2ir-sysmon.xml`.

Puppet intentionally does **not** own:

- Puppet, Sysmon, or Splunk Universal Forwarder installation or upgrade;
- Puppet Agent service state, Puppet Server, CA/enrollment, or scheduled convergence;
- active Sysmon configuration application or semantic comparison;
- the Sysmon Operational channel;
- Splunk `inputs.conf`, `outputs.conf`, deployment-client configuration, or package lifecycle;
- firewall, SSH, users, hostname, IP configuration, VirtualBox networking, or time synchronization;
- Docker, Alert2IR application deployment, Velociraptor, attack simulation, or detections.

Staged Sysmon bytes are not proof that the active Sysmon configuration matches them. [SYSMON.md](../../docs/SYSMON.md) owns the collection policy and active-verification boundary; [LAB.md](../../docs/LAB.md) owns endpoint roles and network relationships.

## Control and bootstrap model

The environment uses deliberate, human-triggered standalone `puppet apply` on each Windows endpoint. No Puppet Server control plane or port-8140 dependency exists. The installed Puppet Agent service remains stopped and disabled and is not the convergence mechanism.

Puppet does not install itself. Bootstrap each endpoint with the same pinned, reviewed x64 Puppet Core package from the official distribution source. Verify the complete package checksum and valid Authenticode signature before installation, keep any distribution credential out of shell history and Git, and install with:

```text
PUPPET_AGENT_STARTUP_MODE=Disabled
```

The reference endpoints use Puppet Core 8.20.0. A different runtime requires separate compatibility review and validation rather than an unpinned `latest` download.

After installation, verify the executable version and require the Puppet Agent service to be stopped and disabled before standalone use. Puppet configuration observed on an endpoint is inventory evidence, not automatically desired state; collect it with [WINDOWS_ENDPOINT_INVENTORY.md](../../docs/WINDOWS_ENDPOINT_INVENTORY.md).

## Build a reviewed artifact

Build from a committed Git revision on `dev01`, never from uncommitted working-tree content:

```bash
tools/puppet/build-ws02-puppet-artifact.sh \
  <reviewed-git-ref> \
  <existing-output-directory>
```

The builder:

1. resolves the ref to a commit;
2. materializes `infra/puppet` from that commit;
3. adds the canonical Sysmon XML from the same commit;
4. creates a deterministic ZIP without repository/private state;
5. refuses to overwrite an existing artifact;
6. reports the commit and complete artifact/Sysmon SHA-256 values.

Verify the complete artifact hash after transfer and retain it as execution evidence. The Windows endpoint does not require Git or repository access; extract the reviewed directory environment to a controlled local path.

## Physical identity and certname guard

`--certname` selects Puppet node classification and Hiera data; it does not prove which physical endpoint is running the command. Before every Puppet invocation, independently inspect:

```powershell
$env:COMPUTERNAME

Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -like '192.168.56.*' } |
  Select-Object IPAddress, InterfaceAlias
```

Require the computer name and host-only address to match [LAB.md](../../docs/LAB.md), then explicitly use `--certname=win11-02` or `--certname=win11-01`. Stop on any mismatch. Puppet does not own these identity or network values; they are an external safety guard.

## Standalone apply

Set local variables to the verified extracted environment and intended endpoint:

```powershell
$Puppet = 'C:\Program Files\Puppet Labs\Puppet\bin\puppet.bat'
$EnvironmentRoot = 'C:\path\to\verified\environment'
$Certname = 'win11-02'
```

Compile a no-op catalog and inspect every proposed correction:

```powershell
& $Puppet apply `
  "$EnvironmentRoot\manifests\site.pp" `
  --modulepath="$EnvironmentRoot\modules" `
  --hiera_config="$EnvironmentRoot\hiera.yaml" `
  --certname=$Certname `
  --noop `
  --detailed-exitcodes
```

After approval, apply the same artifact without `--noop`:

```powershell
& $Puppet apply `
  "$EnvironmentRoot\manifests\site.pp" `
  --modulepath="$EnvironmentRoot\modules" `
  --hiera_config="$EnvironmentRoot\hiera.yaml" `
  --certname=$Certname `
  --detailed-exitcodes
```

For an enforcing run, exit `0` means success without changes and exit `2` means success with changes. Exit `1`, `4`, or `6` is failure-bearing. For a no-op run, exit code alone does not prove convergence: inspect the report/output for simulated corrective events.

Use `win11-02` as the canary. Promote the exact same artifact bytes to `win11-01` only after the canary is healthy and the proposed resource set matches ownership above.

## Validation workflow

For every catalog revision:

1. run the repository contract:

   ```bash
   PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
     .venv/bin/python -m unittest -v tests.test_puppet_contract
   ```

2. build the same reviewed commit twice in separate output directories when deterministic artifact behavior needs verification, and require byte-identical ZIPs;
3. verify endpoint physical identity, Puppet runtime, stopped/disabled agent service, artifact hash, and explicit certname;
4. run no-op, review every proposed change, and reject changes outside the documented profiles;
5. apply on `win11-02`, verify the two service states and staged XML bytes, and confirm telemetry remains healthy;
6. run a second enforcing apply and no-op, requiring no corrective resource events;
7. promote the unchanged artifact to `win11-01` and repeat the identity, apply, idempotence, and telemetry checks;
8. remove only temporary extracted artifacts after evidence is retained; do not remove managed state.

The Python contract freezes node classification, role/profile composition, absence of unsupported resource types and refresh relationships, empty Git-tracked Hiera, exact staged XML bytes, deterministic ZIP contents, and exclusion of private repository state. It is not a Puppet parser or substitute for compilation and endpoint convergence.

## Failure and rollback boundary

Stop if identity, artifact provenance, catalog compilation, proposed scope, service health, staged bytes, or telemetry differs from expectation. Do not broaden ownership or edit an endpoint-local artifact to make an apply pass.

Rollback requires a separately reviewed Git-derived artifact and the same no-op/approval/apply process. Puppet can restore only resources it owns; active Sysmon rollback, Splunk configuration repair, networking, and package recovery remain outside this catalog.
