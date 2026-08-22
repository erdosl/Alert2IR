# Puppet environment

## Purpose and source authority

This directory defines the repository-owned Puppet desired state, deterministic artifact assembly, and safe standalone application workflow for the six Alert2IR reference VMs.

Executable authority is divided as follows:

| Path | Authority |
| --- | --- |
| [`manifests/site.pp`](manifests/site.pp) | Explicit node classification |
| [`modules/role/`](modules/role/) | Node-purpose composition |
| [`modules/profile/`](modules/profile/) | Managed resources |
| [`hiera.yaml`](hiera.yaml) and [`data/`](data/) | Hiera hierarchy and strictly allowlisted public host identity data |
| `tools/puppet/build-puppet-artifact.sh` | Deterministic Git-derived directory-environment builder |
| [`tests/test_puppet_contract.py`](../../tests/test_puppet_contract.py) | Repository ownership and artifact contract |

Never store credentials, private endpoint data, or secrets in manifests, Hiera, artifacts, or documentation.

## Current ownership

`site.pp` explicitly classifies all six reference VMs and rejects every unknown certname. `win11-01` and `win11-02` retain `role::windows_endpoint`, which composes the resource-free `profile::base`, `profile::sysmon`, and `profile::splunk_forwarder`.

| Profile | Puppet owns |
| --- | --- |
| `profile::sysmon` | `C:/ProgramData/Alert2IR`, its `Sysmon` subdirectory, the canonical staged XML file, and `Sysmon64` running/automatic state |
| `profile::splunk_forwarder` | `SplunkForwarder` running/automatic state only |
| `profile::base` | No resources |

The four Ubuntu 24.04 LTS amd64 hosts retain the common foundation and add only
the role-specific state supported by reviewed public or repository-owned inputs:

| Host | Role | Additional profiles after the foundation |
| --- | --- | --- |
| `splunk` | `role::splunk_server` | None; Splunk remains external |
| `ir-core` | `role::ir_core` | `profile::docker_host`, `profile::alert2ir_host`, `profile::alloy` |
| `dev01` | `role::development` | `profile::docker_host`, `profile::development` |
| `obs01` | `role::observability` | `profile::docker_host`, `profile::observability_host`, `profile::alloy` |

Every Linux role continues to contain exactly this common foundation:

| Profile | Puppet owns |
| --- | --- |
| `profile::linux_base` | Resource-free compatibility guard for Linux, Ubuntu 24.04, and amd64 |
| `profile::host_identity_guard` | Read-only equality checks for trusted certname, hostname, and the expected host-only IPv4 in structured interface bindings |
| `profile::operator_tools` | Installed `ripgrep` and `shellcheck` packages |

The identity guard does not assume a Linux interface name or change host
identity or networking. Per-node Hiera contains the four public host-only IPv4
values plus only the Alloy and Docker canonical-file selectors that genuinely
vary between `ir-core` and `obs01`.

The PR2 profiles own this bounded host state:

| Profile | Puppet owns |
| --- | --- |
| `profile::docker_host` | Reviewed Docker public APT key/source, exact APT pins and package versions, the canonical containerd baseline, optional bounded daemon JSON, and enabled/running Docker and containerd services |
| `profile::alloy` | Reviewed Grafana public APT key/source, exact Alloy `1.18.1-1`, canonical staged config, host-specific native-service drop-in, named Docker/containerd access, state directory, and enabled/running Alloy service |
| `profile::development` | Installed `git` only |
| `profile::alert2ir_host` | Stable `/opt/alert2ir` release-parent and `/etc/alert2ir` protected-input parent directories only |
| `profile::observability_host` | Stable observability release and protected-input parents plus the root-owned `/srv/alert2ir-observability` data root only |

`profile::observability_host` does not manage children below the stable data
root. The observability deployment prepares the five container bind-directory
entries and owns their exact image-runtime UID/GID mapping. `profile::alloy`
separately retains ownership of `/srv/alert2ir-observability/alloy` as native
host-service state, with owner/group `alloy` and mode `0750`. The observability
role orders `profile::observability_host` before `profile::alloy` so the shared
parent exists first.

Docker is exact on `dev01`, `ir-core`, and `obs01`: `containerd.io`
`2.3.3-1~ubuntu.24.04~noble`, Engine and CLI
`5:29.7.2-1~ubuntu.24.04~noble`, Buildx
`0.36.1-1~ubuntu.24.04~noble`, and Compose plugin
`5.4.0-1~ubuntu.24.04~noble`. `ca-certificates` is installed but its Ubuntu
patch version is not pinned; `curl` is not a Puppet prerequisite. APT
preferences use priority `1001`; package holds are not used. The Docker public
key SHA-256 is
`1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570`
with fingerprint `9DC858229FC7DD38854AE2D88D81803C0EBFCD88`; the source SHA-256 is
`8f33259a79a8149bed86c66e103fb4c3fa70f9219cd7ff315b6cc30988afef0c`.

The canonical containerd baseline SHA-256 is
`e2bdf61ad4c980e7439ed09a1ab65441afadede63087761679a97cc77cd4d20d`.
It contains no active numeric socket GID. Alloy hosts instead use the unpinned
system group `alloy-containerd`; a bounded helper verifies or applies group
`alloy-containerd` and mode `0660` to only
`/run/containerd/containerd.sock`. A containerd systemd `ExecStartPost`
re-establishes that named-group invariant after a later restart. Puppet
reconciles the current socket but does not restart containerd or Docker.

Alloy uses the reviewed full upstream Grafana key bundle with SHA-256
`d8f5f6f4c174c3b9184cb6ebbf691a2ee69831a109425de4e821f5b43c53a2f8`
and active signing fingerprint `B53AE77BADB630A683046005963FA27710458545`.
The source SHA-256 is
`863616f8c5848c32fc1e1024007835dd0cb2447def236d6542f0b1aab9b729f2`.
The repository files `observability/alloy/ir-core.alloy` and
`observability/alloy/obs01.alloy` remain the only canonical configuration
copies. The artifact builder stages their exact Git-object bytes for Puppet.

Service events are deliberately narrow. Docker daemon or containerd config
changes do not notify either service; they require a separately reviewed
restart or reboot. Alloy configuration bytes are validated with
`/usr/bin/alloy validate` before replacement and then reload the active Alloy
service. Alloy unit execution or supplementary-group changes may restart only
Alloy after `systemctl daemon-reload` where needed. Alloy never restarts Docker,
containerd, or either Compose project.

The Sysmon XML source is [`config/sysmon/alert2ir-sysmon.xml`](../../config/sysmon/alert2ir-sysmon.xml). The artifact builder takes it and the two canonical Alloy configurations from the same reviewed Git commit as the Puppet environment. It exposes artifact-local copies through the corresponding `puppet:///modules/profile/...` paths without adding tracked duplicate Alloy files.

Puppet intentionally does **not** own:

- Puppet, Sysmon, or Splunk Universal Forwarder installation or upgrade;
- Puppet Agent service state, Puppet Server, CA/enrollment, or scheduled convergence;
- active Sysmon configuration application or semantic comparison;
- the Sysmon Operational channel;
- Splunk `inputs.conf`, `outputs.conf`, deployment-client configuration, or package lifecycle;
- initial VM or image construction, hostname or network bootstrap, VirtualBox networking, or time synchronization;
- Puppet runtime installation or distribution on Linux;
- the `jgipsz` account, SSH authorization or private keys, `sshd`, password authentication, root-login policy, or sudo policy;
- host firewall policy or secret distribution;
- Docker administrator-group membership, containers, images, networks, volumes, Compose invocation, or application/observability release contents;
- container-specific children below `/srv/alert2ir-observability` or the numeric runtime UID/GID identities coupled to pinned observability images;
- Splunk Enterprise or its Alert2IR app, Velociraptor, BIND, PostgreSQL, Alert2IR application deployment, attack simulation, attestation, or detections;
- `/opt/.../current` release selectors, runtime environment files, protected file contents, proprietary installers, or private authentication material.

Staged Sysmon bytes are not proof that the active Sysmon configuration matches them. [SYSMON.md](../../docs/SYSMON.md) owns the collection policy and active-verification boundary; [LAB.md](../../docs/LAB.md) owns endpoint roles and network relationships.

## Control and bootstrap model

The environment uses deliberate, human-triggered standalone `puppet apply`; no Puppet Server control plane or port-8140 dependency is introduced. This is the established Windows workflow and the intended Linux workflow after a Linux runtime is selected and bootstrapped.

### Windows runtime

Puppet does not install itself. Bootstrap each endpoint with the same pinned, reviewed x64 Puppet Core package from the official distribution source. Verify the complete package checksum and valid Authenticode signature before installation, keep any distribution credential out of shell history and Git, and install with:

```text
PUPPET_AGENT_STARTUP_MODE=Disabled
```

The reference endpoints use Puppet Core 8.20.0. A different runtime requires separate compatibility review and validation rather than an unpinned `latest` download.

After installation, verify the executable version and require the Puppet Agent service to be stopped and disabled before standalone use. Puppet configuration observed on an endpoint is inventory evidence, not automatically desired state; collect it with [WINDOWS_ENDPOINT_INVENTORY.md](../../docs/WINDOWS_ENDPOINT_INVENTORY.md).

### Linux bootstrap boundary

Puppet and Facter are not currently installed on the four Linux reference hosts. The repository defines foundation and bounded role-specific desired state but does not select or install a Linux Puppet distribution. The exact pinned Linux Puppet runtime, provenance verification, and installation procedure must be reviewed before live acceptance; manifests target Puppet 8 semantics, while CI performs public Puppet 8 DSL syntax compatibility validation rather than runtime parity.

Before Linux Puppet can run, bootstrap must already provide:

- Ubuntu 24.04 LTS on amd64;
- the correct hostname and host-only IPv4 from [LAB.md](../../docs/LAB.md);
- existing administrative access and a working package/network bootstrap path;
- a selected, pinned, and verified Puppet runtime suitable for standalone root execution;
- the reviewed Git-derived Puppet artifact with its complete SHA-256 verified after transfer.

Ordinary Ed25519 public-key authorization, the existing `jgipsz` account and sudo membership, `sshd` policy, and private key custody remain external bootstrap/administration prerequisites. Puppet does not adopt or modify them in this scope.

## Build a reviewed artifact

Build from a committed Git revision on `dev01`, never from uncommitted working-tree content:

```bash
tools/puppet/build-puppet-artifact.sh \
  <reviewed-git-ref> \
  <existing-output-directory>
```

The builder:

1. resolves the ref to a commit;
2. materializes `infra/puppet` from that commit;
3. adds the canonical Sysmon XML and two canonical Alloy configurations from the same commit;
4. creates a deterministic ZIP without repository/private state;
5. refuses to overwrite an existing artifact;
6. reports the commit and complete artifact/Sysmon/Alloy SHA-256 values.

Verify the complete artifact hash after transfer and retain it as execution evidence. The Windows endpoint does not require Git or repository access; extract the reviewed directory environment to a controlled local path.

## Physical identity and certname guards

`--certname` selects Puppet node classification and Hiera data; it does not prove which physical endpoint is running the command. Before every Puppet invocation, independently inspect:

```powershell
$env:COMPUTERNAME

Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -like '192.168.56.*' } |
  Select-Object IPAddress, InterfaceAlias
```

Require the computer name and host-only address to match [LAB.md](../../docs/LAB.md), then explicitly use `--certname=win11-02` or `--certname=win11-01`. Stop on any mismatch. Puppet does not own these identity or network values; they are an external safety guard.

Linux roles add a catalog-evaluation guard without changing the host. It
requires the trusted certname to equal the structured networking hostname. The
expected host-only IPv4 must appear exactly once among all structured IPv4
interface bindings. Interfaces without IPv4 bindings are ignored. If IPv4
bindings are present but malformed, catalog evaluation fails. A missing or
duplicate expected address also fails. The stable invariant is the address,
not `enp0s8` or any other interface name.

## Windows standalone apply

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

## Intended Linux standalone apply

After the Linux runtime decision and bootstrap are separately reviewed, set the verified Puppet executable, extracted environment, and explicit certname. Run as root because package resources cannot be managed through implicit sudo escalation:

```bash
sudo "$PUPPET" apply \
  "$ENVIRONMENT_ROOT/manifests/site.pp" \
  --modulepath="$ENVIRONMENT_ROOT/modules" \
  --hiera_config="$ENVIRONMENT_ROOT/hiera.yaml" \
  --certname="$CERTNAME" \
  --noop \
  --detailed-exitcodes
```

Review every simulated change, then run the identical command without `--noop`. A second enforcing apply and final no-op must report no corrective resource events. Repository implementation work must not run these commands on a live VM.

Adopt current lab state in the order `dev01`, `ir-core`, `obs01`, then the
foundation-only `splunk` role. Stop on an unexpected Docker package change,
Docker/containerd restart, container recreation, firewall change, protected-file
change, Splunk change, or Velociraptor change. `obs01` is expected to converge
the comment-only Alloy config drift and reload Alloy; current required Alloy
groups already exist on both Alloy hosts.

Because current `ir-core` and `obs01` containerd files encode non-portable
numeric socket GIDs, first adoption normalizes them without restarting
containerd. A later, separately reviewed restart or reboot acceptance must prove
that `ExecStartPost` restores a root-owned `0660` socket in group
`alloy-containerd` and that native Alloy remains healthy with Docker/containerd
telemetry access.

## Validation workflow

For every catalog revision:

1. run the repository contract:

   ```bash
   PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
     .venv/bin/python -m unittest -v tests.test_puppet_contract
   ```

2. run ShellCheck over every tracked `.sh` file, `bash -n` over the socket helper, Puppet parser validation over every tracked `.pp` file, and the pinned Alloy validator over both canonical configs;
3. build the same reviewed commit twice in separate output directories when deterministic artifact behavior needs verification, and require byte-identical ZIPs;
4. verify physical identity, Puppet runtime, artifact hash, and explicit certname before any endpoint use;
5. run no-op, review every proposed change, and reject changes outside the documented profiles;
6. preserve the established `win11-02` canary/promotion workflow for Windows catalog changes;
7. after Linux runtime/bootstrap review, validate each Linux host with no-op, first apply, second apply, and final no-op;
8. remove only temporary extracted artifacts after evidence is retained; do not remove managed state.

The Python contracts freeze node classification, role/profile composition,
exact package/source/config identities, bounded service events, named socket
access, stable root and native Alloy directory ownership, absence of
container-image UID/GID knowledge from Puppet, deferred authority, exact public Hiera data,
the complete Puppet environment file set, staged Sysmon/Alloy bytes,
deterministic ZIP contents, and exclusion of private repository state. The
separate Puppet 8 syntax job is a parser check, not catalog compilation or a
substitute for endpoint convergence.

## Failure and rollback boundary

Stop if identity, artifact provenance, catalog compilation, proposed scope, service health, staged bytes, or telemetry differs from expectation. Do not broaden ownership or edit an endpoint-local artifact to make an apply pass.

Rollback requires a separately reviewed Git-derived artifact and the same
no-op/approval/apply process. Puppet can restore only resources it owns; active
Sysmon rollback, Splunk or Velociraptor repair, Linux bootstrap, networking,
firewall, SSH administration, Compose/application recovery, and protected input
recovery remain outside this catalog.
