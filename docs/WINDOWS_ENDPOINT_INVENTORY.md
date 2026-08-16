# Windows endpoint inventory

## Purpose and authority

The repository provides a read-only collector for bounded inventory of an authorized Windows endpoint. It records system, network, Sysmon, Splunk Universal Forwarder, Puppet, and diagnostic facts without installing, configuring, enabling, disabling, starting, or stopping anything.

[`tools/windows/Collect-Alert2IREndpointInventory.ps1`](../tools/windows/Collect-Alert2IREndpointInventory.ps1) is the executable authority. The collector requires Windows PowerShell 5.1 or later and writes schema `alert2ir.windows-endpoint-inventory`, version `1`.

Endpoint roles and addresses belong in [LAB.md](LAB.md). The current Sysmon collection policy belongs in [SYSMON.md](SYSMON.md).

## Authorization and execution

Run the collector only on systems authorized by [LAB_SCOPE.md](LAB_SCOPE.md). Use the same reviewed repository revision on each endpoint and run from an elevated Windows PowerShell session. Elevation improves access to service, optional-feature, event-log, configuration, and local-group metadata; it does not make the collector mutating.

```powershell
Set-Location C:\path\to\Alert2IR
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\windows\Collect-Alert2IREndpointInventory.ps1
```

The last output line is the newly created timestamped evidence directory beneath the current user's temporary directory. Use `-OutputRoot` to select another local diagnostic location:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\windows\Collect-Alert2IREndpointInventory.ps1 `
  -OutputRoot C:\approved\diagnostic-path
```

Do not select a path inside the repository.

## Produced evidence

Every successful invocation creates `endpoint-inventory.json`. Its current top-level content covers:

- collector version and elevation state;
- computer, operating-system, boot, time, VirtualBox, and Puppet facts;
- active adapters, IP configuration, firewall profiles, name resolution, route and TCP reachability to the lab Splunk receiver;
- Sysmon implementation evidence, service/driver/file facts, bounded Operational-channel counts, and read-only configuration/schema inspection;
- Splunk Universal Forwarder product, service, Event Log Readers membership, effective configuration summaries, forwarding destinations, and configuration-file hashes;
- bounded warnings and per-check errors.

Individual collection failures are recorded under `diagnostics.errors` where practical rather than terminating all independent checks.

When the corresponding executable and inspection are available, the collector also writes:

| Artifact | Content |
| --- | --- |
| `sysmon-current-configuration.txt` | Output from the read-only Sysmon `-c` query |
| `sysmon-schema.txt` | Output from the read-only Sysmon `-s` query |
| `splunk-btool-*-sanitized.txt` | Effective `btool --debug` output with sensitive key/value lines redacted |

The Sysmon event aggregate is bounded to at most 10,000 recent events and reports whether the full log exceeded that boundary. A bounded count is an inventory observation, not a retention or volume guarantee.

## Evidence and privacy handling

Inventory output can contain sensitive operational metadata, including host addresses, routes, executable paths, service accounts, configuration provenance, file hashes, and effective forwarding destinations. Generated inventory directories are local diagnostic evidence and **must not be committed to Git**.

The collector deliberately excludes password stores, `user-seed.conf`, private keys, credential stores, product keys, user inventories, machine SIDs, raw Sysmon event bodies, and copied Splunk configuration files. Its Splunk text sanitizer reduces credential exposure but does not make the entire output public. Review, transfer, retain, and destroy the directory using the lab's approved evidence-handling practice.

## Review and comparison

Before using inventory differences to change desired state, classify each difference as:

1. shared desired state;
2. intentional node-specific desired state;
3. incidental or unmanaged state;
4. unresolved evidence requiring a decision.

Do not copy the observed state of `win11-01` or `win11-02` wholesale into Puppet. Compare the evidence with the explicit ownership in [`infra/puppet/README.md`](../infra/puppet/README.md) and with the canonical Sysmon policy. Endpoint-local inventory also does not prove that forwarded events were indexed or that detections matched; those are separate validation boundaries described in [DETECTIONS.md](DETECTIONS.md).
