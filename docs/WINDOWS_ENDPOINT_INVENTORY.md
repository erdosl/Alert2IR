# Windows Endpoint Inventory

## Purpose

Endpoint inventory precedes desired-state implementation so that existing facts, working behavior, and unexplained drift can be reviewed before Puppet resources or Hiera values are designed. This prevents an observed machine from becoming a configuration template by accident.

`win11-01` is a known-good reference observation for the current Sysmon-to-Splunk telemetry path. It is not automatically the desired-state template. Its configuration may include node-specific, incidental, historical, or still-unresolved choices.

This discovery task does not configure Windows, Sysmon, Splunk Universal Forwarder, Puppet, networking, or the firewall. The collector uses read-only inspection and tolerates absent components by recording their state or a per-check error.

## Run the collector

Run the same Git revision on each endpoint from an elevated Windows PowerShell session. Elevation improves access to service, optional-feature, event-log, and configuration metadata; it does not cause the collector to change configuration.

```powershell
Set-Location C:\path\to\Alert2IR
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\windows\Collect-Alert2IREndpointInventory.ps1
```

Run it once on `win11-01` and once on `win11-02`. The last output line is the created output directory. By default it is a timestamped directory beneath the current user's temporary directory, for example:

```text
C:\Users\analyst\AppData\Local\Temp\Alert2IR-EndpointInventory-win11-01-20260809T120000Z
```

`-OutputRoot` may be used to choose another local diagnostic location. Do not point it into the repository.

## Output and handling

Every run creates `endpoint-inventory.json`, whose `schema` and `schema_version` fields identify the format. It contains system, network, Sysmon, Splunk Universal Forwarder, and diagnostic sections. Failures in individual checks are recorded under `diagnostics.errors` instead of ending the whole collection where practical.

The collector creates these supplementary text artifacts only when the corresponding executable and inspection are available:

- `sysmon-current-configuration.txt` contains output from the read-only `sysmon -c` query.
- `sysmon-schema.txt` contains output from the read-only `sysmon -s` query.
- `splunk-btool-*-sanitized.txt` contains effective btool output with `--debug` provenance. Sensitive key/value lines are redacted before the output is written.

The inventory does not export raw Sysmon event bodies or copy Splunk configuration files. It records bounded event-ID aggregates and hashes of relevant local Splunk configuration files. It deliberately excludes password stores, `user-seed.conf`, private keys, credential stores, product keys, user inventories, machine SIDs, and unrelated personal data.

Generated endpoint inventories are local diagnostic evidence. They may still contain host-specific operational details such as addresses and paths and **must not be committed to Git**. Transfer and retain them according to the lab's evidence-handling practices.

## Compare before implementing desired state

Review the two JSON inventories and classify every material difference as one of:

1. **Shared desired state** — a setting both Windows endpoints should converge on.
2. **Node-specific desired state** — an intentional per-node value, represented explicitly rather than copied between hosts.
3. **Incidental/unmanaged** — diagnostic or environmental state that Puppet should not own.
4. **Unresolved/decision required** — a difference needing evidence, testing, or an architectural decision before implementation.

Only after that review should Puppet resources and Hiera values be created. In particular, do not copy `win11-01` configuration wholesale: preserve the working telemetry path as evidence while deciding which parts are genuine desired state.

The inventory establishes endpoint-local facts. End-to-end verification that Sysmon events are actually received, indexed, and queryable in Splunk is a separate validation step.
