# Lab Inventory

## Host

The physical hypervisor is Ubuntu 24.04.4 LTS Desktop running VirtualBox 7.2.8. It has 64 GB RAM, 8 physical CPU cores, and ext4 SSD storage with substantial free capacity. It remains hypervisor-only; Codex is neither installed nor required there.

## Network

The VirtualBox host-only network is `192.168.56.0/24`. Each listed VM also has a VirtualBox NAT interface for normal Internet access.

Existing aliases follow `hostname`, `hostname.lab.test`, `hostname.admin`, and `hostname.admin.lab.test`. The `.admin` names currently resolve to the same host-only interfaces. They are aliases, not a separate management network.

## Systems

| Host | Host-only IP | Known state |
| --- | --- | --- |
| `win11-01` | `192.168.56.60` | Windows 11 Enterprise Evaluation 25H2; EditionID `EnterpriseEval`; build `26200.8875`; VirtualBox Guest Additions; Sysmon 15.21 and Splunk Universal Forwarder 10.4.2 installed and running |
| `splunk` | `192.168.56.61` | Ubuntu Server 24.04.4 LTS; Splunk Enterprise 10.4.1 build `5a009d941268`; currently 1 vCPU |
| `win11-02` | `192.168.56.62` | Windows 11 Enterprise Evaluation 25H2; EditionID `EnterpriseEval`; build `26200.8875`; VirtualBox Guest Additions; Sysmon 15.21 and Splunk Universal Forwarder 10.4.2 installed and running |
| `ir-core` | `192.168.56.63` | Ubuntu Server 24.04.4 LTS; intended Alert2IR and supporting-services runtime host; currently 1 vCPU |
| `dev01` | `192.168.56.64` | Ubuntu Server 24.04.4 LTS; dedicated development/admin VM; Python 3.12.3, Git 2.43.0, Codex CLI 0.147.0; currently 1 vCPU |

## Existing telemetry path

Both Windows endpoints forward Sysmon Operational events to Splunk at `192.168.56.61:9997`. Current telemetry from both endpoints was verified during WS02 validation.

The current Universal Forwarder input is:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true
index = main
source = XmlWinEventLog\:Microsoft-Windows-Sysmon/Operational
sourcetype = XmlWinEventLog
```

Effective forwarding is:

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 192.168.56.61:9997
```

Splunk currently uses the default `main` index. Installed apps include Splunk Add-on for Sysmon, Splunk Security Essentials, and Splunk Common Information Model. These are observed effective settings; the current Puppet catalog does not own the complete Splunk local configuration files, and this baseline does not redesign them.
