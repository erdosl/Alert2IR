# Roadmap

Workstreams describe coherent areas of work. Their numbering communicates a useful progression, but they are not rigid serial dependencies; work may overlap when prerequisites, risk, and validation permit.

1. **01 Baseline & Architecture** — repository conventions, project boundaries, ADRs, lab record, and scope.
2. **02 Windows Endpoint Reproducibility** — completed: repeatable endpoint prerequisites and telemetry configuration.
3. **03 Docker / IR-Core** — next: minimal application/service composition on the runtime host.
4. **04 Alert2IR Core** — API, canonical alert normalization, decisions, incidents, and backend contracts.
5. **05 Persistence** — PostgreSQL data model, migrations, and lifecycle behavior.
6. **06 Puppet** — implement tested desired-state roles and profiles.
7. **07 Attack Simulation** — controlled Atomic Red Team scenarios and ground truth.
8. **08 Sigma + Splunk** — detection-as-code content and validated Splunk execution.
9. **09 Velociraptor** — first real investigation backend and collection workflow.
10. **10 Testing & GitHub Actions** — automated unit, integration, contract, and repository checks.
11. **11 Binalyze AIR** — optional integration after the open-source workflow is functional.
12. **12 Observability** — add operational signals justified by running-system needs.
13. **13 CrowdStrike** — optional integration that is never required for core operation.
14. **14 Packer** — reproducible machine images where image lifecycle provides demonstrated value.
15. **15 osquery / Extended Backends** — additional capability-based backends driven by use cases.

WS02 is complete. Both Windows endpoints run Sysmon 15.21 and Splunk Universal Forwarder 10.4.2 and forward Sysmon Operational telemetry to Splunk. The validated Puppet boundary uses deliberate standalone `puppet apply` to manage `Sysmon64` and `SplunkForwarder` running/automatic state and stage canonical Sysmon XML bytes. Staging is not active Sysmon semantic convergence, and Puppet does not own complete Splunk local configuration, endpoint networking, or lab-administration bootstrap. Remaining configuration-management candidates are deferred, non-blocking, and documented in the Puppet environment documentation. WS03 is the next documented workstream.

## Milestone A — Public MVP

- Alert input
- Alert2IR API
- Normalization
- Policy/risk decision
- Incident representation
- MockBackend
- PostgreSQL
- Automated CI tests

## Milestone B — Open DFIR

- Controlled Atomic Red Team scenario
- Windows/Sysmon telemetry
- Splunk detection
- Alert2IR orchestration
- Velociraptor collection/investigation
- Comparison against known ground truth

Binalyze AIR follows a functional open-source workflow. CrowdStrike remains optional.
