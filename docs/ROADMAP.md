# Roadmap

Workstreams describe coherent areas of work. Their numbering communicates a useful progression, but they are not rigid serial dependencies; work may overlap when prerequisites, risk, and validation permit.

1. **01 Baseline & Architecture** — repository conventions, project boundaries, ADRs, lab record, and scope.
2. **02 Windows Endpoint Reproducibility** — completed: repeatable endpoint prerequisites and telemetry configuration.
3. **03 Docker / IR-Core** — completed: minimal application/service composition validated on the runtime host.
4. **04 Alert2IR Core** — completed: API, canonical alert normalization, decisions, incidents, and backend contracts.
5. **05 Persistence** — completed: PostgreSQL data model, explicit migrations, durable completed processing, and validated lifecycle behavior.
6. **06 Puppet** — completed: tested desired-state roles/profiles and exact-artifact convergence validation on both Windows endpoints.
7. **07 Attack Simulation** — completed: three pinned Atomic-derived scenarios, controlled canary execution, sanitized ground truth, and independently verified required cleanup.
8. **08 Sigma + Splunk** — next: detection-as-code content and validated Splunk execution.
9. **09 Velociraptor** — first real investigation backend and collection workflow.
10. **10 Testing & GitHub Actions** — automated unit, integration, contract, and repository checks.
11. **11 Binalyze AIR** — optional integration after the open-source workflow is functional.
12. **12 Observability** — add operational signals justified by running-system needs.
13. **13 CrowdStrike** — optional integration that is never required for core operation.
14. **14 Packer** — reproducible machine images where image lifecycle provides demonstrated value.
15. **15 osquery / Extended Backends** — additional capability-based backends driven by use cases.

WS02 is complete. Both Windows endpoints run Sysmon 15.21 and Splunk Universal Forwarder 10.4.2 and forward Sysmon Operational telemetry to Splunk. The validated Puppet boundary uses deliberate standalone `puppet apply` to manage `Sysmon64` and `SplunkForwarder` running/automatic state and stage canonical Sysmon XML bytes. Staging is not active Sysmon semantic convergence, and Puppet does not own complete Splunk local configuration, endpoint networking, or lab-administration bootstrap. Remaining configuration-management candidates are deferred, non-blocking, and documented in the Puppet environment documentation.

WS03 is complete. Its Docker Compose runtime is one containerized FastAPI `core` service, validated on `ir-core` with a deterministic health endpoint, non-root execution, loopback-only publication, and successful restart and recreation. Persistence and supporting services are intentionally outside this slice.

WS04 is complete. It provides a vendor-neutral canonical normalization contract, an explainable deterministic policy, incident and investigation representations, capability-based backend selection, a deterministic MockBackend, in-memory orchestration, and typed `POST /v1/alerts`. The exact reviewed artifact was validated on `ir-core`; persistence, live integrations, and production-hardening concerns remain in their later workstreams.

WS05 is complete. The exact Git artifact was validated on `ir-core` with internal-only PostgreSQL, explicit and repeatable migration `0001_processing_records`, durable LOW and HIGH completed processing, core-recreation and ordinary Compose down/up durability, loopback-only API publication, non-root execution, and liveness-only health during PostgreSQL outage. The temporary validation deployment and its retained data volume were deliberately removed afterward; it did not create a permanent deployment. Retries, durable idempotency, execution recovery, lifecycle/correlation/retention, backup/DR, HA, readiness, and production scaling remain deferred.

WS06 is complete. The existing narrow roles/profiles implementation remains unchanged and is now covered by deterministic Python-standard-library repository contracts. One exact Git-derived Puppet artifact was built from commit `8227653814dd25e938ee7ff04849d11968285ca5`, independently hash-verified on `dev01`, `win11-02`, and `win11-01`, and promoted unchanged from the canary. Standalone Puppet 8.20.0 compiled and applied it on both endpoints; each noop, first enforcing apply, and second enforcing apply exited `0` with no corrective resource events. Managed services remained running/automatic, the staged Sysmon XML remained canonical, and Puppet Agent remained stopped/disabled. No desired-state ownership, server control plane, dependencies, credentials, or private Hiera values were added. No WS07 implementation is included in WS06.

WS07 is complete. Commit `2be9f04eac3c7314753793dd5e7c6651f382f815` defines the three-scenario contract, and commit `8852fabf0685c1e053859bf2d230e0546fae65d0` records the sanitized canary ground truth. One exact `config/attack-simulation/scenarios.json` artifact derived from pinned Atomic Red Team commit `1ba1dd8d9ce6f74700f7aec2e60de5632f667f03` supplied literal reviewed commands for controlled execution on `win11-02`. All three processes exited `0`; required Sysmon expectations were observed; the non-guaranteed PowerShell Operational absence and the additional file-content assertion deviation were retained honestly; exact file cleanup succeeded and post-cleanup absence was independently verified. The repository contains no raw/private endpoint evidence or attack framework. No second-host run was required, and no Sigma, Splunk detection, Alert2IR orchestration, or Velociraptor work was pulled forward. WS08 Sigma + Splunk is next.

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
