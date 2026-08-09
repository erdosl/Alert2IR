# Project Definition

## Problem statement

Security detections often arrive in product-specific shapes and lead to investigation actions that are tightly coupled to a particular vendor. This makes workflows difficult to test, reuse, and explain. Alert2IR will provide a narrow orchestration layer that converts detections into explicit, policy-governed investigation requests executed through backend capabilities.

## Goals

- Normalize source-specific alerts into a canonical internal representation.
- Apply correlation, risk, and policy decisions before requesting investigation.
- Address investigation products by supported capabilities rather than false feature parity.
- Provide a useful open-source path using Splunk, Sigma, Atomic Red Team, and Velociraptor.
- Make core behavior repeatable in CI through a MockBackend.
- Keep architecture decisions and reproducibility material in a public monorepo.

## Non-goals

- Replacing a SIEM, EDR, forensic platform, or full SOAR product.
- Requiring Binalyze AIR, CrowdStrike, or any other commercial platform.
- Deploying Active Directory for the initial project.
- Building speculative distributed infrastructure or prematurely adding orchestration technologies.
- Conducting security testing outside the owned lab.

## Intended audience

Alert2IR is primarily for SecOps and DFIR engineers, detection engineers, security automation practitioners, and portfolio reviewers interested in defensible system design and reproducible validation.

## Success criteria

- A detection can traverse input, normalization, policy/risk evaluation, and incident representation.
- The same investigation request can be tested against a MockBackend and routed to a capable real backend.
- An open DFIR scenario connects controlled ground truth to Windows telemetry, Splunk detection, orchestration, and Velociraptor investigation.
- Automated tests run without commercial products or a live lab.
- Documentation accurately distinguishes deployed facts from plans.

## Principles

- Vendor-neutral core contracts and capability-oriented integrations.
- Detection-driven, evidence-based workflows with explicit authorization boundaries.
- Open and testable defaults; commercial integrations remain optional.
- The simplest architecture that meets demonstrated requirements.
- Git-tracked documentation and ADRs as the record of project state and decisions.
- No credentials, secrets, or sensitive environment data in version control.

