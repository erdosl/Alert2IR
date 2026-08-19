# ADR 0015: Bounded live attack-simulation coverage under the Windows execution baseline

**Status:** Accepted

## Context

The seven primary breadth scenarios and one ancestry negative control are statically implemented with reviewed behavior, provenance, telemetry, cleanup, Sigma, Splunk mapping, and evidence contracts. Direct Event 11 detection, Event 26 cleanup, and independent post-state verification are VALIDATED-LIVE. The separately accepted authoritative DNS and Windows NRPT infrastructure satisfies the Event 22 DNS prerequisite.

Execution-policy discovery found Windows PowerShell 5.1 in FullLanguage mode, no effective AppLocker policy, and no applicable custom WDAC enforcement. All PowerShell execution-policy scopes are `Undefined`, so Windows clients use the effective `Restricted` fallback. The current repository `.ps1` wrappers are unsigned, and the SFTP-staged copies have no Mark of the Web. `RemoteSigned` would therefore not meaningfully constrain the actual transport, while `AllSigned` would require a new certificate, signing, trusted-publisher, and lifecycle architecture.

Running Event 3, Event 15, Event 22, or the ancestry positive/control pair would consequently require a policy workaround, a new signing/trust baseline, or changed scenario semantics. The incremental live attack-simulation coverage does not justify that infrastructure or those changes.

## Decision

Keep the current Restricted/default Windows endpoint behavior unchanged. Do not introduce a script-execution trust or signing subsystem solely for attack simulation, and do not bypass or transiently override the endpoint execution baseline.

Preserve all static breadth implementation, including the seven primary scenarios, one ancestry negative control, wrappers, validation-only Sigma rules, mappings, schemas, cleanup contracts, provenance, and deterministic tests. Mark Event 3, Event 15, Event 22, ancestry positive, and ancestry negative-control live execution as deliberately deferred. Event 22's DNS prerequisite remains satisfied and VALIDATED-LIVE; only its wrapper-backed scenario and detection acceptance are deferred.

The breadth portfolio is complete within this bounded stopping condition. Coverage is intentionally asymmetric between static validation and live endpoint execution.

## Rejected alternatives

- **REJECTED FOR CURRENT SCOPE — `AllSigned` plus Authenticode wrapper infrastructure:** creates a new signing and trust lifecycle.
- **REJECTED — `RemoteSigned`:** would not materially constrain the current no-MOTW staging transport.
- **REJECTED — `ExecutionPolicy Bypass`, transient overrides, and execution-policy mutation:** would weaken or evade the endpoint baseline.
- **REJECTED — inline `-Command` delivery of wrapper behavior:** would evade the `.ps1` restriction rather than preserve the reviewed execution boundary.
- **REJECTED — Windows Script Host signed-only policy:** would add another signing/trust baseline solely for this portfolio.
- **REJECTED — native rewrites, a compiled helper, or another replacement implementation solely to increase coverage:** would change scenario semantics and add maintenance cost without product value.

The additional infrastructure and trust lifecycle are not justified by the incremental attack-simulation coverage.

## Consequences

Positive consequences:

- Project and endpoint complexity stay bounded.
- No PKI, signing, certificate-distribution, or trusted-publisher lifecycle is introduced.
- No machine-wide execution-policy change or scenario-specific policy bypass occurs.
- Static correctness and future re-evaluation assets remain intact.
- Evidence classifications remain truthful: implemented does not imply live accepted.
- Engineering can return to the detection-to-investigation product path.

Negative consequences:

- Event 3, Event 15, Event 22, and ancestry remain unvalidated live.
- Some Sigma-to-Splunk field mappings remain static-only.
- The ancestry negative-control behavior remains unproven live.

The independent staging-directory write-permission issue is not an execution-policy reason to reopen this decision. The repository records the desired ACL in `config/windows/attack-simulation-staging-acl.json`; live remediation requires a separately authorized endpoint-hardening change.

## Revisit trigger

Reconsider live execution only if a future independent endpoint-baseline requirement introduces an approved trusted script-execution model. There is no calendar trigger.
