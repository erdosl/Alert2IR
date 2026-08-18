# ADR 0016: Authenticated Splunk source boundary

**Status:** Accepted

## Context

Sigma-derived searches execute in Splunk while Alert2IR accepts only its vendor-neutral canonical alert. Directly publishing `POST /v1/alerts` to the lab network would expose a caller-controlled `source` field that is intentionally an idempotency namespace rather than authentication. Folding Splunk parsing into the canonical application would also violate the vendor-neutral core boundary.

The owned lab needs one small path from a per-result finding to existing durable processing. It does not need a generic SIEM framework, durable source queue, reverse proxy, or second workflow engine.

## Decision

Use a standalone Splunk custom action and a separate `splunk_adapter` Compose service:

```text
Splunk saved-search result
  -> reviewed Sigma metadata + bounded event fields
  -> deterministic alert2ir.splunk-finding.v1 body
  -> timestamped raw-body HMAC
  -> splunk_adapter on 192.168.56.63:8091
  -> deterministic CanonicalAlert + splunk-v1 identity
  -> one private POST to core:8000/v1/alerts
```

The sender owns at most three attempts with one- and two-second delays. The adapter performs no retry, persistence, queueing, or status polling. It fixes canonical `source="splunk"`; derives `source_alert_id` and `Idempotency-Key` from the versioned logical finding identity; and preserves reviewed Sigma level through the versioned severity mapping. PostgreSQL remains the durable replay boundary.

The canonical API stays host-published only at `127.0.0.1:8000`. The adapter shares a private Compose bridge with `core` and is published only at `192.168.56.63:8091`. An external read-only secret file supplies HMAC material. The operator-owned Docker firewall path admits only the Splunk host `192.168.56.61`. HMAC authenticates and protects integrity but does not provide confidentiality; this HTTP design is limited to the owned host-only lab, and a broader network requires TLS review.

The high-severity marker rule is explicit validation-only content, is disabled by default, and may be enabled only for controlled acceptance. It does not alter production-intent detection severity or core policy.

## Alternatives considered

- **Publish canonical `/v1/alerts` to Splunk:** rejected because canonical source is not authentication and the endpoint's loopback trust boundary would be lost.
- **Splunk-side direct canonical conversion:** rejected because it would duplicate the canonical boundary and expose downstream idempotency choice to the sender.
- **Core-side Splunk poller:** rejected because it requires Splunk API credentials, polling state, result-watermark semantics, and more operational coupling.
- **Adapter-local retry or durable queue:** rejected because sender retries are already bounded and a second retry/durability layer would amplify delivery and create another workflow engine.
- **Reverse proxy or TLS stack for the host-only lab:** rejected as unnecessary for the exact owned interface plus source firewall and HMAC boundary. TLS becomes required if that boundary broadens.

## Consequences

Splunk-specific input remains outside `alert2ir.core`, and any future source must independently map to the same canonical contract. A repeated logical finding keeps stable body identity and converges through Alert2IR idempotency, but the architecture does not claim globally exactly-once delivery or remote investigation.

The gateway has no durable source spool. A prolonged outage can exhaust the sender's bounded attempts and require operator re-dispatch. The HMAC secret must be installed as the same protected bytes on two hosts and rotated deliberately. Compose configuration and static tests prove the intended boundary; sanitized records under `validation/integration/` separately preserve the live network, Splunk installation, marker-to-investigation, and replay acceptance evidence.
