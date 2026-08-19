# Alert2IR Splunk finding delivery

This directory is a narrow Splunk Enterprise custom alert-action app. It turns one per-result saved-search row into `alert2ir.splunk-finding.v1` and sends that finding only to the authenticated Alert2IR source gateway at `/v1/splunk/findings`. It never calls `/v1/alerts`, chooses a canonical source, or supplies an idempotency key.

The app is implemented, packageable, statically tested, and separately live-validated in the owned lab. The repository-defined Compose deployment publishes its adapter only at the lab host-only address `192.168.56.63:8091`. This source package alone is not live evidence; a current summary derived from the sanitized acceptance records is retained under `validation/integration/`, with originals in Git history. The committed saved search is disabled, and its host-specific adapter URL and secret-file values are intentionally blank so installation fails closed until an operator supplies `local/` overrides.

## Invocation and result contract

Splunk invokes `bin/alert2ir_delivery.py --execute` with a JSON configuration payload on standard input. The action reads `results_file` as gzip-compressed UTF-8 CSV and requires exactly one row with this ordered bounded projection:

```text
_time Computer host source sourcetype EventCode RecordID
ProcessGuid Image ParentImage TargetFilename
```

With `forceCsvResults=true`, Splunk may append exactly one `__mv_<field>` companion for every projected field. The parser accepts either the projection alone or that exact companion set and discards the companions before finding construction; any arbitrary column or `__mv_` name still fails closed. The saved search uses `alert.digest_mode = false`, so one matching event creates one action invocation. Zero rows, more than one row, malformed CSV, a missing/unsupported projected column, and oversized compressed or decompressed results fail locally without an HTTP request. `_raw`, XML, command line, user, process IDs, search SID, results URL, management URL, and session key are neither forwarded nor logged.

`rule_id`, `rule_title`, `sigma_level`, and `channel` come only from reviewed action configuration. Result columns cannot override them. The action constructs the bounded finding envelope and serializes it once using UTF-8 JSON with sorted keys, compact separators, and NaN disabled. The same exact body bytes are reused for every attempt.

## Authentication

The secret is read from `param.secret_file`; the file must contain at least 32 bytes. At most one terminal LF or CRLF is removed. Secret bytes, request bodies, session keys, timestamps/signatures, and idempotency values are never logged.

Each attempt generates fresh headers:

```text
X-Alert2IR-Timestamp: <Unix epoch seconds>
X-Alert2IR-Signature: v1=<lowercase HMAC-SHA256 hex>
```

The signed bytes exactly match the source-authentication protocol:

```text
alert2ir-splunk-v1\n<timestamp>\n<exact JSON body bytes>
```

The authentication timestamp may change between attempts; the finding body does not.

## Bounded delivery

The sender uses a five-second request timeout, follows no redirects, uses no environment proxy, and performs at most three attempts. It waits one second before attempt two and two seconds before attempt three.

| Adapter result | Sender behavior |
| --- | --- |
| `200 completed` | success |
| `202 accepted` | success |
| `400`, `409`, or `422 permanent_failure` | stop, nonzero |
| `500 durable_failure` | stop, nonzero |
| `502`, `503`, or `504 transient_failure` | retry within the three-attempt bound |
| connection failure or timeout | retry within the three-attempt bound |

The action trusts the bounded gateway classification when it agrees with the HTTP status. A malformed `200`/`202` remains a success because the HTTP contract establishes acceptance; malformed 4xx responses stop; malformed 5xx responses retry because acceptance cannot be established. There is no queue, durable spool, fourth attempt, or status poll.

## Validation-only saved search

`default/savedsearches.conf` contains a disabled validation search derived from `detections/sigma/validation/windows/investigation-delivery-marker.yml` through the repository's process-creation pipeline. Its closed one-minute window runs one minute behind ingestion time when enabled, and its final `table` command drops the command line after applying the Sigma predicate.

The rule detects only the reserved safe lab marker `Alert2IR-INVESTIGATE-` launched by `cmd.exe`. Controlled acceptance used a unique safe marker to exercise the path and then returned the saved search to disabled state. Its `high` level intentionally exercises the existing investigation policy, but it is validation-only content and must not be treated as a production threat detection or run without explicit authorization.

## Package and deploy without enabling delivery

Build an installable archive from a reviewed commit at the repository root:

```bash
tools/splunk/build-alert2ir-delivery-app.sh <reviewed-git-ref> <existing-output-directory>
```

The resulting archive has `alert2ir_delivery/` as its root and contains no Alert2IR application package, generated tarball, secret, or `local/` configuration. Verify the reported SHA-256 after transfer and install it at `$SPLUNK_HOME/etc/apps/alert2ir_delivery` using the normal Splunk app lifecycle. Initial custom-action registration may require a Splunk restart.

Keep repository content under `default/`. On the Splunk host, create `$SPLUNK_HOME/etc/apps/alert2ir_delivery/local/savedsearches.conf` with only the host-specific override and the disabled guard:

```ini
[Alert2IR Investigation Delivery Validation Marker]
disabled = true
enableSched = 0
action.alert2ir_delivery.param.adapter_url = http://192.168.56.63:8091/v1/splunk/findings
action.alert2ir_delivery.param.secret_file = /opt/splunk/etc/auth/alert2ir/alert2ir_delivery.secret
```

Install the same random HMAC bytes used by `splunk_adapter` at that protected path, owned by the Splunk service account and mode `0400`; do not store the bytes in a `.conf` file. Validate effective configuration with `splunk btool alert_actions` and `splunk btool savedsearches`, confirm `bin/alert2ir_delivery.py` is executable, and leave the search disabled. Exact secret installation, firewall rules, health checks, rollback, and trust-boundary verification are in `docs/DEPLOYMENT.md`.

The source gateway is stateless. A prolonged outage can exhaust the sender's three bounded attempts and then requires deliberate operator re-dispatch. There is no queue, spool, proxy retry, or exactly-once claim. The validation rule is not production-intent detection content; the completed acceptance does not authorize future marker execution.
