from contextlib import asynccontextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import unittest

import httpx2

from alert2ir.adapters.splunk import (
    Alert2IRClient,
    Alert2IRDeliveryResult,
    AuthenticationError,
    DeliveryClassification,
    MAX_REQUEST_BODY_BYTES,
    canonicalize,
    compute_signature,
    create_splunk_adapter_app,
    signing_input,
    verify_signature,
)
from alert2ir.adapters.splunk.models import SplunkFinding
from alert2ir.api.schemas import CanonicalAlertRequest


FIXTURE_DIRECTORY = Path(__file__).parent / "fixtures" / "splunk"
SHARED_SECRET = b"0123456789abcdef0123456789abcdef"
OTHER_SECRET = b"abcdef0123456789abcdef0123456789"
NOW_EPOCH = 1_786_566_372
NOW = datetime.fromtimestamp(NOW_EPOCH, tz=timezone.utc)
PROCESSING_ID = "5afaf9ce-3df8-43d3-bac8-1b875211dcc4"
STATUS_URL = f"/v1/processings/{PROCESSING_ID}"
EXPECTED_PROCESS_KEY = (
    "splunk-v1-"
    "6137f60f0a881510b2397bea604e3cb3c97c4846279aa0293de9643440da74a0"
)


def fixture_bytes(name: str = "process_creation.json") -> bytes:
    return (FIXTURE_DIRECTORY / name).read_bytes()


def fixture_object(name: str = "process_creation.json") -> dict[str, object]:
    return json.loads(fixture_bytes(name))


def encode(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def test_signature(
    body: bytes,
    *,
    timestamp: int = NOW_EPOCH,
    secret: bytes = SHARED_SECRET,
) -> str:
    message = (
        b"alert2ir-splunk-v1\n"
        + str(timestamp).encode("ascii")
        + b"\n"
        + body
    )
    return "v1=" + hmac.new(secret, message, hashlib.sha256).hexdigest()


def signed_headers(
    body: bytes,
    *,
    timestamp: int = NOW_EPOCH,
    secret: bytes = SHARED_SECRET,
) -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "X-Alert2IR-Timestamp": str(timestamp),
        "X-Alert2IR-Signature": test_signature(
            body,
            timestamp=timestamp,
            secret=secret,
        ),
    }


def completed_result() -> Alert2IRDeliveryResult:
    return Alert2IRDeliveryResult(
        classification=DeliveryClassification.COMPLETED,
        upstream_status=200,
        processing_id=PROCESSING_ID,
        state="completed",
        status_url=STATUS_URL,
        replayed=False,
        decision_outcome="no_action",
        retryable=False,
        acceptance_unknown=False,
    )


class RecordingDeliveryClient:
    def __init__(self) -> None:
        self.calls: list[tuple[object, str]] = []

    async def submit_alert(
        self,
        alert,
        *,
        idempotency_key: str,
    ) -> Alert2IRDeliveryResult:
        self.calls.append((alert, idempotency_key))
        return completed_result()


class UpstreamRecorder:
    def __init__(
        self,
        *,
        status_code: int = 200,
        body: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
        failure: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.body = body or {}
        self.headers = headers or {}
        self.failure = failure
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        if self.failure == "connection":
            raise httpx2.ConnectError("sanitized connection failure", request=request)
        if self.failure == "timeout":
            raise httpx2.ReadTimeout("sanitized timeout", request=request)
        return httpx2.Response(
            self.status_code,
            json=self.body,
            headers=self.headers,
            request=request,
        )


@asynccontextmanager
async def real_gateway(recorder: UpstreamRecorder):
    upstream = Alert2IRClient(
        base_url="http://alert2ir.invalid",
        timeout_seconds=5.0,
        transport=httpx2.MockTransport(recorder),
    )
    app = create_splunk_adapter_app(
        shared_secret=SHARED_SECRET,
        alert2ir_client=upstream,
        clock=lambda: NOW,
    )
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://adapter.invalid",
    ) as caller:
        yield caller, upstream
    await upstream.aclose()


class SplunkAdapterAuthenticationPrimitiveTests(unittest.TestCase):
    def test_signing_input_and_hmac_vector_are_exact(self) -> None:
        body = b'{"a":1}'
        expected_input = b'alert2ir-splunk-v1\n1786566372\n{"a":1}'
        self.assertEqual(signing_input("1786566372", body), expected_input)
        self.assertEqual(
            compute_signature(SHARED_SECRET, "1786566372", body),
            "c4e03a5591f52c251b1fd38728070921e5e54303714d5dda90529eef1624c179",
        )

    def test_valid_signature_and_inclusive_timestamp_boundaries(self) -> None:
        body = b'{"a":1}'
        for timestamp in (NOW_EPOCH - 300, NOW_EPOCH, NOW_EPOCH + 300):
            with self.subTest(timestamp=timestamp):
                verify_signature(
                    shared_secret=SHARED_SECRET,
                    timestamp_header=str(timestamp),
                    signature_header=test_signature(body, timestamp=timestamp),
                    raw_body=body,
                    now=NOW,
                )

    def test_stale_and_future_timestamps_are_rejected(self) -> None:
        body = b'{"a":1}'
        for timestamp in (NOW_EPOCH - 301, NOW_EPOCH + 301):
            with self.subTest(timestamp=timestamp), self.assertRaises(
                AuthenticationError
            ):
                verify_signature(
                    shared_secret=SHARED_SECRET,
                    timestamp_header=str(timestamp),
                    signature_header=test_signature(body, timestamp=timestamp),
                    raw_body=body,
                    now=NOW,
                )

    def test_signature_is_over_exact_raw_body_bytes(self) -> None:
        compact = b'{"a":1}'
        spaced = b'{ "a": 1 }'
        compact_signature = test_signature(compact)
        verify_signature(
            shared_secret=SHARED_SECRET,
            timestamp_header=str(NOW_EPOCH),
            signature_header=compact_signature,
            raw_body=compact,
            now=NOW,
        )
        with self.assertRaises(AuthenticationError):
            verify_signature(
                shared_secret=SHARED_SECRET,
                timestamp_header=str(NOW_EPOCH),
                signature_header=compact_signature,
                raw_body=spaced,
                now=NOW,
            )
        verify_signature(
            shared_secret=SHARED_SECRET,
            timestamp_header=str(NOW_EPOCH),
            signature_header=test_signature(spaced),
            raw_body=spaced,
            now=NOW,
        )


class SplunkAdapterConstructionTests(unittest.TestCase):
    def test_minimum_secret_is_accepted_and_short_secret_is_rejected(self) -> None:
        create_splunk_adapter_app(
            shared_secret=b"x" * 32,
            alert2ir_client=RecordingDeliveryClient(),
            clock=lambda: NOW,
        )
        with self.assertRaisesRegex(ValueError, "at least 32 bytes"):
            create_splunk_adapter_app(
                shared_secret=b"x" * 31,
                alert2ir_client=RecordingDeliveryClient(),
                clock=lambda: NOW,
            )

    def test_client_rejects_invalid_base_url_and_timeout(self) -> None:
        for base_url in ("", "core:8000", "ftp://core.invalid"):
            with self.subTest(base_url=base_url), self.assertRaises(ValueError):
                Alert2IRClient(base_url=base_url)
        for timeout in (0, -1, float("nan"), float("inf")):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                Alert2IRClient(
                    base_url="http://alert2ir.invalid",
                    timeout_seconds=timeout,
                )


class SplunkAdapterBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.delivery = RecordingDeliveryClient()
        self.app = create_splunk_adapter_app(
            shared_secret=SHARED_SECRET,
            alert2ir_client=self.delivery,
            clock=lambda: NOW,
        )
        self.client = httpx2.AsyncClient(
            transport=httpx2.ASGITransport(
                app=self.app,
                raise_app_exceptions=False,
            ),
            base_url="http://adapter.invalid",
        )

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    async def post(
        self,
        body: bytes,
        *,
        headers: dict[str, str] | list[tuple[str, str]] | None = None,
    ) -> httpx2.Response:
        return await self.client.post(
            "/v1/splunk/findings",
            content=body,
            headers=headers if headers is not None else signed_headers(body),
        )

    async def test_health_is_shallow_and_does_not_call_upstream(self) -> None:
        response = await self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})
        self.assertEqual(self.delivery.calls, [])

    async def test_valid_signature_is_accepted(self) -> None:
        response = await self.post(fixture_bytes())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["classification"], "completed")
        self.assertEqual(len(self.delivery.calls), 1)

    async def test_all_authentication_failures_are_generic_and_skip_upstream(self) -> None:
        body = fixture_bytes()
        valid = signed_headers(body)
        cases: dict[str, dict[str, str] | list[tuple[str, str]]] = {
            "missing signature": {
                "Content-Type": "application/json",
                "X-Alert2IR-Timestamp": str(NOW_EPOCH),
            },
            "missing timestamp": {
                "Content-Type": "application/json",
                "X-Alert2IR-Signature": valid["X-Alert2IR-Signature"],
            },
            "wrong secret": signed_headers(body, secret=OTHER_SECRET),
            "malformed signature": {
                **valid,
                "X-Alert2IR-Signature": "v1=not-hex",
            },
            "short signature": {
                **valid,
                "X-Alert2IR-Signature": "v1=" + "a" * 63,
            },
            "long signature": {
                **valid,
                "X-Alert2IR-Signature": "v1=" + "a" * 65,
            },
            "unsupported version": {
                **valid,
                "X-Alert2IR-Signature": (
                    "v2=" + valid["X-Alert2IR-Signature"].removeprefix("v1=")
                ),
            },
            "uppercase digest": {
                **valid,
                "X-Alert2IR-Signature": valid["X-Alert2IR-Signature"].upper(),
            },
            "stale timestamp": signed_headers(body, timestamp=NOW_EPOCH - 301),
            "future timestamp": signed_headers(body, timestamp=NOW_EPOCH + 301),
            "malformed timestamp": {
                **valid,
                "X-Alert2IR-Timestamp": "not-an-epoch",
            },
            "duplicate signature": [
                ("Content-Type", "application/json"),
                ("X-Alert2IR-Timestamp", str(NOW_EPOCH)),
                ("X-Alert2IR-Signature", valid["X-Alert2IR-Signature"]),
                ("X-Alert2IR-Signature", valid["X-Alert2IR-Signature"]),
            ],
            "duplicate timestamp": [
                ("Content-Type", "application/json"),
                ("X-Alert2IR-Timestamp", str(NOW_EPOCH)),
                ("X-Alert2IR-Timestamp", str(NOW_EPOCH)),
                ("X-Alert2IR-Signature", valid["X-Alert2IR-Signature"]),
            ],
        }
        for name, headers in cases.items():
            with self.subTest(name=name):
                response = await self.post(body, headers=headers)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json(), {"error": "authentication_failed"})
        self.assertEqual(self.delivery.calls, [])

    async def test_unauthenticated_invalid_json_is_not_parsed(self) -> None:
        response = await self.post(b"not-json", headers={})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"error": "authentication_failed"})
        self.assertEqual(self.delivery.calls, [])

    async def test_mutated_body_after_signing_is_rejected(self) -> None:
        body = fixture_bytes()
        changed = body + b" "
        response = await self.post(changed, headers=signed_headers(body))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"error": "authentication_failed"})
        self.assertEqual(self.delivery.calls, [])

    async def test_timestamp_boundaries_are_inclusive(self) -> None:
        body = fixture_bytes()
        for timestamp in (NOW_EPOCH - 300, NOW_EPOCH + 300):
            with self.subTest(timestamp=timestamp):
                response = await self.post(
                    body,
                    headers=signed_headers(body, timestamp=timestamp),
                )
                self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self.delivery.calls), 2)

    async def test_body_size_limit_is_enforced_before_schema_processing(self) -> None:
        at_limit = b" " * MAX_REQUEST_BODY_BYTES
        over_limit = b" " * (MAX_REQUEST_BODY_BYTES + 1)
        accepted_size = await self.post(
            at_limit,
            headers=signed_headers(at_limit),
        )
        rejected_size = await self.post(over_limit, headers={})
        self.assertEqual(accepted_size.status_code, 400)
        self.assertEqual(accepted_size.json(), {"error": "invalid_json"})
        self.assertEqual(rejected_size.status_code, 413)
        self.assertEqual(rejected_size.json(), {"error": "request_too_large"})
        self.assertEqual(self.delivery.calls, [])

    async def test_authenticated_invalid_json_skips_upstream(self) -> None:
        body = b'{"schema":'
        response = await self.post(body)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_json"})
        self.assertEqual(self.delivery.calls, [])

        nonstandard = b'{"value":NaN}'
        response = await self.post(nonstandard)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"error": "invalid_json"})
        self.assertEqual(self.delivery.calls, [])

    async def test_authenticated_schema_and_canonicalization_errors_skip_upstream(
        self,
    ) -> None:
        cases: dict[str, bytes] = {}
        wrong_schema = fixture_object("minimal.json")
        wrong_schema["schema"] = "alert2ir.splunk-finding.v2"
        cases["wrong schema"] = encode(wrong_schema)

        missing_rule = fixture_object("minimal.json")
        del missing_rule["detection"]["rule_id"]
        cases["missing Sigma UUID"] = encode(missing_rule)

        invalid_timestamp = fixture_object("minimal.json")
        invalid_timestamp["event"]["_time"] = "not-a-timestamp"
        cases["invalid timestamp"] = encode(invalid_timestamp)

        overlong = fixture_object("minimal.json")
        overlong["detection"]["rule_title"] = "x" * 257
        cases["overlong value"] = encode(overlong)

        cases["conflicting host"] = fixture_bytes("conflicting_host.json")

        for name, body in cases.items():
            with self.subTest(name=name):
                response = await self.post(body)
                self.assertEqual(response.status_code, 422)
                self.assertEqual(
                    response.json(),
                    {"error": "invalid_splunk_finding"},
                )
        self.assertEqual(self.delivery.calls, [])

    async def test_wrong_content_type_is_rejected_after_authentication(self) -> None:
        body = fixture_bytes()
        headers = signed_headers(body)
        headers["Content-Type"] = "text/plain"
        response = await self.post(body, headers=headers)
        self.assertEqual(response.status_code, 415)
        self.assertEqual(response.json(), {"error": "unsupported_media_type"})
        self.assertEqual(self.delivery.calls, [])

    async def test_all_finding_fixtures_reach_client_once_when_valid(self) -> None:
        expected_hosts = {
            "process_creation.json": "win11-02",
            "file_creation.json": "win11-02",
            "minimal.json": "win11-02",
        }
        for name, expected_host in expected_hosts.items():
            with self.subTest(name=name):
                before = len(self.delivery.calls)
                response = await self.post(fixture_bytes(name))
                self.assertEqual(response.status_code, 200)
                self.assertEqual(len(self.delivery.calls), before + 1)
                alert, _ = self.delivery.calls[-1]
                self.assertEqual(len(alert.entities), 1)
                self.assertEqual(alert.entities[0].kind, "host")
                self.assertEqual(alert.entities[0].value, expected_host)
                self.assertEqual(alert.source.source, "splunk")

    async def test_caller_cannot_choose_idempotency_key(self) -> None:
        body = fixture_bytes()
        headers = signed_headers(body)
        headers["Idempotency-Key"] = "caller-controlled"
        response = await self.post(body, headers=headers)
        self.assertEqual(response.status_code, 200)
        _, actual_key = self.delivery.calls[0]
        self.assertEqual(actual_key, EXPECTED_PROCESS_KEY)


class SplunkAlert2IRClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_exact_canonical_request_is_sent_once(self) -> None:
        recorder = UpstreamRecorder(
            status_code=200,
            body={
                "processing_id": PROCESSING_ID,
                "state": "completed",
                "status_url": STATUS_URL,
                "decision": {"outcome": "no_action"},
            },
        )
        client = Alert2IRClient(
            base_url="http://alert2ir.invalid",
            timeout_seconds=5.0,
            transport=httpx2.MockTransport(recorder),
        )
        canonical_finding = canonicalize(
            SplunkFinding.model_validate(fixture_object())
        )
        try:
            result = await client.submit_alert(
                canonical_finding.alert,
                idempotency_key=canonical_finding.idempotency_key,
            )
        finally:
            await client.aclose()

        self.assertEqual(result.classification, DeliveryClassification.COMPLETED)
        self.assertEqual(len(recorder.requests), 1)
        request = recorder.requests[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.url.path, "/v1/alerts")
        self.assertEqual(request.headers["Content-Type"], "application/json")
        self.assertEqual(request.headers["Idempotency-Key"], EXPECTED_PROCESS_KEY)
        self.assertEqual(
            json.loads(request.content),
            CanonicalAlertRequest.from_domain(canonical_finding.alert).model_dump(mode="json"),
        )
        self.assertEqual(
            json.loads(request.content)["entities"],
            [{"kind": "host", "value": "win11-02"}],
        )


class SplunkGatewayUpstreamSemanticsTests(unittest.IsolatedAsyncioTestCase):
    async def submit(self, recorder: UpstreamRecorder) -> tuple[httpx2.Response, int]:
        body = fixture_bytes()
        async with real_gateway(recorder) as (caller, _):
            response = await caller.post(
                "/v1/splunk/findings",
                content=body,
                headers=signed_headers(body),
            )
        return response, len(recorder.requests)

    async def test_all_upstream_status_and_transport_semantics_are_explicit(
        self,
    ) -> None:
        cases = {
            "200 completed": (
                UpstreamRecorder(
                    status_code=200,
                    body={
                        "processing_id": PROCESSING_ID,
                        "state": "completed",
                        "status_url": STATUS_URL,
                        "decision": {"outcome": "no_action"},
                    },
                ),
                200,
                "completed",
                False,
                False,
                None,
            ),
            "202 accepted": (
                UpstreamRecorder(
                    status_code=202,
                    body={
                        "processing_id": PROCESSING_ID,
                        "state": "submitted",
                        "status_url": STATUS_URL,
                    },
                    headers={"Location": STATUS_URL},
                ),
                202,
                "accepted",
                False,
                False,
                None,
            ),
            "400 permanent": (
                UpstreamRecorder(
                    status_code=400,
                    body={"code": "invalid_idempotency_key"},
                ),
                400,
                "permanent_failure",
                False,
                False,
                "invalid_idempotency_key",
            ),
            "409 idempotency conflict": (
                UpstreamRecorder(
                    status_code=409,
                    body={"code": "idempotency_conflict"},
                ),
                409,
                "permanent_failure",
                False,
                False,
                "idempotency_conflict",
            ),
            "409 unsupported capability": (
                UpstreamRecorder(
                    status_code=409,
                    body={
                        "code": "unsupported_capability",
                        "processing_id": PROCESSING_ID,
                        "state": "failed",
                        "status_url": STATUS_URL,
                    },
                    headers={"Location": STATUS_URL},
                ),
                409,
                "permanent_failure",
                False,
                False,
                "unsupported_capability",
            ),
            "422 permanent": (
                UpstreamRecorder(
                    status_code=422,
                    body={"code": "validation_error"},
                ),
                422,
                "permanent_failure",
                False,
                False,
                "validation_error",
            ),
            "500 durable": (
                UpstreamRecorder(
                    status_code=500,
                    body={
                        "processing_id": PROCESSING_ID,
                        "state": "failed",
                        "status_url": STATUS_URL,
                        "error_category": "backend_execution_failed",
                    },
                    headers={"Location": STATUS_URL},
                ),
                500,
                "durable_failure",
                False,
                False,
                "backend_execution_failed",
            ),
            "500 generic": (
                UpstreamRecorder(
                    status_code=500,
                    body={"detail": "Internal Server Error"},
                ),
                502,
                "transient_failure",
                True,
                True,
                "upstream_internal_failure",
            ),
            "503 unavailable": (
                UpstreamRecorder(
                    status_code=503,
                    body={"code": "persistence_failed"},
                ),
                503,
                "transient_failure",
                True,
                False,
                "persistence_failed",
            ),
            "connection failure": (
                UpstreamRecorder(failure="connection"),
                502,
                "transient_failure",
                True,
                False,
                "upstream_connection_failed",
            ),
            "timeout": (
                UpstreamRecorder(failure="timeout"),
                504,
                "transient_failure",
                True,
                True,
                "upstream_timeout",
            ),
        }
        for name, case in cases.items():
            recorder, status, classification, retryable, unknown, error_code = case
            with self.subTest(name=name):
                response, request_count = await self.submit(recorder)
                body = response.json()
                self.assertEqual(request_count, 1)
                self.assertEqual(response.status_code, status)
                self.assertEqual(body["classification"], classification)
                self.assertEqual(body["retryable"], retryable)
                self.assertEqual(body["acceptance_unknown"], unknown)
                if error_code is None:
                    self.assertNotIn("error_code", body)
                else:
                    self.assertEqual(body["error_code"], error_code)
                self.assertNotIn("detail", body)
                self.assertNotIn("message", body)

    async def test_success_preserves_bounded_processing_fields_without_polling(
        self,
    ) -> None:
        recorder = UpstreamRecorder(
            status_code=202,
            body={
                "processing_id": PROCESSING_ID,
                "state": "submitted",
                "status_url": STATUS_URL,
            },
            headers={"Location": STATUS_URL},
        )
        response, request_count = await self.submit(recorder)
        self.assertEqual(request_count, 1)
        self.assertEqual(response.status_code, 202)
        self.assertEqual(
            response.json(),
            {
                "classification": "accepted",
                "upstream_status": 202,
                "processing_id": PROCESSING_ID,
                "state": "submitted",
                "status_url": STATUS_URL,
                "replayed": False,
                "retryable": False,
                "acceptance_unknown": False,
            },
        )
        self.assertEqual(recorder.requests[0].url.path, "/v1/alerts")

    async def test_repeated_inbound_finding_is_forwarded_once_per_request(self) -> None:
        class ReplayRecorder:
            def __init__(self) -> None:
                self.requests: list[httpx2.Request] = []

            def __call__(self, request: httpx2.Request) -> httpx2.Response:
                self.requests.append(request)
                headers = {"Location": STATUS_URL}
                if len(self.requests) == 2:
                    headers["Idempotency-Replayed"] = "true"
                return httpx2.Response(
                    200,
                    json={
                        "processing_id": PROCESSING_ID,
                        "state": "completed",
                        "status_url": STATUS_URL,
                        "decision": {"outcome": "no_action"},
                    },
                    headers=headers,
                    request=request,
                )

        recorder = ReplayRecorder()
        body = fixture_bytes()
        upstream = Alert2IRClient(
            base_url="http://alert2ir.invalid",
            transport=httpx2.MockTransport(recorder),
        )
        app = create_splunk_adapter_app(
            shared_secret=SHARED_SECRET,
            alert2ir_client=upstream,
            clock=lambda: NOW,
        )
        try:
            async with httpx2.AsyncClient(
                transport=httpx2.ASGITransport(
                    app=app,
                    raise_app_exceptions=False,
                ),
                base_url="http://adapter.invalid",
            ) as caller:
                first = await caller.post(
                    "/v1/splunk/findings",
                    content=body,
                    headers=signed_headers(body),
                )
                second = await caller.post(
                    "/v1/splunk/findings",
                    content=body,
                    headers=signed_headers(body),
                )
        finally:
            await upstream.aclose()

        self.assertEqual(first.status_code, 200)
        self.assertFalse(first.json()["replayed"])
        self.assertTrue(second.json()["replayed"])
        self.assertEqual(len(recorder.requests), 2)
        self.assertEqual(recorder.requests[0].content, recorder.requests[1].content)
        self.assertEqual(
            recorder.requests[0].headers["Idempotency-Key"],
            EXPECTED_PROCESS_KEY,
        )
        self.assertEqual(
            recorder.requests[1].headers["Idempotency-Key"],
            EXPECTED_PROCESS_KEY,
        )


if __name__ == "__main__":
    unittest.main()
