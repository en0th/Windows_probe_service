"""Offline wire-contract checks for the lightweight HTTP API and its guards."""
import copy
import json
import logging
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import AsyncMock, MagicMock

import httpx

SERVICE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_DIR))

import service
from network_policy import NetworkPolicy


TOKEN = "offline-http-pairing-token-never-a-real-token-12345"
PUBLIC = "93.184.216.34"


def valid_batch():
    return {"queryId": "offline-query", "targets": [{"id": "t1", "host": PUBLIC, "port": 443}]}


class HttpValidationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        rules = Path(self.folder.name) / "rules.json"
        rules.write_text(json.dumps({
            "version": "offline-http-fixture", "updatedAt": "2026-11-17",
            "cidrs": [{"cidr": "104.16.0.0/13", "provider": "fixture", "source": "offline"}],
            "domainSuffixes": [{"suffix": "edge.example.invalid", "provider": "fixture", "source": "offline"}],
        }), encoding="utf-8")
        self.settings = service.Settings(token=TOKEN, data_dir=Path(self.folder.name))
        self.engine = types.SimpleNamespace(
            allow_non_windows=True, start=AsyncMock(), close=AsyncMock(),
            submit=MagicMock(side_effect=lambda batch: types.SimpleNamespace(
                id="offline-job", query_id=batch.queryId, total=len(batch.targets))),
            snapshot=MagicMock(return_value={"jobId": "offline-job", "queryId": "offline-query",
                "status": "queued", "total": 1, "completed": 0, "cursor": 0, "results": []}),
            cancel=MagicMock(return_value=types.SimpleNamespace(id="offline-job", query_id="offline-query",
                status="cancelled", total=1, results=[])),
        )
        logger = logging.getLogger("offline-http-validation")
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())
        self.app = service.create_app(settings=self.settings, policy=NetworkPolicy(rules),
                                      engine=self.engine, logger=logger)
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app, client=("127.0.0.1", 12345)),
            base_url="http://127.0.0.1", headers={"Authorization": "Bearer " + TOKEN})
        self.addAsyncCleanup(self.client.aclose)

    def assert_error(self, response, status):
        self.assertEqual(response.status_code, status, response.text)
        self.assertIn("detail", response.json())
        self.assertNotIn(TOKEN, response.text)

    async def test_anonymous_health_get_and_head_do_not_create_work(self):
        for method in ("GET", "HEAD"):
            with self.subTest(method=method):
                response = await self.client.request(method, "/health", headers={"Authorization": ""})
                self.assertEqual(response.status_code, 200)
                self.assertNotIn(TOKEN, response.text)
                if method == "HEAD":
                    self.assertEqual(response.content, b"")
                else:
                    self.assertEqual(response.json()["apiVersion"], 1)
        self.engine.submit.assert_not_called()
        self.engine.snapshot.assert_not_called()

    async def test_wrong_credentials_receive_challenge_without_echo(self):
        for value in ("", "Basic " + TOKEN, "Bearer ", "Bearer wrong", "Bearer " + TOKEN + "x"):
            with self.subTest(header=value[:12]):
                response = await self.client.get("/v1/auth-check", headers={"Authorization": value})
                self.assert_error(response, 401)
                self.assertEqual(response.headers.get("www-authenticate"), "Bearer")
        response = await self.client.get("/v1/auth-check", headers=[
            ("Authorization", "Bearer " + TOKEN), ("Authorization", "Bearer wrong")])
        self.assert_error(response, 401)

    async def test_authentication_precedes_json_content_and_schema_validation(self):
        for content, content_type in ((b"{", "application/json"), (b"null", "application/json"),
                                      (b"not-json", "text/plain")):
            with self.subTest(content=content, content_type=content_type):
                response = await self.client.post("/v1/probes", content=content,
                    headers={"Authorization": "Bearer wrong", "Content-Type": content_type})
                self.assert_error(response, 401)
        response = await self.client.get("/v1/probes/offline-job?after=invalid",
                                         headers={"Authorization": ""})
        self.assert_error(response, 401)
        self.engine.submit.assert_not_called()
        self.engine.snapshot.assert_not_called()

    async def test_non_json_media_types_are_rejected(self):
        for content_type in ("text/plain", "application/x-www-form-urlencoded", "application/octet-stream"):
            with self.subTest(content_type=content_type):
                response = await self.client.post("/v1/probes", content=json.dumps(valid_batch()),
                                                  headers={"Content-Type": content_type})
                self.assert_error(response, 415)
        response = await self.client.post("/v1/probes", content=json.dumps(valid_batch()))
        self.assert_error(response, 415)
        self.engine.submit.assert_not_called()

    async def test_malformed_json_is_rejected_without_echoing_input(self):
        marker = "private-invalid-payload-marker"
        bodies = (b"", b"{", b"\xff", ('{"queryId":"' + marker + '"').encode(),
                  b'{"targets": NaN}', b'{"targets": Infinity}', b'{"targets": -Infinity}',
                  b'{"queryId":"first","queryId":"second","targets":[]}',
                  b"[" * 1100 + b"0" + b"]" * 1100)
        for body in bodies:
            with self.subTest(body=body[:40]):
                response = await self.client.post("/v1/probes", content=body,
                                                  headers={"Content-Type": "application/json"})
                self.assert_error(response, 422)
                self.assertNotIn(marker, response.text)
        self.engine.submit.assert_not_called()

    async def test_non_object_json_is_rejected(self):
        for value in (None, [], "not-a-batch", True, 123):
            with self.subTest(value=value):
                response = await self.client.post("/v1/probes", content=json.dumps(value),
                                                  headers={"Content-Type": "application/json"})
                self.assert_error(response, 422)
        self.engine.submit.assert_not_called()

    async def test_schema_forbids_unknown_fields_and_private_input_echo(self):
        marker = "private-input-must-not-be-echoed"
        batch_extra = valid_batch()
        batch_extra["unexpected"] = marker
        target_extra = valid_batch()
        target_extra["targets"][0]["command"] = marker
        for payload in (batch_extra, target_extra):
            with self.subTest(payload=payload):
                response = await self.client.post("/v1/probes", json=payload)
                self.assert_error(response, 422)
                self.assertNotIn(marker, response.text)
        self.engine.submit.assert_not_called()

    async def test_ports_require_bounded_integers_without_coercion(self):
        for port in (True, False, "443", 443.0, 0, -1, 65536):
            with self.subTest(port=port):
                payload = valid_batch()
                payload["targets"][0]["port"] = port
                self.assert_error(await self.client.post("/v1/probes", json=payload), 422)
        self.engine.submit.assert_not_called()

    async def test_strings_containers_and_duplicate_ids_are_validated(self):
        payloads = []
        for field, value in (("queryId", 42), ("queryId", ""), ("targets", []),
                             ("targets", {}), ("excludedHosts", "1.1.1.1"),
                             ("excludedHosts", [1]), ("excludedCidrs", None),
                             ("excludedCidrs", ["10.0.0.1/24"])):
            payload = valid_batch()
            payload[field] = value
            payloads.append(payload)
        for field, value in (("id", 42), ("id", ""), ("host", 42), ("host", "")):
            payload = valid_batch()
            payload["targets"][0][field] = value
            payloads.append(payload)
        duplicate = valid_batch()
        duplicate["targets"].append(copy.deepcopy(duplicate["targets"][0]))
        payloads.append(duplicate)
        for payload in payloads:
            with self.subTest(payload=payload):
                self.assert_error(await self.client.post("/v1/probes", json=payload), 422)
        self.engine.submit.assert_not_called()

    async def test_valid_submission_normalizes_host_and_preserves_wire_keys(self):
        payload = {"queryId": "offline-query", "excludedHosts": [PUBLIC, PUBLIC],
                   "excludedCidrs": ["93.184.216.0/24", "93.184.216.0/24"],
                   "targets": [{"id": "domain", "host": "ORIGIN.Example.Invalid.", "port": None},
                               {"id": "ip", "host": PUBLIC, "port": 65535}]}
        response = await self.client.post("/v1/probes", content=json.dumps(payload),
                                          headers={"Content-Type": "application/json; charset=utf-8"})
        self.assertEqual(response.status_code, 202, response.text)
        self.assertEqual(response.json(), {"jobId": "offline-job", "queryId": "offline-query", "total": 2, "cursor": 0})
        batch = self.engine.submit.call_args.args[0]
        self.assertEqual(batch.targets[0].host, "origin.example.invalid")
        self.assertIsNone(batch.targets[0].port)
        self.assertEqual(batch.excludedHosts, [PUBLIC])
        self.assertEqual(batch.excludedCidrs, ["93.184.216.0/24"])

    async def test_omitted_port_remains_optional(self):
        payload = valid_batch()
        del payload["targets"][0]["port"]
        response = await self.client.post("/v1/probes", json=payload)
        self.assertEqual(response.status_code, 202, response.text)
        self.assertIsNone(self.engine.submit.call_args.args[0].targets[0].port)

    async def test_invalid_result_cursors_do_not_reach_engine(self):
        for after in ("", "-1", str(service.MAX_TARGETS + 1), "1.5", "true", "invalid"):
            with self.subTest(after=after):
                self.assert_error(await self.client.get("/v1/probes/offline-job", params={"after": after}), 422)
        self.engine.snapshot.assert_not_called()

    async def test_engine_errors_preserve_public_status_contract(self):
        self.engine.submit.side_effect = service.CapacityError("queue_full")
        response = await self.client.post("/v1/probes", json=valid_batch())
        self.assert_error(response, 429)
        self.assertEqual(response.headers.get("retry-after"), "2")
        for method, mock in (("GET", self.engine.snapshot), ("DELETE", self.engine.cancel)):
            mock.side_effect = KeyError("private-engine-detail")
            response = await self.client.request(method, "/v1/probes/missing")
            self.assert_error(response, 404)
            self.assertEqual(response.json()["detail"], "job_not_found")
            self.assertNotIn("private-engine-detail", response.text)
        self.engine.snapshot.side_effect = ValueError("private-engine-detail")
        response = await self.client.get("/v1/probes/offline-job?after=1")
        self.assert_error(response, 400)
        self.assertEqual(response.json()["detail"], "cursor_ahead")

    async def test_streamed_request_cannot_exceed_body_limit(self):
        async def chunks():
            chunk = b" " * (64 * 1024)
            for _ in range(service.MAX_BODY_BYTES // len(chunk)):
                yield chunk
            yield b" "

        response = await self.client.post("/v1/probes", content=chunks(),
                                          headers={"Content-Type": "application/json"})
        self.assert_error(response, 413)
        self.engine.submit.assert_not_called()

    async def test_non_loopback_and_invalid_host_are_blocked(self):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app, client=("192.0.2.10", 12345)),
                                    base_url="http://127.0.0.1") as external:
            self.assert_error(await external.get("/health"), 403)
        response = await self.client.get("/health", headers={"Host": "outside.example.invalid"})
        self.assertEqual(response.status_code, 400)
        self.engine.submit.assert_not_called()

    async def test_route_methods_remain_explicit(self):
        for method, path in (("POST", "/health"), ("GET", "/v1/probes"),
                             ("PUT", "/v1/probes/offline-job"), ("DELETE", "/v1/auth-check")):
            with self.subTest(method=method, path=path):
                response = await self.client.request(method, path)
                self.assert_error(response, 405)
        self.assert_error(await self.client.get("/unknown-route"), 404)
        self.engine.submit.assert_not_called()
        self.engine.snapshot.assert_not_called()
        self.engine.cancel.assert_not_called()


if __name__ == "__main__":
    unittest.main()
