"""Offline contracts for K01 API login, bounded queries and browser fallback."""
import asyncio
import io
import json
import logging
from pathlib import Path
import ssl
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import httpx

SERVICE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_DIR))

import k01_intelligence as k01
import service
from network_policy import NetworkPolicy


PAIRING = "offline-k01-pairing-token-not-a-real-token-123456"
PASSWORD = "offline-api-password-value"
ACCESS = "offline-upstream-access-token"
CONFIG = {"baseUrl": "https://k01.example.invalid", "username": "apiuser", "password": PASSWORD}


def login_reply(token=ACCESS):
    return k01.Reply(200, {"success": True, "token": {"access_token": token,
                                                    "refresh_token": "offline-refresh-token"}})


def result_reply(host="origin.example.invalid"):
    return k01.Reply(200, {"success": True, "error_code": 0,
                          "data": {"base_info": {"host": host, "malice_num": 1},
                                   "descriptors": [{"name": "Offline supplier", "isEmpty": False}]}})


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)

    def test_config_persists_without_overwriting_existing_probe_settings(self):
        folder = Path(self.folder.name)
        original = {"token": PAIRING, "port": 8765, "excludedCidrs": ["192.168.0.0/16"],
                    "unrelated": {"existing": True}}
        (folder / "config.json").write_text(json.dumps(original))
        client = k01.K01IntelligenceClient(folder, PAIRING)
        self.assertFalse(client.status()["configured"])
        saved = client.update_config(CONFIG)
        encoded = json.dumps(saved)
        self.assertNotIn(PASSWORD, encoded)
        self.assertNotIn(PAIRING, encoded)
        self.assertTrue(saved["config"]["passwordConfigured"])
        disk = json.loads((folder / "config.json").read_text())
        self.assertEqual({key: disk[key] for key in original}, original)
        self.assertEqual(disk["k01"]["password"], PASSWORD)
        restarted = k01.K01IntelligenceClient(folder, PAIRING)
        self.assertTrue(restarted.status()["configured"])
        self.assertEqual(restarted.config.password, PASSWORD)

    def test_empty_password_preserves_and_explicit_clear_removes_it(self):
        client = k01.K01IntelligenceClient(self.folder.name, PAIRING)
        client.update_config(CONFIG)
        client.update_config({"password": "", "cacheSeconds": 30})
        self.assertEqual(client.config.password, PASSWORD)
        client.update_config({"clearPassword": True})
        self.assertEqual(client.config.password, "")
        self.assertFalse(client.status()["configured"])

    def test_tls_verification_defaults_on_and_explicit_optout_persists(self):
        default = k01.config_from_payload(CONFIG)
        self.assertTrue(default.verify_tls)
        self.assertTrue(default.public()["verifyTLS"])
        insecure = k01.config_from_payload({**CONFIG, "verifyTLS": False})
        self.assertFalse(insecure.verify_tls)
        self.assertFalse(insecure.public()["verifyTLS"])
        client = k01.K01IntelligenceClient(self.folder.name, PAIRING)
        saved = client.update_config({**CONFIG, "verifyTLS": False})
        self.assertFalse(saved["config"]["verifyTLS"])
        restarted = k01.K01IntelligenceClient(self.folder.name, PAIRING)
        self.assertFalse(restarted.config.verify_tls)
        client.update_config({"verifyTLS": True})
        self.assertTrue(client.config.verify_tls)

    def test_tls_context_optout_is_explicit_and_turns_off_hostname_and_chain_checks(self):
        verified = k01._tls_context(k01.config_from_payload(CONFIG))
        self.assertTrue(verified.check_hostname)
        self.assertEqual(verified.verify_mode, ssl.CERT_REQUIRED)
        ignored = k01._tls_context(k01.config_from_payload({**CONFIG, "verifyTLS": False,
                                                            "caFile": "ignored-when-verification-is-off.pem"}))
        self.assertFalse(ignored.check_hostname)
        self.assertEqual(ignored.verify_mode, ssl.CERT_NONE)

    def test_config_rejects_arbitrary_paths_userinfo_untrusted_tls_and_invalid_numbers(self):
        for payload in [{"baseUrl": value} for value in (
                "http://k01.example.invalid", "https://u:p@k01.example.invalid", "https://k01.example.invalid/api",
                "https://k01.example.invalid/?x=1", "https://k01.example.invalid/#x", "https://k01.example.invalid:0",
                "https://k01.example.invalid:65536", "https://a..example.invalid", "https://0177.0.0.1",
                "https://k01.example.invalid\\@other.invalid")]+[
                {"verifyTLS": 1}, {"timeoutMs": True}, {"timeoutMs": 30001},
                {"cacheSeconds": -1}, {"cacheSeconds": 0.0}, {"url": "https://other.invalid"},
                {"password": None}, {"clearPassword": "true"}, {"username": "x\0y"}]:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                k01.config_from_payload(payload)
        self.assertEqual(k01.normalized_origin("https://K01.Example.Invalid:443/"),
                         "https://k01.example.invalid")

    def test_failed_atomic_save_retains_previous_disk_and_runtime_configuration(self):
        client = k01.K01IntelligenceClient(self.folder.name, PAIRING)
        client.update_config(CONFIG)
        before = client.path.read_bytes()
        previous = client.config
        with patch.object(k01.os, "replace", side_effect=OSError("offline filesystem failure")):
            with self.assertRaises(OSError):
                client.update_config({"username": "replacement"})
        self.assertEqual(client.path.read_bytes(), before)
        self.assertEqual(client.config, previous)
        self.assertFalse(list(Path(self.folder.name).glob(".k01-config-*")))

    def test_query_accepts_only_single_ipv4_or_domain_and_documented_count(self):
        self.assertEqual(k01.validate_trace_payload({"host": "Origin.Example.Invalid."}),
                         ("origin.example.invalid", 10, False))
        self.assertEqual(k01.validate_trace_payload({"host": "104.16.1.2", "count": 100, "force": True}),
                         ("104.16.1.2", 100, True))  # Intelligence lookup is independent of CDN probing filters.
        for payload in (None, [], {}, {"host": "::1"}, {"host": "https://example.invalid/path"},
                        {"host": "1.2.3.4:443"}, {"host": "1.2.3.4;whoami"},
                        {"host": ["1.2.3.4"]}, {"host": "example.invalid", "count": True},
                        {"host": "example.invalid", "count": 1}, {"host": "example.invalid", "count": "10"},
                        {"host": "example.invalid", "force": 1},
                        {"host": "example.invalid", "url": "https://different.invalid"}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                k01.validate_trace_payload(payload)


class ClientTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.calls = []
        self.responses = []
        self.clock = [0.0]
        self.log = io.StringIO()
        logger = logging.getLogger("offline-k01-test-" + str(id(self)))
        logger.handlers.clear()
        logger.setLevel(logging.INFO)
        logger.propagate = False
        logger.addHandler(logging.StreamHandler(self.log))
        async def transport(config, path, payload, bearer):
            self.calls.append((config, path, payload, bearer))
            reply = self.responses.pop(0)
            if isinstance(reply, Exception):
                raise reply
            return reply
        self.client = k01.K01IntelligenceClient(self.folder.name, PAIRING, logger,
                                               transport, lambda: self.clock[0])
        self.addAsyncCleanup(self.client.close)

    def configure(self, **extra):
        self.client.update_config({**CONFIG, **extra})

    async def test_unconfigured_account_requests_frontend_without_network(self):
        with self.assertRaises(k01.K01Error) as raised:
            await self.client.trace({"host": "example.invalid"})
        self.assertEqual(raised.exception.status, 409)
        self.assertEqual(raised.exception.payload()["code"], "K01_FRONTEND_REQUIRED")
        self.assertEqual(raised.exception.reason, "api_not_configured")
        self.assertTrue(raised.exception.fallback)
        self.assertEqual(self.calls, [])

    async def test_login_and_trace_use_only_documented_paths_and_strip_secrets(self):
        self.configure()
        response = result_reply()
        response.data["data"]["nested"] = {"access_token": ACCESS,
            "normal": PASSWORD + " Bearer private-value", "cookie": "private-cookie", "pairing": PAIRING}
        self.responses = [login_reply(), response]
        actual = await self.client.trace({"host": "Origin.Example.Invalid."})
        self.assertTrue(actual["success"])
        self.assertEqual(actual["authSource"], "api-account")
        self.assertEqual(actual["host"], "origin.example.invalid")
        self.assertFalse(actual["cacheHit"])
        self.assertEqual(self.calls[0][1:], (k01.LOGIN_PATH, {"username": "apiuser", "password": PASSWORD}, None))
        self.assertEqual(self.calls[1][1:], (k01.TRACE_PATH, {"host": "origin.example.invalid", "count": 10}, ACCESS))
        combined = json.dumps(actual) + self.log.getvalue() + json.dumps(self.client.status())
        for secret in (ACCESS, PASSWORD, PAIRING, "private-cookie", "private-value"):
            self.assertNotIn(secret, combined)

    async def test_login_rejection_and_missing_api_endpoint_allow_explicit_fallback(self):
        for status, reason in ((400, "api_login_failed"), (401, "api_login_failed"),
                               (403, "api_login_failed"), (404, "api_login_unavailable"),
                               (405, "api_login_unavailable")):
            self.configure()
            self.responses = [k01.Reply(status, None)]
            with self.subTest(status=status), self.assertRaises(k01.K01Error) as raised:
                await self.client.trace({"host": "example.invalid"})
            self.assertEqual(raised.exception.reason, reason)
            self.assertTrue(raised.exception.fallback)
        self.configure()
        self.responses = [k01.Reply(200, {"success": False, "msg": PASSWORD})]
        with self.assertRaises(k01.K01Error) as raised:
            await self.client.trace({"host": "example.invalid"})
        self.assertEqual(raised.exception.reason, "api_login_failed")
        self.assertNotIn(PASSWORD, json.dumps(raised.exception.payload()))

    async def test_login_rejection_reports_upstream_error_code_and_message(self):
        self.configure()
        self.responses = [k01.Reply(200, {"success": False, "error_code": 999,
                                          "msg": "登录用户失败：用户名或密码错误"})]
        with self.assertRaises(k01.K01Error) as raised:
            await self.client.trace({"host": "example.invalid"})
        error = raised.exception
        self.assertEqual(error.code, "K01_FRONTEND_REQUIRED")
        self.assertEqual(error.reason, "api_login_failed")
        self.assertEqual(error.stage, "login")
        self.assertEqual(error.diagnostic_code, "login_rejected")
        self.assertEqual(error.diagnostic["errorCode"], 999)
        self.assertIn("用户名或密码错误", error.diagnostic["message"])
        self.assertIn("用户名或密码错误", error.message)
        payload = error.payload()
        self.assertEqual(payload["diagnosticCode"], "login_rejected")
        self.assertEqual(payload["diagnostic"]["errorCode"], 999)
        self.assertNotIn(PASSWORD, json.dumps(payload, ensure_ascii=False))

    async def test_first_login_password_notice_still_uses_issued_token(self):
        self.configure()
        advisory = k01.Reply(200, {"success": False, "error_code": 999, "status": "change",
                                   "msg": "首次登录建议修改密码！",
                                   "token": {"access_token": ACCESS,
                                             "refresh_token": "offline-refresh-token"}})
        self.responses = [advisory, result_reply()]
        actual = await self.client.trace({"host": "example.invalid"})
        self.assertTrue(actual["success"])
        self.assertEqual(actual["authSource"], "api-account")
        self.assertEqual(actual["loginNotice"]["errorCode"], 999)
        self.assertEqual(actual["loginNotice"]["status"], "change")
        self.assertIn("首次登录建议修改密码", actual["loginNotice"]["message"])
        self.assertEqual(self.calls[1][1:][2], ACCESS)
        output = self.log.getvalue() + json.dumps(actual, ensure_ascii=False)
        self.assertIn("ok-with-notice", output)
        for secret in (ACCESS, PASSWORD, PAIRING):
            self.assertNotIn(secret, output)

    async def test_rejection_without_usable_token_is_still_a_login_failure(self):
        for body in ({"success": False, "error_code": 999, "msg": "登录用户失败：用户名或密码错误"},
                     {"success": False, "error_code": 999, "status": "change",
                      "msg": "首次登录建议修改密码！", "token": {"access_token": "bad\r\nvalue"}},
                     {"success": False, "error_code": 999, "token": []}):
            self.configure()
            self.responses = [k01.Reply(200, body)]
            with self.subTest(body=body), self.assertRaises(k01.K01Error) as raised:
                await self.client.trace({"host": "example.invalid"})
            self.assertEqual(raised.exception.reason, "api_login_failed")
            self.assertEqual(raised.exception.diagnostic_code, "login_rejected")
            self.assertTrue(raised.exception.fallback)

    async def test_trace_endpoint_not_supported_allows_frontend_fallback(self):
        for status in (404, 405):
            self.configure()
            self.responses = [login_reply(), k01.Reply(status, None)]
            with self.subTest(status=status), self.assertRaises(k01.K01Error) as raised:
                await self.client.trace({"host": "example.invalid"})
            self.assertEqual(raised.exception.reason, "api_endpoint_unavailable")
            self.assertTrue(raised.exception.fallback)

    async def test_upstream_failure_or_malformed_login_does_not_silently_fallback(self):
        replies = [k01.Reply(500, None), k01.Reply(429, None), k01.Reply(302, None),
                   k01.Reply(200, []), k01.Reply(200, {"success": "true"}),
                   k01.Reply(200, {"success": True}), login_reply("bad\r\nheader"),
                   k01.K01Error("K01_TIMEOUT", "offline timeout", 504)]
        for reply in replies:
            self.configure()
            self.responses = [reply]
            with self.subTest(reply=repr(reply)), self.assertRaises(k01.K01Error) as raised:
                await self.client.trace({"host": "example.invalid"})
            self.assertFalse(raised.exception.fallback)
            self.assertNotEqual(raised.exception.code, "K01_FRONTEND_REQUIRED")

    async def test_expired_api_token_relogs_once_then_uses_fresh_bearer(self):
        self.configure()
        self.responses = [login_reply("stale-token"), k01.Reply(401, None),
                          login_reply("fresh-token"), result_reply()]
        result = await self.client.trace({"host": "example.invalid"})
        self.assertTrue(result["success"])
        self.assertEqual([call[1] for call in self.calls],
                         [k01.LOGIN_PATH, k01.TRACE_PATH, k01.LOGIN_PATH, k01.TRACE_PATH])
        self.assertEqual(self.calls[-1][3], "fresh-token")
        self.assertNotIn("fresh-token", json.dumps(result) + self.log.getvalue())

    async def test_repeated_resource_auth_denial_is_frontend_required(self):
        self.configure()
        self.responses = [login_reply(), k01.Reply(200, {"success": False, "error_code": 401}),
                          login_reply("another-token"), k01.Reply(403, None)]
        with self.assertRaises(k01.K01Error) as raised:
            await self.client.trace({"host": "example.invalid"})
        self.assertEqual(raised.exception.reason, "api_access_denied")
        self.assertIsNone(self.client.token)
        self.assertEqual(len(self.calls), 4)

    async def test_protocol_and_business_errors_do_not_become_empty_success(self):
        for reply in (k01.Reply(500, None), k01.Reply(200, None),
                      k01.Reply(200, {"success": True, "error_code": False, "data": {}}),
                      k01.Reply(200, {"success": False, "error_code": [401], "data": {}}),
                      k01.Reply(200, {"success": False, "error_code": 17, "msg": PASSWORD}),
                      k01.Reply(200, {"success": True, "error_code": 0, "data": []})):
            self.configure()
            self.responses = [login_reply(), reply]
            with self.subTest(reply=repr(reply)), self.assertRaises(k01.K01Error) as raised:
                await self.client.trace({"host": "example.invalid"})
            self.assertFalse(raised.exception.fallback)
            self.assertNotIn(PASSWORD, json.dumps(raised.exception.payload()))

    async def test_cache_is_bounded_by_count_ttl_force_and_independent_copies(self):
        self.configure(cacheSeconds=30)
        self.responses = [login_reply(), result_reply(), result_reply(), result_reply(), result_reply()]
        one = await self.client.trace({"host": "EXAMPLE.INVALID."})
        one["data"]["base_info"]["malice_num"] = 99
        cached = await self.client.trace({"host": "example.invalid"})
        self.assertTrue(cached["cacheHit"])
        self.assertEqual(cached["data"]["base_info"]["malice_num"], 1)
        self.assertEqual(len(self.calls), 2)
        await self.client.trace({"host": "example.invalid", "force": True})
        await self.client.trace({"host": "example.invalid", "count": 20})
        self.clock[0] = 31
        self.assertFalse((await self.client.trace({"host": "example.invalid"}))["cacheHit"])
        self.assertEqual(len(self.calls), 5)

    async def test_simultaneous_identical_queries_share_work_and_cancellation(self):
        self.configure()
        started, release = asyncio.Event(), asyncio.Event()
        calls = []
        async def transport(config, path, payload, bearer):
            calls.append(path)
            if path == k01.LOGIN_PATH:
                return login_reply()
            started.set()
            await release.wait()
            return result_reply()
        self.client.transport = transport
        one = asyncio.create_task(self.client.trace({"host": "EXAMPLE.INVALID."}))
        two = asyncio.create_task(self.client.trace({"host": "example.invalid"}))
        await started.wait()
        one.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await one
        release.set()
        self.assertTrue((await two)["success"])
        self.assertEqual(calls, [k01.LOGIN_PATH, k01.TRACE_PATH])

    async def test_configuration_snapshot_prevents_cross_origin_token_or_cache_reuse(self):
        self.configure()
        login_started, release_login = asyncio.Event(), asyncio.Event()
        calls = []
        async def transport(config, path, payload, bearer):
            calls.append((config.base_url, path, bearer))
            if path == k01.LOGIN_PATH:
                if config.base_url == CONFIG["baseUrl"]:
                    login_started.set()
                    await release_login.wait()
                return login_reply("old-token" if config.base_url == CONFIG["baseUrl"] else "new-token")
            return result_reply()
        self.client.transport = transport
        old = asyncio.create_task(self.client.trace({"host": "example.invalid"}))
        await login_started.wait()
        self.configure(baseUrl="https://replacement.example.invalid")
        release_login.set()
        self.assertTrue((await old)["success"])
        self.assertIsNone(self.client.token)
        self.assertEqual(len(self.client.cache), 0)
        await self.client.trace({"host": "example.invalid"})
        self.assertEqual(calls[-1], ("https://replacement.example.invalid", k01.TRACE_PATH, "new-token"))

    async def test_bounded_query_admission_and_close_clear_all_work(self):
        self.configure()
        started, release = asyncio.Event(), asyncio.Event()
        async def transport(config, path, payload, bearer):
            if path == k01.LOGIN_PATH:
                return login_reply()
            started.set()
            await release.wait()
            return result_reply()
        self.client.transport = transport
        with patch.object(k01, "MAX_INFLIGHT", 1):
            first = asyncio.create_task(self.client.trace({"host": "one.example.invalid"}))
            await started.wait()
            with self.assertRaises(k01.K01Error) as raised:
                await self.client.trace({"host": "two.example.invalid"})
            self.assertEqual(raised.exception.status, 429)
            self.assertFalse(raised.exception.fallback)
            await self.client.close()
            with self.assertRaises(asyncio.CancelledError):
                await first
        self.assertFalse(self.client.inflight)
        self.assertFalse(self.client.cache)
        self.assertIsNone(self.client.token)

    async def test_overall_deadline_bounds_queued_and_active_queries_and_releases_capacity(self):
        self.configure()
        self.client.semaphore = asyncio.Semaphore(1)
        started, release = asyncio.Event(), asyncio.Event()
        active = 0
        async def blocked_transport(config, path, payload, bearer):
            nonlocal active
            if path == k01.LOGIN_PATH:
                return login_reply()
            active += 1
            started.set()
            try:
                await release.wait()
                return result_reply()
            finally:
                active -= 1
        self.client.transport = blocked_transport
        with patch.object(k01, "MAX_QUERY_SECONDS", 0.06):
            first = asyncio.create_task(self.client.trace({"host": "active.example.invalid"}))
            await started.wait()
            with patch.object(k01, "MAX_QUERY_SECONDS", 0.01):
                with self.assertRaises(k01.K01Error) as queued:
                    await self.client.trace({"host": "queued.example.invalid"})
            self.assertEqual(queued.exception.code, "K01_TIMEOUT")
            self.assertEqual(queued.exception.status, 504)
            self.assertFalse(queued.exception.fallback)
            self.assertEqual(active, 1)
            with self.assertRaises(k01.K01Error) as running:
                await first
        self.assertEqual(running.exception.code, "K01_TIMEOUT")
        self.assertEqual(active, 0)
        self.assertFalse(self.client.inflight)
        self.assertFalse(self.client.cache)
        async def recovered_transport(config, path, payload, bearer):
            return login_reply() if path == k01.LOGIN_PATH else result_reply()
        self.client.transport = recovered_transport
        self.assertTrue((await self.client.trace({"host": "recovered.example.invalid"}))["success"])


class TraceDiagnosticsTests(unittest.IsolatedAsyncioTestCase):
    """The operator can only read the userscript log and probe.jsonl, so every
    transport failure must surface a stage, a diagnostic code and a trace id."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.log = io.StringIO()
        self.logger = logging.getLogger("offline-k01-trace-" + str(id(self)))
        self.logger.handlers.clear()
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        self.logger.addHandler(logging.StreamHandler(self.log))

    async def asyncSetUp(self):
        self.transport_replies = []

        async def transport(config, path, payload, bearer):
            reply = self.transport_replies.pop(0)
            if isinstance(reply, Exception):
                raise reply
            return reply

        self.client = k01.K01IntelligenceClient(self.folder.name, PAIRING, self.logger, transport)
        self.addAsyncCleanup(self.client.close)
        self.client.update_config(CONFIG)

    def test_certificate_failure_reports_stage_code_and_actionable_hint(self):
        error = URLError(ssl.SSLCertVerificationError(1, "certificate verify failed: self signed certificate"))
        with patch.object(k01, "build_opener") as build:
            build.return_value.open.side_effect = error
            with self.assertRaises(k01.K01Error) as raised:
                k01._blocking_post(k01.config_from_payload(CONFIG), k01.LOGIN_PATH, {}, None)
        payload = raised.exception.payload()
        self.assertEqual(payload["code"], "K01_TLS_ERROR")
        self.assertEqual(payload["stage"], "login")
        self.assertEqual(payload["diagnosticCode"], "certificate_verification_failed")
        self.assertTrue(payload["fallbackAllowed"])
        self.assertIn("CA", payload["message"])
        self.assertTrue(payload["diagnostic"]["verifyTLS"])
        self.assertEqual(payload["diagnostic"]["requestPath"], k01.LOGIN_PATH)
        self.assertNotIn(PASSWORD, json.dumps(payload))

    def test_redirect_and_gateway_page_keep_bounded_forensics(self):
        with patch.object(k01, "build_opener") as build:
            build.return_value.open.side_effect = HTTPError(
                CONFIG["baseUrl"] + k01.LOGIN_PATH, 302, "Found",
                {"Location": "https://k01.example.invalid/login", "Content-Type": "text/html"}, io.BytesIO())
            reply = k01._blocking_post(k01.config_from_payload(CONFIG), k01.LOGIN_PATH, {}, None)
        self.assertEqual(reply.status, 302)
        self.assertEqual(reply.stage, "login")
        self.assertEqual(reply.diagnostic_code, "unexpected_redirect")
        self.assertEqual(reply.diagnostic["httpStatus"], 302)
        self.assertEqual(reply.diagnostic["locationHost"], "k01.example.invalid")

    async def test_upstream_status_and_diagnostic_reach_payload_and_log_with_trace_id(self):
        self.transport_replies = [k01.Reply(302, None, diagnostic_code="unexpected_redirect", stage="login",
                                            diagnostic={"httpStatus": 302, "locationHost": "k01.example.invalid"})]
        token = k01.set_trace_id("trace-abc-123")
        try:
            with self.assertRaises(k01.K01Error) as raised:
                await self.client.trace({"host": "example.invalid"})
        finally:
            k01.reset_trace_id(token)
        payload = raised.exception.payload()
        self.assertEqual(payload["code"], "K01_UPSTREAM_ERROR")
        self.assertEqual(payload["upstreamStatus"], 302)
        self.assertEqual(payload["diagnosticCode"], "unexpected_redirect")
        self.assertEqual(payload["traceId"], "trace-abc-123")
        self.assertIn("重定向", payload["message"])
        line = json.loads(self.log.getvalue().strip().splitlines()[-1])
        self.assertEqual(line["event"], "k01-query-error")
        self.assertEqual(line["traceId"], "trace-abc-123")
        self.assertEqual(line["diagnostic"]["locationHost"], "k01.example.invalid")
        self.assertTrue(line["config"]["verifyTLS"])

    class Response(io.BytesIO):
        def __init__(self, body, headers=None):
            super().__init__(body)
            self.headers = headers or {"Content-Type": "application/json"}
            self.code = 200

    def test_transport_uses_fixed_https_origin_no_proxy_no_redirect_and_validates_json(self):
        config = k01.config_from_payload(CONFIG)
        response = self.Response(b'{"success":true,"data":{}}')
        with patch.object(k01, "build_opener") as build:
            build.return_value.open.return_value = response
            reply = k01._blocking_post(config, k01.TRACE_PATH, {"host": "example.invalid"}, ACCESS)
            self.assertEqual(reply.status, 200)
            request = build.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, CONFIG["baseUrl"] + k01.TRACE_PATH)
            self.assertEqual(request.get_header("Authorization"), "Bearer " + ACCESS)
            self.assertEqual(json.loads(request.data), {"host": "example.invalid"})
            self.assertTrue(any(isinstance(arg, k01.NoRedirect) for arg in build.call_args.args))
            self.assertTrue(any(isinstance(arg, k01.ProxyHandler) and not arg.proxies
                                for arg in build.call_args.args))
        self.assertIsNone(k01.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.invalid"))
        with self.assertRaises(ValueError):
            k01._blocking_post(config, "/undocumented", {}, None)

    def test_html_duplicate_keys_nonfinite_oversized_and_redirect_are_not_success(self):
        config = k01.config_from_payload(CONFIG)
        responses = [self.Response(b"<html>login</html>", {"Content-Type": "text/html"}),
                     self.Response(b'{"data":{},"data":{}}'), self.Response(b'{"value":NaN}'),
                     self.Response(b"[]"), self.Response(b"\xff"),
                     self.Response(b"{}", {"Content-Type": "application/json", "Content-Length": "999999999"})]
        for response in responses:
            with self.subTest(response=response), patch.object(k01, "build_opener") as build:
                build.return_value.open.return_value = response
                with self.assertRaises(k01.K01Error) as raised:
                    k01._blocking_post(config, k01.LOGIN_PATH, {}, None)
                self.assertFalse(raised.exception.fallback)
        with patch.object(k01, "build_opener") as build:
            build.return_value.open.side_effect = HTTPError(CONFIG["baseUrl"], 302, "redirect", {}, io.BytesIO())
            self.assertEqual(k01._blocking_post(config, k01.LOGIN_PATH, {}, None).status, 302)

    def test_timeout_tls_and_connection_errors_are_distinct_and_do_not_echo_secrets(self):
        for error, expected in ((TimeoutError(PASSWORD), "K01_TIMEOUT"),
                                (URLError(TimeoutError(PASSWORD)), "K01_TIMEOUT"),
                                (URLError(ssl.SSLError(PASSWORD)), "K01_TLS_ERROR"),
                                (URLError(PASSWORD), "K01_CONNECTION_ERROR")):
            with self.subTest(error=repr(error)), patch.object(k01, "build_opener") as build:
                build.return_value.open.side_effect = error
                with self.assertRaises(k01.K01Error) as raised:
                    k01._blocking_post(k01.config_from_payload(CONFIG), k01.LOGIN_PATH, {}, None)
                self.assertEqual(raised.exception.code, expected)
                self.assertNotIn(PASSWORD, json.dumps(raised.exception.payload()))


class HttpTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        folder = Path(self.folder.name)
        rules = folder / "rules.json"
        rules.write_text(json.dumps({"version": "offline-k01", "updatedAt": "2026-11-18", "cidrs": [], "domainSuffixes": []}))
        logger = logging.getLogger("offline-k01-http-" + str(id(self)))
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())
        self.app = service.create_app(service.Settings(token=PAIRING, data_dir=folder),
                                      NetworkPolicy(rules), logger=logger)
        self.intelligence = self.app.state.intelligence
        self.addAsyncCleanup(self.intelligence.close)
        async def no_network(*args):
            raise AssertionError("offline test must not contact an appliance")
        self.intelligence.transport = no_network
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app, client=("127.0.0.1", 1234)),
                                       base_url="http://127.0.0.1", headers={"Authorization": "Bearer " + PAIRING})
        self.addAsyncCleanup(self.client.aclose)

    async def test_all_k01_routes_require_existing_pairing_token_before_body_validation(self):
        for method, path in (("GET", "/v1/intelligence/status"), ("GET", "/v1/intelligence/config"),
                             ("PUT", "/v1/intelligence/config"), ("POST", "/v1/intelligence/config"),
                             ("POST", "/v1/intelligence/trace")):
            with self.subTest(method=method, path=path):
                response = await self.client.request(method, path, content=b"{", headers={"Authorization": ""})
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.headers.get("WWW-Authenticate"), "Bearer")
                self.assertNotIn(PAIRING, response.text)

    async def test_config_get_put_and_status_preserve_password_and_return_no_upstream_credentials(self):
        response = await self.client.put("/v1/intelligence/config", json=CONFIG)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["config"]["passwordConfigured"])
        for path in ("/v1/intelligence/config", "/v1/intelligence/status"):
            response = await self.client.get(path)
            self.assertEqual(response.status_code, 200)
            for secret in (PASSWORD, ACCESS, PAIRING):
                self.assertNotIn(secret, response.text)
            self.assertNotIn('"password":', response.text)
        await self.client.put("/v1/intelligence/config", json={"password": ""})
        self.assertEqual(self.intelligence.config.password, PASSWORD)

    async def test_trace_id_header_round_trip_and_error_diagnostics(self):
        response = await self.client.post("/v1/intelligence/trace", json={"host": "example.invalid"},
                                          headers={"X-Trace-Id": "client-trace-0001"})
        self.assertEqual(response.headers.get("X-Trace-Id"), "client-trace-0001")
        self.assertEqual(response.json()["traceId"], "client-trace-0001")
        # An unusable trace id is replaced, never echoed back into the log verbatim.
        response = await self.client.post("/v1/intelligence/trace", json={"host": "example.invalid"},
                                          headers={"X-Trace-Id": "../etc/passwd"})
        self.assertEqual(response.status_code, 409)
        self.assertRegex(response.headers.get("X-Trace-Id", ""), r"^[a-f\d]{32}$")
        self.assertNotIn("passwd", response.text)

    async def test_unconfigured_trace_returns_only_explicit_fallback_contract(self):
        response = await self.client.post("/v1/intelligence/trace", json={"host": "example.invalid"})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["code"], "K01_FRONTEND_REQUIRED")
        self.assertTrue(response.json()["fallbackAllowed"])
        self.assertEqual(response.json()["reason"], "api_not_configured")
        health = await self.client.get("/health", headers={"Authorization": ""})
        self.assertTrue(health.json()["k01Intelligence"])
        self.assertEqual(health.json()["version"], service.SERVICE_VERSION)
        self.assertEqual(health.json()["apiVersion"], service.API_VERSION)
        self.assertNotIn("k01.example.invalid", health.text)

    async def test_invalid_json_configuration_and_host_are_rejected_without_input_echo(self):
        for path in ("/v1/intelligence/config", "/v1/intelligence/trace"):
            response = await self.client.post(path, content="not-json", headers={"Content-Type": "text/plain"})
            self.assertEqual(response.status_code, 415)
            for payload in (b"{", b"null", b'{"host":"a.invalid","host":"b.invalid"}', b'{"count":NaN}'):
                response = await self.client.post(path, content=payload, headers={"Content-Type": "application/json"})
                self.assertEqual(response.status_code, 422)
                self.assertFalse(response.json()["fallbackAllowed"])
        response = await self.client.post("/v1/intelligence/trace", json={"host": "https://private-marker.invalid/path"})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("private-marker", response.text)

    async def test_success_payload_survives_http_adapter_without_probe_submissions(self):
        self.intelligence.update_config(CONFIG)
        async def transport(config, path, payload, bearer):
            return login_reply() if path == k01.LOGIN_PATH else result_reply()
        self.intelligence.transport = transport
        response = await self.client.post("/v1/intelligence/trace", json={"host": "example.invalid", "count": 20})
        self.assertEqual(response.status_code, 200)
        value = response.json()
        self.assertEqual(value["authSource"], "api-account")
        self.assertEqual(value["host"], "example.invalid")
        self.assertEqual(value["data"]["base_info"]["malice_num"], 1)
        # The answering build travels with the payload so a stale exe is visible client side.
        self.assertEqual(value["serviceVersion"], service.SERVICE_VERSION)
        self.assertFalse(self.app.state.engine.jobs)


class ServiceVersionStampTests(unittest.TestCase):
    """Every K01 payload names the probe build that produced it."""

    def tearDown(self):
        k01.set_service_version(service.SERVICE_VERSION)

    def test_error_payload_carries_service_version(self):
        k01.set_service_version("9.9.9-test")
        error = k01.K01Error("K01_CONNECTION_ERROR", "boom", 502, fallback=True)
        self.assertEqual(error.payload()["serviceVersion"], "9.9.9-test")

    def test_payload_omits_version_when_unset(self):
        k01.set_service_version("")
        self.assertNotIn("serviceVersion", k01.K01Error("K01_BUSY", "boom", 429).payload())

    def test_startup_banner_names_the_build(self):
        stream = io.StringIO()
        service.print_banner(stream)
        self.assertIn(service.SERVICE_VERSION, stream.getvalue())


class OsTlsFallbackTests(unittest.TestCase):
    """A gateway that requests renegotiation is replayed over the OS TLS stack."""

    def setUp(self):
        patcher = patch.dict("os.environ", {k01.CURL_FALLBACK_ENV: "1"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_renegotiation_drop_is_recognised(self):
        import http.client
        self.assertTrue(k01._is_renegotiation_drop(URLError(http.client.RemoteDisconnected(
            "Remote end closed connection without response"))))
        self.assertTrue(k01._is_renegotiation_drop(URLError(ConnectionResetError(10054, "reset"))))
        self.assertTrue(k01._is_renegotiation_drop(URLError(ssl.SSLError("renegotiation refused"))))
        self.assertFalse(k01._is_renegotiation_drop(URLError(ConnectionRefusedError(61, "refused"))))
        self.assertFalse(k01._is_renegotiation_drop(TimeoutError("slow")))

    def test_renegotiation_drop_is_replayed_once_over_os_tls(self):
        import http.client
        reply = k01._CurlReply(200, {"Content-Type": "application/json"},
                               b'{"access_token": "os-tls"}')
        with patch.object(k01, "build_opener") as build, \
                patch.object(k01, "_curl_binary", return_value="/usr/bin/curl"), \
                patch.object(k01, "_post_with_os_tls", return_value=reply) as retried:
            build.return_value.open.side_effect = URLError(http.client.RemoteDisconnected(
                "Remote end closed connection without response"))
            answer = k01._blocking_post(k01.config_from_payload(CONFIG), k01.LOGIN_PATH,
                                        {}, None)
        self.assertEqual(answer.status, 200)
        self.assertEqual(answer.data["access_token"], "os-tls")
        self.assertEqual(retried.call_count, 1)
        self.assertEqual(k01._TRANSPORT.get(), "os-tls")

    def test_fallback_can_be_disabled_and_then_reports_connection_error(self):
        import http.client
        with patch.object(k01, "build_opener") as build, \
                patch.object(k01, "_curl_binary", return_value="/usr/bin/curl"), \
                patch.dict("os.environ", {k01.CURL_FALLBACK_ENV: "0"}):
            build.return_value.open.side_effect = URLError(ConnectionResetError(10054, PASSWORD))
            with self.assertRaises(k01.K01Error) as raised:
                k01._blocking_post(k01.config_from_payload(CONFIG), k01.LOGIN_PATH, {}, None)
        payload = raised.exception.payload()
        self.assertEqual(payload["code"], "K01_CONNECTION_ERROR")
        self.assertEqual(payload["diagnostic"]["transport"], "urllib")
        self.assertNotIn(PASSWORD, json.dumps(payload))

    def test_failed_os_tls_retry_reports_the_transport_it_used(self):
        import http.client
        with patch.object(k01, "build_opener") as build, \
                patch.object(k01, "_curl_binary", return_value="/usr/bin/curl"), \
                patch.object(k01, "_post_with_os_tls",
                             side_effect=OSError(104, "os tls retry failed (curl exit 7)")):
            build.return_value.open.side_effect = URLError(http.client.RemoteDisconnected("closed"))
            with self.assertRaises(k01.K01Error) as raised:
                k01._blocking_post(k01.config_from_payload(CONFIG), k01.LOGIN_PATH, {}, None)
        payload = raised.exception.payload()
        self.assertEqual(payload["code"], "K01_CONNECTION_ERROR")
        self.assertEqual(payload["diagnostic"]["transport"], "os-tls")
        self.assertIn("curl exit 7", payload["diagnostic"]["osError"])

    def test_curl_command_keeps_credentials_out_of_argv_and_honours_tls_flags(self):
        import subprocess
        config = k01.config_from_payload(CONFIG)
        command = k01._curl_command("curl.exe", config, k01.LOGIN_PATH, "h.txt", "p.json", "rh", "rb")
        self.assertNotIn(PASSWORD, " ".join(command))
        self.assertIn("--http1.1", command)
        self.assertNotIn("-k", command)
        insecure = k01._curl_command("curl.exe", k01.config_from_payload(dict(CONFIG, verifyTLS=False)),
                                     k01.LOGIN_PATH, "h.txt", "p.json", "rh", "rb")
        self.assertIn("-k", insecure)
        trusted = k01._curl_command("curl.exe", k01.config_from_payload(dict(CONFIG, caFile="/tmp/ca.pem")),
                                    k01.LOGIN_PATH, "h.txt", "p.json", "rh", "rb")
        self.assertEqual(trusted[trusted.index("--cacert") + 1], "/tmp/ca.pem")

    def test_os_tls_retry_sends_headers_through_a_private_file(self):
        import subprocess
        seen = {}

        def fake_run(command, **kwargs):
            seen["command"] = command
            header_arg = command[command.index("-H") + 1]
            body_arg = command[command.index("--data-binary") + 1]
            seen["headers"] = Path(header_arg.lstrip("@")).read_text(encoding="utf-8")
            seen["body"] = Path(body_arg.lstrip("@")).read_bytes()
            header_out = command[command.index("-D") + 1]
            body_out = command[command.index("-o") + 1]
            Path(header_out).write_text("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n", encoding="latin-1")
            Path(body_out).write_bytes(b'{"success": true}')
            return subprocess.CompletedProcess(command, 0, b"200", b"")

        with patch.object(k01, "_curl_binary", return_value="curl.exe"), \
                patch.object(k01.subprocess, "run", side_effect=fake_run):
            reply = k01._post_with_os_tls(k01.config_from_payload(CONFIG), k01.LOGIN_PATH,
                                          json.dumps({"password": PASSWORD}).encode("utf-8"), ACCESS)
        self.assertEqual(reply.code, 200)
        self.assertEqual(reply.headers.get("Content-Type"), "application/json")
        self.assertEqual(reply.read(), b'{"success": true}')
        self.assertIn("Authorization: Bearer " + ACCESS, seen["headers"])
        self.assertNotIn(ACCESS, " ".join(seen["command"]))
        self.assertIn(PASSWORD.encode("utf-8"), seen["body"])

    def test_curl_header_block_parsing_ignores_status_lines(self):
        headers = k01._curl_headers("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n")
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertNotIn("HTTP/1.1 200 OK", headers)


if __name__ == "__main__":
    unittest.main()
