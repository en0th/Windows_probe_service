"""Offline service contracts: every DNS, ICMP and TCP operation is simulated."""
from __future__ import annotations

import asyncio
import ctypes
import io
import ipaddress
import json
import logging
from pathlib import Path
import socket
import sys
import tempfile
import types
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from pydantic import ValidationError

SERVICE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_DIR))
import service
import windows_icmp
from network_policy import NetworkPolicy, DEFAULT_SAFETY_CIDRS
import update_cdn_rules

PUBLIC = "93.184.216.34"
OTHER = "45.33.32.156"
TOKEN = "test-pairing-token-never-a-real-token-12345"


def logger():
    value = logging.getLogger("offline-probe-test")
    value.handlers.clear()
    value.addHandler(logging.NullHandler())
    return value


def rules(folder):
    path = Path(folder) / "rules.json"
    path.write_text(json.dumps({"version": "offline-fixture", "updatedAt": "2026-11-17", "cidrs": [
        {"cidr": "104.16.0.0/13", "provider": "fixture-cdn", "source": "offline"}],
        "domainSuffixes": [{"suffix": "edge.example.invalid", "provider": "fixture-cdn", "source": "offline"}]}))
    return NetworkPolicy(path)


def batch(host=PUBLIC, query="q1", targets=None, **kwargs):
    return service.ProbeBatch(queryId=query, targets=targets or [{"id": "t1", "host": host, "port": 443}], **kwargs)


class PolicyAndConfigTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.policy = rules(self.folder.name)

    def test_private_special_multicast_and_ipv6_never_eligible(self):
        for address in ["0.0.0.0", "0.1.2.3", "10.4.5.6", "100.64.0.1", "127.0.0.1", "169.254.1.1",
                        "172.16.0.1", "192.168.1.1", "192.0.2.1", "198.18.0.1", "203.0.113.1", "224.0.0.1", "255.255.255.255"]:
            with self.subTest(address=address):
                self.assertEqual(self.policy.address(address)["status"], "skipped_private")
        self.assertEqual(self.policy.address("2606:4700::1")["status"], "skipped_ipv6")
        self.assertIsNone(self.policy.address(PUBLIC))

    def test_cdn_suffix_boundaries_and_network_metadata(self):
        self.assertIsNotNone(self.policy.domain("a.edge.example.invalid"))
        self.assertIsNone(self.policy.domain("eviledge.example.invalid"))
        self.assertEqual(self.policy.address("104.16.1.2")["provider"], "fixture-cdn")

    def test_public_and_system_dns_excluded(self):
        for address in ["8.8.8.8", "114.114.114.114", "223.5.5.5", "119.29.29.29", "180.184.2.2"]:
            self.assertEqual(self.policy.address(address)["status"], "skipped_dns")
        self.policy.add_system_dns([PUBLIC])
        self.assertEqual(self.policy.address(PUBLIC)["source"], "system_dns_configuration")

    def test_default_safety_filter_is_immutable_and_covers_all_entries(self):
        self.assertIsInstance(DEFAULT_SAFETY_CIDRS, tuple)
        for network in DEFAULT_SAFETY_CIDRS:
            for address in [str(network.network_address), str(network.broadcast_address)]:
                with self.subTest(address=address):
                    self.assertTrue(self.policy.address(address)["status"].startswith("skipped_"))
        for address in ["210.39.0.1", "210.39.15.255", "116.13.96.1", "116.13.111.255",
                        "202.127.241.128", "202.127.241.255", "172.1.1.1", "116.76.255.38"]:
            with self.subTest(address=address):
                result = self.policy.address(address)
                self.assertEqual(result["status"], "skipped_safety")
                self.assertEqual(result["source"], "built_in_safety_policy")
        for address in ["210.39.16.0", "116.13.112.0", "202.127.241.127"]:
            self.assertIsNone(self.policy.address(address))

    def test_request_safety_cidrs_validated_and_normalized(self):
        for excluded in [["::1"], ["2001:db8::/32"], ["93.184.216.1/24"], ["invalid"], [True]]:
            with self.subTest(excluded=excluded), self.assertRaises(ValidationError):
                batch(excludedCidrs=excluded)
        normalized = batch(excludedCidrs=[PUBLIC, PUBLIC + "/32", "93.184.216.0/24"])
        self.assertEqual(normalized.excludedCidrs, [PUBLIC + "/32", "93.184.216.0/24"])
        with self.assertRaises(ValidationError):
            batch(excludedCidrs=[f"93.184.{index // 256}.{index % 256}/32" for index in range(2049)])

    def test_config_survives_reinstall_and_bad_values_fail(self):
        first = service.load_settings(Path(self.folder.name) / "config")
        second = service.load_settings(first.data_dir)
        self.assertEqual(first.token, second.token)
        path = first.data_dir / "config.json"
        config = json.loads(path.read_text())
        config["port"] = True
        path.write_text(json.dumps(config))
        with self.assertRaises(ValueError):
            service.load_settings(first.data_dir)

    def test_batch_rejects_commands_ports_duplicates_and_invalid_exclusions(self):
        for host in ["1.2.3.4;whoami", "https://example.com", "1234", "0177.0.0.1", "127.0.0.1/x"]:
            with self.subTest(host=host), self.assertRaises(ValidationError):
                batch(host)
        for port in [0, 65536, True, "443"]:
            with self.subTest(port=port), self.assertRaises(ValidationError):
                batch(targets=[{"id": "t1", "host": PUBLIC, "port": port}])
        with self.assertRaises(ValidationError):
            batch(targets=[{"id": "same", "host": PUBLIC}, {"id": "same", "host": OTHER}])
        for excluded in [["::1"], ["10.0.0.0/8"], ["invalid"], [True]]:
            with self.subTest(excluded=excluded), self.assertRaises(ValidationError):
                batch(excludedHosts=excluded)
        validated = batch(excludedHosts=[OTHER, PUBLIC, OTHER])
        self.assertEqual(set(validated.excludedHosts), {PUBLIC, OTHER})
        self.assertEqual(len(validated.excludedHosts), 2)
        with self.assertRaises(ValidationError):
            batch(excludedHosts=[f"93.184.{index // 256}.{index % 256}" for index in range(201)])

    def test_cdn_conversion_never_imports_all_cloud_ranges(self):
        converted = update_cdn_rules.convert({"cdn": {"fixture": ["104.16.0.0/13"]}, "waf": {},
            "cloud": {"generic-cloud": ["0.0.0.0/0"]}, "common": {"fixture": ["edge.example.invalid"]}}, "a" * 40)
        self.assertEqual([entry["cidr"] for entry in converted["cidrs"]], ["104.16.0.0/13"])

    def test_bundled_dataset_loads_with_source_and_version(self):
        policy = NetworkPolicy(SERVICE_DIR / "cdn_rules.json")
        self.assertGreater(len(policy.cidrs), 100)
        self.assertGreater(len(policy.domains), 20)
        self.assertTrue(policy.version.startswith("cdncheck-"))
        self.assertEqual(policy.address("104.16.1.1")["status"], "skipped_cdn")


class EngineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.policy = rules(self.folder.name)
        self.settings = service.Settings(token=TOKEN, data_dir=Path(self.folder.name), concurrency=2, operations_per_second=0)
        self.engine = service.ProbeEngine(self.settings, self.policy, logger())
        # Any forgotten mock fails rather than contacting a real target.
        self.engine._resolve = AsyncMock(side_effect=AssertionError("offline DNS guard"))
        self.engine._ping = AsyncMock(side_effect=AssertionError("offline ICMP guard"))
        self.engine._tcp = AsyncMock(side_effect=AssertionError("offline TCP guard"))

    async def asyncTearDown(self):
        await self.engine.close()
        self.folder.cleanup()

    async def test_every_resolved_address_checked_before_io(self):
        self.engine._resolve = AsyncMock(return_value=(["10.1.2.3", "104.16.1.2", "8.8.8.8", PUBLIC], []))
        self.engine._ping = AsyncMock(return_value={"address": PUBLIC, "status": "reachable"})
        self.engine._tcp = AsyncMock(return_value={"address": PUBLIC, "port": 443, "status": "open"})
        result = await self.engine.probe("origin.example.invalid", 443)
        self.engine._ping.assert_awaited_once_with(PUBLIC)
        self.engine._tcp.assert_awaited_once_with(PUBLIC, 443)
        self.assertEqual([x["status"] for x in result["ping"]], ["skipped_private", "skipped_cdn", "skipped_dns", "reachable"])

    async def test_domain_cname_cdn_stops_all_probes(self):
        self.engine._resolve = AsyncMock(return_value=([PUBLIC], ["node.edge.example.invalid"]))
        result = await self.engine.probe("origin.example.invalid", 443)
        self.assertEqual(result["dns"]["status"], "skipped_cdn")
        self.engine._ping.assert_not_called()
        self.engine._tcp.assert_not_called()

    async def test_ipv6_and_dns_port_have_no_io(self):
        result = await self.engine.probe("2606:4700::1", 443)
        self.assertEqual(result["ping"][0]["status"], "skipped_ipv6")
        result = await self.engine.probe(PUBLIC, 53)
        self.assertEqual(result["dns"]["status"], "skipped_dns")
        self.engine._resolve.assert_not_called()
        self.engine._ping.assert_not_called()
        self.engine._tcp.assert_not_called()

    async def test_extra_exclusions_apply_after_dns(self):
        self.engine._resolve = AsyncMock(return_value=([PUBLIC, OTHER], []))
        self.engine._ping = AsyncMock(return_value={"address": OTHER, "status": "reachable"})
        self.engine._tcp = AsyncMock(return_value={"address": OTHER, "port": 443, "status": "open"})
        result = await self.engine.probe("origin.example.invalid", 443, excluded_hosts=(PUBLIC,))
        self.assertEqual(result["ping"][0]["status"], "skipped_custom")
        self.engine._ping.assert_awaited_once_with(OTHER)
        self.engine._tcp.assert_awaited_once_with(OTHER, 443)

    async def test_default_safety_literal_address_has_no_io(self):
        for network in DEFAULT_SAFETY_CIDRS:
            await self.engine.probe(str(network.network_address), 443)
        self.engine._resolve.assert_not_called()
        self.engine._ping.assert_not_called()
        self.engine._tcp.assert_not_called()

    async def test_default_safety_filter_checked_after_dns(self):
        protected = ["210.39.0.1", "116.13.96.1", "202.127.241.128", "172.1.1.1", "116.76.255.38"]
        self.engine._resolve = AsyncMock(return_value=(protected, []))
        result = await self.engine.probe("origin.example.invalid", 443)
        self.assertEqual([item["status"] for item in result["ping"]], ["skipped_safety"] * len(protected))
        self.assertEqual([item["status"] for item in result["tcp"]], ["skipped_safety"] * len(protected))
        self.engine._ping.assert_not_called()
        self.engine._tcp.assert_not_called()

    async def test_request_cidrs_checked_after_dns_before_ping_and_tcp(self):
        self.engine._resolve = AsyncMock(return_value=([PUBLIC, OTHER], []))
        self.engine._ping = AsyncMock(return_value={"address": OTHER, "status": "reachable"})
        self.engine._tcp = AsyncMock(return_value={"address": OTHER, "port": 443, "status": "open"})
        result = await self.engine.probe("origin.example.invalid", 443, excluded_cidrs=("93.184.216.0/24",))
        self.assertEqual(result["ping"][0]["status"], "skipped_custom")
        self.assertEqual(result["tcp"][0]["source"], "request.excludedCidrs")
        self.assertEqual(result["tcp"][0]["rule"], "93.184.216.0/24")
        self.engine._ping.assert_awaited_once_with(OTHER)
        self.engine._tcp.assert_awaited_once_with(OTHER, 443)

    async def test_known_port_tcp_attempted_even_when_ping_has_no_response(self):
        for status in ["unreachable", "timeout", "error"]:
            with self.subTest(status=status):
                self.engine._ping = AsyncMock(return_value={"address": PUBLIC, "status": status})
                self.engine._tcp = AsyncMock(return_value={"address": PUBLIC, "port": 443, "status": "open"})
                result = await self.engine.probe(PUBLIC, 443)
                self.engine._tcp.assert_awaited_once_with(PUBLIC, 443)
                self.assertEqual(result["tcp"][0]["status"], "open")

    async def test_dns_limit_and_failure_do_not_probe(self):
        self.engine._resolve = AsyncMock(return_value=([PUBLIC] * 65, []))
        result = await self.engine.probe("origin.example.invalid", 443)
        self.assertEqual(result["dns"]["error"], "dns_address_limit_exceeded")
        self.engine._resolve = AsyncMock(side_effect=socket.gaierror("offline failure"))
        result = await self.engine.probe("origin.example.invalid", 443)
        self.assertEqual(result["dns"]["status"], "error")
        self.engine._ping.assert_not_called()

    async def test_cancellation_stops_remaining_operations(self):
        live = [True]
        self.engine._resolve = AsyncMock(return_value=([PUBLIC, OTHER], []))
        async def ping(address):
            live[0] = False
            return {"address": address, "status": "reachable"}
        self.engine._ping = AsyncMock(side_effect=ping)
        with self.assertRaises(service.AbandonedProbe):
            await self.engine.probe("origin.example.invalid", 443, should_continue=lambda: live[0])
        self.engine._ping.assert_awaited_once_with(PUBLIC)
        self.engine._tcp.assert_not_called()

    async def test_queue_dedup_cache_and_incremental_cursor(self):
        self.engine.probe = AsyncMock(return_value={"resolved": [PUBLIC], "dns": {"status": "ok"}, "ping": [], "tcp": []})
        await self.engine.start()
        job = self.engine.submit(batch(targets=[{"id": "a", "host": PUBLIC}, {"id": "b", "host": PUBLIC}]))
        await asyncio.wait_for(self.engine.queue.join(), 1)
        self.engine.probe.assert_awaited_once()
        self.assertEqual(self.engine.snapshot(job.id)["status"], "completed")
        self.assertEqual(len(self.engine.snapshot(job.id, after=1)["results"]), 1)
        next_job = self.engine.submit(batch(targets=[{"id": "c", "host": PUBLIC}]))
        self.assertTrue(self.engine.snapshot(next_job.id)["results"][0]["cached"])
        with self.assertRaises(ValueError):
            self.engine.snapshot(job.id, after=3)

    async def test_policy_exclusions_isolate_cache_and_inflight_work(self):
        self.engine.probe = AsyncMock(return_value={"resolved": [PUBLIC], "dns": {"status": "ok"}, "ping": [], "tcp": []})
        first = self.engine.submit(batch(host="origin.example.invalid", excludedHosts=[PUBLIC]))
        second = self.engine.submit(batch(host="origin.example.invalid", excludedHosts=[OTHER]))
        self.assertEqual(len(self.engine.inflight), 2)
        await self.engine.start()
        await asyncio.wait_for(self.engine.queue.join(), 1)
        self.assertEqual(self.engine.probe.await_count, 2)
        self.engine.submit(batch(host="origin.example.invalid", excludedHosts=[]))
        await asyncio.wait_for(self.engine.queue.join(), 1)
        self.assertEqual(self.engine.probe.await_count, 3)
        self.assertEqual(self.engine.snapshot(first.id)["status"], "completed")
        self.assertEqual(self.engine.snapshot(second.id)["status"], "completed")

    async def test_request_cidrs_isolate_cached_and_inflight_results(self):
        self.engine.probe = AsyncMock(return_value={"resolved": [PUBLIC], "dns": {"status": "ok"}, "ping": [], "tcp": []})
        first = self.engine.submit(batch(host="origin.example.invalid", excludedCidrs=[PUBLIC]))
        second = self.engine.submit(batch(host="origin.example.invalid", excludedCidrs=["93.184.216.0/24"]))
        self.assertEqual(len(self.engine.inflight), 2)
        await self.engine.start()
        await asyncio.wait_for(self.engine.queue.join(), 1)
        self.assertEqual(self.engine.probe.await_count, 2)
        self.engine.submit(batch(host="origin.example.invalid", excludedCidrs=[PUBLIC + "/32"]))
        self.assertEqual(self.engine.probe.await_count, 2)
        self.engine.submit(batch(host="origin.example.invalid", excludedCidrs=[]))
        await asyncio.wait_for(self.engine.queue.join(), 1)
        self.assertEqual(self.engine.probe.await_count, 3)
        self.assertEqual(self.engine.snapshot(first.id)["status"], "completed")
        self.assertEqual(self.engine.snapshot(second.id)["status"], "completed")

    async def test_cancelled_queued_job_does_not_probe(self):
        job = self.engine.submit(batch())
        self.engine.cancel(job.id)
        self.engine.probe = AsyncMock()
        await self.engine.start()
        await asyncio.wait_for(self.engine.queue.join(), 1)
        self.engine.probe.assert_not_called()
        self.assertEqual(self.engine.snapshot(job.id)["status"], "cancelled")

    async def test_queue_capacity_is_checked_atomically(self):
        self.engine.settings.queue_size = 1
        self.engine.queue = asyncio.Queue(maxsize=1)
        with self.assertRaises(service.CapacityError):
            self.engine.submit(batch(targets=[{"id": "a", "host": PUBLIC}, {"id": "b", "host": OTHER}]))
        self.assertEqual(len(self.engine.jobs), 0)
        self.assertEqual(self.engine.queue.qsize(), 0)

    async def test_resolver_queries_only_a_and_collects_aliases(self):
        # Use the actual resolver wrapper, replacing only the external resolver.
        answer = types.SimpleNamespace(canonical_name="origin.example.invalid.", response=types.SimpleNamespace(answer=[
            types.SimpleNamespace(rdtype=5, __iter__=lambda self: iter([]))]))
        class Answer:
            canonical_name = "target.example.invalid."
            response = types.SimpleNamespace(answer=[])
            def __iter__(self): return iter([types.SimpleNamespace(address=PUBLIC)])
        resolver = types.SimpleNamespace(lifetime=0, resolve=AsyncMock(return_value=Answer()))
        with patch.object(service.dns.asyncresolver, "Resolver", return_value=resolver):
            addresses, aliases = await service.ProbeEngine._resolve(self.engine, "origin.example.invalid")
        self.assertEqual(addresses, [PUBLIC])
        self.assertEqual(aliases, ["target.example.invalid"])
        self.assertEqual(resolver.resolve.await_args.args, ("origin.example.invalid", "A"))

    async def test_tcp_classifies_refusal_and_closes_successful_writer(self):
        with patch.object(service.asyncio, "open_connection", AsyncMock(side_effect=ConnectionRefusedError(61, "offline"))):
            result = await service.ProbeEngine._tcp(self.engine, PUBLIC, 443)
        self.assertEqual(result["status"], "refused")
        writer = types.SimpleNamespace(close=MagicMock(), wait_closed=AsyncMock())
        with patch.object(service.asyncio, "open_connection", AsyncMock(return_value=(None, writer))):
            result = await service.ProbeEngine._tcp(self.engine, PUBLIC, 443)
        self.assertEqual(result["status"], "open")
        writer.close.assert_called_once()
        writer.wait_closed.assert_awaited_once()

    async def test_auth_health_and_host_guard_never_probe(self):
        app = service.create_app(settings=self.settings, policy=self.policy, engine=self.engine, logger=logger())
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 12345))
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            health = await client.get("/health")
            self.assertEqual(health.status_code, 200)
            self.assertTrue(health.json()["ipv4Only"])
            self.assertTrue(health.json()["safetyExclusions"])
            self.assertTrue(health.json()["excludedCidrsSupported"])
            self.assertTrue(health.json()["domainNslookup"])
            self.assertTrue(health.json()["domainPing"])
            self.assertTrue(health.json()["domainDnsFallback"])
            self.assertEqual(health.json()["domainDefaultPorts"], [80, 443])
            self.assertNotIn(TOKEN, health.text)
            self.assertEqual((await client.get("/v1/auth-check")).status_code, 401)
            good = await client.get("/v1/auth-check", headers={"Authorization": "Bearer " + TOKEN})
            self.assertEqual(good.status_code, 200)
            bad_host = await client.get("/health", headers={"Host": "evil.example"})
            self.assertEqual(bad_host.status_code, 400)
        self.engine._resolve.assert_not_called()
        self.engine._ping.assert_not_called()
        self.assertFalse(self.engine.jobs)

    async def test_global_io_semaphore_bounds_independent_jobs(self):
        active = 0
        maximum = 0
        async def simulated_io():
            nonlocal active, maximum
            active += 1
            maximum = max(maximum, active)
            await asyncio.sleep(0.001)
            active -= 1
            return "ok"
        results = await asyncio.gather(*(self.engine._io(simulated_io) for _ in range(20)))
        self.assertEqual(results, ["ok"] * 20)
        self.assertEqual(maximum, self.settings.concurrency)
        self.assertEqual(active, 0)

    async def test_asgi_submit_incremental_results_and_cancel(self):
        self.engine.allow_non_windows = True
        self.engine.probe = AsyncMock(return_value={"resolved": [PUBLIC], "dns": {"status": "ok"}, "ping": [], "tcp": []})
        app = service.create_app(settings=self.settings, policy=self.policy, engine=self.engine, logger=logger())
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 12345))
        headers = {"Authorization": "Bearer " + TOKEN}
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1", headers=headers) as client:
            unauthorized = await client.post("/v1/probes", headers={"Authorization": "Bearer wrong"}, json=batch().model_dump())
            self.assertEqual(unauthorized.status_code, 401)
            submitted = await client.post("/v1/probes", json=batch(host="origin.example.invalid", excludedHosts=[OTHER], excludedCidrs=["93.184.216.0/24"]).model_dump())
            self.assertEqual(submitted.status_code, 202)
            job_id = submitted.json()["jobId"]
            await self.engine.start()
            await asyncio.wait_for(self.engine.queue.join(), 1)
            fetched = await client.get(f"/v1/probes/{job_id}?after=0")
            self.assertEqual(fetched.json()["queryId"], "q1")
            self.assertEqual(fetched.json()["status"], "completed")
            self.assertEqual(fetched.json()["cursor"], 1)
            after = await client.get(f"/v1/probes/{job_id}?after=1")
            self.assertEqual(after.json()["results"], [])
            self.assertEqual((await client.get(f"/v1/probes/{job_id}?after=2")).status_code, 400)
            pending = self.engine.submit(batch(host=OTHER, query="q2"))
            cancelled = await client.delete(f"/v1/probes/{pending.id}")
            self.assertEqual(cancelled.status_code, 200)
            self.assertEqual(cancelled.json()["status"], "cancelled")
        self.assertEqual(self.engine.probe.await_args.kwargs["excluded_hosts"], (OTHER,))
        self.assertEqual(self.engine.probe.await_args.kwargs["excluded_cidrs"], ("93.184.216.0/24",))

    async def test_log_does_not_echo_token_used_as_query_id(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        self.engine.logger.handlers = [handler]
        self.engine.logger.setLevel(logging.INFO)
        self.engine.submit(batch(query=TOKEN))
        self.assertNotIn(TOKEN, stream.getvalue())
        self.assertIn("[REDACTED]", stream.getvalue())


class WindowsIcmpTests(unittest.TestCase):
    def test_fixed_width_reply_layout_and_status_mapping(self):
        self.assertEqual(ctypes.sizeof(windows_icmp.EchoReply), 28)
        self.assertEqual(windows_icmp.EchoReply.status.offset, 4)
        self.assertEqual(windows_icmp.EchoReply.rtt.offset, 8)
        self.assertEqual(windows_icmp.classify_status(0), "reachable")
        self.assertEqual(windows_icmp.classify_status(11010), "timeout")
        self.assertEqual(windows_icmp.classify_status(11003), "unreachable")

    def test_mock_dll_reply_byte_order_and_handle_cleanup(self):
        api = types.SimpleNamespace(IcmpCreateFile=MagicMock(return_value=123), IcmpSendEcho=MagicMock(), IcmpCloseHandle=MagicMock())
        def echo(handle, address, request, size, options, buffer, buffer_size, timeout):
            self.assertEqual(address, int.from_bytes(ipaddress.ip_address(PUBLIC).packed, byteorder=sys.byteorder))
            self.assertEqual(size, 9)
            reply = ctypes.cast(buffer, ctypes.POINTER(windows_icmp.EchoReply)).contents
            reply.status = 0
            reply.rtt = 12
            return 1
        api.IcmpSendEcho.side_effect = echo
        with patch.object(windows_icmp.os, "name", "nt"), patch.object(windows_icmp.ctypes, "WinDLL", create=True, return_value=api):
            result = windows_icmp.ping(PUBLIC, 1000)
        self.assertEqual(result["status"], "reachable")
        self.assertEqual(result["roundTripMs"], 12)
        api.IcmpCloseHandle.assert_called_once_with(123)

    def test_mock_dll_timeout_is_not_false_success(self):
        api = types.SimpleNamespace(IcmpCreateFile=MagicMock(return_value=123), IcmpSendEcho=MagicMock(return_value=0), IcmpCloseHandle=MagicMock())
        with patch.object(windows_icmp.os, "name", "nt"), patch.object(windows_icmp.ctypes, "WinDLL", create=True, return_value=api), patch.object(windows_icmp.ctypes, "get_last_error", create=True, return_value=11010):
            result = windows_icmp.ping(PUBLIC, 1000)
        self.assertEqual(result["status"], "timeout")
        api.IcmpCloseHandle.assert_called_once_with(123)


if __name__ == "__main__":
    unittest.main()
