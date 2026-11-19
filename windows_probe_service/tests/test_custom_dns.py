"""Custom resolver validation, per-job isolation and policy checks, without network I/O."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import AsyncMock, patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_dns_evidence as evidence
import test_dns_fallback as fallback
import service
from probe_models import DEFAULT_DNS_SERVERS, DNS_SERVER_DENIED_CIDRS, ProbeBatch, ValidationError

PUBLIC, OTHER, DOMAIN = evidence.PUBLIC, evidence.OTHER, evidence.DOMAIN
CUSTOM = "9.9.9.9"
ENTERPRISE = "10.8.0.53"


def batch(servers=None, query="custom-dns", **changes):
    payload = {"queryId": query, "targets": [{"id": query, "host": DOMAIN, "port": 443}]}
    if servers is not None:
        payload["dnsServers"] = servers
    payload.update(changes)
    return ProbeBatch(**payload)


class DnsServerValidationTests(unittest.TestCase):
    def test_omitted_dns_preserves_old_defaults_and_empty_dns_means_system_only(self):
        self.assertEqual(batch().dnsServers, list(DEFAULT_DNS_SERVERS))
        self.assertEqual(batch([]).dnsServers, [])
        self.assertEqual(batch([" 10.8.0.53 ", CUSTOM, ENTERPRISE]).dnsServers, [ENTERPRISE, CUSTOM])
        self.assertEqual(batch(["100.64.0.53", "192.168.1.53", "172.16.0.53"]).dnsServers,
                         ["100.64.0.53", "192.168.1.53", "172.16.0.53"])

    def test_dns_rejects_wrong_containers_and_noncanonical_or_non_ipv4_strings(self):
        for value in (None, True, CUSTOM, (), {}, [None], [True], [1234], [""], ["system"],
                      ["[9.9.9.9]"], ["9.9.9.9:53"], ["https://dns.example"], ["::1"],
                      ["2001:4860:4860::8888"], ["009.9.9.9"], ["9.9.9.9\nwhoami"]):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                batch(dnsServers=value)

    def test_special_resolver_ranges_are_rejected_on_both_network_boundaries(self):
        import ipaddress
        for cidr in DNS_SERVER_DENIED_CIDRS:
            network = ipaddress.ip_network(cidr)
            for address in (network.network_address, network.broadcast_address):
                with self.subTest(address=str(address)), self.assertRaises(ValidationError):
                    batch([str(address)])

    def test_dns_count_limit_applies_before_deduplication_and_errors_do_not_echo_input(self):
        self.assertEqual(batch([CUSTOM] * 8).dnsServers, [CUSTOM])
        with self.assertRaises(ValidationError):
            batch([CUSTOM] * 9)
        with self.assertRaises(ValidationError) as error:
            batch(["private-input-marker"])
        self.assertEqual(error.exception.errors()[0]["loc"], ("dnsServers", 0))
        self.assertNotIn("private-input-marker", json.dumps(error.exception.errors()))

    def test_dns_defaults_input_and_dumped_lists_are_independent(self):
        servers = [CUSTOM, ENTERPRISE]
        original = batch(servers)
        servers.clear()
        dumped = original.model_dump()
        dumped["dnsServers"].clear()
        self.assertEqual(original.dnsServers, [CUSTOM, ENTERPRISE])
        self.assertEqual(ProbeBatch.model_validate(original).dnsServers, [CUSTOM, ENTERPRISE])
        first, second = batch(), batch()
        first.dnsServers.clear()
        self.assertEqual(second.dnsServers, list(DEFAULT_DNS_SERVERS))


class CustomDnsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await evidence.DnsEvidenceTests.asyncSetUp(self)

    async def asyncTearDown(self):
        await evidence.DnsEvidenceTests.asyncTearDown(self)

    def use_resolvers(self, outcomes, calls):
        self.engine._resolve = types.MethodType(service.ProbeEngine._resolve, self.engine)
        factory = fallback.DnsFallbackTests.resolver_factory(self, outcomes, calls)
        return patch.object(service.dns.asyncresolver, "Resolver", side_effect=factory)

    def successful_probes(self):
        self.engine._ping = AsyncMock(side_effect=lambda ip: {"address": ip, "status": "reachable"})
        self.engine._tcp = AsyncMock(side_effect=lambda ip, port: {"address": ip, "port": port, "status": "open"})

    async def test_custom_order_replaces_defaults_and_stops_on_first_success(self):
        calls = []
        self.successful_probes()
        outcomes = {"system": service.dns.resolver.NoAnswer(), ENTERPRISE: service.dns.resolver.NXDOMAIN(),
                    CUSTOM: ([PUBLIC], DOMAIN)}
        with self.use_resolvers(outcomes, calls):
            result = await self.engine.probe(DOMAIN, None, dns_servers=(ENTERPRISE, CUSTOM, OTHER), ping_count=1, tcp_attempts=1)
        self.assertEqual([item["server"] for item in calls], ["system", ENTERPRISE, CUSTOM])
        self.assertEqual([item["server"] for item in result["nslookup"]["attempts"]], ["system", ENTERPRISE, CUSTOM])
        self.assertEqual(result["nslookup"]["resolver"], CUSTOM)
        self.assertEqual([item.args for item in self.engine._tcp.await_args_list], [(PUBLIC, 80), (PUBLIC, 443)])

    async def test_system_only_never_uses_the_old_default_or_any_other_resolver(self):
        calls = []
        with self.use_resolvers({"system": service.dns.resolver.NoAnswer()}, calls):
            result = await self.engine.probe(DOMAIN, 443, dns_servers=())
        self.assertEqual([item["server"] for item in calls], ["system"])
        self.assertEqual(result["nslookup"]["status"], "error")
        self.assertEqual(result["nslookup"]["attempts"][0]["error"], "dns_nodata")
        self.engine._ping.assert_not_called(); self.engine._tcp.assert_not_called()

    async def test_successful_answer_is_filtered_without_trying_a_later_custom_server(self):
        calls = []
        with self.use_resolvers({"system": (["104.16.1.1", "10.8.0.1"], "a.edge.example.invalid")}, calls):
            result = await self.engine.probe(DOMAIN, None, dns_servers=(ENTERPRISE, CUSTOM))
        self.assertEqual([item["server"] for item in calls], ["system"])
        self.assertEqual(result["skipped"]["status"], "skipped_cdn")
        self.engine._ping.assert_not_called(); self.engine._tcp.assert_not_called()

    async def test_configured_dns_literals_are_skipped_without_global_policy_mutation(self):
        result = await self.engine.probe(PUBLIC, 8443, dns_servers=(PUBLIC, ENTERPRISE))
        self.assertEqual(result["ping"][0]["status"], "skipped_dns")
        self.assertEqual(result["ping"][0]["source"], "request.dnsServers")
        self.assertEqual(result["tcp"][0]["status"], "skipped_dns")
        self.engine._resolve.assert_not_called(); self.engine._ping.assert_not_called(); self.engine._tcp.assert_not_called()
        self.assertIsNone(self.engine.policy.address(PUBLIC))
        self.successful_probes()
        other_request = await self.engine.probe(PUBLIC, 8443, dns_servers=())
        self.assertEqual(other_request["tcp"][0]["status"], "open")

    async def test_dns_answers_exclude_configured_servers_but_keep_other_public_answers(self):
        calls = []
        self.successful_probes()
        with self.use_resolvers({"system": ([PUBLIC, OTHER], DOMAIN)}, calls):
            result = await self.engine.probe(DOMAIN, 443, dns_servers=(PUBLIC,), ping_count=1, tcp_attempts=1)
        self.assertEqual([item["status"] for item in result["ping"]], ["skipped_dns", "reachable"])
        self.engine._ping.assert_awaited_once_with(OTHER)
        self.engine._tcp.assert_awaited_once_with(OTHER, 443)
        self.assertEqual([item["server"] for item in calls], ["system"])

    async def test_dns_order_and_empty_configuration_isolate_inflight_and_cached_results(self):
        self.engine.probe = AsyncMock(side_effect=lambda host, port, **kwargs: {
            "resolved": [], "dns": {"status": "ok", "servers": list(kwargs["dns_servers"])}, "ping": [], "tcp": []})
        configurations = [[ENTERPRISE, CUSTOM], [CUSTOM, ENTERPRISE], [], list(DEFAULT_DNS_SERVERS)]
        jobs = [self.engine.submit(batch(servers, query=f"q{index}")) for index, servers in enumerate(configurations)]
        self.assertEqual(len(self.engine.inflight), 4)
        await self.engine.start()
        await asyncio.wait_for(self.engine.queue.join(), 1)
        self.assertEqual(self.engine.probe.await_count, 4)
        for job, servers in zip(jobs, configurations):
            self.assertEqual(job.results[0]["dns"]["servers"], servers)
        cached = self.engine.submit(batch(configurations[0], query="cached"))
        self.assertTrue(cached.results[0]["cached"])
        self.assertEqual(cached.results[0]["dns"]["servers"], configurations[0])
        self.assertEqual(self.engine.probe.await_count, 4)

    async def test_job_resolver_snapshot_is_not_changed_by_later_model_mutation(self):
        self.engine.probe = AsyncMock(return_value={"resolved": [], "dns": {"status": "ok"}, "ping": [], "tcp": []})
        request = batch([ENTERPRISE, CUSTOM])
        self.engine.submit(request)
        request.dnsServers[:] = [OTHER]
        await self.engine.start()
        await asyncio.wait_for(self.engine.queue.join(), 1)
        self.assertEqual(self.engine.probe.await_args.kwargs["dns_servers"], (ENTERPRISE, CUSTOM))

    async def test_http_health_advertises_capability_and_old_and_custom_requests_both_work(self):
        self.engine.allow_non_windows = True
        # ASGITransport reuses this already-started fixture without lifespan.
        # Reuse its logger so no unowned rotating file handle remains open when
        # TemporaryDirectory removes the logs directory on Windows.
        app = service.create_app(settings=self.engine.settings, policy=self.engine.policy, engine=self.engine,
                                 logger=self.engine.logger)
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 12345))
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1",
                                     headers={"Authorization": "Bearer " + self.engine.settings.token}) as client:
            health = (await client.get("/health")).json()
            self.assertIs(health["customDnsServers"], True)
            self.assertEqual(health["dnsServers"], list(DEFAULT_DNS_SERVERS))
            self.assertIs(health["probeSettings"], True)
            self.assertIs(health["cdnSkipConfigurable"], True)
            self.assertIs(health["cdnCidrsSupported"], True)
            self.assertEqual(health["defaultPingCount"], 5)
            self.assertEqual(health["defaultTcpAttempts"], 3)
            self.assertEqual(health["defaultProbeTimeoutMs"], 3000)
            payload = {"queryId": "old-client", "targets": [{"id": "old", "host": PUBLIC}]}
            self.assertEqual((await client.post("/v1/probes", json=payload)).status_code, 202)
            payload["queryId"] = "system-only-client"
            payload["dnsServers"] = []
            self.assertEqual((await client.post("/v1/probes", json=payload)).status_code, 202)
            payload["dnsServers"] = ["127.0.0.1"]
            self.assertEqual((await client.post("/v1/probes", json=payload)).status_code, 422)
            payload["dnsServers"] = list(DEFAULT_DNS_SERVERS)
            payload["pingCount"] = 5
            payload["tcpAttempts"] = 3
            payload["timeoutMs"] = 3000
            payload["skipCdn"] = False
            payload["cdnCidrs"] = ["203.0.113.0/24"]
            self.assertEqual((await client.post("/v1/probes", json=payload)).status_code, 202)
            payload["cdnCidrs"] = ["203.0.113.0/33"]
            self.assertEqual((await client.post("/v1/probes", json=payload)).status_code, 422)
            payload["cdnCidrs"] = []
            payload["skipCdn"] = "false"
            self.assertEqual((await client.post("/v1/probes", json=payload)).status_code, 422)
            payload["skipCdn"] = True
            payload["timeoutMs"] = 199
            self.assertEqual((await client.post("/v1/probes", json=payload)).status_code, 422)


if __name__ == "__main__":
    unittest.main()
