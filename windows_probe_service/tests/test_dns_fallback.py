"""Exercise ordered DNS fallback with a simulated resolver and guarded target I/O."""
from __future__ import annotations

import asyncio
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_dns_evidence as evidence
import service
DOMAIN, PUBLIC = evidence.DOMAIN, evidence.PUBLIC


class DnsFallbackTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await evidence.DnsEvidenceTests.asyncSetUp(self)

    async def asyncTearDown(self):
        await evidence.DnsEvidenceTests.asyncTearDown(self)

    def real_lookup(self):
        self.engine._resolve = types.MethodType(service.ProbeEngine._resolve, self.engine)

    def resolver_factory(self, outcomes, calls):
        class Answer:
            def __init__(self, addresses, canonical=DOMAIN):
                self.addresses = addresses
                self.canonical_name = canonical + "."
                self.response = types.SimpleNamespace(answer=[])
            def __iter__(self):
                return iter(types.SimpleNamespace(address=ip) for ip in self.addresses)

        def factory(configure=True):
            resolver = types.SimpleNamespace(nameservers=[], lifetime=0, timeout=0)
            async def resolve(host, record_type, **options):
                server = "system" if configure else resolver.nameservers[0]
                calls.append({"server": server, "host": host, "type": record_type, **options})
                value = outcomes[server]
                if isinstance(value, BaseException):
                    raise value
                if callable(value):
                    return await value()
                return Answer(*value)
            resolver.resolve = resolve
            return resolver
        return factory

    def successful_probes(self):
        self.engine._ping = AsyncMock(side_effect=lambda ip: {"address": ip, "status": "reachable"})
        self.engine._tcp = AsyncMock(side_effect=lambda ip, port: {"address": ip, "port": port, "status": "open"})

    async def test_system_failure_falls_back_to_google_and_default_domain_ports_share_one_lookup(self):
        calls = []
        outcomes = {"system": service.dns.resolver.NXDOMAIN(), "8.8.8.8": ([PUBLIC], "canonical.example.invalid")}
        self.real_lookup(); self.successful_probes()
        self.engine.io_limit = asyncio.Semaphore(1)
        with patch.object(service.dns.asyncresolver, "Resolver", side_effect=self.resolver_factory(outcomes, calls)):
            result = await asyncio.wait_for(self.engine.probe(DOMAIN, None, ping_count=1, tcp_attempts=1), 1)
        self.assertEqual([call["server"] for call in calls], ["system", "8.8.8.8"])
        self.assertTrue(all(call["type"] == "A" and call["search"] is False for call in calls))
        self.assertEqual(result["nslookup"]["resolver"], "8.8.8.8")
        self.assertEqual([attempt["status"] for attempt in result["nslookup"]["attempts"]], ["error", "ok"])
        self.assertEqual(result["nslookup"]["attempts"][0]["error"], "dns_nxdomain")
        self.assertEqual(result["nslookup"]["aliases"], ["canonical.example.invalid"])
        self.engine._ping.assert_awaited_once_with(PUBLIC)
        self.assertEqual([call.args for call in self.engine._tcp.await_args_list], [(PUBLIC, 80), (PUBLIC, 443)])

    async def test_no_a_answers_then_google_failure_falls_back_to_alidns_in_order(self):
        calls = []
        outcomes = {"system": ([], DOMAIN), "8.8.8.8": service.dns.resolver.NoNameservers(), "223.5.5.5": ([PUBLIC], DOMAIN)}
        self.real_lookup(); self.successful_probes()
        with patch.object(service.dns.asyncresolver, "Resolver", side_effect=self.resolver_factory(outcomes, calls)):
            result = await self.engine.probe(DOMAIN, 8443, ping_count=1, tcp_attempts=1)
        self.assertEqual([call["server"] for call in calls], list(service.DNS_RESOLVER_SEQUENCE))
        self.assertEqual(result["nslookup"]["resolver"], "223.5.5.5")
        self.assertEqual([attempt.get("error") for attempt in result["nslookup"]["attempts"]], ["dns_nodata", "dns_server_failure", None])
        self.engine._ping.assert_awaited_once_with(PUBLIC)
        self.engine._tcp.assert_awaited_once_with(PUBLIC, 8443)

    async def test_all_resolvers_fail_and_no_target_operations_are_started(self):
        calls = []
        outcomes = {"system": service.dns.resolver.NoAnswer(), "8.8.8.8": service.dns.resolver.NXDOMAIN(), "223.5.5.5": asyncio.TimeoutError()}
        self.real_lookup()
        with patch.object(service.dns.asyncresolver, "Resolver", side_effect=self.resolver_factory(outcomes, calls)):
            result = await self.engine.probe(DOMAIN, None)
        self.assertEqual([call["server"] for call in calls], list(service.DNS_RESOLVER_SEQUENCE))
        self.assertEqual(result["nslookup"]["resolver"], None)
        self.assertEqual(result["nslookup"]["status"], "timeout")
        self.assertEqual(result["nslookup"]["answers"], [])
        self.assertEqual(len(result["nslookup"]["attempts"]), 3)
        self.engine._ping.assert_not_called(); self.engine._tcp.assert_not_called()

    async def test_first_successful_answer_is_filtered_without_querying_another_resolver(self):
        calls = []
        outcomes = {"system": (["210.39.0.1", PUBLIC], DOMAIN)}
        self.real_lookup()
        with patch.object(service.dns.asyncresolver, "Resolver", side_effect=self.resolver_factory(outcomes, calls)):
            result = await self.engine.probe(DOMAIN, None, excluded_cidrs=("93.184.216.0/24",))
        self.assertEqual([call["server"] for call in calls], ["system"])
        self.assertEqual(result["nslookup"]["status"], "ok")
        self.assertEqual(result["nslookup"]["resolver"], "system")
        self.assertEqual([item["status"] for item in result["ping"]], ["skipped_safety", "skipped_custom"])
        self.assertEqual([item["port"] for item in result["tcp"]], [80, 443, 80, 443])
        self.engine._ping.assert_not_called(); self.engine._tcp.assert_not_called()

    async def test_successful_cdn_cname_is_not_retried_using_other_resolvers(self):
        calls = []
        outcomes = {"system": ([PUBLIC], "a.edge.example.invalid")}
        self.real_lookup()
        with patch.object(service.dns.asyncresolver, "Resolver", side_effect=self.resolver_factory(outcomes, calls)):
            result = await self.engine.probe(DOMAIN, None)
        self.assertEqual([call["server"] for call in calls], ["system"])
        self.assertEqual(result["skipped"]["status"], "skipped_cdn")
        self.engine._ping.assert_not_called(); self.engine._tcp.assert_not_called()

    async def test_cancellation_after_one_failure_prevents_next_dns_attempt(self):
        calls, live = [], [True]
        async def abandon():
            live[0] = False
            raise service.dns.resolver.NoAnswer()
        self.real_lookup()
        with patch.object(service.dns.asyncresolver, "Resolver", side_effect=self.resolver_factory({"system": abandon}, calls)):
            with self.assertRaises(service.AbandonedProbe):
                await self.engine.probe(DOMAIN, None, should_continue=lambda: live[0])
        self.assertEqual([call["server"] for call in calls], ["system"])
        self.engine._ping.assert_not_called(); self.engine._tcp.assert_not_called()

    async def test_each_fallback_attempt_has_its_own_timeout_and_io_guard(self):
        calls = []
        async def hanging():
            await asyncio.Future()
        self.real_lookup(); self.engine.settings.timeout_ms = 1
        outcomes = {server: hanging for server in service.DNS_RESOLVER_SEQUENCE}
        with patch.object(service.dns.asyncresolver, "Resolver", side_effect=self.resolver_factory(outcomes, calls)), \
             patch.object(self.engine, "_io", wraps=self.engine._io) as io:
            result = await asyncio.wait_for(self.engine.probe(DOMAIN, None), 1)
        self.assertEqual(len(calls), 3); self.assertEqual(io.await_count, 3)
        self.assertEqual([attempt["status"] for attempt in result["nslookup"]["attempts"]], ["timeout"] * 3)
        self.engine._ping.assert_not_called(); self.engine._tcp.assert_not_called()

    async def test_literal_ip_without_port_remains_ping_only_and_never_uses_dns_fallback(self):
        self.engine._ping = AsyncMock(return_value={"address": PUBLIC, "status": "reachable"})
        result = await self.engine.probe(PUBLIC, None, ping_count=1, tcp_attempts=1)
        self.engine._resolve.assert_not_called(); self.engine._tcp.assert_not_called()
        self.engine._ping.assert_awaited_once_with(PUBLIC)
        self.assertEqual(result["nslookup"]["status"], "not_applicable")
        self.assertEqual(result["nslookup"]["attempts"], [])
