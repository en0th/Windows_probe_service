"""Offline nslookup/Ping/TCP evidence and policy checks; no network operations."""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
import socket
import sys
import tempfile
import types
import unittest
from unittest.mock import AsyncMock, patch

SERVICE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_DIR))
import service
from network_policy import NetworkPolicy

PUBLIC = "93.184.216.34"
OTHER = "45.33.32.156"
DOMAIN = "origin.example.invalid"


class DnsEvidenceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.folder = tempfile.TemporaryDirectory()
        path = Path(self.folder.name) / "rules.json"
        path.write_text(json.dumps({"version": "offline", "cidrs": [], "domainSuffixes": [
            {"suffix": "edge.example.invalid", "source": "offline", "provider": "fixture"}]}))
        policy = NetworkPolicy(path)
        settings = service.Settings(token="offline-dns-evidence-token-never-real", data_dir=Path(self.folder.name), operations_per_second=0)
        logger = logging.getLogger("offline-dns-evidence")
        logger.handlers = [logging.NullHandler()]
        self.engine = service.ProbeEngine(settings, policy, logger)
        self.engine._resolve = AsyncMock(side_effect=AssertionError("offline DNS guard"))
        self.engine._ping = AsyncMock(side_effect=AssertionError("offline ICMP guard"))
        self.engine._tcp = AsyncMock(side_effect=AssertionError("offline TCP guard"))

    async def asyncTearDown(self):
        await self.engine.close()
        self.folder.cleanup()

    async def test_domain_lookup_is_explicit_and_each_checked_ipv4_is_pinged_and_connected(self):
        addresses = [PUBLIC, OTHER]
        self.engine._resolve = AsyncMock(return_value=(addresses, ["canonical.example.invalid"]))
        self.engine._ping = AsyncMock(side_effect=lambda ip: {"address": ip, "status": "reachable"})
        self.engine._tcp = AsyncMock(side_effect=lambda ip, port: {"address": ip, "port": port, "status": "open"})
        result = await self.engine.probe(DOMAIN, 443, ping_count=1, tcp_attempts=1)
        self.engine._resolve.assert_awaited_once_with(DOMAIN, should_continue=None, dns_servers=service.DEFAULT_DNS_SERVERS)
        self.assertEqual([call.args for call in self.engine._ping.await_args_list], [(PUBLIC,), (OTHER,)])
        self.assertEqual([call.args for call in self.engine._tcp.await_args_list], [(PUBLIC, 443), (OTHER, 443)])
        lookup = result["nslookup"]
        self.assertEqual(lookup["question"], DOMAIN)
        self.assertEqual(lookup["recordType"], "A")
        self.assertEqual(lookup["status"], "ok")
        self.assertEqual(lookup["answers"], addresses)
        self.assertEqual(lookup["aliases"], ["canonical.example.invalid"])
        self.assertGreaterEqual(lookup["elapsedMs"], 0)
        self.assertEqual(result["resolved"], addresses)

    async def test_literal_ipv4_port_connects_even_when_ping_times_out_without_a_dns_query(self):
        self.engine._ping = AsyncMock(return_value={"address": PUBLIC, "status": "timeout"})
        self.engine._tcp = AsyncMock(return_value={"address": PUBLIC, "port": 8443, "status": "open"})
        result = await self.engine.probe(PUBLIC, 8443, ping_count=1, tcp_attempts=1)
        self.engine._resolve.assert_not_called()
        self.engine._tcp.assert_awaited_once_with(PUBLIC, 8443)
        self.assertEqual(result["nslookup"]["status"], "not_applicable")
        self.assertEqual(result["nslookup"]["answers"], [])
        self.assertEqual(result["tcp"][0]["status"], "open")

    async def test_protected_domains_and_dns_ports_do_not_lookup_or_probe(self):
        for host, port, status in [("dns.google", None, "skipped_dns"), (DOMAIN, 53, "skipped_dns")]:
            with self.subTest(host=host, port=port):
                result = await self.engine.probe(host, port)
                self.assertEqual(result["nslookup"]["status"], status)
                self.assertEqual(result["nslookup"]["answers"], [])
        self.engine._resolve.assert_not_called()
        self.engine._ping.assert_not_called()
        self.engine._tcp.assert_not_called()

    async def test_successful_lookup_of_filtered_addresses_keeps_evidence_without_ping_or_tcp(self):
        addresses = ["10.1.2.3", "210.39.0.1", "8.8.8.8", PUBLIC]
        self.engine._resolve = AsyncMock(return_value=(addresses, []))
        result = await self.engine.probe(DOMAIN, 443, excluded_cidrs=("93.184.216.0/24",))
        self.assertEqual(result["nslookup"]["status"], "ok")
        self.assertEqual(result["nslookup"]["answers"], addresses)
        self.assertEqual([item["status"] for item in result["ping"]], ["skipped_private", "skipped_safety", "skipped_dns", "skipped_custom"])
        self.assertEqual([item["status"] for item in result["tcp"]], ["skipped_private", "skipped_safety", "skipped_dns", "skipped_custom"])
        self.engine._ping.assert_not_called()
        self.engine._tcp.assert_not_called()

    async def test_cdn_alias_keeps_lookup_evidence_and_does_not_imply_skip_without_cdn_cidrs(self):
        self.engine._resolve = AsyncMock(return_value=([PUBLIC], ["a.edge.example.invalid"]))
        self.engine._ping = AsyncMock(return_value={"address": PUBLIC, "status": "reachable"})
        self.engine._tcp = AsyncMock(return_value={"address": PUBLIC, "port": 443, "status": "open"})
        result = await self.engine.probe(DOMAIN, 443, ping_count=1, tcp_attempts=1)
        self.assertEqual(result["nslookup"]["status"], "ok")
        self.assertEqual(result["nslookup"]["answers"], [PUBLIC])
        self.assertEqual(result["nslookup"]["aliases"], ["a.edge.example.invalid"])
        self.assertNotIn("skipped", result)
        self.engine._resolve.assert_awaited_once_with(DOMAIN, should_continue=None, dns_servers=service.DEFAULT_DNS_SERVERS)
        self.engine._ping.assert_awaited_once_with(PUBLIC)
        self.engine._tcp.assert_awaited_once_with(PUBLIC, 443)

    async def test_lookup_failures_have_explicit_error_kind_and_do_not_probe(self):
        cases = [(service.dns.resolver.NXDOMAIN(), "error", "dns_nxdomain"),
                 (service.dns.resolver.NoAnswer(), "error", "dns_nodata"),
                 (service.dns.resolver.NoNameservers(), "error", "dns_server_failure"),
                 (asyncio.TimeoutError(), "timeout", "dns_timeout"),
                 (socket.gaierror("offline failure"), "error", "dns_failed_or_incomplete")]
        for failure, status, error in cases:
            with self.subTest(error=error):
                self.engine._resolve = AsyncMock(side_effect=failure)
                result = await self.engine.probe(DOMAIN, None)
                self.assertEqual(result["nslookup"]["status"], status)
                self.assertEqual(result["nslookup"]["error"], error)
                self.assertEqual(result["nslookup"]["answers"], [])
                self.assertEqual(result["dns"]["error"], error)
                self.assertEqual(result["nslookup"]["question"], DOMAIN)
        self.engine._ping.assert_not_called()
        self.engine._tcp.assert_not_called()

    async def test_lookup_address_limit_caps_evidence_and_never_probes_partial_results(self):
        self.engine._resolve = AsyncMock(return_value=([PUBLIC] * 65, []))
        result = await self.engine.probe(DOMAIN, 443)
        self.assertEqual(result["nslookup"]["status"], "error")
        self.assertEqual(result["nslookup"]["error"], "dns_address_limit_exceeded")
        self.assertEqual(len(result["nslookup"]["answers"]), 64)
        self.engine._ping.assert_not_called()
        self.engine._tcp.assert_not_called()

    async def test_worker_internal_failure_keeps_explicit_domain_lookup_error(self):
        self.engine.probe = AsyncMock(side_effect=RuntimeError("offline internal failure"))
        await self.engine.start()
        job = self.engine.submit(service.ProbeBatch(queryId="offline", targets=[{"id": "domain", "host": DOMAIN}]))
        await asyncio.wait_for(self.engine.queue.join(), 1)
        lookup = self.engine.snapshot(job.id)["results"][0]["nslookup"]
        self.assertEqual(lookup["question"], DOMAIN)
        self.assertEqual(lookup["status"], "error")
        self.assertEqual(lookup["error"], "probe_internal_error")
        self.assertEqual(lookup["answers"], [])

    async def test_real_lookup_wrapper_issues_one_a_question_and_keeps_only_actual_aliases(self):
        for canonical, expected in [(DOMAIN + ".", []), ("canonical.example.invalid.", ["canonical.example.invalid"])]:
            with self.subTest(canonical=canonical):
                class Answer:
                    canonical_name = canonical
                    response = types.SimpleNamespace(answer=[])
                    def __iter__(self):
                        return iter([types.SimpleNamespace(address=PUBLIC)])
                resolver = types.SimpleNamespace(lifetime=0, resolve=AsyncMock(return_value=Answer()))
                with patch.object(service.dns.asyncresolver, "Resolver", return_value=resolver):
                    addresses, aliases = await service.ProbeEngine._resolve(self.engine, DOMAIN)
                self.assertEqual(addresses, [PUBLIC])
                self.assertEqual(aliases, expected)
                resolver.resolve.assert_awaited_once_with(DOMAIN, "A", search=False, lifetime=resolver.lifetime)
