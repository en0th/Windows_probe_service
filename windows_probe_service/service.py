"""SOAR local Windows probe agent. Bind to loopback only; never execute commands."""
from __future__ import annotations

import argparse
import asyncio
from collections import OrderedDict
from contextlib import asynccontextmanager
import contextvars
from dataclasses import dataclass, field
from datetime import datetime, timezone
import errno
import hmac
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import secrets
import socket
import sys
import threading
import time
from typing import Optional
import uuid

import dns.asyncresolver
import dns.exception
import dns.resolver
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.middleware.trustedhost import TrustedHostMiddleware

from network_policy import NetworkPolicy
from probe_models import (DEFAULT_DNS_SERVERS, DEFAULT_PING_COUNT, DEFAULT_PROBE_TIMEOUT_MS,
                            DEFAULT_SKIP_CDN, DEFAULT_TCP_ATTEMPTS, MAX_TARGETS, ProbeBatch,
                            ProbeTarget, ValidationError, normalize_host)
from k01_intelligence import (K01IntelligenceClient, K01Error, new_trace_id, normalize_trace_id,
                              reset_trace_id, set_trace_id, set_service_version,
                              config_from_payload as k01_config_from_payload)
import windows_icmp

API_VERSION = 1
SERVICE_VERSION = "1.6.15"
# K01 payloads are stamped with this build so the userscript log names the exe that answered.
set_service_version(SERVICE_VERSION)
MAX_DNS_ADDRESSES = 64
DNS_RESOLVER_SEQUENCE = ("system", *DEFAULT_DNS_SERVERS)
_PROBE_TIMEOUT_MS = contextvars.ContextVar("soar_probe_timeout_ms", default=None)
DOMAIN_DEFAULT_PORTS = (80, 443)
MAX_BODY_BYTES = 2 * 1024 * 1024
def resource_path(name: str) -> Path:
    """Resolve a read-only resource inside a frozen executable or source tree."""
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("resource path must be relative")
    base = Path(sys._MEIPASS) if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS") else Path(__file__).resolve().parent
    return base / relative


RULES_PATH = resource_path("cdn_rules.json")


def resolve_rules_path(data_dir: Path) -> Path:
    """An explicit persistent update takes precedence over the bundled rules."""
    override = Path(data_dir) / "cdn_rules.json"
    return override if override.exists() else resource_path("cdn_rules.json")


def run_self_test() -> dict:
    """Check packaged dependencies and data without probing or creating settings."""
    import uvicorn
    import starlette
    import dns
    import importlib
    import importlib.util
    frozen = bool(getattr(sys, "frozen", False))
    runtime_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)).resolve()
    bundle_layout = ("onedir" if runtime_dir == Path(sys.executable).resolve().parent / "_internal" else "onefile") if frozen else "source"
    forbidden = ("fastapi", "pydantic", "pydantic_core", "_pydantic_core")
    if any(name.split(".")[0] in forbidden for name in sys.modules):
        raise RuntimeError("legacy validation dependency was loaded")
    if frozen:
        if any(importlib.util.find_spec(name) is not None for name in forbidden):
            raise RuntimeError("legacy validation dependency remains in the bundle")
        if any(any(part.lower().startswith(forbidden) for part in path.relative_to(runtime_dir).parts)
               for path in runtime_dir.rglob("*")):
            raise RuntimeError("legacy validation dependency remains in bundled files")
        python_runtime = runtime_dir / f"python{sys.version_info.major}{sys.version_info.minor}.dll"
        if not python_runtime.is_file():
            raise RuntimeError("bundled Python runtime missing")
    else:
        python_runtime = Path(sys.executable).resolve()
    for module in ("uvicorn.protocols.http.h11_impl", "uvicorn.lifespan.on", "uvicorn.loops.asyncio", "dns._asyncio_backend", "anyio._backends._asyncio"):
        importlib.import_module(module)
    k01_config_from_payload({"baseUrl": "https://k01.example.invalid", "verifyTLS": True})
    policy = NetworkPolicy(resource_path("cdn_rules.json"))
    if not resource_path("LICENSE.cdncheck.md").is_file() or not policy.cidrs or not policy.domains:
        raise RuntimeError("bundled CDN data or license missing")
    if policy.address("0.0.0.0") is None or policy.address("8.8.8.8") is None or policy.address("::1") is None:
        raise RuntimeError("address exclusion self-test failed")
    validation = ProbeBatch(queryId="offline-self-test", targets=[{"id": "offline", "host": "example.invalid"}],
                            dnsServers=["10.0.0.53"])
    if validation.dnsServers != ["10.0.0.53"]:
        raise RuntimeError("custom DNS validation self-test failed")
    return {"status": "ok", "service": "soar-network-probe", "version": SERVICE_VERSION,
            "apiVersion": API_VERSION, "frozen": frozen, "bundleLayout": bundle_layout,
            "httpStack": "starlette", "validationImplementation": "python",
            "pydanticCoreBundled": False,
            "k01Intelligence": True, "k01PasswordChange": True,
            "probeSettings": True, "cdnSkipConfigurable": True, "cdnCidrsSupported": True,
            "cdnOnlyCidrs": True, "skipOptionsConfigurable": True, "customDnsServers": True, "dnsServers": list(DEFAULT_DNS_SERVERS),
            "nativeDependencies": {"pythonRuntime": str(python_runtime)},
            "ipv4Only": True, "cdnRulesVersion": policy.version,
            "cdnCidrs": len(policy.cidrs), "cdnDomainSuffixes": len(policy.domains),
            "dependencies": {"starlette": starlette.__version__,
                             "uvicorn": uvicorn.__version__, "dnspython": dns.__version__}}


def _windows_clipboard_write(text: str):
    import ctypes
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.OpenClipboard.argtypes, user32.OpenClipboard.restype = [ctypes.c_void_p], ctypes.c_int
    user32.EmptyClipboard.argtypes, user32.EmptyClipboard.restype = [], ctypes.c_int
    user32.SetClipboardData.argtypes, user32.SetClipboardData.restype = [ctypes.c_uint, ctypes.c_void_p], ctypes.c_void_p
    user32.CloseClipboard.argtypes, user32.CloseClipboard.restype = [], ctypes.c_int
    kernel32.GlobalAlloc.argtypes, kernel32.GlobalAlloc.restype = [ctypes.c_uint, ctypes.c_size_t], ctypes.c_void_p
    kernel32.GlobalLock.argtypes, kernel32.GlobalLock.restype = [ctypes.c_void_p], ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes, kernel32.GlobalUnlock.restype = [ctypes.c_void_p], ctypes.c_int
    kernel32.GlobalFree.argtypes, kernel32.GlobalFree.restype = [ctypes.c_void_p], ctypes.c_void_p
    kernel32.GetConsoleWindow.argtypes, kernel32.GetConsoleWindow.restype = [], ctypes.c_void_p
    payload = text.encode("utf-16-le") + b"\0\0"
    handle = kernel32.GlobalAlloc(0x0002, len(payload))
    opened, transferred = False, False
    try:
        if not handle:
            raise OSError("clipboard allocation failed")
        pointer = kernel32.GlobalLock(handle)
        if not pointer:
            raise OSError("clipboard lock failed")
        try:
            ctypes.memmove(pointer, payload, len(payload))
        finally:
            kernel32.GlobalUnlock(handle)
        owner = kernel32.GetConsoleWindow()
        if not owner:
            raise OSError("no console clipboard owner; use --show-token")
        for _ in range(5):
            if user32.OpenClipboard(owner):
                opened = True
                break
            time.sleep(0.05)
        if not opened or not user32.EmptyClipboard() or not user32.SetClipboardData(13, handle):
            raise OSError("clipboard unavailable; use --show-token")
        transferred = True  # Windows owns the memory after SetClipboardData succeeds.
    finally:
        if opened:
            user32.CloseClipboard()
        if handle and not transferred:
            kernel32.GlobalFree(handle)


def copy_token_to_clipboard(token: str):
    if os.name != "nt":
        raise RuntimeError("clipboard support requires Windows")
    _windows_clipboard_write(token)


def start_console_controls(server, settings):
    """Console hotkeys make the standalone EXE usable without extra launchers."""
    import msvcrt

    def listen():
        while not server.should_exit:
            if not server.started:
                time.sleep(0.1)
                continue
            if not msvcrt.kbhit():
                time.sleep(0.1)
                continue
            key = msvcrt.getwch().lower()
            try:
                if key == "c":
                    copy_token_to_clipboard(settings.token)
                    print("Pairing token copied. Paste it into the userscript settings.", flush=True)
                elif key == "l":
                    os.startfile(str(settings.data_dir / "logs"))
                elif key == "q":
                    print("Stopping service...", flush=True)
                    server.should_exit = True
            except (OSError, RuntimeError):
                print("Action failed. For the token, run SOARProbe.exe --show-token.", flush=True)

    thread = threading.Thread(target=listen, name="soar-probe-console", daemon=True)
    thread.start()
    return thread


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class Settings:
    token: str = field(repr=False)
    data_dir: Path = field(default_factory=lambda: Path.home() / ".soar-probe")
    port: int = 8765
    concurrency: int = 16
    timeout_ms: int = 3000
    operations_per_second: float = 50
    cache_seconds: float = 60
    cache_size: int = 4096
    queue_size: int = 8192
    max_jobs: int = 32
    max_active_jobs: int = 4
    job_ttl_seconds: int = 3600
    excluded_cidrs: list = field(default_factory=list)


def default_data_dir():
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "SOARProbe"
    return Path.home() / ".soar-probe"


def load_settings(data_dir: Optional[Path] = None) -> Settings:
    folder = Path(data_dir or default_data_dir())
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "config.json"
    if not path.exists():
        data = {"token": secrets.token_urlsafe(32), "port": 8765,
                "concurrency": 16, "timeoutMs": 3000,
                "operationsPerSecond": 50, "cacheSeconds": 60, "excludedCidrs": []}
        # Exclusive creation preserves the original pairing token on repeated install.
        try:
            with path.open("x", encoding="utf-8") as out:
                json.dump(data, out, ensure_ascii=False, indent=2)
            if os.name != "nt":
                path.chmod(0o600)
        except FileExistsError:
            pass
    data = json.loads(path.read_text(encoding="utf-8"))
    token = data.get("token")
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token):
        raise ValueError("config.json token invalid; use a random URL-safe token of 32+ characters")
    numbers = {"port": (1024, 65535), "concurrency": (1, 64), "timeoutMs": (200, 10000),
               "operationsPerSecond": (1, 200), "cacheSeconds": (0, 3600)}
    defaults = {"port": 8765, "concurrency": 16, "timeoutMs": 3000,
                "operationsPerSecond": 50, "cacheSeconds": 60}
    for key, (low, high) in numbers.items():
        value = data.get(key, defaults[key])
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
            raise ValueError(f"config.json {key} out of range")
        if key in {"port", "concurrency", "timeoutMs"} and not isinstance(value, int):
            raise ValueError(f"config.json {key} must be an integer")
        defaults[key] = value
    excluded = data.get("excludedCidrs", [])
    if not isinstance(excluded, list) or len(excluded) > 2048:
        raise ValueError("config.json excludedCidrs must be a list of at most 2048 CIDRs")
    for cidr in excluded:
        if not isinstance(cidr, str):
            raise ValueError("config.json excludedCidrs entries must be CIDR strings")
        ipaddress.ip_network(cidr, strict=True)
    return Settings(token=token, data_dir=folder, port=defaults["port"],
        concurrency=defaults["concurrency"], timeout_ms=defaults["timeoutMs"],
        operations_per_second=defaults["operationsPerSecond"], cache_seconds=defaults["cacheSeconds"],
        excluded_cidrs=excluded)


def create_logger(settings: Settings):
    logger = logging.getLogger(f"soar-probe.{id(settings)}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    folder = settings.data_dir / "logs"
    folder.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(folder / "probe.jsonl", maxBytes=4 * 1024 * 1024,
                                  backupCount=5, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger


@dataclass
class Job:
    id: str
    query_id: str
    total: int
    created: float = field(default_factory=time.monotonic)
    status: str = "queued"
    results: list = field(default_factory=list)


@dataclass
class Entry:
    key: tuple
    host: str
    port: Optional[int]
    excluded_hosts: tuple = ()
    excluded_cidrs: tuple = ()
    dns_servers: tuple = DEFAULT_DNS_SERVERS
    ping_count: int = DEFAULT_PING_COUNT
    tcp_attempts: int = DEFAULT_TCP_ATTEMPTS
    timeout_ms: int = DEFAULT_PROBE_TIMEOUT_MS
    skip_cdn: bool = DEFAULT_SKIP_CDN
    skip_private: bool = True
    skip_dns: bool = True
    skip_safety: bool = True
    cdn_cidrs: tuple = ()
    watchers: list = field(default_factory=list)
    started: bool = False


@dataclass
class DnsResolution:
    addresses: list
    aliases: list
    attempts: list
    resolver: Optional[str] = None
    status: str = "ok"
    error: Optional[str] = None

    def __iter__(self):
        # Preserve the existing two-value resolver contract for callers while
        # carrying the ordered resolver evidence alongside those values.
        yield self.addresses
        yield self.aliases


def dns_failure_details(exc):
    if isinstance(exc, (asyncio.TimeoutError, dns.exception.Timeout)):
        return "timeout", "dns_timeout"
    return "error", ("dns_nxdomain" if isinstance(exc, dns.resolver.NXDOMAIN)
                     else "dns_nodata" if isinstance(exc, dns.resolver.NoAnswer)
                     else "dns_server_failure" if isinstance(exc, dns.resolver.NoNameservers)
                     else "dns_failed_or_incomplete")


class CapacityError(Exception):
    pass


class AbandonedProbe(Exception):
    pass


class ProbeEngine:
    def __init__(self, settings: Settings, policy: NetworkPolicy, logger=None):
        self.settings, self.policy = settings, policy
        self.logger = logger or logging.getLogger("soar-probe.test")
        self.jobs = OrderedDict()
        self.cache = OrderedDict()
        self.inflight = {}
        self.queue = asyncio.Queue(maxsize=settings.queue_size)
        self.workers = []
        self.io_limit = asyncio.Semaphore(settings.concurrency)
        self.rate_lock = asyncio.Lock()
        self.next_operation = 0.0
        self.closed = False

    def log(self, event, **fields):
        message = json.dumps({"time": utcnow(), "event": event, **fields}, ensure_ascii=False)
        # Input-controlled query/target identifiers must not smuggle the pairing
        # token into logs even if a caller deliberately reuses it as an ID.
        self.logger.info(message.replace(self.settings.token, "[REDACTED]"))

    async def start(self):
        self.closed = False
        self.workers = [asyncio.create_task(self._worker(), name=f"probe-worker-{i}")
                        for i in range(self.settings.concurrency)]
        self.log("service_started", serviceVersion=SERVICE_VERSION, apiVersion=API_VERSION,
                 cdnRulesVersion=self.policy.version,
                 concurrency=self.settings.concurrency, timeoutMs=self.settings.timeout_ms)

    async def close(self):
        self.closed = True
        for job in self.jobs.values():
            if job.status in {"queued", "running"}:
                job.status = "cancelled"
        for worker in self.workers:
            worker.cancel()
        await asyncio.gather(*self.workers, return_exceptions=True)
        self.workers.clear()
        self.inflight.clear()
        self.log("service_stopped")

    def _prune(self):
        now = time.monotonic()
        for job_id, job in list(self.jobs.items()):
            if job.status in {"completed", "cancelled"} and now - job.created > self.settings.job_ttl_seconds:
                del self.jobs[job_id]
        while len(self.jobs) >= self.settings.max_jobs:
            old = next((key for key, job in self.jobs.items() if job.status in {"completed", "cancelled"}), None)
            if old is None:
                break
            del self.jobs[old]
        for key, (expires, _) in list(self.cache.items()):
            if expires <= now:
                del self.cache[key]

    def submit(self, batch: ProbeBatch):
        if self.closed:
            raise CapacityError("service_stopping")
        self._prune()
        if len(self.jobs) >= self.settings.max_jobs or sum(j.status in {"queued", "running"} for j in self.jobs.values()) >= self.settings.max_active_jobs:
            raise CapacityError("too_many_jobs")
        exclusions = tuple(sorted(batch.excludedHosts))
        excluded_cidrs = tuple(sorted(batch.excludedCidrs))
        dns_servers = tuple(batch.dnsServers)
        ping_count, tcp_attempts, timeout_ms = batch.pingCount, batch.tcpAttempts, batch.timeoutMs
        skip_cdn, skip_private = batch.skipCdn, batch.skipPrivate
        skip_dns, skip_safety = batch.skipDns, batch.skipSafety
        cdn_cidrs = tuple(batch.cdnCidrs)
        def target_key(target):
            return (target.host, target.port, exclusions, excluded_cidrs, dns_servers,
                    cdn_cidrs, ping_count, tcp_attempts, timeout_ms, skip_cdn,
                    skip_private, skip_dns, skip_safety)
        new_keys = {target_key(t) for t in batch.targets} - self.inflight.keys() - self.cache.keys()
        if self.queue.qsize() + len(new_keys) > self.settings.queue_size:
            raise CapacityError("probe_queue_full")
        job = Job(uuid.uuid4().hex, batch.queryId, len(batch.targets))
        self.jobs[job.id] = job
        for target in batch.targets:
            key = target_key(target)
            if key in self.cache:
                self.cache.move_to_end(key)
                self._append(job, target, self.cache[key][1], cached=True)
                continue
            if key not in self.inflight:
                entry = Entry(key, target.host, target.port, excluded_hosts=exclusions,
                              excluded_cidrs=excluded_cidrs, dns_servers=dns_servers,
                              ping_count=ping_count, tcp_attempts=tcp_attempts,
                              timeout_ms=timeout_ms, skip_cdn=skip_cdn,
                              skip_private=skip_private, skip_dns=skip_dns,
                              skip_safety=skip_safety, cdn_cidrs=cdn_cidrs)
                self.inflight[key] = entry
                self.queue.put_nowait(entry)
            self.inflight[key].watchers.append((job.id, target))
        self.log("job_submitted", jobId=job.id, queryId=job.query_id, total=job.total,
                 uniqueTargets=len({(t.host, t.port) for t in batch.targets}),
                 excludedHosts=list(exclusions), excludedCidrs=list(excluded_cidrs), dnsServers=list(dns_servers),
                 pingCount=ping_count, tcpAttempts=tcp_attempts, timeoutMs=timeout_ms,
                 skipCdn=skip_cdn, skipPrivate=skip_private, skipDns=skip_dns,
                 skipSafety=skip_safety, cdnCidrs=list(cdn_cidrs))
        return job

    def cancel(self, job_id):
        job = self.jobs.get(job_id)
        if job is None:
            raise KeyError(job_id)
        if job.status not in {"completed", "cancelled"}:
            job.status = "cancelled"
            for entry in self.inflight.values():
                entry.watchers[:] = [(key, target) for key, target in entry.watchers if key != job_id]
            self.log("job_cancelled", jobId=job.id, queryId=job.query_id, completed=len(job.results))
        return job

    def snapshot(self, job_id, after=0):
        job = self.jobs.get(job_id)
        if job is None:
            raise KeyError(job_id)
        if after > len(job.results):
            raise ValueError("cursor_ahead")
        return {"jobId": job.id, "queryId": job.query_id, "status": job.status,
                "total": job.total, "completed": len(job.results), "cursor": len(job.results),
                "results": job.results[after:], "errors": []}

    def _append(self, job, target, core, cached=False):
        if job.status in {"cancelled", "completed"}:
            return
        result = {**core, "id": target.id, "host": target.host, "port": target.port,
                  "cached": cached, "finishedAt": utcnow()}
        job.results.append(result)
        job.status = "completed" if len(job.results) == job.total else "running"
        self.log("target_result", jobId=job.id, queryId=job.query_id, **result)
        if job.status == "completed":
            self.log("job_completed", jobId=job.id, queryId=job.query_id, total=job.total)

    async def _worker(self):
        while True:
            entry = await self.queue.get()
            try:
                if not entry.watchers:
                    continue
                entry.started = True
                for job_id, _ in entry.watchers:
                    job = self.jobs.get(job_id)
                    if job and job.status == "queued":
                        job.status = "running"
                try:
                    result = await self.probe(entry.host, entry.port, should_continue=lambda: bool(entry.watchers),
                                              excluded_hosts=entry.excluded_hosts, excluded_cidrs=entry.excluded_cidrs,
                                              dns_servers=entry.dns_servers, ping_count=entry.ping_count,
                                              tcp_attempts=entry.tcp_attempts, timeout_ms=entry.timeout_ms,
                                              skip_cdn=entry.skip_cdn, skip_private=entry.skip_private,
                                              skip_dns=entry.skip_dns, skip_safety=entry.skip_safety,
                                              cdn_cidrs=entry.cdn_cidrs)
                except AbandonedProbe:
                    continue
                except Exception as exc:
                    self.log("probe_internal_error", host=entry.host, port=entry.port, error=type(exc).__name__)
                    lookup = {"question": entry.host, "recordType": "A", "answers": [], "aliases": [],
                              "attempts": [], "resolver": None, "elapsedMs": 0}
                    try:
                        ipaddress.ip_address(entry.host)
                        lookup["status"] = "not_applicable"
                    except ValueError:
                        lookup.update(status="error", error="probe_internal_error")
                    result = {"resolved": [], "dns": {"status": "error", "elapsedMs": 0,
                              "error": "probe_internal_error"}, "nslookup": lookup, "ping": [], "tcp": []}
                if self.settings.cache_seconds > 0:
                    self.cache[entry.key] = (time.monotonic() + self.settings.cache_seconds, result)
                    self.cache.move_to_end(entry.key)
                    while len(self.cache) > self.settings.cache_size:
                        self.cache.popitem(last=False)
                for job_id, target in entry.watchers:
                    job = self.jobs.get(job_id)
                    if job:
                        self._append(job, target, result)
            finally:
                if self.inflight.get(entry.key) is entry:
                    del self.inflight[entry.key]
                self.queue.task_done()

    async def _io(self, operation, should_continue=None):
        async with self.io_limit:
            if self.settings.operations_per_second > 0:
                async with self.rate_lock:
                    now = time.monotonic()
                    delay = self.next_operation - now
                    if delay > 0:
                        await asyncio.sleep(delay)
                    self.next_operation = time.monotonic() + 1 / self.settings.operations_per_second
            if should_continue is not None and not should_continue():
                raise AbandonedProbe()
            return await operation()

    def _probe_timeout_ms(self):
        return _PROBE_TIMEOUT_MS.get() or self.settings.timeout_ms

    async def _resolve(self, host, should_continue=None, dns_servers=DEFAULT_DNS_SERVERS):
        attempts = []
        budget = self._probe_timeout_ms() / 1000
        for server in ("system", *dns_servers):
            if should_continue is not None and not should_continue():
                raise AbandonedProbe()
            started = None

            async def lookup_once():
                nonlocal started
                started = time.monotonic()
                resolver = dns.asyncresolver.Resolver() if server == "system" else dns.asyncresolver.Resolver(configure=False)
                if server != "system":
                    resolver.nameservers = [server]
                resolver.lifetime = budget
                resolver.timeout = budget
                # A records only. dnspython follows the CNAME chain in the
                # same bounded request and handles truncated UDP replies.
                answer = await resolver.resolve(host, "A", search=False, lifetime=budget)
                canonical_name = str(answer.canonical_name).rstrip(".")
                aliases = [canonical_name] if canonical_name.lower() != host.lower().rstrip(".") else []
                for rrset in answer.response.answer:
                    if rrset.rdtype == 5:
                        aliases.extend(str(record.target).rstrip(".") for record in rrset)
                addresses = list(dict.fromkeys(str(ipaddress.ip_address(record.address)) for record in answer
                                               if ipaddress.ip_address(record.address).version == 4))
                if not addresses:
                    raise dns.resolver.NoAnswer()
                return addresses, list(dict.fromkeys(aliases))

            try:
                # Count and limit every DNS attempt separately. Do not hold an
                # outer I/O slot while acquiring the next attempt's slot.
                addresses, aliases = await self._io(lambda: asyncio.wait_for(lookup_once(), budget + 0.1), should_continue)
                elapsed = round((time.monotonic() - started) * 1000)
                attempts.append({"server": server, "status": "ok", "elapsedMs": elapsed,
                                 "answers": addresses[:MAX_DNS_ADDRESSES], "aliases": aliases})
                return DnsResolution(addresses, aliases, attempts, resolver=server)
            except (OSError, dns.exception.DNSException, ValueError, asyncio.TimeoutError) as exc:
                status, error = dns_failure_details(exc)
                elapsed = round((time.monotonic() - started) * 1000) if started is not None else 0
                attempts.append({"server": server, "status": status, "error": error, "elapsedMs": elapsed, "answers": []})
        last = attempts[-1]
        return DnsResolution([], [], attempts, status=last["status"], error=last["error"])

    async def _ping(self, address):
        return await asyncio.to_thread(windows_icmp.ping, address, self._probe_timeout_ms())

    async def _tcp(self, address, port):
        started = time.monotonic()
        writer = None
        timeout = self._probe_timeout_ms() / 1000
        try:
            # A validated numeric address pins the actual destination; never
            # resolve the original domain again after policy validation.
            _, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout)
            return {"address": address, "port": port, "status": "open",
                    "elapsedMs": round((time.monotonic() - started) * 1000)}
        except asyncio.TimeoutError:
            return {"address": address, "port": port, "status": "timeout",
                    "elapsedMs": round((time.monotonic() - started) * 1000)}
        except OSError as exc:
            refused = isinstance(exc, ConnectionRefusedError) or exc.errno in {errno.ECONNREFUSED, 10061}
            return {"address": address, "port": port, "status": "refused" if refused else "error",
                    "elapsedMs": round((time.monotonic() - started) * 1000),
                    "error": f"os_error_{getattr(exc, 'winerror', None) or exc.errno or 'unknown'}"}
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), 0.5)
                except (OSError, asyncio.TimeoutError):
                    pass

    async def _ping_with_retries(self, address, count, should_continue):
        started = time.monotonic()
        attempts = []
        # A configured Ping count is a fixed sample count, not a "retry until
        # success" count: always perform every echo request so the UI can show
        # the full history and any packet loss. Any successful reply still makes
        # the aggregate result reachable.
        for attempt in range(1, count + 1):
            result = await self._io(lambda: self._ping(address), should_continue)
            attempts.append({"attempt": attempt, "status": result.get("status"),
                             "elapsedMs": result.get("elapsedMs", 0),
                             **({"roundTripMs": result["roundTripMs"]} if "roundTripMs" in result else {}),
                             **({"error": result["error"]} if "error" in result else {})})
        successes = [item for item in attempts if item.get("status") == "reachable"]
        last = attempts[-1]
        status = "reachable" if successes else last.get("status", "error")
        result = {"address": address, "status": status,
                  "attempts": len(attempts), "configuredAttempts": count,
                  "successCount": len(successes),
                  "attemptDetails": attempts,
                  "elapsedMs": round((time.monotonic() - started) * 1000)}
        if successes and "roundTripMs" in successes[0]:
            result["roundTripMs"] = successes[0]["roundTripMs"]
        if not successes and "error" in last:
            result["error"] = last["error"]
        return result

    async def _tcp_with_retries(self, address, port, count, should_continue):
        started = time.monotonic()
        attempts = []
        # Keep the complete TCP attempt history as well. Open is the strongest
        # positive outcome; refused is definitive when no attempt opened.
        for attempt in range(1, count + 1):
            result = await self._io(lambda: self._tcp(address, port), should_continue)
            attempts.append({"attempt": attempt, "status": result.get("status"),
                             "elapsedMs": result.get("elapsedMs", 0),
                             **({"error": result["error"]} if "error" in result else {})})
        statuses = [item.get("status") for item in attempts]
        status = ("open" if "open" in statuses else
                  "refused" if "refused" in statuses else attempts[-1].get("status", "error"))
        result = {"address": address, "port": port, "status": status,
                  "attempts": len(attempts), "configuredAttempts": count,
                  "successCount": statuses.count("open"),
                  "attemptDetails": attempts,
                  "elapsedMs": round((time.monotonic() - started) * 1000)}
        if status not in {"open", "refused"} and "error" in attempts[-1]:
            result["error"] = attempts[-1]["error"]
        return result

    async def probe(self, host, port, should_continue=None, excluded_hosts=(), excluded_cidrs=(),
                    dns_servers=DEFAULT_DNS_SERVERS, ping_count=DEFAULT_PING_COUNT,
                    tcp_attempts=DEFAULT_TCP_ATTEMPTS, timeout_ms=None, skip_cdn=DEFAULT_SKIP_CDN,
                    skip_private=True, skip_dns=True, skip_safety=True, cdn_cidrs=()):
        token = _PROBE_TIMEOUT_MS.set(timeout_ms if timeout_ms is not None else self.settings.timeout_ms)
        try:
            return await self._probe_impl(host, port, should_continue=should_continue,
                                          excluded_hosts=excluded_hosts, excluded_cidrs=excluded_cidrs,
                                          dns_servers=dns_servers, ping_count=ping_count,
                                          tcp_attempts=tcp_attempts, skip_cdn=skip_cdn,
                                          skip_private=skip_private, skip_dns=skip_dns,
                                          skip_safety=skip_safety, cdn_cidrs=cdn_cidrs)
        finally:
            _PROBE_TIMEOUT_MS.reset(token)

    async def _probe_impl(self, host, port, should_continue=None, excluded_hosts=(), excluded_cidrs=(),
                          dns_servers=DEFAULT_DNS_SERVERS, ping_count=DEFAULT_PING_COUNT,
                          tcp_attempts=DEFAULT_TCP_ATTEMPTS, skip_cdn=DEFAULT_SKIP_CDN,
                          skip_private=True, skip_dns=True, skip_safety=True, cdn_cidrs=()):
        try:
            literal_address = ipaddress.ip_address(host)
        except ValueError:
            literal_address = None
        is_domain = literal_address is None
        # The explicit nslookup evidence describes the same A/CNAME lookup used
        # to pin Ping/TCP destinations. Do not invoke a shell or resolve again.
        nslookup = {"question": host, "recordType": "A", "status": "pending" if is_domain else "not_applicable",
                    "answers": [], "aliases": [], "attempts": [], "resolver": None, "elapsedMs": 0}
        result = {"resolved": [], "aliases": [], "dns": {"status": "ok", "elapsedMs": 0},
                  "nslookup": nslookup, "ping": [], "tcp": []}
        request_networks = tuple(ipaddress.ip_network(value, strict=True) for value in excluded_cidrs)
        cdn_networks = tuple(ipaddress.ip_network(value, strict=True) for value in cdn_cidrs)
        if skip_dns and port in {53, 853}:
            skip = {"status": "skipped_dns", "reason": "dns_service_port", "rule": str(port), "source": "built_in_dns_policy"}
            if is_domain:
                nslookup.update(skip)
            return {**result, "dns": {"elapsedMs": 0, **skip}, "skipped": skip}
        domain_skip = self.policy.domain(host)
        # Built-in/custom CDN suffix rules are informational only. CDN skipping
        # is now driven exclusively by the request's cdnCidrs list; DNS-hostname
        # exclusions from policy.domain still apply.
        if skip_dns and domain_skip and domain_skip.get("status") == "skipped_dns":
            if is_domain:
                nslookup.update(domain_skip)
            return {**result, "dns": {"status": "skipped_dns", "elapsedMs": 0, **domain_skip},
                    "skipped": {"status": "skipped_dns", **domain_skip}}
        started = time.monotonic()
        try:
            if is_domain:
                if should_continue is not None and not should_continue():
                    raise AbandonedProbe()
                resolution = await self._resolve(host, should_continue=should_continue, dns_servers=dns_servers)
                addresses, aliases = resolution
                nslookup["attempts"] = getattr(resolution, "attempts", [{"server": "system", "status": "ok", "answers": addresses[:MAX_DNS_ADDRESSES], "elapsedMs": round((time.monotonic() - started) * 1000)}])
                nslookup["resolver"] = getattr(resolution, "resolver", "system")
                if getattr(resolution, "status", "ok") != "ok":
                    result["dns"] = {"status": resolution.status, "error": resolution.error, "elapsedMs": round((time.monotonic() - started) * 1000)}
                    nslookup.update(result["dns"])
                    return result
            else:
                addresses, aliases = [str(literal_address)], []
            result["resolved"], result["aliases"] = addresses, aliases
            result["dns"]["elapsedMs"] = round((time.monotonic() - started) * 1000)
            if is_domain:
                nslookup.update(status="ok", answers=addresses[:MAX_DNS_ADDRESSES], aliases=list(aliases),
                                elapsedMs=result["dns"]["elapsedMs"])
            alias_skip = next((skip for alias in aliases
                               for skip in (self.policy.domain(alias),)
                               if skip and skip.get("status") == "skipped_dns"), None) if skip_dns else None
            if alias_skip:
                return {**result, "dns": {**result["dns"], "status": "skipped_dns", **alias_skip},
                        "skipped": {"status": "skipped_dns", **alias_skip}}
            if len(addresses) > MAX_DNS_ADDRESSES:
                result["resolved"] = addresses[:MAX_DNS_ADDRESSES]
                result["dns"].update(status="error", error="dns_address_limit_exceeded")
                if is_domain:
                    nslookup.update(status="error", error="dns_address_limit_exceeded")
                return result
        except (asyncio.TimeoutError, dns.exception.Timeout):
            result["dns"] = {"status": "timeout", "elapsedMs": round((time.monotonic() - started) * 1000), "error": "dns_timeout"}
            if is_domain:
                nslookup.update(result["dns"])
                if not nslookup["attempts"]:
                    nslookup["attempts"] = [{"server": "system", **result["dns"], "answers": []}]
            return result
        except (OSError, dns.exception.DNSException, ValueError) as exc:
            _, error = dns_failure_details(exc)
            result["dns"] = {"status": "error", "elapsedMs": round((time.monotonic() - started) * 1000), "error": error}
            if is_domain:
                nslookup.update(result["dns"])
                if not nslookup["attempts"]:
                    nslookup["attempts"] = [{"server": "system", **result["dns"], "answers": []}]
            return result
        tcp_ports = (port,) if port is not None else DOMAIN_DEFAULT_PORTS if is_domain else ()
        for address in addresses:
            if should_continue is not None and not should_continue():
                raise AbandonedProbe()
            policy_skip = self.policy.address(address)
            policy_status = (policy_skip or {}).get("status")
            if ((policy_status == "skipped_cdn") or
                    (policy_status == "skipped_private" and not skip_private) or
                    (policy_status == "skipped_dns" and not skip_dns) or
                    (policy_status == "skipped_safety" and not skip_safety)):
                policy_skip = None
            custom_cdn_rule = None
            if skip_cdn and (policy_skip is None or policy_skip.get("status") == "skipped_cdn"):
                ip = ipaddress.ip_address(address)
                custom_cdn_rule = next((network for network in cdn_networks if ip in network), None)
            if custom_cdn_rule is not None:
                skipped = {"status": "skipped_cdn", "reason": "request.cdnCidrs",
                           "rule": str(custom_cdn_rule), "source": "request.cdnCidrs"}
            else:
                skipped = ({"status": "skipped_dns", "reason": "configured_dns_server",
                            "rule": address, "source": "request.dnsServers"}
                           if skip_dns and address in dns_servers else policy_skip)
            if skipped is None and address in excluded_hosts:
                skipped = {"status": "skipped_custom", "reason": "custom_exclusion",
                           "rule": address, "source": "request.excludedHosts"}
            if skipped is None:
                ip = ipaddress.ip_address(address)
                network = next((network for network in request_networks if ip in network), None)
                if network is not None:
                    skipped = {"status": "skipped_custom", "reason": "custom_exclusion",
                               "rule": str(network), "source": "request.excludedCidrs"}
            if skipped:
                result["ping"].append({"address": address, "elapsedMs": 0, **skipped})
                for tcp_port in tcp_ports:
                    result["tcp"].append({"address": address, "port": tcp_port, "elapsedMs": 0, **skipped})
                continue
            # Every actual operation receives the already-checked numeric address.
            # Ping/TCP attempts are individually rate-limited and counted.
            result["ping"].append(await self._ping_with_retries(address, ping_count, should_continue))
            for tcp_port in tcp_ports:
                result["tcp"].append(await self._tcp_with_retries(address, tcp_port, tcp_attempts, should_continue))
        return result


class BodyLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if scope.get("client") and scope["client"][0] not in {"127.0.0.1", "::1"}:
            return await JSONResponse({"detail": "loopback_only"}, status_code=403)(scope, receive, send)
        if scope["method"] not in {"POST", "PUT", "PATCH"}:
            return await self.app(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                return await JSONResponse({"detail": "request_too_large"}, status_code=413)(scope, receive, send)
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()
        await self.app(scope, replay, send)


def create_app(settings=None, policy=None, engine=None, logger=None, intelligence=None):
    settings = settings or load_settings()
    if policy is None:
        policy = NetworkPolicy(resolve_rules_path(settings.data_dir), settings.data_dir / "cdn_custom_rules.json", settings.excluded_cidrs)
        try:
            policy.add_system_dns(dns.resolver.Resolver().nameservers)
        except dns.exception.DNSException:
            pass
    logger = logger or create_logger(settings)
    engine = engine or ProbeEngine(settings, policy, logger)
    intelligence = intelligence or K01IntelligenceClient(settings.data_dir, settings.token, logger)

    @asynccontextmanager
    async def lifespan(app):
        await engine.start()
        try:
            yield
        finally:
            await intelligence.close()
            await engine.close()
            for handler in list(logger.handlers):
                handler.flush()
                handler.close()
                logger.removeHandler(handler)

    def authenticate(request: Request):
        authorization = request.headers.get("authorization")
        prefix = "Bearer "
        supplied = authorization[len(prefix):] if authorization and authorization.startswith(prefix) else ""
        if (len(request.headers.getlist("authorization")) != 1
                or not hmac.compare_digest(supplied.encode("utf-8"), settings.token.encode("utf-8"))):
            return JSONResponse({"detail": "invalid_token"}, status_code=401,
                                headers={"WWW-Authenticate": "Bearer"})
        return None

    async def health(request: Request):
        return JSONResponse({"status": "ok", "service": "soar-network-probe", "apiVersion": API_VERSION,
                "version": SERVICE_VERSION, "platform": "windows" if os.name == "nt" else "unsupported",
                "cdnRulesVersion": policy.version, "cdnRulesUpdatedAt": policy.updated_at,
                "cdnCidrs": len(policy.cidrs), "cdnDomainSuffixes": len(policy.domains),
                "publicOnly": True, "ipv4Only": True, "cdnExcluded": True,
                "safetyExclusions": True, "excludedCidrsSupported": True,
                "domainNslookup": True, "domainPing": True,
                "domainDnsFallback": True, "customDnsServers": True, "dnsServers": list(DEFAULT_DNS_SERVERS),
                "k01Intelligence": True, "k01PasswordChange": True,
                "probeSettings": True, "cdnSkipConfigurable": True, "cdnCidrsSupported": True,
                "cdnOnlyCidrs": True, "skipOptionsConfigurable": True, "defaultPingCount": DEFAULT_PING_COUNT,
                "defaultTcpAttempts": DEFAULT_TCP_ATTEMPTS,
                "defaultProbeTimeoutMs": DEFAULT_PROBE_TIMEOUT_MS,
                "domainDefaultPorts": list(DOMAIN_DEFAULT_PORTS),
                "dnsExcluded": True, "excludedDnsAddresses": len(policy.dns_addresses)})

    def reject_constant(value):
        raise ValueError("non-standard JSON constant")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result

    async def submit(request: Request):
        denied = authenticate(request)
        if denied is not None:
            return denied
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            return JSONResponse({"detail": "json_required"}, status_code=415)
        try:
            payload = json.loads(await request.body(), parse_constant=reject_constant,
                                 object_pairs_hook=unique_object)
            batch = ProbeBatch.model_validate(payload)
        except (ValueError, TypeError, RecursionError, UnicodeError):
            return JSONResponse({"detail": "invalid_probe_request"}, status_code=422)
        if os.name != "nt" and not getattr(engine, "allow_non_windows", False):
            return JSONResponse({"detail": "windows_required"}, status_code=503)
        try:
            job = engine.submit(batch)
        except CapacityError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=429, headers={"Retry-After": "2"})
        return JSONResponse({"jobId": job.id, "queryId": job.query_id, "total": job.total, "cursor": 0}, status_code=202)

    async def auth_check(request: Request):
        denied = authenticate(request)
        if denied is not None:
            return denied
        return JSONResponse({"status": "ok", "service": "soar-network-probe", "apiVersion": API_VERSION})

    async def results(request: Request):
        denied = authenticate(request)
        if denied is not None:
            return denied
        values = request.query_params.getlist("after")
        cursor = values[0] if values else "0"
        if len(values) > 1 or not re.fullmatch(r"[0-9]{1,5}", cursor) or int(cursor) > MAX_TARGETS:
            return JSONResponse({"detail": "invalid_cursor"}, status_code=422)
        try:
            return JSONResponse(engine.snapshot(request.path_params["job_id"], int(cursor)))
        except KeyError:
            return JSONResponse({"detail": "job_not_found"}, status_code=404)
        except ValueError:
            return JSONResponse({"detail": "cursor_ahead"}, status_code=400)

    async def cancel(request: Request):
        denied = authenticate(request)
        if denied is not None:
            return denied
        try:
            job = engine.cancel(request.path_params["job_id"])
            return JSONResponse({"jobId": job.id, "queryId": job.query_id, "status": job.status,
                                 "completed": len(job.results), "total": job.total})
        except KeyError:
            return JSONResponse({"detail": "job_not_found"}, status_code=404)

    def intelligence_error(error, trace_id=""):
        # The local log is the only forensic trail for an exe-side K01 failure: record the
        # stage, upstream status and diagnostic code next to the returned error code.
        if trace_id and not error.trace_id:
            error.trace_id = trace_id
        try:
            intelligence._log("k01-http-error", code=error.code, status=error.status,
                              reason=error.reason, stage=error.stage,
                              upstreamStatus=error.upstream_status,
                              diagnosticCode=error.diagnostic_code, diagnostic=error.diagnostic,
                              fallbackAllowed=error.fallback,
                              config=intelligence._config_forensics())
        except Exception:
            pass
        response = JSONResponse(error.payload(), status_code=error.status)
        if trace_id:
            response.headers["X-Trace-Id"] = trace_id
        return response

    def request_trace_id(request):
        """Per-request correlation id: client supplied or locally minted, always log safe."""
        return normalize_trace_id(request.headers.get("x-trace-id", "")) or new_trace_id()

    async def intelligence_payload(request):
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise K01Error("K01_JSON_REQUIRED", "请使用 JSON 请求。", 415)
        try:
            return json.loads(await request.body(), parse_constant=reject_constant,
                              object_pairs_hook=unique_object)
        except (ValueError, TypeError, RecursionError, UnicodeError):
            raise K01Error("K01_INVALID_REQUEST", "情报请求格式无效。", 422) from None

    async def intelligence_status(request: Request):
        denied = authenticate(request)
        if denied is not None:
            return denied
        return JSONResponse(intelligence.status())

    async def intelligence_config(request: Request):
        denied = authenticate(request)
        if denied is not None:
            return denied
        trace_id = request_trace_id(request)
        if request.method in {"GET", "HEAD"}:
            response = JSONResponse(intelligence.public_config())
            response.headers["X-Trace-Id"] = trace_id
            return response
        token = set_trace_id(trace_id)
        try:
            payload = await intelligence_payload(request)
            response = JSONResponse(intelligence.update_config(payload))
            response.headers["X-Trace-Id"] = trace_id
            return response
        except K01Error as error:
            return intelligence_error(error, trace_id)
        except (ValueError, TypeError, RecursionError):
            return intelligence_error(K01Error("K01_INVALID_CONFIG", "请检查 K01 地址、账号和连接设置。", 422), trace_id)
        except OSError:
            return intelligence_error(K01Error("K01_CONFIG_SAVE_FAILED", "本地 K01 配置保存失败。", 500), trace_id)
        finally:
            reset_trace_id(token)

    async def intelligence_trace(request: Request):
        denied = authenticate(request)
        if denied is not None:
            return denied
        trace_id = request_trace_id(request)
        token = set_trace_id(trace_id)
        try:
            payload = await intelligence_payload(request)
            response = JSONResponse(await intelligence.trace(payload))
            response.headers["X-Trace-Id"] = trace_id
            return response
        except K01Error as error:
            return intelligence_error(error, trace_id)
        except (ValueError, TypeError, RecursionError):
            return intelligence_error(K01Error("K01_INVALID_REQUEST", "请输入有效的 IPv4 地址或域名。", 422), trace_id)
        finally:
            reset_trace_id(token)

    async def intelligence_change_password(request: Request):
        denied = authenticate(request)
        if denied is not None:
            return denied
        trace_id = request_trace_id(request)
        token = set_trace_id(trace_id)
        try:
            payload = await intelligence_payload(request)
            response = JSONResponse(await intelligence.change_password(payload))
            response.headers["X-Trace-Id"] = trace_id
            return response
        except K01Error as error:
            return intelligence_error(error, trace_id)
        except (ValueError, TypeError, RecursionError):
            return intelligence_error(K01Error("K01_INVALID_REQUEST",
                                               "请输入 8–16 位且两次一致的新密码。", 422), trace_id)
        finally:
            reset_trace_id(token)

    async def http_error(request: Request, error: HTTPException):
        return JSONResponse({"detail": error.detail}, status_code=error.status_code, headers=error.headers)

    app = Starlette(lifespan=lifespan, exception_handlers={HTTPException: http_error}, routes=[
        Route("/health", health, methods=["GET"]),
        Route("/v1/auth-check", auth_check, methods=["GET"]),
        Route("/v1/probes", submit, methods=["POST"]),
        Route("/v1/probes/{job_id}", results, methods=["GET"]),
        Route("/v1/probes/{job_id}", cancel, methods=["DELETE"]),
        Route("/v1/intelligence/status", intelligence_status, methods=["GET"]),
        Route("/v1/intelligence/config", intelligence_config, methods=["GET", "POST", "PUT"]),
        Route("/v1/intelligence/change-password", intelligence_change_password, methods=["POST"]),
        Route("/v1/intelligence/trace", intelligence_trace, methods=["POST"]),
    ])
    app.state.engine = engine
    app.state.intelligence = intelligence
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]"])
    app.add_middleware(BodyLimitMiddleware)
    return app


def print_banner(stream=None):
    """Startup build stamp. Goes to stderr so stdout stays machine-readable (--self-test)."""
    print(f"SOARProbe v{SERVICE_VERSION} (API v{API_VERSION})",
          file=stream or sys.stderr, flush=True)


def set_console_title(text):
    """Also show the version in the console window title, which survives output scrolling."""
    if os.name != "nt":
        return
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleTitleW(text)
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="SOAR Windows localhost probe service")
    parser.add_argument("--init-config", action="store_true", help="create/validate persistent configuration and exit")
    parser.add_argument("--show-token", action="store_true", help="explicitly display pairing token; do not redirect to logs")
    parser.add_argument("--copy-token", action="store_true", help="copy pairing token to the Windows clipboard")
    parser.add_argument("--self-test", action="store_true", help="check bundled resources without starting probes or creating settings")
    parser.add_argument("--update-cdn-rules", action="store_true", help="download and validate a persistent CDN rules update, then exit")
    parser.add_argument("--no-interactive", action="store_true", help="disable console hotkeys and error pause for automation")
    parser.add_argument("--data-dir", type=Path, help="override configuration/log directory")
    parser.add_argument("--version", action="store_true", help="print the service version and exit")
    args = parser.parse_args()
    # Stamp the version before configuration is read so it is still visible when startup
    # fails later (invalid config, occupied port, application-control block).
    print_banner()
    if args.version:
        print(f"SOARProbe v{SERVICE_VERSION} (API v{API_VERSION})")
        return
    if args.self_test:
        print(json.dumps(run_self_test(), ensure_ascii=False))
        return
    settings = load_settings(args.data_dir)
    if args.show_token:
        print(settings.token)
        return
    if args.copy_token:
        copy_token_to_clipboard(settings.token)
        print("Pairing token copied to the clipboard.")
        return
    if args.init_config:
        print(f"Configuration ready: {settings.data_dir / 'config.json'}")
        return
    if args.update_cdn_rules:
        import update_cdn_rules
        from tempfile import NamedTemporaryFile
        dataset, sha = update_cdn_rules.download()
        converted = update_cdn_rules.convert(dataset, sha)
        temporary = None
        try:
            with NamedTemporaryFile(mode="w", encoding="utf-8", dir=settings.data_dir, suffix=".json", delete=False) as output:
                temporary = Path(output.name)
                json.dump(converted, output, ensure_ascii=False)
            NetworkPolicy(temporary)
            os.replace(temporary, settings.data_dir / "cdn_rules.json")
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        print(f"Updated CDN rules: {converted['version']}. Restart the service to load the update.")
        return
    if os.name != "nt":
        raise SystemExit("This probe service runs on Windows only. Offline tests can run on other platforms.")
    import uvicorn
    set_console_title(f"SOARProbe v{SERVICE_VERSION} · 127.0.0.1:{settings.port}")
    print(f"SOAR probe: http://127.0.0.1:{settings.port} (Ctrl+C to stop)")
    print(f"Config: {settings.data_dir / 'config.json'}")
    print("[C] Copy pairing token  [L] Open logs  [Q] Quit (or Ctrl+C)")
    print("Paste the token into the userscript's local probe settings. Tokens are not written to logs.")
    server = uvicorn.Server(uvicorn.Config(create_app(settings=settings), host="127.0.0.1", port=settings.port,
                workers=1, access_log=False, proxy_headers=False, log_level="warning",
                loop="asyncio", http="h11", ws="none", lifespan="on"))
    if not args.no_interactive:
        start_console_controls(server, settings)
    server.run()


def launch():
    try:
        main()
        return 0
    except (Exception, SystemExit) as error:
        if isinstance(error, SystemExit) and not error.code:
            return 0
        # Pause only for the standalone double-click experience. CLI and build
        # checks must terminate deterministically instead of waiting for input.
        print(f"SOARProbe v{SERVICE_VERSION} startup failed: {error}", file=sys.stderr)
        if (getattr(sys, "frozen", False) and len(sys.argv) == 1
                and os.environ.get("SOAR_PROBE_CMD_LAUNCH") != "1"
                and getattr(sys.stdin, "isatty", lambda: False)()):
            try:
                input("Press Enter to close this window...")
            except (EOFError, OSError):
                pass
        return 1


if __name__ == "__main__":
    raise SystemExit(launch())
