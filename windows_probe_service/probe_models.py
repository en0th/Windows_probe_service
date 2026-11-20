"""Strict API request models with only Python standard-library dependencies.

Keep validation separate from the HTTP adapter so importing the probe service
does not need Pydantic's native extension. These models preserve the v1 JSON
contract; network eligibility remains the responsibility of NetworkPolicy.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re


MAX_TARGETS = 4000
MAX_DNS_SERVERS = 8
DEFAULT_DNS_SERVERS = ("8.8.8.8", "223.5.5.5", "223.6.6.6", "180.76.76.76")
DEFAULT_PING_COUNT = 5
DEFAULT_TCP_ATTEMPTS = 3
DEFAULT_PROBE_TIMEOUT_MS = 3000
DEFAULT_SKIP_CDN = True
MAX_PING_COUNT = 10
MAX_TCP_ATTEMPTS = 10
MIN_PROBE_TIMEOUT_MS = 200
MAX_PROBE_TIMEOUT_MS = 10000
# Explicit ranges keep validation stable across Python ipaddress database updates.
# RFC1918 and shared enterprise networks remain valid resolver destinations.
DNS_SERVER_DENIED_CIDRS = (
    "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24",
    "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)
_DNS_SERVER_DENIED = tuple(ipaddress.ip_network(value) for value in DNS_SERVER_DENIED_CIDRS)


class ValidationError(ValueError):
    """A request validation failure whose public details contain no input data."""

    def __init__(self, message: str, *, loc=(), error_type="value_error"):
        super().__init__(message)
        self.loc = tuple(loc)
        self.error_type = error_type

    def errors(self) -> list[dict]:
        return [{"type": self.error_type, "loc": self.loc, "msg": str(self)}]

    def with_prefix(self, *prefix) -> ValidationError:
        return ValidationError(str(self), loc=(*prefix, *self.loc), error_type=self.error_type)


def normalize_host(value: str) -> str:
    """Normalize canonical IPs and full DNS names, rejecting command-like input."""
    if not isinstance(value, str):
        raise ValueError("host must be an IP address or DNS hostname")
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if not value or len(value) > 253 or any(c in value for c in "/\\@%?#\r\n\t "):
        raise ValueError("host must be an IP address or DNS hostname")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        value = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("invalid hostname") from exc
    if len(value) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")):
        raise ValueError("invalid hostname")
    if "." not in value or re.fullmatch(r"[0-9.]+", value) or value.startswith("0x"):
        raise ValueError("use a full DNS hostname or canonical IP address")
    return value


def _check_fields(data: dict, allowed: set[str], required: tuple[str, ...]):
    for key in data:
        if key not in allowed:
            raise ValidationError("Extra inputs are not permitted", loc=(key,), error_type="extra_forbidden")
    for key in required:
        if key not in data:
            raise ValidationError("Field required", loc=(key,), error_type="missing")


def _string(value, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValidationError("Input should be a valid string", loc=(field,), error_type="string_type")
    if not 1 <= len(value) <= maximum:
        raise ValidationError(f"String must contain between 1 and {maximum} characters", loc=(field,), error_type="string_length")
    return value


def _strict_bool(value, field: str) -> bool:
    if type(value) is not bool:
        raise ValidationError("Input should be a valid boolean", loc=(field,), error_type="bool_type")
    return value


def _bounded_int(value, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValidationError(f"Integer must be between {minimum} and {maximum}", loc=(field,), error_type="int_range")
    return value


def _list(value, field: str, maximum: int, minimum: int = 0) -> list:
    if not isinstance(value, list):
        raise ValidationError("Input should be a valid list", loc=(field,), error_type="list_type")
    if not minimum <= len(value) <= maximum:
        raise ValidationError(f"List must contain between {minimum} and {maximum} items", loc=(field,), error_type="list_length")
    return value


def _exclusions(values, field: str, maximum: int, *, cidrs: bool) -> list[str]:
    values = _list(values, field, maximum)
    normalized, seen = [], set()
    for index, value in enumerate(values):
        if not isinstance(value, str):
            raise ValidationError("Input should be a valid string", loc=(field, index), error_type="string_type")
        message = (f"{field} must contain canonical IPv4 addresses or CIDRs" if cidrs
                   else f"{field} must contain IPv4 addresses")
        try:
            address = ipaddress.ip_network(value.strip(), strict=True) if cidrs else ipaddress.ip_address(value.strip())
        except ValueError as exc:
            raise ValidationError(message, loc=(field, index)) from exc
        if address.version != 4:
            raise ValidationError(message, loc=(field, index))
        canonical = str(address)
        if canonical not in seen:
            normalized.append(canonical)
            seen.add(canonical)
    return normalized


def normalize_dns_servers(values) -> list[str]:
    values = _list(values, "dnsServers", MAX_DNS_SERVERS)
    normalized, seen = [], set()
    for index, value in enumerate(values):
        if not isinstance(value, str):
            raise ValidationError("DNS server must be a canonical IPv4 string", loc=("dnsServers", index))
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError as exc:
            raise ValidationError("DNS server must be a canonical IPv4 string", loc=("dnsServers", index)) from exc
        if address.version != 4 or any(address in network for network in _DNS_SERVER_DENIED):
            raise ValidationError("DNS server must be a usable unicast IPv4 address", loc=("dnsServers", index))
        canonical = str(address)
        if canonical not in seen:
            normalized.append(canonical)
            seen.add(canonical)
    return normalized


@dataclass(frozen=True, init=False)
class ProbeTarget:
    id: str
    host: str
    port: int | None

    def __init__(self, **data):
        _check_fields(data, {"id", "host", "port"}, ("id", "host"))
        target_id = _string(data["id"], "id", 160)
        host = _string(data["host"], "host", 253)
        try:
            host = normalize_host(host)
        except ValueError as exc:
            raise ValidationError(str(exc), loc=("host",)) from exc
        port = data.get("port")
        if port is not None and (type(port) is not int or not 1 <= port <= 65535):
            raise ValidationError("Port must be an integer between 1 and 65535", loc=("port",), error_type="int_range")
        object.__setattr__(self, "id", target_id)
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "port", port)

    @classmethod
    def model_validate(cls, value) -> ProbeTarget:
        if isinstance(value, cls):
            value = value.model_dump()
        if not isinstance(value, dict):
            raise ValidationError("Input should be a valid object", error_type="model_type")
        _check_fields(value, {"id", "host", "port"}, ("id", "host"))
        return cls(**value)

    def model_dump(self) -> dict:
        return {"id": self.id, "host": self.host, "port": self.port}


@dataclass(frozen=True, init=False)
class ProbeBatch:
    queryId: str
    targets: list[ProbeTarget]
    excludedHosts: list[str]
    excludedCidrs: list[str]
    dnsServers: list[str]
    cdnCidrs: list[str]
    pingCount: int
    tcpAttempts: int
    timeoutMs: int
    skipCdn: bool
    skipPrivate: bool
    skipDns: bool
    skipSafety: bool

    def __init__(self, **data):
        _check_fields(data, {"queryId", "targets", "excludedHosts", "excludedCidrs", "dnsServers",
                             "cdnCidrs", "pingCount", "tcpAttempts", "timeoutMs", "skipCdn",
                             "skipPrivate", "skipDns", "skipSafety"},
                      ("queryId", "targets"))
        query_id = _string(data["queryId"], "queryId", 160)
        raw_targets = _list(data["targets"], "targets", MAX_TARGETS, minimum=1)
        targets, ids = [], set()
        for index, value in enumerate(raw_targets):
            try:
                target = ProbeTarget.model_validate(value)
            except ValidationError as exc:
                raise exc.with_prefix("targets", index) from exc
            if target.id in ids:
                raise ValidationError("target ids must be unique within a job", loc=("targets", index, "id"))
            ids.add(target.id)
            targets.append(target)
        excluded_hosts = _exclusions(data.get("excludedHosts", []), "excludedHosts", 200, cidrs=False)
        excluded_cidrs = _exclusions(data.get("excludedCidrs", []), "excludedCidrs", 2048, cidrs=True)
        dns_servers = normalize_dns_servers(data.get("dnsServers", list(DEFAULT_DNS_SERVERS)))
        cdn_cidrs = _exclusions(data.get("cdnCidrs", []), "cdnCidrs", 2048, cidrs=True)
        ping_count = _bounded_int(data.get("pingCount", DEFAULT_PING_COUNT),
                                  "pingCount", 1, MAX_PING_COUNT)
        tcp_attempts = _bounded_int(data.get("tcpAttempts", DEFAULT_TCP_ATTEMPTS),
                                    "tcpAttempts", 1, MAX_TCP_ATTEMPTS)
        timeout_ms = _bounded_int(data.get("timeoutMs", DEFAULT_PROBE_TIMEOUT_MS),
                                  "timeoutMs", MIN_PROBE_TIMEOUT_MS, MAX_PROBE_TIMEOUT_MS)
        skip_cdn = _strict_bool(data.get("skipCdn", True), "skipCdn")
        skip_private = _strict_bool(data.get("skipPrivate", True), "skipPrivate")
        skip_dns = _strict_bool(data.get("skipDns", True), "skipDns")
        skip_safety = _strict_bool(data.get("skipSafety", True), "skipSafety")
        object.__setattr__(self, "queryId", query_id)
        object.__setattr__(self, "targets", targets)
        object.__setattr__(self, "excludedHosts", excluded_hosts)
        object.__setattr__(self, "excludedCidrs", excluded_cidrs)
        object.__setattr__(self, "dnsServers", dns_servers)
        object.__setattr__(self, "cdnCidrs", cdn_cidrs)
        object.__setattr__(self, "pingCount", ping_count)
        object.__setattr__(self, "tcpAttempts", tcp_attempts)
        object.__setattr__(self, "timeoutMs", timeout_ms)
        object.__setattr__(self, "skipCdn", skip_cdn)
        object.__setattr__(self, "skipPrivate", skip_private)
        object.__setattr__(self, "skipDns", skip_dns)
        object.__setattr__(self, "skipSafety", skip_safety)

    @classmethod
    def model_validate(cls, value) -> ProbeBatch:
        if isinstance(value, cls):
            value = value.model_dump()
        if not isinstance(value, dict):
            raise ValidationError("Input should be a valid object", error_type="model_type")
        _check_fields(value, {"queryId", "targets", "excludedHosts", "excludedCidrs", "dnsServers",
                              "cdnCidrs", "pingCount", "tcpAttempts", "timeoutMs", "skipCdn",
                              "skipPrivate", "skipDns", "skipSafety"},
                      ("queryId", "targets"))
        return cls(**value)

    def model_dump(self) -> dict:
        return {"queryId": self.queryId, "targets": [target.model_dump() for target in self.targets],
                "excludedHosts": list(self.excludedHosts), "excludedCidrs": list(self.excludedCidrs),
                "dnsServers": list(self.dnsServers), "cdnCidrs": list(self.cdnCidrs),
                "pingCount": self.pingCount, "tcpAttempts": self.tcpAttempts,
                "timeoutMs": self.timeoutMs, "skipCdn": self.skipCdn,
                "skipPrivate": self.skipPrivate, "skipDns": self.skipDns,
                "skipSafety": self.skipSafety}
