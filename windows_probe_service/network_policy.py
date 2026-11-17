"""Fail-closed public-address and bundled CDN matching policy."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path

SPECIAL_V4 = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24",
    "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"))
SPECIAL_V6 = tuple(ipaddress.ip_network(value) for value in (
    "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "2620:4f:8000::/48"))
GLOBAL_V6 = ipaddress.ip_network("2000::/3")
# These are the userscript's default safety-filter entries, rather than only
# RFC-private ranges. Keep the service-side protection on every installation,
# including upgrades whose persisted config has no explicit exclusions.
DEFAULT_SAFETY_CIDRS = tuple(ipaddress.ip_network(value) for value in (
    "210.39.0.0/20", "202.127.241.128/25", "172.0.0.0/8", "192.168.0.0/16",
    "116.13.96.0/20", "10.0.0.0/8", "127.0.0.1", "0.0.0.0",
    "116.76.255.38", "202.96.134.133", "114.114.114.114", "114.114.115.115",
    "202.96.128.86", "210.22.70.3", "211.137.191.26", "211.137.96.205"))
DNS_ADDRESSES = {
    "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
    "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",
    "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9",
    "223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200::2",
    "114.114.114.114", "114.114.115.115", "119.29.29.29", "2402:4e00::",
    "180.76.76.76", "119.28.28.28", "182.254.116.116", "1.2.4.8", "210.2.4.8",
    "101.226.4.6", "218.30.118.6", "123.125.81.6", "140.207.198.6",
    "180.184.1.1", "180.184.2.2", "208.67.222.222", "208.67.220.220",
    "2620:119:35::35", "2620:119:53::53",
    "208.67.222.123", "208.67.220.123", "94.140.14.14", "94.140.15.15",
    "94.140.14.15", "94.140.15.16", "117.50.11.11", "52.80.66.66",
    "117.50.22.22", "52.80.52.52", "185.228.168.9", "185.228.169.9",
    "185.228.168.168", "185.228.169.168", "185.228.168.10", "185.228.169.11",
    "76.76.2.0", "76.76.10.0", "76.76.19.19", "76.223.122.150",
}
DNS_DOMAINS = {"dns.google", "cloudflare-dns.com", "dns.quad9.net", "dns.alidns.com", "doh.pub", "dot.pub"}


def public_address_reason(address: str):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "invalid_address"
    if getattr(ip, "ipv4_mapped", None) is not None:
        return "ipv4_mapped_ipv6"
    # Exclude transition mechanisms too: a global IPv6 outer address can carry
    # a private IPv4 target. Never let a string representation bypass policy.
    if ip.version == 6 and (ip.sixtofour is not None or ip.teredo is not None):
        return "ipv6_transition_address"
    if (not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_loopback
            or ip.is_link_local or ip.is_unspecified):
        return "non_public_address"
    if ip.version == 4 and any(ip in network for network in SPECIAL_V4):
        return "special_purpose_address"
    if ip.version == 6 and (ip not in GLOBAL_V6 or any(ip in network for network in SPECIAL_V6)):
        return "special_purpose_address"
    return None


class NetworkPolicy:
    def __init__(self, path: Path, custom_path=None, excluded_cidrs=None):
        self.path = Path(path)
        self.custom_path = Path(custom_path) if custom_path else None
        self.cidrs = []
        self.domains = []
        self.buckets = {}
        self.version = "unknown"
        self.updated_at = "unknown"
        self.dns_addresses = {value: "built_in_dns_policy" for value in DNS_ADDRESSES}
        self.excluded_cidrs = [ipaddress.ip_network(value, strict=True) for value in (excluded_cidrs or [])]
        self.load()

    def load(self):
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("cidrs"), list) or not isinstance(data.get("domainSuffixes"), list):
            raise ValueError("cdn_rules.json schema invalid; probes disabled")
        custom = {"cidrs": [], "domainSuffixes": []}
        if self.custom_path and self.custom_path.exists():
            custom = json.loads(self.custom_path.read_text(encoding="utf-8"))
            if not isinstance(custom, dict) or not isinstance(custom.get("cidrs"), list) or not isinstance(custom.get("domainSuffixes"), list):
                raise ValueError("cdn_custom_rules.json invalid; probes disabled")
        cidrs, domains, buckets = [], [], {}
        for item in [*data["cidrs"], *custom["cidrs"]]:
            if not isinstance(item, dict):
                raise ValueError("CDN CIDR must contain source metadata")
            network = ipaddress.ip_network(item["cidr"], strict=True)
            cidrs.append((network, dict(item)))
            buckets.setdefault(network.version, {}).setdefault(network.prefixlen, {})[int(network.network_address)] = (network, dict(item))
        for item in [*data["domainSuffixes"], *custom["domainSuffixes"]]:
            suffix = str(item["suffix"]).lower().strip(".")
            if not suffix or "*" in suffix or "/" in suffix:
                raise ValueError("CDN domain suffix invalid")
            domains.append((suffix.encode("idna").decode("ascii"), dict(item)))
        self.cidrs, self.domains = cidrs, domains
        self.buckets = buckets
        self.version = str(data.get("version", "unknown"))
        self.updated_at = str(data.get("updatedAt", "unknown"))

    def domain(self, hostname: str):
        hostname = hostname.lower().rstrip(".")
        for suffix in DNS_DOMAINS:
            if hostname == suffix or hostname.endswith("." + suffix):
                return {"status": "skipped_dns", "reason": "known_dns_hostname", "rule": suffix,
                        "source": "built_in_dns_policy"}
        for suffix, item in self.domains:
            if hostname == suffix or hostname.endswith("." + suffix):
                return {"reason": "cdn_domain", "rule": suffix,
                        "source": item.get("source", "bundled"),
                        "provider": item.get("provider", "CDN")}
        return None

    def address(self, address: str):
        try:
            if ipaddress.ip_address(address).version != 4:
                return {"status": "skipped_ipv6", "reason": "ipv4_only", "rule": "ipv4_only", "source": "built_in_policy"}
        except ValueError:
            pass
        reason = public_address_reason(address)
        if reason:
            return {"status": "skipped_private", "reason": reason,
                    "rule": "public_addresses_only", "source": "ipaddress"}
        ip = ipaddress.ip_address(address)
        if str(ip) in self.dns_addresses:
            return {"status": "skipped_dns", "reason": "known_public_dns_resolver",
                    "rule": str(ip), "source": self.dns_addresses[str(ip)]}
        for network in DEFAULT_SAFETY_CIDRS:
            if ip in network:
                return {"status": "skipped_safety", "reason": "default_safety_exclusion",
                        "rule": str(network), "source": "built_in_safety_policy"}
        for network in self.excluded_cidrs:
            if ip.version == network.version and ip in network:
                return {"status": "skipped_custom", "reason": "custom_exclusion",
                        "rule": str(network), "source": "config.excludedCidrs"}
        bits = ip.max_prefixlen
        number = int(ip)
        for prefix, networks in sorted(self.buckets.get(ip.version, {}).items(), reverse=True):
            masked = number >> (bits - prefix) << (bits - prefix)
            match = networks.get(masked)
            if match:
                network, item = match
                return {"status": "skipped_cdn", "reason": "cdn_cidr",
                        "rule": str(network), "source": item.get("source", "bundled"),
                        "provider": item.get("provider", "CDN")}
        return None

    def add_system_dns(self, addresses):
        for address in addresses:
            try:
                self.dns_addresses[str(ipaddress.ip_address(str(getattr(address, "address", address))))] = "system_dns_configuration"
            except ValueError:
                continue
