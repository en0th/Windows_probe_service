"""Refresh the bundled ProjectDiscovery CDN/WAF dataset without probing targets."""
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

API = "https://api.github.com/repos/projectdiscovery/cdncheck"
MAX_BYTES = 20 * 1024 * 1024


def read_json(url: str):
    if not url.startswith(API + "/"):
        raise ValueError("Unexpected upstream URL")
    request = Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "SOARProbe-CDN-Updater/1"})
    with urlopen(request, timeout=30) as response:
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Upstream dataset exceeds size limit")
    return json.loads(raw)


def download():
    metadata = read_json(API + "/contents/sources_data.json")
    sha = metadata["sha"]
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
        raise ValueError("Invalid upstream blob identity")
    blob = metadata if metadata.get("content") else read_json(API + "/git/blobs/" + sha)
    if blob.get("encoding") != "base64":
        raise ValueError("Unexpected upstream encoding")
    raw = base64.b64decode(blob["content"])
    actual = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if len(raw) > MAX_BYTES or actual != sha:
        raise ValueError("Upstream blob checksum mismatch")
    return json.loads(raw), sha


def convert(dataset, sha: str):
    cidrs, domains, seen = [], [], set()
    source = "https://github.com/projectdiscovery/cdncheck/blob/main/sources_data.json"
    # General cloud-provider ranges are deliberately outside the CDN policy.
    for category in ("cdn", "waf"):
        providers = dataset.get(category)
        if not isinstance(providers, dict):
            raise ValueError("Missing CDN/WAF source category")
        for provider, values in providers.items():
            if not isinstance(values, list):
                raise ValueError("Invalid provider ranges")
            for value in values:
                cidr = str(ipaddress.ip_network(value, strict=False))
                key = (provider, cidr)
                if key not in seen:
                    cidrs.append({"cidr": cidr, "provider": provider, "source": source})
                    seen.add(key)
    common = dataset.get("common")
    if not isinstance(common, dict):
        raise ValueError("Missing CDN domain suffixes")
    for provider, values in common.items():
        if not isinstance(values, list):
            raise ValueError("Invalid provider suffixes")
        for value in values:
            suffix = str(value).lower().strip(".").encode("idna").decode("ascii")
            if not suffix or any(c in suffix for c in "/*: "):
                raise ValueError("Invalid CDN domain suffix")
            domains.append({"suffix": suffix, "provider": provider, "source": source})
    if not cidrs or not domains or len(cidrs) > 100000 or len(domains) > 10000:
        raise ValueError("Unexpected CDN dataset size")
    return {"version": "cdncheck-" + sha[:12], "updatedAt": datetime.now(timezone.utc).isoformat(),
            "sources": [source], "upstreamBlobSha": sha, "cidrs": cidrs, "domainSuffixes": domains}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="Import an offline upstream sources_data.json")
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("cdn_rules.json"))
    args = parser.parse_args()
    if args.input:
        raw = args.input.read_bytes()
        if len(raw) > MAX_BYTES:
            raise ValueError("Input exceeds size limit")
        dataset = json.loads(raw)
        sha = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    else:
        dataset, sha = download()
    converted = convert(dataset, sha)
    temporary = args.output.with_name(args.output.name + ".new")
    try:
        temporary.write_text(json.dumps(converted, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
        os.replace(temporary, args.output)
    finally:
        temporary.unlink(missing_ok=True)
    print(f"Updated {converted['version']}: {len(converted['cidrs'])} CIDRs, {len(converted['domainSuffixes'])} domain suffixes. Restart the service to load it.")


if __name__ == "__main__":
    main()
