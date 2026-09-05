"""Cloudflare real-IP trust boundary helpers."""

from __future__ import annotations

import ipaddress
import json
import urllib.request


DEFAULT_CLOUDFLARE_NETWORKS = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)

OFFICIAL_IP_URLS = (
    "https://www.cloudflare.com/ips-v4",
    "https://www.cloudflare.com/ips-v6",
)


def _values(value):
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple, set)):
        return value
    return ()


def _networks(values):
    result = []
    for value in _values(values):
        try:
            result.append(ipaddress.ip_network(str(value).strip(), strict=False))
        except ValueError:
            continue
    return result


def canonical_networks(values):
    """Return valid network strings in stable input order without duplicates."""

    result = []
    seen = set()
    for network in _networks(values):
        value = str(network)
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def merge_networks(official_networks=None, manual_networks=None):
    """Build the effective Cloudflare trust list, preserving both sources."""

    return canonical_networks(list(official_networks or []) + list(manual_networks or []))


def normalize_cloudflare_config(value):
    """Migrate legacy Cloudflare state and return a complete safe shape."""

    current = value if isinstance(value, dict) else {}
    split_config = "official_networks" in current or "manual_networks" in current
    if split_config:
        official = current.get("official_networks")
        if official is None:
            official = list(DEFAULT_CLOUDFLARE_NETWORKS)
        manual = current.get("manual_networks")
        if manual is None:
            manual = []
    else:
        # The old schema stored one combined list.  Treat it as manual state
        # so a later official-list refresh cannot silently discard it.
        official = list(DEFAULT_CLOUDFLARE_NETWORKS)
        manual = current.get("networks", [])
    official = canonical_networks(official)
    manual = canonical_networks(manual)

    enabled = current.get("enabled", False)
    if isinstance(enabled, str):
        enabled = enabled.strip().lower() in {"1", "true", "on", "yes"}
    else:
        enabled = bool(enabled)
    return {
        "enabled": enabled,
        "official_networks": official,
        "manual_networks": manual,
        "networks": merge_networks(official, manual),
        "updated_at": current.get("updated_at", 0),
    }


def is_trusted_proxy(remote_addr, networks) -> bool:
    try:
        address = ipaddress.ip_address(str(remote_addr).strip())
    except ValueError:
        return False
    return any(address in network for network in _networks(networks))


def resolve_real_ip(remote_addr, headers, networks=None, enabled=False) -> str:
    remote = str(remote_addr or "").strip()
    headers = headers if isinstance(headers, dict) else {}
    if not enabled or not is_trusted_proxy(remote, networks or DEFAULT_CLOUDFLARE_NETWORKS):
        return remote
    candidate = headers.get("CF-Connecting-IP") or headers.get("cf-connecting-ip")
    try:
        return str(ipaddress.ip_address(str(candidate).strip()))
    except ValueError:
        return remote


def lookup_network_membership(address, official_networks=None, manual_networks=None):
    """Check one IP against effective Cloudflare networks and their sources."""

    value = str(address or "").strip()
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("请输入有效的 IPv4 或 IPv6 地址") from exc

    source_networks = (
        ("official", DEFAULT_CLOUDFLARE_NETWORKS if official_networks is None else official_networks),
        ("manual", [] if manual_networks is None else manual_networks),
    )
    matches = {}
    for source, values in source_networks:
        for network in _networks(values):
            canonical = str(network)
            if ip not in network:
                continue
            entry = matches.setdefault(canonical, {"network": canonical, "sources": []})
            if source not in entry["sources"]:
                entry["sources"].append(source)
    return {
        "ip": str(ip),
        "matched": bool(matches),
        "matches": list(matches.values()),
    }


def fetch_official_networks(timeout=5):
    """Fetch only the two official Cloudflare IP-list endpoints."""

    values = []
    for url in OFFICIAL_IP_URLS:
        request = urllib.request.Request(url, headers={"User-Agent": "Nginx-Guard/1.0"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(64 * 1024)
            values.extend(line.strip() for line in body.decode("utf-8").splitlines() if line.strip())
    valid = canonical_networks(values)
    if not valid:
        raise ValueError("Cloudflare returned no valid networks")
    return valid


def networks_json(networks):
    return json.dumps(list(networks), ensure_ascii=False, separators=(",", ":"))
