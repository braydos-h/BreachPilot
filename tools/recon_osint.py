"""Passive OSINT module for the NetAttackAi pentest agent (lab build).

All lookups are PASSIVE and READ-ONLY: they query PUBLIC data sources
(certificate transparency, reverse DNS, DNS AAAA, optional Shodan) about
the SINGLE authorized target only. No active scanning, no submission to
third parties, no destructive actions. IPv6 is PASSIVE ONLY (DNS AAAA
lookup for the target; no active IPv6 scanning).

Every network-touching function accepts an injectable ``resolver_fn`` /
``fetch_fn`` so tests can mock them without touching the network.

All functions are error-tolerant: they NEVER raise. On any failure they
return a graceful empty / error-shaped result.
"""

from __future__ import annotations

import json
import socket
import urllib.request

from tools.opsec import process_user_agent


def _default_ipv6_resolver(host: str) -> list[str]:
    """Default AAAA resolver using socket.getaddrinfo(AF_INET6)."""
    addrs: list[str] = []
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET6, socket.SOCK_STREAM)
    except Exception:
        return []
    seen: set[str] = set()
    for family, _stype, _proto, _canon, sockaddr in infos:
        if family != socket.AF_INET6:
            continue
        # sockaddr for AF_INET6 is (host, port, flowinfo, scopeid)
        try:
            ip = sockaddr[0]
        except Exception:
            continue
        if ip and ip not in seen:
            seen.add(ip)
            addrs.append(ip)
    return addrs


def passive_ipv6_lookup(host: str, *, resolver_fn=None) -> list[str]:
    """Return IPv6 (AAAA) addresses for host via socket.getaddrinfo(AF_INET6).

    ``resolver_fn(host) -> list[str]`` may be injected for testing.
    Returns ``[]`` on any error. PASSIVE ONLY — no active IPv6 scanning.
    """
    if not host:
        return []
    resolver = resolver_fn if resolver_fn is not None else _default_ipv6_resolver
    try:
        result = resolver(host)
    except Exception:
        return []
    if not isinstance(result, list):
        return []
    # sanitize: keep only non-empty strings
    out: list[str] = []
    for entry in result:
        if isinstance(entry, str) and entry:
            out.append(entry)
    return out


def _default_reverse_resolver(ip: str) -> str:
    """Default reverse-DNS resolver using socket.gethostbyaddr."""
    try:
        host, _aliases, _addrs = socket.gethostbyaddr(ip)
    except Exception:
        return ""
    return host or ""


def reverse_dns(ip: str, *, resolver_fn=None) -> str:
    """Reverse-DNS lookup of ip via socket.gethostbyaddr.

    ``resolver_fn(ip) -> str`` injectable. Returns ``""`` on error.
    """
    if not ip:
        return ""
    resolver = resolver_fn if resolver_fn is not None else _default_reverse_resolver
    try:
        result = resolver(ip)
    except Exception:
        return ""
    if isinstance(result, str):
        return result
    return ""


def _default_fetch(url: str) -> str:
    """Default HTTP GET via urllib returning text."""
    req = urllib.request.Request(url, headers={"User-Agent": process_user_agent("NetAttackAi-OSINT/1.0")})
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - passive OSINT
        data = resp.read()
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


def crtsh_cert_transparency(domain: str, *, fetch_fn=None) -> dict:
    """Query crt.sh certificate transparency for issued certs.

    Fetches ``https://crt.sh/?q=%25<domain>&output=json``.
    ``fetch_fn(url) -> str`` injectable (must return JSON text).
    Returns ``{"domain": domain, "certs": [...], "count": N}`` on success;
    ``{"domain": domain, "certs": [], "count": 0, "error": "<msg>"}`` on any
    error (never raises).
    """
    if not domain:
        return {"domain": domain or "", "certs": [], "count": 0, "error": "empty domain"}
    fetch = fetch_fn if fetch_fn is not None else _default_fetch
    url = "https://crt.sh/?q=%25" + domain + "&output=json"
    try:
        text = fetch(url)
    except Exception as exc:
        return {"domain": domain, "certs": [], "count": 0, "error": "fetch failed: %s" % exc}
    try:
        parsed = json.loads(text)
    except Exception as exc:
        return {"domain": domain, "certs": [], "count": 0, "error": "parse failed: %s" % exc}
    if not isinstance(parsed, list):
        return {"domain": domain, "certs": [], "count": 0, "error": "unexpected payload type"}
    return {"domain": domain, "certs": parsed, "count": len(parsed)}


def shodan_lookup(ip: str, api_key: str = "", *, fetch_fn=None) -> dict:
    """Optional Shodan host lookup (read-only).

    If ``api_key`` is empty, returns
    ``{"enabled": False, "note": "no Shodan API key configured"}``.
    ``fetch_fn(url) -> str`` injectable. Returns
    ``{"enabled": True, "ip": ip, "data": <parsed>}`` on success;
    ``{"enabled": True, "error": "<msg>"}`` on error (never raises).
    """
    if not api_key:
        return {"enabled": False, "note": "no Shodan API key configured"}
    if not ip:
        return {"enabled": True, "error": "empty ip"}
    fetch = fetch_fn if fetch_fn is not None else _default_fetch
    url = "https://api.shodan.io/shodan/host/%s?key=%s" % (ip, api_key)
    try:
        text = fetch(url)
    except Exception as exc:
        return {"enabled": True, "error": "fetch failed: %s" % exc}
    try:
        parsed = json.loads(text)
    except Exception as exc:
        return {"enabled": True, "error": "parse failed: %s" % exc}
    return {"enabled": True, "ip": ip, "data": parsed}


def run_osint(
    target_ip: str,
    *,
    hostname: str = "",
    shodan_api_key: str = "",
    resolver_fn=None,
    fetch_fn=None,
) -> dict:
    """Aggregate passive OSINT for the single target.

    Uses ``reverse_dns(target_ip)`` to derive a hostname if none given, then
    ``passive_ipv6_lookup(hostname_or_ip)``, ``crtsh_cert_transparency(hostname)``
    if a hostname is known, and ``shodan_lookup(target_ip, shodan_api_key)``
    if a key is given. Returns a dict with keys: ``target_ip``, ``hostname``,
    ``ipv6_addresses``, ``reverse_dns``, ``cert_transparency``, ``shodan``.

    All sub-calls are error-tolerant; never raises. Only passive/public
    lookups about the single target.
    """
    result = {
        "target_ip": target_ip,
        "hostname": hostname or "",
        "ipv6_addresses": [],
        "reverse_dns": "",
        "cert_transparency": {"domain": hostname or "", "certs": [], "count": 0, "error": "no hostname"},
        "shodan": {"enabled": False, "note": "no Shodan API key configured"},
    }

    # Reverse DNS to derive a hostname if none provided.
    rev = ""
    try:
        rev = reverse_dns(target_ip, resolver_fn=resolver_fn)
    except Exception:
        rev = ""
    result["reverse_dns"] = rev

    resolved_hostname = hostname or rev or ""
    result["hostname"] = resolved_hostname

    # Passive IPv6 (AAAA) lookup on the hostname or the IP itself.
    ipv6_host = resolved_hostname or target_ip
    try:
        result["ipv6_addresses"] = passive_ipv6_lookup(ipv6_host, resolver_fn=resolver_fn)
    except Exception:
        result["ipv6_addresses"] = []

    # Certificate transparency only meaningful for a hostname (domain).
    if resolved_hostname:
        try:
            result["cert_transparency"] = crtsh_cert_transparency(resolved_hostname, fetch_fn=fetch_fn)
        except Exception as exc:
            result["cert_transparency"] = {
                "domain": resolved_hostname,
                "certs": [],
                "count": 0,
                "error": "osint failed: %s" % exc,
            }

    # Optional Shodan lookup (read-only, gated on api_key).
    try:
        result["shodan"] = shodan_lookup(target_ip, shodan_api_key, fetch_fn=fetch_fn)
    except Exception as exc:
        result["shodan"] = {"enabled": bool(shodan_api_key), "error": "osint failed: %s" % exc}

    return result
