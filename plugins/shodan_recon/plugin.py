"""Shodan passive-recon plugin for NetAttackAi.

Advisory-only OSINT: queries the Shodan REST API (``https://api.shodan.io``)
for host banners, ports, services, and CVEs. NEVER touches the target -- the
plugin issues a single GET to Shodan's API, not to the target IP. The MCP
tool is wrapped with ``@ctx.audit_tool`` (free-text query, no ``target_ip``)
so the audit trail records every call; the target-IP allowlist lock is not
in play because Shodan is a third-party data source, not the target.

Two-gate enablement (defense-in-depth):
  1. ``plugins.enabled`` must list ``shodan_recon`` (plugin opt-in).
  2. ``recon.shodan_api_key`` in config.yaml must be a non-empty string.
The MCP tool refuses with a ``BLOCKED:`` marker when the key is unset, so
even if the plugin is enabled, the surface vanishes without the key.

Prompt-injection surface: Shodan banners are untrusted third-party text.
Mitigations: (1) return structured JSON; (2) ``_clean`` every string
(strip control chars + cap at 200 chars); (3) never auto-execute returned
strings; (4) the agent's system prompt carries the
``auditing-mcp-servers-for-tool-poisoning`` skill (default-enabled).

Pure stdlib (urllib) -- no new dependency. The Shodan Python SDK is not
used because the REST API is a single GET and urllib is already the
codebase's HTTP path (cve_lookup, exploit_search, threat_intel).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

from tools.opsec import process_user_agent
from tools.plugins import Plugin, PluginManifest, PluginRegistry

_MANIFEST_PATH = Path(__file__).resolve().parent / "plugin.yaml"
_SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
_SHODAN_SEARCH_URL = "https://api.shodan.io/shodan/host/search"
_MAX_STR = 200


def _clean(value: Any) -> Any:
    """Strip control chars + cap string length on Shodan banner data."""
    if isinstance(value, str):
        return "".join(c for c in value if c >= " ")[:_MAX_STR]
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {str(k)[:_MAX_STR]: _clean(v) for k, v in value.items()}
    return value


def _shodan_api_key(config: dict[str, Any] | None) -> str:
    recon = (config or {}).get("recon", {}) or {}
    return str(recon.get("shodan_api_key", "") or "").strip()


def _shodan_get(
    url: str,
    params: dict[str, str],
    timeout: int,
    *,
    fetch_fn: Callable[[str], Any] | None = None,
) -> Any:
    """GET a Shodan endpoint returning parsed JSON. ``fetch_fn(url)`` overrides
    the real urllib path so tests never touch the network."""
    full = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    if fetch_fn is not None:
        return fetch_fn(full)
    req = urllib.request.Request(
        full,
        headers={"User-Agent": process_user_agent("netattackai-shodan/1.0")},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def shodan_host(
    ip: str,
    api_key: str,
    *,
    timeout: int = 30,
    fetch_fn: Callable[[str], Any] | None = None,
) -> dict[str, Any]:
    """Look up a single host in Shodan. Returns a structured dict.

    The IP is sent to Shodan (third-party), NOT to the target -- this is
    passive OSINT. Returns ``{"error": ...}`` on failure; never raises.
    """
    if not api_key:
        return {"error": "shodan api key missing"}
    if not ip:
        return {"error": "empty ip"}
    try:
        url = _SHODAN_HOST_URL.format(ip=urllib.parse.quote(ip))
        payload = _shodan_get(url, {"key": api_key}, timeout, fetch_fn=fetch_fn)
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")[:200]
        except Exception:
            body = str(getattr(exc, "filename", ""))[:200]
        return {"error": f"shodan HTTP {exc.code}", "body": body}
    except Exception as exc:
        return {"error": f"shodan fetch failed: {exc}"}
    out = {
        "ip": payload.get("ip_str", ""),
        "ports": payload.get("ports", []),
        "hostnames": payload.get("hostnames", []),
        "org": payload.get("org", ""),
        "os": payload.get("os", ""),
        "vulns": list((payload.get("vulns") or []).keys())
        if isinstance(payload.get("vulns"), dict)
        else (payload.get("vulns") or []),
        "services": [
            {
                "port": s.get("port"),
                "transport": s.get("transport"),
                "product": s.get("product", ""),
                "version": s.get("version", ""),
                "cpe": s.get("cpe", []),
            }
            for s in (payload.get("data") or [])
        ],
    }
    return _clean(out)


def shodan_search(
    query: str,
    api_key: str,
    *,
    timeout: int = 30,
    max_results: int = 20,
    fetch_fn: Callable[[str], Any] | None = None,
) -> dict[str, Any]:
    """Search Shodan for a free-text query (e.g. ``"apache country:US"``).
    Returns ``{"matches": [...]}``. The query is sent to Shodan, NOT executed
    against any target."""
    if not api_key:
        return {"error": "shodan api key missing"}
    q = (query or "").strip()
    if not q:
        return {"error": "empty query"}
    if len(q) > 500:
        return {"error": "query too long"}
    try:
        payload = _shodan_get(
            _SHODAN_SEARCH_URL,
            {"key": api_key, "query": q, "limit": str(max_results)},
            timeout,
            fetch_fn=fetch_fn,
        )
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")[:200]
        except Exception:
            body = str(getattr(exc, "filename", ""))[:200]
        return {"error": f"shodan HTTP {exc.code}", "body": body}
    except Exception as exc:
        return {"error": f"shodan fetch failed: {exc}"}
    matches = []
    for m in (payload.get("matches") or [])[:max_results]:
        matches.append(
            {
                "ip": m.get("ip_str", ""),
                "port": m.get("port"),
                "product": m.get("product", ""),
                "version": m.get("version", ""),
                "hostnames": m.get("hostnames", []),
                "vulns": list(m.get("vulns", {}).keys())
                if isinstance(m.get("vulns"), dict)
                else (m.get("vulns") or []),
            }
        )
    return _clean({"matches": matches, "total": payload.get("total", 0)})


class ShodanReconPlugin(Plugin):
    """Plugin wrapper registering the Shodan MCP tools (default-off)."""

    manifest: PluginManifest

    def __init__(self) -> None:
        self.manifest = self._load_manifest()

    @staticmethod
    def _load_manifest() -> PluginManifest:
        text = _MANIFEST_PATH.read_text(encoding="utf-8")
        from tools.plugins import _parse_manifest_yaml  # type: ignore

        return PluginManifest.from_dict(_parse_manifest_yaml(text))

    def register(self, registry: PluginRegistry) -> None:
        # Register the config section so ConfigValidator doesn't warn about
        # a plugin-contributed key. The actual key lives under ``recon`` in
        # config.yaml (already a known top-level key), so this is belt-and-
        # suspenders -- it lets a future plugin-scoped key be added cleanly.
        registry.register_config_section(
            "shodan_recon",
            {
                "enabled": {"type": "bool", "default": False},
            },
        )
        registry.register_mcp_tools(_register_shodan_tools)


def _register_shodan_tools(mcp: Any, ctx: Any) -> None:
    audit_tool = ctx.audit_tool
    config = ctx.config

    @mcp.tool()
    @audit_tool
    def shodan_host_lookup(ip: str) -> str:
        """Look up a host in Shodan (passive OSINT). Returns JSON with ports, services, banners, and CVEs from Shodan's cache. Advisory-only -- never touches the target. Requires recon.shodan_api_key in config.yaml; returns BLOCKED when unset."""
        key = _shodan_api_key(config)
        if not key:
            return "BLOCKED: shodan api key not set in config.yaml (recon.shodan_api_key)."
        result = shodan_host(ip, key)
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    @audit_tool
    def shodan_search(query: str) -> str:
        """Search Shodan for a free-text query (e.g. 'apache country:US'). Returns JSON with matching hosts, ports, products, and CVEs. Advisory-only -- never touches the target. Requires recon.shodan_api_key in config.yaml; returns BLOCKED when unset."""
        key = _shodan_api_key(config)
        if not key:
            return "BLOCKED: shodan api key not set in config.yaml (recon.shodan_api_key)."
        result = shodan_search_tool(query, key)
        return json.dumps(result, indent=2, default=str)


def shodan_search_tool(query: str, key: str) -> dict[str, Any]:
    """Thin wrapper so the MCP tool's body stays a one-liner."""
    return shodan_search(query, key)


def create_plugin() -> Plugin:
    """Factory invoked by PluginManager when loading this plugin."""
    return ShodanReconPlugin()
