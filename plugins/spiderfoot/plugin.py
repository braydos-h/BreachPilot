"""SpiderFoot OSINT integration plugin for NetAttackAi.

Wraps the SpiderFoot REST API for passive OSINT (DNS, whois, certs, leaks) in
one tool. All tools are passive — no target touch — so they use
``@audit_tool`` for the audit trail only (not ``@require_allowlist()``).

SAFETY (lab build):
* Plugin is OFF by default; opt in via ``config plugins.enabled``.
* Every MCP tool uses ``@audit_tool`` (audit trail only). No target touch.
* The SpiderFoot daemon runs on the operator's box; the operator MUST start
  SpiderFoot with its REST API enabled before invoking this plugin.
* No log clearing, timestomping, EDR/AV defeat, DoS, or malware distribution.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from tools.plugins import Plugin, PluginManifest, PluginRegistry

log = logging.getLogger("plugins.spiderfoot")

_MANIFEST_PATH = Path(__file__).resolve().parent / "plugin.yaml"


def _sf_cfg(config: dict[str, Any] | None) -> dict[str, Any]:
    cfg_block = (config or {}).get("spiderfoot") or {}
    return cfg_block if isinstance(cfg_block, dict) else {}


def _sf_base(config: dict[str, Any] | None) -> str:
    return str(_sf_cfg(config).get("api_url", "http://127.0.0.1:5001")).rstrip("/")


def _sf_api_key(config: dict[str, Any] | None) -> str:
    env_name = str(_sf_cfg(config).get("api_key_env", "SPIDERFOOT_API_KEY"))
    return os.environ.get(env_name, "")


def _sf_request(
    config: dict[str, Any] | None,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    timeout: int = 60,
) -> tuple[int, str]:
    """HTTP call against the SpiderFoot REST API. Returns (status, body)."""
    base = _sf_base(config)
    url = base + path
    headers = {"Accept": "application/json"}
    api_key = _sf_api_key(config)
    if api_key:
        headers["X-SpiderFoot-API-Key"] = api_key
        # Some SpiderFoot versions use a query param instead of a header.
        url += ("?" if "?" not in url else "&") + f"api_key={urllib.parse.quote(api_key)}"
    data = json.dumps(body).encode() if body is not None else None
    if data is not None:
        headers["Content-Type"] = "application/json"
    try:
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        return 0, f"SpiderFoot request failed: {exc}"


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class SpiderFootPlugin(Plugin):
    """Plugin wrapper that registers the SpiderFoot OSINT MCP tools."""

    manifest: PluginManifest

    def __init__(self) -> None:
        self.manifest = self._load_manifest()

    @staticmethod
    def _load_manifest() -> PluginManifest:
        text = _MANIFEST_PATH.read_text(encoding="utf-8")
        from tools.plugins import _parse_manifest_yaml  # type: ignore

        return PluginManifest.from_dict(_parse_manifest_yaml(text))

    def register(self, registry: PluginRegistry) -> None:
        registry.register_mcp_tools(_register_spiderfoot_tools)


def _register_spiderfoot_tools(mcp: Any, ctx: Any) -> None:
    """Register SpiderFoot MCP tools. All tools use @audit_tool (passive, no
    target touch)."""
    audit_tool = ctx.audit_tool
    config = ctx.config

    @mcp.tool()
    @audit_tool
    def spiderfoot_scan(target: str, modules: str = "") -> str:
        """Start a passive SpiderFoot scan against a target (domain or IP).

        PASSIVE ONLY: queries PUBLIC data sources (DNS, whois, certs, leaks).
        No active scanning, no third-party submissions. The SpiderFoot REST
        API must already be running on the operator's box.
        """
        if not target or not target.strip():
            return "BLOCKED: target is required."
        cfg = _sf_cfg(config)
        if not cfg.get("enabled", False):
            return "BLOCKED: spiderfoot plugin not enabled in config."

        body: dict[str, Any] = {"scan_target": target.strip()}
        if modules and modules.strip():
            body["modules"] = modules.strip()
        status, body_text = _sf_request(
            config,
            "POST",
            "/api/v1/scan",
            body=body,
            timeout=int(cfg.get("timeout_seconds", 60)),
        )
        if status == 0:
            return f"SPIDERFOOT_SCAN_ERROR: {body_text}"
        if status != 200:
            return f"SPIDERFOOT_SCAN_ERROR: http_{status}\n{body_text}"
        try:
            scan_id = json.loads(body_text).get("scan_id", "")
        except Exception:  # noqa: BLE001
            scan_id = ""
        return (
            f"SPIDERFOOT_SCAN_RESULT: started\n"
            f"SCAN_ID: {scan_id}\n"
            f"TARGET: {target}\n"
            f"RESPONSE: {body_text[:2000]}"
        )

    @mcp.tool()
    @audit_tool
    def spiderfoot_scan_status(scan_id: str) -> str:
        """Return the status of a SpiderFoot scan by scan_id.

        Passive-only; uses ``@audit_tool``. No target touch.
        """
        if not scan_id or not scan_id.strip():
            return "BLOCKED: scan_id is required."
        status, body_text = _sf_request(config, "GET", f"/api/v1/scan/{scan_id.strip()}")
        if status == 0:
            return f"SPIDERFOOT_STATUS_ERROR: {body_text}"
        return f"SPIDERFOOT_SCAN_STATUS:\n{body_text[:4000]}"

    @mcp.tool()
    @audit_tool
    def spiderfoot_results(scan_id: str, limit: int = 200) -> str:
        """Return the results of a completed SpiderFoot scan by scan_id.

        Passive-only; uses ``@audit_tool``. No target touch.
        """
        if not scan_id or not scan_id.strip():
            return "BLOCKED: scan_id is required."
        if not isinstance(limit, int) or limit <= 0 or limit > 1000:
            limit = 200
        status, body_text = _sf_request(
            config,
            "GET",
            f"/api/v1/scan/{scan_id.strip()}/results",
            timeout=60,
        )
        if status == 0:
            return f"SPIDERFOOT_RESULTS_ERROR: {body_text}"
        try:
            obj = json.loads(body_text)
            results = obj.get("results", []) if isinstance(obj, dict) else obj
            if isinstance(results, list):
                results = results[:limit]
        except Exception:  # noqa: BLE001
            results = body_text
        return (
            f"SPIDERFOOT_RESULTS_RESULT: count={len(results) if isinstance(results, list) else 'unknown'}\n"
            f"SCAN_ID: {scan_id}\n"
            f"RESULTS:\n{json.dumps(results, indent=2, default=str)[:6000]}"
        )

    @mcp.tool()
    @audit_tool
    def spiderfoot_list_modules() -> str:
        """List the SpiderFoot modules available for the ``modules`` parameter
        of ``spiderfoot_scan``. Passive-only; uses ``@audit_tool``.
        """
        cfg = _sf_cfg(config)
        if not cfg.get("enabled", False):
            return "BLOCKED: spiderfoot plugin not enabled in config."
        status, body_text = _sf_request(config, "GET", "/api/v1/modules")
        if status == 0:
            return f"SPIDERFOOT_MODULES_ERROR: {body_text}"
        return f"SPIDERFOOT_MODULES:\n{body_text[:6000]}"


def create_plugin() -> Plugin:
    """Factory invoked by PluginManager when loading this plugin."""
    return SpiderFootPlugin()
