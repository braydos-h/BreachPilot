"""BloodHound CE plugin for NetAttackAi.

Pairs with the existing ``tools/mcp_tools/ad.py:bloodhound_collect`` tool.
The existing tool collects AD data via bloodhound-python and emits a zip; this
plugin ingests the zip into BloodHound CE (neo4j-backed) and exposes attack-path
queries (shortest path to Domain Admin, kerberoastable users, etc.) via the
BloodHound CE REST API or direct neo4j.

SAFETY (lab build):
* Plugin is OFF by default; opt in via ``config plugins.enabled``.
* Every target-touching MCP tool is wrapped with ``ctx.require_allowlist()`` so
  the target-IP allowlist lock + JSONL audit trail apply automatically.
* The BloodHound CE / neo4j endpoint is operator-side (not target-side): it
  lives on the operator's box and does NOT need to be in
  ``exploit.allowed_targets``.
* No log clearing, timestomping, EDR/AV defeat, DoS, or malware distribution.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any

from tools.plugins import Plugin, PluginManifest, PluginRegistry

log = logging.getLogger("plugins.bloodhound_ce")

_MANIFEST_PATH = Path(__file__).resolve().parent / "plugin.yaml"


# ---------------------------------------------------------------------------
# Lazy neo4j / CE API client
# ---------------------------------------------------------------------------

_NEO4J_DRIVER = None  # type: Any | None
_DRIVER_LOCK = threading.Lock()


def _build_neo4j_driver(config: dict[str, Any] | None) -> Any | None:
    """Build and cache a neo4j driver from the plugin config block."""
    global _NEO4J_DRIVER
    with _DRIVER_LOCK:
        if _NEO4J_DRIVER is not None:
            return _NEO4J_DRIVER
        cfg_block = (config or {}).get("bloodhound_ce") or {}
        if not cfg_block.get("enabled", False):
            log.warning("bloodhound_ce: plugin not enabled in config; tools will refuse")
            return None
        uri = str(cfg_block.get("neo4j_uri", "bolt://127.0.0.1:7687"))
        user = str(cfg_block.get("neo4j_user", "neo4j"))
        pw_env = str(cfg_block.get("neo4j_password_env", "NEO4J_PASSWORD"))
        password = os.environ.get(pw_env, "")
        if not password:
            log.warning("bloodhound_ce: %s env var not set; neo4j auth will fail", pw_env)
        try:
            from neo4j import GraphDatabase  # type: ignore
        except ImportError:
            log.warning("bloodhound_ce: 'neo4j' python package not installed; tools will refuse")
            return None
        try:
            driver = GraphDatabase.driver(uri, auth=(user, password))
            driver.verify_connectivity()
            _NEO4J_DRIVER = driver
            return _NEO4J_DRIVER
        except Exception as exc:  # noqa: BLE001
            log.warning("bloodhound_ce: neo4j connection failed: %s", exc)
            return None


def _reset_driver_cache() -> None:
    """Test hook."""
    global _NEO4J_DRIVER
    with _DRIVER_LOCK:
        _NEO4J_DRIVER = None


def _ce_api_url(config: dict[str, Any] | None) -> str:
    cfg_block = (config or {}).get("bloodhound_ce") or {}
    return str(cfg_block.get("ce_api_url", "http://127.0.0.1:8080"))


def _ce_api_key(config: dict[str, Any] | None) -> str:
    cfg_block = (config or {}).get("bloodhound_ce") or {}
    env_name = str(cfg_block.get("ce_api_key_env", "BLOODHOUND_CE_API_KEY"))
    return os.environ.get(env_name, "")


# ---------------------------------------------------------------------------
# Cypher queries
# ---------------------------------------------------------------------------

# ponytail: pre-baked Cypher queries. The BloodHound community edition schema
# uses lowercase labels (User, Group, Computer, etc.) matching BHCE v5+.
# Ceiling: these queries assume the standard BHCE schema; if the operator
# runs a custom schema, add new query entries here rather than building a
# dynamic query builder.
_QUERIES = {
    "shortest_path_to_domain_admin": (
        "MATCH (n), (m:Domain) WHERE m.name CONTAINS 'DOMAIN' "
        "MATCH p=shortestPath((n)-[*1..15]->(m)) RETURN p LIMIT 50"
    ),
    "kerberoastable_users": (
        "MATCH (u:User) WHERE u.kerberoastable=true RETURN u.name, u.serviceprincipalnames LIMIT 200"
    ),
    "asrep_roastable_users": (
        "MATCH (u:User) WHERE u.dontreqpreauth=true RETURN u.name LIMIT 200"
    ),
    "dcsync_users": (
        "MATCH (u:User) WHERE u.owned=true OR u.dcsync=true RETURN u.name LIMIT 200"
    ),
    "all_admins": (
        "MATCH (u:User)-[:MemberOf]->(g:Group) WHERE g.name CONTAINS 'ADMIN' "
        "RETURN u.name, g.name LIMIT 200"
    ),
}


def _run_cypher(driver: Any, query: str, limit: int = 50) -> list[dict[str, Any]]:
    """Run a Cypher query against neo4j and return a list of record dicts."""
    out: list[dict[str, Any]] = []
    with driver.session() as session:
        result = session.run(query)
        for record in result:
            try:
                out.append(dict(record))
            except Exception:  # noqa: BLE001
                continue
    return out[:limit]


# ---------------------------------------------------------------------------
# CE REST API fallback (when neo4j is not exposed but the CE HTTP API is)
# ---------------------------------------------------------------------------


def _ce_api_request(method: str, path: str, config: dict[str, Any] | None, body: dict | None = None) -> tuple[int, str]:
    """Best-effort HTTP call to the BloodHound CE REST API. Returns (status, body)."""
    import json as _json
    import urllib.error
    import urllib.request

    base = _ce_api_url(config).rstrip("/")
    url = base + path
    headers = {"Accept": "application/json"}
    api_key = _ce_api_key(config)
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    data = _json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        return 0, f"CE API request failed: {exc}"


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class BloodhoundCEPlugin(Plugin):
    """Plugin wrapper that registers the BloodHound CE MCP tools."""

    manifest: PluginManifest

    def __init__(self) -> None:
        self.manifest = self._load_manifest()

    @staticmethod
    def _load_manifest() -> PluginManifest:
        text = _MANIFEST_PATH.read_text(encoding="utf-8")
        from tools.plugins import _parse_manifest_yaml  # type: ignore

        return PluginManifest.from_dict(_parse_manifest_yaml(text))

    def register(self, registry: PluginRegistry) -> None:
        registry.register_mcp_tools(_register_bloodhound_ce_tools)


def _register_bloodhound_ce_tools(mcp: Any, ctx: Any) -> None:
    """Register BloodHound CE MCP tools. Every tool is allowlist-gated via ctx."""
    require_allowlist = ctx.require_allowlist
    workspace = ctx.workspace
    config = ctx.config

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def bloodhound_ce_ingest(target_ip: str, zip_path: str) -> str:
        """Ingest a BloodHound data zip (from bloodhound_collect) into BloodHound CE.

        The zip_path must be a file produced by ``bloodhound_collect`` under the
        per-target workspace. This tool uploads it to the CE REST API for
        parsing into the neo4j graph. Target_ip is allowlist-gated; the CE API
        endpoint itself is operator-side and does not need to be in
        ``exploit.allowed_targets``.
        """
        if not zip_path or not zip_path.strip():
            return "BLOCKED: zip_path is required."
        candidate = Path(zip_path)
        if not candidate.is_absolute():
            candidate = workspace / zip_path
        if not candidate.exists() or not candidate.is_file():
            return f"BLOCKED: zip file not found: {candidate}"
        if not str(candidate).lower().endswith(".zip"):
            return f"BLOCKED: file must be a .zip: {candidate}"

        status, body = _ce_api_request(
            "POST",
            "/api/v2/ingest",
            config,
            body={"file_path": str(candidate), "target": target_ip},
        )
        if status == 0:
            # CE API unavailable; fall back to a neo4j-driven ingest hint.
            return (
                f"BLOODHOUND_CE_INGEST_RESULT: ce_api_unavailable\n"
                f"ZIP: {candidate}\n"
                f"NOTE: CE REST API did not respond. Start bloodhound-ce and retry, "
                f"or use bloodhound_ce_query to query the existing graph directly."
            )
        return (
            f"BLOODHOUND_CE_INGEST_RESULT: http_{status}\n"
            f"ZIP: {candidate}\n"
            f"TARGET: {target_ip}\n"
            f"RESPONSE: {body[:2000]}"
        )

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def bloodhound_ce_query(target_ip: str, query_name: str, limit: int = 50) -> str:
        """Run a pre-baked BloodHound CE attack-path query against the neo4j graph.

        Supported query_name values:
        - shortest_path_to_domain_admin
        - kerberoastable_users
        - asrep_roastable_users
        - dcsync_users
        - all_admins

        The neo4j endpoint is operator-side; target_ip is allowlist-gated for
        audit-trail consistency even though the query reads from neo4j, not the
        target.
        """
        if not query_name or not query_name.strip():
            return "BLOCKED: query_name is required."
        key = query_name.strip().lower()
        if key not in _QUERIES:
            return (
                f"BLOCKED: unknown query '{query_name}'. Supported: "
                f"{', '.join(sorted(_QUERIES.keys()))}"
            )
        if not isinstance(limit, int) or limit <= 0 or limit > 500:
            limit = 50

        driver = _build_neo4j_driver(config)
        if driver is None:
            # Fallback: try the CE REST API query endpoint.
            status, body = _ce_api_request(
                "POST",
                "/api/v2/queries",
                config,
                body={"query_name": key, "limit": limit},
            )
            if status == 0:
                return (
                    f"BLOODHOUND_CE_QUERY_RESULT: no_driver_no_api\n"
                    f"QUERY: {key}\n"
                    f"NOTE: neo4j driver unavailable and CE REST API did not respond. "
                    f"Install the 'neo4j' package or start bloodhound-ce."
                )
            return (
                f"BLOODHOUND_CE_QUERY_RESULT: http_{status}\n"
                f"QUERY: {key}\n"
                f"RESPONSE: {body[:4000]}"
            )
        try:
            results = _run_cypher(driver, _QUERIES[key], limit=limit)
        except Exception as exc:  # noqa: BLE001
            return f"BLOODHOUND_CE_QUERY_ERROR: {exc}"
        if not results:
            return f"BLOODHOUND_CE_QUERY_RESULT: empty\nQUERY: {key}"
        import json as _json

        return (
            f"BLOODHOUND_CE_QUERY_RESULT: ok\n"
            f"QUERY: {key}\n"
            f"COUNT: {len(results)}\n"
            f"RESULTS:\n{_json.dumps(results, default=str, indent=2)[:4000]}"
        )

    @mcp.tool()
    @require_allowlist(target_param="target_ip", audit=True)
    def bloodhound_ce_list_queries(target_ip: str) -> str:
        """List the pre-baked BloodHound CE attack-path query names available.

        This is an advisory tool: it returns the static query catalog. The
        allowlist gate applies for audit-trail consistency; no target touch.
        """
        lines = ["BLOODHOUND_CE_QUERIES:"]
        for name, query in sorted(_QUERIES.items()):
            lines.append(f"  {name}: {query[:120]}...")
        return "\n".join(lines)


def create_plugin() -> Plugin:
    """Factory invoked by PluginManager when loading this plugin."""
    return BloodhoundCEPlugin()
