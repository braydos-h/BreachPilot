"""Engine MCP server — exposes BreachPilot's advisory capabilities to other AI
assistants (Claude Desktop, Cursor, etc.) as MCP tools.

Distinct from ``mcp_server.py`` (defensive Nmap scanning) and
``mcp_exploit_server.py`` (offensive tooling for the exploit agent): this
server exposes the engine's *advisory + history* surface so a foreign
assistant can query the skill catalog, look up CVEs, and inspect past runs
without touching targets. v1 is read-only — no target touching, no terminal,
no exploit surface. The target-IP allowlist lock and audit chain are not in
scope because no tool reaches the network or the operator box filesystem
beyond the reports/skills directories.

Tools:
    search_skills(query, limit?)  -> semantic + lexical skill search
    get_skill(name)               -> one SKILL.md body
    cve_lookup(query)             -> NVD CVE lookup (rate-limited, cached)
    list_runs(limit?)              -> recent run history (read-only)
    get_run(run_id)                -> one run's details (state, request, result)

Run:
    python mcp_engine_server.py --transport stdio
    python mcp_engine_server.py --transport http --port 8002

HTTP transport is loopback-only by default; a non-loopback bind requires
``--allow-public-bind`` AND ``MCP_ALLOW_PUBLIC_BIND=1`` (two-person rule,
shared with the other two servers via ``tools.mcp_shared.run_mcp_http_server``).
Optional bearer auth via ``MCP_HTTP_TOKEN``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover - import guard
    raise RuntimeError("The MCP Python SDK is not installed. Run: python -m pip install -r requirements.txt") from exc

from tools.api.persistence import ApiPersistence
from tools.cve_lookup import format_cve_results
from tools.mcp_shared import build_cve_search, load_config, run_mcp_http_server
from tools.skill_registry import load_skill_registry


def create_mcp_server(
    *,
    nvd: Any,
    config: dict[str, Any] | None = None,
    reports_dir: Path | None = None,
    skill_roots: list[str | Path] | None = None,
) -> FastMCP:
    """Create the engine MCP server.

    Args:
        nvd: shared NVDClient (built by ``build_cve_search``)
        config: full loaded config (used for skill roots + reports dir)
        reports_dir: overrides ``config["reports_dir"]``-derived path
        skill_roots: overrides ``config["skills"]["roots"]``
    """
    config = config or {}
    skills_cfg = config.get("skills", {}) or {}

    if skill_roots is None:
        skill_roots = list(skills_cfg.get("roots") or ["skills"])
    registry = load_skill_registry(skill_roots)

    if reports_dir is None:
        reports_dir = Path("reports")
    persistence = ApiPersistence(Path(reports_dir))

    mcp = FastMCP(
        "breachpilot-engine",
        instructions=(
            "BreachPilot engine advisory surface. Tools are read-only: skill "
            "search, skill body retrieval, NVD CVE lookup, and run history. "
            "No target touching, no terminal, no exploit execution. For active "
            "scanning use mcp_server.py; for exploitation use mcp_exploit_server.py."
        ),
        json_response=True,
    )

    # ── search_skills ────────────────────────────────────────────────
    @mcp.tool()
    def search_skills(query: str, limit: int = 10) -> dict[str, Any]:
        """Lexical + field-weighted search over the runtime skill catalog
        (~140 methodology SKILL.md files). Returns name + description + tags
        for each match, highest score first.

        Args:
            query: free-text query (matches name, tags, description, body).
            limit: max results (default 10, capped at 50).
        """
        limit = max(1, min(int(limit), 50))
        matches = registry.search(query, limit=limit)
        return {
            "count": len(matches),
            "skills": [
                {
                    "name": s.name,
                    "description": s.metadata.description,
                    "tags": list(s.metadata.tags),
                    "domain": s.metadata.domain,
                }
                for s in matches
            ],
        }

    # ── get_skill ───────────────────────────────────────────────────
    @mcp.tool()
    def get_skill(name: str) -> dict[str, Any]:
        """Return one skill's full body + metadata by name.

        Args:
            name: exact skill name (as returned by search_skills).
        """
        skill = registry.get(name)
        if skill is None:
            return {"ok": False, "error": f"skill {name!r} not found"}
        return {
            "ok": True,
            "name": skill.name,
            "description": skill.metadata.description,
            "tags": list(skill.metadata.tags),
            "domain": skill.metadata.domain,
            "subdomain": skill.metadata.subdomain,
            "version": skill.metadata.version,
            "nist_csf": list(skill.metadata.nist_csf),
            "mitre_attack": list(skill.metadata.mitre_attack),
            "sections": dict(skill.sections),
            "body": skill.body,
        }

    # ── cve_lookup ──────────────────────────────────────────────────
    @mcp.tool()
    def cve_lookup(query: str) -> str:
        """NVD CVE lookup for a known product/version string (e.g.
        'apache 2.4.49'). Rate-limited, cached, circuit-breakered. Returns
        formatted CVE entries with CVSS + references.
        """
        entries = nvd.search_sync(query)
        return format_cve_results(entries, query)

    # ── list_runs ───────────────────────────────────────────────────
    @mcp.tool()
    def list_runs(limit: int = 20) -> dict[str, Any]:
        """List recent assessment runs (read-only history). Newest first.

        Args:
            limit: max runs to return (default 20, capped at 100).
        """
        limit = max(1, min(int(limit), 100))
        rows = persistence.list_runs(limit=limit, sort="created_desc")
        # Trim to the summary columns a foreign assistant needs.
        return {
            "count": len(rows),
            "runs": [
                {
                    "id": r.get("id"),
                    "state": r.get("state"),
                    "created_at": r.get("created_at"),
                    "target": r.get("target"),
                    "mode": r.get("mode"),
                    "goal_name": r.get("goal_name"),
                    "model_alias": r.get("model_alias"),
                    "title": r.get("title"),
                }
                for r in rows
            ],
        }

    # ── get_run ─────────────────────────────────────────────────────
    @mcp.tool()
    def get_run(run_id: str) -> dict[str, Any]:
        """Return one run's details: state, request, preview, result, error.

        Args:
            run_id: the run identifier.
        """
        run = persistence.get_run(run_id)
        if run is None:
            return {"ok": False, "error": f"run {run_id!r} not found"}
        return {"ok": True, "run": run}

    return mcp


# ── CLI entrypoint ──────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Engine MCP server — advisory surface for foreign AI assistants.")
    parser.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    parser.add_argument("--config", type=Path, default=Path("config.yaml"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8002)
    parser.add_argument(
        "--allow-public-bind",
        action="store_true",
        help="Allow binding a non-loopback interface (requires MCP_ALLOW_PUBLIC_BIND=1 too).",
    )
    args = parser.parse_args(argv)

    config = load_config(args.config)
    nvd = build_cve_search(config)
    server = create_mcp_server(nvd=nvd, config=config)

    if args.transport == "stdio":
        server.run(transport="stdio")
    else:
        run_mcp_http_server(server, args.host, args.port, allow_public_bind=args.allow_public_bind)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
