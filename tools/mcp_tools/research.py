"""Research MCP tool registration."""

from __future__ import annotations

from tools.mcp_tools.registry import *


def register_research_tools(mcp: Any, *, ctx: ToolContext) -> None:
    workspace = ctx.workspace
    config = ctx.config
    search = ctx.search
    nvd = ctx.nvd
    researcher = ctx.researcher
    audit_tool = ctx.audit_tool
    require_allowlist = ctx.require_allowlist

    @mcp.tool()
    def search_exploit_db(query: str) -> str:
        """Search the local exploit-db database via searchsploit. Returns exploit IDs, titles, paths and any associated CVEs. Use this to find known exploits for discovered services and CVEs."""
        return search.search_exploit_db(query)

    @mcp.tool()
    def search_web_exploit(query: str) -> str:
        """Read-only public web search for candidate exploit, PoC, advisory, and vulnerability-research sources. Returns titles, URLs, snippets, source quality, provider metadata, and warnings; it does not fetch full pages or execute anything."""
        if not research_api_keys_available(config or {}):
            return disabled_research_tools_message(config or {})
        return search.search_web_exploit(query)

    @mcp.tool()
    def fetch_webpage(url: str) -> str:
        """Read-only fetch for one public source URL discovered during research. Returns title, source URL, readable content, links, provider metadata, and warnings. Private/internal/localhost URLs are blocked by default, and this tool does not execute exploit code."""
        if not research_api_keys_available(config or {}):
            return disabled_research_tools_message(config or {})
        return researcher.fetch_webpage(url)

    @mcp.tool()
    def deep_research(query: str) -> str:
        """Perform read-only multi-source research for an authorized vulnerability, CVE, product/version, or technique. Searches candidate sources, ranks/de-duplicates them, fetches selected public pages, and returns structured JSON with citations, key facts, reliability notes, relevant CVEs, warnings, and suggested next queries. It does not execute exploits or payloads."""
        if not research_api_keys_available(config or {}):
            return disabled_research_tools_message(config or {})
        return researcher.deep_research(query, search.search_web_exploit)

    @mcp.tool()
    def search_cve_intel(query: str) -> str:
        """Look up CVEs in the NVD database for a known CVE ID or product/version string. Returns CVSS score, description, and reference links."""
        entries = nvd.search_sync(query)
        return format_cve_results(entries, query)

    @mcp.tool()
    def cve_to_poc(cve_id: str) -> str:
        """Resolve a CVE ID to VERIFIED PoC URLs only (GitHub Search API + searchsploit --cve + NVD references, each HTTP-existence-checked). Returns CVE_TO_POC_RESULTS with verified URLs, or NO_VERIFIED_POC_FOUND if none verify. NEVER fabricate or guess a PoC/clone URL — always call this tool first and use ONLY the URLs it returns; if it returns NO_VERIFIED_POC_FOUND, write a workspace-contained exploit from the CVE details (cve_to_exploit_synth) instead of inventing a URL."""
        # Gather NVD reference URLs (best-effort) to feed the resolver so
        # NVD-listed PoC refs are also HTTP-verified and surfaced.
        nvd_refs: list[str] = []
        try:
            for entry in nvd.search_sync(cve_id):
                for ref in getattr(entry, "references", []) or []:
                    if isinstance(ref, str) and ref:
                        nvd_refs.append(ref)
        except Exception:
            pass
        return search.cve_to_poc(cve_id, nvd_refs=nvd_refs)



