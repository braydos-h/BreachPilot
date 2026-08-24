from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import pytest

from tools.web_researcher import (
    FetchResult,
    OllamaResearchProvider,
    OllamaResearchSettings,
    ResearchProvider,
    SearchResult,
    WebResearcher,
    WebResearcherSettings,
    validate_url,
)


class FakeProvider(ResearchProvider):
    name = "fake"

    def __init__(self, *, search_results: list[SearchResult] | None = None, fetch_content: str = "") -> None:
        super().__init__(timeout_seconds=1, max_content_chars=5000)
        self.search_results = search_results or []
        self.fetch_content = fetch_content

    async def _search(self, query: str, *, max_results: int) -> list[SearchResult]:
        return self.search_results[:max_results]

    async def _fetch(self, url: str) -> FetchResult:
        return FetchResult(
            url=url,
            title="Fetched advisory",
            content=self.fetch_content or f"{url} documents CVE-2024-12345 affected versions and mitigation guidance.",
            links=["https://nvd.nist.gov/"],
            provider=self.name,
        )


class FakeSerpAPIProvider(FakeProvider):
    name = "serpapi"


def test_validate_url_blocks_private_and_internal_hosts() -> None:
    blocked = [
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://192.168.1.5/",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8000/",
        "http://service.internal/",
        "http://[::1]/",
    ]

    for url in blocked:
        assert validate_url(url).startswith("BLOCKED: private/internal host not allowed")

    assert validate_url("example.com/path#frag") == "https://example.com/path"
    assert validate_url("https://example.com/", allowed_domains=["nvd.nist.gov"]).startswith("BLOCKED:")
    assert validate_url("https://tracker.doubleclick.net/", blocked_domains=["doubleclick.net"]).startswith("BLOCKED:")


@pytest.mark.asyncio
async def test_ollama_provider_uses_mocked_web_search_and_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeOllamaModule:
        @staticmethod
        def web_search(query: str, max_results: int = 8) -> dict[str, Any]:
            assert query == "CVE-2024-12345"
            assert max_results == 2
            return {
                "results": [
                    {
                        "title": "Vendor advisory",
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
                        "content": "NVD reference for CVE-2024-12345.",
                    }
                ]
            }

        @staticmethod
        def web_fetch(url: str) -> dict[str, Any]:
            return {
                "title": "Fetched source",
                "content": "CVE-2024-12345 affects test product versions before 1.2.3.",
                "links": ["https://cve.org/CVERecord?id=CVE-2024-12345"],
            }

    monkeypatch.setitem(sys.modules, "ollama", FakeOllamaModule)
    monkeypatch.setenv("OLLAMA_API_KEY", "test-key")

    provider = OllamaResearchProvider(
        OllamaResearchSettings(max_results=2),
        timeout_seconds=1,
        max_content_chars=1000,
    )

    results = await provider.search("CVE-2024-12345", max_results=2)
    fetched = await provider.fetch(results[0].url)

    assert results[0].provider == "ollama"
    assert results[0].url == "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"
    assert fetched.provider == "ollama"
    assert "CVE-2024-12345" in fetched.content
    assert fetched.links == ["https://cve.org/CVERecord?id=CVE-2024-12345"]


@pytest.mark.asyncio
async def test_missing_ollama_api_key_falls_back_to_serpapi_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)

    fallback = FakeSerpAPIProvider(
        search_results=[
            SearchResult(
                title="Fallback advisory",
                url="https://example.com/advisory",
                content="Fallback source for CVE-2024-12345.",
                provider="serpapi",
            )
        ]
    )
    researcher = WebResearcher(
        WebResearcherSettings(provider="ollama", fallback_provider="serpapi"),
        providers={
            "ollama": OllamaResearchProvider(
                OllamaResearchSettings(),
                timeout_seconds=1,
                max_content_chars=1000,
            ),
            "serpapi": fallback,
        },
    )

    results = await researcher.search_results_async("CVE-2024-12345")

    assert results[0].provider == "serpapi"
    assert results[0].title == "Fallback advisory"


def test_dedupe_and_source_ranking_prefers_primary_sources() -> None:
    researcher = WebResearcher(WebResearcherSettings(provider="fake"), providers={"fake": FakeProvider()})
    ranked = researcher._dedupe_and_rank(
        [
            SearchResult(
                title="Copied post",
                url="https://lowquality.example/post",
                content="Top 10 SEO summary of CVE-2024-12345",
                provider="fake",
                rank=1,
            ),
            SearchResult(
                title="NVD CVE-2024-12345",
                url="https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
                content="NVD advisory and references for CVE-2024-12345",
                provider="fake",
                rank=2,
            ),
            SearchResult(
                title="Duplicate NVD",
                url="https://nvd.nist.gov/vuln/detail/CVE-2024-12345#references",
                content="Longer NVD advisory and references for CVE-2024-12345 affected versions.",
                provider="fake",
                rank=3,
            ),
        ]
    )

    assert len(ranked) == 2
    assert ranked[0].url == "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"
    assert "Longer NVD" in ranked[0].title or "Longer" in ranked[0].content


@pytest.mark.asyncio
async def test_deep_research_returns_structured_source_backed_brief() -> None:
    provider = FakeProvider(
        search_results=[
            SearchResult(
                title="NVD CVE-2024-12345",
                url="https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
                content="CVE-2024-12345 has affected versions and mitigation references.",
                provider="fake",
                rank=1,
            ),
            SearchResult(
                title="Vendor advisory",
                url="https://www.apache.org/security/CVE-2024-12345",
                content="Vendor advisory describes patch and workaround for CVE-2024-12345.",
                provider="fake",
                rank=2,
            ),
        ],
        fetch_content=(
            "CVE-2024-12345 is a test vulnerability. Affected versions before 1.2.3 "
            "should apply the vendor patch and mitigation guidance."
        ),
    )
    researcher = WebResearcher(
        WebResearcherSettings(provider="fake", fallback_provider="", min_source_quality="low", max_fetch_depth=2),
        providers={"fake": provider},
    )

    payload = json.loads(await researcher.deep_research_async("CVE-2024-12345 test product"))

    assert payload["status"] == "ok"
    assert payload["query"] == "CVE-2024-12345 test product"
    assert payload["provider_used"] == "fake"
    assert payload["source_urls"]
    assert payload["sources_fetched"]
    assert payload["key_facts"]
    assert payload["relevant_cves"] == ["CVE-2024-12345"]
    assert payload["suggested_next_queries"]
    assert all("url" in source for source in payload["sources_searched"])


def test_exploit_search_has_no_hardcoded_api_key_assignment() -> None:
    text = Path("tools/exploit_search.py").read_text(encoding="utf-8")

    assert re.search(r"api_key\s*=\s*[\"']", text) is None
    assert "SERPAPI_API_KEY" in text
    assert "os.getenv" in text


@pytest.mark.asyncio
async def test_mcp_research_tool_names_still_work(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings

    monkeypatch.setenv("OLLAMA_API_KEY", "test-key")
    provider = FakeProvider(
        search_results=[
            SearchResult(
                title="NVD CVE-2024-12345",
                url="https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
                content="CVE-2024-12345 exploitability and mitigation references.",
                provider="fake",
            )
        ]
    )
    researcher = WebResearcher(
        WebResearcherSettings(provider="fake", fallback_provider="", min_source_quality="low"),
        providers={"fake": provider},
    )
    server = create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings(enabled=False)),
        researcher,
        tmp_path,
        {"exploit": {"require_explicit_allowlist": False}},
    )

    search_text = _mcp_text(await server.call_tool("search_web_exploit", {"query": "CVE-2024-12345"}))
    fetch_text = _mcp_text(
        await server.call_tool("fetch_webpage", {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"})
    )
    deep_payload = json.loads(_mcp_text(await server.call_tool("deep_research", {"query": "CVE-2024-12345"})))

    assert "WEB_SEARCH_RESULTS" in search_text
    assert "FETCHED:" in fetch_text
    assert deep_payload["query"] == "CVE-2024-12345"
    assert deep_payload["source_urls"]


def test_api_key_store_saves_and_loads_without_printing_values(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from tools.api_key_store import load_api_keys_into_env, save_api_keys

    store = tmp_path / "secr.json"
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)

    saved = save_api_keys(store, {"OLLAMA_API_KEY": "secret-value"})
    loaded = load_api_keys_into_env(store, allowed_names=["OLLAMA_API_KEY"])

    assert saved == ["OLLAMA_API_KEY"]
    assert loaded == ["OLLAMA_API_KEY"]
    assert os.environ["OLLAMA_API_KEY"] == "secret-value"
    assert "secret-value" not in store.name
    assert store.exists()


@pytest.mark.asyncio
async def test_mcp_research_tools_disabled_without_api_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings

    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    monkeypatch.delenv("SERPAPI_API_KEY", raising=False)
    researcher = WebResearcher(
        WebResearcherSettings(provider="fake", fallback_provider="", min_source_quality="low"),
        providers={"fake": FakeProvider()},
    )
    server = create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings(enabled=False)),
        researcher,
        tmp_path,
        {
            "exploit": {"require_explicit_allowlist": False},
            "research": {"provider": "ollama", "fallback_provider": "serpapi", "require_api_key_for_mcp_tools": True},
        },
    )

    text = _mcp_text(await server.call_tool("deep_research", {"query": "CVE-2024-12345"}))

    assert text.startswith("RESEARCH_API_KEY_MISSING")
    assert "disabled" in text


def _mcp_text(result: Any) -> str:
    content = result[0] if isinstance(result, (list, tuple)) else result
    if hasattr(content, "content"):
        content = content.content
    parts: list[str] = []
    for item in content:
        text = getattr(item, "text", None)
        if text is None and isinstance(item, dict):
            text = item.get("text")
        parts.append(str(text if text is not None else item))
    return "".join(parts)
