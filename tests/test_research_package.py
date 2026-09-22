"""Characterization tests for the ``tools.research`` package split (todo 06).

Pins the post-split contract without touching the network: model roundtrips,
URL validation, quality scoring, text helpers, provider backoff math, and the
disabled-research short-circuit. Provider ``_search_sync`` paths that perform
I/O are not exercised here.

Split map (``tools.web_researcher`` is a thin shim over all of these):

- ``tools.research.models`` — result/brief/settings types, error codes
- ``tools.research.providers`` — ResearchProvider base + backends
- ``tools.research.facade`` — WebResearcher
- ``tools.research.text_utils`` — validation, scoring, excerpts
"""

from __future__ import annotations

import tools.web_researcher as wr
from tools.research import facade as _facade
from tools.research import models as _models
from tools.research import providers as _providers
from tools.research import text_utils as _text


def test_shim_reexports_canonical_objects():
    assert wr.WebResearcher is _facade.WebResearcher
    assert wr.SearchResult is _models.SearchResult
    assert wr.FetchResult is _models.FetchResult
    assert wr.ResearchBrief is _models.ResearchBrief
    assert wr.WebResearcherSettings is _models.WebResearcherSettings
    assert wr.ResearchProvider is _providers.ResearchProvider
    assert wr.OllamaResearchProvider is _providers.OllamaResearchProvider
    assert wr.RESEARCH_DISABLED == "RESEARCH_DISABLED"


def test_search_result_roundtrip():
    result = wr.SearchResult(title="t", url="https://example.com", provider="ollama", rank=1)
    assert result.to_dict()["url"] == "https://example.com"


def test_fetch_result_truncation():
    result = wr.FetchResult(url="https://example.com", content="x" * 100)
    assert result.to_dict(max_content_chars=10).endswith("[truncated]")


def test_brief_json_shape():
    brief = wr.ResearchBrief(
        query="q",
        timestamp="t",
        provider_used="none",
        sources_searched=[],
        sources_fetched=[],
        key_facts=[],
        confidence="none",
        reliability_notes=[],
        relevant_cves=[],
        suggested_next_queries=[],
        status="ok",
        warnings=[],
    )
    assert brief.to_dict()["query"] == "q"
    assert "source_urls" in dir(brief)


def test_validate_url_blocks_private():
    assert _text.validate_url("") == "BLOCKED: empty URL."
    assert "BLOCKED" in _text.validate_url("http://127.0.0.1/admin")
    assert "BLOCKED" in _text.validate_url("http://localhost/x")
    assert "BLOCKED" in _text.validate_url("ftp://example.com/x")


def test_validate_url_allows_public():
    cleaned = _text.validate_url("https://nvd.nist.gov/vuln/detail/CVE-2021-44228#frag")
    assert cleaned.startswith("https://nvd.nist.gov/")
    assert "#frag" not in cleaned


def test_quality_score_prefers_primary_sources():
    primary = _text.source_quality_score("https://nvd.nist.gov/vuln/detail/CVE-2021-44228")
    assert _text.source_quality_label(primary) == "high"
    assert _text.source_quality_label(0) == "low"
    assert _text.source_quality_label(50) == "medium"


def test_canonicalize_url_normalizes():
    assert _text.canonicalize_url("HTTPS://Example.COM/docs/") == "https://example.com/docs"


def test_excerpt_and_cves_and_dedupe():
    assert _text._excerpt("x" * 100, 10).endswith("...")
    assert _text._extract_cves("see cve-2021-44228 and CVE-2017-0144") == ["CVE-2017-0144", "CVE-2021-44228"]
    assert _text._dedupe_strings(["a", "a", "b"]) == ["a", "b"]


def test_disabled_research_short_circuits_without_network():
    researcher = wr.WebResearcher(wr.WebResearcherSettings(enabled=False))
    assert researcher.search("log4j").startswith("RESEARCH_DISABLED")
    assert researcher.fetch_webpage("https://example.com").startswith("RESEARCH_DISABLED")


def test_provider_backoff_after_failures():
    settings = wr.OllamaResearchSettings()
    provider = wr.OllamaResearchProvider(settings, timeout_seconds=5, max_content_chars=100)
    assert provider.name == "ollama"
    provider._record_failure()
    try:
        provider._check_backoff()
    except wr.ResearchProviderError as exc:
        assert exc.code == wr.RESEARCH_PROVIDER_UNAVAILABLE
    else:  # pragma: no cover - backoff must trigger after a failure
        raise AssertionError("expected backoff")
    provider._record_success()
    provider._check_backoff()  # no raise after success resets the breaker
