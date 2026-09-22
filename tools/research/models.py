"""Research data model: result/brief/settings types, error codes, ResearchProviderError (split from tools.web_researcher)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

RESEARCH_DISABLED = "RESEARCH_DISABLED"
RESEARCH_PROVIDER_UNAVAILABLE = "RESEARCH_PROVIDER_UNAVAILABLE"
RESEARCH_API_KEY_MISSING = "RESEARCH_API_KEY_MISSING"
RESEARCH_SEARCH_FAILED = "RESEARCH_SEARCH_FAILED"
RESEARCH_FETCH_FAILED = "RESEARCH_FETCH_FAILED"


@dataclass(frozen=True)
class SearchResult:
    """One candidate source returned by a research provider."""

    title: str
    url: str
    content: str = ""
    provider: str = ""
    rank: int = 0
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "url": self.url,
            "content": self.content,
            "provider": self.provider,
            "rank": self.rank,
        }


@dataclass(frozen=True)
class FetchResult:
    """Readable content fetched from one source URL."""

    url: str
    title: str = ""
    content: str = ""
    links: list[str] = field(default_factory=list)
    provider: str = ""
    ok: bool = True
    error_code: str = ""
    error: str = ""

    def to_dict(self, *, max_content_chars: int | None = None) -> dict[str, Any]:
        content = self.content
        if max_content_chars is not None and len(content) > max_content_chars:
            content = content[:max_content_chars] + "\n[truncated]"
        return {
            "url": self.url,
            "title": self.title,
            "content": content,
            "links": self.links,
            "provider": self.provider,
            "ok": self.ok,
            "error_code": self.error_code,
            "error": self.error,
        }


@dataclass(frozen=True)
class ResearchSource:
    """A source selected for a structured research brief."""

    title: str
    url: str
    snippet: str
    provider: str
    quality: str
    quality_score: int
    fetched: bool = False
    fetch_provider: str = ""
    content_excerpt: str = ""
    warning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "url": self.url,
            "snippet": self.snippet,
            "provider": self.provider,
            "quality": self.quality,
            "quality_score": self.quality_score,
            "fetched": self.fetched,
            "fetch_provider": self.fetch_provider,
            "content_excerpt": self.content_excerpt,
            "warning": self.warning,
        }


@dataclass(frozen=True)
class ResearchBrief:
    """Structured multi-source research output."""

    query: str
    timestamp: str
    provider_used: str
    sources_searched: list[ResearchSource]
    sources_fetched: list[ResearchSource]
    key_facts: list[dict[str, str]]
    confidence: str
    reliability_notes: list[str]
    relevant_cves: list[str]
    suggested_next_queries: list[str]
    warnings: list[str] = field(default_factory=list)
    status: str = "ok"
    fallback_used: bool = False
    error_code: str = ""
    error: str = ""

    @property
    def source_titles(self) -> list[str]:
        return [source.title for source in self.sources_searched if source.title]

    @property
    def source_urls(self) -> list[str]:
        return [source.url for source in self.sources_searched if source.url]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "error_code": self.error_code,
            "error": self.error,
            "query": self.query,
            "timestamp": self.timestamp,
            "provider_used": self.provider_used,
            "fallback_used": self.fallback_used,
            "sources_searched": [source.to_dict() for source in self.sources_searched],
            "sources_fetched": [source.to_dict() for source in self.sources_fetched],
            "source_titles": self.source_titles,
            "source_urls": self.source_urls,
            "key_facts": self.key_facts,
            "confidence": self.confidence,
            "reliability_notes": self.reliability_notes,
            "relevant_cves": self.relevant_cves,
            "suggested_next_queries": self.suggested_next_queries,
            "warnings": self.warnings,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=False)


@dataclass(frozen=True)
class OllamaResearchSettings:
    api_key_env: str = "OLLAMA_API_KEY"
    max_results: int = 8
    use_web_search: bool = True
    use_web_fetch: bool = True


@dataclass(frozen=True)
class SerpAPIResearchSettings:
    api_key_env: str = "SERPAPI_API_KEY"
    endpoint: str = "https://serpapi.com/search.json"
    engine: str = "duckduckgo"
    region: str = "us-en"


@dataclass(frozen=True)
class WebResearcherSettings:
    enabled: bool = True
    provider: str = "ollama"
    fallback_provider: str = "serpapi"
    timeout_seconds: int = 15
    max_results: int = 8
    max_fetch_depth: int = 5
    max_content_chars: int = 12000
    cache_ttl_seconds: float = 1800.0
    cache_max_entries: int = 250
    min_source_quality: str = "medium"
    allow_local_fetch: bool = False
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    )
    allowed_domains: list[str] = field(default_factory=list)
    blocked_domains: list[str] = field(
        default_factory=lambda: [
            "doubleclick.net",
            "googleadservices.com",
            "googlesyndication.com",
            "facebook.com",
            "twitter.com",
            "instagram.com",
            "tiktok.com",
        ]
    )
    ollama: OllamaResearchSettings = field(default_factory=OllamaResearchSettings)
    serpapi: SerpAPIResearchSettings = field(default_factory=SerpAPIResearchSettings)


class ResearchProviderError(RuntimeError):
    """Provider failure with a stable error code safe to show to models/users."""

    def __init__(self, code: str, message: str, *, provider: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.provider = provider
        self.message = message

    def public_message(self) -> str:
        provider = f" ({self.provider})" if self.provider else ""
        return f"{self.code}{provider}: {self.message}"
