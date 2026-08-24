"""Provider-backed web research for authorized vulnerability analysis.

The public ``WebResearcher`` API remains string-based for MCP compatibility,
but the implementation now works with structured provider results internally.
Research tools are read-only: they search, fetch, rank, summarize, and cite
sources. They do not execute commands or payloads.
"""

from __future__ import annotations

import asyncio
import html
import importlib
import ipaddress
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any, Callable, Iterable
from urllib.parse import urljoin, urlparse, urlunparse

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


class ResearchProvider(ABC):
    """Provider abstraction for web search and fetch."""

    name: str = "provider"

    def __init__(self, *, timeout_seconds: int, max_content_chars: int) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_content_chars = max_content_chars
        self._failure_count = 0
        self._backoff_until = 0.0

    async def search(self, query: str, *, max_results: int) -> list[SearchResult]:
        self._check_backoff()
        try:
            results = await self._search(query, max_results=max_results)
        except ResearchProviderError as exc:
            if exc.code not in {RESEARCH_API_KEY_MISSING, RESEARCH_PROVIDER_UNAVAILABLE}:
                self._record_failure()
            raise
        except Exception as exc:
            self._record_failure()
            raise ResearchProviderError(
                RESEARCH_SEARCH_FAILED,
                f"search failed: {exc}",
                provider=self.name,
            ) from exc
        self._record_success()
        return results

    async def fetch(self, url: str) -> FetchResult:
        self._check_backoff()
        try:
            result = await self._fetch(url)
        except ResearchProviderError as exc:
            if exc.code not in {RESEARCH_API_KEY_MISSING, RESEARCH_PROVIDER_UNAVAILABLE}:
                self._record_failure()
            raise
        except Exception as exc:
            self._record_failure()
            raise ResearchProviderError(
                RESEARCH_FETCH_FAILED,
                f"fetch failed: {exc}",
                provider=self.name,
            ) from exc
        self._record_success()
        return result

    @abstractmethod
    async def _search(self, query: str, *, max_results: int) -> list[SearchResult]:
        raise NotImplementedError

    @abstractmethod
    async def _fetch(self, url: str) -> FetchResult:
        raise NotImplementedError

    def _check_backoff(self) -> None:
        remaining = self._backoff_until - time.monotonic()
        if remaining > 0:
            raise ResearchProviderError(
                RESEARCH_PROVIDER_UNAVAILABLE,
                f"provider is backing off for {remaining:.1f}s after recent failures",
                provider=self.name,
            )

    def _record_success(self) -> None:
        self._failure_count = 0
        self._backoff_until = 0.0

    def _record_failure(self) -> None:
        self._failure_count += 1
        delay = min(60.0, 2.0 ** min(self._failure_count, 6))
        self._backoff_until = time.monotonic() + delay


class OllamaResearchProvider(ResearchProvider):
    """Ollama official web_search/web_fetch provider."""

    name = "ollama"

    def __init__(self, settings: OllamaResearchSettings, *, timeout_seconds: int, max_content_chars: int) -> None:
        super().__init__(timeout_seconds=timeout_seconds, max_content_chars=max_content_chars)
        self.settings = settings

    async def _search(self, query: str, *, max_results: int) -> list[SearchResult]:
        if not self.settings.use_web_search:
            raise ResearchProviderError(
                RESEARCH_PROVIDER_UNAVAILABLE,
                "Ollama web_search is disabled in config",
                provider=self.name,
            )
        self._require_api_key()
        limit = min(max_results, self.settings.max_results)
        return await asyncio.to_thread(self._search_sync, query, limit)

    async def _fetch(self, url: str) -> FetchResult:
        if not self.settings.use_web_fetch:
            raise ResearchProviderError(
                RESEARCH_PROVIDER_UNAVAILABLE,
                "Ollama web_fetch is disabled in config",
                provider=self.name,
            )
        self._require_api_key()
        return await asyncio.to_thread(self._fetch_sync, url)

    def _require_api_key(self) -> None:
        if not os.getenv(self.settings.api_key_env):
            raise ResearchProviderError(
                RESEARCH_API_KEY_MISSING,
                f"set {self.settings.api_key_env} to use Ollama web search/fetch",
                provider=self.name,
            )

    def _ollama_module(self) -> Any:
        try:
            return importlib.import_module("ollama")
        except ImportError as exc:
            raise ResearchProviderError(
                RESEARCH_PROVIDER_UNAVAILABLE,
                "the ollama Python package is not installed",
                provider=self.name,
            ) from exc

    def _search_sync(self, query: str, max_results: int) -> list[SearchResult]:
        ollama = self._ollama_module()
        web_search = getattr(ollama, "web_search", None)
        if web_search is None:
            raise ResearchProviderError(
                RESEARCH_PROVIDER_UNAVAILABLE,
                "installed ollama package does not expose web_search",
                provider=self.name,
            )
        try:
            payload = web_search(query, max_results=max_results)
        except TypeError:
            payload = web_search(query)
        return _parse_search_payload(payload, self.name, max_results)

    def _fetch_sync(self, url: str) -> FetchResult:
        ollama = self._ollama_module()
        web_fetch = getattr(ollama, "web_fetch", None)
        if web_fetch is None:
            raise ResearchProviderError(
                RESEARCH_PROVIDER_UNAVAILABLE,
                "installed ollama package does not expose web_fetch",
                provider=self.name,
            )
        payload = web_fetch(url)
        data = _coerce_mapping(payload)
        title = _clean_text(str(data.get("title") or ""))
        content = _clean_text(str(data.get("content") or ""))
        links = _coerce_links(data.get("links"))
        if len(content) > self.max_content_chars:
            content = content[: self.max_content_chars] + "\n[truncated]"
        return FetchResult(
            url=str(data.get("url") or url),
            title=title,
            content=content,
            links=links,
            provider=self.name,
            ok=True,
        )


class SerpAPIResearchProvider(ResearchProvider):
    """SerpAPI-compatible search provider. Fetch is intentionally unsupported."""

    name = "serpapi"

    def __init__(
        self, settings: SerpAPIResearchSettings, *, timeout_seconds: int, max_content_chars: int, user_agent: str
    ) -> None:
        super().__init__(timeout_seconds=timeout_seconds, max_content_chars=max_content_chars)
        self.settings = settings
        self.user_agent = user_agent

    async def _search(self, query: str, *, max_results: int) -> list[SearchResult]:
        api_key = os.getenv(self.settings.api_key_env)
        if not api_key:
            raise ResearchProviderError(
                RESEARCH_API_KEY_MISSING,
                f"set {self.settings.api_key_env} to use SerpAPI fallback search",
                provider=self.name,
            )
        return await asyncio.to_thread(self._search_sync, query, max_results, api_key)

    async def _fetch(self, url: str) -> FetchResult:
        raise ResearchProviderError(
            RESEARCH_PROVIDER_UNAVAILABLE,
            "SerpAPI provider does not fetch pages",
            provider=self.name,
        )

    def _search_sync(self, query: str, max_results: int, api_key: str) -> list[SearchResult]:
        params = {
            "engine": self.settings.engine,
            "q": query,
            "kl": self.settings.region,
            "num": str(max_results),
            "api_key": api_key,
        }
        url = self.settings.endpoint + "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            raise ResearchProviderError(
                RESEARCH_SEARCH_FAILED,
                f"HTTP {exc.code} from SerpAPI endpoint",
                provider=self.name,
            ) from exc
        except urllib.error.URLError as exc:
            raise ResearchProviderError(
                RESEARCH_SEARCH_FAILED,
                f"network error from SerpAPI endpoint: {exc.reason}",
                provider=self.name,
            ) from exc
        except json.JSONDecodeError as exc:
            raise ResearchProviderError(
                RESEARCH_SEARCH_FAILED,
                "SerpAPI response was not valid JSON",
                provider=self.name,
            ) from exc
        return _parse_search_payload(payload, self.name, max_results)


class StdlibFetchProvider(ResearchProvider):
    """Last-resort stdlib URL fetcher with HTML extraction."""

    name = "stdlib"

    def __init__(self, *, timeout_seconds: int, max_content_chars: int, user_agent: str) -> None:
        super().__init__(timeout_seconds=timeout_seconds, max_content_chars=max_content_chars)
        self.user_agent = user_agent

    async def _search(self, query: str, *, max_results: int) -> list[SearchResult]:
        raise ResearchProviderError(
            RESEARCH_PROVIDER_UNAVAILABLE,
            "stdlib provider does not perform web search",
            provider=self.name,
        )

    async def _fetch(self, url: str) -> FetchResult:
        return await asyncio.to_thread(self._fetch_sync, url)

    def _fetch_sync(self, url: str) -> FetchResult:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.5",
                "Accept-Language": "en-US,en;q=0.5",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                content_type = resp.headers.get("Content-Type", "")
                body = resp.read()
                final_url = resp.geturl()
        except urllib.error.HTTPError as exc:
            return FetchResult(
                url=url,
                provider=self.name,
                ok=False,
                error_code=RESEARCH_FETCH_FAILED,
                error=f"HTTP {exc.code} for URL",
            )
        except urllib.error.URLError as exc:
            return FetchResult(
                url=url,
                provider=self.name,
                ok=False,
                error_code=RESEARCH_FETCH_FAILED,
                error=f"network error: {exc.reason}",
            )
        except Exception as exc:
            return FetchResult(
                url=url,
                provider=self.name,
                ok=False,
                error_code=RESEARCH_FETCH_FAILED,
                error=f"unexpected fetch error: {exc}",
            )

        raw = body.decode("utf-8", errors="replace")
        links: list[str] = []
        title = ""
        if "text/html" in content_type or "application/xhtml" in content_type:
            extractor = _TextExtractor()
            try:
                extractor.feed(raw)
                title = extractor.get_title()
                content = extractor.get_text()
            except Exception:
                content = _fallback_strip_html(raw)
            links = _extract_links(raw, final_url)
        else:
            content = raw

        content = _clean_text(content)
        if len(content) > self.max_content_chars:
            content = content[: self.max_content_chars] + "\n[truncated]"
        return FetchResult(
            url=final_url or url,
            title=_clean_text(title),
            content=content,
            links=links,
            provider=self.name,
            ok=True,
        )


class WebResearcher:
    """Provider-backed read-only web research facade."""

    def __init__(self, settings: WebResearcherSettings, providers: dict[str, ResearchProvider] | None = None) -> None:
        self.settings = settings
        self.providers = providers or self._build_default_providers(settings)
        self._search_cache: OrderedDict[str, tuple[float, list[SearchResult], str, list[str], bool]] = OrderedDict()
        self._fetch_cache: OrderedDict[str, tuple[float, FetchResult, list[str], bool]] = OrderedDict()

    def search(self, query: str) -> str:
        """Sync wrapper for provider-backed web search."""
        return _run_coro_sync(self.search_async(query))

    async def search_async(self, query: str) -> str:
        """Search candidate public sources and return MCP-compatible text."""
        if not self.settings.enabled:
            return f"{RESEARCH_DISABLED}: web research is disabled."
        try:
            results, provider_used, warnings, fallback_used = await self._search_structured_async(query)
        except ResearchProviderError as exc:
            return exc.public_message()
        return self._format_search_results(query, results, provider_used, warnings, fallback_used)

    async def search_results_async(self, query: str) -> list[SearchResult]:
        """Structured async search API for tests and internal callers."""
        results, _provider_used, _warnings, _fallback_used = await self._search_structured_async(query)
        return results

    def fetch_webpage(self, url: str) -> str:
        """Sync wrapper for fetching one source URL."""
        return _run_coro_sync(self.fetch_webpage_async(url))

    async def fetch_webpage_async(self, url: str) -> str:
        """Fetch one URL and return readable text with citation metadata."""
        if not self.settings.enabled:
            return f"{RESEARCH_DISABLED}: web research is disabled."
        try:
            result, warnings, fallback_used = await self._fetch_structured_async(url)
        except ResearchProviderError as exc:
            return exc.public_message()
        return self._format_fetch_result(result, warnings, fallback_used)

    async def fetch_result_async(self, url: str) -> FetchResult:
        """Structured async fetch API for tests and internal callers."""
        result, _warnings, _fallback_used = await self._fetch_structured_async(url)
        return result

    def deep_research(self, query: str, search_fn: Callable[[str], str] | None = None) -> str:
        """Sync wrapper for multi-source structured research."""
        return _run_coro_sync(self.deep_research_async(query, search_fn))

    async def deep_research_async(self, query: str, search_fn: Callable[[str], str] | None = None) -> str:
        """Search, rank, fetch, and summarize multiple public sources.

        ``search_fn`` is retained for legacy callers. It is only used as a
        final fallback if configured providers cannot return candidates.
        """
        brief = await self.build_brief_async(query, search_fn)
        return brief.to_json()

    async def build_brief_async(self, query: str, search_fn: Callable[[str], str] | None = None) -> ResearchBrief:
        timestamp = datetime.now(timezone.utc).isoformat()
        if not self.settings.enabled:
            return ResearchBrief(
                query=str(query or ""),
                timestamp=timestamp,
                provider_used="none",
                sources_searched=[],
                sources_fetched=[],
                key_facts=[],
                confidence="none",
                reliability_notes=["Research is disabled by configuration."],
                relevant_cves=_extract_cves(str(query or "")),
                suggested_next_queries=[],
                status="error",
                error_code=RESEARCH_DISABLED,
                error="web research is disabled",
            )

        clean_query = self._clean_query(query)
        if clean_query.startswith("BLOCKED:"):
            return ResearchBrief(
                query=str(query or ""),
                timestamp=timestamp,
                provider_used="none",
                sources_searched=[],
                sources_fetched=[],
                key_facts=[],
                confidence="none",
                reliability_notes=["The query was rejected before provider use."],
                relevant_cves=_extract_cves(str(query or "")),
                suggested_next_queries=[],
                status="error",
                error_code=RESEARCH_SEARCH_FAILED,
                error=clean_query,
            )

        warnings: list[str] = []
        fallback_used = False
        provider_used = "none"
        try:
            search_results, provider_used, provider_warnings, fallback_used = await self._search_structured_async(
                clean_query
            )
            warnings.extend(provider_warnings)
        except ResearchProviderError as exc:
            warnings.append(exc.public_message())
            if search_fn is None:
                return self._error_brief(
                    clean_query,
                    timestamp,
                    RESEARCH_SEARCH_FAILED,
                    exc.public_message(),
                    warnings,
                )
            legacy_text = await asyncio.to_thread(search_fn, clean_query)
            search_results = self._extract_results_from_text(legacy_text, provider="legacy_search_fn")
            provider_used = "legacy_search_fn"
            fallback_used = True
            if not search_results:
                warnings.append("Legacy search fallback returned no extractable URLs.")
                return self._error_brief(
                    clean_query,
                    timestamp,
                    RESEARCH_SEARCH_FAILED,
                    "no usable search results",
                    warnings,
                )

        ranked_results = self._dedupe_and_rank(search_results)
        searched_sources = [
            self._source_from_search_result(result) for result in ranked_results[: self.settings.max_results]
        ]
        fetch_candidates = self._select_fetch_candidates(ranked_results)
        if not fetch_candidates and ranked_results:
            warnings.append("Only low-quality search results were available; using top snippets only.")
            fetch_candidates = ranked_results[: self.settings.max_fetch_depth]

        fetched_sources: list[ResearchSource] = []
        fact_inputs: list[tuple[str, str]] = []
        for result in fetch_candidates[: self.settings.max_fetch_depth]:
            try:
                fetched, fetch_warnings, fetch_fallback = await self._fetch_structured_async(result.url)
                warnings.extend(fetch_warnings)
                fallback_used = fallback_used or fetch_fallback
            except ResearchProviderError as exc:
                source = self._source_from_search_result(result, warning=exc.public_message())
                fetched_sources.append(source)
                fact_inputs.append((source.snippet, source.url))
                warnings.append(f"Only snippet available for {result.url}: {exc.public_message()}")
                continue

            if fetched.ok and fetched.content:
                source = self._source_from_search_result(
                    result,
                    fetched=True,
                    fetch_provider=fetched.provider,
                    content_excerpt=_excerpt(fetched.content, min(1200, self.settings.max_content_chars)),
                )
                fact_inputs.append((f"{result.content}\n{fetched.content}", fetched.url))
            else:
                warning = fetched.error or "no readable content returned"
                source = self._source_from_search_result(result, warning=warning)
                fact_inputs.append((result.content, result.url))
                warnings.append(f"Only snippet available for {result.url}: {warning}")
            fetched_sources.append(source)

        for source in searched_sources:
            fact_inputs.append((source.snippet, source.url))

        relevant_cves = sorted(set(_extract_cves(clean_query + "\n" + "\n".join(text for text, _ in fact_inputs))))
        key_facts = self._extract_key_facts(fact_inputs)
        confidence, reliability_notes = self._confidence_notes(searched_sources, fetched_sources, warnings)
        suggestions = self._suggest_next_queries(clean_query, relevant_cves, searched_sources)

        status = "ok" if fetched_sources else "partial"
        if not fetched_sources:
            warnings.append("No sources were fetched; brief is based on search snippets only.")

        return ResearchBrief(
            query=clean_query,
            timestamp=timestamp,
            provider_used=provider_used,
            fallback_used=fallback_used,
            sources_searched=searched_sources,
            sources_fetched=fetched_sources,
            key_facts=key_facts,
            confidence=confidence,
            reliability_notes=reliability_notes,
            relevant_cves=relevant_cves,
            suggested_next_queries=suggestions,
            warnings=_dedupe_strings(warnings),
            status=status,
        )

    def _build_default_providers(self, settings: WebResearcherSettings) -> dict[str, ResearchProvider]:
        return {
            "ollama": OllamaResearchProvider(
                settings.ollama,
                timeout_seconds=settings.timeout_seconds,
                max_content_chars=settings.max_content_chars,
            ),
            "serpapi": SerpAPIResearchProvider(
                settings.serpapi,
                timeout_seconds=settings.timeout_seconds,
                max_content_chars=settings.max_content_chars,
                user_agent=settings.user_agent,
            ),
            "stdlib": StdlibFetchProvider(
                timeout_seconds=settings.timeout_seconds,
                max_content_chars=settings.max_content_chars,
                user_agent=settings.user_agent,
            ),
        }

    def _clean_query(self, query: str) -> str:
        text = " ".join(str(query or "").strip().split())
        if not text:
            return "BLOCKED: empty research query."
        if len(text) > 200:
            text = text[:200]
        if re.search(r"[;&|<>`$\\\n\r]", text):
            return "BLOCKED: shell metacharacters in research query."
        return text

    async def _search_structured_async(self, query: str) -> tuple[list[SearchResult], str, list[str], bool]:
        clean_query = self._clean_query(query)
        if clean_query.startswith("BLOCKED:"):
            raise ResearchProviderError(RESEARCH_SEARCH_FAILED, clean_query)

        warnings: list[str] = []
        first_provider = ""
        for provider in self._search_chain():
            if not first_provider:
                first_provider = provider.name
            cache_key = self._search_cache_key(provider, clean_query)
            cached = self._get_search_cached(cache_key)
            if cached is not None:
                results, provider_name, cached_warnings, fallback_used = cached
                return results, provider_name, cached_warnings, fallback_used
            try:
                results = await provider.search(clean_query, max_results=self.settings.max_results)
            except ResearchProviderError as exc:
                warnings.append(exc.public_message())
                continue
            ranked = self._dedupe_and_rank(results)
            if ranked:
                fallback_used = provider.name != first_provider
                self._store_search_cache(cache_key, ranked, provider.name, warnings, fallback_used)
                return ranked, provider.name, warnings, fallback_used
            warnings.append(f"{RESEARCH_SEARCH_FAILED} ({provider.name}): provider returned no results")

        if warnings:
            raise ResearchProviderError(RESEARCH_SEARCH_FAILED, "; ".join(warnings))
        raise ResearchProviderError(RESEARCH_PROVIDER_UNAVAILABLE, "no search providers are configured")

    async def _fetch_structured_async(self, url: str) -> tuple[FetchResult, list[str], bool]:
        clean_url = self._validate_url(url)
        if clean_url.startswith("BLOCKED:"):
            raise ResearchProviderError(RESEARCH_FETCH_FAILED, clean_url)

        warnings: list[str] = []
        first_provider = ""
        for provider in self._fetch_chain():
            if not first_provider:
                first_provider = provider.name
            cache_key = self._fetch_cache_key(provider, clean_url)
            cached = self._get_fetch_cached(cache_key)
            if cached is not None:
                return cached
            try:
                result = await provider.fetch(clean_url)
            except ResearchProviderError as exc:
                warnings.append(exc.public_message())
                continue
            fallback_used = provider.name != first_provider
            self._store_fetch_cache(cache_key, result, warnings, fallback_used)
            return result, warnings, fallback_used

        if warnings:
            raise ResearchProviderError(RESEARCH_FETCH_FAILED, "; ".join(warnings))
        raise ResearchProviderError(RESEARCH_PROVIDER_UNAVAILABLE, "no fetch providers are configured")

    def _search_chain(self) -> list[ResearchProvider]:
        names = [self.settings.provider, self.settings.fallback_provider]
        return [provider for provider in self._provider_chain(names) if provider.name != "stdlib"]

    def _fetch_chain(self) -> list[ResearchProvider]:
        names = [self.settings.provider, self.settings.fallback_provider, "stdlib"]
        return self._provider_chain(names)

    def _provider_chain(self, names: Iterable[str]) -> list[ResearchProvider]:
        chain: list[ResearchProvider] = []
        seen: set[str] = set()
        for name in names:
            normalized = str(name or "").strip().lower()
            if not normalized or normalized in seen:
                continue
            provider = self.providers.get(normalized)
            if provider is None:
                continue
            seen.add(normalized)
            chain.append(provider)
        return chain

    def _validate_url(self, url: str) -> str:
        return validate_url(
            url,
            allowed_domains=self.settings.allowed_domains,
            blocked_domains=self.settings.blocked_domains,
            allow_local_fetch=self.settings.allow_local_fetch,
        )

    def _dedupe_and_rank(self, results: list[SearchResult]) -> list[SearchResult]:
        deduped: dict[str, SearchResult] = {}
        for result in results:
            clean_url = self._validate_url(result.url)
            if clean_url.startswith("BLOCKED:"):
                continue
            key = canonicalize_url(clean_url)
            if key not in deduped:
                deduped[key] = SearchResult(
                    title=result.title or clean_url,
                    url=clean_url,
                    content=result.content,
                    provider=result.provider,
                    rank=result.rank,
                    raw=result.raw,
                )
            else:
                current = deduped[key]
                if len(result.content) > len(current.content):
                    deduped[key] = SearchResult(
                        title=result.title or current.title,
                        url=clean_url,
                        content=result.content,
                        provider=result.provider or current.provider,
                        rank=min(result.rank or current.rank, current.rank or result.rank),
                        raw=result.raw or current.raw,
                    )

        ranked = sorted(
            deduped.values(),
            key=lambda item: (-source_quality_score(item.url, item.title, item.content), item.rank or 999),
        )
        return ranked[: self.settings.max_results]

    def _select_fetch_candidates(self, results: list[SearchResult]) -> list[SearchResult]:
        threshold = _quality_threshold(self.settings.min_source_quality)
        candidates = [
            result for result in results if source_quality_score(result.url, result.title, result.content) >= threshold
        ]
        return candidates[: self.settings.max_fetch_depth]

    def _source_from_search_result(
        self,
        result: SearchResult,
        *,
        fetched: bool = False,
        fetch_provider: str = "",
        content_excerpt: str = "",
        warning: str = "",
    ) -> ResearchSource:
        score = source_quality_score(result.url, result.title, result.content)
        return ResearchSource(
            title=result.title or result.url,
            url=result.url,
            snippet=_excerpt(result.content, 500),
            provider=result.provider,
            quality=source_quality_label(score),
            quality_score=score,
            fetched=fetched,
            fetch_provider=fetch_provider,
            content_excerpt=content_excerpt,
            warning=warning,
        )

    def _extract_results_from_text(self, text: str, *, provider: str) -> list[SearchResult]:
        results: list[SearchResult] = []
        current_title = ""
        rank = 0
        for line in str(text or "").splitlines():
            title_match = re.match(r"\s*(\d+)\.\s+(.+)$", line)
            if title_match:
                rank = int(title_match.group(1))
                current_title = title_match.group(2).strip()
                continue
            url_match = re.search(r"URL:\s*(https?://\S+)", line)
            if url_match:
                results.append(
                    SearchResult(
                        title=current_title or url_match.group(1),
                        url=url_match.group(1).rstrip(".,;:)!?\"'"),
                        provider=provider,
                        rank=rank or len(results) + 1,
                    )
                )
        if results:
            return results
        for idx, match in enumerate(re.finditer(r"https?://[^\s\"'<>]+", str(text or "")), 1):
            url = match.group(0).strip().rstrip(".,;:)!?\"'")
            results.append(SearchResult(title=url, url=url, provider=provider, rank=idx))
        return results

    def _extract_key_facts(self, fact_inputs: list[tuple[str, str]]) -> list[dict[str, str]]:
        facts: list[dict[str, str]] = []
        seen: set[str] = set()
        fact_terms = re.compile(
            r"\b(CVE-\d{4}-\d{4,7}|affected|vulnerab|exploit|proof[- ]of[- ]concept|PoC|"
            r"patch|mitigat|workaround|version|remote code execution|RCE|authentication bypass|"
            r"SQL injection|privilege escalation|CVSS)\b",
            re.IGNORECASE,
        )
        for text, source_url in fact_inputs:
            for sentence in _sentences(text):
                if not fact_terms.search(sentence):
                    continue
                normalized = re.sub(r"\s+", " ", sentence).strip().lower()
                if normalized in seen:
                    continue
                seen.add(normalized)
                facts.append({"fact": _excerpt(sentence, 260), "source_url": source_url})
                if len(facts) >= 10:
                    return facts
        return facts

    def _confidence_notes(
        self,
        searched_sources: list[ResearchSource],
        fetched_sources: list[ResearchSource],
        warnings: list[str],
    ) -> tuple[str, list[str]]:
        high = sum(1 for source in searched_sources if source.quality == "high")
        medium_or_better = sum(1 for source in searched_sources if source.quality in {"high", "medium"})
        fetched_ok = sum(1 for source in fetched_sources if source.fetched)
        notes: list[str] = []
        if high:
            notes.append(f"{high} primary or high-reputation source(s) were found.")
        if fetched_ok:
            notes.append(f"{fetched_ok} source(s) were fetched and read beyond snippets.")
        if warnings:
            notes.append("Some provider/fetch warnings were encountered; review warnings before relying on the brief.")
        if not fetched_ok:
            notes.append("No full pages were fetched, so confidence is limited to search snippets.")

        if fetched_ok >= 2 and high >= 1:
            confidence = "high"
        elif fetched_ok >= 1 and medium_or_better >= 1:
            confidence = "medium"
        elif searched_sources:
            confidence = "low"
        else:
            confidence = "none"
        return confidence, notes

    def _suggest_next_queries(self, query: str, cves: list[str], sources: list[ResearchSource]) -> list[str]:
        suggestions: list[str] = []
        for cve in cves[:3]:
            suggestions.extend(
                [
                    f"{cve} vendor advisory mitigation",
                    f"{cve} NVD references",
                    f"{cve} exploit-db github PoC",
                ]
            )
        if not suggestions:
            suggestions.extend(
                [
                    f"{query} vendor advisory",
                    f"{query} NVD CVE",
                    f"{query} github proof of concept",
                    f"{query} mitigation patch workaround",
                ]
            )
        if not any("site:nvd.nist.gov" in item for item in suggestions):
            suggestions.append(f"site:nvd.nist.gov {query}")
        if sources and not any("exploit-db" in source.url.lower() for source in sources):
            suggestions.append(f"site:exploit-db.com {query}")
        return _dedupe_strings(suggestions)[:8]

    def _format_search_results(
        self,
        query: str,
        results: list[SearchResult],
        provider_used: str,
        warnings: list[str],
        fallback_used: bool,
    ) -> str:
        clean_query = self._clean_query(query)
        if not results:
            return f"{RESEARCH_SEARCH_FAILED}: no results for {clean_query!r}"
        lines = [
            "WEB_SEARCH_RESULTS:",
            f"QUERY: {clean_query}",
            f"PROVIDER: {provider_used}",
            f"FALLBACK_USED: {str(fallback_used).lower()}",
        ]
        for warning in _dedupe_strings(warnings):
            lines.append(f"WARNING: {warning}")
        lines.append("")
        for index, result in enumerate(results[: self.settings.max_results], 1):
            score = source_quality_score(result.url, result.title, result.content)
            lines.extend(
                [
                    f"{index}. {result.title or 'Untitled'}",
                    f"   URL: {result.url}",
                    f"   Quality: {source_quality_label(score)}",
                    f"   Summary: {_excerpt(result.content, 500)}",
                ]
            )
        return "\n".join(lines)

    def _format_fetch_result(self, result: FetchResult, warnings: list[str], fallback_used: bool) -> str:
        lines: list[str] = []
        if not result.ok:
            lines.append(f"{result.error_code or RESEARCH_FETCH_FAILED}: {result.error}")
        else:
            lines.extend(
                [
                    f"FETCHED: {result.url}",
                    f"PROVIDER: {result.provider}",
                    f"FALLBACK_USED: {str(fallback_used).lower()}",
                ]
            )
            if result.title:
                lines.append(f"TITLE: {result.title}")
            for warning in _dedupe_strings(warnings):
                lines.append(f"WARNING: {warning}")
            lines.extend(["CONTENT:", result.content])
            if result.links:
                lines.append("LINKS:")
                lines.extend(f"- {link}" for link in result.links[:20])
        return "\n".join(lines)

    def _error_brief(
        self,
        query: str,
        timestamp: str,
        code: str,
        error: str,
        warnings: list[str],
    ) -> ResearchBrief:
        return ResearchBrief(
            query=query,
            timestamp=timestamp,
            provider_used="none",
            sources_searched=[],
            sources_fetched=[],
            key_facts=[],
            confidence="none",
            reliability_notes=["Research could not complete."],
            relevant_cves=_extract_cves(query),
            suggested_next_queries=[],
            warnings=_dedupe_strings(warnings),
            status="error",
            error_code=code,
            error=error,
        )

    def _search_cache_key(self, provider: ResearchProvider, query: str) -> str:
        return f"{provider.name}|{self.settings.max_results}|{query}"

    def _fetch_cache_key(self, provider: ResearchProvider, url: str) -> str:
        return f"{provider.name}|{self.settings.max_content_chars}|{url}"

    def _get_search_cached(self, key: str) -> tuple[list[SearchResult], str, list[str], bool] | None:
        if key in self._search_cache:
            ts, results, provider_name, warnings, fallback_used = self._search_cache[key]
            if time.monotonic() - ts < self.settings.cache_ttl_seconds:
                self._search_cache.move_to_end(key)
                return results, provider_name, warnings, fallback_used
            del self._search_cache[key]
        return None

    def _store_search_cache(
        self,
        key: str,
        results: list[SearchResult],
        provider_name: str,
        warnings: list[str],
        fallback_used: bool,
    ) -> None:
        self._search_cache[key] = (time.monotonic(), results, provider_name, _dedupe_strings(warnings), fallback_used)
        while len(self._search_cache) > self.settings.cache_max_entries:
            self._search_cache.popitem(last=False)

    def _get_fetch_cached(self, key: str) -> tuple[FetchResult, list[str], bool] | None:
        if key in self._fetch_cache:
            ts, result, warnings, fallback_used = self._fetch_cache[key]
            if time.monotonic() - ts < self.settings.cache_ttl_seconds:
                self._fetch_cache.move_to_end(key)
                return result, warnings, fallback_used
            del self._fetch_cache[key]
        return None

    def _store_fetch_cache(self, key: str, result: FetchResult, warnings: list[str], fallback_used: bool) -> None:
        self._fetch_cache[key] = (time.monotonic(), result, _dedupe_strings(warnings), fallback_used)
        while len(self._fetch_cache) > self.settings.cache_max_entries:
            self._fetch_cache.popitem(last=False)


class _TextExtractor(HTMLParser):
    """Small HTML-to-readable-text extractor."""

    _skip_container_tags = {
        "script",
        "style",
        "nav",
        "footer",
        "header",
        "aside",
        "noscript",
        "svg",
        "form",
        "iframe",
        "canvas",
        "video",
        "audio",
        "button",
        "select",
        "textarea",
        "picture",
        "object",
        "applet",
        "map",
        "figure",
    }
    _block_tags = {
        "p",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "li",
        "td",
        "th",
        "pre",
        "blockquote",
        "article",
        "main",
        "section",
        "div",
        "tr",
        "ul",
        "ol",
        "dl",
        "dt",
        "dd",
        "figcaption",
        "details",
        "summary",
        "fieldset",
        "legend",
    }

    def __init__(self) -> None:
        super().__init__()
        self._text: list[str] = []
        self._title: list[str] = []
        self._skip_depth = 0
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        if tag_lower in self._skip_container_tags:
            self._skip_depth += 1
            return
        if self._skip_depth > 0:
            return
        if tag_lower == "title":
            self._in_title = True
            return
        if tag_lower in self._block_tags and self._text and self._text[-1] != "\n":
            self._text.append("\n")

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if tag_lower in self._skip_container_tags:
            if self._skip_depth > 0:
                self._skip_depth -= 1
            return
        if self._skip_depth > 0:
            return
        if tag_lower == "title":
            self._in_title = False
            return
        if tag_lower in self._block_tags and self._text and self._text[-1] != "\n":
            self._text.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth > 0:
            return
        text = html.unescape(data).strip()
        if not text:
            return
        if self._in_title:
            self._title.append(text)
        else:
            self._text.append(f" {text} ")

    def get_title(self) -> str:
        return _clean_text(" ".join(self._title))

    def get_text(self) -> str:
        return _clean_text("".join(self._text))


def validate_url(
    url: str,
    *,
    allowed_domains: list[str] | None = None,
    blocked_domains: list[str] | None = None,
    allow_local_fetch: bool = False,
) -> str:
    """Validate and normalize a URL, blocking private/internal fetch targets."""

    raw = str(url or "").strip().strip("\"'")
    if not raw:
        return "BLOCKED: empty URL."
    if len(raw) > 2000:
        return "BLOCKED: URL too long."
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw

    try:
        parsed = urlparse(raw)
    except Exception:
        return f"BLOCKED: malformed URL: {raw[:100]}"

    if parsed.scheme not in {"http", "https"}:
        return f"BLOCKED: only http/https URLs allowed, got {parsed.scheme}."

    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        return "BLOCKED: URL has no hostname."

    if not allow_local_fetch and is_private_or_internal_host(hostname):
        return f"BLOCKED: private/internal host not allowed: {hostname}"

    allowed = allowed_domains or []
    if allowed and not any(_domain_matches(hostname, domain) for domain in allowed):
        return f"BLOCKED: domain {hostname} not in allowed_domains."

    for domain in blocked_domains or []:
        if _domain_matches(hostname, domain):
            return f"BLOCKED: domain {hostname} is in blocked_domains."

    return urlunparse(parsed._replace(fragment=""))


def is_private_or_internal_host(hostname: str) -> bool:
    host = hostname.strip().lower().strip("[]").rstrip(".")
    if host in {"localhost", "localhost.localdomain", "0.0.0.0"}:
        return True
    if host.endswith((".localhost", ".local", ".internal", ".lan", ".home", ".corp")):
        return True
    if "." not in host and ":" not in host:
        return True

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified


def canonicalize_url(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urlunparse((scheme, netloc, path, "", parsed.query, ""))


def source_quality_score(url: str, title: str = "", content: str = "") -> int:
    host = (urlparse(url).hostname or "").lower()
    text = f"{title} {content}".lower()
    score = 50

    primary_hosts = (
        "nvd.nist.gov",
        "cve.org",
        "github.com",
        "gitlab.com",
        "exploit-db.com",
        "packetstormsecurity.com",
        "msrc.microsoft.com",
        "support.microsoft.com",
        "apache.org",
        "openssl.org",
        "openssh.com",
        "cisco.com",
        "redhat.com",
        "ubuntu.com",
        "debian.org",
        "oracle.com",
        "vmware.com",
        "citrix.com",
        "fortinet.com",
        "paloaltonetworks.com",
        "juniper.net",
        "atlassian.com",
        "jenkins.io",
        "docker.com",
        "kubernetes.io",
    )
    reputable_hosts = (
        "rapid7.com",
        "tenable.com",
        "qualys.com",
        "cloudflare.com",
        "googleprojectzero.blogspot.com",
        "projectdiscovery.io",
        "watchtowr.com",
        "horizon3.ai",
        "wiz.io",
        "sonatype.com",
        "snyk.io",
        "huntr.com",
        "vulners.com",
        "cvedetails.com",
    )
    spam_terms = (
        "coupon",
        "casino",
        "apk",
        "crack",
        "warez",
        "free download",
        "top 10",
        "what is",
        "essay",
        "assignment",
        "seo",
    )

    if any(host == domain or host.endswith("." + domain) for domain in primary_hosts):
        score += 35
    elif any(host == domain or host.endswith("." + domain) for domain in reputable_hosts):
        score += 20
    if "advisory" in text or "security bulletin" in text:
        score += 8
    if "cve-" in text:
        score += 5
    if "proof-of-concept" in text or "poc" in text:
        score += 3
    if any(term in text or term in host for term in spam_terms):
        score -= 35
    if len(content) < 40:
        score -= 5
    return max(0, min(100, score))


def source_quality_label(score: int) -> str:
    if score >= 75:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def _quality_threshold(label: str) -> int:
    normalized = str(label or "medium").lower()
    if normalized == "high":
        return 75
    if normalized == "low":
        return 0
    return 45


def _parse_search_payload(payload: Any, provider: str, max_results: int) -> list[SearchResult]:
    data = _coerce_mapping(payload)
    items = data.get("results") or data.get("organic_results") or data.get("items") or payload
    if not isinstance(items, list):
        items = []

    results: list[SearchResult] = []
    for idx, item in enumerate(items[:max_results], 1):
        item_data = _coerce_mapping(item)
        if item_data.get("error"):
            continue
        title = _clean_text(str(item_data.get("title") or item_data.get("name") or "Untitled"))
        url = str(item_data.get("url") or item_data.get("link") or item_data.get("href") or "").strip()
        content = _clean_text(
            str(
                item_data.get("content")
                or item_data.get("snippet")
                or item_data.get("description")
                or item_data.get("summary")
                or ""
            )
        )
        if not url:
            continue
        results.append(SearchResult(title=title, url=url, content=content, provider=provider, rank=idx, raw=item_data))
    return results


def _coerce_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        dumped = value.model_dump()
        return dumped if isinstance(dumped, dict) else {}
    if hasattr(value, "dict"):
        dumped = value.dict()
        return dumped if isinstance(dumped, dict) else {}
    if hasattr(value, "__dict__"):
        return dict(value.__dict__)
    return {}


def _coerce_links(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    links: list[str] = []
    for item in value:
        if isinstance(item, str):
            links.append(item)
        elif isinstance(item, dict):
            url = item.get("url") or item.get("href") or item.get("link")
            if url:
                links.append(str(url))
    return _dedupe_strings(links)[:100]


def _extract_links(html_text: str, base_url: str) -> list[str]:
    links: list[str] = []
    for match in re.finditer(r"""href=["']([^"']+)["']""", html_text, re.IGNORECASE):
        href = html.unescape(match.group(1)).strip()
        if not href or href.startswith(("#", "mailto:", "javascript:", "tel:")):
            continue
        links.append(urljoin(base_url, href))
    return _dedupe_strings(links)[:100]


def _fallback_strip_html(html_text: str) -> str:
    text = re.sub(r"<script[^>]*>.*?</script>", "", html_text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<noscript[^>]*>.*?</noscript>", "", text, flags=re.DOTALL | re.IGNORECASE)
    for tag in ("p", "div", "br", "h1", "h2", "h3", "h4", "h5", "h6", "li", "tr", "article", "section"):
        text = re.sub(rf"<{tag}[^>]*>", "\n", text, flags=re.IGNORECASE)
        text = re.sub(rf"</{tag}>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    return _clean_text(html.unescape(text))


def _clean_text(value: str) -> str:
    text = html.unescape(str(value or ""))
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r" \n", "\n", text)
    text = re.sub(r"\n ", "\n", text)
    return text.strip()


def _excerpt(text: str, max_chars: int) -> str:
    cleaned = _clean_text(text)
    if len(cleaned) <= max_chars:
        return cleaned
    return cleaned[:max_chars].rstrip() + "..."


def _extract_cves(text: str) -> list[str]:
    return sorted({match.upper() for match in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text or "", re.IGNORECASE)})


def _sentences(text: str) -> list[str]:
    cleaned = re.sub(r"\s+", " ", _clean_text(text))
    if not cleaned:
        return []
    parts = re.split(r"(?<=[.!?])\s+", cleaned)
    return [part.strip() for part in parts if 40 <= len(part.strip()) <= 500]


def _dedupe_strings(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _domain_matches(hostname: str, domain: str) -> bool:
    normalized = str(domain or "").strip().lower().rstrip(".")
    if not normalized:
        return False
    return hostname == normalized or hostname.endswith("." + normalized)


def _run_coro_sync(coro):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    if not loop.is_running():
        return loop.run_until_complete(coro)

    result_box: dict[str, Any] = {}

    def runner() -> None:
        try:
            result_box["result"] = asyncio.run(coro)
        except BaseException as exc:  # pragma: no cover - defensive bridge
            result_box["error"] = exc

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join()
    if "error" in result_box:
        raise result_box["error"]
    return result_box.get("result")
