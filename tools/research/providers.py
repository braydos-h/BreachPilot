"""Research providers: ResearchProvider base plus Ollama / SerpAPI / stdlib-fetch backends (split from tools.web_researcher)."""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from typing import Any

from tools.research.models import (
    RESEARCH_API_KEY_MISSING,
    RESEARCH_FETCH_FAILED,
    RESEARCH_PROVIDER_UNAVAILABLE,
    RESEARCH_SEARCH_FAILED,
    FetchResult,
    OllamaResearchSettings,
    ResearchProviderError,
    SearchResult,
    SerpAPIResearchSettings,
)
from tools.research.text_utils import (
    _clean_text,
    _coerce_links,
    _coerce_mapping,
    _extract_links,
    _fallback_strip_html,
    _parse_search_payload,
    _TextExtractor,
)


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
