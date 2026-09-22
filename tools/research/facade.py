"""WebResearcher facade: search / fetch / deep-research orchestration (split from tools.web_researcher)."""

from __future__ import annotations

import asyncio
import re
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from tools.research.models import (
    RESEARCH_DISABLED,
    RESEARCH_FETCH_FAILED,
    RESEARCH_PROVIDER_UNAVAILABLE,
    RESEARCH_SEARCH_FAILED,
    FetchResult,
    ResearchBrief,
    ResearchProviderError,
    ResearchSource,
    SearchResult,
    WebResearcherSettings,
)
from tools.research.providers import (
    OllamaResearchProvider,
    ResearchProvider,
    SerpAPIResearchProvider,
    StdlibFetchProvider,
)
from tools.research.text_utils import (
    _dedupe_strings,
    _excerpt,
    _extract_cves,
    _quality_threshold,
    _run_coro_sync,
    _sentences,
    canonicalize_url,
    source_quality_label,
    source_quality_score,
    validate_url,
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
        # ponytail perf: fetches are independent read-only HTTP — run them
        # concurrently (was serial await, up to max_fetch_depth × timeout).
        # gather preserves candidate order so downstream ranking is unchanged.
        fetch_targets = fetch_candidates[: self.settings.max_fetch_depth]

        async def _fetch_one(
            result: SearchResult,
        ) -> tuple[SearchResult, FetchResult | None, list[str], bool, str]:
            try:
                fetched, fetch_warnings, fetch_fallback = await self._fetch_structured_async(result.url)
                return (result, fetched, list(fetch_warnings), bool(fetch_fallback), "")
            except ResearchProviderError as exc:
                return (result, None, [], False, exc.public_message())

        fetch_outcomes: list[Any] = []
        if fetch_targets:
            fetch_outcomes = await asyncio.gather(*(_fetch_one(r) for r in fetch_targets), return_exceptions=True)
        for outcome in fetch_outcomes:
            if isinstance(outcome, Exception):
                warnings.append(f"Fetch failed: {outcome}")
                continue
            result, fetched, fetch_warnings, fetch_fallback, err_code = outcome
            warnings.extend(fetch_warnings)
            fallback_used = fallback_used or fetch_fallback
            if fetched is None:
                source = self._source_from_search_result(result, warning=err_code)
                fetched_sources.append(source)
                fact_inputs.append((source.snippet, source.url))
                warnings.append(f"Only snippet available for {result.url}: {err_code}")
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
