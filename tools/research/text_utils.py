"""Research text utilities: HTML extraction, URL validation, quality scoring, excerpts, CVE parsing (split from tools.web_researcher)."""

from __future__ import annotations

import asyncio
import html
import ipaddress
import re
import threading
from html.parser import HTMLParser
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse, urlunparse

from tools.research.models import SearchResult


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
