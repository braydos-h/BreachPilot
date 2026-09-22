#!/usr/bin/env python3
"""Release-truth guard: every URL advertised in an install section must resolve (todo 09).

Extracts all ``http(s)://`` URLs between ``--start`` and ``--end`` markers
in a Markdown file, GETs each one (following redirects), and fails on any
non-2xx status. Also enforces the sha256 + signature path: whenever the
section advertises a ``releases/download/`` asset, the sibling ``.sha256``
URL and a ``verify-installer.sh`` reference must appear in the same section.

Defaults cover the README Linux install section; pass ``--file``/``--start``/
``--end`` for mirrors such as ``docs/deployment.md``. Wired into the CI
``release-truth`` job so a 404 install URL can never ship again. Stdlib only.
"""

from __future__ import annotations

import argparse
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

URL_RE = re.compile(r"https?://[^\s)`\]\"'<]+")
TRAILING_PUNCT_RE = re.compile(r"[.,;:!?]+$")

DEFAULT_FILE = "README.md"
DEFAULT_START = "### Linux (primary)"
DEFAULT_END = "### Windows (secondary)"

TIMEOUT_SECONDS = 30
MAX_ATTEMPTS = 3


def extract_section(path: Path, start: str, end: str) -> str:
    text = path.read_text(encoding="utf-8")
    begin = text.find(start)
    if begin < 0:
        raise ValueError(f"{path}: start marker not found: {start!r}")
    finish = text.find(end, begin + len(start))
    if finish < 0:
        raise ValueError(f"{path}: end marker not found: {end!r}")
    return text[begin:finish]


def extract_urls(section: str) -> list[str]:
    urls: list[str] = []
    for match in URL_RE.finditer(section):
        url = TRAILING_PUNCT_RE.sub("", match.group(0))
        if url not in urls:
            urls.append(url)
    return urls


def is_loopback(url: str) -> bool:
    """Loopback service addresses (WebUI origin comments) are not downloads."""
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    return host in ("localhost", "::1") or host.startswith("127.")


def fetch_status(url: str) -> int:
    """GET the URL (following redirects), returning the final HTTP status.

    Reads one byte so large artifacts (tarballs) are never downloaded fully.
    Retries transient network errors; HTTP error statuses are returned, not
    raised, so the caller can report them.
    """
    last_error = "unknown error"
    for _ in range(MAX_ATTEMPTS):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "BreachPilot-release-truth/1.0"})
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                response.read(1)
                return int(response.status)
        except urllib.error.HTTPError as exc:
            return int(exc.code)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = str(exc) or type(exc).__name__
    raise OSError(f"{url}: unreachable after {MAX_ATTEMPTS} attempts ({last_error})")


def check_section(path: Path, start: str, end: str) -> list[str]:
    problems: list[str] = []
    try:
        section = extract_section(path, start, end)
    except (OSError, ValueError) as exc:
        return [str(exc)]
    urls = extract_urls(section)
    if not urls:
        return [f"{path}: no URLs found between {start!r} and {end!r}"]
    for url in urls:
        if is_loopback(url):
            print(f"  SKIP loopback {url}")
            continue
        try:
            status = fetch_status(url)
        except OSError as exc:
            problems.append(str(exc))
            continue
        if 200 <= status < 300:
            print(f"  OK {status} {url}")
        else:
            problems.append(f"{url}: HTTP {status} (install URL must resolve)")
    if any("releases/download/" in url for url in urls):
        if not any(url.endswith(".sha256") for url in urls):
            problems.append(f"{path}: releases/download asset without a sibling .sha256 URL in the same section")
        if "verify-installer" not in section:
            problems.append(f"{path}: releases/download asset without a verify-installer.sh reference")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail if any install-section URL 404s.")
    parser.add_argument("--file", default=DEFAULT_FILE, help="Markdown file, repo-relative (default: README.md)")
    parser.add_argument("--start", default=DEFAULT_START, help="section start marker")
    parser.add_argument("--end", default=DEFAULT_END, help="section end marker")
    args = parser.parse_args(argv)
    path = REPO / args.file
    print(f"release-truth: {args.file} [{args.start} -> {args.end}]")
    problems = check_section(path, args.start, args.end)
    if problems:
        print("release-truth FAILED:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("release-truth passed: every install-section URL resolves")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
