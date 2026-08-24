"""Tier 4 regression tests: defensive-server allowlist CIDR-subset fix and the
``run_exploit_terminal`` tool-layer target-IP lock (LAB BUILD: the destructive /
interpreter-``-c`` / ``find -exec`` gates were removed; the allowlist is the one
attack-mode safety kept -- no pivoting to other hosts).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mcp_server import _is_in_allowlist

# ── _is_in_allowlist: CIDR-subset-of-CIDR (the gap the old matcher missed) ─────


def test_is_in_allowlist_exact_ip():
    assert _is_in_allowlist("10.0.0.50", ["10.0.0.50"]) is True


def test_is_in_allowlist_ip_in_cidr():
    assert _is_in_allowlist("10.0.0.50", ["10.0.0.0/24"]) is True


def test_is_in_allowlist_ip_outside_cidr():
    assert _is_in_allowlist("10.0.1.50", ["10.0.0.0/24"]) is False


def test_is_in_allowlist_cidr_subset_of_bigger_cidr():
    """A /24 asset against a /16 allow entry must be accepted (subnet_of).

    The old hand-rolled matcher called ``ipaddress.ip_address(asset)`` which
    raises on a CIDR, skipping the containment loop and returning False -- so
    an approved /24 was wrongly refused when the allowlist held a /16."""
    assert _is_in_allowlist("10.0.0.0/24", ["10.0.0.0/16"]) is True


def test_is_in_allowlist_cidr_equal():
    assert _is_in_allowlist("10.0.0.0/24", ["10.0.0.0/24"]) is True


def test_is_in_allowlist_cidr_not_subset():
    assert _is_in_allowlist("10.1.0.0/24", ["10.0.0.0/16"]) is False


def test_is_in_allowlist_wildcard_domain():
    assert _is_in_allowlist("api.example.com", ["*.example.com"]) is True


def test_is_in_allowlist_empty_allow():
    assert _is_in_allowlist("10.0.0.50", []) is False


# ── run_exploit_terminal: tool-layer target-IP lock (LAB BUILD) ──────────────


def _text(result) -> str:
    content = result[0] if isinstance(result, (list, tuple)) else result
    if hasattr(content, "content"):
        content = content.content
    parts = []
    for c in content:
        t = getattr(c, "text", None)
        if t is None and isinstance(c, dict):
            t = c.get("text")
        if t is None:
            t = str(c)
        parts.append(t)
    return "".join(parts)


@pytest.mark.asyncio
async def test_terminal_does_not_block_benign_nmap(tmp_path: Path):
    """LAB BUILD: the destructive / interpreter-``-c`` / ``find -exec`` gates were
    removed, so the ONLY block on a benign scan is the target-IP allowlist. Use
    an out-of-scope target (require_explicit_allowlist=True, 10.0.0.99 not
    allowed) so the allowlist refuses it; the block reason must be the allowlist
    ("not in the explicit allowlist"), NOT any removed destructive/interpreter
    gate (i.e. the target lock does not false-fire old-gate reasons)."""
    from mcp_exploit_server import create_mcp_server
    from tools.cve_lookup import CVESearchSettings, NVDClient
    from tools.exploit_search import ExploitSearch, ExploitSearchSettings
    from tools.web_researcher import WebResearcher, WebResearcherSettings

    mcp = create_mcp_server(
        ExploitSearch(ExploitSearchSettings()),
        NVDClient(CVESearchSettings()),
        WebResearcher(WebResearcherSettings()),
        tmp_path,
        {"exploit": {"require_explicit_allowlist": True, "allowed_targets": ["10.0.0.50"]}},
    )
    text = _text(await mcp.call_tool(
        "run_exploit_terminal", {"command": "nmap -sV 10.0.0.99"},
    ))
    # The target-IP allowlist refuses the out-of-scope scan...
    assert "blocked" in text.lower() or "BLOCKED" in text
    assert "not in the explicit allowlist" in text
    # ...and the removed destructive/interpreter gates do not supply the reason.
    assert "interpreter -c" not in text
    assert "find -exec" not in text
    assert "find -delete" not in text
