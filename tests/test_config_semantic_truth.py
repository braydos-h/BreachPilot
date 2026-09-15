"""Semantic config/docs truth guard (#08).

Syntax/link/version checks cannot catch contradictions such as
``document A: fallback_native defaults true`` vs ``schema: false``.
This test is the executable form of the single-source-of-truth rule:
the schema default, the shipped ``config.yaml``, and the user-facing
docs must agree on safety-critical defaults. If the default ever
intentionally changes, update schema + config.yaml + docs together —
this test will tell you which side drifted.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent


def _load_schema() -> dict:
    from tools.config_manager import CONFIG_SCHEMA

    return CONFIG_SCHEMA


def test_sandbox_safety_defaults_single_source():
    schema = _load_schema()
    sandbox = schema["sandbox"]
    # Canonical truth: default-ON containment, fail-closed (no native fallback).
    assert sandbox["enabled"] is True
    assert sandbox["fallback_native"] is False
    assert sandbox["backend"] == "docker"
    assert sandbox["image"] == "breachpilot-sandbox:latest"


def test_shipped_config_matches_schema_sandbox_defaults():
    schema = _load_schema()
    cfg = yaml.safe_load((REPO / "config.yaml").read_text(encoding="utf-8"))
    for key in ("enabled", "fallback_native", "backend", "image"):
        assert cfg["sandbox"][key] == schema["sandbox"][key], (
            f"config.yaml sandbox.{key}={cfg['sandbox'][key]!r} drifts from schema default {schema['sandbox'][key]!r}"
        )


def test_exploit_permission_defaults_documented():
    """Schema default is full_access (lab); missing-key fallback is read_only.

    Both are true at once: the checked-in config explicitly sets
    full_access, while _resolve_exploit_permission falls back to read_only
    when the key is absent so a partial config never silently goes live.
    """
    schema = _load_schema()
    assert schema["exploit"]["permission"] == "full_access"
    cfg = yaml.safe_load((REPO / "config.yaml").read_text(encoding="utf-8"))
    assert cfg["exploit"]["permission"] == "full_access"
    from tools.cli_exploit_settings import _resolve_exploit_permission

    assert _resolve_exploit_permission({}) == "read_only"


def test_no_doc_claims_fallback_native_defaults_true():
    """No user-facing doc may claim the native fallback defaults to true."""
    offenders: list[str] = []
    # Phrases that assert a true default (case-insensitive).
    default_true_re = re.compile(
        r"fallback_native[^.\n]{0,80}default[^.\n]{0,20}true",
        re.IGNORECASE,
    )
    alt_re = re.compile(
        r"default[^.\n]{0,20}[:(]?\s*fallback_native[^.\n]{0,20}true",
        re.IGNORECASE,
    )
    true_default_re = re.compile(
        r"\(the default\)[^.\n]{0,60}fallback_native|fallback_native[^.\n]{0,20}\(the default\)",
        re.IGNORECASE,
    )
    scan = [REPO / "README.md", REPO / "CLAUDE.md", REPO / "AGENTS.md"]
    scan += sorted((REPO / "docs").rglob("*.md"))
    for path in scan:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        # Strip fenced code blocks: yaml examples showing
        # `fallback_native: true` as an explicit opt-in are fine.
        text_nofence = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
        for regex in (default_true_re, alt_re, true_default_re):
            for match in regex.finditer(text_nofence):
                # Allow sentences that explicitly say the default is FALSE.
                snippet = text_nofence[max(0, match.start() - 60) : match.end() + 60]
                if re.search(r"default\s*[`'\"]?\s*false", snippet, re.IGNORECASE):
                    continue
                offenders.append(f"{path.relative_to(REPO)}: {match.group(0).strip()[:100]}")
    assert not offenders, "stale fallback_native default claims:\n" + "\n".join(offenders)


def test_schema_config_top_level_keys_in_sync():
    from tools.config_manager import CONFIG_SCHEMA

    cfg = yaml.safe_load((REPO / "config.yaml").read_text(encoding="utf-8"))
    assert set(cfg) == set(CONFIG_SCHEMA), (
        f"config.yaml and CONFIG_SCHEMA drift: "
        f"extra in yaml {sorted(set(cfg) - set(CONFIG_SCHEMA))}, "
        f"missing in yaml {sorted(set(CONFIG_SCHEMA) - set(cfg))}"
    )


def test_readme_headline_leads_with_reliability_not_stale_counts():
    """#01: the first screen must not hardcode rotted capability counts."""
    text = (REPO / "README.md").read_text(encoding="utf-8")
    first_screen = "\n".join(text.splitlines()[:30])
    assert "139 skills, 153 MCP tools" not in first_screen
    assert "139 skills" not in first_screen or "146" in first_screen
    # Reliability contract is linked from the headline.
    assert "reliability-metrics" in first_screen
    # Generated catalogs exist and are linked.
    assert (REPO / "docs/mcp/tool-catalog-generated.md").exists()
    assert (REPO / "docs/skills/catalog.md").exists()
    assert "tool-catalog-generated" in text
    assert "docs/reliability-metrics.md" in text
    assert (REPO / "docs/reliability-metrics.md").exists()


def test_two_layer_scope_sandbox_claim_present():
    """TODO 016: canonical two-layer statement must exist in README + safety docs."""
    canonical = (
        "Commands are scope-checked at the application layer, "
        "while the sandbox network boundary independently enforces "
        "the effective destination allowlist."
    )
    for rel in ("README.md", "docs/safety-model.md", "docs/sandbox.md"):
        text = (REPO / rel).read_text(encoding="utf-8")
        assert canonical in text, f"{rel} missing two-layer scope+sandbox sentence"


def test_credential_vault_docs_fail_closed():
    """TODO 004: vault docs must state fail-closed default + opt-in env + HMAC downgrade."""
    text = (REPO / "docs" / "credential-vault.md").read_text(encoding="utf-8")
    assert "fail closed" in text.lower(), "vault docs must state fail-closed default"
    assert "BREACHPILOT_ALLOW_PLAINTEXT_VAULT" in text
    assert "confirmed=True" in text and "downgrad" in text.lower()
    assert "silent" not in text.lower() or "never silent" in text.lower() or "fail" in text.lower()
