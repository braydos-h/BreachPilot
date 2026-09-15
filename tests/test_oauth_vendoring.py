"""TODO 015: vendored openai-oauth provenance is machine-verifiable."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_vendor_json_matches_bootstrap_pins():
    vendor = json.loads((REPO / "third_party" / "openai-oauth.VENDOR.json").read_text(encoding="utf-8"))
    assert vendor["upstream"] == "https://github.com/EvanZhouDev/openai-oauth.git"
    assert vendor["commit"]
    from tools.chatgpt_bootstrap import OPENAI_OAUTH_COMMIT, OPENAI_OAUTH_REPO, OPENAI_OAUTH_TAG

    assert vendor["upstream"] == OPENAI_OAUTH_REPO
    assert vendor["tag"] == OPENAI_OAUTH_TAG
    assert vendor["commit"] == OPENAI_OAUTH_COMMIT
    # Patches listed must exist; empty list is valid (no local mods).
    for patch in vendor.get("local_patches", []):
        assert (REPO / "third_party" / "patches" / "openai-oauth" / patch).exists()


def test_is_authenticated_is_existence_only():
    from tools.providers import chatgpt_provider

    src = inspect.getsource(chatgpt_provider.ChatGptProxyManager.is_authenticated)
    assert "exists" in src or "is_file" in src or "stat" in src
    # Must never read token contents.
    for forbidden in ("read_text", "read_bytes", "open(", "json.load"):
        assert forbidden not in src, f"is_authenticated must not {forbidden}"
