"""Injection regression corpus (#16): prompt/tool/MCP/memory layers.

The JSON corpus (tests/fixtures/injection_corpus.json) is the shared,
reviewable attack-string set; this test asserts each layer handles its
cases. Tool-arg shell injection has deeper coverage in
test_mcp_injection_hardening.py (40 tests) — here the corpus pins the
cross-layer contract in one place.
"""

from __future__ import annotations

import json
from pathlib import Path

CORPUS = json.loads((Path(__file__).parent / "fixtures" / "injection_corpus.json").read_text(encoding="utf-8"))["cases"]


def _by_id(case_id: str) -> dict:
    return next(c for c in CORPUS if c["id"] == case_id)


def test_corpus_is_versioned_and_covers_all_layers():
    layers = {c["layer"] for c in CORPUS}
    assert layers == {"prompt", "tool", "mcp", "memory"}
    assert all(c["expect"] for c in CORPUS)


def test_prompt_layer_directives_sanitized_or_wrapped():
    from tools.skill_registry import _sanitize_skill_body, _wrap_untrusted

    for case in [c for c in CORPUS if c["layer"] == "prompt"]:
        if case["expect"] == "preserved":
            assert "enumerate SMB shares" in _sanitize_skill_body(case["payload"])
            continue
        clean = _sanitize_skill_body(case["payload"])
        wrapped = _wrap_untrusted(clean)
        # Either the directive is gone, or the surviving text is explicitly
        # marked untrusted for the model.
        assert ("Ignore all previous" not in clean and "SYSTEM:" not in clean and "run tool:" not in clean) or (
            "<untrusted_skill_guidance" in wrapped
        )


def test_tool_layer_rejects_command_chaining():
    from tools.validation_utils import validate_target_or_ip

    for case in [c for c in CORPUS if c["layer"] == "tool"]:
        result = validate_target_or_ip(case["payload"])
        assert result is (case["expect"] == "accepted"), case["id"]


def test_mcp_layer_content_never_executes():
    from tools.skill_registry import _sanitize_skill_body, _wrap_untrusted

    for case in [c for c in CORPUS if c["layer"] == "mcp"]:
        clean = _sanitize_skill_body(case["payload"])
        # Tool-call mimics are stripped; everything else is wrapped untrusted.
        assert "invoke tool:" not in clean
        assert "<untrusted_skill_guidance" in _wrap_untrusted(clean)


def test_memory_layer_poison_marked_or_redacted():
    from tools.kernel.audit import _redact_nested
    from tools.skill_registry import _wrap_untrusted

    for case in [c for c in CORPUS if c["layer"] == "memory"]:
        redacted = _redact_nested({"lesson": case["payload"]})
        wrapped = _wrap_untrusted(case["payload"])
        assert ("AKIAIOSFODNN7EXAMPLE" not in json.dumps(redacted)) or ("<untrusted_skill_guidance" in wrapped)
        # Anti-scope lessons must never survive as plain trusted guidance.
        if "skip the allowlist" in case["payload"]:
            assert "<untrusted_skill_guidance" in wrapped
