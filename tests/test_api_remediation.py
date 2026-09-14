"""Stable remediation codes, backend+UI contract (#53)."""

from __future__ import annotations


def test_every_code_has_title_fix_docs():
    from tools.api.remediation import REMEDIATION_CODES, REMEDIATION_VERSION

    assert REMEDIATION_VERSION == 1
    assert len(REMEDIATION_CODES) >= 10
    for code, entry in REMEDIATION_CODES.items():
        assert entry["title"] and entry["fix"] and entry["docs"], code


def test_remediation_for_known_and_unknown():
    from tools.api.remediation import remediation_for

    known = remediation_for("sandbox_image_missing")
    assert known["code"] == "sandbox_image_missing"
    assert "docker build" in known["fix"]
    fallback = remediation_for("no_such_code")
    assert fallback["code"] == "internal_error"
    assert fallback["requested"] == "no_such_code"


def test_docs_targets_exist():
    from pathlib import Path

    from tools.api.remediation import REMEDIATION_CODES

    repo = Path(__file__).resolve().parent.parent
    for code, entry in REMEDIATION_CODES.items():
        assert (repo / entry["docs"]).exists(), f"{code}: missing {entry['docs']}"
