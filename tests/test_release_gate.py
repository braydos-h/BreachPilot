"""0.69 beta release gate (#80). The gate must be honest, not green."""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _load():
    import sys

    path = REPO / "scripts" / "release_gate.py"
    spec = importlib.util.spec_from_file_location("release_gate", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["release_gate"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_all_local_boxes_pass_on_current_tree():
    mod = _load()
    for check in (
        mod.check_versions,
        mod.check_ci_tiers,
        mod.check_eval_skip_visibility,
        mod.check_safety_defaults,
        mod.check_safety_suite,
        mod.check_negative_controls,
        mod.check_provenance_fields,
        mod.check_native_consent_gate,
        mod.check_docs_contract,
    ):
        result = check(REPO)
        assert result.passed, f"{result.name}: {result.detail}"


def test_externals_are_never_green():
    mod = _load()
    report = mod.run_gate(REPO)
    assert report.externals, "gate must list EXTERNAL boxes until humans act"
    assert report.verdict == "NO-GO"
    # No silent green: every external box is explicit.
    names = {r.name for r in report.results}
    assert {"live-eval-backend", "repeated-trials", "branch-rules-applied", "sandbox-image-published"} <= names
    payload = report.to_dict()
    assert payload["verdict"] == "NO-GO"


def test_version_mismatch_fails(monkeypatch, tmp_path):
    mod = _load()
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "9.9.9"\n', encoding="utf-8")
    (tmp_path / "main.py").write_text('__version__ = "0.0.0"\n', encoding="utf-8")
    (tmp_path / "webui").mkdir()
    (tmp_path / "webui" / "package.json").write_text('{"version": "0.0.1"}', encoding="utf-8")
    result = mod.check_versions(tmp_path)
    assert result.passed is False
