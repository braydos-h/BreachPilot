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


def _make_safety_root(tmp_path: Path, doc_text: str) -> Path:
    """Minimal repo layout for check_safety_defaults: schema-matching config + one doc."""
    import shutil

    (tmp_path / "docs").mkdir(exist_ok=True)
    shutil.copy(REPO / "config.yaml", tmp_path / "config.yaml")
    (tmp_path / "README.md").write_text("safe readme\n", encoding="utf-8")
    (tmp_path / "CLAUDE.md").write_text("safe claude\n", encoding="utf-8")
    (tmp_path / "docs" / "probe.md").write_text(doc_text, encoding="utf-8")
    return tmp_path


def test_safety_defaults_catches_true_before_default_order(tmp_path):
    mod = _load()
    root = _make_safety_root(tmp_path, "`sandbox.fallback_native: true` (default)\n")
    result = mod.check_safety_defaults(root)
    assert result.passed is False, f"true-before-default must fail: {result.detail}"
    assert "probe.md" in result.detail


def test_safety_defaults_catches_default_before_true_order(tmp_path):
    mod = _load()
    root = _make_safety_root(tmp_path, "fallback_native default is true\n")
    result = mod.check_safety_defaults(root)
    assert result.passed is False, f"default-before-true must fail: {result.detail}"


def test_safety_defaults_allows_fail_closed_wording(tmp_path):
    mod = _load()
    root = _make_safety_root(
        tmp_path,
        "with `sandbox.fallback_native: true` (explicit opt-in; default `false`), "
        "fail-closed. Keep `sandbox.fallback_native: false` (default, fail-closed).\n",
    )
    result = mod.check_safety_defaults(root)
    assert result.passed, f"correct fail-closed wording must pass: {result.detail}"


def test_safety_defaults_generated_table_exists():
    assert (REPO / "docs" / "generated" / "safety-defaults.md").exists()
    text = (REPO / "docs" / "generated" / "safety-defaults.md").read_text(encoding="utf-8")
    assert "fallback_native" in text
    assert "`False`" in text or "`false`" in text


def _valid_provenance(trials: int = 5) -> dict:
    return {
        "model_alias": "glm",
        "provider": "ollama",
        "model_id": "glm-5.2:cloud",
        "model_version": "test",
        "temperature": "0.1",
        "scenario_version": "abc123",
        "code_revision": "da2d1c7",
        "breachpilot_version": "0.68.4",
        "config_hash": "c" * 12,
        "prompt_hash": "p" * 12,
        "tool_catalog_hash": "t" * 12,
        "skill_catalog_hash": "s" * 12,
        "sandbox_image": "breachpilot-sandbox:latest",
        "sandbox_image_digest": "sha256:" + "a" * 64,
        "orchestration_mode": "agent",
        "provider_adapter_version": "1",
        "trials": trials,
    }


def test_external_missing_evidence_stays_external(tmp_path):
    mod = _load()
    results = {r.name: r for r in mod.check_external(tmp_path)}
    for name in ("live-eval-backend", "repeated-trials", "branch-rules-applied", "sandbox-image-published"):
        assert results[name].external, f"{name} must be EXTERNAL when evidence missing"


def test_external_valid_evidence_passes(tmp_path):
    import json

    mod = _load()
    eval_dir = tmp_path / "eval"
    eval_dir.mkdir()
    for i in range(5):
        (eval_dir / f"trial-{i}.json").write_text(
            json.dumps({"provenance": _valid_provenance(trials=5)}), encoding="utf-8"
        )
    digest = tmp_path / "digests.txt"
    digest.write_text("breachpilot-sandbox@sha256:" + "b" * 64, encoding="utf-8")
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            [
                {
                    "name": "main-protected",
                    "enforcement": "active",
                    "conditions": {"ref_name": {"include": ["refs/heads/main"]}},
                    "rules": [
                        {
                            "type": "required_status_checks",
                            "parameters": {"required_status_checks": [{"context": "CI success"}]},
                        }
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )
    results = {
        r.name: r
        for r in mod.check_external(tmp_path, eval_dir=eval_dir, sandbox_digest_file=digest, branch_rules_file=rules)
    }
    assert results["live-eval-backend"].passed and not results["live-eval-backend"].external
    assert results["repeated-trials"].passed and not results["repeated-trials"].external
    assert results["branch-rules-applied"].passed
    assert results["sandbox-image-published"].passed


def test_external_stale_evidence_fails(tmp_path):
    import json
    import os
    import time

    mod = _load()
    eval_dir = tmp_path / "eval"
    eval_dir.mkdir()
    bad = _valid_provenance()
    del bad["config_hash"]
    (eval_dir / "bad.json").write_text(json.dumps({"provenance": bad}), encoding="utf-8")
    live, repeated = mod._verify_eval_dir(eval_dir)
    assert live.passed is False and live.external is False
    # Stale mtime (>90d) fails even when fields are valid.
    good = eval_dir / "good.json"
    good.write_text(json.dumps({"provenance": _valid_provenance()}), encoding="utf-8")
    old = time.time() - 100 * 86400
    os.utime(good, (old, old))
    (eval_dir / "bad.json").unlink()
    live2, _ = mod._verify_eval_dir(eval_dir)
    assert live2.passed is False and live2.external is False
    # Malformed digest fails.
    digest = tmp_path / "digests.txt"
    digest.write_text("no digest here", encoding="utf-8")
    assert mod._verify_sandbox_digest(digest).passed is False
    # Ruleset without main fails.
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps([{"name": "other", "enforcement": "active"}]), encoding="utf-8")
    assert mod._verify_branch_rules(rules).passed is False


def test_no_unconditional_external_without_verification():
    import inspect

    mod = _load()
    src = inspect.getsource(mod.check_external)
    assert "eval_dir" in src and "sandbox_digest" in src and "branch_rules" in src
    assert "_external(" in src  # safe default preserved
    assert "_verify_eval_dir" in src
