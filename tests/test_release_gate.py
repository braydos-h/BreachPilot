"""0.69 beta release gate (#80). The gate must be honest, not green."""

from __future__ import annotations

import importlib.util
import json
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


def _valid_provenance(trials: int = 1) -> dict:
    return {
        "model_alias": "glm",
        "provider": "ollama",
        "model_id": "glm-5.2:cloud",
        "model_version": "test",
        "temperature": "0.1",
        "seed": "42",
        "action_budget": 100,
        "max_rounds": 30,
        "sandbox_enabled": True,
        "scenario_version": "abc123",
        "code_revision": "d" * 40,
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


def _valid_eval_report(trials: int = 1, *, outcome: str = "PASS", run_id: str = "eval-1") -> dict:
    target_rows = []
    trial_rows = []
    for oracle_path in sorted((REPO / "eval_targets").glob("*.oracle.json")):
        oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
        target_id = oracle["target_id"]
        is_supported = oracle.get("verification_supported", True) is not False
        is_positive = oracle.get("negative_control") is not True
        target_rows.append(
            {
                "target_id": target_id,
                "success": outcome == "PASS" and is_supported and is_positive,
                "findings_verified": 1 if is_supported and is_positive else 0,
                "flags_captured": 1 if is_supported and is_positive else 0,
                "details": {}
                if is_supported
                else {"skipped": "verification unsupported", "verification_unsupported": True},
            }
        )
        if is_supported:
            target_rows[-1]["details"]["findings_false_positives"] = 0
        if is_supported:
            trial_rows.append({"target_id": target_id, "success": outcome == "PASS"})
    return {
        "run_id": run_id,
        "full_suite": True,
        "live_outcome": outcome,
        "provenance": _valid_provenance(trials),
        "reliability": {"scope_violation_count": 0},
        "targets": target_rows,
        "trials": trial_rows,
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
            json.dumps(_valid_eval_report(trials=5, run_id=f"eval-{i}")), encoding="utf-8"
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
                    "target": "branch",
                    "bypass_actors": [],
                    "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
                    "rules": [
                        {
                            "type": "required_status_checks",
                            "parameters": {
                                "strict_required_status_checks_policy": True,
                                "required_status_checks": [
                                    {"context": "CI success"},
                                    {"context": "Eval unit tests (mocked, no API key)"},
                                    {"context": "CodeQL / Analyze (python)"},
                                    {"context": "CodeQL / Analyze (javascript)"},
                                    {"context": "Dependency Review / dependency-review"},
                                ],
                            },
                        },
                        {"type": "deletion"},
                        {"type": "non_fast_forward"},
                        {
                            "type": "pull_request",
                            "parameters": {
                                "required_approving_review_count": 1,
                                "dismiss_stale_reviews_on_push": True,
                                "required_review_thread_resolution": True,
                            },
                        },
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )
    results = {
        r.name: r
        for r in mod.check_external(REPO, eval_dir=eval_dir, sandbox_digest_file=digest, branch_rules_file=rules)
    }
    assert results["live-eval-backend"].passed and not results["live-eval-backend"].external
    assert results["repeated-trials"].passed and not results["repeated-trials"].external
    assert results["branch-rules-applied"].passed
    assert results["sandbox-image-published"].passed

    rules_payload = json.loads(rules.read_text(encoding="utf-8"))
    rules_payload[0]["conditions"]["ref_name"]["exclude"] = ["refs/heads/main"]
    rules.write_text(json.dumps(rules_payload), encoding="utf-8")
    assert mod._verify_branch_rules(rules).passed is False


def test_repeated_eval_requires_matching_provenance_pins(tmp_path):
    mod = _load()
    eval_dir = tmp_path / "eval"
    eval_dir.mkdir()
    for i in range(5):
        report = _valid_eval_report(run_id=f"eval-{i}")
        report["provenance"]["config_hash"] = f"{i:016x}"
        (eval_dir / f"trial-{i}.json").write_text(json.dumps(report), encoding="utf-8")
    _live, repeated = mod._verify_eval_dir(eval_dir)
    assert repeated.external is True
    assert "need at least 5" in repeated.detail


def test_eval_source_revision_must_match_release_source(tmp_path):
    mod = _load()
    eval_dir = tmp_path / "eval"
    eval_dir.mkdir()
    (eval_dir / "report.json").write_text(json.dumps(_valid_eval_report()), encoding="utf-8")
    live, _repeated = mod._verify_eval_dir(eval_dir, source_revision="a" * 40)
    assert live.passed is False
    assert "does not match release source" in live.detail


def test_eval_gate_rejects_unknown_scope_and_false_positive_evidence(tmp_path):
    mod = _load()
    eval_dir = tmp_path / "eval"
    eval_dir.mkdir()
    report = _valid_eval_report()
    report["reliability"]["scope_violation_count"] = None
    (eval_dir / "scope.json").write_text(json.dumps(report), encoding="utf-8")
    live, _repeated = mod._verify_eval_dir(eval_dir)
    assert live.passed is False
    assert "scope-violation telemetry" in live.detail

    report = _valid_eval_report()
    executed = next(row for row in report["targets"] if not row["details"].get("skipped"))
    executed["details"]["findings_false_positives"] = 1
    (eval_dir / "scope.json").write_text(json.dumps(report), encoding="utf-8")
    live, _repeated = mod._verify_eval_dir(eval_dir)
    assert live.passed is False
    assert "false-positive findings" in live.detail


def test_external_stale_evidence_fails(tmp_path):
    import json
    import os
    import time

    mod = _load()
    eval_dir = tmp_path / "eval"
    eval_dir.mkdir()
    bad = _valid_eval_report()
    del bad["provenance"]["config_hash"]
    (eval_dir / "bad.json").write_text(json.dumps(bad), encoding="utf-8")
    live, repeated = mod._verify_eval_dir(eval_dir)
    assert live.passed is False and live.external is False
    # Stale mtime (>90d) fails even when fields are valid.
    good = eval_dir / "good.json"
    good.write_text(json.dumps(_valid_eval_report()), encoding="utf-8")
    old = time.time() - 100 * 86400
    os.utime(good, (old, old))
    (eval_dir / "bad.json").unlink()
    live2, _ = mod._verify_eval_dir(eval_dir)
    assert live2.passed is False and live2.external is False
    # Malformed digest fails.
    digest = tmp_path / "digests.txt"
    digest.write_text("no digest here", encoding="utf-8")
    assert mod._verify_sandbox_digest(digest).passed is False
    digest.write_text("breachpilot-sandbox@sha256:" + "b" * 32, encoding="utf-8")
    assert mod._verify_sandbox_digest(digest).passed is False
    digest.write_text(
        "breachpilot-sandbox@sha256:" + "b" * 64 + "\nSource commit: " + "a" * 40 + "\n",
        encoding="utf-8",
    )
    assert mod._verify_sandbox_digest(digest, "a" * 40).passed is True
    assert mod._verify_sandbox_digest(digest, "c" * 40).passed is False
    # Ruleset without main fails.
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps([{"name": "other", "enforcement": "active"}]), encoding="utf-8")
    assert mod._verify_branch_rules(rules).passed is False


def test_eval_gate_finds_nested_reports_and_rejects_skipped_runs(tmp_path: Path) -> None:
    import json

    mod = _load()
    nested = tmp_path / "eval" / "run-1"
    nested.mkdir(parents=True)
    (nested / "report.json").write_text(json.dumps(_valid_eval_report(trials=1)), encoding="utf-8")

    live, repeated = mod._verify_eval_dir(tmp_path / "eval")
    assert live.passed and not live.external
    assert repeated.external

    skipped = tmp_path / "skipped" / "run-2"
    skipped.mkdir(parents=True)
    (skipped / "report.json").write_text(
        json.dumps(_valid_eval_report(trials=0, outcome="SKIPPED", run_id="skip-1") | {"trials": []}),
        encoding="utf-8",
    )
    skipped_live, skipped_repeated = mod._verify_eval_dir(tmp_path / "skipped")
    assert not skipped_live.passed and not skipped_live.external
    assert not skipped_repeated.passed and not skipped_repeated.external


def test_eval_gate_does_not_treat_targets_as_repeated_trials(tmp_path: Path) -> None:
    import json

    mod = _load()
    report = _valid_eval_report(trials=5, run_id="one-run-many-targets")
    (tmp_path / "one.json").write_text(json.dumps(report), encoding="utf-8")

    live, repeated = mod._verify_eval_dir(tmp_path)

    assert live.passed
    assert repeated.external
    assert "only 1 distinct full-suite run IDs" in repeated.detail


def test_eval_gate_rejects_filtered_or_incomplete_target_coverage(tmp_path: Path) -> None:
    import json

    mod = _load()
    filtered = _valid_eval_report(run_id="filtered")
    filtered["full_suite"] = False
    incomplete = _valid_eval_report(run_id="incomplete")
    incomplete["targets"] = incomplete["targets"][:-1]
    (tmp_path / "filtered.json").write_text(json.dumps(filtered), encoding="utf-8")
    (tmp_path / "incomplete.json").write_text(json.dumps(incomplete), encoding="utf-8")

    live, repeated = mod._verify_eval_dir(tmp_path)

    assert not live.passed and not live.external
    assert not repeated.passed and not repeated.external


def test_eval_gate_rejects_negative_control_only_pass(tmp_path: Path) -> None:
    import json

    mod = _load()
    report = _valid_eval_report(run_id="negative-only")
    for row in report["targets"]:
        oracle = json.loads((REPO / "eval_targets" / f"{row['target_id']}.oracle.json").read_text())
        if oracle.get("negative_control") is not True:
            row["success"] = False
            row["findings_verified"] = 0
            row["flags_captured"] = 0
    eval_dir = tmp_path / "eval"
    eval_dir.mkdir()
    (eval_dir / "negative-only.json").write_text(json.dumps(report), encoding="utf-8")

    live, _repeated = mod._verify_eval_dir(eval_dir)

    assert live.passed is False
    assert "no supported positive target" in live.detail


def test_branch_rules_gate_checks_structured_ruleset_fields(tmp_path: Path) -> None:
    import json

    mod = _load()
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            [
                {
                    "name": "an unrelated active ruleset mentioning main and CI success in its description",
                    "description": "main CI success",
                    "enforcement": "active",
                    "target": "branch",
                    "conditions": {"ref_name": {"include": ["refs/heads/release"]}},
                    "rules": [],
                }
            ]
        ),
        encoding="utf-8",
    )
    assert not mod._verify_branch_rules(rules).passed


def test_branch_rules_gate_requires_strict_checks_and_review_thread_resolution(tmp_path: Path) -> None:
    import copy
    import json

    mod = _load()
    source = json.loads((REPO / "docs/governance/ruleset-main.json").read_text(encoding="utf-8"))
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(source), encoding="utf-8")
    assert mod._verify_branch_rules(path).passed

    source["rules"][3]["parameters"]["strict_required_status_checks_policy"] = False
    path.write_text(json.dumps(source), encoding="utf-8")
    assert not mod._verify_branch_rules(path).passed

    source = copy.deepcopy(json.loads((REPO / "docs/governance/ruleset-main.json").read_text(encoding="utf-8")))
    source["rules"][2]["parameters"]["required_review_thread_resolution"] = False
    path.write_text(json.dumps(source), encoding="utf-8")
    assert not mod._verify_branch_rules(path).passed


def test_no_unconditional_external_without_verification():
    import inspect

    mod = _load()
    src = inspect.getsource(mod.check_external)
    assert "eval_dir" in src and "sandbox_digest" in src and "branch_rules" in src
    assert "_external(" in src  # safe default preserved
    assert "_verify_eval_dir" in src
